/**
 * @file apps/cli/src/credentials.ts
 * @description Encrypted-at-rest CLI credential store using Node `node:crypto`
 * AES-256-GCM + scrypt key derivation + 0o600 permissions, with backward-compatible
 * legacy plaintext read and secret redaction helpers.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export type AIProviderName =
  | "openai"
  | "google"
  | "nvidia"
  | "openrouter"
  | "claude"
  | "grok"
  | "codex";

export interface AICredentials {
  openaiApiKey?: string;
  googleApiKey?: string;
  nvidiaApiKey?: string;
  openrouterApiKey?: string;
  anthropicApiKey?: string;
  grokApiKey?: string;
  codexSubscriptionToken?: string;
  typesafeApiKey?: string;
  activeProvider: AIProviderName;
}

export interface CredentialStoreOptions {
  filePath?: string;
  passphrase?: string;
}

export interface EncryptedCredentialsEnvelope {
  schemaVersion: "script-kitty.credentials.v1";
  algorithm: "aes-256-gcm";
  kdf: "scrypt";
  kdfParams: {
    N: number;
    r: number;
    p: number;
    keyLen: number;
  };
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

export interface RedactedAICredentials {
  activeProvider: AIProviderName;
  hasAnyConfiguredKey: boolean;
  configuredKeys: {
    openai: boolean;
    google_gemini: boolean;
    nvidia_nim: boolean;
    openrouter: boolean;
    claude: boolean;
    grok: boolean;
    codex_subscription: boolean;
    typesafe_jev: boolean;
  };
  maskedKeys: {
    openaiApiKey?: string;
    googleApiKey?: string;
    nvidiaApiKey?: string;
    openrouterApiKey?: string;
    anthropicApiKey?: string;
    grokApiKey?: string;
    codexSubscriptionToken?: string;
    typesafeApiKey?: string;
  };
}

export class CredentialStoreError extends Error {
  readonly code: "DECRYPTION_FAILED" | "INVALID_ENVELOPE" | "IO_ERROR";

  constructor(
    code: "DECRYPTION_FAILED" | "INVALID_ENVELOPE" | "IO_ERROR",
    message: string
  ) {
    super(`${code}: ${message}`);
    this.name = "CredentialStoreError";
    this.code = code;
  }
}

const ENVELOPE_SCHEMA_VERSION = "script-kitty.credentials.v1";
const ENVELOPE_AAD = Buffer.from(ENVELOPE_SCHEMA_VERSION, "utf8");
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keyLen: 32 } as const;
const MAX_SCRYPT_N = 65536;
const MIN_SCRYPT_N = 1024;
const MAX_SCRYPT_R = 16;
const MAX_SCRYPT_P = 4;
const REQUIRED_SCRYPT_KEY_LEN = 32;

function assertValidKdfParams(raw: unknown): {
  N: number;
  r: number;
  p: number;
  keyLen: number;
} {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new CredentialStoreError(
      "INVALID_ENVELOPE",
      "Encrypted credential envelope has invalid kdfParams"
    );
  }
  const obj = raw as Record<string, unknown>;
  const N = Number(obj.N);
  const r = Number(obj.r);
  const p = Number(obj.p);
  const keyLen = Number(obj.keyLen);

  if (
    !Number.isInteger(N) ||
    N < MIN_SCRYPT_N ||
    N > MAX_SCRYPT_N ||
    (N & (N - 1)) !== 0 ||
    !Number.isInteger(r) ||
    r < 1 ||
    r > MAX_SCRYPT_R ||
    !Number.isInteger(p) ||
    p < 1 ||
    p > MAX_SCRYPT_P ||
    !Number.isInteger(keyLen) ||
    keyLen !== REQUIRED_SCRYPT_KEY_LEN
  ) {
    throw new CredentialStoreError(
      "INVALID_ENVELOPE",
      `Encrypted credential envelope kdfParams exceed safe bounds (max N=${MAX_SCRYPT_N}, r=${MAX_SCRYPT_R}, p=${MAX_SCRYPT_P}, keyLen=${REQUIRED_SCRYPT_KEY_LEN})`
    );
  }
  return { N, r, p, keyLen };
}

const VALID_PROVIDERS = new Set<AIProviderName>([
  "openai",
  "google",
  "nvidia",
  "openrouter",
  "claude",
  "grok",
  "codex",
]);

export function resolveCredentialsFilePath(options?: CredentialStoreOptions): string {
  if (options?.filePath && options.filePath.trim()) {
    return path.resolve(options.filePath);
  }
  const envPath = process.env.SCRIPT_KITTY_CREDENTIALS_FILE?.trim();
  if (envPath) {
    return path.resolve(envPath);
  }
  return path.resolve(".context", "config", "credentials.json");
}

function deriveLocalMachinePassphrase(): string {
  let username = "unknown-user";
  try {
    username = os.userInfo().username || "unknown-user";
  } catch {
    username = process.env.USERNAME || process.env.USER || "unknown-user";
  }
  return [
    "script-kitty-cli-credentials-v1",
    os.hostname(),
    username,
    os.homedir(),
    process.platform,
    process.arch,
  ].join("|");
}

function resolveKeyMaterial(options?: CredentialStoreOptions): string {
  if (options?.passphrase !== undefined && options.passphrase.length > 0) {
    return options.passphrase;
  }
  const envMaster = process.env.SCRIPT_KITTY_MASTER_KEY;
  if (envMaster && envMaster.length > 0) {
    return envMaster;
  }
  return deriveLocalMachinePassphrase();
}

function deriveAesKey(
  salt: Buffer,
  options?: CredentialStoreOptions,
  params: { N: number; r: number; p: number; keyLen: number } = SCRYPT_PARAMS
): Buffer {
  const safeParams = assertValidKdfParams(params);
  const keyMaterial = resolveKeyMaterial(options);
  return crypto.scryptSync(keyMaterial, salt, safeParams.keyLen, {
    N: safeParams.N,
    r: safeParams.r,
    p: safeParams.p,
  });
}

export function isEncryptedCredentialsEnvelope(
  value: unknown
): value is EncryptedCredentialsEnvelope {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    v.schemaVersion === ENVELOPE_SCHEMA_VERSION &&
    v.algorithm === "aes-256-gcm" &&
    v.kdf === "scrypt" &&
    typeof v.salt === "string" &&
    typeof v.iv === "string" &&
    typeof v.tag === "string" &&
    typeof v.ciphertext === "string"
  );
}

function normalizeCredentials(raw: unknown): AICredentials {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { activeProvider: "openai" };
  }
  const obj = raw as Record<string, unknown>;
  const providerCandidate =
    typeof obj.activeProvider === "string" &&
    VALID_PROVIDERS.has(obj.activeProvider as AIProviderName)
      ? (obj.activeProvider as AIProviderName)
      : "openai";

  const out: AICredentials = {
    activeProvider: providerCandidate,
  };

  const stringFields: Array<keyof Omit<AICredentials, "activeProvider">> = [
    "openaiApiKey",
    "googleApiKey",
    "nvidiaApiKey",
    "openrouterApiKey",
    "anthropicApiKey",
    "grokApiKey",
    "codexSubscriptionToken",
    "typesafeApiKey",
  ];

  for (const field of stringFields) {
    const val = obj[field];
    if (typeof val === "string" && val.length > 0) {
      out[field] = val;
    }
  }

  return out;
}

export function encryptCredentials(
  creds: AICredentials,
  options?: CredentialStoreOptions
): EncryptedCredentialsEnvelope {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveAesKey(salt, options, SCRYPT_PARAMS);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(ENVELOPE_AAD);

  const plaintext = JSON.stringify(normalizeCredentials(creds));
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    schemaVersion: ENVELOPE_SCHEMA_VERSION,
    algorithm: "aes-256-gcm",
    kdf: "scrypt",
    kdfParams: { ...SCRYPT_PARAMS },
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
  };
}

export function decryptCredentials(
  envelope: EncryptedCredentialsEnvelope,
  options?: CredentialStoreOptions
): AICredentials {
  if (!isEncryptedCredentialsEnvelope(envelope)) {
    throw new CredentialStoreError(
      "INVALID_ENVELOPE",
      "Credential file does not match encrypted envelope schema"
    );
  }

  try {
    const salt = Buffer.from(envelope.salt, "base64");
    const iv = Buffer.from(envelope.iv, "base64");
    const tag = Buffer.from(envelope.tag, "base64");
    const ciphertext = Buffer.from(envelope.ciphertext, "base64");

    if (salt.length < 16 || iv.length !== 12 || tag.length !== 16) {
      throw new CredentialStoreError(
        "INVALID_ENVELOPE",
        "Encrypted credential envelope has invalid salt, IV, or auth tag length"
      );
    }

    const safeKdfParams = assertValidKdfParams(envelope.kdfParams);
    const key = deriveAesKey(salt, options, safeKdfParams);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(ENVELOPE_AAD);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString("utf8");

    return normalizeCredentials(JSON.parse(decrypted));
  } catch (err) {
    if (err instanceof CredentialStoreError) {
      throw err;
    }
    throw new CredentialStoreError(
      "DECRYPTION_FAILED",
      "Unable to decrypt credentials (wrong key or tampered ciphertext/tag)"
    );
  }
}

/**
 * Loads credentials from disk. Supports both AES-256-GCM encrypted envelopes
 * and backward-compatible reading of legacy plaintext credentials JSON.
 * Fails closed on tampered encrypted envelopes or wrong decryption keys.
 */
export function loadCredentials(options?: CredentialStoreOptions): AICredentials {
  const filePath = resolveCredentialsFilePath(options);
  if (!fs.existsSync(filePath)) {
    return { activeProvider: "openai" };
  }

  let rawText: string;
  try {
    rawText = fs.readFileSync(filePath, "utf-8");
  } catch (err) {
    throw new CredentialStoreError(
      "IO_ERROR",
      err instanceof Error ? err.message : "Failed to read credentials file"
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new CredentialStoreError(
      "INVALID_ENVELOPE",
      "Credentials file contains invalid JSON"
    );
  }

  if (isEncryptedCredentialsEnvelope(parsed)) {
    return decryptCredentials(parsed, options);
  }

  // Backward-compatible read of legacy plaintext JSON format
  return normalizeCredentials(parsed);
}

/**
 * Saves credentials encrypted at rest (AES-256-GCM + scrypt) with strict 0o600 permissions.
 * Automatically upgrades legacy plaintext credential files on write.
 */
export function saveCredentials(
  creds: Partial<AICredentials>,
  options?: CredentialStoreOptions
): AICredentials {
  const filePath = resolveCredentialsFilePath(options);
  const current = loadCredentials(options);
  const updated = normalizeCredentials({ ...current, ...creds });

  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const envelope = encryptCredentials(updated, options);
  const serialized = JSON.stringify(envelope, null, 2);

  fs.writeFileSync(filePath, serialized, { encoding: "utf-8", mode: 0o600 });
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Some Windows environments ignore POSIX chmod bits; mode was passed on writeFileSync
  }

  return updated;
}

/**
 * Explicitly migrates a legacy plaintext credentials file in place to AES-256-GCM.
 */
export function migratePlaintextCredentials(
  options?: CredentialStoreOptions
): { migrated: boolean; filePath: string } {
  const filePath = resolveCredentialsFilePath(options);
  if (!fs.existsSync(filePath)) {
    return { migrated: false, filePath };
  }
  const raw = JSON.parse(fs.readFileSync(filePath, "utf-8")) as unknown;
  if (isEncryptedCredentialsEnvelope(raw)) {
    return { migrated: false, filePath };
  }
  const legacy = normalizeCredentials(raw);
  saveCredentials(legacy, options);
  return { migrated: true, filePath };
}

export function maskSecret(value?: string): string | undefined {
  if (!value || value.length === 0) {
    return undefined;
  }
  if (value.length <= 8) {
    return "***";
  }
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

export function redactCredentials(creds: AICredentials): RedactedAICredentials {
  const configuredKeys = {
    openai: Boolean(creds.openaiApiKey),
    google_gemini: Boolean(creds.googleApiKey),
    nvidia_nim: Boolean(creds.nvidiaApiKey),
    openrouter: Boolean(creds.openrouterApiKey),
    claude: Boolean(creds.anthropicApiKey),
    grok: Boolean(creds.grokApiKey),
    codex_subscription: Boolean(creds.codexSubscriptionToken),
    typesafe_jev: Boolean(creds.typesafeApiKey || process.env.TYPESAFE_API_KEY?.trim()),
  };

  return {
    activeProvider: creds.activeProvider,
    hasAnyConfiguredKey: Object.values(configuredKeys).some(Boolean),
    configuredKeys,
    maskedKeys: {
      ...(creds.openaiApiKey ? { openaiApiKey: maskSecret(creds.openaiApiKey) } : {}),
      ...(creds.googleApiKey ? { googleApiKey: maskSecret(creds.googleApiKey) } : {}),
      ...(creds.nvidiaApiKey ? { nvidiaApiKey: maskSecret(creds.nvidiaApiKey) } : {}),
      ...(creds.openrouterApiKey
        ? { openrouterApiKey: maskSecret(creds.openrouterApiKey) }
        : {}),
      ...(creds.anthropicApiKey
        ? { anthropicApiKey: maskSecret(creds.anthropicApiKey) }
        : {}),
      ...(creds.grokApiKey ? { grokApiKey: maskSecret(creds.grokApiKey) } : {}),
      ...(creds.codexSubscriptionToken
        ? { codexSubscriptionToken: maskSecret(creds.codexSubscriptionToken) }
        : {}),
      ...(creds.typesafeApiKey
        ? { typesafeApiKey: maskSecret(creds.typesafeApiKey) }
        : {}),
    },
  };
}
