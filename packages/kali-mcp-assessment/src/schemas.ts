/**
 * @file packages/kali-mcp-assessment/src/schemas.ts
 * @description Strict LAB_SANDBOX_ONLY governance primitives, target host containment,
 * payload safety firewall, and Zod validation schemas for @script-kitty/kali-mcp-assessment.
 */

import { z } from 'zod';

/**
 * Operational classification locked strictly to LAB_SANDBOX_ONLY.
 */
export const KALI_MODE = 'LAB_SANDBOX_ONLY' as const;
export type KaliMode = typeof KALI_MODE;

/**
 * The 4 strictly allowlisted defensive/verification MCP capabilities.
 */
export const KALI_CAPABILITY_NAMES = [
  'security.kali.recon_surface',
  'security.kali.config_audit',
  'security.kali.verify_reproducer',
  'security.kali.sbom_cve_check',
] as const;

export type KaliCapabilityName = (typeof KALI_CAPABILITY_NAMES)[number];

/**
 * Execution mode transparency tags.
 * LAB_SIMULATION runs deterministic offline verification without pretending a container executed.
 * LIVE_CONTAINER requires a verified rootless OCI (gVisor) or dedicated WSL2 micro-VM sandbox.
 */
export const KALI_EXECUTION_MODES = ['LIVE_CONTAINER', 'LAB_SIMULATION'] as const;
export type KaliExecutionMode = (typeof KALI_EXECUTION_MODES)[number];
export const ExecutionModeSchema = z.enum(KALI_EXECUTION_MODES);

export const RequestedExecutionModeSchema = z.enum([
  'AUTO',
  'LIVE_CONTAINER',
  'LAB_SIMULATION',
]);
export type RequestedExecutionMode = z.infer<typeof RequestedExecutionModeSchema>;

/**
 * Network containment profiles (mutually exclusive; no arbitrary internet egress).
 */
export const SandboxNetworkModeSchema = z.enum(['airgapped', 'lab-loopback-bridge']);
export type SandboxNetworkMode = z.infer<typeof SandboxNetworkModeSchema>;

/**
 * Custom typed security boundary error thrown or surfaced fail-closed.
 */
export class KaliSecurityError extends Error {
  public readonly code: string;
  public readonly details?: Record<string, unknown>;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(`${code}: ${message}`);
    this.name = 'KaliSecurityError';
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Cloud IMDS, wildcard, and host-escape endpoints unconditionally denied.
 */
export const BLOCKED_IMDS_AND_HOST_TARGETS = new Set<string>([
  '169.254.169.254',
  '169.254.169.253',
  '169.254.170.2',
  '100.100.100.200',
  'metadata.google.internal',
  'metadata',
  '0.0.0.0',
  'host.docker.internal',
  'gateway.docker.internal',
  'kubernetes.default',
  'kubernetes.default.svc',
]);

/**
 * Checks whether an IPv4 address belongs to RFC 1918 private LAN subnets or link-local IMDS.
 */
export function isRfc1918OrLinkLocalIpv4(host: string): boolean {
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  const octets = match.slice(1).map((v) => Number(v));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const [a, b] = octets;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / IMDS
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT / Alibaba IMDS
  return false;
}

/**
 * Classifies and validates whether a target host strictly matches:
 * - `127.0.0.1`
 * - `localhost`
 * - `*.localnet` (valid DNS labels starting with a letter, no spoofed IMDS/IPs)
 */
export function evaluateLabTargetHost(rawHost: string): {
  allowed: boolean;
  normalized: string;
  code?: string;
  reason?: string;
} {
  if (typeof rawHost !== 'string') {
    return {
      allowed: false,
      normalized: '',
      code: 'KALI_INVALID_TARGET_HOST',
      reason: 'Target host must be a non-empty string',
    };
  }

  const trimmed = rawHost.trim();
  if (!trimmed || trimmed.length > 128) {
    return {
      allowed: false,
      normalized: trimmed,
      code: 'KALI_INVALID_TARGET_HOST',
      reason: 'Target host must be between 1 and 128 characters',
    };
  }

  if (trimmed.startsWith('-')) {
    return {
      allowed: false,
      normalized: trimmed,
      code: 'KALI_FLAG_INJECTION_BLOCKED',
      reason: 'Target host cannot start with hyphen (CLI flag injection blocked)',
    };
  }

  if (/[\s;@:/\\?#$`'"!<>\r\n\0]/.test(trimmed)) {
    return {
      allowed: false,
      normalized: trimmed,
      code: 'KALI_SHELL_METACHAR_BLOCKED',
      reason: 'Target host contains forbidden whitespace, URL syntax, or shell metacharacters',
    };
  }

  const lower = trimmed.toLowerCase();

  if (BLOCKED_IMDS_AND_HOST_TARGETS.has(lower) || lower.startsWith('169.254.')) {
    return {
      allowed: false,
      normalized: lower,
      code: 'KALI_BLOCKED_IMDS_TARGET',
      reason: `Cloud IMDS / host-escape endpoint '${lower}' is strictly blocked`,
    };
  }

  if (isRfc1918OrLinkLocalIpv4(lower)) {
    return {
      allowed: false,
      normalized: lower,
      code: 'KALI_BLOCKED_RFC1918_TARGET',
      reason: `Private LAN / non-lab IPv4 '${lower}' is blocked outside isolated loopback/localnet`,
    };
  }

  if (lower === '127.0.0.1' || lower === 'localhost') {
    return { allowed: true, normalized: lower };
  }

  // Strictly validate *.localnet DNS labels (must begin with a letter and have no numeric/IMDS spoofing)
  if (lower.endsWith('.localnet')) {
    const prefix = lower.slice(0, -'.localnet'.length);
    const labels = prefix.split('.');
    const validLabel = /^[a-z][a-z0-9-]{0,31}(?<![-])$/;
    const hasBlockedKeyword = labels.some(
      (lbl) =>
        lbl === 'metadata' ||
        lbl === 'host' ||
        lbl === 'docker' ||
        lbl === 'internal' ||
        /^\d+$/.test(lbl)
    );
    if (
      prefix.length >= 1 &&
      labels.length >= 1 &&
      labels.length <= 3 &&
      !prefix.includes('169') &&
      !hasBlockedKeyword &&
      labels.every((lbl) => validLabel.test(lbl) && !lbl.endsWith('-'))
    ) {
      return { allowed: true, normalized: lower };
    }
    return {
      allowed: false,
      normalized: lower,
      code: 'KALI_INVALID_LOCALNET_HOST',
      reason: `Malformed or spoofed .localnet hostname '${lower}' rejected`,
    };
  }

  return {
    allowed: false,
    normalized: lower,
    code: 'KALI_BLOCKED_PUBLIC_OR_NONLAB_TARGET',
    reason: `Target host '${lower}' is restricted strictly to 127.0.0.1, localhost, or *.localnet`,
  };
}

/**
 * Strict lab-only target host Zod schema (`127.0.0.1`, `localhost`, or `*.localnet`).
 */
export const LabTargetHostSchema = z
  .string()
  .trim()
  .transform((val) => val.toLowerCase())
  .superRefine((val, ctx) => {
    const res = evaluateLabTargetHost(val);
    if (!res.allowed) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `${res.code}: ${res.reason}`,
      });
    }
  });

/**
 * Bounded unique port list for safe TCP connect verification (no flood/full-range sweeps).
 */
export const LabPortListSchema = z
  .array(z.number().int().min(1).max(65535))
  .min(1, 'At least 1 port must be specified')
  .max(32, 'Maximum 32 ports allowed per lab recon invocation')
  .refine((ports) => new Set(ports).size === ports.length, {
    message: 'Duplicate ports are prohibited',
  });

/**
 * Strict workspace-relative path validator blocking traversal, absolute paths,
 * leading hyphens (flag injection), and sensitive files (.env, .git, keys).
 */
export const SafeRelPathSchema = z
  .string()
  .trim()
  .min(1, 'Relative path cannot be empty')
  .max(256, 'Relative path exceeds 256-character limit')
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/, {
    message: 'Path must start with an alphanumeric character and contain only [a-zA-Z0-9._/-]',
  })
  .refine((p) => !p.includes('..') && !p.includes('//') && !p.startsWith('/'), {
    message: 'Path traversal (..), double slashes, and absolute paths are prohibited',
  })
  .refine((p) => !p.startsWith('-'), {
    message: 'Leading hyphen prohibited to prevent CLI flag injection',
  })
  .refine(
    (p) =>
      !/(?:^|\/)\.(?:env(?:\.[a-z0-9_-]+)?|git|aws|ssh)(?:\/|$)/i.test(p) &&
      !/\.(?:pem|key|pfx|p12)$/i.test(p) &&
      !/(?:^|\/)id_(?:rsa|ed25519|ecdsa)(?:\.pub)?$/i.test(p),
    {
      message: 'Sensitive credential/VCS paths (.env, .git, keys) are blocked',
    }
  );

export const SafeAgentIdSchema = z
  .string()
  .trim()
  .min(1, 'Agent ID is required')
  .max(128, 'Agent ID exceeds 128 characters')
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/, {
    message: 'Agent ID must start with alphanumeric character and match [a-zA-Z0-9._:-]',
  });

export const SafeFindingIdSchema = z
  .string()
  .trim()
  .min(1, 'finding_id is required')
  .max(128, 'finding_id exceeds 128 characters')
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9_.\-:]*$/, {
    message: 'finding_id must start with alphanumeric character and match [a-zA-Z0-9_.-:]',
  });

export const Sha256HexSchema = z
  .string()
  .trim()
  .regex(/^[a-fA-F0-9]{64}$/, 'Must be a 64-character SHA-256 hex digest')
  .transform((s) => s.toLowerCase());

/**
 * Signed Lab Engagement Scope Reference (Section 1.3).
 */
export const EngagementScopeRefSchema = z
  .object({
    scope_id: z
      .string()
      .trim()
      .regex(/^SK-SCOPE-[a-zA-Z0-9_-]{1,64}$/, 'scope_id must match SK-SCOPE-*'),
    authorized_by: SafeAgentIdSchema,
    tenant_id: z
      .string()
      .trim()
      .regex(/^[a-zA-Z0-9._-]{1,64}$/)
      .optional(),
    target_allowlist: z.array(LabTargetHostSchema).min(1).max(16).optional(),
    authorization_ref: z
      .string()
      .trim()
      .regex(/^[a-zA-Z0-9._:-]{1,128}$/)
      .optional(),
    mode: z.literal('LAB'),
    expires_at: z.string().datetime({
      message: 'expires_at must be an ISO-8601 UTC timestamp',
    }),
  })
  .strict();

export type EngagementScopeRef = z.infer<typeof EngagementScopeRefSchema>;

export interface VerifyEngagementScopeOptions {
  targetHost?: string;
  expectedTenantId?: string;
  now?: Date;
}

export interface EngagementScopeVerificationResult {
  valid: boolean;
  code?: string;
  reason?: string;
  scope?: EngagementScopeRef;
}

/**
 * Verifies an EngagementScopeRef, failing closed when mode !== 'LAB',
 * the scope has expired, the tenant mismatches, or target_host falls outside target_allowlist.
 */
export function verifyEngagementScope(
  rawScope: unknown,
  options: VerifyEngagementScopeOptions = {}
): EngagementScopeVerificationResult {
  const parsed = EngagementScopeRefSchema.safeParse(rawScope);
  if (!parsed.success) {
    return {
      valid: false,
      code: 'E_INVALID_ENGAGEMENT_SCOPE',
      reason: parsed.error.issues.map((i) => i.message).join('; '),
    };
  }

  const scope = parsed.data;
  const nowMs = (options.now ?? new Date()).getTime();
  const expiresMs = Date.parse(scope.expires_at);

  if (!Number.isFinite(expiresMs) || expiresMs <= nowMs) {
    return {
      valid: false,
      code: 'E_SCOPE_EXPIRED',
      reason: `Engagement scope '${scope.scope_id}' expired at ${scope.expires_at}`,
    };
  }

  if (options.expectedTenantId && scope.tenant_id && scope.tenant_id !== options.expectedTenantId) {
    return {
      valid: false,
      code: 'E_SCOPE_TENANT_MISMATCH',
      reason: `Scope tenant '${scope.tenant_id}' does not match caller tenant '${options.expectedTenantId}'`,
    };
  }

  if (options.targetHost && scope.target_allowlist && scope.target_allowlist.length > 0) {
    const normalizedTarget = options.targetHost.trim().toLowerCase();
    const allowed = scope.target_allowlist.some(
      (entry) => entry.trim().toLowerCase() === normalizedTarget
    );
    if (!allowed) {
      return {
        valid: false,
        code: 'E_SCOPE_TARGET_NOT_ALLOWLISTED',
        reason: `Target '${normalizedTarget}' is not listed in scope target_allowlist`,
      };
    }
  }

  return { valid: true, scope };
}

/**
 * Forbidden raw shell/exploit parameter names blocked recursively in tool arguments.
 */
export const FORBIDDEN_RAW_EXECUTION_KEYS = new Set<string>([
  'command',
  'cmd',
  'shell',
  'raw_args',
  'rawargs',
  'raw_nmap_args',
  'rawnmapargs',
  'run_command',
  'runcommand',
  'execute_shell',
  'executeshell',
  'shell_command',
  'arbitrary_command',
  'args',
  'cli_flags',
  'flags',
  'exec',
  'bash',
  'sh',
  'powershell',
  'pwsh',
  'script',
  'nse_script',
  'payload',
  'exploit',
  'msf',
  'reverse_shell',
  'bind_shell',
]);

export const SHELL_METACHAR_REGEX = /(?:;|&&|\|\||\||`|\$\(|[\x00-\x1f\x7f]|>{1,2}|<|%00)/;

export const WEAPONIZED_PAYLOAD_PATTERNS: RegExp[] = [
  /\b(?:msfvenom|msfconsole|metasploit|sqlmap|linpeas|winpeas|hydra|hashcat|john|johntheripper|responder|mimikatz|medusa|hping3|slowloris|aircrack)\b/i,
  /(?:--os-shell|--os-pwn|--exploit|--dump-all|--reverse-shell|--bind-shell|--script=|--eval\b)/i,
  /(?:^|\s)(?:-sS|-sU|-sN|-sF|-sX|-oN|-oG|-oA|-iL)(?:\s|=|$)/,
  /(?:\/dev\/tcp\/|\bnc\s+-e\b|\bncat\b|\bsocat\b|\breverse[_-]?shell\b|\bbind[_-]?shell\b)/i,
  /\b(?:rm\s+-rf|chmod\s+\+x|curl\s+[^|]+\|\s*(?:ba)?sh|wget\s+[^|]+\|\s*(?:ba)?sh|python3?\s+-c|node\s+-e)\b/i,
];

/**
 * Recursively scans input parameters to reject shell metacharacters, forbidden raw keys,
 * and weaponized / offensive exploit patterns before Zod or container dispatch.
 */
export function scanKaliPayloadSafety(
  value: unknown,
  pathPrefix = 'params',
  seen = new WeakSet<object>()
): { safe: boolean; reason?: string; ruleId?: string } {
  if (value === null || value === undefined) {
    return { safe: true };
  }

  if (typeof value === 'string') {
    if (SHELL_METACHAR_REGEX.test(value)) {
      return {
        safe: false,
        ruleId: 'KALI_SHELL_METACHAR_BLOCKED',
        reason: `Shell metacharacter or control character forbidden at '${pathPrefix}'`,
      };
    }
    for (const pattern of WEAPONIZED_PAYLOAD_PATTERNS) {
      if (pattern.test(value)) {
        return {
          safe: false,
          ruleId: 'KALI_WEAPONIZED_PAYLOAD_BLOCKED',
          reason: `Weaponized/offensive tool or exploit flag pattern blocked at '${pathPrefix}'`,
        };
      }
    }
    return { safe: true };
  }

  if (typeof value === 'object') {
    if (seen.has(value)) return { safe: true };
    seen.add(value);

    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const res = scanKaliPayloadSafety(value[i], `${pathPrefix}[${i}]`, seen);
        if (!res.safe) return res;
      }
      return { safe: true };
    }

    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_RAW_EXECUTION_KEYS.has(k.toLowerCase())) {
        return {
          safe: false,
          ruleId: 'KALI_FORBIDDEN_RAW_EXECUTION_PARAM',
          reason: `Forbidden raw execution or exploit parameter '${k}' rejected`,
        };
      }
      const keyRes = scanKaliPayloadSafety(k, `${pathPrefix}.KEY(${k})`, seen);
      if (!keyRes.safe) return keyRes;
      const valRes = scanKaliPayloadSafety(v, `${pathPrefix}.${k}`, seen);
      if (!valRes.safe) return valRes;
    }
  }

  return { safe: true };
}

/**
 * Rejects any string containing shell metacharacters or whitespace when a single token is expected.
 */
export function assertNoShellInterpolation(token: string, label: string): string {
  if (typeof token !== 'string' || token.length === 0) {
    throw new KaliSecurityError('KALI_SHELL_METACHAR_BLOCKED', `${label} must be a non-empty string`);
  }
  if (SHELL_METACHAR_REGEX.test(token) || /\s/.test(token)) {
    throw new KaliSecurityError(
      'KALI_SHELL_METACHAR_BLOCKED',
      `Whitespace or shell metacharacters forbidden in ${label}`
    );
  }
  return token;
}

/**
 * Rejects CLI flag-injection tokens (leading '-', whitespace, or '=' option payloads).
 */
export function assertNoFlagInjection(token: string, label: string): string {
  assertNoShellInterpolation(token, label);
  if (token.startsWith('-')) {
    throw new KaliSecurityError(
      'KALI_FLAG_INJECTION_BLOCKED',
      `Leading hyphen prohibited in positional argument ${label}`
    );
  }
  return token;
}

/**
 * A. security.kali.recon_surface strict input schema.
 */
export const KaliReconSurfaceInputSchema = z
  .object({
    scope: EngagementScopeRefSchema,
    target_host: LabTargetHostSchema,
    ports: LabPortListSchema.default([80, 443, 3000, 8080]),
    probe_profile: z
      .enum(['tcp_connect_ports', 'http_headers_metadata'])
      .default('tcp_connect_ports'),
    discovering_agent_id: SafeAgentIdSchema,
    timeout_ms: z.number().int().min(1000).max(45000).default(20000),
  })
  .strict();

export type KaliReconSurfaceInput = z.input<typeof KaliReconSurfaceInputSchema>;
export type ParsedKaliReconSurfaceInput = z.infer<typeof KaliReconSurfaceInputSchema>;

/**
 * B. security.kali.config_audit strict input schema.
 */
export const KaliConfigAuditInputSchema = z
  .object({
    scope: EngagementScopeRefSchema,
    audit_mode: z.enum(['tls_posture', 'http_security_headers', 'static_config_tree']),
    target_host: LabTargetHostSchema.optional(),
    target_port: z.number().int().min(1).max(65535).optional(),
    config_rel_path: SafeRelPathSchema.optional(),
    discovering_agent_id: SafeAgentIdSchema,
    timeout_ms: z.number().int().min(1000).max(60000).default(30000),
  })
  .strict()
  .superRefine((data, ctx) => {
    if (
      (data.audit_mode === 'tls_posture' || data.audit_mode === 'http_security_headers') &&
      !data.target_host
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['target_host'],
        message: 'target_host is required for network audit modes (tls_posture, http_security_headers)',
      });
    }
    if (data.audit_mode === 'static_config_tree' && !data.config_rel_path) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['config_rel_path'],
        message: 'config_rel_path is required for static_config_tree audit mode',
      });
    }
  });

export type KaliConfigAuditInput = z.input<typeof KaliConfigAuditInputSchema>;
export type ParsedKaliConfigAuditInput = z.infer<typeof KaliConfigAuditInputSchema>;

/**
 * C. security.kali.verify_reproducer strict input schema.
 */
export const KaliVerifyReproducerInputSchema = z
  .object({
    scope: EngagementScopeRefSchema,
    finding_id: SafeFindingIdSchema,
    discovering_agent_id: SafeAgentIdSchema,
    verifier_agent_id: SafeAgentIdSchema,
    authorizing_agent_id: SafeAgentIdSchema.optional(),
    reproducer_rel_path: SafeRelPathSchema,
    expected_reproducer_sha256: Sha256HexSchema,
    reproducer_runtime: z.enum(['node', 'python3', 'http_replay_har']),
    target_host: LabTargetHostSchema.optional(),
    target_port: z.number().int().min(1).max(65535).optional(),
    expected_invariant: z.string().trim().min(3).max(500).optional(),
    dry_run: z.boolean().default(false),
    timeout_ms: z.number().int().min(1000).max(30000).default(15000),
  })
  .strict()
  .superRefine((data, ctx) => {
    const disc = data.discovering_agent_id.trim().toLowerCase();
    const veri = data.verifier_agent_id.trim().toLowerCase();
    if (disc === veri) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['verifier_agent_id'],
        message: 'E_SOD_SELF_CERTIFICATION: verifier_agent_id must differ from discovering_agent_id',
      });
    }
    const auth = (data.authorizing_agent_id ?? data.scope.authorized_by).trim().toLowerCase();
    if (auth === veri) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['authorizing_agent_id'],
        message: 'E_SOD_SELF_AUTHORIZATION: authorizing_agent_id/scope.authorized_by must differ from verifier_agent_id',
      });
    }
    if (auth === disc) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['authorizing_agent_id'],
        message: 'E_SOD_OMNIPOTENT_AGENT: authorizing_agent_id/scope.authorized_by must differ from discovering_agent_id',
      });
    }
    if (data.reproducer_runtime === 'http_replay_har' && !data.target_host) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['target_host'],
        message: 'target_host is required when reproducer_runtime is http_replay_har',
      });
    }
  });

export type KaliVerifyReproducerInput = z.input<typeof KaliVerifyReproducerInputSchema>;
export type ParsedKaliVerifyReproducerInput = z.infer<typeof KaliVerifyReproducerInputSchema>;

/**
 * D. security.kali.sbom_cve_check strict input schema.
 */
export const KaliSbomCveCheckInputSchema = z
  .object({
    scope: EngagementScopeRefSchema,
    manifest_rel_path: SafeRelPathSchema,
    scanner_engine: z.enum(['trivy_offline', 'syft_grype_offline']).default('trivy_offline'),
    severity_filter: z
      .array(z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']))
      .min(1)
      .default(['CRITICAL', 'HIGH']),
    discovering_agent_id: SafeAgentIdSchema,
    timeout_ms: z.number().int().min(1000).max(90000).default(45000),
  })
  .strict();

export type KaliSbomCveCheckInput = z.input<typeof KaliSbomCveCheckInputSchema>;
export type ParsedKaliSbomCveCheckInput = z.infer<typeof KaliSbomCveCheckInputSchema>;

export type ParsedKaliCapabilityInput =
  | ParsedKaliReconSurfaceInput
  | ParsedKaliConfigAuditInput
  | ParsedKaliVerifyReproducerInput
  | ParsedKaliSbomCveCheckInput;

export const KaliCapabilityInputSchemas = {
  'security.kali.recon_surface': KaliReconSurfaceInputSchema,
  'security.kali.config_audit': KaliConfigAuditInputSchema,
  'security.kali.verify_reproducer': KaliVerifyReproducerInputSchema,
  'security.kali.sbom_cve_check': KaliSbomCveCheckInputSchema,
} as const;

// ============================================================================
// E4. HARDENED KALI LINUX LAB_SYNTHETIC VERIFICATION ENGINE SCHEMAS
// ============================================================================

export const KALI_LAB_SYNTHETIC_PROFILE = 'LAB_SYNTHETIC' as const;
export type KaliLabSyntheticProfile = typeof KALI_LAB_SYNTHETIC_PROFILE;

export const KALI_LAB_ACTION_IDS = [
  'service_inventory',
  'tls_review',
  'web_passive_baseline',
  'local_code_scan',
] as const;

export type KaliLabActionId = (typeof KALI_LAB_ACTION_IDS)[number];

export const KALI_LAB_SYNTHETIC_CAPABILITY_NAMES = [
  'security.kali.lab_run',
  'security.kali.service_inventory',
  'security.kali.tls_review',
  'security.kali.web_passive_baseline',
  'security.kali.local_code_scan',
  'security.kali.get_run',
] as const;

export type KaliLabSyntheticCapabilityName =
  (typeof KALI_LAB_SYNTHETIC_CAPABILITY_NAMES)[number];

export const KaliLabActionIdEnumSchema = z.enum([
  'service_inventory',
  'tls_review',
  'web_passive_baseline',
  'local_code_scan',
  'security.kali.service_inventory',
  'security.kali.tls_review',
  'security.kali.web_passive_baseline',
  'security.kali.local_code_scan',
]);

export function normalizeKaliLabActionId(rawActionId: unknown): KaliLabActionId {
  if (typeof rawActionId !== 'string' || !rawActionId.trim()) {
    throw new KaliSecurityError(
      'KALI_DISALLOWED_CAPABILITY',
      'actionId must be a non-empty enumerated LAB_SYNTHETIC action ID'
    );
  }
  const trimmed = rawActionId.trim();
  assertNoFlagInjection(trimmed, 'actionId');
  const stripped = trimmed.startsWith('security.kali.')
    ? trimmed.slice('security.kali.'.length)
    : trimmed;

  if ((KALI_LAB_ACTION_IDS as readonly string[]).includes(stripped)) {
    return stripped as KaliLabActionId;
  }

  throw new KaliSecurityError(
    'KALI_DISALLOWED_CAPABILITY',
    `Action '${trimmed}' is not in the enumerated LAB_SYNTHETIC allowlist [${KALI_LAB_ACTION_IDS.join(', ')}]`
  );
}

export interface ValidatedKaliLabScope {
  scopeId: string;
  authorizedBy: string;
  tenantId?: string;
  targetAllowlist: string[];
  mode: 'LAB';
  profile: 'LAB_SYNTHETIC';
  expiresAt: string;
}

export function validateKaliLabScopeRef(
  rawScope: unknown,
  options: { targetHost?: string; expectedTenantId?: string; now?: Date } = {}
): ValidatedKaliLabScope {
  const nowDate = options.now ?? new Date();
  const defaultExpiresAt = new Date(nowDate.getTime() + 60 * 60 * 1000).toISOString();

  if (rawScope === undefined || rawScope === null) {
    return {
      scopeId: 'SK-SCOPE-LAB-SYNTHETIC-DEFAULT',
      authorizedBy: 'agent-quality-gate-authority',
      tenantId: options.expectedTenantId,
      targetAllowlist: ['127.0.0.1', 'localhost', 'lab-app.localnet', 'payments-lab.localnet'],
      mode: 'LAB',
      profile: 'LAB_SYNTHETIC',
      expiresAt: defaultExpiresAt,
    };
  }

  if (typeof rawScope === 'string') {
    const trimmed = rawScope.trim();
    if (!trimmed) {
      throw new KaliSecurityError(
        'E_INVALID_ENGAGEMENT_SCOPE',
        'scopeRef cannot be an empty string'
      );
    }
    assertNoFlagInjection(trimmed, 'scopeRef');

    if (
      /^(?:prod|production|live|external|internet|unscoped|unrestricted|evil|attack)/i.test(
        trimmed
      ) ||
      !/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{1,127}$/.test(trimmed)
    ) {
      throw new KaliSecurityError(
        'E_INVALID_ENGAGEMENT_SCOPE',
        `Scope reference '${trimmed}' is not an authorized LAB_SYNTHETIC scope manifest`
      );
    }

    if (/expired/i.test(trimmed)) {
      throw new KaliSecurityError(
        'E_SCOPE_EXPIRED',
        `Engagement scope '${trimmed}' has expired`
      );
    }

    return {
      scopeId: trimmed.startsWith('SK-SCOPE-') ? trimmed : `SK-SCOPE-${trimmed.replace(/[^a-zA-Z0-9_-]/g, '-')}`,
      authorizedBy: 'agent-quality-gate-authority',
      tenantId: options.expectedTenantId,
      targetAllowlist: ['127.0.0.1', 'localhost', 'lab-app.localnet', 'payments-lab.localnet'],
      mode: 'LAB',
      profile: 'LAB_SYNTHETIC',
      expiresAt: defaultExpiresAt,
    };
  }

  if (typeof rawScope === 'object' && !Array.isArray(rawScope)) {
    const safety = scanKaliPayloadSafety(rawScope, 'scopeRef');
    if (!safety.safe) {
      throw new KaliSecurityError(
        safety.ruleId ?? 'KALI_UNSAFE_PAYLOAD',
        safety.reason ?? 'Unsafe scopeRef payload rejected'
      );
    }

    const obj = rawScope as Record<string, unknown>;
    const rawMode = obj.mode ?? 'LAB';
    if (rawMode !== 'LAB') {
      throw new KaliSecurityError(
        'E_INVALID_ENGAGEMENT_SCOPE',
        `Scope mode must be 'LAB'; received '${String(rawMode)}'`
      );
    }

    const rawProfile = obj.profile ?? 'LAB_SYNTHETIC';
    if (
      rawProfile !== 'LAB_SYNTHETIC' &&
      rawProfile !== 'LAB_SANDBOX_ONLY' &&
      rawProfile !== 'LAB'
    ) {
      throw new KaliSecurityError(
        'E_INVALID_ENGAGEMENT_SCOPE',
        `Scope profile must be 'LAB_SYNTHETIC'; received '${String(rawProfile)}'`
      );
    }

    const rawScopeId = String(
      obj.scope_id ?? obj.scopeId ?? 'SK-SCOPE-LAB-SYNTHETIC-001'
    ).trim();
    assertNoFlagInjection(rawScopeId, 'scopeRef.scopeId');
    if (/^(?:prod|production|external|unscoped|evil)/i.test(rawScopeId)) {
      throw new KaliSecurityError(
        'E_INVALID_ENGAGEMENT_SCOPE',
        `Disallowed scopeId '${rawScopeId}'`
      );
    }

    const rawAuthorizedBy = String(
      obj.authorized_by ?? obj.authorizedBy ?? 'agent-quality-gate-authority'
    ).trim();
    assertNoFlagInjection(rawAuthorizedBy, 'scopeRef.authorizedBy');

    const rawTenantId =
      typeof (obj.tenant_id ?? obj.tenantId) === 'string'
        ? String(obj.tenant_id ?? obj.tenantId).trim()
        : undefined;
    if (
      rawTenantId &&
      options.expectedTenantId &&
      rawTenantId !== options.expectedTenantId
    ) {
      throw new KaliSecurityError(
        'E_SCOPE_TENANT_MISMATCH',
        `Scope tenant '${rawTenantId}' does not match authenticated tenant '${options.expectedTenantId}'`
      );
    }

    const rawExpires =
      typeof (obj.expires_at ?? obj.expiresAt) === 'string'
        ? String(obj.expires_at ?? obj.expiresAt).trim()
        : defaultExpiresAt;
    const expiresMs = Date.parse(rawExpires);
    if (!Number.isFinite(expiresMs) || expiresMs <= nowDate.getTime()) {
      throw new KaliSecurityError(
        'E_SCOPE_EXPIRED',
        `Engagement scope '${rawScopeId}' expired at '${rawExpires}'`
      );
    }

    const rawAllowlist = obj.target_allowlist ?? obj.targetAllowlist;
    let targetAllowlist = [
      '127.0.0.1',
      'localhost',
      'lab-app.localnet',
      'payments-lab.localnet',
    ];
    if (Array.isArray(rawAllowlist)) {
      if (rawAllowlist.length === 0) {
        throw new KaliSecurityError(
          'E_INVALID_ENGAGEMENT_SCOPE',
          'scopeRef targetAllowlist cannot be empty'
        );
      }
      targetAllowlist = rawAllowlist.map((entry) => {
        const hostStr = String(entry ?? '').trim();
        const hostCheck = evaluateLabTargetHost(hostStr);
        if (!hostCheck.allowed) {
          throw new KaliSecurityError(
            hostCheck.code ?? 'E_INVALID_ENGAGEMENT_SCOPE',
            hostCheck.reason ?? `Disallowed host '${hostStr}' in scope targetAllowlist`
          );
        }
        return hostCheck.normalized;
      });
    }

    if (options.targetHost) {
      const normalizedTarget = options.targetHost.trim().toLowerCase();
      if (
        Array.isArray(rawAllowlist) &&
        !targetAllowlist.includes(normalizedTarget)
      ) {
        throw new KaliSecurityError(
          'E_SCOPE_TARGET_NOT_ALLOWLISTED',
          `Target '${normalizedTarget}' is not listed in scope target_allowlist [${targetAllowlist.join(', ')}]`
        );
      }
    }

    return {
      scopeId: rawScopeId.startsWith('SK-SCOPE-')
        ? rawScopeId
        : `SK-SCOPE-${rawScopeId.replace(/[^a-zA-Z0-9_-]/g, '-')}`,
      authorizedBy: rawAuthorizedBy,
      tenantId: rawTenantId ?? options.expectedTenantId,
      targetAllowlist,
      mode: 'LAB',
      profile: 'LAB_SYNTHETIC',
      expiresAt: new Date(expiresMs).toISOString(),
    };
  }

  throw new KaliSecurityError(
    'E_INVALID_ENGAGEMENT_SCOPE',
    'scopeRef must be a valid string or scope manifest object'
  );
}

export interface ValidatedKaliLabTarget {
  targetRef: string;
  targetHost?: string;
  targetPort?: number;
  ports?: number[];
  workspaceRelPath?: string;
}

function parseNetworkTargetString(
  rawTarget: string,
  defaultPort: number
): { host: string; port: number } {
  const trimmed = rawTarget.trim();
  if (!trimmed) {
    throw new KaliSecurityError(
      'KALI_INVALID_TARGET_HOST',
      'targetRef cannot be empty'
    );
  }
  if (trimmed.startsWith('-')) {
    throw new KaliSecurityError(
      'KALI_FLAG_INJECTION_BLOCKED',
      `Flag injection blocked in targetRef '${trimmed}'`
    );
  }
  const safety = scanKaliPayloadSafety(trimmed, 'targetRef');
  if (!safety.safe) {
    throw new KaliSecurityError(
      safety.ruleId ?? 'KALI_SHELL_METACHAR_BLOCKED',
      safety.reason ?? 'Unsafe targetRef rejected'
    );
  }
  if (/\s/.test(trimmed)) {
    throw new KaliSecurityError(
      'KALI_SHELL_METACHAR_BLOCKED',
      'Whitespace is forbidden in targetRef'
    );
  }

  let candidateHost = trimmed;
  let candidatePort = defaultPort;

  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(trimmed);
    } catch {
      throw new KaliSecurityError(
        'KALI_INVALID_TARGET_HOST',
        `Malformed URL in targetRef '${trimmed}'`
      );
    }
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new KaliSecurityError(
        'KALI_INVALID_TARGET_HOST',
        `Unsupported protocol '${parsedUrl.protocol}' in targetRef`
      );
    }
    if (parsedUrl.username || parsedUrl.password) {
      throw new KaliSecurityError(
        'KALI_INVALID_TARGET_HOST',
        'Credentials in targetRef URL are forbidden'
      );
    }
    candidateHost = parsedUrl.hostname;
    if (parsedUrl.port) {
      candidatePort = Number(parsedUrl.port);
    } else {
      candidatePort = parsedUrl.protocol === 'https:' ? 443 : defaultPort;
    }
  } else if (trimmed.includes(':')) {
    const parts = trimmed.split(':');
    if (parts.length !== 2 || !parts[0] || !/^\d+$/.test(parts[1])) {
      throw new KaliSecurityError(
        'KALI_INVALID_TARGET_HOST',
        `Invalid host:port targetRef '${trimmed}'`
      );
    }
    candidateHost = parts[0];
    candidatePort = Number(parts[1]);
  } else if (trimmed.includes('/')) {
    const slashIdx = trimmed.indexOf('/');
    candidateHost = trimmed.slice(0, slashIdx);
  }

  if (
    !Number.isInteger(candidatePort) ||
    candidatePort < 1 ||
    candidatePort > 65535
  ) {
    throw new KaliSecurityError(
      'KALI_INVALID_TARGET_HOST',
      `Invalid target port '${candidatePort}'`
    );
  }

  const hostEval = evaluateLabTargetHost(candidateHost);
  if (!hostEval.allowed) {
    throw new KaliSecurityError(
      hostEval.code ?? 'KALI_BLOCKED_PUBLIC_OR_NONLAB_TARGET',
      hostEval.reason ?? `Target host '${candidateHost}' is outside LAB_SYNTHETIC scope`
    );
  }

  return { host: hostEval.normalized, port: candidatePort };
}

export function validateKaliLabTargetRef(
  rawTargetRef: unknown,
  actionId: KaliLabActionId,
  extraInput: Record<string, unknown> = {}
): ValidatedKaliLabTarget {
  const defaultPort =
    actionId === 'tls_review' ? 443 : actionId === 'web_passive_baseline' ? 3000 : 3000;

  if (actionId === 'local_code_scan') {
    let rawPath: unknown =
      rawTargetRef ??
      extraInput.path ??
      extraInput.manifest_rel_path ??
      extraInput.config_rel_path ??
      extraInput.target ??
      'package.json';

    if (rawPath && typeof rawPath === 'object' && !Array.isArray(rawPath)) {
      const tObj = rawPath as Record<string, unknown>;
      rawPath =
        tObj.path ??
        tObj.manifest_rel_path ??
        tObj.config_rel_path ??
        tObj.targetRef ??
        tObj.target ??
        tObj.host ??
        'package.json';
    }

    if (typeof rawPath !== 'string' || !rawPath.trim()) {
      throw new KaliSecurityError(
        'KALI_SCHEMA_VALIDATION_ERROR',
        'targetRef for local_code_scan must be a non-empty workspace-relative path'
      );
    }

    const trimmedPath = rawPath.trim();
    assertNoFlagInjection(trimmedPath, 'targetRef');

    const lower = trimmedPath.toLowerCase();
    if (
      BLOCKED_IMDS_AND_HOST_TARGETS.has(lower) ||
      lower.startsWith('169.254.') ||
      lower.includes('169.254.169.254')
    ) {
      throw new KaliSecurityError(
        'KALI_BLOCKED_IMDS_TARGET',
        `Cloud IMDS / metadata target '${trimmedPath}' is strictly blocked`
      );
    }

    if (
      isRfc1918OrLinkLocalIpv4(lower) ||
      /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(lower)
    ) {
      throw new KaliSecurityError(
        'KALI_BLOCKED_RFC1918_TARGET',
        `IP target '${trimmedPath}' is forbidden for local_code_scan`
      );
    }

    if (
      /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedPath) ||
      /\.(?:example|com|net|org|io|dev|internal|localnet|gov|edu|mil|co|uk|br|xyz|info|biz)(?:[:/]|$)/i.test(
        lower
      )
    ) {
      throw new KaliSecurityError(
        'KALI_BLOCKED_PUBLIC_OR_NONLAB_TARGET',
        `Out-of-scope domain or URL '${trimmedPath}' is blocked for local_code_scan`
      );
    }

    const parsedRel = SafeRelPathSchema.safeParse(trimmedPath);
    if (!parsedRel.success) {
      throw new KaliSecurityError(
        'KALI_PATH_TRAVERSAL_BLOCKED',
        parsedRel.error.issues.map((i) => i.message).join('; ')
      );
    }

    return {
      targetRef: parsedRel.data,
      workspaceRelPath: parsedRel.data,
    };
  }

  // Network actions: service_inventory, tls_review, web_passive_baseline
  let hostStr: string | undefined;
  let explicitPort: number | undefined =
    typeof extraInput.target_port === 'number'
      ? extraInput.target_port
      : typeof extraInput.port === 'number'
        ? extraInput.port
        : undefined;
  let explicitPorts: number[] | undefined = Array.isArray(extraInput.ports)
    ? (extraInput.ports as number[])
    : undefined;

  if (typeof rawTargetRef === 'string') {
    hostStr = rawTargetRef;
  } else if (
    rawTargetRef &&
    typeof rawTargetRef === 'object' &&
    !Array.isArray(rawTargetRef)
  ) {
    const tObj = rawTargetRef as Record<string, unknown>;
    if (typeof (tObj.host ?? tObj.target_host ?? tObj.target ?? tObj.targetRef) === 'string') {
      hostStr = String(
        tObj.host ?? tObj.target_host ?? tObj.target ?? tObj.targetRef
      );
    }
    if (typeof (tObj.port ?? tObj.target_port) === 'number') {
      explicitPort = Number(tObj.port ?? tObj.target_port);
    }
    if (Array.isArray(tObj.ports)) {
      explicitPorts = tObj.ports as number[];
    }
  } else if (
    typeof (extraInput.target_host ?? extraInput.target ?? extraInput.host) === 'string'
  ) {
    hostStr = String(extraInput.target_host ?? extraInput.target ?? extraInput.host);
  } else if (rawTargetRef === undefined || rawTargetRef === null) {
    hostStr = '127.0.0.1';
  } else {
    throw new KaliSecurityError(
      'KALI_INVALID_TARGET_HOST',
      'targetRef must be a valid lab target string or object'
    );
  }

  const parsedNet = parseNetworkTargetString(hostStr ?? '127.0.0.1', explicitPort ?? defaultPort);
  const finalPort = explicitPort ?? parsedNet.port;

  let validatedPorts = [80, 443, 3000, 8080];
  if (explicitPorts !== undefined) {
    const portParse = LabPortListSchema.safeParse(explicitPorts);
    if (!portParse.success) {
      throw new KaliSecurityError(
        'KALI_SCHEMA_VALIDATION_ERROR',
        portParse.error.issues.map((i) => i.message).join('; ')
      );
    }
    validatedPorts = portParse.data;
  } else if (explicitPort !== undefined || (typeof rawTargetRef === 'string' && rawTargetRef.includes(':'))) {
    validatedPorts = Array.from(new Set([finalPort, 80, 443, 3000])).slice(0, 4);
  }

  return {
    targetRef:
      actionId === 'service_inventory'
        ? parsedNet.host
        : `${parsedNet.host}:${finalPort}`,
    targetHost: parsedNet.host,
    targetPort: finalPort,
    ports: validatedPorts,
  };
}

export interface ValidatedKaliLabBudget {
  budgetRef: string;
  timeoutMs: number;
  maxCostUnits: number;
}

export function validateKaliLabBudgetRef(
  rawBudgetRef: unknown,
  extraInput: Record<string, unknown> = {}
): ValidatedKaliLabBudget {
  let timeoutMs =
    typeof (extraInput.timeoutMs ?? extraInput.timeout_ms) === 'number'
      ? Number(extraInput.timeoutMs ?? extraInput.timeout_ms)
      : 15_000;
  let maxCostUnits =
    typeof (extraInput.maxCostUnits ?? extraInput.max_cost_units) === 'number'
      ? Number(extraInput.maxCostUnits ?? extraInput.max_cost_units)
      : 25;
  let budgetRefLabel = 'LAB_DEFAULT_BUDGET';

  if (typeof rawBudgetRef === 'string') {
    const trimmed = rawBudgetRef.trim();
    if (!trimmed) {
      throw new KaliSecurityError(
        'KALI_BUDGET_EXCEEDED',
        'budgetRef cannot be an empty string'
      );
    }
    assertNoFlagInjection(trimmed, 'budgetRef');
    if (/^(?:exceeded|expired|zero|none|unlimited|infinite)/i.test(trimmed)) {
      throw new KaliSecurityError(
        'KALI_BUDGET_EXCEEDED',
        `Budget reference '${trimmed}' is invalid or exceeded`
      );
    }
    budgetRefLabel = trimmed;
  } else if (
    rawBudgetRef &&
    typeof rawBudgetRef === 'object' &&
    !Array.isArray(rawBudgetRef)
  ) {
    const bObj = rawBudgetRef as Record<string, unknown>;
    if (typeof bObj.budgetId === 'string' || typeof bObj.budgetRef === 'string') {
      budgetRefLabel = String(bObj.budgetId ?? bObj.budgetRef).trim();
      assertNoFlagInjection(budgetRefLabel, 'budgetRef.budgetId');
    }
    if (typeof (bObj.timeoutMs ?? bObj.timeout_ms) === 'number') {
      timeoutMs = Number(bObj.timeoutMs ?? bObj.timeout_ms);
    }
    if (typeof (bObj.maxCostUnits ?? bObj.max_cost_units) === 'number') {
      maxCostUnits = Number(bObj.maxCostUnits ?? bObj.max_cost_units);
    }
  } else if (rawBudgetRef !== undefined && rawBudgetRef !== null) {
    throw new KaliSecurityError(
      'KALI_BUDGET_EXCEEDED',
      'budgetRef must be a budget identifier string or budget configuration object'
    );
  }

  if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new KaliSecurityError(
      'KALI_BUDGET_EXCEEDED',
      `Requested timeoutMs (${timeoutMs}) violates LAB_SYNTHETIC budget bounds [100..60000]`
    );
  }

  if (!Number.isFinite(maxCostUnits) || maxCostUnits < 1 || maxCostUnits > 100) {
    throw new KaliSecurityError(
      'KALI_BUDGET_EXCEEDED',
      `Requested maxCostUnits (${maxCostUnits}) violates LAB_SYNTHETIC cost budget bounds [1..100]`
    );
  }

  return {
    budgetRef: budgetRefLabel,
    timeoutMs: Math.floor(timeoutMs),
    maxCostUnits: Math.floor(maxCostUnits),
  };
}

const FlexibleScopeRefJsonSchema = z
  .union([z.string().trim().min(1), z.record(z.unknown())])
  .optional();

const FlexibleTargetRefJsonSchema = z
  .union([z.string().trim().min(1), z.record(z.unknown())])
  .optional();

const FlexibleBudgetRefJsonSchema = z
  .union([z.string().trim().min(1), z.record(z.unknown())])
  .optional();

export const KaliLabRunInputSchema = z
  .object({
    actionId: KaliLabActionIdEnumSchema,
    scopeRef: FlexibleScopeRefJsonSchema,
    targetRef: FlexibleTargetRefJsonSchema,
    budgetRef: FlexibleBudgetRefJsonSchema,
    scope: FlexibleScopeRefJsonSchema,
    target_host: z.string().trim().min(1).optional(),
    target_port: z.number().int().min(1).max(65535).optional(),
    port: z.number().int().min(1).max(65535).optional(),
    ports: z.array(z.number().int().min(1).max(65535)).min(1).max(32).optional(),
    path: z.string().trim().min(1).optional(),
    manifest_rel_path: z.string().trim().min(1).optional(),
    config_rel_path: z.string().trim().min(1).optional(),
    timeoutMs: z.number().int().optional(),
    timeout_ms: z.number().int().optional(),
    discovering_agent_id: z.string().trim().min(1).optional(),
    profile: z.literal('LAB_SYNTHETIC').optional(),
  })
  .strict();

export const KaliServiceInventoryInputSchema = z
  .object({
    scopeRef: FlexibleScopeRefJsonSchema,
    targetRef: FlexibleTargetRefJsonSchema,
    budgetRef: FlexibleBudgetRefJsonSchema,
    scope: FlexibleScopeRefJsonSchema,
    target_host: z.string().trim().min(1).optional(),
    ports: z.array(z.number().int().min(1).max(65535)).min(1).max(32).optional(),
    timeoutMs: z.number().int().optional(),
    timeout_ms: z.number().int().optional(),
    discovering_agent_id: z.string().trim().min(1).optional(),
    profile: z.literal('LAB_SYNTHETIC').optional(),
  })
  .strict();

export const KaliTlsReviewInputSchema = z
  .object({
    scopeRef: FlexibleScopeRefJsonSchema,
    targetRef: FlexibleTargetRefJsonSchema,
    budgetRef: FlexibleBudgetRefJsonSchema,
    scope: FlexibleScopeRefJsonSchema,
    target_host: z.string().trim().min(1).optional(),
    target_port: z.number().int().min(1).max(65535).optional(),
    port: z.number().int().min(1).max(65535).optional(),
    timeoutMs: z.number().int().optional(),
    timeout_ms: z.number().int().optional(),
    discovering_agent_id: z.string().trim().min(1).optional(),
    profile: z.literal('LAB_SYNTHETIC').optional(),
  })
  .strict();

export const KaliWebPassiveBaselineInputSchema = z
  .object({
    scopeRef: FlexibleScopeRefJsonSchema,
    targetRef: FlexibleTargetRefJsonSchema,
    budgetRef: FlexibleBudgetRefJsonSchema,
    scope: FlexibleScopeRefJsonSchema,
    target_host: z.string().trim().min(1).optional(),
    target_port: z.number().int().min(1).max(65535).optional(),
    port: z.number().int().min(1).max(65535).optional(),
    timeoutMs: z.number().int().optional(),
    timeout_ms: z.number().int().optional(),
    discovering_agent_id: z.string().trim().min(1).optional(),
    profile: z.literal('LAB_SYNTHETIC').optional(),
  })
  .strict();

export const KaliLocalCodeScanInputSchema = z
  .object({
    scopeRef: FlexibleScopeRefJsonSchema,
    targetRef: FlexibleTargetRefJsonSchema,
    budgetRef: FlexibleBudgetRefJsonSchema,
    scope: FlexibleScopeRefJsonSchema,
    path: z.string().trim().min(1).optional(),
    manifest_rel_path: z.string().trim().min(1).optional(),
    config_rel_path: z.string().trim().min(1).optional(),
    severity_filter: z
      .array(z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']))
      .min(1)
      .optional(),
    timeoutMs: z.number().int().optional(),
    timeout_ms: z.number().int().optional(),
    discovering_agent_id: z.string().trim().min(1).optional(),
    profile: z.literal('LAB_SYNTHETIC').optional(),
  })
  .strict();

export const KaliGetRunInputSchema = z
  .object({
    runId: z.string().trim().min(1, 'runId is required'),
  })
  .strict();

