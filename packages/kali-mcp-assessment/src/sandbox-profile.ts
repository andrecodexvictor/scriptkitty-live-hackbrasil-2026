/**
 * @file packages/kali-mcp-assessment/src/sandbox-profile.ts
 * @description Isolation Profile Generators & Fail-Closed Sandbox Orchestrator:
 * - Profile A: Rootless OCI Container (`--user=65532:65532`, `--cap-drop=ALL`,
 *   `--security-opt=no-new-privileges:true`, `--read-only`, `--runtime=runsc`, `--net=none` or
 *   `lab-loopback-bridge`, immutable `@sha256:` image digest pinning).
 * - Profile B: Dedicated WSL2 Micro-VM (`scriptkitty-kali-sandbox`, `[automount] enabled = false`,
 *   `[interop] enabled = false`, `appendWindowsPath = false`).
 * - Complete host credential stripping (`AWS_*`, `GITHUB_*`, `OPENAI_*`, `TYPESAFE_*`, etc.).
 * - Fail-closed `LIVE_CONTAINER` enforcement (no host shell fallback).
 */

import { execFile as nodeExecFile } from 'node:child_process';
import * as path from 'node:path';
import { z } from 'zod';
import { sanitizeOutput } from '../../adapters/dist/index.js';
import {
  type SafeKaliArgvSpec,
  assertSafeKaliArgv,
} from './argv-builder.js';
import {
  KALI_MODE,
  type KaliExecutionMode,
  type RequestedExecutionMode,
  type SandboxNetworkMode,
  KaliSecurityError,
} from './schemas.js';

/**
 * Immutable SHA-256 pinned default Kali container image reference (no mutable `:latest` tags).
 */
export const DEFAULT_KALI_IMAGE_DIGEST =
  'kalilinux/kali-rolling@sha256:9f7a8f2f5b4e1e6e8f2c0b7a4d5c6e8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d';

export const DEFAULT_WSL2_DISTRO_NAME = 'scriptkitty-kali-sandbox';
export const DEFAULT_LAB_BRIDGE_NETWORK = 'scriptkitty-lab-internal';
export const MAX_SANDBOX_OUTPUT_BYTES = 1024 * 1024; // 1 MiB

/**
 * Enforces immutable OCI digest pinning (`<repo>@sha256:<64-hex>`).
 */
export const PinnedImageDigestSchema = z
  .string()
  .trim()
  .regex(
    /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*@sha256:[a-f0-9]{64}$/i,
    'Container image MUST be pinned by immutable @sha256:<64-hex> digest (mutable tags like :latest are forbidden)'
  );

export function assertPinnedImageDigest(imageRef: string): string {
  const parsed = PinnedImageDigestSchema.safeParse(imageRef);
  if (!parsed.success) {
    throw new KaliSecurityError(
      'KALI_UNPINNED_CONTAINER_IMAGE',
      parsed.error.issues.map((i) => i.message).join('; ')
    );
  }
  return parsed.data;
}

/**
 * Host credential prefixes & suffixes stripped from all sandboxed environments.
 */
export const STRIPPED_CREDENTIAL_ENV_PREFIXES = [
  'AWS_',
  'GITHUB_',
  'GH_',
  'CLOUDFLARE_',
  'CF_',
  'OPENAI_',
  'ANTHROPIC_',
  'CLAUDE_',
  'GOOGLE_',
  'GEMINI_',
  'NVIDIA_',
  'OPENROUTER_',
  'GROK_',
  'TYPESAFE_',
  'SLACK_',
  'DOCKER_',
  'SSH_',
  'AZ_',
  'AZURE_',
  'GCP_',
  'NPM_',
] as const;

export const STRIPPED_CREDENTIAL_ENV_EXACT = new Set<string>([
  'NPM_TOKEN',
  'NODE_AUTH_TOKEN',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'FTP_PROXY',
  'CURL_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
  'ftp_proxy',
  'curl_proxy',
  'GITHUB_TOKEN',
  'OPENAI_API_KEY',
  'TYPESAFE_API_KEY',
]);

export const STRIPPED_CREDENTIAL_SUFFIX_REGEX =
  /(?:_SECRET|_KEY|_TOKEN|_PASSWORD|_PASSWD|_CREDENTIAL|_CREDENTIALS|_AUTH)$/i;

export function isSensitiveEnvKey(key: string): boolean {
  const upper = key.trim().toUpperCase();
  if (STRIPPED_CREDENTIAL_ENV_EXACT.has(key) || STRIPPED_CREDENTIAL_ENV_EXACT.has(upper)) {
    return true;
  }
  if (STRIPPED_CREDENTIAL_ENV_PREFIXES.some((prefix) => upper.startsWith(prefix))) {
    return true;
  }
  if (STRIPPED_CREDENTIAL_SUFFIX_REGEX.test(upper)) {
    return true;
  }
  return false;
}

export interface SanitizedSandboxEnvAudit {
  sanitizedEnv: Record<string, string>;
  strippedKeys: string[];
  preservedLabDummyKeys: string[];
}

/**
 * Builds an isolated minimal environment for container/micro-VM execution.
 * Completely rejects host credential inheritance (`AWS_*`, `GITHUB_*`, `OPENAI_*`, `TYPESAFE_*`, etc.).
 * Only synthetic `lab_dummy_*` values under `LAB_*` keys may pass explicitly as test fixtures.
 */
export function buildSanitizedSandboxEnv(
  hostEnv: Record<string, string | undefined> = {},
  explicitLabOverrides: Record<string, string | undefined> = {}
): SanitizedSandboxEnvAudit {
  const strippedKeys: string[] = [];
  const preservedLabDummyKeys: string[] = [];

  for (const key of Object.keys(hostEnv)) {
    if (hostEnv[key] !== undefined) {
      strippedKeys.push(key);
    }
  }

  const sanitizedEnv: Record<string, string> = {
    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    HOME: '/tmp',
    NO_PROXY: '*',
    no_proxy: '*',
    SCRIPTKITTY_SANDBOX: KALI_MODE,
    SCRIPTKITTY_OFFLINE: '1',
  };

  for (const [key, rawVal] of Object.entries(explicitLabOverrides)) {
    if (rawVal === undefined) continue;
    const trimmedKey = key.trim();
    const isValidDummyFixture =
      /^LAB_[A-Z0-9_]+$/.test(trimmedKey) && rawVal.startsWith('lab_dummy_');

    if (isValidDummyFixture) {
      sanitizedEnv[trimmedKey] = rawVal;
      preservedLabDummyKeys.push(trimmedKey);
      continue;
    }

    if (isSensitiveEnvKey(trimmedKey)) {
      strippedKeys.push(trimmedKey);
      continue;
    }

    // Permit safe non-secret numeric/string lab metadata overrides
    if (/^(?:PORT|LAB_TARGET_PORT|NODE_ENV|TERM)$/.test(trimmedKey) && !/[\r\n\0]/.test(rawVal)) {
      sanitizedEnv[trimmedKey] = rawVal;
    } else {
      strippedKeys.push(trimmedKey);
    }
  }

  return {
    sanitizedEnv,
    strippedKeys: Array.from(new Set(strippedKeys)).sort(),
    preservedLabDummyKeys: preservedLabDummyKeys.sort(),
  };
}

/**
 * Profile A: Rootless OCI Container + gVisor (`--runtime=runsc`) options.
 */
export interface ProfileAOptions {
  containerBinary?: 'docker' | 'podman';
  imageDigest?: string;
  requireGvisor?: boolean;
  networkMode: SandboxNetworkMode;
  labBridgeNetwork?: string;
  workspaceRoot: string;
  offlineDbRoot?: string;
  memoryLimit?: string;
  cpusLimit?: string;
  pidsLimit?: number;
  hostEnv?: Record<string, string | undefined>;
  extraLabEnv?: Record<string, string | undefined>;
  innerSpec: SafeKaliArgvSpec;
}

export interface ProfileAConfigValidation {
  valid: boolean;
  violations: string[];
  securityFlags: {
    gvisor: boolean;
    capDropAll: boolean;
    noNewPrivileges: boolean;
    readOnlyRootfs: boolean;
    tmpfsNoexecNosuid: boolean;
    pidsLimited: boolean;
    memoryLimited: boolean;
    cpuLimited: boolean;
    nonRootUser65532: boolean;
    networkIsolated: boolean;
    workspaceReadOnly: boolean;
    pinnedDigest: boolean;
  };
}

/**
 * Validates any mount host path to ensure host credentials/sockets are never mounted into sandbox.
 */
function assertSafeHostMountPath(hostPath: string): string {
  const normalized = path.resolve(hostPath);
  const lower = normalized.replace(/\\/g, '/').toLowerCase();
  if (
    lower.includes('/.ssh') ||
    lower.includes('/.aws') ||
    lower.endsWith('.env') ||
    lower.includes('/.env') ||
    lower.includes('docker.sock')
  ) {
    throw new KaliSecurityError(
      'KALI_SENSITIVE_MOUNT_BLOCKED',
      `Sensitive host path '${normalized}' cannot be mounted into sandbox container`
    );
  }
  return normalized;
}

/**
 * Generates hardened Profile A OCI container `argv` (`docker run ...` / `podman run ...`).
 */
export function generateProfileAArgs(options: ProfileAOptions): {
  binary: 'docker' | 'podman';
  args: readonly string[];
  argv: readonly string[];
  imageDigest: string;
  envAudit: SanitizedSandboxEnvAudit;
} {
  assertSafeKaliArgv(options.innerSpec.argv);
  const binary = options.containerBinary ?? 'docker';
  const imageDigest = assertPinnedImageDigest(options.imageDigest ?? DEFAULT_KALI_IMAGE_DIGEST);
  const requireGvisor = options.requireGvisor !== false;
  const safeWorkspaceRoot = assertSafeHostMountPath(options.workspaceRoot);

  const memoryLimit = options.memoryLimit ?? '1024m';
  const cpusLimit = options.cpusLimit ?? '1.0';
  const pidsLimit = Math.min(Math.max(16, options.pidsLimit ?? 64), 128);

  const envAudit = buildSanitizedSandboxEnv(options.hostEnv, options.extraLabEnv);

  const args: string[] = [
    'run',
    '--rm',
    '--init',
    ...(requireGvisor ? ['--runtime=runsc'] : []),
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges:true',
    '--read-only',
    '--tmpfs',
    '/tmp:rw,noexec,nosuid,size=64m',
    `--pids-limit=${pidsLimit}`,
    `--memory=${memoryLimit}`,
    `--cpus=${cpusLimit}`,
    '--user=65532:65532',
  ];

  if (options.networkMode === 'airgapped') {
    args.push('--net=none');
  } else {
    const netName = (options.labBridgeNetwork ?? DEFAULT_LAB_BRIDGE_NETWORK).trim();
    if (!/^[a-zA-Z0-9._-]+$/.test(netName) || netName === 'host' || netName === 'bridge') {
      throw new KaliSecurityError(
        'KALI_UNSAFE_NETWORK_MODE',
        `Container network '${netName}' is not an isolated internal lab bridge`
      );
    }
    args.push(`--network=${netName}`);
  }

  args.push('-v', `${safeWorkspaceRoot}:/workspace:ro`);

  if (options.offlineDbRoot) {
    const safeDbRoot = assertSafeHostMountPath(options.offlineDbRoot);
    args.push('-v', `${safeDbRoot}:/var/cache/trivy:ro`);
  }

  for (const [k, v] of Object.entries(envAudit.sanitizedEnv)) {
    args.push('-e', `${k}=${v}`);
  }

  args.push('--workdir', '/workspace');
  args.push(imageDigest);
  args.push(...options.innerSpec.argv);

  const argv = Object.freeze([binary, ...args]);
  const validation = validateProfileAArgs(argv, { requireGvisor });
  if (!validation.valid) {
    throw new KaliSecurityError(
      'KALI_PROFILE_A_VALIDATION_FAILED',
      validation.violations.join('; ')
    );
  }

  return {
    binary,
    args: Object.freeze(args),
    argv,
    imageDigest,
    envAudit,
  };
}

/**
 * Audits a Profile A OCI `argv` array against all containment invariants.
 */
export function validateProfileAArgs(
  argv: readonly string[],
  options: { requireGvisor?: boolean } = {}
): ProfileAConfigValidation {
  const violations: string[] = [];
  const requireGvisor = options.requireGvisor !== false;

  const hasArg = (exact: string) => argv.includes(exact);
  const gvisor = hasArg('--runtime=runsc');
  const capDropAll = hasArg('--cap-drop=ALL');
  const noNewPrivileges = hasArg('--security-opt=no-new-privileges:true');
  const readOnlyRootfs = hasArg('--read-only');
  const nonRootUser65532 = hasArg('--user=65532:65532');
  const pidsLimited = argv.some((a) => /^--pids-limit=\d+$/.test(a));
  const memoryLimited = argv.some((a) => /^--memory=\d+[mk]$/i.test(a));
  const cpuLimited = argv.some((a) => /^--cpus=\d+(?:\.\d+)?$/.test(a));

  const tmpIdx = argv.indexOf('--tmpfs');
  const tmpfsNoexecNosuid =
    tmpIdx !== -1 &&
    typeof argv[tmpIdx + 1] === 'string' &&
    argv[tmpIdx + 1].includes('noexec') &&
    argv[tmpIdx + 1].includes('nosuid');

  const networkIsolated =
    hasArg('--net=none') ||
    hasArg('--network=none') ||
    argv.some(
      (a) =>
        /^--(?:net|network)=[a-zA-Z0-9._-]+$/.test(a) &&
        a !== '--net=host' &&
        a !== '--network=host' &&
        a !== '--net=bridge' &&
        a !== '--network=bridge'
    );

  // Inspect mounts for `:rw`, `docker.sock`, `.ssh`, `.aws`, `.env`
  let workspaceReadOnly = false;
  for (let i = 0; i < argv.length - 1; i++) {
    if (argv[i] === '-v' || argv[i] === '--volume') {
      const mountSpec = argv[i + 1];
      if (mountSpec.includes(':/workspace:ro')) {
        workspaceReadOnly = true;
      }
      if (!mountSpec.endsWith(':ro')) {
        violations.push(`Volume mount must be read-only (:ro): ${mountSpec}`);
      }
      if (/(?:docker\.sock|\.ssh|\.aws|\.env)/i.test(mountSpec)) {
        violations.push(`Forbidden sensitive mount detected: ${mountSpec}`);
      }
    }
    if (argv[i] === '-e') {
      const envEntry = argv[i + 1] ?? '';
      const eqIdx = envEntry.indexOf('=');
      const envKey = eqIdx > 0 ? envEntry.slice(0, eqIdx) : envEntry;
      const envVal = eqIdx > 0 ? envEntry.slice(eqIdx + 1) : '';
      if (isSensitiveEnvKey(envKey) && !envVal.startsWith('lab_dummy_')) {
        violations.push(`Sensitive credential env var injected into sandbox: ${envKey}`);
      }
    }
  }

  if (hasArg('--privileged')) {
    violations.push('Privileged container mode (--privileged) is strictly forbidden');
  }
  if (hasArg('--net=host') || hasArg('--network=host')) {
    violations.push('Host networking (--net=host) is strictly forbidden');
  }

  const pinnedDigest = argv.some((a) => PinnedImageDigestSchema.safeParse(a).success);
  if (!pinnedDigest) {
    violations.push('No @sha256 pinned container image digest found in OCI argv');
  }

  if (requireGvisor && !gvisor) violations.push('Missing --runtime=runsc gVisor sandbox flag');
  if (!capDropAll) violations.push('Missing --cap-drop=ALL');
  if (!noNewPrivileges) violations.push('Missing --security-opt=no-new-privileges:true');
  if (!readOnlyRootfs) violations.push('Missing --read-only root filesystem');
  if (!tmpfsNoexecNosuid) violations.push('Missing hardened noexec,nosuid /tmp tmpfs mount');
  if (!pidsLimited) violations.push('Missing --pids-limit containment');
  if (!memoryLimited) violations.push('Missing --memory containment');
  if (!cpuLimited) violations.push('Missing --cpus containment');
  if (!nonRootUser65532) violations.push('Missing --user=65532:65532 unprivileged UID/GID');
  if (!networkIsolated) violations.push('Missing isolated network mode (--net=none or lab bridge)');
  if (!workspaceReadOnly) violations.push('Missing read-only :/workspace:ro bind mount');

  return {
    valid: violations.length === 0,
    violations,
    securityFlags: {
      gvisor,
      capDropAll,
      noNewPrivileges,
      readOnlyRootfs,
      tmpfsNoexecNosuid,
      pidsLimited,
      memoryLimited,
      cpuLimited,
      nonRootUser65532,
      networkIsolated,
      workspaceReadOnly,
      pinnedDigest,
    },
  };
}

/**
 * Profile B: Dedicated WSL2 Micro-VM Configuration & `/etc/wsl.conf` generator/validator.
 */
export interface ProfileBWslOptions {
  distroName?: string;
  username?: string;
  automount?: boolean;
  interop?: boolean;
}

export function generateProfileBWslConf(options: ProfileBWslOptions = {}): string {
  if (options.automount === true) {
    throw new KaliSecurityError(
      'KALI_PROFILE_B_UNSAFE_AUTOMOUNT',
      'Profile B WSL2 micro-VM requires automount=false'
    );
  }
  if (options.interop === true) {
    throw new KaliSecurityError(
      'KALI_PROFILE_B_UNSAFE_INTEROP',
      'Profile B WSL2 micro-VM requires interop=false'
    );
  }
  const user = (options.username ?? 'nobody').trim();
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(user) || user === 'root') {
    throw new KaliSecurityError(
      'KALI_PROFILE_B_UNSAFE_USER',
      'Profile B WSL2 micro-VM requires a valid non-root default user'
    );
  }

  return [
    '[automount]',
    'enabled = false',
    'mountFsTab = false',
    '',
    '[interop]',
    'enabled = false',
    'appendWindowsPath = false',
    '',
    '[user]',
    `default = ${user}`,
    '',
  ].join('\n');
}

export function validateProfileBWslConf(confText: string): {
  valid: boolean;
  automountDisabled: boolean;
  interopDisabled: boolean;
  appendWindowsPathDisabled: boolean;
  nonRootDefaultUser: boolean;
  violations: string[];
} {
  const sections: Record<string, Record<string, string>> = {};
  let currentSection = '';

  for (const rawLine of confText.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const secMatch = line.match(/^\[([^\]]+)\]$/);
    if (secMatch) {
      currentSection = secMatch[1].trim().toLowerCase();
      sections[currentSection] = sections[currentSection] ?? {};
      continue;
    }
    const kvMatch = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*(.+)$/);
    if (kvMatch && currentSection) {
      sections[currentSection][kvMatch[1].trim().toLowerCase()] = kvMatch[2].trim().toLowerCase();
    }
  }

  const automountDisabled = sections.automount?.enabled === 'false';
  const interopDisabled = sections.interop?.enabled === 'false';
  const appendWindowsPathDisabled = sections.interop?.appendwindowspath === 'false';
  const defaultUser = sections.user?.default;
  const nonRootDefaultUser = Boolean(defaultUser && defaultUser !== 'root');

  const violations: string[] = [];
  if (!automountDisabled) violations.push('wsl.conf [automount] enabled MUST be false');
  if (!interopDisabled) violations.push('wsl.conf [interop] enabled MUST be false');
  if (!appendWindowsPathDisabled) {
    violations.push('wsl.conf [interop] appendWindowsPath MUST be false');
  }
  if (!nonRootDefaultUser) violations.push('wsl.conf [user] default MUST be a non-root user');

  return {
    valid: violations.length === 0,
    automountDisabled,
    interopDisabled,
    appendWindowsPathDisabled,
    nonRootDefaultUser,
    violations,
  };
}

export function generateProfileBArgv(options: {
  distroName?: string;
  username?: string;
  innerSpec: SafeKaliArgvSpec;
}): {
  binary: 'wsl.exe';
  args: readonly string[];
  argv: readonly string[];
  distroName: string;
} {
  assertSafeKaliArgv(options.innerSpec.argv);
  const distroName = (options.distroName ?? DEFAULT_WSL2_DISTRO_NAME).trim();
  if (distroName !== DEFAULT_WSL2_DISTRO_NAME) {
    throw new KaliSecurityError(
      'KALI_PROFILE_B_UNEXPECTED_DISTRO',
      `WSL2 micro-VM distro must be dedicated '${DEFAULT_WSL2_DISTRO_NAME}', got '${distroName}'`
    );
  }
  const username = (options.username ?? 'nobody').trim();
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(username) || username === 'root') {
    throw new KaliSecurityError('KALI_PROFILE_B_UNSAFE_USER', 'WSL2 micro-VM user cannot be root');
  }

  const args = Object.freeze([
    '-d',
    distroName,
    '-u',
    username,
    '--',
    ...options.innerSpec.argv,
  ]);

  return {
    binary: 'wsl.exe',
    args,
    argv: Object.freeze(['wsl.exe', ...args]),
    distroName,
  };
}

/**
 * Minimal execFile abstraction for hermetic unit testing without shelling out.
 */
export type ExecFileLike = (
  file: string,
  args: readonly string[],
  options: {
    shell: false;
    timeout?: number;
    maxBuffer?: number;
    env?: Record<string, string>;
    cwd?: string;
    windowsHide?: boolean;
  }
) => Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut?: boolean;
}>;

export function defaultExecFileImpl(): ExecFileLike {
  return (file, args, options) => {
    return new Promise((resolve) => {
      nodeExecFile(
        file,
        [...args],
        {
          shell: false,
          timeout: options.timeout,
          maxBuffer: options.maxBuffer ?? MAX_SANDBOX_OUTPUT_BYTES * 2,
          env: options.env as NodeJS.ProcessEnv,
          cwd: options.cwd,
          windowsHide: true,
        },
        (error, stdout, stderr) => {
          const safeStdout = (typeof stdout === 'string' ? stdout : String(stdout ?? '')).slice(
            0,
            MAX_SANDBOX_OUTPUT_BYTES
          );
          const safeStderr = (typeof stderr === 'string' ? stderr : String(stderr ?? '')).slice(
            0,
            MAX_SANDBOX_OUTPUT_BYTES
          );

          if (!error) {
            resolve({ exitCode: 0, stdout: safeStdout, stderr: safeStderr, timedOut: false });
            return;
          }

          const errObj = error as NodeJS.ErrnoException & {
            killed?: boolean;
            signal?: string;
            code?: number | string;
          };
          const timedOut =
            Boolean(errObj.killed) ||
            errObj.signal === 'SIGKILL' ||
            errObj.signal === 'SIGTERM' ||
            errObj.code === 'ETIMEDOUT';

          const exitCode = timedOut
            ? 124
            : typeof errObj.code === 'number'
              ? errObj.code
              : 1;

          resolve({
            exitCode,
            stdout: safeStdout,
            stderr: safeStderr || errObj.message,
            timedOut,
          });
        }
      );
    });
  };
}

export interface SandboxRuntimeProbeResult {
  available: boolean;
  profile: 'PROFILE_A_OCI_GVISOR' | 'PROFILE_A_OCI_ROOTLESS' | 'PROFILE_B_WSL2_MICROVM' | 'NONE';
  binary?: 'docker' | 'podman' | 'wsl.exe';
  gvisorAvailable: boolean;
  imagePinnedPresent: boolean;
  wslMicroVmPresent: boolean;
  wslConfValidated: boolean;
  imageDigest: string;
  reason: string;
}

export interface SandboxProbeOptions {
  preferredProfile?: 'PROFILE_A' | 'PROFILE_B' | 'AUTO';
  containerBinary?: 'docker' | 'podman';
  imageDigest?: string;
  wslDistroName?: string;
  execFileImpl?: ExecFileLike;
}

/**
 * Probes host sandbox availability cleanly via `execFile(..., { shell: false })`.
 * Never falls back silently to host execution if no sandbox container/micro-VM is verified.
 */
export async function probeContainerSandboxRuntime(
  options: SandboxProbeOptions = {}
): Promise<SandboxRuntimeProbeResult> {
  const execFn = options.execFileImpl ?? defaultExecFileImpl();
  const preferred = options.preferredProfile ?? 'AUTO';
  const containerBin = options.containerBinary ?? 'docker';
  const imageDigest = assertPinnedImageDigest(options.imageDigest ?? DEFAULT_KALI_IMAGE_DIGEST);
  const wslDistro = options.wslDistroName ?? DEFAULT_WSL2_DISTRO_NAME;
  const probeEnv = buildSanitizedSandboxEnv().sanitizedEnv;

  if (preferred === 'AUTO' || preferred === 'PROFILE_A') {
    const infoRes = await execFn(
      containerBin,
      ['info', '--format', '{{json .}}'],
      { shell: false, timeout: 3000, maxBuffer: 256 * 1024, env: probeEnv, windowsHide: true }
    ).catch(() => ({ exitCode: 1, stdout: '', stderr: 'container runtime unavailable' }));

    if (infoRes.exitCode === 0) {
      const gvisorAvailable = infoRes.stdout.toLowerCase().includes('runsc');
      const inspectRes = await execFn(
        containerBin,
        ['image', 'inspect', '--', imageDigest],
        { shell: false, timeout: 3000, maxBuffer: 256 * 1024, env: probeEnv, windowsHide: true }
      ).catch(() => ({ exitCode: 1, stdout: '', stderr: 'digest not present locally' }));

      if (inspectRes.exitCode === 0) {
        return {
          available: true,
          profile: gvisorAvailable ? 'PROFILE_A_OCI_GVISOR' : 'PROFILE_A_OCI_ROOTLESS',
          binary: containerBin,
          gvisorAvailable,
          imagePinnedPresent: true,
          wslMicroVmPresent: false,
          wslConfValidated: false,
          imageDigest,
          reason: gvisorAvailable
            ? `Verified Profile A OCI runtime (${containerBin} + gVisor runsc) with pinned digest`
            : `Verified Profile A rootless OCI runtime (${containerBin}) with pinned digest`,
        };
      }

      if (preferred === 'PROFILE_A') {
        return {
          available: false,
          profile: 'NONE',
          gvisorAvailable,
          imagePinnedPresent: false,
          wslMicroVmPresent: false,
          wslConfValidated: false,
          imageDigest,
          reason: `Container engine reachable, but pinned image digest '${imageDigest}' is not pulled/verified locally`,
        };
      }
    }
  }

  if (preferred === 'AUTO' || preferred === 'PROFILE_B') {
    const listRes = await execFn(
      'wsl.exe',
      ['--list', '--quiet'],
      { shell: false, timeout: 3000, maxBuffer: 64 * 1024, env: probeEnv, windowsHide: true }
    ).catch(() => ({ exitCode: 1, stdout: '', stderr: 'wsl.exe unavailable' }));

    const normalizedDistros = listRes.stdout
      .replace(/\0/g, '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (listRes.exitCode === 0 && normalizedDistros.includes(wslDistro)) {
      const confRes = await execFn(
        'wsl.exe',
        ['-d', wslDistro, '-u', 'nobody', '--', 'cat', '/etc/wsl.conf'],
        { shell: false, timeout: 3000, maxBuffer: 32 * 1024, env: probeEnv, windowsHide: true }
      ).catch(() => ({ exitCode: 1, stdout: '', stderr: 'unable to inspect /etc/wsl.conf' }));

      if (confRes.exitCode === 0) {
        const confValidation = validateProfileBWslConf(confRes.stdout);
        if (confValidation.valid) {
          return {
            available: true,
            profile: 'PROFILE_B_WSL2_MICROVM',
            binary: 'wsl.exe',
            gvisorAvailable: false,
            imagePinnedPresent: false,
            wslMicroVmPresent: true,
            wslConfValidated: true,
            imageDigest,
            reason: `Verified Profile B dedicated WSL2 micro-VM (${wslDistro}) with automount=false and interop=false`,
          };
        }
        return {
          available: false,
          profile: 'NONE',
          gvisorAvailable: false,
          imagePinnedPresent: false,
          wslMicroVmPresent: true,
          wslConfValidated: false,
          imageDigest,
          reason: `Profile B WSL2 micro-VM '${wslDistro}' failed wsl.conf safety audit: ${confValidation.violations.join('; ')}`,
        };
      }
    }
  }

  return {
    available: false,
    profile: 'NONE',
    gvisorAvailable: false,
    imagePinnedPresent: false,
    wslMicroVmPresent: false,
    wslConfValidated: false,
    imageDigest,
    reason: 'No verified rootless OCI+gVisor container or hardened WSL2 micro-VM sandbox detected on host',
  };
}

export interface SandboxExecutionRequest {
  spec: SafeKaliArgvSpec;
  workspaceRoot: string;
  requestedMode?: RequestedExecutionMode;
  extraLabEnv?: Record<string, string | undefined>;
}

export interface SandboxExecutionResponse {
  ok: boolean;
  mode: typeof KALI_MODE;
  executionMode: KaliExecutionMode;
  simulated: boolean;
  profile: string;
  imageDigest: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  sandboxArgv?: readonly string[];
  failClosedReason?: string;
}

export interface KaliSandboxOrchestratorConfig {
  workspaceRoot?: string;
  imageDigest?: string;
  containerBinary?: 'docker' | 'podman';
  requireGvisorForLive?: boolean;
  preferredProfile?: 'PROFILE_A' | 'PROFILE_B' | 'AUTO';
  offlineDbRoot?: string;
  labBridgeNetwork?: string;
  hostEnv?: Record<string, string | undefined>;
  execFileImpl?: ExecFileLike;
}

/**
 * Orchestrates live sandbox execution (`LIVE_CONTAINER`) strictly when a verified
 * container or WSL2 micro-VM sandbox exists, failing closed otherwise.
 */
export class KaliSandboxOrchestrator {
  private readonly config: KaliSandboxOrchestratorConfig;
  private readonly execFileImpl: ExecFileLike;
  private readonly imageDigest: string;

  constructor(config: KaliSandboxOrchestratorConfig = {}) {
    this.config = config;
    this.execFileImpl = config.execFileImpl ?? defaultExecFileImpl();
    this.imageDigest = assertPinnedImageDigest(config.imageDigest ?? DEFAULT_KALI_IMAGE_DIGEST);
  }

  public getImageDigest(): string {
    return this.imageDigest;
  }

  public async probeRuntime(): Promise<SandboxRuntimeProbeResult> {
    return probeContainerSandboxRuntime({
      preferredProfile: this.config.preferredProfile ?? 'AUTO',
      containerBinary: this.config.containerBinary ?? 'docker',
      imageDigest: this.imageDigest,
      execFileImpl: this.execFileImpl,
    });
  }

  /**
   * Executes a pre-built SafeKaliArgvSpec in LIVE_CONTAINER mode.
   * Fail-closed: if no verified OCI+gVisor container or hardened WSL2 micro-VM is present,
   * rejects with `KALI_SANDBOX_UNAVAILABLE` rather than running directly on the host.
   */
  public async executeLive(request: SandboxExecutionRequest): Promise<SandboxExecutionResponse> {
    assertSafeKaliArgv(request.spec.argv);
    const probe = await this.probeRuntime();
    const requireGvisor = this.config.requireGvisorForLive !== false;

    if (!probe.available) {
      return {
        ok: false,
        mode: KALI_MODE,
        executionMode: 'LIVE_CONTAINER',
        simulated: false,
        profile: 'NONE',
        imageDigest: this.imageDigest,
        exitCode: 125,
        stdout: '',
        stderr: '',
        durationMs: 0,
        timedOut: false,
        failClosedReason: `KALI_SANDBOX_UNAVAILABLE: Fail closed — live container requested without verified sandbox (${probe.reason})`,
      };
    }

    if (
      probe.profile.startsWith('PROFILE_A') &&
      requireGvisor &&
      !probe.gvisorAvailable
    ) {
      return {
        ok: false,
        mode: KALI_MODE,
        executionMode: 'LIVE_CONTAINER',
        simulated: false,
        profile: probe.profile,
        imageDigest: this.imageDigest,
        exitCode: 125,
        stdout: '',
        stderr: '',
        durationMs: 0,
        timedOut: false,
        failClosedReason:
          'KALI_SANDBOX_UNAVAILABLE: Fail closed — gVisor (runsc) required for LIVE_CONTAINER Profile A',
      };
    }

    const startedMs = Date.now();
    const workspaceRoot = request.workspaceRoot || this.config.workspaceRoot || process.cwd();
    const sanitizedProcessEnv = buildSanitizedSandboxEnv(
      this.config.hostEnv ?? process.env,
      request.extraLabEnv
    ).sanitizedEnv;

    if (probe.profile === 'PROFILE_B_WSL2_MICROVM') {
      const profileB = generateProfileBArgv({
        distroName: DEFAULT_WSL2_DISTRO_NAME,
        username: 'nobody',
        innerSpec: request.spec,
      });

      const res = await this.execFileImpl(profileB.binary, profileB.args, {
        shell: false,
        timeout: request.spec.timeoutMs,
        maxBuffer: MAX_SANDBOX_OUTPUT_BYTES * 2,
        env: sanitizedProcessEnv,
        cwd: workspaceRoot,
        windowsHide: true,
      });

      const isSuccessExit =
        res.exitCode === 0 ||
        (request.spec.capability === 'security.kali.verify_reproducer' && res.exitCode === 1);

      return {
        ok: !res.timedOut && isSuccessExit,
        mode: KALI_MODE,
        executionMode: 'LIVE_CONTAINER',
        simulated: false,
        profile: 'PROFILE_B_WSL2_MICROVM',
        imageDigest: this.imageDigest,
        exitCode: res.exitCode,
        stdout: sanitizeOutput(res.stdout.slice(0, MAX_SANDBOX_OUTPUT_BYTES)),
        stderr: sanitizeOutput(res.stderr.slice(0, MAX_SANDBOX_OUTPUT_BYTES)),
        durationMs: Date.now() - startedMs,
        timedOut: Boolean(res.timedOut),
        sandboxArgv: profileB.argv,
      };
    }

    const profileA = generateProfileAArgs({
      containerBinary: (probe.binary === 'podman' ? 'podman' : 'docker'),
      imageDigest: this.imageDigest,
      requireGvisor: requireGvisor && probe.gvisorAvailable,
      networkMode: request.spec.networkMode,
      labBridgeNetwork: this.config.labBridgeNetwork,
      workspaceRoot,
      offlineDbRoot: this.config.offlineDbRoot,
      hostEnv: this.config.hostEnv ?? process.env,
      extraLabEnv: request.extraLabEnv,
      innerSpec: request.spec,
    });

    const res = await this.execFileImpl(profileA.binary, profileA.args, {
      shell: false,
      timeout: request.spec.timeoutMs,
      maxBuffer: MAX_SANDBOX_OUTPUT_BYTES * 2,
      env: sanitizedProcessEnv,
      cwd: workspaceRoot,
      windowsHide: true,
    });

    const isSuccessExitA =
      res.exitCode === 0 ||
      (request.spec.capability === 'security.kali.verify_reproducer' && res.exitCode === 1);

    return {
      ok: !res.timedOut && isSuccessExitA,
      mode: KALI_MODE,
      executionMode: 'LIVE_CONTAINER',
      simulated: false,
      profile: probe.profile,
      imageDigest: this.imageDigest,
      exitCode: res.exitCode,
      stdout: sanitizeOutput(res.stdout.slice(0, MAX_SANDBOX_OUTPUT_BYTES)),
      stderr: sanitizeOutput(res.stderr.slice(0, MAX_SANDBOX_OUTPUT_BYTES)),
      durationMs: Date.now() - startedMs,
      timedOut: Boolean(res.timedOut),
      sandboxArgv: profileA.argv,
    };
  }
}
