/**
 * @file packages/kali-mcp-assessment/src/argv-builder.ts
 * @description Zero-shell static argv builder (`buildSafeKaliArgv`) constructing immutable
 * `string[]` tuples for `execFile(..., { shell: false })` with POSIX `--` end-of-options markers,
 * binary/flag allowlists, and defense-in-depth flag-injection rejection.
 */

import {
  type KaliCapabilityName,
  type KaliConfigAuditInput,
  type KaliLabActionId,
  type KaliReconSurfaceInput,
  type KaliSbomCveCheckInput,
  type KaliVerifyReproducerInput,
  type ValidatedKaliLabBudget,
  type ValidatedKaliLabScope,
  type ValidatedKaliLabTarget,
  KaliConfigAuditInputSchema,
  KaliReconSurfaceInputSchema,
  KaliSbomCveCheckInputSchema,
  KaliVerifyReproducerInputSchema,
  KaliSecurityError,
  SHELL_METACHAR_REGEX,
  type SandboxNetworkMode,
  assertNoFlagInjection,
  assertNoShellInterpolation,
  evaluateLabTargetHost,
  normalizeKaliLabActionId,
  scanKaliPayloadSafety,
  validateKaliLabBudgetRef,
  validateKaliLabScopeRef,
  validateKaliLabTargetRef,
  verifyEngagementScope,
} from './schemas.js';

/**
 * Strictly allowlisted read-only / defensive verification binaries inside the sandbox.
 */
export const ALLOWLISTED_KALI_BINARIES = new Set<string>([
  'nmap',
  'httpx',
  'curl',
  'testssl.sh',
  'trivy',
  'syft',
  'grype',
  'lynis',
  'node',
  'python3',
]);

/**
 * Shells and offensive binaries unconditionally forbidden even as arguments or targets.
 */
export const FORBIDDEN_KALI_BINARIES = new Set<string>([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'msfconsole',
  'msfvenom',
  'metasploit',
  'sqlmap',
  'hydra',
  'hashcat',
  'john',
  'johntheripper',
  'responder',
  'mimikatz',
  'medusa',
  'hping3',
  'nc',
  'ncat',
  'socat',
]);

/**
 * Forbidden offensive/arbitrary-script CLI flags that must never appear in constructed argv tuples.
 */
export const FORBIDDEN_KALI_FLAGS = new Set<string>([
  '-sS',
  '-sU',
  '-sN',
  '-sF',
  '-sX',
  '-A',
  '-O',
  '-iL',
  '-oN',
  '-oG',
  '-oA',
  '--script',
  '--os-shell',
  '--os-pwn',
  '--exploit',
  '--dump-all',
  '--reverse-shell',
  '--bind-shell',
  '-e',
  '--eval',
  '-c',
]);

export interface SafeKaliArgvSpec {
  readonly capability: KaliCapabilityName;
  readonly binary: string;
  readonly args: readonly string[];
  readonly argv: readonly string[];
  readonly networkMode: SandboxNetworkMode;
  readonly workspaceMount: '/workspace';
  readonly readOnlyWorkspaceMount: true;
  readonly timeoutMs: number;
  readonly targetHost?: string;
  readonly targetPort?: number;
  readonly workspaceRelPath?: string;
}

export interface BuildSafeKaliArgvOptions {
  now?: Date;
  expectedTenantId?: string;
}

/**
 * Asserts defense-in-depth invariants over any built Kali `argv` tuple before execution.
 */
export function assertSafeKaliArgv(argv: readonly string[]): void {
  if (!Array.isArray(argv) || argv.length < 3) {
    throw new KaliSecurityError(
      'KALI_UNSAFE_ARGV',
      'Built argv must be a non-empty tuple containing binary, `--`, and target'
    );
  }

  const binary = argv[0];
  if (!ALLOWLISTED_KALI_BINARIES.has(binary) || FORBIDDEN_KALI_BINARIES.has(binary.toLowerCase())) {
    throw new KaliSecurityError(
      'KALI_BINARY_NOT_ALLOWLISTED',
      `Binary '${binary}' is not in the defensive verification allowlist`
    );
  }

  const dashDashIndex = argv.indexOf('--');
  if (dashDashIndex < 1 || dashDashIndex >= argv.length - 1) {
    throw new KaliSecurityError(
      'KALI_MISSING_END_OF_OPTIONS',
      'argv MUST include `--` end-of-options marker prior to positional target/path arguments'
    );
  }

  for (let i = 1; i < argv.length; i++) {
    const token = argv[i];
    if (typeof token !== 'string' || token.length === 0) {
      throw new KaliSecurityError('KALI_UNSAFE_ARGV', `Empty or non-string argv token at index ${i}`);
    }
    if (SHELL_METACHAR_REGEX.test(token) || /\s/.test(token)) {
      throw new KaliSecurityError(
        'KALI_SHELL_METACHAR_BLOCKED',
        `Shell metacharacter or whitespace detected in argv[${i}]`
      );
    }

    if (i < dashDashIndex) {
      if (FORBIDDEN_KALI_FLAGS.has(token) || token.startsWith('--script=') || token.startsWith('-oN')) {
        throw new KaliSecurityError(
          'KALI_FORBIDDEN_FLAG',
          `Forbidden flag '${token}' rejected at argv[${i}]`
        );
      }
      // If nmap uses `-oX`, strictly require stdout (`-`) only.
      if (token === '-oX' && argv[i + 1] !== '-') {
        throw new KaliSecurityError(
          'KALI_FORBIDDEN_FLAG',
          `'-oX' output target must be '-' (stdout) only`
        );
      }
    } else if (i > dashDashIndex) {
      if (token.startsWith('-')) {
        throw new KaliSecurityError(
          'KALI_FLAG_INJECTION_BLOCKED',
          `Positional argument '${token}' at argv[${i}] starts with '-' (flag injection blocked)`
        );
      }
      if (token.includes('..')) {
        throw new KaliSecurityError(
          'KALI_PATH_TRAVERSAL_BLOCKED',
          `Path traversal '..' forbidden in positional argument '${token}'`
        );
      }
    }
  }
}

function precheckStringField(
  raw: Record<string, unknown>,
  fieldName: string,
  kind: 'host' | 'path'
): void {
  const val = raw[fieldName];
  if (val === undefined) return;
  if (typeof val !== 'string') {
    throw new KaliSecurityError(
      'KALI_SCHEMA_VALIDATION_ERROR',
      `Field '${fieldName}' must be a string`
    );
  }
  const trimmed = val.trim();
  assertNoFlagInjection(trimmed, fieldName);
  if (kind === 'host') {
    const hostEval = evaluateLabTargetHost(trimmed);
    if (!hostEval.allowed) {
      throw new KaliSecurityError(
        hostEval.code ?? 'KALI_SSRF_BLOCKED',
        hostEval.reason ?? `Target host '${trimmed}' is not allowed`
      );
    }
  } else {
    assertNoShellInterpolation(trimmed, fieldName);
  }
}

/**
 * Builds a strictly static, shell-free `string[]` argv tuple for one of the 4
 * allowlisted `security.kali.*` verification capabilities.
 */
export function buildSafeKaliArgv(
  capability: 'security.kali.recon_surface',
  rawInput: KaliReconSurfaceInput | Record<string, unknown>,
  options?: BuildSafeKaliArgvOptions
): SafeKaliArgvSpec;
export function buildSafeKaliArgv(
  capability: 'security.kali.config_audit',
  rawInput: KaliConfigAuditInput | Record<string, unknown>,
  options?: BuildSafeKaliArgvOptions
): SafeKaliArgvSpec;
export function buildSafeKaliArgv(
  capability: 'security.kali.verify_reproducer',
  rawInput: KaliVerifyReproducerInput | Record<string, unknown>,
  options?: BuildSafeKaliArgvOptions
): SafeKaliArgvSpec;
export function buildSafeKaliArgv(
  capability: 'security.kali.sbom_cve_check',
  rawInput: KaliSbomCveCheckInput | Record<string, unknown>,
  options?: BuildSafeKaliArgvOptions
): SafeKaliArgvSpec;
export function buildSafeKaliArgv(
  capability: KaliCapabilityName,
  rawInput: Record<string, unknown>,
  options?: BuildSafeKaliArgvOptions
): SafeKaliArgvSpec;
export function buildSafeKaliArgv(
  capability: KaliCapabilityName,
  rawInput: Record<string, unknown>,
  options: BuildSafeKaliArgvOptions = {}
): SafeKaliArgvSpec {
  if (!rawInput || typeof rawInput !== 'object' || Array.isArray(rawInput)) {
    throw new KaliSecurityError('KALI_SCHEMA_VALIDATION_ERROR', 'Tool input must be a plain object');
  }

  // 1. Recursive shell metacharacter, raw-key, and weaponized payload firewall
  const safety = scanKaliPayloadSafety(rawInput);
  if (!safety.safe) {
    throw new KaliSecurityError(
      safety.ruleId ?? 'KALI_UNSAFE_PAYLOAD',
      safety.reason ?? 'Unsafe payload rejected'
    );
  }

  // 2. Explicit pre-parse checks for flag injection and SSRF before Zod formatting
  precheckStringField(rawInput, 'target_host', 'host');
  precheckStringField(rawInput, 'config_rel_path', 'path');
  precheckStringField(rawInput, 'reproducer_rel_path', 'path');
  precheckStringField(rawInput, 'manifest_rel_path', 'path');

  // 3. Strict capability schema validation + static argv assembly
  switch (capability) {
    case 'security.kali.recon_surface': {
      const parsedRes = KaliReconSurfaceInputSchema.safeParse(rawInput);
      if (!parsedRes.success) {
        throw new KaliSecurityError(
          'KALI_SCHEMA_VALIDATION_ERROR',
          parsedRes.error.issues.map((i) => i.message).join('; ')
        );
      }
      const input = parsedRes.data;
      const scopeCheck = verifyEngagementScope(input.scope, {
        targetHost: input.target_host,
        expectedTenantId: options.expectedTenantId,
        now: options.now,
      });
      if (!scopeCheck.valid) {
        throw new KaliSecurityError(scopeCheck.code ?? 'E_SCOPE_INVALID', scopeCheck.reason ?? 'Scope check failed');
      }

      const timeoutSeconds = Math.max(1, Math.min(45, Math.ceil(input.timeout_ms / 1000)));
      const argv: readonly string[] =
        input.probe_profile === 'tcp_connect_ports'
          ? Object.freeze([
              'nmap',
              '-sT',
              '-Pn',
              '-n',
              '--max-retries',
              '1',
              '--host-timeout',
              `${timeoutSeconds}s`,
              '-p',
              input.ports.join(','),
              '-oX',
              '-',
              '--',
              input.target_host,
            ])
          : Object.freeze([
              'curl',
              '--silent',
              '--show-error',
              '--head',
              '--max-time',
              String(Math.min(15, timeoutSeconds)),
              '--proto',
              '=http,https',
              '--noproxy',
              '*',
              '--',
              `http://${input.target_host}:${input.ports[0]}/`,
            ]);

      assertSafeKaliArgv(argv);
      return {
        capability,
        binary: argv[0],
        args: Object.freeze(argv.slice(1)),
        argv,
        networkMode: 'lab-loopback-bridge',
        workspaceMount: '/workspace',
        readOnlyWorkspaceMount: true,
        timeoutMs: input.timeout_ms,
        targetHost: input.target_host,
        targetPort: input.ports[0],
      };
    }

    case 'security.kali.config_audit': {
      const parsedRes = KaliConfigAuditInputSchema.safeParse(rawInput);
      if (!parsedRes.success) {
        throw new KaliSecurityError(
          'KALI_SCHEMA_VALIDATION_ERROR',
          parsedRes.error.issues.map((i) => i.message).join('; ')
        );
      }
      const input = parsedRes.data;
      const scopeCheck = verifyEngagementScope(input.scope, {
        targetHost: input.target_host,
        expectedTenantId: options.expectedTenantId,
        now: options.now,
      });
      if (!scopeCheck.valid) {
        throw new KaliSecurityError(scopeCheck.code ?? 'E_SCOPE_INVALID', scopeCheck.reason ?? 'Scope check failed');
      }

      const timeoutSeconds = Math.max(1, Math.min(60, Math.ceil(input.timeout_ms / 1000)));
      let argv: readonly string[];
      let networkMode: SandboxNetworkMode;

      if (input.audit_mode === 'tls_posture') {
        const port = input.target_port ?? 443;
        argv = Object.freeze([
          'testssl.sh',
          '--quiet',
          '--color',
          '0',
          '--jsonfile-pretty',
          '-',
          '--connect-timeout',
          '10',
          '--openssl-timeout',
          '10',
          '--',
          `${input.target_host}:${port}`,
        ]);
        networkMode = 'lab-loopback-bridge';
      } else if (input.audit_mode === 'http_security_headers') {
        const port = input.target_port ?? 3000;
        argv = Object.freeze([
          'curl',
          '--silent',
          '--show-error',
          '--head',
          '--max-time',
          String(Math.min(15, timeoutSeconds)),
          '--proto',
          '=http,https',
          '--noproxy',
          '*',
          '--',
          `http://${input.target_host}:${port}/`,
        ]);
        networkMode = 'lab-loopback-bridge';
      } else {
        const rel = assertNoFlagInjection(input.config_rel_path!, 'config_rel_path');
        argv = Object.freeze([
          'trivy',
          'config',
          '--offline-scan',
          '--format',
          'json',
          '--quiet',
          '--',
          `/workspace/${rel}`,
        ]);
        networkMode = 'airgapped';
      }

      assertSafeKaliArgv(argv);
      return {
        capability,
        binary: argv[0],
        args: Object.freeze(argv.slice(1)),
        argv,
        networkMode,
        workspaceMount: '/workspace',
        readOnlyWorkspaceMount: true,
        timeoutMs: input.timeout_ms,
        targetHost: input.target_host,
        targetPort: input.target_port,
        workspaceRelPath: input.config_rel_path,
      };
    }

    case 'security.kali.verify_reproducer': {
      const parsedRes = KaliVerifyReproducerInputSchema.safeParse(rawInput);
      if (!parsedRes.success) {
        const firstMsg = parsedRes.error.issues.map((i) => i.message).join('; ');
        const isSod = firstMsg.includes('E_SOD_');
        throw new KaliSecurityError(
          isSod ? firstMsg.split(':')[0] : 'KALI_SCHEMA_VALIDATION_ERROR',
          firstMsg
        );
      }
      const input = parsedRes.data;
      const scopeCheck = verifyEngagementScope(input.scope, {
        targetHost: input.target_host,
        expectedTenantId: options.expectedTenantId,
        now: options.now,
      });
      if (!scopeCheck.valid) {
        throw new KaliSecurityError(scopeCheck.code ?? 'E_SCOPE_INVALID', scopeCheck.reason ?? 'Scope check failed');
      }

      const rel = assertNoFlagInjection(input.reproducer_rel_path, 'reproducer_rel_path');
      const timeoutSeconds = Math.max(1, Math.min(30, Math.ceil(input.timeout_ms / 1000)));
      let argv: readonly string[];
      let networkMode: SandboxNetworkMode = input.target_host ? 'lab-loopback-bridge' : 'airgapped';

      if (input.reproducer_runtime === 'node') {
        argv = Object.freeze([
          'node',
          '--disallow-code-generation-from-strings',
          '--',
          `/workspace/${rel}`,
        ]);
      } else if (input.reproducer_runtime === 'python3') {
        argv = Object.freeze(['python3', '-I', '--', `/workspace/${rel}`]);
      } else {
        const port = input.target_port ?? 3000;
        argv = Object.freeze([
          'curl',
          '--silent',
          '--show-error',
          '--max-time',
          String(Math.min(15, timeoutSeconds)),
          '--proto',
          '=http,https',
          '--noproxy',
          '*',
          '--',
          `http://${input.target_host ?? '127.0.0.1'}:${port}/`,
        ]);
        networkMode = 'lab-loopback-bridge';
      }

      assertSafeKaliArgv(argv);
      return {
        capability,
        binary: argv[0],
        args: Object.freeze(argv.slice(1)),
        argv,
        networkMode,
        workspaceMount: '/workspace',
        readOnlyWorkspaceMount: true,
        timeoutMs: input.timeout_ms,
        targetHost: input.target_host,
        targetPort: input.target_port,
        workspaceRelPath: rel,
      };
    }

    case 'security.kali.sbom_cve_check': {
      const parsedRes = KaliSbomCveCheckInputSchema.safeParse(rawInput);
      if (!parsedRes.success) {
        throw new KaliSecurityError(
          'KALI_SCHEMA_VALIDATION_ERROR',
          parsedRes.error.issues.map((i) => i.message).join('; ')
        );
      }
      const input = parsedRes.data;
      const scopeCheck = verifyEngagementScope(input.scope, {
        expectedTenantId: options.expectedTenantId,
        now: options.now,
      });
      if (!scopeCheck.valid) {
        throw new KaliSecurityError(scopeCheck.code ?? 'E_SCOPE_INVALID', scopeCheck.reason ?? 'Scope check failed');
      }

      const rel = assertNoFlagInjection(input.manifest_rel_path, 'manifest_rel_path');
      const severityArg = input.severity_filter.join(',');

      const argv: readonly string[] =
        input.scanner_engine === 'trivy_offline'
          ? Object.freeze([
              'trivy',
              'fs',
              '--offline-scan',
              '--skip-db-update',
              '--format',
              'json',
              '--quiet',
              '--severity',
              severityArg,
              '--',
              `/workspace/${rel}`,
            ])
          : Object.freeze([
              'grype',
              '--offline',
              '-o',
              'json',
              '--',
              `/workspace/${rel}`,
            ]);

      assertSafeKaliArgv(argv);
      return {
        capability,
        binary: argv[0],
        args: Object.freeze(argv.slice(1)),
        argv,
        networkMode: 'airgapped',
        workspaceMount: '/workspace',
        readOnlyWorkspaceMount: true,
        timeoutMs: input.timeout_ms,
        workspaceRelPath: rel,
      };
    }
  }
}

export interface SafeKaliLabSyntheticArgvSpec extends SafeKaliArgvSpec {
  readonly actionId: KaliLabActionId;
  readonly profile: 'LAB_SYNTHETIC';
  readonly validatedScope: ValidatedKaliLabScope;
  readonly validatedTarget: ValidatedKaliLabTarget;
  readonly validatedBudget: ValidatedKaliLabBudget;
}

/**
 * Builds a strictly static, shell-free `string[]` argv tuple for the E4
 * `LAB_SYNTHETIC` verification actions (`service_inventory`, `tls_review`,
 * `web_passive_baseline`, `local_code_scan`).
 */
export function buildSafeKaliLabSyntheticArgv(
  rawActionId: KaliLabActionId | string,
  rawInput: Record<string, unknown>,
  options: BuildSafeKaliArgvOptions = {}
): SafeKaliLabSyntheticArgvSpec {
  if (!rawInput || typeof rawInput !== 'object' || Array.isArray(rawInput)) {
    throw new KaliSecurityError(
      'KALI_SCHEMA_VALIDATION_ERROR',
      'Tool input must be a plain object'
    );
  }

  // 1. Recursive shell metacharacter, raw-key, and weaponized payload firewall
  const safety = scanKaliPayloadSafety(rawInput);
  if (!safety.safe) {
    throw new KaliSecurityError(
      safety.ruleId ?? 'KALI_UNSAFE_PAYLOAD',
      safety.reason ?? 'Unsafe payload rejected'
    );
  }

  // 2. Enumerated actionId validation
  const actionId = normalizeKaliLabActionId(rawActionId);

  // 3. Target, Scope, and Budget validation
  const validatedTarget = validateKaliLabTargetRef(
    rawInput.targetRef,
    actionId,
    rawInput
  );
  const validatedScope = validateKaliLabScopeRef(
    rawInput.scopeRef ?? rawInput.scope,
    {
      targetHost: validatedTarget.targetHost,
      expectedTenantId: options.expectedTenantId,
      now: options.now,
    }
  );
  const validatedBudget = validateKaliLabBudgetRef(
    rawInput.budgetRef ?? rawInput.budget,
    rawInput
  );

  const timeoutSeconds = Math.max(
    1,
    Math.min(60, Math.ceil(validatedBudget.timeoutMs / 1000))
  );

  let argv: readonly string[];
  let networkMode: SandboxNetworkMode;
  let mappedCapability: KaliCapabilityName;

  switch (actionId) {
    case 'service_inventory': {
      const host = validatedTarget.targetHost ?? '127.0.0.1';
      const ports = validatedTarget.ports ?? [80, 443, 3000, 8080];
      argv = Object.freeze([
        'nmap',
        '-sT',
        '-Pn',
        '-n',
        '--max-retries',
        '1',
        '--host-timeout',
        `${Math.min(45, timeoutSeconds)}s`,
        '-p',
        ports.join(','),
        '-oX',
        '-',
        '--',
        host,
      ]);
      networkMode = 'lab-loopback-bridge';
      mappedCapability = 'security.kali.recon_surface';
      break;
    }

    case 'tls_review': {
      const host = validatedTarget.targetHost ?? '127.0.0.1';
      const port = validatedTarget.targetPort ?? 443;
      argv = Object.freeze([
        'testssl.sh',
        '--quiet',
        '--color',
        '0',
        '--jsonfile-pretty',
        '-',
        '--connect-timeout',
        '10',
        '--openssl-timeout',
        '10',
        '--',
        `${host}:${port}`,
      ]);
      networkMode = 'lab-loopback-bridge';
      mappedCapability = 'security.kali.config_audit';
      break;
    }

    case 'web_passive_baseline': {
      const host = validatedTarget.targetHost ?? '127.0.0.1';
      const port = validatedTarget.targetPort ?? 3000;
      argv = Object.freeze([
        'curl',
        '--silent',
        '--show-error',
        '--head',
        '--max-time',
        String(Math.min(15, timeoutSeconds)),
        '--proto',
        '=http,https',
        '--noproxy',
        '*',
        '--',
        `http://${host}:${port}/`,
      ]);
      networkMode = 'lab-loopback-bridge';
      mappedCapability = 'security.kali.config_audit';
      break;
    }

    case 'local_code_scan': {
      const rel = assertNoFlagInjection(
        validatedTarget.workspaceRelPath ?? 'package.json',
        'targetRef'
      );
      const sevFilter = Array.isArray(rawInput.severity_filter)
        ? (rawInput.severity_filter as string[])
        : ['CRITICAL', 'HIGH', 'MEDIUM'];
      argv = Object.freeze([
        'trivy',
        'fs',
        '--offline-scan',
        '--skip-db-update',
        '--format',
        'json',
        '--quiet',
        '--severity',
        sevFilter.join(','),
        '--',
        `/workspace/${rel}`,
      ]);
      networkMode = 'airgapped';
      mappedCapability = 'security.kali.sbom_cve_check';
      break;
    }
  }

  assertSafeKaliArgv(argv);

  return {
    capability: mappedCapability,
    actionId,
    profile: 'LAB_SYNTHETIC',
    binary: argv[0],
    args: Object.freeze(argv.slice(1)),
    argv,
    networkMode,
    workspaceMount: '/workspace',
    readOnlyWorkspaceMount: true,
    timeoutMs: validatedBudget.timeoutMs,
    targetHost: validatedTarget.targetHost,
    targetPort: validatedTarget.targetPort,
    workspaceRelPath: validatedTarget.workspaceRelPath,
    validatedScope,
    validatedTarget,
    validatedBudget,
  };
}

