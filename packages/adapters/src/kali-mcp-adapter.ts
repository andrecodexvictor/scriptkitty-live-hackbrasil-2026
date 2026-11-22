/**
 * @file packages/adapters/src/kali-mcp-adapter.ts
 * @description Kali Linux Security Verification MCP Adapter Contract for ScriptKitty 2.0.
 * Strictly defensive / verification-only lab adapter operating in LAB_SANDBOX_ONLY mode.
 * Defaults to NOT_CONFIGURED unless an explicit local sandboxed runner is enabled.
 * Exposes ONLY allowlisted read-only/verification capabilities (recon_surface, config_audit,
 * verify_reproducer, sbom_cve_check), with ZERO raw shell execution, ZERO weaponized payloads,
 * full @script-kitty/runtime-guardian interception, and @script-kitty/quality-gate SoD enforcement.
 */

import { z } from 'zod';

import {
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type TargetType,
  type RecheckStatus,
  validateFinding,
  validateEvidence,
  computeFindingFingerprint,
  computeEvidenceChainHash,
  sha256,
} from '../../contracts/dist/index.js';

import {
  PromptInjectionDetector,
  ScopeBoundaryGuard,
  ConfusedDeputyGuard,
  InMemoryAuditLogger,
  DEFAULT_PATH_ARGUMENT_NAMES,
  type InterceptionContext,
  type SignedDelegationToken,
  type GuardianAuditEvent,
  type GuardianAuditEventType,
  type GuardianDecision,
} from '../../runtime-guardian/dist/index.js';

import {
  validateSeparationOfDuties,
  SoDViolationCode,
  type SeparationOfDutiesResult,
} from '../../quality-gate/dist/index.js';

import type {
  ISecurityEngineAdapter,
  AdapterStatusReport,
  ScanTarget,
  ScanOptions,
  AdapterScanResult,
  ReproduceOptions,
  AdapterReproduceResult,
  RecheckOptions,
  AdapterRecheckResult,
} from './adapter-interface.js';

import {
  withTimeout,
  sanitizeOutput,
  sanitizeObject,
  safeExecute,
  TimeoutError,
} from './execution-boundary.js';

import { assertLoopbackQualityEngineUrl } from './quality-engine-adapter.js';

/**
 * Strictly allowlisted defensive/verification capabilities exposed by the Kali Lab MCP contract.
 */
export const KALI_ALLOWED_CAPABILITIES = [
  'recon_surface',
  'config_audit',
  'verify_reproducer',
  'sbom_cve_check',
] as const;

export type KaliMcpCapability = (typeof KALI_ALLOWED_CAPABILITIES)[number];

/**
 * Forbidden raw execution parameter names that must NEVER be accepted by Kali MCP capabilities.
 */
const FORBIDDEN_RAW_EXECUTION_KEYS = new Set([
  'command',
  'cmd',
  'shell',
  'raw_args',
  'rawargs',
  'exec',
  'bash',
  'sh',
  'powershell',
  'script',
  'payload',
  'exploit',
  'msf',
  'reverse_shell',
  'bind_shell',
]);

/**
 * Offensive/weaponized tool patterns and shell metacharacters strictly rejected at the adapter boundary.
 */
const SHELL_METACHAR_REGEX = /(?:;|&&|\|\||\||`|\$\(|[\r\n\0]|>{1,2}|<)/;
const WEAPONIZED_PAYLOAD_PATTERNS: RegExp[] = [
  /\b(?:msfvenom|msfconsole|metasploit|sqlmap|linpeas|winpeas|hydra|hashcat|johntheripper|responder|mimikatz)\b/i,
  /(?:--os-shell|--os-pwn|--exploit|--dump-all|--reverse-shell|--bind-shell)/i,
  /(?:\/dev\/tcp\/|\bnc\s+-e\b|\bncat\b|\bsocat\b|\breverse[_-]?shell\b|\bbind[_-]?shell\b)/i,
  /\b(?:rm\s+-rf|chmod\s+\+x|curl\s+[^|]+\|\s*(?:ba)?sh|wget\s+[^|]+\|\s*(?:ba)?sh)\b/i,
];

/**
 * Validates that a host/endpoint lies strictly inside loopback or explicitly allowlisted lab domains.
 */
function isSafeLabHost(rawTarget: string, allowedLabHosts: Set<string>): boolean {
  const trimmed = rawTarget.trim();
  if (!trimmed || trimmed.length > 255) return false;
  if (trimmed.includes('@') || /\s/.test(trimmed)) return false;

  let hostname = trimmed.toLowerCase();
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
      if (parsed.username || parsed.password) return false;
      hostname = parsed.hostname.toLowerCase();
    } catch {
      return false;
    }
  }

  // Block well-known SSRF/metadata/wildcard addresses explicitly
  if (
    hostname === '169.254.169.254' ||
    hostname === 'metadata.google.internal' ||
    hostname === '100.100.100.200' ||
    hostname === '0.0.0.0'
  ) {
    return false;
  }

  if (
    hostname === '127.0.0.1' ||
    hostname === 'localhost' ||
    hostname === '::1' ||
    hostname === '[::1]' ||
    hostname.endsWith('.lab.local')
  ) {
    return true;
  }

  return allowedLabHosts.has(hostname);
}

/**
 * Strict allowlisted Zod parameter schemas (no unknown keys permitted).
 */
export const ReconSurfaceParamsSchema = z.object({
  target_host: z.string().min(1).max(255).regex(/^[a-zA-Z0-9.\-:\[\]]+$/),
  ports: z.array(z.number().int().min(1).max(65535)).min(1).max(20).optional(),
  protocol: z.enum(['http', 'https', 'tcp']).default('https'),
  include_tls_metadata: z.boolean().optional(),
}).strict();

export const ConfigAuditParamsSchema = z.object({
  config_path: z.string().min(1).max(255),
  profile: z.enum(['headers', 'tls', 'cors', 'csp', 'mcp_manifest']).default('headers'),
}).strict();

export const VerifyReproducerParamsSchema = z.object({
  finding_id: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_\-\.:]+$/),
  reproducer_path: z.string().min(1).max(255),
  target_endpoint: z.string().min(1).max(255).optional(),
  expected_invariant: z.string().min(3).max(500),
  dry_run: z.boolean().optional(),
}).strict();

export const SbomCveCheckParamsSchema = z.object({
  manifest_path: z.string().min(1).max(255),
  ecosystem: z.enum(['npm', 'pypi', 'cargo', 'cyclonedx', 'spdx']).default('npm'),
  severity_threshold: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).default('HIGH'),
}).strict();

export type ReconSurfaceParams = z.infer<typeof ReconSurfaceParamsSchema>;
export type ConfigAuditParams = z.infer<typeof ConfigAuditParamsSchema>;
export type VerifyReproducerParams = z.infer<typeof VerifyReproducerParamsSchema>;
export type SbomCveCheckParams = z.infer<typeof SbomCveCheckParamsSchema>;

export interface KaliCapabilityRequest {
  capability: KaliMcpCapability | string;
  params: Record<string, unknown>;
}

export interface KaliGovernanceContext {
  callerAgentId: string;
  discoveringAgentId?: string;
  authorizingAgentId?: string;
  isTainted?: boolean;
  taintSource?: string;
  delegationToken?: SignedDelegationToken | string;
}

export interface KaliSandboxTransport {
  invoke<T = Record<string, unknown>>(
    capability: KaliMcpCapability,
    validatedParams: Record<string, unknown>,
    options?: { timeoutMs?: number }
  ): Promise<T>;
}

export interface KaliMcpAdapterConfig {
  sandboxEnabled?: boolean;
  runnerEndpoint?: string;
  transport?: KaliSandboxTransport;
  fetchImpl?: typeof fetch;
  workspaceRoot?: string;
  allowedLabHosts?: string[];
  requireDelegationToken?: boolean;
  hmacSecret?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}

export type KaliInvocationStatus =
  | 'SUCCESS'
  | 'NOT_CONFIGURED'
  | 'BLOCKED_DISALLOWED_CAPABILITY'
  | 'BLOCKED_UNSAFE_PAYLOAD'
  | 'BLOCKED_BY_GUARDIAN'
  | 'BLOCKED_BY_SOD'
  | 'UNAVAILABLE'
  | 'ERROR';

export interface KaliCapabilityResult<T = Record<string, unknown>> {
  ok: boolean;
  status: KaliInvocationStatus;
  mode: 'LAB_SANDBOX_ONLY';
  capability: string;
  data?: T;
  evidence?: Evidence;
  sod_evaluation?: SeparationOfDutiesResult;
  guardian_rule_id?: string;
  errors: string[];
  warnings: string[];
}

/**
 * Recursively rejects forbidden raw shell/exploit parameter names, shell metacharacters,
 * and weaponized payload signatures anywhere in request parameters.
 */
export function scanKaliPayloadSafety(
  value: unknown,
  pathPrefix = 'params',
  seen = new WeakSet<object>()
): { safe: boolean; reason?: string; ruleId?: string } {
  if (value === null || value === undefined) return { safe: true };

  if (typeof value === 'string') {
    if (SHELL_METACHAR_REGEX.test(value)) {
      return {
        safe: false,
        ruleId: 'KALI_SHELL_METACHAR_BLOCKED',
        reason: `Shell metacharacter or control character forbidden at '${pathPrefix}': raw shell execution is disallowed.`,
      };
    }
    for (const pat of WEAPONIZED_PAYLOAD_PATTERNS) {
      if (pat.test(value)) {
        return {
          safe: false,
          ruleId: 'KALI_WEAPONIZED_PAYLOAD_BLOCKED',
          reason: `Weaponized/offensive payload pattern blocked at '${pathPrefix}': defensive verification only.`,
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
          reason: `Forbidden raw execution/exploit parameter '${sanitizeOutput(k)}' rejected.`,
        };
      }
      const keyCheck = scanKaliPayloadSafety(k, `${pathPrefix}.KEY(${k})`, seen);
      if (!keyCheck.safe) return keyCheck;
      const valCheck = scanKaliPayloadSafety(v, `${pathPrefix}.${k}`, seen);
      if (!valCheck.safe) return valCheck;
    }
  }

  return { safe: true };
}

/**
 * Kali Linux Security Verification MCP Adapter Contract (LAB_SANDBOX_ONLY).
 */
export class KaliMcpAdapter implements ISecurityEngineAdapter {
  public readonly engine_name = 'kali_mcp';
  public readonly mode = 'LAB_SANDBOX_ONLY' as const;
  public readonly supported_target_types: (TargetType | string)[] = [
    'API_ENDPOINT',
    'CONFIGURATION',
    'DEPENDENCY',
    'CLOUD_RESOURCE',
  ];

  private readonly config: KaliMcpAdapterConfig;
  private readonly allowedLabHosts: Set<string>;
  private readonly promptDetector: PromptInjectionDetector;
  private readonly scopeGuard: ScopeBoundaryGuard;
  private readonly confusedDeputyGuard: ConfusedDeputyGuard;
  private readonly auditLogger: InMemoryAuditLogger;

  constructor(config: KaliMcpAdapterConfig = {}) {
    this.config = config;
    this.allowedLabHosts = new Set((config.allowedLabHosts ?? []).map((h) => h.trim().toLowerCase()));
    const workspaceRoot = config.workspaceRoot ?? process.cwd();

    this.promptDetector = new PromptInjectionDetector({
      enabled: true,
      action: 'BLOCK',
      blockExfiltration: true,
      detectCredentials: true,
    });

    this.scopeGuard = new ScopeBoundaryGuard({
      enabled: true,
      allowedRoots: [workspaceRoot],
      allowSensitiveFiles: false,
      pathArgumentNames: [
        ...DEFAULT_PATH_ARGUMENT_NAMES,
        'config_path',
        'reproducer_path',
        'manifest_path',
      ],
    });

    this.confusedDeputyGuard = new ConfusedDeputyGuard({
      enabled: true,
      enforceSeparationOfDuties: true,
      requireDelegationToken: config.requireDelegationToken ?? false,
      hmacSecret: config.hmacSecret,
      verificationToolNames: ['verify_reproducer'],
      stateChangingToolNames: ['verify_reproducer'],
    });

    this.auditLogger = new InMemoryAuditLogger();
  }

  /**
   * Returns explicit configuration & sandbox readiness status.
   * Defaults strictly to NOT_CONFIGURED unless local sandbox runner is enabled and reachable.
   */
  public getStatus(): AdapterStatusReport {
    const env = this.config.env ?? process.env;
    const enabled =
      this.config.sandboxEnabled !== undefined
        ? this.config.sandboxEnabled === true
        : String(env.KALI_MCP_SANDBOX_ENABLED ?? 'false').trim().toLowerCase() === 'true';

    const runnerUrl = (this.config.runnerEndpoint ?? env.KALI_MCP_RUNNER_URL ?? '').trim();
    let runnerLoopbackValid = false;
    let runnerError: string | undefined;

    if (runnerUrl) {
      try {
        assertLoopbackQualityEngineUrl(runnerUrl);
        runnerLoopbackValid = true;
      } catch (err: unknown) {
        runnerError = sanitizeOutput(err instanceof Error ? err.message : String(err));
      }
    }

    const hasRunner = Boolean(this.config.transport) || runnerLoopbackValid;
    const configured = enabled && hasRunner;

    let configuration_status: AdapterStatusReport['configuration_status'] = 'NOT_CONFIGURED';
    if (runnerUrl && !runnerLoopbackValid) {
      configuration_status = 'UNAVAILABLE';
    } else if (configured) {
      configuration_status = 'LAB_SANDBOX_ONLY';
    }

    const missing: string[] = [];
    if (!enabled) missing.push('KALI_MCP_SANDBOX_ENABLED=true');
    if (!hasRunner) missing.push('KALI_MCP_RUNNER_URL (loopback http://127.0.0.1:<port>) or transport');

    return {
      engine_name: this.engine_name,
      mode: 'LAB_SANDBOX_ONLY',
      configuration_status,
      configured,
      enabled,
      reason: runnerError
        ? `Kali MCP runner URL rejected: ${runnerError}`
        : configured
          ? 'Kali Linux verification MCP adapter ready in LAB_SANDBOX_ONLY mode (defensive allowlist, Guardian + SoD active).'
          : 'Kali Linux verification MCP adapter is NOT_CONFIGURED by default; enable local sandbox runner explicitly for lab verification.',
      missing_requirements: missing,
      capabilities: [...KALI_ALLOWED_CAPABILITIES],
      warnings: [
        'Strict LAB_SANDBOX_ONLY contract: zero raw shell execution, zero weaponized payloads, governed by RuntimeGuardian and Tri-Party SoD.',
      ],
      details: {
        shell_execution_allowed: false,
        weaponized_payloads_allowed: false,
        audit_log_entries: this.auditLogger.getEventsSync().length,
      },
    };
  }

  public getAuditLogs(): readonly GuardianAuditEvent[] {
    return this.auditLogger.getEventsSync();
  }

  public verifyAuditChainIntegrity() {
    return this.auditLogger.verifyIntegritySync();
  }

  public async initialize(): Promise<boolean> {
    return this.getStatus().configured;
  }

  /**
   * Executes one of the 4 strictly allowlisted defensive verification capabilities,
   * enforced by payload firewall, RuntimeGuardian, Tri-Party Separation of Duties,
   * and fail-closed LAB_SANDBOX_ONLY configuration checks.
   */
  public async invokeCapability(
    request: KaliCapabilityRequest,
    governance: KaliGovernanceContext
  ): Promise<KaliCapabilityResult> {
    const capability = String(request?.capability ?? '').trim();

    // 1. Capability Allowlist Check
    if (!KALI_ALLOWED_CAPABILITIES.includes(capability as KaliMcpCapability)) {
      this.logAudit(governance.callerAgentId, capability, 'BLOCKED', 'KALI_DISALLOWED_CAPABILITY');
      return {
        ok: false,
        status: 'BLOCKED_DISALLOWED_CAPABILITY',
        mode: 'LAB_SANDBOX_ONLY',
        capability,
        guardian_rule_id: 'KALI_DISALLOWED_CAPABILITY',
        errors: [
          `Capability '${sanitizeOutput(capability)}' is not in the allowlisted verification set [${KALI_ALLOWED_CAPABILITIES.join(', ')}].`,
        ],
        warnings: [],
      };
    }

    const typedCap = capability as KaliMcpCapability;

    // 2. Shell Metacharacter & Weaponized Payload Firewall
    const safety = scanKaliPayloadSafety(request.params ?? {});
    if (!safety.safe) {
      this.logAudit(governance.callerAgentId, typedCap, 'BLOCKED', safety.ruleId || 'KALI_UNSAFE_PAYLOAD');
      return {
        ok: false,
        status: 'BLOCKED_UNSAFE_PAYLOAD',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        guardian_rule_id: safety.ruleId,
        errors: [safety.reason || 'Unsafe payload blocked by Kali defensive firewall.'],
        warnings: [],
      };
    }

    // 3. Prompt Injection Interception (@script-kitty/runtime-guardian)
    const guardianContext: InterceptionContext = {
      session_id: `kali-lab-${sha256(`${governance.callerAgentId}:${typedCap}`).slice(0, 12)}`,
      timestamp: new Date().toISOString(),
      caller_agent_id: governance.callerAgentId,
      discovering_agent_id: governance.discoveringAgentId,
      is_tainted: governance.isTainted,
      taint_context: governance.isTainted
        ? { is_tainted: true, taint_source: governance.taintSource ?? 'untrusted_input' }
        : undefined,
      delegation_token: governance.delegationToken,
      tool_name: typedCap,
    };

    const injectionDecision = this.promptDetector.inspect(request.params ?? {}, guardianContext);
    if (injectionDecision.verdict === 'BLOCK') {
      this.logAudit(governance.callerAgentId, typedCap, 'BLOCKED', injectionDecision.rule_id);
      return {
        ok: false,
        status: 'BLOCKED_BY_GUARDIAN',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        guardian_rule_id: injectionDecision.rule_id,
        errors: [sanitizeOutput(injectionDecision.reason || 'Prompt injection or secret leak blocked by RuntimeGuardian.')],
        warnings: [],
      };
    }

    // 4. Strict Zod Allowlisted Parameter Schema Validation
    let validatedParams: Record<string, unknown>;
    try {
      switch (typedCap) {
        case 'recon_surface': {
          const parsed = ReconSurfaceParamsSchema.parse(request.params);
          if (!isSafeLabHost(parsed.target_host, this.allowedLabHosts)) {
            this.logAudit(governance.callerAgentId, typedCap, 'BLOCKED', 'E_SSRF_NON_LAB_TARGET');
            return {
              ok: false,
              status: 'BLOCKED_BY_GUARDIAN',
              mode: 'LAB_SANDBOX_ONLY',
              capability: typedCap,
              guardian_rule_id: 'E_SSRF_NON_LAB_TARGET',
              errors: [`Target host '${sanitizeOutput(parsed.target_host)}' rejected: restricted strictly to loopback or explicit lab allowlist.`],
              warnings: [],
            };
          }
          validatedParams = parsed;
          break;
        }
        case 'config_audit':
          validatedParams = ConfigAuditParamsSchema.parse(request.params);
          break;
        case 'verify_reproducer': {
          const parsed = VerifyReproducerParamsSchema.parse(request.params);
          if (parsed.target_endpoint && !isSafeLabHost(parsed.target_endpoint, this.allowedLabHosts)) {
            this.logAudit(governance.callerAgentId, typedCap, 'BLOCKED', 'E_SSRF_NON_LAB_TARGET');
            return {
              ok: false,
              status: 'BLOCKED_BY_GUARDIAN',
              mode: 'LAB_SANDBOX_ONLY',
              capability: typedCap,
              guardian_rule_id: 'E_SSRF_NON_LAB_TARGET',
              errors: [`Target endpoint '${sanitizeOutput(parsed.target_endpoint)}' rejected: restricted strictly to loopback or explicit lab allowlist.`],
              warnings: [],
            };
          }
          validatedParams = parsed;
          break;
        }
        case 'sbom_cve_check':
          validatedParams = SbomCveCheckParamsSchema.parse(request.params);
          break;
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logAudit(governance.callerAgentId, typedCap, 'BLOCKED', 'KALI_SCHEMA_VALIDATION_ERROR');
      return {
        ok: false,
        status: 'BLOCKED_UNSAFE_PAYLOAD',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        guardian_rule_id: 'KALI_SCHEMA_VALIDATION_ERROR',
        errors: [sanitizeOutput(`Parameter validation failed: ${msg}`)],
        warnings: [],
      };
    }

    // 5. Scope Boundary Guard (Path Containment & Sensitive File Protection)
    const scopeDecision = this.scopeGuard.inspect(validatedParams, guardianContext);
    if (scopeDecision.verdict === 'BLOCK') {
      this.logAudit(governance.callerAgentId, typedCap, 'BLOCKED', scopeDecision.rule_id);
      return {
        ok: false,
        status: 'BLOCKED_BY_GUARDIAN',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        guardian_rule_id: scopeDecision.rule_id,
        errors: [sanitizeOutput(scopeDecision.reason || 'Path boundary violation blocked by ScopeBoundaryGuard.')],
        warnings: [],
      };
    }

    // 6. Confused Deputy Guard (@script-kitty/runtime-guardian)
    const deputyDecision = this.confusedDeputyGuard.inspect(typedCap, validatedParams, guardianContext);
    if (deputyDecision.verdict === 'BLOCK') {
      this.logAudit(governance.callerAgentId, typedCap, 'BLOCKED', deputyDecision.rule_id);
      const isSodViolation = deputyDecision.rule_id.startsWith('E_SOD');
      const sodEval = isSodViolation
        ? validateSeparationOfDuties(
            governance.discoveringAgentId,
            governance.callerAgentId,
            governance.authorizingAgentId,
            {
              hasIndependentEvidence: true,
              evidenceVerifierId: governance.callerAgentId,
            }
          )
        : undefined;
      return {
        ok: false,
        status: isSodViolation ? 'BLOCKED_BY_SOD' : 'BLOCKED_BY_GUARDIAN',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        sod_evaluation: sodEval,
        guardian_rule_id: deputyDecision.rule_id,
        errors: [sanitizeOutput(deputyDecision.reason || 'Blocked by ConfusedDeputyGuard.')],
        warnings: [],
      };
    }

    // 7. Tri-Party Separation of Duties (@script-kitty/quality-gate)
    let sodResult: SeparationOfDutiesResult | undefined;
    if (typedCap === 'verify_reproducer' || (governance.discoveringAgentId && governance.authorizingAgentId)) {
      sodResult = validateSeparationOfDuties(
        governance.discoveringAgentId,
        governance.callerAgentId,
        governance.authorizingAgentId,
        {
          hasIndependentEvidence: true,
          evidenceVerifierId: governance.callerAgentId,
        }
      );

      if (!sodResult.is_valid) {
        this.logAudit(
          governance.callerAgentId,
          typedCap,
          'BLOCKED',
          sodResult.violation_code ?? SoDViolationCode.E_SOD_SELF_CERTIFICATION
        );
        return {
          ok: false,
          status: 'BLOCKED_BY_SOD',
          mode: 'LAB_SANDBOX_ONLY',
          capability: typedCap,
          sod_evaluation: sodResult,
          guardian_rule_id: sodResult.violation_code,
          errors: [sanitizeOutput(sodResult.violation_details || 'Tri-Party Separation of Duties violation.')],
          warnings: [],
        };
      }
    }

    // 8. Fail-Closed LAB_SANDBOX_ONLY Readiness Check
    const statusReport = this.getStatus();
    if (!statusReport.configured) {
      this.logAudit(governance.callerAgentId, typedCap, 'ERROR', 'NOT_CONFIGURED');
      return {
        ok: false,
        status: 'NOT_CONFIGURED',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        sod_evaluation: sodResult,
        errors: [statusReport.reason],
        warnings: ['Fail closed: Kali verification runner is NOT_CONFIGURED; zero simulated findings emitted.'],
      };
    }

    // 9. Invoke Isolated Local Runner / Transport (ZERO shell execution)
    const timeoutMs = this.config.timeoutMs ?? 20_000;
    try {
      let runnerOutput: Record<string, unknown>;
      if (this.config.transport) {
        const raw = await withTimeout(
          this.config.transport.invoke(typedCap, validatedParams, { timeoutMs }),
          timeoutMs,
          `KaliMcpAdapter.${typedCap}`
        );
        runnerOutput = sanitizeObject((raw && typeof raw === 'object' ? raw : { value: raw }) as Record<string, unknown>);
      } else {
        const runnerUrl = (this.config.runnerEndpoint ?? (this.config.env ?? process.env).KALI_MCP_RUNNER_URL ?? '').trim();
        const loopbackUrl = assertLoopbackQualityEngineUrl(runnerUrl);
        const fetchFn = this.config.fetchImpl ?? globalThis.fetch;
        if (typeof fetchFn !== 'function') {
          return {
            ok: false,
            status: 'UNAVAILABLE',
            mode: 'LAB_SANDBOX_ONLY',
            capability: typedCap,
            sod_evaluation: sodResult,
            errors: ['Fetch API unavailable for Kali loopback MCP runner'],
            warnings: [],
          };
        }

        const resp = await withTimeout(
          fetchFn(loopbackUrl.toString(), {
            method: 'POST',
            redirect: 'error',
            headers: {
              'content-type': 'application/json',
              accept: 'application/json',
            },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: `kali-${Date.now()}`,
              method: 'tools/call',
              params: {
                name: typedCap,
                arguments: validatedParams,
              },
            }),
          }),
          timeoutMs,
          `KaliMcpAdapter.${typedCap}`
        );

        if (!resp.ok) {
          this.logAudit(governance.callerAgentId, typedCap, 'ERROR', `HTTP_${resp.status}`);
          return {
            ok: false,
            status: 'UNAVAILABLE',
            mode: 'LAB_SANDBOX_ONLY',
            capability: typedCap,
            sod_evaluation: sodResult,
            errors: [`Kali MCP runner returned HTTP ${resp.status}`],
            warnings: [],
          };
        }
        const rpcBody = (await resp.json()) as Record<string, unknown>;
        const rpcResult = (rpcBody.result ?? rpcBody) as Record<string, unknown>;
        runnerOutput = sanitizeObject(
          (rpcResult.structuredContent as Record<string, unknown>) ?? rpcResult
        );
      }

      let evidence: Evidence | undefined;
      if (typedCap === 'verify_reproducer') {
        const verified = runnerOutput.reproduction_verified === true || runnerOutput.exit_code === 1;
        const evStatus = verified ? 'VERIFIED_TRUE_POSITIVE' : 'REFUTED_FALSE_POSITIVE';
        const recordedAt = new Date().toISOString();
        const findingId = String(validatedParams.finding_id);
        const reproPath = String(validatedParams.reproducer_path);
        const payloadDigest = sha256(JSON.stringify(validatedParams));

        const candidateEvidence: Evidence = {
          evidence_id: `SK-EVID-KALI-${sha256(findingId + recordedAt).substring(0, 16)}`,
          finding_id: findingId,
          verification_type: 'REPRODUCER_EXECUTION',
          status: evStatus,
          verifier_agent_id: governance.callerAgentId,
          sandbox_environment: {
            runtime: 'docker_isolated',
            network_isolated: true,
            timeout_ms: timeoutMs,
            os_platform: 'linux-kali-lab',
          },
          reproducer_artifact: {
            script_path: reproPath,
            script_sha256: payloadDigest,
            exit_code: typeof runnerOutput.exit_code === 'number' ? runnerOutput.exit_code : (verified ? 1 : 0),
            stdout: sanitizeOutput(String(runnerOutput.stdout ?? '')),
            stderr: sanitizeOutput(String(runnerOutput.stderr ?? '')),
            execution_duration_ms: typeof runnerOutput.duration_ms === 'number' ? runnerOutput.duration_ms : 1,
          },
          reproduction_proof: {
            proof_type: 'MCP_PAYLOAD',
            payload: sanitizeOutput(JSON.stringify(validatedParams)),
            expected_behavior: String(validatedParams.expected_invariant),
            observed_vulnerable_behavior: sanitizeOutput(
              String(runnerOutput.summary ?? (verified ? 'Lab verification confirmed violation of expected invariant.' : 'Expected invariant held cleanly.'))
            ),
          },
          chain_hash: computeEvidenceChainHash({
            finding_id: findingId,
            verifier_agent_id: governance.callerAgentId,
            status: evStatus,
            script_sha256: payloadDigest,
            recorded_at: recordedAt,
          }),
          recorded_at: recordedAt,
        };

        const evValidation = validateEvidence(candidateEvidence);
        if (evValidation.success) {
          evidence = evValidation.data;
        }
      }

      this.logAudit(governance.callerAgentId, typedCap, 'ALLOWED', 'KALI_CAPABILITY_EXECUTED');
      return {
        ok: true,
        status: 'SUCCESS',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        data: runnerOutput,
        evidence,
        sod_evaluation: sodResult,
        errors: [],
        warnings: [],
      };
    } catch (err: unknown) {
      this.logAudit(governance.callerAgentId, typedCap, 'ERROR', 'KALI_EXECUTION_ERROR');
      return {
        ok: false,
        status: 'UNAVAILABLE',
        mode: 'LAB_SANDBOX_ONLY',
        capability: typedCap,
        sod_evaluation: sodResult,
        errors: [sanitizeOutput(err instanceof Error ? err.message : String(err))],
        warnings: [],
      };
    }
  }

  /**
   * Standard ISecurityEngineAdapter.scan entrypoint, routing strictly through allowlisted
   * recon_surface / config_audit / sbom_cve_check governance and fail-closed NOT_CONFIGURED rules.
   */
  public async scan(target: ScanTarget, options?: ScanOptions): Promise<AdapterScanResult> {
    const startTime = Date.now();
    const timeoutMs = options?.timeout_ms ?? 20_000;

    return safeExecute(async () => {
      return await withTimeout(
        this.performScanInternal(target, options, startTime),
        timeoutMs,
        'KaliMcpAdapter.scan'
      );
    }, (error: Error) => ({
      engine_name: this.engine_name,
      status: 'error',
      configuration_status: this.getStatus().configuration_status,
      findings: [],
      duration_ms: Date.now() - startTime,
      is_partial: error instanceof TimeoutError,
      errors: [sanitizeOutput(error.message)],
    }));
  }

  private async performScanInternal(
    target: ScanTarget,
    options: ScanOptions | undefined,
    startTime: number
  ): Promise<AdapterScanResult> {
    const capability = (options?.custom_config?.capability as string) ?? 'recon_surface';
    const callerAgentId = (options?.custom_config?.caller_agent_id as string) ?? 'kali-lab-verifier';
    const defaultParams =
      capability === 'config_audit'
        ? { config_path: target.target_url_or_path || 'lab-config.json', profile: 'headers' }
        : capability === 'sbom_cve_check'
          ? { manifest_path: target.target_url_or_path || 'package.json', ecosystem: 'npm', severity_threshold: 'HIGH' }
          : { target_host: target.target_url_or_path || '127.0.0.1', ports: [8080], protocol: 'http' };

    const invocation = await this.invokeCapability(
      {
        capability,
        params: (options?.custom_config?.params as Record<string, unknown>) ?? defaultParams,
      },
      {
        callerAgentId,
        discoveringAgentId: options?.custom_config?.discovering_agent_id as string | undefined,
        authorizingAgentId: options?.custom_config?.authorizing_agent_id as string | undefined,
        isTainted: options?.custom_config?.is_tainted === true,
        taintSource: options?.custom_config?.taint_source as string | undefined,
        delegationToken: options?.custom_config?.delegation_token as SignedDelegationToken | undefined,
      }
    );

    if (invocation.status === 'NOT_CONFIGURED') {
      return {
        engine_name: this.engine_name,
        status: 'skipped',
        configuration_status: 'NOT_CONFIGURED',
        findings: [],
        duration_ms: Date.now() - startTime,
        warnings: [...invocation.errors, ...invocation.warnings],
        raw_metadata: {
          mode: 'LAB_SANDBOX_ONLY',
          configuration_status: 'NOT_CONFIGURED',
        },
      };
    }

    if (!invocation.ok) {
      return {
        engine_name: this.engine_name,
        status: 'error',
        configuration_status: this.getStatus().configuration_status,
        findings: [],
        duration_ms: Date.now() - startTime,
        errors: invocation.errors,
        raw_metadata: {
          mode: 'LAB_SANDBOX_ONLY',
          blocked_status: invocation.status,
          guardian_rule_id: invocation.guardian_rule_id,
        },
      };
    }

    const rawIssues = Array.isArray(invocation.data?.findings)
      ? (invocation.data.findings as Array<Record<string, unknown>>)
      : [];
    const findings: SecurityFinding[] = [];
    const warnings: string[] = [];
    const commitHash = target.commit_hash || 'f6a7b8c9d0e12345678901234567890123456789';

    for (let i = 0; i < rawIssues.length; i++) {
      const item = rawIssues[i];
      const filePath = String(item.file_path ?? target.target_url_or_path ?? 'lab/surface.json');
      const cweId = String(item.cwe_id ?? 'CWE-200');
      const candidate: SecurityFinding = {
        finding_id: String(item.id ?? `SK-KALI-${sha256(filePath + cweId + i).substring(0, 16)}`),
        source_engine: this.engine_name,
        title: sanitizeOutput(String(item.title ?? 'Kali Lab Verification Finding')),
        description: sanitizeOutput(String(item.description ?? 'Defensive lab check detected misconfiguration or vulnerable dependency.')),
        cwe_id: cweId,
        owasp_category: String(item.owasp_category ?? 'A05:2021-Security Misconfiguration'),
        severity: (String(item.severity ?? 'MEDIUM').toUpperCase() as SecurityFinding['severity']),
        confidence: 'FIRM',
        target_type: (target.target_type as TargetType) || 'API_ENDPOINT',
        target: target.target_url_or_path,
        location: {
          file_path: filePath,
          start_line: Number(item.start_line ?? 1),
          end_line: Number(item.end_line ?? 1),
        },
        fingerprint: computeFindingFingerprint({
          cwe_id: cweId,
          file_path: filePath,
          rule_or_match: String(item.rule_id ?? capability),
        }),
        commit_hash: commitHash,
        discovered_at: new Date().toISOString(),
        agent_context: {
          discovering_agent_id: callerAgentId,
          agent_archetype: 'kali_lab_recon',
          tool_call_trace: [`kali_mcp:${capability}`],
        },
        raw_metadata: sanitizeObject({
          mode: 'LAB_SANDBOX_ONLY',
          capability,
        }),
      };

      const valid = validateFinding(candidate);
      if (valid.success) {
        findings.push(valid.data);
      } else {
        warnings.push(`Discarded non-compliant Kali finding: ${valid.errors?.map(e => e.message).join('; ')}`);
      }
    }

    return {
      engine_name: this.engine_name,
      status: 'success',
      configuration_status: 'LAB_SANDBOX_ONLY',
      findings,
      duration_ms: Date.now() - startTime,
      warnings: warnings.length > 0 ? warnings : undefined,
      raw_metadata: {
        mode: 'LAB_SANDBOX_ONLY',
        capability,
      },
    };
  }

  /**
   * Executes governed `verify_reproducer` capability enforcing RuntimeGuardian + Tri-Party SoD.
   */
  public async reproduce(finding: SecurityFinding, options?: ReproduceOptions): Promise<AdapterReproduceResult> {
    const startTime = Date.now();
    const timeoutMs = options?.timeout_ms ?? 20_000;

    return safeExecute(async () => {
      const customConfig = options?.custom_config || {};
      const invocation = await this.invokeCapability(
        {
          capability: 'verify_reproducer',
          params: {
            finding_id: finding.finding_id,
            reproducer_path: options?.reproducer_script_path || finding.location.file_path,
            target_endpoint: customConfig.target_endpoint as string | undefined,
            expected_invariant: (customConfig.expected_invariant as string) || `Verify ${finding.cwe_id} mitigation on ${finding.location.file_path}`,
            dry_run: options?.sandbox_runtime === 'dry_run',
          },
        },
        {
          callerAgentId: options?.verifier_agent_id ?? 'kali-independent-verifier',
          discoveringAgentId: finding.agent_context?.discovering_agent_id ?? (customConfig.discovering_agent_id as string | undefined),
          authorizingAgentId: (customConfig.authorizing_agent_id as string | undefined) ?? 'quality-gate-authority',
          isTainted: customConfig.is_tainted === true,
          taintSource: customConfig.taint_source as string | undefined,
          delegationToken: customConfig.delegation_token as SignedDelegationToken | undefined,
        }
      );

      if (invocation.status === 'NOT_CONFIGURED') {
        return {
          engine_name: this.engine_name,
          finding_id: finding.finding_id,
          status: 'skipped',
          reproduction_verified: false,
          duration_ms: Date.now() - startTime,
          error: invocation.errors.join('; '),
        };
      }

      if (!invocation.ok || !invocation.evidence) {
        return {
          engine_name: this.engine_name,
          finding_id: finding.finding_id,
          status: 'error',
          reproduction_verified: false,
          duration_ms: Date.now() - startTime,
          error: invocation.errors.join('; ') || 'Kali verification failed',
        };
      }

      return {
        engine_name: this.engine_name,
        finding_id: finding.finding_id,
        status: 'success',
        evidence: invocation.evidence,
        reproduction_verified: invocation.evidence.status === 'VERIFIED_TRUE_POSITIVE',
        duration_ms: Date.now() - startTime,
      };
    }, (error: Error) => ({
      engine_name: this.engine_name,
      finding_id: finding.finding_id,
      status: 'error',
      reproduction_verified: false,
      duration_ms: Date.now() - startTime,
      error: sanitizeOutput(error.message),
    }));
  }

  /**
   * Executes governed post-patch verification via `verify_reproducer` + SoD + ScopeBoundaryGuard.
   */
  public async recheck(patch: PatchProposal, options?: RecheckOptions): Promise<AdapterRecheckResult> {
    const startTime = Date.now();
    return safeExecute<AdapterRecheckResult>(async () => {
      const customConfig = options?.custom_config || {};
      const reproPath = patch.affected_files[0] ?? 'src/recheck-target.ts';

      const invocation = await this.invokeCapability(
        {
          capability: 'verify_reproducer',
          params: {
            finding_id: patch.finding_id,
            reproducer_path: reproPath,
            target_endpoint: customConfig.target_endpoint as string | undefined,
            expected_invariant: `Confirm patch ${patch.patch_id} resolves finding ${patch.finding_id}`,
            dry_run: options?.sandbox_runtime === 'dry_run',
          },
        },
        {
          callerAgentId: options?.verifier_agent_id ?? 'kali-recheck-verifier',
          discoveringAgentId: (customConfig.discovering_agent_id as string | undefined) ?? patch.author_engine,
          authorizingAgentId: (customConfig.authorizing_agent_id as string | undefined) ?? 'quality-gate-authority',
          isTainted: customConfig.is_tainted === true,
          taintSource: customConfig.taint_source as string | undefined,
          delegationToken: customConfig.delegation_token as SignedDelegationToken | undefined,
        }
      );

      if (invocation.status === 'NOT_CONFIGURED') {
        return {
          engine_name: this.engine_name,
          patch_id: patch.patch_id,
          finding_id: patch.finding_id,
          status: 'skipped',
          recheck_status: 'untested',
          duration_ms: Date.now() - startTime,
          error: invocation.errors.join('; '),
          tests_passed: false,
          reproducer_passed: false,
        };
      }

      if (!invocation.ok) {
        return {
          engine_name: this.engine_name,
          patch_id: patch.patch_id,
          finding_id: patch.finding_id,
          status: 'error',
          recheck_status: 'untested',
          duration_ms: Date.now() - startTime,
          error: invocation.errors.join('; '),
          tests_passed: false,
          reproducer_passed: false,
        };
      }

      const stillFails =
        invocation.data?.reproduction_verified === true ||
        invocation.data?.exit_code === 1;
      const recheckStatus: RecheckStatus = stillFails ? 'reproducer_still_fails' : 'passed_clean';

      return {
        engine_name: this.engine_name,
        patch_id: patch.patch_id,
        finding_id: patch.finding_id,
        status: 'success',
        recheck_status: recheckStatus,
        evidence: invocation.evidence,
        duration_ms: Date.now() - startTime,
        tests_passed: !stillFails,
        reproducer_passed: !stillFails,
      };
    }, (error: Error): AdapterRecheckResult => ({
      engine_name: this.engine_name,
      patch_id: patch.patch_id,
      finding_id: patch.finding_id,
      status: 'error',
      recheck_status: 'untested',
      duration_ms: Date.now() - startTime,
      error: sanitizeOutput(error.message),
      tests_passed: false,
      reproducer_passed: false,
    }));
  }

  private logAudit(agentId: string, toolName: string, outcome: 'ALLOWED' | 'BLOCKED' | 'MODIFIED' | 'ERROR', ruleId: string): void {
    const decision: GuardianDecision = outcome === 'ALLOWED' ? 'ALLOW' : 'BLOCK';
    let eventType: GuardianAuditEventType = 'POLICY_VIOLATION';
    if (outcome === 'ALLOWED') {
      eventType = 'TOOL_CALL';
    } else if (
      ruleId.startsWith('E_SOD') ||
      ruleId.startsWith('E_TAINTED') ||
      ruleId.includes('DELEGATION') ||
      ruleId.includes('TOKEN')
    ) {
      eventType = 'CONFUSED_DEPUTY_DETECTED';
    } else if (
      ruleId.startsWith('E_PATH') ||
      ruleId.startsWith('E_SENSITIVE') ||
      ruleId.startsWith('E_INVALID_URI')
    ) {
      eventType = 'SCOPE_VIOLATION_DETECTED';
    } else if (
      ruleId.startsWith('E_BEHAVIORAL') ||
      ruleId.startsWith('E_EXFILTRATION') ||
      ruleId.startsWith('E_DELIMITER') ||
      ruleId.startsWith('E_SECRET') ||
      ruleId.startsWith('E_OBFUSCATION')
    ) {
      eventType = 'PROMPT_INJECTION_DETECTED';
    } else if (outcome === 'ERROR') {
      eventType = 'SECURITY_VIOLATION';
    }

    this.auditLogger.logSync({
      agent_id: agentId || 'anonymous',
      event_type: eventType,
      stage: 'ON_CALL_TOOL',
      tool_name: toolName || 'unknown',
      decision,
      policy_id: 'kali-lab-sandbox-only-v1',
      rule_id: ruleId,
      details: { outcome },
    });
  }
}
