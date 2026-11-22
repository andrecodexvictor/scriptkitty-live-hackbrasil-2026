/**
 * @file packages/adapters/src/adapter-interface.ts
 * @description Core interface contracts and lifecycle types for ScriptKitty 2.0
 * Security Engine Adapters (Mantis, Codex Security, Cloudflare Security Center, Quality Engine).
 */

import type {
  SecurityFinding,
  Evidence,
  PatchProposal,
  TargetType,
  VerificationStatus,
  RecheckStatus,
} from '../../contracts/dist/index.js';

/**
 * Execution status indicator for security engine adapter operations.
 */
export type AdapterExecutionStatus = 'success' | 'partial' | 'error' | 'skipped';

/**
 * Operational readiness and configuration status of an adapter.
 * Fail-closed adapters MUST report NOT_CONFIGURED, DISABLED_BY_FLAG, or UNAVAILABLE
 * rather than fabricating passing checks when credentials/services are absent.
 */
export type AdapterConfigurationState =
  | 'CONFIGURED'
  | 'NOT_CONFIGURED'
  | 'DISABLED_BY_FLAG'
  | 'UNAVAILABLE'
  | 'LAB_ISOLATED'
  | 'LAB_SANDBOX_ONLY';

/**
 * Execution isolation / integration mode of an adapter.
 */
export type AdapterMode = 'PASSIVE' | 'LIVE' | 'LAB_ISOLATED' | 'LAB_SANDBOX_ONLY';

/**
 * Explicit runtime readiness report returned by adapter.getStatus().
 */
export interface AdapterStatusReport {
  engine_name: string;
  mode: AdapterMode;
  configuration_status: AdapterConfigurationState;
  configured: boolean;
  enabled: boolean;
  reason: string;
  missing_requirements?: string[];
  capabilities?: string[];
  warnings?: string[];
  details?: Record<string, unknown>;
}

/**
 * Scan target specification representing a codebase, artifact, cloud resource, or runtime agent.
 */
export interface ScanTarget {
  /**
   * Target classification matching canonical TargetType enum or string.
   */
  target_type: TargetType | string;

  /**
   * Primary target locator (local directory path, git repo URL, hostname, zone ID, or file).
   */
  target_url_or_path: string;

  /**
   * Optional VCS commit hash (SHA-1 or SHA-256) of the snapshot being scanned.
   */
  commit_hash?: string;

  /**
   * Optional sub-paths or file glob patterns to constrain audit scope.
   */
  scope_paths?: string[];

  /**
   * Optional threat model overlay (e.g. THREAT_MODEL.md or architectural specifications).
   */
  threat_model_overlay?: string;

  /**
   * Engine-specific target attributes or contextual metadata.
   */
  metadata?: Record<string, unknown>;
}

/**
 * Configurable scan options passed to the security engine adapter.
 */
export interface ScanOptions {
  /**
   * Maximum wall-clock duration in milliseconds before timeout enforcement.
   */
  timeout_ms?: number;

  /**
   * Maximum number of findings to collect before halting scanner.
   */
  max_findings?: number;

  /**
   * Strict token / API spending ceiling in USD (e.g. for Codex Security).
   */
  max_cost_usd?: number;

  /**
   * Severity filters to include (e.g. ['CRITICAL', 'HIGH']).
   */
  severity_filter?: string[];

  /**
   * Path to architectural knowledge base or context directory.
   */
  knowledge_base_path?: string;

  /**
   * Sandbox runtime type for dynamic scanners.
   */
  sandbox_type?: 'gvisor' | 'docker' | 'node_sandbox' | 'mock_fixture' | 'dry_run';

  /**
   * Engine-specific custom configuration parameters.
   */
  custom_config?: Record<string, unknown>;
}

/**
 * Canonical outcome of an adapter scan operation.
 */
export interface AdapterScanResult {
  /**
   * Name of the security engine that performed the scan.
   */
  engine_name: string;

  /**
   * Overall status of the scan pass.
   */
  status: AdapterExecutionStatus;

  /**
   * Readiness/configuration status reported by the adapter (e.g. NOT_CONFIGURED, DISABLED_BY_FLAG).
   */
  configuration_status?: AdapterConfigurationState;

  /**
   * Discovered security findings, normalized to canonical SecurityFinding contracts.
   */
  findings: SecurityFinding[];

  /**
   * Duration of the scan execution in milliseconds.
   */
  duration_ms: number;

  /**
   * True if scan was halted early due to spending cap, file limit, or partial error.
   */
  is_partial?: boolean;

  /**
   * Estimated or reported monetary cost incurred during scan (USD).
   */
  cost_usd?: number;

  /**
   * Diagnostic error messages captured during execution.
   */
  errors?: string[];

  /**
   * Diagnostic advisory or deprecation warnings.
   */
  warnings?: string[];

  /**
   * Engine-specific raw telemetry or metadata (sanitized of sensitive secrets).
   */
  raw_metadata?: Record<string, unknown>;
}

/**
 * Options for reproducing and empirically verifying a security finding.
 */
export interface ReproduceOptions {
  /**
   * Maximum execution timeout in milliseconds for the reproduction run.
   */
  timeout_ms?: number;

  /**
   * Isolated sandbox environment runtime.
   */
  sandbox_runtime?: 'gvisor' | 'docker_isolated' | 'node_sandbox' | 'mock_fixture' | 'dry_run';

  /**
   * Whether network egress is blocked (MUST default to true for PoC execution).
   */
  network_isolated?: boolean;

  /**
   * Path to an existing or generated reproduction script (e.g. poc_cwe89.ts).
   */
  reproducer_script_path?: string;

  /**
   * Identifier of the verifying agent performing reproduction (MUST differ from discoverer).
   */
  verifier_agent_id?: string;

  /**
   * Environment variables supplied into the sandbox.
   */
  env_vars?: Record<string, string>;

  /**
   * Engine-specific custom configuration parameters.
   */
  custom_config?: Record<string, unknown>;
}

/**
 * Canonical outcome of an empirical vulnerability reproduction attempt.
 */
export interface AdapterReproduceResult {
  /**
   * Name of the security engine executing reproduction.
   */
  engine_name: string;

  /**
   * Finding ID being verified.
   */
  finding_id: string;

  /**
   * Execution status of the reproducer attempt.
   */
  status: AdapterExecutionStatus;

  /**
   * Validated canonical Evidence contract (if reproduction produced evidence).
   */
  evidence?: Evidence;

  /**
   * True if reproduction conclusively confirmed exploitability (VERIFIED_TRUE_POSITIVE).
   */
  reproduction_verified?: boolean;

  /**
   * Execution duration in milliseconds.
   */
  duration_ms: number;

  /**
   * Diagnostic error message if execution failed or timed out.
   */
  error?: string;

  /**
   * Sanitized execution traces from sandbox.
   */
  raw_output?: {
    exit_code?: number;
    stdout?: string;
    stderr?: string;
  };
}

/**
 * Options for rechecking a proposed patch against reproduction scripts and regression suites.
 */
export interface RecheckOptions {
  /**
   * Maximum timeout in milliseconds for the complete recheck loop.
   */
  timeout_ms?: number;

  /**
   * Identifier of the verification agent running the recheck.
   */
  verifier_agent_id?: string;

  /**
   * Sandbox runtime for testing the candidate patch.
   */
  sandbox_runtime?: 'gvisor' | 'docker_isolated' | 'node_sandbox' | 'mock_fixture' | 'dry_run';

  /**
   * Whether to run the project's pre-existing regression test suite.
   */
  run_regression_suite?: boolean;

  /**
   * Command used to run regression test suite (e.g. "npm test", "pytest").
   */
  regression_test_command?: string;

  /**
   * Engine-specific custom configuration parameters.
   */
  custom_config?: Record<string, unknown>;
}

/**
 * Canonical outcome of a patch recheck operation.
 */
export interface AdapterRecheckResult {
  /**
   * Name of the security engine performing the recheck.
   */
  engine_name: string;

  /**
   * Target patch ID.
   */
  patch_id: string;

  /**
   * Associated finding ID.
   */
  finding_id: string;

  /**
   * Execution status of the recheck operation.
   */
  status: AdapterExecutionStatus;

  /**
   * Recheck verification status matching PatchProposal schema.
   */
  recheck_status: RecheckStatus | 'passed_clean' | 'reproducer_still_fails' | 'regression_detected' | 'untested';

  /**
   * Canonical Evidence contract generated during the regression test pass.
   */
  evidence?: Evidence;

  /**
   * Duration of the recheck pass in milliseconds.
   */
  duration_ms: number;

  /**
   * Diagnostic error message if technical failure occurred.
   */
  error?: string;

  /**
   * Whether the full pre-existing test suite passed cleanly.
   */
  tests_passed?: boolean;

  /**
   * Whether the crash reproducer was successfully mitigated.
   */
  reproducer_passed?: boolean;
}

/**
 * Standard decoupled security engine adapter interface.
 * All third-party security scanners and analyzers implement this contract.
 */
export interface ISecurityEngineAdapter {
  /**
   * Unique name of the security engine (e.g. "mantis", "codex_security", "cloudflare_security_center", "quality_engine").
   */
  readonly engine_name: string;

  /**
   * Target types supported by this adapter.
   */
  readonly supported_target_types: (TargetType | string)[];

  /**
   * Optional explicit configuration & readiness report.
   */
  getStatus?(): AdapterStatusReport;

  /**
   * Optional healthcheck and capability initialization.
   */
  initialize?(): Promise<boolean>;

  /**
   * Executes a scan against the target, returning canonical SecurityFinding objects.
   * MUST never throw unhandled exceptions; errors must be captured in AdapterScanResult.
   */
  scan(target: ScanTarget, options?: ScanOptions): Promise<AdapterScanResult>;

  /**
   * Executes an empirical crash reproducer or secondary opinion review to produce canonical Evidence.
   * MUST never throw unhandled exceptions.
   */
  reproduce(finding: SecurityFinding, options?: ReproduceOptions): Promise<AdapterReproduceResult>;

  /**
   * Evaluates a candidate patch diff by re-running reproducers and regression tests.
   * MUST never throw unhandled exceptions.
   */
  recheck(patch: PatchProposal, options?: RecheckOptions): Promise<AdapterRecheckResult>;
}
