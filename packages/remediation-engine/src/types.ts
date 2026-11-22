/**
 * @file packages/remediation-engine/src/types.ts
 * @description Comprehensive type definitions, interfaces, and enums for the Autonomous Remediation Engine.
 */

import {
  EvidenceSchema,
  SecurityFindingSchema,
  PatchProposalSchema,
  GateDecisionSchema,
  VerificationStatus,
  VerificationType,
  GateVerdict,
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type GateDecision,
  type ChainOfCustody,
  type AstImpactScope,
  type BreakingChangeRisk,
  type RecheckStatus,
  type ProofType,
  type BlastRadius,
  type RollbackPlan,
} from '@script-kitty/contracts';

import type {
  Policy,
  SeparationOfDutiesResult,
} from '@script-kitty/quality-gate';

// Re-export runtime schemas and enums
export {
  EvidenceSchema,
  SecurityFindingSchema,
  PatchProposalSchema,
  GateDecisionSchema,
  VerificationStatus,
  VerificationType,
  GateVerdict,
};

// Re-export contract and quality-gate types for consumer convenience
export type {
  SecurityFinding,
  Evidence,
  PatchProposal,
  GateDecision,
  ChainOfCustody,
  AstImpactScope,
  BreakingChangeRisk,
  RecheckStatus,
  ProofType,
  BlastRadius,
  RollbackPlan,
  Policy,
  SeparationOfDutiesResult,
};

/**
 * 5-Stage Closed-Loop Remediation Lifecycle Stages
 * Supports both short names ('FIND', 'PROVE', ...) and long names ('FIND_IT', ...)
 */
export const RemediationStage = {
  FIND_IT: 'FIND_IT',
  PROVE_IT: 'PROVE_IT',
  FIX_IT: 'FIX_IT',
  VERIFY_IT: 'VERIFY_IT',
  LEARN_FROM_IT: 'LEARN_FROM_IT',
  FIND: 'FIND',
  PROVE: 'PROVE',
  FIX: 'FIX',
  VERIFY: 'VERIFY',
  LEARN: 'LEARN',
  DISCOVERY: 'DISCOVERY',
  REPRODUCTION: 'REPRODUCTION',
  PATCHING: 'PATCHING',
  GATING: 'GATING',
  ROLLBACK: 'ROLLBACK',
} as const;

export type RemediationStage = (typeof RemediationStage)[keyof typeof RemediationStage];

/**
 * Overall Remediation Result Status
 */
export const RemediationStatus = {
  INITIALIZED: 'INITIALIZED',
  DISCOVERED: 'DISCOVERED',
  PROVEN: 'PROVEN',
  PATCHED: 'PATCHED',
  VERIFIED: 'VERIFIED',
  AUTHORIZED: 'AUTHORIZED',
  REJECTED: 'REJECTED',
  ROLLED_BACK: 'ROLLED_BACK',
  ERROR: 'ERROR',
  SUCCESS: 'SUCCESS',
  FAILED: 'FAILED',
} as const;

export type RemediationStatus = (typeof RemediationStatus)[keyof typeof RemediationStatus];
export type LifecycleStatus = RemediationStatus;

/**
 * Offline Sandbox Execution Options
 */
export interface SandboxExecutionOptions {
  timeoutMs?: number;
  timeout_ms?: number;
  cwd?: string;
  env?: Record<string, string | undefined>;
  labAppUrl?: string;
  command?: string;
  args?: string[];
  isolated_network?: boolean;
  allowed_hosts?: string[];
}

export interface SandboxConfig {
  runtime?: 'node_sandbox' | 'docker_isolated' | 'mock_fixture';
  network_isolated?: boolean;
  timeout_ms?: number;
  environment_variables?: Record<string, string>;
  workspace_dir?: string;
}

/**
 * Offline Sandbox Execution Results
 */
export interface SandboxRunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  scriptPath: string;
  scriptSha256: string;
  timedOut: boolean;
  vulnerability_confirmed?: boolean;
  neutralized?: boolean;
}

export interface SandboxExecutionResult {
  exit_code: number;
  exitCode?: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  durationMs?: number;
  timed_out: boolean;
  timedOut?: boolean;
  command_executed?: string;
  script_path?: string;
  script_sha256?: string;
  vulnerability_confirmed?: boolean;
  neutralized?: boolean;
}

/**
 * Patch Synthesis Options
 */
export interface PatcherOptions {
  workspaceRoot: string;
  buildAfterPatch?: boolean;
  authorEngine?: string;
}

export interface PatchSynthesisOptions {
  authorEngine?: string;
  baseCommit?: string;
  contextLines?: number;
  astImpactScope?: AstImpactScope;
  breakingChangeRisk?: BreakingChangeRisk;
  killswitchFlag?: string;
}

export interface PatchSynthesisResult {
  patch: PatchProposal;
  originalContent: string;
  patchedContent: string;
  targetFile: string;
}

export interface PatchOptions {
  finding: SecurityFinding;
  target_file: string;
  original_content: string;
  patched_content: string;
  author_engine?: string;
  base_commit?: string;
  ast_impact_scope?: AstImpactScope;
  downstream_dependents?: string[];
  breaking_change_risk?: BreakingChangeRisk;
  killswitch_flag?: string;
  automated_rollback_trigger?: string;
}

export interface PatchApplyResult {
  success: boolean;
  applied_files?: string[];
  patchedContent?: string;
  checkpoint_id?: string;
  error?: string;
}

/**
 * File Snapshot for Deterministic Rollback
 */
export interface FileSnapshot {
  filePath?: string;
  file_path?: string;
  content: string;
  sha256: string | null;
  exists?: boolean;
  mtimeMs?: number;
}

export type RollbackTrigger =
  | 'PATCH_SYNTAX_ERROR'
  | 'SYNTAX_ERROR'
  | 'REPRODUCER_STILL_FAILS'
  | 'REGRESSION_DETECTED'
  | 'GATE_REJECTED'
  | 'MANUAL_ABORT';

export interface RollbackRecord {
  rollback_id: string;
  patch_id: string;
  finding_id: string;
  trigger: RollbackTrigger;
  trigger_details: string;
  files_affected: string[];
  reverted_via: 'REVERSE_DIFF' | 'SNAPSHOT_RESTORE';
  success: boolean;
  restoration_error?: string;
  executed_at: string;
}

export interface RollbackCheckpoint {
  checkpoint_id: string;
  created_at: string;
  base_commit: string;
  snapshots: Record<string, FileSnapshot>;
  revert_patch?: string;
}

export interface RollbackResult {
  success: boolean;
  checkpoint_id?: string;
  reverted_files?: string[];
  restored_files?: string[];
  restored_hashes?: Record<string, string>;
  error?: string;
  timestamp?: string;
}

/**
 * Recheck Execution Options & Results
 */
export interface RecheckOptions {
  workspaceRoot: string;
  reproducerPath: string;
  baselineCommand?: string;
  verifierAgentId: string;
  timeoutMs?: number;
}

export interface RecheckResult {
  recheckStatus: 'passed_clean' | 'reproducer_still_fails' | 'regression_detected';
  reproducerPassed: boolean;
  baselineTestsPassed: boolean;
  evidence?: Evidence;
  reproducerLogs: SandboxRunResult;
  baselineLogs?: { exitCode: number; stdout: string; stderr: string; durationMs: number };
  errorDetails?: string;
}

export interface DualPhaseRecheckOptions {
  reproducer: {
    script_path: string;
    cwd?: string;
    env?: Record<string, string | undefined>;
    timeout_ms?: number;
  };
  regression: {
    test_command?: string;
    test_args?: string[];
    cwd?: string;
    env?: Record<string, string | undefined>;
    timeout_ms?: number;
  };
}

export interface DualPhaseRecheckResult {
  passed: boolean;
  recheck_status: 'passed_clean' | 'reproducer_still_fails' | 'regression_detected' | 'error';
  reproducer_exit_code?: number;
  reproducer_output?: string;
  regression_exit_code?: number;
  regression_tests_total?: number;
  regression_tests_failed?: number;
  recheck_evidence?: Evidence;
  error?: string;
  phase_a?: {
    passed: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    duration_ms: number;
    recheck_status: 'passed_clean' | 'reproducer_still_fails' | 'error';
  };
  phase_b?: {
    passed: boolean;
    exit_code: number;
    stdout: string;
    stderr: string;
    duration_ms: number;
    recheck_status: 'passed_clean' | 'regression_detected' | 'error';
  };
  overall_status?: 'passed_clean' | 'reproducer_still_fails' | 'regression_detected' | 'error';
}

/**
 * Agent Identities for Tri-Party Separation of Duties
 */
export interface AgentIdentities {
  discovering_agent_id: string;
  verifying_agent_id: string;
  authorizing_agent_id: string;
}

/**
 * Remediation Engine Configuration
 */
export interface EngineConfig {
  workspaceRoot?: string;
  discoveringAgentId?: string;
  verifyingAgentId?: string;
  authorizingAgentId?: string;
  agentIdentities?: Partial<AgentIdentities>;
  policy?: Policy | Record<string, unknown>;
  autoRollback?: boolean;
  buildAfterPatch?: boolean;
  timeoutMs?: number;
  baselineCommand?: string;
}

export interface RemediationEngineConfig extends EngineConfig {
  workspace_root?: string;
  sandbox?: Partial<SandboxConfig>;
  agent_identities?: Partial<AgentIdentities>;
  regression_command?: string;
  target_app_url?: string;
  auto_rollback_on_failure?: boolean;
  working_dir?: string;
  discovering_agent_id?: string;
  verifying_agent_id?: string;
  authorizing_agent_id?: string;
  sandbox_timeout_ms?: number;
  base_commit?: string;
  scope_root?: string;
}

export type RemediationConfig = RemediationEngineConfig;

/**
 * Final End-to-End Remediation Result
 */
export interface RemediationResult {
  stage: RemediationStage;
  status: LifecycleStatus;
  finding: SecurityFinding;
  evidence?: Evidence;
  pre_patch_evidence?: Evidence;
  patch?: PatchProposal;
  patch_proposal?: PatchProposal;
  recheckEvidence?: Evidence;
  recheck_evidence?: Evidence;
  post_patch_evidence?: Evidence;
  recheck_result?: DualPhaseRecheckResult;
  gateDecision?: GateDecision;
  gate_decision?: GateDecision;
  custodyChain?: ChainOfCustody;
  custody_chain?: ChainOfCustody;
  success: boolean;
  rollbackOccurred: boolean;
  rollback_occurred?: boolean;
  rollbackReason?: string;
  rollback_reason?: string;
  errors: string[];
  error?: string;
}
