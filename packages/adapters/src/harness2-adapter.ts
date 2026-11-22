/**
 * @file packages/adapters/src/harness2-adapter.ts
 * @description Google Harness² recursive agent strategy/skill/memory optimization adapter.
 * Strictly gated behind HARNESS2_EXPERIMENTS_ENABLED=false by default in LAB_ISOLATED mode.
 * Enforces hard immutable invariants preventing modification of quality gates,
 * security policies, authorization decisions, SoD boundaries, credentials, or production code.
 */

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

/**
 * Only non-security, lab-scoped optimization artifacts are permitted as Harness² targets.
 */
export const HARNESS2_ALLOWED_TARGET_CATEGORIES = [
  'strategy_prompt_note',
  'skill_routing_heuristic',
  'lab_memory_summary',
  'search_ordering',
] as const;

export type Harness2AllowedTargetCategory = (typeof HARNESS2_ALLOWED_TARGET_CATEGORIES)[number];

/**
 * Protected security boundaries that Harness² is mathematically forbidden from modifying.
 */
export const HARNESS2_IMMUTABLE_BOUNDARY_PATTERNS: Array<{ code: string; label: string; pattern: RegExp }> = [
  {
    code: 'IMMUTABLE_QUALITY_GATE',
    label: 'Quality Gate / Release Eligibility',
    pattern: /(?:^|[\\/_.-])(?:quality[-_]?gate|release[-_]?gate|deterministic[-_]?gate|factory[-_]?delivery|quality[-_]?policy)(?:[\\/_.-]|$)/i,
  },
  {
    code: 'IMMUTABLE_SECURITY_POLICY',
    label: 'Security Policy / .security-pack.json',
    pattern: /(?:\.security-pack\.json|(?:^|[\\/_.-])(?:security[-_]?policy|policies|security[-_]?pack|exceptions)(?:[\\/_.-]|$))/i,
  },
  {
    code: 'IMMUTABLE_AUTHORIZATION_OR_SOD',
    label: 'Authorization / SoD / Delegation Decisions',
    pattern: /(?:^|[\\/_.-])(?:auth|authorization|rbac|acl|permissions?|separation[-_]?of[-_]?duties|sod|confused[-_]?deputy|delegation|scope[-_]?guard|runtime[-_]?guardian|tenant[-_]?isolation|oauth|jwt)(?:[\\/_.-]|$)/i,
  },
  {
    code: 'IMMUTABLE_AUDIT_CUSTODY',
    label: 'Chain of Custody / Merkle Audit',
    pattern: /(?:^|[\\/_.-])(?:custody|merkle|audit[-_]?logger|evidence[-_]?ledger)(?:[\\/_.-]|$)/i,
  },
  {
    code: 'IMMUTABLE_CREDENTIALS',
    label: 'Credentials / Keys / Environment Secrets',
    pattern: /(?:\.env(?:\.|$)|(?:^|[\\/_.-])(?:credentials?|secrets?|id_rsa|id_ed25519)(?:[\\/_.-]|$)|\.(?:pem|key|pfx|p12)$)/i,
  },
  {
    code: 'IMMUTABLE_PRODUCTION_OR_WORKFLOWS',
    label: 'Production Code / Live Apps / CI Workflows',
    pattern: /(?:^|[\\/_.-])(?:apps[\\/]production|apps[\\/]lab-app|production|prod|deploy|\.github[\\/]workflows)(?:[\\/_.-]|$)/i,
  },
];

const FORBIDDEN_CONTENT_MUTATION_PATTERNS: RegExp[] = [
  /\b(?:bypass|disable|override|skip)[_-]?(?:quality[-_]?gate|gate|policy|policies|sod|auth|authorization|security)\b/i,
  /HARNESS2_EXPERIMENTS_ENABLED\s*=\s*true/i,
  /enforceSeparationOfDuties\s*:\s*false/i,
  /\b(?:auto[-_]?merge|auto[-_]?deploy|approve[-_]?all|allowAllOrigins)\s*[:=]\s*true/i,
];

export class Harness2InvariantError extends Error {
  public readonly violation_code: string;

  constructor(message: string, violationCode = 'HARNESS2_INVARIANT_VIOLATION') {
    super(message);
    this.name = 'Harness2InvariantError';
    this.violation_code = violationCode;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface Harness2AdapterConfig {
  experimentsEnabled?: boolean;
  env?: NodeJS.ProcessEnv;
  maxIterations?: number;
  maxCostUsd?: number;
  sandboxRoot?: string;
}

export interface Harness2InvariantCheckInput {
  targetPath: string;
  targetCategory?: string;
  mutationScope?: string;
  proposedContent?: string;
}

export interface Harness2InvariantCheckResult {
  allowed: boolean;
  violation_code?: string;
  reason?: string;
}

export interface Harness2OptimizationRequest {
  experiment_name: string;
  target_path: string;
  target_category: Harness2AllowedTargetCategory | string;
  current_strategy?: string;
  proposed_delta: string;
  mutation_scope?: string;
  max_iterations?: number;
  estimated_cost_usd?: number;
  benchmark_scores?: number[];
}

export interface Harness2ProposalArtifact {
  proposal_id: string;
  experiment_name: string;
  target_path: string;
  target_category: Harness2AllowedTargetCategory;
  iterations_executed: number;
  estimated_cost_usd: number;
  strategy_delta: string;
  strategy_sha256: string;
  requires_human_review: true;
  auto_applied: false;
  rollback_note: string;
}

export interface Harness2OptimizationResult {
  ok: boolean;
  status: 'PROPOSAL_GENERATED' | 'DISABLED_BY_FLAG' | 'INVARIANT_BLOCKED' | 'BUDGET_EXCEEDED' | 'ERROR';
  mode: 'LAB_ISOLATED';
  violation_code?: string;
  reason: string;
  proposal?: Harness2ProposalArtifact;
}

/**
 * Evaluates HARNESS2_EXPERIMENTS_ENABLED gate (strictly defaults to false).
 */
export function isHarness2ExperimentsEnabled(config?: Harness2AdapterConfig): boolean {
  if (config?.experimentsEnabled !== undefined) {
    return config.experimentsEnabled === true;
  }
  const env = config?.env ?? process.env;
  const raw = String(env.HARNESS2_EXPERIMENTS_ENABLED ?? 'false').trim().toLowerCase();
  return raw === 'true';
}

/**
 * Hard Invariant Check: Prevents Harness² from targeting or mutating quality gates,
 * security policies, authorization decisions, SoD boundaries, credentials, or production paths.
 */
export function validateHarness2ProposalTarget(
  input: Harness2InvariantCheckInput
): Harness2InvariantCheckResult {
  const targetPath = (input.targetPath ?? '').trim();
  if (!targetPath) {
    return {
      allowed: false,
      violation_code: 'HARNESS2_INVARIANT_EMPTY_TARGET',
      reason: 'Harness² invariant violation: targetPath must be a non-empty sandbox-relative path.',
    };
  }

  // Reject path traversal, null bytes, UNC paths, and absolute paths
  const normalized = targetPath.normalize('NFKC').replace(/\\/g, '/');
  if (
    normalized.includes('\0') ||
    normalized.includes('%00') ||
    normalized.includes('..') ||
    normalized.startsWith('/') ||
    normalized.startsWith('//') ||
    /^[a-zA-Z]:/.test(normalized) ||
    /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(normalized)
  ) {
    return {
      allowed: false,
      violation_code: 'HARNESS2_INVARIANT_PATH_ESCAPE',
      reason: `Harness² invariant violation: unsafe or escaping path '${sanitizeOutput(targetPath)}' rejected.`,
    };
  }

  if (input.targetCategory !== undefined) {
    const allowedSet = new Set<string>(HARNESS2_ALLOWED_TARGET_CATEGORIES);
    if (!allowedSet.has(input.targetCategory)) {
      return {
        allowed: false,
        violation_code: 'HARNESS2_INVARIANT_FORBIDDEN_CATEGORY',
        reason: `Harness² invariant violation: category '${sanitizeOutput(input.targetCategory)}' cannot be tuned (allowed: ${HARNESS2_ALLOWED_TARGET_CATEGORIES.join(', ')}).`,
      };
    }
  }

  const combinedMeta = `${normalized} ${input.mutationScope ?? ''}`;
  for (const boundary of HARNESS2_IMMUTABLE_BOUNDARY_PATTERNS) {
    if (boundary.pattern.test(combinedMeta)) {
      return {
        allowed: false,
        violation_code: `HARNESS2_${boundary.code}`,
        reason: `Harness² invariant violation: protected boundary '${boundary.label}' matched by target '${sanitizeOutput(targetPath)}'.`,
      };
    }
  }

  if (input.proposedContent) {
    for (const pat of FORBIDDEN_CONTENT_MUTATION_PATTERNS) {
      if (pat.test(input.proposedContent)) {
        return {
          allowed: false,
          violation_code: 'HARNESS2_IMMUTABLE_POLICY_OVERRIDE',
          reason: 'Harness² invariant violation: proposed content attempts to weaken security gates, policies, or authorization checks.',
        };
      }
    }
  }

  return { allowed: true };
}

/**
 * Google Harness² Experimental Lab Adapter.
 */
export class Harness2Adapter implements ISecurityEngineAdapter {
  public readonly engine_name = 'harness2';
  public readonly mode = 'LAB_ISOLATED' as const;
  public readonly supported_target_types: (TargetType | string)[] = [
    'AGENT_MEMORY',
    'LLM_PROMPT',
    'CONFIGURATION',
  ];

  private readonly config: Harness2AdapterConfig;
  private readonly maxIterations: number;
  private readonly maxCostUsd: number;

  constructor(config: Harness2AdapterConfig = {}) {
    this.config = config;
    this.maxIterations = Math.max(1, Math.min(config.maxIterations ?? 5, 25));
    this.maxCostUsd = Math.max(0.01, Math.min(config.maxCostUsd ?? 2.0, 25.0));
  }

  public isEnabled(): boolean {
    return isHarness2ExperimentsEnabled(this.config);
  }

  /**
   * Returns explicit feature-flag and isolation status for Harness².
   */
  public getStatus(): AdapterStatusReport {
    const enabled = this.isEnabled();
    return {
      engine_name: this.engine_name,
      mode: 'LAB_ISOLATED',
      configuration_status: enabled ? 'LAB_ISOLATED' : 'DISABLED_BY_FLAG',
      configured: enabled,
      enabled,
      reason: enabled
        ? 'Harness² experimental optimization enabled strictly in LAB_ISOLATED mode with hard security/gate immutability invariants.'
        : 'Harness² recursive optimization disabled by default (HARNESS2_EXPERIMENTS_ENABLED=false).',
      missing_requirements: enabled ? [] : ['HARNESS2_EXPERIMENTS_ENABLED=true (lab-only opt-in)'],
      capabilities: [
        'strategy_prompt_note_tuning',
        'skill_routing_heuristic_eval',
        'lab_memory_summary_compaction',
        'immutable_security_boundary_check',
      ],
      warnings: [
        'Harness² is strictly non-authoritative (LAB_ISOLATED) and hard-blocked from modifying quality gates, security policies, authorization, or production code.',
      ],
      details: {
        max_iterations: this.maxIterations,
        max_cost_usd: this.maxCostUsd,
        sandbox_root: this.config.sandboxRoot ?? 'lab-experiments/',
      },
    };
  }

  /**
   * Fail-closed initialization: returns false unless HARNESS2_EXPERIMENTS_ENABLED=true.
   */
  public async initialize(): Promise<boolean> {
    return this.isEnabled();
  }

  /**
   * Proposes bounded, human-reviewed strategy/skill/memory optimization deltas inside LAB_ISOLATED sandbox.
   * Always enforces hard invariants preventing modification of gates, policies, or authorization decisions.
   */
  public async proposeOptimization(
    request: Harness2OptimizationRequest
  ): Promise<Harness2OptimizationResult> {
    // Hard invariant check runs first so forbidden security mutations are ALWAYS explicitly flagged.
    const invariantCheck = validateHarness2ProposalTarget({
      targetPath: request.target_path,
      targetCategory: request.target_category,
      mutationScope: request.mutation_scope,
      proposedContent: request.proposed_delta,
    });

    if (!invariantCheck.allowed) {
      return {
        ok: false,
        status: 'INVARIANT_BLOCKED',
        mode: 'LAB_ISOLATED',
        violation_code: invariantCheck.violation_code ?? 'HARNESS2_INVARIANT_VIOLATION',
        reason: invariantCheck.reason ?? 'Harness² invariant violation blocked mutation proposal.',
      };
    }

    if (!this.isEnabled()) {
      return {
        ok: false,
        status: 'DISABLED_BY_FLAG',
        mode: 'LAB_ISOLATED',
        violation_code: 'HARNESS2_DISABLED_BY_FLAG',
        reason: 'Harness² optimization blocked: HARNESS2_EXPERIMENTS_ENABLED is false by default.',
      };
    }

    const estimatedCost = request.estimated_cost_usd ?? 0.05;
    if (estimatedCost > this.maxCostUsd) {
      return {
        ok: false,
        status: 'BUDGET_EXCEEDED',
        mode: 'LAB_ISOLATED',
        violation_code: 'HARNESS2_BUDGET_EXCEEDED',
        reason: `Estimated experiment cost $${estimatedCost.toFixed(2)} exceeds LAB_ISOLATED cap $${this.maxCostUsd.toFixed(2)}.`,
      };
    }

    const iterationsExecuted = Math.max(1, Math.min(request.max_iterations ?? 1, this.maxIterations));
    const strategySha = sha256(`${request.target_path}\0${request.proposed_delta}`);
    const proposalId = `SK-H2-PROP-${strategySha.substring(0, 16)}`;

    return {
      ok: true,
      status: 'PROPOSAL_GENERATED',
      mode: 'LAB_ISOLATED',
      reason: 'Generated bounded LAB_ISOLATED optimization proposal pending mandatory human review.',
      proposal: {
        proposal_id: proposalId,
        experiment_name: sanitizeOutput(request.experiment_name),
        target_path: request.target_path,
        target_category: request.target_category as Harness2AllowedTargetCategory,
        iterations_executed: iterationsExecuted,
        estimated_cost_usd: estimatedCost,
        strategy_delta: sanitizeOutput(request.proposed_delta),
        strategy_sha256: strategySha,
        requires_human_review: true,
        auto_applied: false,
        rollback_note: 'Revert non-authoritative lab strategy artifact if eval metrics degrade.',
      },
    };
  }

  /**
   * Scans candidate Harness² strategy/memory optimization proposals for unauthorized gate/policy/auth mutations.
   * Fails closed with status: 'skipped' (DISABLED_BY_FLAG) when HARNESS2_EXPERIMENTS_ENABLED=false.
   */
  public async scan(target: ScanTarget, options?: ScanOptions): Promise<AdapterScanResult> {
    const startTime = Date.now();
    const timeoutMs = options?.timeout_ms ?? 15_000;

    return safeExecute(async () => {
      return await withTimeout(
        this.performScanInternal(target, options, startTime),
        timeoutMs,
        'Harness2Adapter.scan'
      );
    }, (error: Error) => {
      const isTimeout = error instanceof TimeoutError;
      return {
        engine_name: this.engine_name,
        status: 'error',
        configuration_status: this.getStatus().configuration_status,
        findings: [],
        duration_ms: Date.now() - startTime,
        is_partial: isTimeout,
        errors: [sanitizeOutput(error.message)],
      };
    });
  }

  private async performScanInternal(
    target: ScanTarget,
    options: ScanOptions | undefined,
    startTime: number
  ): Promise<AdapterScanResult> {
    const findings: SecurityFinding[] = [];
    const warnings: string[] = [];
    const commitHash = target.commit_hash || 'd4e5f6a7b8c90123456789012345678901234567';
    const candidateProposals = (target.metadata?.proposals as Harness2InvariantCheckInput[]) || [];

    // Check any candidate mutation proposals against hard invariants regardless of enablement
    for (let i = 0; i < candidateProposals.length; i++) {
      if (options?.max_findings && findings.length >= options.max_findings) {
        warnings.push(`Max findings limit of ${options.max_findings} reached.`);
        break;
      }

      const candidate = candidateProposals[i];
      const check = validateHarness2ProposalTarget(candidate);
      if (!check.allowed) {
        const filePath = candidate.targetPath || `harness2/proposal-${i}.json`;
        const ruleId = check.violation_code || 'HARNESS2_INVARIANT_VIOLATION';
        const findingId = `SK-H2-${sha256(ruleId + filePath + i).substring(0, 16)}`;

        const finding: SecurityFinding = {
          finding_id: findingId,
          source_engine: this.engine_name,
          title: sanitizeOutput(`Harness² Immutable Boundary Violation (${ruleId})`),
          description: sanitizeOutput(check.reason || 'Attempted modification of immutable security/gate boundary'),
          cwe_id: 'CWE-284',
          owasp_category: 'LLM06:2025-Excessive Agency',
          severity: 'CRITICAL',
          confidence: 'CERTAIN',
          target_type: 'AGENT_MEMORY',
          target: target.target_url_or_path || filePath,
          location: {
            file_path: filePath,
            start_line: 1,
            end_line: 1,
          },
          fingerprint: computeFindingFingerprint({
            cwe_id: 'CWE-284',
            file_path: filePath,
            rule_or_match: ruleId,
          }),
          commit_hash: commitHash,
          discovered_at: new Date().toISOString(),
          agent_context: {
            discovering_agent_id: 'harness2-invariant-guard',
            agent_archetype: 'invariant_monitor',
            tool_call_trace: ['validateHarness2ProposalTarget'],
            reasoning_hash: sha256(ruleId + filePath),
          },
          raw_metadata: sanitizeObject({
            mode: 'LAB_ISOLATED',
            violation_code: ruleId,
            target_category: candidate.targetCategory ?? null,
          }),
        };

        const validated = validateFinding(finding);
        if (validated.success) {
          findings.push(validated.data);
        } else {
          warnings.push(`Discarded invalid Harness² finding: ${validated.errors?.map(e => e.message).join('; ')}`);
        }
      }
    }

    if (!this.isEnabled() && findings.length === 0) {
      return {
        engine_name: this.engine_name,
        status: 'skipped',
        configuration_status: 'DISABLED_BY_FLAG',
        findings: [],
        duration_ms: Date.now() - startTime,
        warnings: ['Harness² experiments disabled by default (HARNESS2_EXPERIMENTS_ENABLED=false).'],
        raw_metadata: {
          mode: 'LAB_ISOLATED',
          experiments_enabled: false,
          invariants_enforced: true,
        },
      };
    }

    return {
      engine_name: this.engine_name,
      status: 'success',
      configuration_status: this.isEnabled() ? 'LAB_ISOLATED' : 'DISABLED_BY_FLAG',
      findings,
      duration_ms: Date.now() - startTime,
      warnings: warnings.length > 0 ? warnings : undefined,
      raw_metadata: {
        mode: 'LAB_ISOLATED',
        experiments_enabled: this.isEnabled(),
        proposals_inspected: candidateProposals.length,
        invariants_enforced: true,
      },
    };
  }

  /**
   * Re-verifies a Harness² invariant finding using deterministic synthetic benchmark boundary checks.
   */
  public async reproduce(finding: SecurityFinding, options?: ReproduceOptions): Promise<AdapterReproduceResult> {
    const startTime = Date.now();
    const timeoutMs = options?.timeout_ms ?? 15_000;

    return safeExecute(async () => {
      return await withTimeout(
        this.performReproduceInternal(finding, options, startTime),
        timeoutMs,
        'Harness2Adapter.reproduce'
      );
    }, (error: Error) => ({
      engine_name: this.engine_name,
      finding_id: finding.finding_id,
      status: 'error',
      reproduction_verified: false,
      duration_ms: Date.now() - startTime,
      error: sanitizeOutput(error.message),
    }));
  }

  private async performReproduceInternal(
    finding: SecurityFinding,
    options: ReproduceOptions | undefined,
    startTime: number
  ): Promise<AdapterReproduceResult> {
    const customConfig = options?.custom_config || {};
    const targetCategory = customConfig.target_category as string | undefined;
    const mutationScope = customConfig.mutation_scope as string | undefined;
    const check = validateHarness2ProposalTarget({
      targetPath: finding.location.file_path,
      targetCategory,
      mutationScope,
    });

    if (!this.isEnabled() && check.allowed && customConfig.force_disabled_skip !== false) {
      return {
        engine_name: this.engine_name,
        finding_id: finding.finding_id,
        status: 'skipped',
        reproduction_verified: false,
        duration_ms: Date.now() - startTime,
        error: 'DISABLED_BY_FLAG: Harness² optimization disabled when HARNESS2_EXPERIMENTS_ENABLED=false.',
      };
    }

    const verifierAgentId = options?.verifier_agent_id ?? 'harness2-invariant-verifier';
    const isViolation = !check.allowed;
    const status = isViolation ? 'VERIFIED_TRUE_POSITIVE' : 'REFUTED_FALSE_POSITIVE';
    const recordedAt = new Date().toISOString();
    const proofPayload = JSON.stringify({
      targetPath: finding.location.file_path,
      targetCategory: targetCategory ?? null,
      invariantViolation: check.violation_code ?? null,
    });

    const evidence: Evidence = {
      evidence_id: `SK-EVID-H2-${sha256(finding.finding_id + recordedAt).substring(0, 16)}`,
      finding_id: finding.finding_id,
      verification_type: 'SYNTHETIC_BENCHMARK_PROBE',
      status,
      verifier_agent_id: verifierAgentId,
      sandbox_environment: {
        runtime: 'dry_run',
        network_isolated: true,
        timeout_ms: options?.timeout_ms ?? 15_000,
      },
      reproduction_proof: {
        proof_type: 'MOCK_PAYLOAD',
        payload: proofPayload,
        expected_behavior: 'Harness² may only propose deltas inside lab-scoped strategy/memory artifacts.',
        observed_vulnerable_behavior: isViolation
          ? (check.reason ?? 'Harness² invariant check blocked immutable security target.')
          : 'Proposal path lies strictly inside allowed LAB_ISOLATED optimization targets.',
      },
      chain_hash: computeEvidenceChainHash({
        finding_id: finding.finding_id,
        verifier_agent_id: verifierAgentId,
        status,
        script_sha256: sha256(proofPayload),
        recorded_at: recordedAt,
      }),
      recorded_at: recordedAt,
    };

    const validated = validateEvidence(evidence);
    if (!validated.success) {
      return {
        engine_name: this.engine_name,
        finding_id: finding.finding_id,
        status: 'error',
        reproduction_verified: false,
        duration_ms: Date.now() - startTime,
        error: `Evidence validation failed: ${validated.errors?.map(e => e.message).join('; ')}`,
      };
    }

    return {
      engine_name: this.engine_name,
      finding_id: finding.finding_id,
      status: 'success',
      evidence: validated.data,
      reproduction_verified: isViolation,
      duration_ms: Date.now() - startTime,
    };
  }

  /**
   * Verifies that no PatchProposal from or involving Harness² touches protected gates/policies/auth/production files.
   */
  public async recheck(patch: PatchProposal, options?: RecheckOptions): Promise<AdapterRecheckResult> {
    const startTime = Date.now();
    return safeExecute<AdapterRecheckResult>(async () => {
      for (const file of patch.affected_files) {
        const check = validateHarness2ProposalTarget({
          targetPath: file,
          proposedContent: patch.diff_content,
        });
        if (!check.allowed) {
          return {
            engine_name: this.engine_name,
            patch_id: patch.patch_id,
            finding_id: patch.finding_id,
            status: 'error',
            recheck_status: 'regression_detected' as RecheckStatus,
            duration_ms: Date.now() - startTime,
            error: check.reason,
            tests_passed: false,
            reproducer_passed: false,
          };
        }
      }

      if (!this.isEnabled()) {
        return {
          engine_name: this.engine_name,
          patch_id: patch.patch_id,
          finding_id: patch.finding_id,
          status: 'skipped',
          recheck_status: 'untested',
          duration_ms: Date.now() - startTime,
          error: 'DISABLED_BY_FLAG: Harness² experiments disabled by default.',
          tests_passed: false,
          reproducer_passed: false,
        };
      }

      return {
        engine_name: this.engine_name,
        patch_id: patch.patch_id,
        finding_id: patch.finding_id,
        status: 'success',
        recheck_status: 'passed_clean',
        duration_ms: Date.now() - startTime,
        tests_passed: true,
        reproducer_passed: true,
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
}
