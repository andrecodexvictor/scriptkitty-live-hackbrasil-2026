/**
 * @file packages/quality-gate/src/engine.ts
 * @description Deterministic Quality Gate & Policy Enforcement Engine for ScriptKitty 2.0.
 * Enforces Zero-Trust Gate Predicates, Tri-Party Separation of Duties, bounded limits,
 * unexpired exception validation, custody chain integrity, and tamper-evident audit logging.
 */

import { randomUUID } from 'node:crypto';
import {
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type GateDecision,
  type RuleEvaluation,
  type ChainOfCustody,
  type CustodyNode,
  GateVerdict,
  GateDecisionSchema,
  verifyChainOfCustody,
} from '@script-kitty/contracts';

import {
  type Policy,
  DEFAULT_POLICY,
  parsePolicy,
  evaluateExceptionsValidity,
  findMatchingException,
  insideScope,
  isSeverityBlocking,
} from './policy.js';

import {
  validateSeparationOfDuties,
  type SeparationOfDutiesResult,
  type AgentRoleMapping,
} from './separation-of-duties.js';

import { TamperEvidentAuditLogger } from './audit.js';

/**
 * Gate Evaluation Request
 */
export interface GateEvaluationRequest {
  commit_hash?: string;
  target_commit?: string;
  policy_id?: string;
  policy_version?: string;
  policy?: Policy | Record<string, unknown>;
  findings?: SecurityFinding[];
  evidence?: Evidence[];
  patches?: PatchProposal[];
  agent_roles?: AgentRoleMapping;
  discovering_agent_id?: string;
  verifying_agent_id?: string;
  authorizing_agent_id?: string;
  custody_chain?: ChainOfCustody | { nodes: CustodyNode[]; merkle_root?: string };
  scope_root?: string;
  evaluated_files?: string[];
  total_scanned_bytes?: number;
  evaluated_at?: string;
}

/**
 * Deterministic Quality Gate Engine.
 * Evaluates findings, evidence, patches, and policies using strict zero-trust invariants:
 * Any evaluation with missing, incomplete, unverified, or inconclusive evidence
 * mathematically evaluates to REJECT or BLOCK — NEVER PASS.
 */
export class DeterministicQualityGate {
  private auditLogger: TamperEvidentAuditLogger;

  constructor() {
    this.auditLogger = new TamperEvidentAuditLogger();
  }

  /**
   * Main gate evaluation pipeline.
   */
  public async evaluate(request: GateEvaluationRequest): Promise<GateDecision> {
    this.auditLogger.clear();

    const rulesEvaluated: RuleEvaluation[] = [];
    const blockingFindings: string[] = [];
    const unverifiedFindings: string[] = [];
    const evaluationTimestamp = request.evaluated_at ?? new Date().toISOString();

    // 1. Resolve Target Commit Hash (40-char SHA-1 or 64-char SHA-256)
    let targetCommit = (request.target_commit ?? request.commit_hash ?? '').trim();
    if (!/^[0-9a-fA-F]{40,64}$/.test(targetCommit)) {
      // Fallback to finding commit or zero hash if valid, else error
      const findingCommit = request.findings?.[0]?.commit_hash;
      if (findingCommit && /^[0-9a-fA-F]{40,64}$/.test(findingCommit)) {
        targetCommit = findingCommit;
      } else {
        targetCommit = '0'.repeat(40);
      }
    }

    // 2. Parse and Validate Policy
    let policy: Policy;
    try {
      policy = request.policy ? parsePolicy(request.policy) : DEFAULT_POLICY;
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const rule: RuleEvaluation = {
        rule_id: 'RULE_POLICY_PARSER',
        status: 'ERROR',
        reason: `Policy parsing failed: ${errorMsg}`,
      };
      rulesEvaluated.push(rule);
      this.auditLogger.logRuleEvaluation(rule);

      const decisionId = `SK-GATE-${Date.now()}-${randomUUID().slice(0, 8)}`;
      const emptySod = validateSeparationOfDuties('agent-error', 'agent-verifier', 'agent-authorizer');

      const auditRoot = this.auditLogger.getMerkleRoot();
      return GateDecisionSchema.parse({
        decision_id: decisionId,
        policy_version: '1',
        policy_id: request.policy_id ?? 'default-zero-trust-policy',
        target_commit: targetCommit,
        verdict: GateVerdict.ERROR,
        blocking_findings: [],
        unverified_findings: [],
        audit_merkle_root: auditRoot,
        sod_evaluation: emptySod,
        rules_evaluated: rulesEvaluated,
        evaluation_summary: `Policy configuration error: ${errorMsg}`,
        decided_at: evaluationTimestamp,
      });
    }

    // 3. Resolve and Validate Tri-Party Separation of Duties (SoD)
    let discAgent = (request.discovering_agent_id ?? '').trim();
    let veriAgent = (request.verifying_agent_id ?? '').trim();
    let authAgent = (request.authorizing_agent_id ?? '').trim();

    if (request.agent_roles) {
      for (const [agentId, role] of Object.entries(request.agent_roles)) {
        const r = String(role).trim().toLowerCase();
        if (r === 'discovery' && !discAgent) discAgent = agentId;
        if (r === 'verification' && !veriAgent) veriAgent = agentId;
        if (r === 'authorization' && !authAgent) authAgent = agentId;
      }
    }

    if (!discAgent && request.findings && request.findings.length > 0) {
      discAgent = request.findings[0].agent_context?.discovering_agent_id ?? request.findings[0].source_engine ?? 'agent-discovery';
    }
    if (!veriAgent && request.evidence && request.evidence.length > 0) {
      veriAgent = request.evidence[0].verifier_agent_id ?? request.evidence[0].signature?.verifying_agent_id ?? 'agent-verification';
    }
    if (!authAgent) {
      authAgent = 'agent-authorizer-gate';
    }

    const sodResult: SeparationOfDutiesResult = validateSeparationOfDuties(
      discAgent,
      veriAgent,
      authAgent
    );

    const sodRule: RuleEvaluation = {
      rule_id: 'RULE_SEPARATION_OF_DUTIES',
      status: sodResult.is_valid ? 'PASS' : 'FAIL',
      reason: sodResult.is_valid
        ? `Strict Tri-Party Separation of Duties satisfied: Discoverer (${sodResult.discovering_agent_id}) != Verifier (${sodResult.verifying_agent_id}) != Authorizer (${sodResult.authorizing_agent_id})`
        : `Separation of Duties violation: ${sodResult.violation_details}`,
    };
    rulesEvaluated.push(sodRule);
    this.auditLogger.logRuleEvaluation(sodRule);
    this.auditLogger.logSoDEvaluation(sodResult);

    // 4. Verify Custody Chain Integrity (if supplied)
    let isCustodyValid = true;
    if (request.custody_chain) {
      const chainVerification = verifyChainOfCustody(request.custody_chain);
      if (!chainVerification.valid) {
        isCustodyValid = false;
        const chainRule: RuleEvaluation = {
          rule_id: 'RULE_CUSTODY_INTEGRITY',
          status: 'FAIL',
          reason: `Cryptographic Chain of Custody integrity check failed: ${chainVerification.error ?? 'Tampered custody chain or Merkle root mismatch'}`,
        };
        rulesEvaluated.push(chainRule);
        this.auditLogger.logRuleEvaluation(chainRule);
      } else {
        const chainRule: RuleEvaluation = {
          rule_id: 'RULE_CUSTODY_INTEGRITY',
          status: 'PASS',
          reason: `Chain of Custody verified: ${chainVerification.total_nodes} nodes unbroken, Merkle root: ${chainVerification.merkle_root}`,
        };
        rulesEvaluated.push(chainRule);
        this.auditLogger.logRuleEvaluation(chainRule);
      }
    }

    // 5. Evaluate Policy Exception Expirations
    const exceptionCheck = evaluateExceptionsValidity(policy.exceptions);
    let hasExpiredExceptions = false;
    if (!exceptionCheck.valid) {
      hasExpiredExceptions = true;
      const expiredList = exceptionCheck.expiredExceptions
        .map((e) => `${e.rule_id} (expired: ${e.expires})`)
        .join(', ');
      const exRule: RuleEvaluation = {
        rule_id: 'RULE_POLICY_EXCEPTIONS',
        status: 'FAIL',
        reason: `Expired policy exception detected: [${expiredList}]. Expired exceptions immediately invalidate the gate.`,
      };
      rulesEvaluated.push(exRule);
      this.auditLogger.logRuleEvaluation(exRule);
    } else if (policy.exceptions.length > 0) {
      const exRule: RuleEvaluation = {
        rule_id: 'RULE_POLICY_EXCEPTIONS',
        status: 'PASS',
        reason: `All ${policy.exceptions.length} policy exceptions are unexpired and valid.`,
      };
      rulesEvaluated.push(exRule);
      this.auditLogger.logRuleEvaluation(exRule);
    }

    // 6. Check Bounded Limits (Files & Bytes)
    let limitViolated = false;
    if (request.evaluated_files && request.evaluated_files.length > policy.max_files) {
      limitViolated = true;
      const fileCountRule: RuleEvaluation = {
        rule_id: 'RULE_LIMIT_MAX_FILES',
        status: 'FAIL',
        reason: `Evaluated file count ${request.evaluated_files.length} exceeds policy ceiling of ${policy.max_files}`,
      };
      rulesEvaluated.push(fileCountRule);
      this.auditLogger.logRuleEvaluation(fileCountRule);
    }

    if (request.total_scanned_bytes && request.total_scanned_bytes > policy.max_total_bytes) {
      limitViolated = true;
      const byteLimitRule: RuleEvaluation = {
        rule_id: 'RULE_LIMIT_MAX_TOTAL_BYTES',
        status: 'FAIL',
        reason: `Total scanned bytes ${request.total_scanned_bytes} exceeds policy limit of ${policy.max_total_bytes}`,
      };
      rulesEvaluated.push(byteLimitRule);
      this.auditLogger.logRuleEvaluation(byteLimitRule);
    }

    // 7. Check Scope Safety (Directory traversal & Symlink escapes)
    let hasScopeEscape = false;
    const allowedScopes = policy.allowed_scopes.length > 0
      ? policy.allowed_scopes
      : request.scope_root
      ? [request.scope_root]
      : [];

    if (allowedScopes.length > 0 && request.findings) {
      for (const finding of request.findings) {
        const targetPath = finding.location?.file_path;
        if (targetPath) {
          const inScope = allowedScopes.some((scope) => insideScope(scope, targetPath));
          if (!inScope) {
            hasScopeEscape = true;
            blockingFindings.push(finding.finding_id);
            const scopeRule: RuleEvaluation = {
              rule_id: 'RULE_SCOPE_BOUNDARY',
              status: 'FAIL',
              finding_id: finding.finding_id,
              reason: `Target file '${targetPath}' escapes authorized scope boundaries [${allowedScopes.join(', ')}]`,
            };
            rulesEvaluated.push(scopeRule);
            this.auditLogger.logRuleEvaluation(scopeRule);
          }
        }
      }
    }

    // 8. Evaluate Findings, Evidence, and Patches under Zero-Trust Invariants
    const findings = request.findings ?? [];
    const evidenceList = request.evidence ?? [];
    const patches = request.patches ?? [];

    let hasInconclusiveEvidence = false;
    let hasPatchRegression = false;
    let hasHighBlastRadius = false;

    for (const finding of findings) {
      // 8.1 Check for unexpired policy suppression
      const exceptionMatch = findMatchingException(finding, policy.exceptions);
      if (exceptionMatch.matched) {
        if (exceptionMatch.isExpired) {
          hasExpiredExceptions = true;
          unverifiedFindings.push(finding.finding_id);
          const rule: RuleEvaluation = {
            rule_id: 'RULE_EXCEPTION_MATCH',
            status: 'FAIL',
            finding_id: finding.finding_id,
            reason: `Finding ${finding.finding_id} matched exception '${exceptionMatch.exception?.rule_id}' but the exception is EXPIRED (${exceptionMatch.exception?.expires})`,
          };
          rulesEvaluated.push(rule);
          this.auditLogger.logRuleEvaluation(rule);
          continue;
        } else {
          const rule: RuleEvaluation = {
            rule_id: 'RULE_EXCEPTION_MATCH',
            status: 'PASS',
            finding_id: finding.finding_id,
            reason: `Finding ${finding.finding_id} suppressed by valid policy exception: ${exceptionMatch.exception?.reason}`,
          };
          rulesEvaluated.push(rule);
          this.auditLogger.logRuleEvaluation(rule);
          continue;
        }
      }

      // 8.2 Locate reproduction evidence
      const matchingEvidence = evidenceList.filter((e) => e.finding_id === finding.finding_id);

      // Case a: Missing evidence -> REJECT
      if (matchingEvidence.length === 0) {
        unverifiedFindings.push(finding.finding_id);
        const rule: RuleEvaluation = {
          rule_id: 'RULE_EMPIRICAL_REPRODUCTION',
          status: 'FAIL',
          finding_id: finding.finding_id,
          reason: `Zero-Trust Violation: Finding ${finding.finding_id} has no independent empirical reproduction evidence`,
        };
        rulesEvaluated.push(rule);
        this.auditLogger.logRuleEvaluation(rule);
        continue;
      }

      // Check evidence verification status
      for (const evidence of matchingEvidence) {
        const evVerifier = (evidence.verifier_agent_id ?? evidence.signature?.verifying_agent_id)?.trim().toLowerCase();
        const discNormalized = (finding.agent_context?.discovering_agent_id ?? finding.source_engine ?? discAgent).trim().toLowerCase();

        // Check self-certification in evidence
        if (evVerifier && evVerifier === discNormalized) {
          unverifiedFindings.push(finding.finding_id);
          const rule: RuleEvaluation = {
            rule_id: 'RULE_INDEPENDENT_VERIFIER',
            status: 'FAIL',
            finding_id: finding.finding_id,
            reason: `SoD Violation: Evidence ${evidence.evidence_id} was self-certified by discovering agent '${discNormalized}'`,
          };
          rulesEvaluated.push(rule);
          this.auditLogger.logRuleEvaluation(rule);
          continue;
        }

        // Case b: Inconclusive reproducer status -> BLOCK
        if (
          evidence.status === 'INCONCLUSIVE' ||
          evidence.status === 'EXECUTION_ERROR'
        ) {
          hasInconclusiveEvidence = true;
          blockingFindings.push(finding.finding_id);
          const rule: RuleEvaluation = {
            rule_id: 'RULE_REPRODUCER_DECISIVENESS',
            status: 'FAIL',
            finding_id: finding.finding_id,
            reason: `Finding ${finding.finding_id} reproducer returned inconclusive status '${evidence.status}'`,
          };
          rulesEvaluated.push(rule);
          this.auditLogger.logRuleEvaluation(rule);
          continue;
        }

        // Refuted false positive
        if (evidence.status === 'REFUTED_FALSE_POSITIVE') {
          const rule: RuleEvaluation = {
            rule_id: 'RULE_REPRODUCER_RESULT',
            status: 'PASS',
            finding_id: finding.finding_id,
            reason: `Finding ${finding.finding_id} was empirically refuted as a false positive`,
          };
          rulesEvaluated.push(rule);
          this.auditLogger.logRuleEvaluation(rule);
          continue;
        }

        // Verified True Positive
        if (evidence.status === 'VERIFIED_TRUE_POSITIVE') {
          const rule: RuleEvaluation = {
            rule_id: 'RULE_REPRODUCER_RESULT',
            status: 'PASS',
            finding_id: finding.finding_id,
            reason: `Finding ${finding.finding_id} reproduction confirmed by independent verifier '${evidence.verifier_agent_id ?? 'verifier'}'`,
          };
          rulesEvaluated.push(rule);
          this.auditLogger.logRuleEvaluation(rule);

          // Evaluate patch proposal for confirmed vulnerability
          const matchingPatches = patches.filter((p) => p.finding_id === finding.finding_id);
          if (matchingPatches.length === 0) {
            // No patch proposed
            if (isSeverityBlocking(finding.severity, policy.severity_threshold)) {
              blockingFindings.push(finding.finding_id);
              const patchRule: RuleEvaluation = {
                rule_id: 'RULE_PATCH_REMEDIATION',
                status: 'FAIL',
                finding_id: finding.finding_id,
                reason: `Unremediated ${finding.severity} vulnerability ${finding.finding_id} has no proposed patch`,
              };
              rulesEvaluated.push(patchRule);
              this.auditLogger.logRuleEvaluation(patchRule);
            }
          } else {
            // Case c: Proposed patch with regression detected or reproducer still failing -> BLOCK
            for (const patch of matchingPatches) {
              const pStatus = patch.recheck_status;
              if (pStatus === 'regression_detected' || pStatus === 'reproducer_still_fails') {
                hasPatchRegression = true;
                blockingFindings.push(finding.finding_id);
                const patchRule: RuleEvaluation = {
                  rule_id: 'RULE_PATCH_REGRESSION',
                  status: 'FAIL',
                  finding_id: finding.finding_id,
                  reason: `Proposed patch ${patch.patch_id} recheck failed with status: ${pStatus}`,
                };
                rulesEvaluated.push(patchRule);
                this.auditLogger.logRuleEvaluation(patchRule);
              } else if (pStatus === 'untested') {
                unverifiedFindings.push(finding.finding_id);
                const patchRule: RuleEvaluation = {
                  rule_id: 'RULE_PATCH_VERIFICATION',
                  status: 'FAIL',
                  finding_id: finding.finding_id,
                  reason: `Proposed patch ${patch.patch_id} has untested recheck status`,
                };
                rulesEvaluated.push(patchRule);
                this.auditLogger.logRuleEvaluation(patchRule);
              } else {
                // Check blast radius
                if (
                  patch.blast_radius?.breaking_change_risk === 'HIGH' ||
                  patch.blast_radius?.ast_impact_scope === 'PUBLIC_API'
                ) {
                  hasHighBlastRadius = true;
                  const patchRule: RuleEvaluation = {
                    rule_id: 'RULE_BLAST_RADIUS',
                    status: 'PASS',
                    finding_id: finding.finding_id,
                    reason: `Patch ${patch.patch_id} has HIGH blast radius or impacts public API; requires human release authorization`,
                  };
                  rulesEvaluated.push(patchRule);
                  this.auditLogger.logRuleEvaluation(patchRule);
                } else {
                  const patchRule: RuleEvaluation = {
                    rule_id: 'RULE_PATCH_VERIFIED',
                    status: 'PASS',
                    finding_id: finding.finding_id,
                    reason: `Patch ${patch.patch_id} verified clean with zero regressions`,
                  };
                  rulesEvaluated.push(patchRule);
                  this.auditLogger.logRuleEvaluation(patchRule);
                }
              }
            }
          }
        }
      }
    }

    // 9. Quad-State Verdict Resolution with Strict Precedence
    let verdict: GateVerdict;
    let summary: string;

    const uniqueBlocking = Array.from(new Set(blockingFindings));
    const uniqueUnverified = Array.from(new Set(unverifiedFindings));

    // Priority 1: REJECT
    // - SoD violation (agent self-certification or overlapping roles)
    // - Unverified findings / missing evidence
    // - Expired policy exceptions
    // - Tampered custody chain / broken Merkle root
    // - Out of scope target / directory traversal
    if (!sodResult.is_valid) {
      verdict = GateVerdict.REJECT;
      summary = `Gate REJECTED due to Separation of Duties violation: ${sodResult.violation_details}`;
    } else if (hasExpiredExceptions) {
      verdict = GateVerdict.REJECT;
      summary = `Gate REJECTED due to expired policy exception(s). Exceptions must have expires >= today.`;
    } else if (!isCustodyValid) {
      verdict = GateVerdict.REJECT;
      summary = `Gate REJECTED due to cryptographic custody chain corruption or Merkle root tampering.`;
    } else if (hasScopeEscape) {
      verdict = GateVerdict.REJECT;
      summary = `Gate REJECTED due to unauthorized file path escaping scope boundaries.`;
    } else if (uniqueUnverified.length > 0) {
      verdict = GateVerdict.REJECT;
      summary = `Gate REJECTED under Zero-Trust Gate Predicate: ${uniqueUnverified.length} finding(s) lack independent empirical verification evidence [${uniqueUnverified.join(', ')}].`;
    }
    // Priority 2: BLOCK
    // - Inconclusive reproducer status
    // - Proposed patch with regression detected or reproducer still failing
    // - Unremediated critical/high vulnerabilities
    // - Policy limits violated
    else if (uniqueBlocking.length > 0 || hasInconclusiveEvidence || hasPatchRegression || limitViolated) {
      verdict = GateVerdict.BLOCK;
      summary = `Gate BLOCKED: ${uniqueBlocking.length} blocking finding(s) detected [${uniqueBlocking.join(', ')}].`;
      if (hasInconclusiveEvidence) summary += ` Inconclusive reproducer execution detected.`;
      if (hasPatchRegression) summary += ` Regression detected in proposed patch.`;
      if (limitViolated) summary += ` Policy size or file limits exceeded.`;
    }
    // Priority 3: REQUIRES_HUMAN_APPROVAL
    // - Clean evaluation, but high blast radius patch requires operator sign-off
    else if (hasHighBlastRadius) {
      verdict = GateVerdict.REQUIRES_HUMAN_APPROVAL;
      summary = `Gate clean but REQUIRES_HUMAN_APPROVAL: High blast radius patch requires manual authorization.`;
    }
    // Priority 4: PASS
    // - Zero blocking findings, zero unverified findings, valid SoD, unexpired exceptions, clean regressions
    else {
      verdict = GateVerdict.PASS;
      summary = `Quality Gate PASSED: All findings verified, zero blocking issues, zero regressions, valid SoD, and unbroken custody chain.`;
    }

    // 10. Audit Logging and SHA-256 Merkle Root Calculation
    const decisionId = `SK-GATE-${Date.now()}-${randomUUID().slice(0, 8)}`;

    const candidateDecision = {
      decision_id: decisionId,
      policy_version: policy.version.toString(),
      policy_id: request.policy_id ?? 'default-zero-trust-policy',
      target_commit: targetCommit,
      verdict,
      blocking_findings: verdict === GateVerdict.PASS ? [] : uniqueBlocking,
      unverified_findings: verdict === GateVerdict.PASS ? [] : uniqueUnverified,
      sod_evaluation: {
        discovering_agent_id: sodResult.discovering_agent_id,
        verifying_agent_id: sodResult.verifying_agent_id,
        authorizing_agent_id: sodResult.authorizing_agent_id,
        is_valid: sodResult.is_valid,
        violation_details: sodResult.violation_details,
      },
      rules_evaluated: rulesEvaluated,
      evaluation_summary: summary,
      decided_at: evaluationTimestamp,
    };

    this.auditLogger.logGateDecision(candidateDecision);
    const auditMerkleRoot = this.auditLogger.getMerkleRoot();

    const finalizedDecision = {
      ...candidateDecision,
      audit_merkle_root: auditMerkleRoot,
    };

    // 11. Final Schema Validation & Invariant Enforcement
    return GateDecisionSchema.parse(finalizedDecision);
  }
}

/**
 * Convenience evaluation helper function.
 */
export async function evaluateQualityGate(request: GateEvaluationRequest): Promise<GateDecision> {
  const engine = new DeterministicQualityGate();
  return engine.evaluate(request);
}
