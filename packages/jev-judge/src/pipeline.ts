/**
 * @file packages/jev-judge/src/pipeline.ts
 * @description JEV-as-a-Judge v0 deterministic pre-validation, sanitized JEV evaluation,
 * escalation policy, and deterministic risk assessment pipeline.
 */

import {
  sanitizeStateForJev,
  type SanitizedJevState,
} from './sanitizer.js';
import {
  AdjudicationResultSchema,
  ApprovedPolicyRefSchema,
  JEV_RUBRIC_VERSION,
  JevAuthContextSchema,
  JevEscalationPolicyConfigSchema,
  JudgeAnalysisInputSchema,
  JudgeEvidenceInputSchema,
  sha256,
  type AdjudicationResult,
  type ApprovedPolicyRef,
  type AtomicJevAnswers,
  type JevAuthContext,
  type JevDecisionSource,
  type JevEscalationPolicyConfig,
  type JevProviderStatus,
  type JevRiskLevel,
  type JudgeAnalysisInput,
  type JudgeEvidenceInput,
  type PreValidationIssue,
  type PreValidationResult,
} from './schemas.js';
import {
  buildJevAtomicQuestions,
  JEV_ATOMIC_QUESTION_TEXTS,
  MockTypeSafeJevProvider,
  resolveDefaultJevProvider,
  type JevInferenceOutput,
  type JevProvider,
  type TypeSafeClientLike,
} from './typesafe-provider.js';

export interface EvaluateWithJevJudgeInput {
  analysis: JudgeAnalysisInput;
  evidence?: JudgeEvidenceInput[];
  authContext: JevAuthContext;
  sourceGraph?: Record<string, unknown>;
  expectedInputSha256?: string;
  evidencePayloads?: Record<string, unknown>;
  approvedPolicies?: ApprovedPolicyRef[];
  escalationPolicy?: Partial<JevEscalationPolicyConfig>;
  provider?: JevProvider;
  client?: TypeSafeClientLike;
  model?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  now?: string;
}

const RISK_SEVERITY_ORDER: Record<JevRiskLevel, number> = {
  P0: 5,
  P1: 4,
  P2: 3,
  P3: 2,
  UNDETERMINED: 1,
  NONE: 0,
};

function isMissingOrPlaceholderRef(value: string | undefined): boolean {
  if (!value) return true;
  const trimmed = value.trim();
  if (!trimmed) return true;
  const lower = trimmed.toLowerCase();
  return (
    lower === 'missing' ||
    lower === 'unknown' ||
    lower === 'none' ||
    lower === 'n/a'
  );
}

function collectEvidenceMap(
  analysis: JudgeAnalysisInput,
  extraEvidence?: JudgeEvidenceInput[]
): Map<string, JudgeEvidenceInput> {
  const map = new Map<string, JudgeEvidenceInput>();
  for (const ev of analysis.evidence ?? []) {
    map.set(ev.evidenceId, ev);
  }
  for (const ev of extraEvidence ?? []) {
    map.set(ev.evidenceId, ev);
  }
  return map;
}

function computeSourceGraphSha256(graph: Record<string, unknown>): string {
  const copy = { ...graph };
  delete copy.declaredInputSha256;
  return sha256(copy);
}

/**
 * Computes risk strictly from deterministic graph findings and legitimate-operation status.
 * JEV NEVER defines `P0` alone.
 */
export function computeDeterministicRiskRecommendation(
  analysis: JudgeAnalysisInput,
  preValidationPassed: boolean
): JevRiskLevel {
  if (!preValidationPassed) {
    return 'UNDETERMINED';
  }
  if (analysis.status === 'FAILED') {
    return 'UNDETERMINED';
  }
  if (analysis.paths.length === 0) {
    return analysis.legitimateOperationsPreserved ? 'NONE' : 'P2';
  }

  let highest: JevRiskLevel = 'P3';
  let sawUndetermined = false;
  let sawConcrete = false;

  for (const path of analysis.paths) {
    if (path.status === 'INCONCLUSIVE' || path.riskRecommendation === 'UNDETERMINED') {
      sawUndetermined = true;
      continue;
    }
    sawConcrete = true;
    const candidate = path.riskRecommendation;
    if (RISK_SEVERITY_ORDER[candidate] > RISK_SEVERITY_ORDER[highest]) {
      highest = candidate;
    }
  }

  if (!sawConcrete && sawUndetermined) {
    return 'UNDETERMINED';
  }
  return highest;
}

/**
 * Deterministic pre-validations executed strictly BEFORE calling TypeSafe JEV.
 * Validates identity & tenant scope, LAB mode, SHA-256 hash integrity, evidence completeness
 * & verification status, and policy/sourceRef provenance.
 */
export function runDeterministicPreValidations(params: {
  analysis: JudgeAnalysisInput;
  evidence?: JudgeEvidenceInput[];
  authContext: JevAuthContext;
  sourceGraph?: Record<string, unknown>;
  expectedInputSha256?: string;
  evidencePayloads?: Record<string, unknown>;
  approvedPolicies?: ApprovedPolicyRef[];
  now?: string;
}): PreValidationResult {
  const checkedAt = params.now ?? new Date().toISOString();
  const issues: PreValidationIssue[] = [];
  let shouldReject = false;

  const { analysis, authContext } = params;

  // 1. Identity & Tenant Scope
  let identityAndTenantScope = true;
  if (
    !authContext.principalId?.trim() ||
    !authContext.tenantId?.trim() ||
    analysis.tenantId !== authContext.tenantId
  ) {
    identityAndTenantScope = false;
    shouldReject = true;
    issues.push({
      code: 'TENANT_SCOPE_MISMATCH',
      severity: 'ERROR',
      message: `Authenticated tenant '${authContext.tenantId}' does not match analysis tenant '${analysis.tenantId}'`,
      refId: analysis.analysisId,
    });
  }

  for (const spec of analysis.remediationSpecs ?? []) {
    if (spec.tenantId && spec.tenantId !== authContext.tenantId) {
      identityAndTenantScope = false;
      shouldReject = true;
      issues.push({
        code: 'REMEDIATION_TENANT_MISMATCH',
        severity: 'ERROR',
        message: 'RemediationSpec tenantId does not match authenticated tenant',
      });
    }
  }

  // 2. LAB Mode & Analysis Status Boundary
  let labModeBoundary = true;
  if (analysis.mode !== 'LAB' || analysis.productionTested === true) {
    labModeBoundary = false;
    shouldReject = true;
    issues.push({
      code: 'PRODUCTION_EXECUTION_FORBIDDEN',
      severity: 'ERROR',
      message: 'JEV-as-a-Judge v0 strictly permits LAB-mode non-production analyses only',
      refId: analysis.analysisId,
    });
  }
  if (analysis.status === 'FAILED' || analysis.status === 'QUEUED' || analysis.status === 'RUNNING') {
    labModeBoundary = false;
    issues.push({
      code: 'ANALYSIS_NOT_READY_OR_FAILED',
      severity: 'ERROR',
      message: `Analysis status '${analysis.status}' cannot pass deterministic pre-validation`,
      refId: analysis.analysisId,
    });
  }

  // 3. Hash Integrity
  let hashIntegrity = true;
  if (!/^[a-f0-9]{64}$/i.test(analysis.inputSha256)) {
    hashIntegrity = false;
    shouldReject = true;
    issues.push({
      code: 'INVALID_INPUT_SHA256',
      severity: 'ERROR',
      message: 'Analysis inputSha256 is missing or invalid 64-hex SHA-256',
      refId: analysis.analysisId,
    });
  }

  if (
    params.expectedInputSha256 &&
    params.expectedInputSha256.toLowerCase() !== analysis.inputSha256.toLowerCase()
  ) {
    hashIntegrity = false;
    shouldReject = true;
    issues.push({
      code: 'INPUT_HASH_MISMATCH',
      severity: 'ERROR',
      message: `Expected inputSha256 '${params.expectedInputSha256}' does not match analysis inputSha256 '${analysis.inputSha256}'`,
      refId: analysis.analysisId,
    });
  }

  if (params.sourceGraph) {
    const computed = computeSourceGraphSha256(params.sourceGraph);
    const declared =
      typeof params.sourceGraph.declaredInputSha256 === 'string'
        ? params.sourceGraph.declaredInputSha256.toLowerCase()
        : undefined;
    if (declared && declared !== computed) {
      hashIntegrity = false;
      shouldReject = true;
      issues.push({
        code: 'SOURCE_GRAPH_TAMPER_DETECTED',
        severity: 'ERROR',
        message: 'sourceGraph declaredInputSha256 does not match computed canonical SHA-256',
        refId: analysis.analysisId,
      });
    }
    if (computed !== analysis.inputSha256.toLowerCase()) {
      hashIntegrity = false;
      shouldReject = true;
      issues.push({
        code: 'SOURCE_GRAPH_HASH_MISMATCH',
        severity: 'ERROR',
        message: 'sourceGraph computed SHA-256 does not match analysis inputSha256',
        refId: analysis.analysisId,
      });
    }
  }

  // 4. Evidence Completeness, Integrity, and Verification
  let evidenceCompletenessAndVerification = true;
  const evidenceMap = collectEvidenceMap(analysis, params.evidence);

  if (analysis.evidenceIds.length === 0 || evidenceMap.size === 0) {
    evidenceCompletenessAndVerification = false;
    issues.push({
      code: 'MISSING_EVIDENCE',
      severity: 'ERROR',
      message: 'Analysis has no attached evidence identifiers',
      refId: analysis.analysisId,
    });
  }

  const requiredEvidenceIds = new Set<string>(analysis.evidenceIds);
  for (const p of analysis.paths) {
    for (const eid of p.evidenceIds) {
      requiredEvidenceIds.add(eid);
    }
  }

  for (const eid of requiredEvidenceIds) {
    const ev = evidenceMap.get(eid);
    if (!ev) {
      evidenceCompletenessAndVerification = false;
      issues.push({
        code: 'EVIDENCE_ID_UNRESOLVED',
        severity: 'ERROR',
        message: `Referenced evidenceId '${eid}' does not exist in evidence store`,
        refId: eid,
      });
      continue;
    }

    if (ev.analysisId !== analysis.analysisId) {
      evidenceCompletenessAndVerification = false;
      shouldReject = true;
      issues.push({
        code: 'EVIDENCE_ANALYSIS_MISMATCH',
        severity: 'ERROR',
        message: `Evidence '${eid}' belongs to analysis '${ev.analysisId}', expected '${analysis.analysisId}'`,
        refId: eid,
      });
    }

    if (!/^[a-f0-9]{64}$/i.test(ev.contentSha256)) {
      hashIntegrity = false;
      shouldReject = true;
      issues.push({
        code: 'EVIDENCE_INVALID_HASH',
        severity: 'ERROR',
        message: `Evidence '${eid}' lacks valid 64-char SHA-256 digest`,
        refId: eid,
      });
    }

    if (params.evidencePayloads && Object.prototype.hasOwnProperty.call(params.evidencePayloads, eid)) {
      const recomputed = sha256(params.evidencePayloads[eid]);
      if (recomputed !== ev.contentSha256.toLowerCase()) {
        hashIntegrity = false;
        shouldReject = true;
        issues.push({
          code: 'EVIDENCE_PAYLOAD_HASH_MISMATCH',
          severity: 'ERROR',
          message: `Evidence '${eid}' payload digest does not match recorded contentSha256`,
          refId: eid,
        });
      }
    }

    if (ev.verified !== true) {
      evidenceCompletenessAndVerification = false;
      issues.push({
        code: 'UNVERIFIED_EVIDENCE',
        severity: 'ERROR',
        message: `Evidence '${eid}' is marked verified=false and cannot be accepted`,
        refId: eid,
      });
    }

    if (isMissingOrPlaceholderRef(ev.sourceRef)) {
      evidenceCompletenessAndVerification = false;
      issues.push({
        code: 'EVIDENCE_MISSING_SOURCE_REF',
        severity: 'ERROR',
        message: `Evidence '${eid}' has missing or placeholder sourceRef`,
        refId: eid,
      });
    }
  }

  // Also check any additional supplied evidence for unverified flags / mismatched analysisId
  for (const ev of evidenceMap.values()) {
    if (ev.analysisId !== analysis.analysisId) {
      evidenceCompletenessAndVerification = false;
      shouldReject = true;
      issues.push({
        code: 'EVIDENCE_ANALYSIS_MISMATCH',
        severity: 'ERROR',
        message: `Evidence '${ev.evidenceId}' analysisId mismatch`,
        refId: ev.evidenceId,
      });
    }
    if (ev.verified !== true) {
      evidenceCompletenessAndVerification = false;
      issues.push({
        code: 'UNVERIFIED_EVIDENCE',
        severity: 'ERROR',
        message: `Evidence '${ev.evidenceId}' is unverified (verified=false)`,
        refId: ev.evidenceId,
      });
    }
    if (!/^[a-f0-9]{64}$/i.test(ev.contentSha256)) {
      hashIntegrity = false;
      shouldReject = true;
      issues.push({
        code: 'EVIDENCE_INVALID_HASH',
        severity: 'ERROR',
        message: `Evidence '${ev.evidenceId}' has invalid contentSha256`,
        refId: ev.evidenceId,
      });
    }
  }

  // 5. Policy References & Path Provenance
  let policyAndSourceRefs = true;
  if (isMissingOrPlaceholderRef(analysis.policyVersion)) {
    policyAndSourceRefs = false;
    issues.push({
      code: 'MISSING_POLICY_VERSION',
      severity: 'ERROR',
      message: 'Analysis policyVersion is missing',
      refId: analysis.analysisId,
    });
  }

  const approvedMap = new Map<string, ApprovedPolicyRef>();
  for (const pol of params.approvedPolicies ?? []) {
    const parsedPol = ApprovedPolicyRefSchema.safeParse(pol);
    if (parsedPol.success) {
      approvedMap.set(
        `${parsedPol.data.policyId}@${parsedPol.data.policyVersion}`,
        parsedPol.data
      );
    }
  }

  for (const path of analysis.paths) {
    if (isMissingOrPlaceholderRef(path.violatedPolicyId)) {
      policyAndSourceRefs = false;
      issues.push({
        code: 'MISSING_VIOLATED_POLICY_ID',
        severity: 'ERROR',
        message: `Path '${path.pathId}' is missing violatedPolicyId`,
        refId: path.pathId,
      });
    }

    if (
      params.approvedPolicies &&
      params.approvedPolicies.length > 0 &&
      !approvedMap.has(`${path.violatedPolicyId}@${analysis.policyVersion}`)
    ) {
      policyAndSourceRefs = false;
      issues.push({
        code: 'POLICY_REFERENCE_UNAPPROVED_OR_MISSING',
        severity: 'ERROR',
        message: `Policy '${path.violatedPolicyId}@${analysis.policyVersion}' is not in approved policy snapshots`,
        refId: path.violatedPolicyId,
      });
    }

    if (path.status === 'INCONCLUSIVE' || (path.missingReferences && path.missingReferences.length > 0)) {
      policyAndSourceRefs = false;
      issues.push({
        code: 'INCONCLUSIVE_PATH_PROVENANCE',
        severity: 'ERROR',
        message: `Path '${path.pathId}' has INCONCLUSIVE provenance or missingReferences`,
        refId: path.pathId,
      });
    }

    if (path.evidenceIds.length === 0) {
      evidenceCompletenessAndVerification = false;
      issues.push({
        code: 'PATH_MISSING_EVIDENCE_IDS',
        severity: 'ERROR',
        message: `Path '${path.pathId}' has no backing evidenceIds`,
        refId: path.pathId,
      });
    }

    for (const edge of path.edges) {
      if (isMissingOrPlaceholderRef(edge.sourceRef)) {
        policyAndSourceRefs = false;
        issues.push({
          code: 'EDGE_MISSING_SOURCE_REF',
          severity: 'ERROR',
          message: `Edge '${edge.edgeId}' on path '${path.pathId}' lacks valid sourceRef`,
          refId: edge.edgeId,
        });
      }
      if (
        isMissingOrPlaceholderRef(edge.policyVersion) ||
        edge.policyVersion !== analysis.policyVersion
      ) {
        policyAndSourceRefs = false;
        issues.push({
          code: 'EDGE_POLICY_VERSION_MISMATCH',
          severity: 'ERROR',
          message: `Edge '${edge.edgeId}' policyVersion '${edge.policyVersion}' does not match '${analysis.policyVersion}'`,
          refId: edge.edgeId,
        });
      }
    }
  }

  const passed =
    identityAndTenantScope &&
    labModeBoundary &&
    hashIntegrity &&
    evidenceCompletenessAndVerification &&
    policyAndSourceRefs;

  return {
    passed,
    blockingOutcome: passed ? 'NONE' : shouldReject ? 'REJECTED' : 'BLOCKED',
    checkedAt,
    checks: {
      identityAndTenantScope,
      labModeBoundary,
      hashIntegrity,
      evidenceCompletenessAndVerification,
      policyAndSourceRefs,
    },
    issues,
  };
}

export function detectJevContradictions(
  answers: AtomicJevAnswers,
  analysis: JudgeAnalysisInput
): string[] {
  const contradictions: string[] = [];
  const { evidence_sufficient, needs_manual_review, triage } = answers;

  if (
    triage.choice === 'likely_actionable' &&
    evidence_sufficient.noul < 0.5
  ) {
    contradictions.push(
      `CONTRADICTION_ACTIONABLE_LOW_EVIDENCE: triage='likely_actionable' conflicts with evidence_sufficient=${evidence_sufficient.noul}`
    );
  }

  if (
    triage.choice === 'likely_actionable' &&
    analysis.paths.length === 0
  ) {
    contradictions.push(
      `CONTRADICTION_ACTIONABLE_NO_PATHS: triage='likely_actionable' claimed on analysis with 0 modeled attack paths`
    );
  }

  if (
    triage.choice === 'likely_irrelevant' &&
    analysis.paths.some((p) => p.status === 'PATH_VALIDATED')
  ) {
    contradictions.push(
      `CONTRADICTION_IRRELEVANT_VALIDATED_PATH: triage='likely_irrelevant' conflicts with deterministic PATH_VALIDATED reachability finding(s)`
    );
  }

  if (
    triage.choice === 'needs_more_evidence' &&
    evidence_sufficient.noul >= 0.85 &&
    needs_manual_review.noul < 0.2 &&
    analysis.paths.length > 0
  ) {
    contradictions.push(
      `CONTRADICTION_EVIDENCE_SCORE_VS_TRIAGE: triage='needs_more_evidence' conflicts with high evidence_sufficient=${evidence_sufficient.noul} and low needs_manual_review=${needs_manual_review.noul}`
    );
  }

  const chosenProb = triage.probabilities[triage.choice];
  if (chosenProb === undefined) {
    contradictions.push(
      `CONTRADICTION_MISSING_CHOICE_PROBABILITY: probabilities map lacks chosen triage '${triage.choice}'`
    );
  } else {
    if (Math.abs(chosenProb - triage.confidence) > 0.05) {
      contradictions.push(
        `CONTRADICTION_CONFIDENCE_MISMATCH: triage.confidence=${triage.confidence} disagrees with probabilities['${triage.choice}']=${chosenProb}`
      );
    }
    for (const [label, prob] of Object.entries(triage.probabilities)) {
      if (label !== triage.choice && prob > chosenProb + 1e-6) {
        contradictions.push(
          `CONTRADICTION_NON_MAX_CHOICE: probabilities['${label}']=${prob} exceeds chosen '${triage.choice}'=${chosenProb}`
        );
      }
    }
  }

  return contradictions;
}

/**
 * Pure post-validation / escalation & risk policy evaluation.
 * Enforces that deterministic pre-validation failure ALWAYS blocks/rejects even if JEV
 * returned 0.99 confidence.
 */
export function applyEscalationAndRiskPolicy(params: {
  evaluationId: string;
  analysis: JudgeAnalysisInput;
  evidence: JudgeEvidenceInput[];
  preValidation: PreValidationResult;
  sanitizedStateDigest: string;
  inference?: JevInferenceOutput;
  providerStatus: JevProviderStatus;
  config: JevEscalationPolicyConfig;
  timestamp: string;
}): AdjudicationResult {
  const {
    evaluationId,
    analysis,
    evidence,
    preValidation,
    sanitizedStateDigest,
    inference,
    providerStatus,
    config,
    timestamp,
  } = params;

  const sourceRefs = Array.from(
    new Set(
      [
        ...evidence.map((e) => e.sourceRef),
        ...analysis.paths.flatMap((p) => p.edges.map((ed) => ed.sourceRef)),
      ].filter((r) => !isMissingOrPlaceholderRef(r))
    )
  );
  const evidenceIds = Array.from(
    new Set([
      ...analysis.evidenceIds,
      ...evidence.map((e) => e.evidenceId),
    ])
  );

  const deterministicRisk = computeDeterministicRiskRecommendation(
    analysis,
    preValidation.passed
  );

  const calibrationNote =
    'Threshold is uncalibrated raw score/confidence; not a calibrated statistical probability.';

  // INVARIANT 1: Deterministic validation failure ALWAYS blocks/rejects before trusting JEV
  if (!preValidation.passed) {
    const isRejected = preValidation.blockingOutcome === 'REJECTED';
    const reasons = preValidation.issues.map((i) => `${i.code}: ${i.message}`);
    return AdjudicationResultSchema.parse({
      evaluationId,
      analysisId: analysis.analysisId,
      tenantId: analysis.tenantId,
      model: inference?.model ?? 'deterministic-pre-validator',
      modelVersion: inference?.modelVersion ?? '0.1.0',
      rubricVersion: JEV_RUBRIC_VERSION,
      questions: JEV_ATOMIC_QUESTION_TEXTS,
      answers: null,
      triage: null,
      decision: isRejected ? 'rejected_pre_validation' : 'blocked_pre_validation',
      status: isRejected ? 'REJECTED' : 'BLOCKED',
      probabilities: {
        evidenceSufficient: 0,
        needsManualReview: 1,
        triageProbabilities: {},
      },
      confidenceOrUncertainty: {
        confidence: 0,
        uncertainty: 1,
        evidenceSufficiencyScore: 0,
        manualReviewScore: 1,
        threshold: config.confidenceThreshold,
        thresholdCalibrated: false,
        calibrationNote,
      },
      escalated: true,
      escalationReasons: reasons,
      escalationReason: reasons.join('; '),
      requiresHumanReview: true,
      riskRecommendation: deterministicRisk,
      evidenceIds,
      sourceRefs,
      decisionSource: 'HUMAN_PENDING',
      providerStatus,
      preValidation,
      sanitizedStateDigest,
      mergeAllowed: false,
      deployAllowed: false,
      exploitConfirmed: false,
      p0DefinedByJevAlone: false,
      timestamp,
    });
  }

  // INVARIANT 2: Missing/unavailable provider fails closed to PENDING_REVIEW
  if (!inference) {
    const reasons = [
      `PROVIDER_UNAVAILABLE: JEV provider returned no valid adjudication (${providerStatus})`,
    ];
    return AdjudicationResultSchema.parse({
      evaluationId,
      analysisId: analysis.analysisId,
      tenantId: analysis.tenantId,
      model: 'unavailable',
      modelVersion: '0.0.0',
      rubricVersion: JEV_RUBRIC_VERSION,
      questions: JEV_ATOMIC_QUESTION_TEXTS,
      answers: null,
      triage: null,
      decision: 'escalated_provider_unavailable',
      status: 'PENDING_REVIEW',
      probabilities: {
        evidenceSufficient: 0,
        needsManualReview: 1,
        triageProbabilities: {},
      },
      confidenceOrUncertainty: {
        confidence: 0,
        uncertainty: 1,
        evidenceSufficiencyScore: 0,
        manualReviewScore: 1,
        threshold: config.confidenceThreshold,
        thresholdCalibrated: false,
        calibrationNote,
      },
      escalated: true,
      escalationReasons: reasons,
      escalationReason: reasons.join('; '),
      requiresHumanReview: true,
      riskRecommendation: deterministicRisk,
      evidenceIds,
      sourceRefs,
      decisionSource: 'HUMAN_PENDING',
      providerStatus,
      preValidation,
      sanitizedStateDigest,
      mergeAllowed: false,
      deployAllowed: false,
      exploitConfirmed: false,
      p0DefinedByJevAlone: false,
      timestamp,
    });
  }

  const { answers, decisionSource, model, modelVersion } = inference;
  const escalationReasons: string[] = [];

  // INVARIANT 3: Uncalibrated confidence & manual review thresholds
  if (answers.triage.confidence < config.confidenceThreshold) {
    escalationReasons.push(
      `LOW_CONFIDENCE: triage confidence ${answers.triage.confidence} < threshold ${config.confidenceThreshold} (uncalibrated)`
    );
  }
  if (answers.evidence_sufficient.noul < config.evidenceSufficiencyThreshold) {
    escalationReasons.push(
      `LOW_EVIDENCE_SUFFICIENCY: evidence_sufficient=${answers.evidence_sufficient.noul} < threshold ${config.evidenceSufficiencyThreshold}`
    );
  }
  if (answers.needs_manual_review.noul >= config.manualReviewThreshold) {
    escalationReasons.push(
      `JEV_FLAGGED_MANUAL_REVIEW: needs_manual_review=${answers.needs_manual_review.noul} >= threshold ${config.manualReviewThreshold}`
    );
  }

  // INVARIANT 4: Contradictory answers force human review
  for (const contradiction of detectJevContradictions(answers, analysis)) {
    escalationReasons.push(contradiction);
  }

  // INVARIANT 5: Critical impact (P0/P1) & broken legitimate ops force human review
  if (
    config.escalateOnCriticalRisk &&
    (deterministicRisk === 'P0' || deterministicRisk === 'P1' || deterministicRisk === 'UNDETERMINED')
  ) {
    escalationReasons.push(
      `CRITICAL_OR_UNDETERMINED_RISK: deterministic risk=${deterministicRisk} requires mandatory human review`
    );
  }
  if (!analysis.legitimateOperationsPreserved) {
    escalationReasons.push(
      'LEGITIMATE_OPERATIONS_NOT_PRESERVED: business workflows require human verification'
    );
  }
  if (answers.triage.choice === 'needs_more_evidence') {
    escalationReasons.push(
      'TRIAGE_NEEDS_MORE_EVIDENCE: JEV requested additional supporting evidence'
    );
  }

  const escalated = escalationReasons.length > 0;
  const status = escalated ? 'PENDING_REVIEW' : 'ACCEPTED_FOR_TRIAGE';
  const decision = escalated
    ? 'escalated_human_review'
    : answers.triage.choice === 'likely_actionable'
      ? 'triage_actionable'
      : 'triage_no_actionable_paths';

  return AdjudicationResultSchema.parse({
    evaluationId,
    analysisId: analysis.analysisId,
    tenantId: analysis.tenantId,
    model,
    modelVersion,
    rubricVersion: JEV_RUBRIC_VERSION,
    questions: JEV_ATOMIC_QUESTION_TEXTS,
    answers,
    triage: answers.triage.choice,
    decision,
    status,
    probabilities: {
      evidenceSufficient: answers.evidence_sufficient.noul,
      needsManualReview: answers.needs_manual_review.noul,
      triageProbabilities: answers.triage.probabilities,
    },
    confidenceOrUncertainty: {
      confidence: answers.triage.confidence,
      uncertainty: Number((1 - answers.triage.confidence).toFixed(6)),
      evidenceSufficiencyScore: answers.evidence_sufficient.noul,
      manualReviewScore: answers.needs_manual_review.noul,
      threshold: config.confidenceThreshold,
      thresholdCalibrated: false,
      calibrationNote,
    },
    escalated,
    escalationReasons,
    ...(escalated ? { escalationReason: escalationReasons.join('; ') } : {}),
    requiresHumanReview: escalated,
    riskRecommendation: deterministicRisk,
    evidenceIds,
    sourceRefs,
    decisionSource,
    providerStatus: inference.providerStatus,
    preValidation,
    sanitizedStateDigest,
    mergeAllowed: false,
    deployAllowed: false,
    exploitConfirmed: false,
    p0DefinedByJevAlone: false,
    timestamp,
  });
}

/**
 * Runs the complete JEV-as-a-Judge v0 pipeline:
 * Graph facts + Evidence -> Deterministic pre-validations -> Sanitized State ->
 * JEV atomic questions -> Escalation policy -> Deterministic Risk policy -> AdjudicationResult.
 */
export async function evaluateWithJevJudge(
  rawInput: EvaluateWithJevJudgeInput
): Promise<AdjudicationResult> {
  const analysis = JudgeAnalysisInputSchema.parse(rawInput.analysis);
  const authContext = JevAuthContextSchema.parse(rawInput.authContext);
  const extraEvidence = (rawInput.evidence ?? []).map((e) =>
    JudgeEvidenceInputSchema.parse(e)
  );
  const config = JevEscalationPolicyConfigSchema.parse(
    rawInput.escalationPolicy ?? {}
  );
  const timestamp = rawInput.now ?? new Date().toISOString();

  const mergedEvidenceMap = collectEvidenceMap(analysis, extraEvidence);
  const allEvidence = Array.from(mergedEvidenceMap.values());

  const provider =
    rawInput.provider ?? resolveDefaultJevProvider({ client: rawInput.client });

  const preValidation = runDeterministicPreValidations({
    analysis,
    evidence: extraEvidence,
    authContext,
    sourceGraph: rawInput.sourceGraph,
    expectedInputSha256: rawInput.expectedInputSha256,
    evidencePayloads: rawInput.evidencePayloads,
    approvedPolicies: rawInput.approvedPolicies,
    now: timestamp,
  });

  const evaluationId = `jev-${sha256({
    analysisId: analysis.analysisId,
    tenantId: authContext.tenantId,
    inputSha256: analysis.inputSha256,
    timestamp,
  }).slice(0, 16)}`;

  let sanitizedState: SanitizedJevState;
  let sanitizedStateDigest: string;
  try {
    const sanitized = sanitizeStateForJev(analysis, extraEvidence);
    sanitizedState = sanitized.state;
    sanitizedStateDigest = sanitized.sanitizedStateDigest;
  } catch {
    sanitizedStateDigest = sha256({
      analysisId: analysis.analysisId,
      sanitizationFailed: true,
    });
    return applyEscalationAndRiskPolicy({
      evaluationId,
      analysis,
      evidence: allEvidence,
      preValidation: {
        ...preValidation,
        passed: false,
        blockingOutcome: 'BLOCKED',
        issues: [
          ...preValidation.issues,
          {
            code: 'SANITIZATION_BLOCKED',
            severity: 'ERROR',
            message: 'State failed secret/code sanitization before JEV inference',
          },
        ],
      },
      sanitizedStateDigest,
      providerStatus: provider.getStatus(),
      config,
      timestamp,
    });
  }

  // Deterministic validation failure BEFORE JEV immediately blocks/rejects without calling JEV
  if (!preValidation.passed) {
    return applyEscalationAndRiskPolicy({
      evaluationId,
      analysis,
      evidence: allEvidence,
      preValidation,
      sanitizedStateDigest,
      providerStatus: provider.getStatus(),
      config,
      timestamp,
    });
  }

  const questions = buildJevAtomicQuestions();
  let inference: JevInferenceOutput | undefined;
  let effectiveProviderStatus: JevProviderStatus = provider.getStatus();

  try {
    inference = await provider.evaluate({
      state: sanitizedState,
      questions,
      model: rawInput.model,
      signal: rawInput.signal,
      timeoutMs: rawInput.timeoutMs,
    });
    effectiveProviderStatus = inference.providerStatus;
  } catch {
    if (config.fallbackOnProviderError === 'MOCK') {
      const fallbackProvider = new MockTypeSafeJevProvider({ asFallback: true });
      inference = await fallbackProvider.evaluate({ state: sanitizedState });
      effectiveProviderStatus = inference.providerStatus;
    } else {
      inference = undefined;
      effectiveProviderStatus = 'UNAVAILABLE';
    }
  }

  return applyEscalationAndRiskPolicy({
    evaluationId,
    analysis,
    evidence: allEvidence,
    preValidation,
    sanitizedStateDigest,
    inference,
    providerStatus: effectiveProviderStatus,
    config,
    timestamp,
  });
}
