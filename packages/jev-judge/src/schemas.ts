/**
 * @file packages/jev-judge/src/schemas.ts
 * @description Canonical Zod schemas and types for JEV-as-a-Judge v0 (`@script-kitty/jev-judge`).
 * Enforces evidence-first pre-validations, uncalibrated threshold escalation,
 * and strict non-authorization safety invariants.
 */

import * as crypto from 'node:crypto';
import { z } from 'zod';

export function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalStringify(item)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return (
    '{' +
    keys
      .map((k) => `${JSON.stringify(k)}:${canonicalStringify(obj[k])}`)
      .join(',') +
    '}'
  );
}

export function sha256(value: unknown): string {
  const input = typeof value === 'string' ? value : canonicalStringify(value);
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

export const JEV_RUBRIC_VERSION = 'jev-rubric-v0' as const;

export const JevTriageChoiceSchema = z.enum([
  'likely_actionable',
  'needs_more_evidence',
  'likely_irrelevant',
]);
export type JevTriageChoice = z.infer<typeof JevTriageChoiceSchema>;

export const JevDecisionSourceSchema = z.enum([
  'LIVE',
  'MOCK',
  'FALLBACK',
  'HUMAN_PENDING',
]);
export type JevDecisionSource = z.infer<typeof JevDecisionSourceSchema>;

export const JevProviderStatusSchema = z.enum([
  'LIVE',
  'NOT_CONFIGURED',
  'FALLBACK',
  'UNAVAILABLE',
]);
export type JevProviderStatus = z.infer<typeof JevProviderStatusSchema>;

export const JevAdjudicationStatusSchema = z.enum([
  'ACCEPTED_FOR_TRIAGE',
  'PENDING_REVIEW',
  'BLOCKED',
  'REJECTED',
  'INCONCLUSIVE',
]);
export type JevAdjudicationStatus = z.infer<typeof JevAdjudicationStatusSchema>;

export const JevRiskLevelSchema = z.enum([
  'P0',
  'P1',
  'P2',
  'P3',
  'NONE',
  'UNDETERMINED',
]);
export type JevRiskLevel = z.infer<typeof JevRiskLevelSchema>;

export const NoulAnswerSchema = z.object({
  type: z.literal('noul'),
  noul: z.number().min(0).max(1),
});
export type NoulAnswer = z.infer<typeof NoulAnswerSchema>;

export const ChoiceAnswerSchema = z.object({
  type: z.literal('choice'),
  choice: JevTriageChoiceSchema,
  confidence: z.number().min(0).max(1),
  probabilities: z.record(z.number().min(0).max(1)),
});
export type ChoiceAnswer = z.infer<typeof ChoiceAnswerSchema>;

export const AtomicJevAnswersSchema = z.object({
  evidence_sufficient: NoulAnswerSchema,
  needs_manual_review: NoulAnswerSchema,
  triage: ChoiceAnswerSchema,
});
export type AtomicJevAnswers = z.infer<typeof AtomicJevAnswersSchema>;

export const PreValidationIssueSchema = z.object({
  code: z.string().min(1),
  severity: z.enum(['ERROR', 'WARNING']),
  message: z.string().min(1),
  refId: z.string().optional(),
});
export type PreValidationIssue = z.infer<typeof PreValidationIssueSchema>;

export const PreValidationResultSchema = z.object({
  passed: z.boolean(),
  blockingOutcome: z.enum(['NONE', 'BLOCKED', 'REJECTED']),
  checkedAt: z.string().datetime(),
  checks: z.object({
    identityAndTenantScope: z.boolean(),
    labModeBoundary: z.boolean(),
    hashIntegrity: z.boolean(),
    evidenceCompletenessAndVerification: z.boolean(),
    policyAndSourceRefs: z.boolean(),
  }),
  issues: z.array(PreValidationIssueSchema),
});
export type PreValidationResult = z.infer<typeof PreValidationResultSchema>;

export const JevEscalationPolicyConfigSchema = z.object({
  confidenceThreshold: z.number().min(0).max(1).default(0.75),
  evidenceSufficiencyThreshold: z.number().min(0).max(1).default(0.75),
  manualReviewThreshold: z.number().min(0).max(1).default(0.5),
  escalateOnCriticalRisk: z.boolean().default(true),
  fallbackOnProviderError: z.enum(['HUMAN_PENDING', 'MOCK']).default('HUMAN_PENDING'),
});
export type JevEscalationPolicyConfig = z.infer<
  typeof JevEscalationPolicyConfigSchema
>;

export const JevAuthContextSchema = z.object({
  principalId: z.string().min(1),
  tenantId: z.string().min(1),
  correlationId: z.string().min(1).optional(),
});
export type JevAuthContext = z.infer<typeof JevAuthContextSchema>;

export const JudgeEvidenceInputSchema = z
  .object({
    evidenceId: z.string().min(1),
    analysisId: z.string().min(1),
    kind: z.enum([
      'POLICY_SNAPSHOT',
      'GRAPH_PATH',
      'TEST_RESULT',
      'QUALITY_RESULT',
    ]),
    sourceRef: z.string(),
    contentSha256: z.string(),
    producer: z.string().min(1),
    createdAt: z.string().min(1),
    commitSha: z.string().optional(),
    verified: z.boolean(),
    summary: z.string().optional(),
  })
  .passthrough();
export type JudgeEvidenceInput = z.infer<typeof JudgeEvidenceInputSchema>;

export const JudgePathEdgeInputSchema = z
  .object({
    edgeId: z.string().min(1),
    from: z.string().min(1),
    to: z.string().min(1),
    kind: z.string().min(1),
    scope: z.string().min(1),
    sourceRef: z.string(),
    policyId: z.string().optional(),
    policyVersion: z.string(),
    dataClassification: z.string().optional(),
  })
  .passthrough();
export type JudgePathEdgeInput = z.infer<typeof JudgePathEdgeInputSchema>;

export const JudgePathInputSchema = z
  .object({
    pathId: z.string().min(1),
    startIdentity: z.string().min(1),
    targetAsset: z.string().min(1),
    targetDestination: z.string().optional(),
    edges: z.array(JudgePathEdgeInputSchema),
    violatedPolicyId: z.string().min(1),
    status: z.enum([
      'POTENTIAL',
      'PATH_VALIDATED',
      'INCONCLUSIVE',
      'NOT_REPRODUCED',
    ]),
    evidenceIds: z.array(z.string()),
    riskRecommendation: z.enum(['P0', 'P1', 'P2', 'P3', 'UNDETERMINED']),
    explanation: z.string().optional(),
    nonTechnicalSummary: z.string().optional(),
    missingReferences: z.array(z.string()).optional(),
  })
  .passthrough();
export type JudgePathInput = z.infer<typeof JudgePathInputSchema>;

export const JudgeAnalysisInputSchema = z
  .object({
    schemaVersion: z.string(),
    analysisId: z.string().min(1),
    tenantId: z.string().min(1),
    fixtureId: z.string().min(1),
    commitSha: z.string().optional(),
    policyVersion: z.string().min(1),
    mode: z.string(),
    paths: z.array(JudgePathInputSchema),
    evidenceIds: z.array(z.string()),
    evidence: z.array(JudgeEvidenceInputSchema).optional(),
    remediationSpecs: z
      .array(z.object({ tenantId: z.string().optional() }).passthrough())
      .optional(),
    legitimateOperationsPreserved: z.boolean(),
    startedAt: z.string(),
    completedAt: z.string().optional(),
    status: z.enum([
      'QUEUED',
      'RUNNING',
      'COMPLETED',
      'INCONCLUSIVE',
      'FAILED',
    ]),
    inputSha256: z.string(),
    source: z.string().optional(),
    productionTested: z.boolean().optional(),
    diagnostics: z.array(z.record(z.unknown())).optional(),
  })
  .passthrough();
export type JudgeAnalysisInput = z.infer<typeof JudgeAnalysisInputSchema>;

export const ApprovedPolicyRefSchema = z.object({
  policyId: z.string().min(1),
  policyVersion: z.string().min(1),
  sourceRef: z.string().min(1),
  contentSha256: z.string().optional(),
});
export type ApprovedPolicyRef = z.infer<typeof ApprovedPolicyRefSchema>;

export const ConfidenceOrUncertaintySchema = z.object({
  confidence: z.number().min(0).max(1),
  uncertainty: z.number().min(0).max(1),
  evidenceSufficiencyScore: z.number().min(0).max(1),
  manualReviewScore: z.number().min(0).max(1),
  threshold: z.number().min(0).max(1),
  thresholdCalibrated: z.literal(false),
  calibrationNote: z.string().min(1),
});
export type ConfidenceOrUncertainty = z.infer<
  typeof ConfidenceOrUncertaintySchema
>;

export const AdjudicationResultSchema = z.object({
  evaluationId: z.string().min(1),
  analysisId: z.string().min(1),
  tenantId: z.string().min(1),
  model: z.string().min(1),
  modelVersion: z.string().min(1),
  rubricVersion: z.literal(JEV_RUBRIC_VERSION),
  questions: z.object({
    evidence_sufficient: z.string(),
    needs_manual_review: z.string(),
    triage: z.string(),
  }),
  answers: AtomicJevAnswersSchema.nullable(),
  triage: JevTriageChoiceSchema.nullable(),
  decision: z.string().min(1),
  status: JevAdjudicationStatusSchema,
  probabilities: z.object({
    evidenceSufficient: z.number().min(0).max(1),
    needsManualReview: z.number().min(0).max(1),
    triageProbabilities: z.record(z.number().min(0).max(1)),
  }),
  confidenceOrUncertainty: ConfidenceOrUncertaintySchema,
  escalated: z.boolean(),
  escalationReasons: z.array(z.string()),
  escalationReason: z.string().optional(),
  requiresHumanReview: z.boolean(),
  riskRecommendation: JevRiskLevelSchema,
  evidenceIds: z.array(z.string()),
  sourceRefs: z.array(z.string()),
  decisionSource: JevDecisionSourceSchema,
  providerStatus: JevProviderStatusSchema,
  preValidation: PreValidationResultSchema,
  sanitizedStateDigest: z.string().regex(/^[a-f0-9]{64}$/),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
  exploitConfirmed: z.literal(false),
  p0DefinedByJevAlone: z.literal(false),
  timestamp: z.string().datetime(),
});
export type AdjudicationResult = z.infer<typeof AdjudicationResultSchema>;
