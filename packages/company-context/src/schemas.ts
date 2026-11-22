/**
 * @file packages/company-context/src/schemas.ts
 * @description Canonical schemas for Company Brain v0 tenant-isolated persistence
 * and `factory.delivery.v1` delivery eligibility verification.
 */

import * as crypto from 'node:crypto';
import { z } from 'zod';

// ============================================================================
// 1. DETERMINISTIC HASHING & COMMON HELPERS
// ============================================================================

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

export const Sha256HexSchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/i, 'Must be a 64-character hex SHA-256');

export const CommitShaSchema = z
  .string()
  .regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/, 'commitSha must be 40 or 64 lowercase hex chars');

export const FlexibleCommitShaSchema = z
  .string()
  .regex(/^[a-f0-9]{7,64}$/i, 'commitSha must be 7-64 hex chars');

export const NonEmptyTenantIdSchema = z
  .string()
  .trim()
  .min(1, 'tenantId is required')
  .max(128, 'tenantId is too long');

// ============================================================================
// 2. FACTORY DELIVERY ELIGIBILITY (factory.delivery.v1)
// ============================================================================

export const FACTORY_DELIVERY_POLICY = {
  contract: 'factory.delivery.v1' as const,
  deadlineHours: 24,
  maxSubmissions: 4,
  maxOpen: 20,
  maxNewPerHour: 20,
  requiredChecks: ['tests', 'typecheck', 'build'] as const,
  externalExecution: false as const,
  mergeAllowed: false as const,
  deployAllowed: false as const,
  deploymentAllowed: false as const,
} as const;

export const utcDeadlinePattern =
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/;

const EvidenceRefSchema = z
  .string()
  .min(3)
  .max(200)
  .regex(/^[a-zA-Z0-9][a-zA-Z0-9_./:-]*$/);

export const FactoryDeliveryCheckSchema = z
  .object({
    key: z.enum(['tests', 'typecheck', 'build']),
    status: z.enum(['passed', 'failed']),
    evidenceRef: EvidenceRefSchema,
  })
  .strict();
export type FactoryDeliveryCheck = z.infer<typeof FactoryDeliveryCheckSchema>;

export const FactoryDeliveryArtifactSchema = z
  .object({
    commitSha: CommitShaSchema,
    summary: z.string().min(20).max(1000),
    checks: z.array(FactoryDeliveryCheckSchema).min(1).max(3),
  })
  .strict();
export type FactoryDeliveryArtifact = z.infer<
  typeof FactoryDeliveryArtifactSchema
>;

export const FactoryDeliveryReviewSchema = z
  .object({
    commitSha: CommitShaSchema,
    verdict: z.enum(['approve', 'changes_requested']),
    summary: z.string().min(20).max(1000),
    evidenceRefs: z.array(EvidenceRefSchema).min(1).max(10),
  })
  .strict();
export type FactoryDeliveryReview = z.infer<typeof FactoryDeliveryReviewSchema>;

export const FactoryDeliverySnapshotSchema = z
  .object({
    cancelled: z.boolean(),
    deadlineAt: z.string().regex(utcDeadlinePattern),
    submissions: z.number().int().min(0).max(4),
    maxSubmissions: z.literal(4),
    artifact: FactoryDeliveryArtifactSchema.nullable(),
    review: FactoryDeliveryReviewSchema.nullable(),
    submitter: z.string().min(3).max(100).nullable(),
    reviewer: z.string().min(3).max(100).nullable(),
  })
  .strict();
export type FactoryDeliverySnapshot = z.infer<
  typeof FactoryDeliverySnapshotSchema
>;

export const FactoryDeliveryAuthoritySchema = z
  .object({
    requesterActive: z.boolean(),
    submitterActive: z.boolean(),
    reviewerActive: z.boolean(),
    enabled: z.boolean(),
  })
  .strict();
export type FactoryDeliveryAuthority = z.infer<
  typeof FactoryDeliveryAuthoritySchema
>;

export const FactoryDeliveryRecordSchema = z
  .object({
    contract: z.literal('factory.delivery.v1'),
    snapshot: FactoryDeliverySnapshotSchema,
    authority: FactoryDeliveryAuthoritySchema,
  })
  .strict();
export type FactoryDeliveryRecord = z.infer<typeof FactoryDeliveryRecordSchema>;

export const DeliveryBlockReasonSchema = z.enum([
  'CANCELLED',
  'INVALID_DEADLINE',
  'DEADLINE_EXPIRED',
  'FACTORY_DISABLED',
  'REQUESTER_REVOKED',
  'INVALID_SNAPSHOT',
  'ARTIFACT_REQUIRED',
  'EXECUTOR_REVOKED',
  'HEAD_CHANGED',
  'CHECKS_INCOMPLETE',
  'REVIEW_REQUIRED',
  'REVIEW_STALE',
  'INDEPENDENT_REVIEW_REQUIRED',
  'REVIEWER_REVOKED',
  'CORRECTION_LIMIT',
  'CHANGES_REQUESTED',
]);
export type DeliveryBlockReason = z.infer<typeof DeliveryBlockReasonSchema>;

export const DeliveryStageSchema = z.enum([
  'approved',
  'cancelled',
  'blocked',
  'expired',
  'implementation',
  'review',
  'verification',
]);
export type DeliveryStage = z.infer<typeof DeliveryStageSchema>;

export const FactoryDeliveryEligibilityResultSchema = z.object({
  contract: z.literal('factory.delivery.v1'),
  eligible: z.boolean(),
  stage: DeliveryStageSchema,
  blockReason: DeliveryBlockReasonSchema.nullable(),
  submissionsRemaining: z.number().int().nonnegative(),
  correctionsRemaining: z.number().int().nonnegative(),
  commitSha: z.string().optional(),
  checkedAt: z.string().datetime(),
  externalExecution: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
  deploymentAllowed: z.literal(false),
});
export type FactoryDeliveryEligibilityResult = z.infer<
  typeof FactoryDeliveryEligibilityResultSchema
>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Trims artifact.summary and review.summary without mutating the caller's object,
 * matching factory-starter-kit normalizeDeliveryRecord behavior.
 */
export function normalizeDeliveryRecord(input: unknown): unknown {
  if (!isPlainObject(input) || !isPlainObject(input.snapshot)) {
    return input;
  }
  const normalizeSummary = (value: unknown): unknown =>
    isPlainObject(value) && typeof value.summary === 'string'
      ? { ...value, summary: value.summary.trim() }
      : value;

  return {
    ...input,
    snapshot: {
      ...input.snapshot,
      artifact: normalizeSummary(input.snapshot.artifact),
      review: normalizeSummary(input.snapshot.review),
    },
  };
}

export class FactoryDeliveryValidationError extends Error {
  readonly code: string;
  readonly issues: Array<{ path: string; message: string }>;

  constructor(
    code: string,
    message: string,
    issues: Array<{ path: string; message: string }> = []
  ) {
    super(`${code}: ${message}`);
    this.name = 'FactoryDeliveryValidationError';
    this.code = code;
    this.issues = issues;
  }
}

export interface EvaluateFactoryDeliveryOptions {
  headSha?: string;
  now?: Date | string;
}

/**
 * Assesses delivery eligibility strictly against `factory.delivery.v1` rules.
 * Guarantees fail-closed behavior and ALWAYS enforces `mergeAllowed: false`,
 * `deployAllowed: false`, `deploymentAllowed: false`, `externalExecution: false`.
 */
export function evaluateFactoryDeliveryEligibility(
  record: unknown,
  headShaOrOptions?: string | EvaluateFactoryDeliveryOptions,
  nowInput?: Date | string
): FactoryDeliveryEligibilityResult {
  const options: EvaluateFactoryDeliveryOptions =
    typeof headShaOrOptions === 'string'
      ? { headSha: headShaOrOptions, now: nowInput }
      : { ...(headShaOrOptions ?? {}), ...(nowInput ? { now: nowInput } : {}) };

  const normalized = normalizeDeliveryRecord(record);
  const parsed = FactoryDeliveryRecordSchema.safeParse(normalized);
  if (!parsed.success) {
    throw new FactoryDeliveryValidationError(
      'INVALID_RECORD',
      parsed.error.errors
        .map((e) => `${e.path.join('.') || 'record'}: ${e.message}`)
        .join('; '),
      parsed.error.errors.map((e) => ({
        path: e.path.join('.'),
        message: e.message,
      }))
    );
  }

  const headSha = options.headSha;
  if (
    headSha !== undefined &&
    !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(headSha)
  ) {
    throw new FactoryDeliveryValidationError(
      'INVALID_HEAD',
      'headSha must be a 40- or 64-char lowercase hex SHA'
    );
  }

  const now =
    options.now instanceof Date
      ? options.now
      : options.now !== undefined
        ? new Date(options.now)
        : new Date();

  const { snapshot, authority } = parsed.data;
  const { artifact, review } = snapshot;

  let reason: DeliveryBlockReason | null = null;
  let stage: DeliveryStage = 'approved';

  const deadline = new Date(snapshot.deadlineAt);
  const canonicalDeadline =
    snapshot.deadlineAt.length === 20
      ? snapshot.deadlineAt.slice(0, -1) + '.000Z'
      : snapshot.deadlineAt;

  if (snapshot.cancelled) {
    reason = 'CANCELLED';
    stage = 'cancelled';
  } else if (
    !utcDeadlinePattern.test(snapshot.deadlineAt) ||
    !Number.isFinite(deadline.getTime()) ||
    !Number.isFinite(now.getTime()) ||
    deadline.toISOString() !== canonicalDeadline
  ) {
    reason = 'INVALID_DEADLINE';
    stage = 'blocked';
  } else if (deadline.getTime() <= now.getTime()) {
    reason = 'DEADLINE_EXPIRED';
    stage = 'expired';
  } else if (!authority.enabled) {
    reason = 'FACTORY_DISABLED';
    stage = 'blocked';
  } else if (!authority.requesterActive) {
    reason = 'REQUESTER_REVOKED';
    stage = 'blocked';
  } else if (
    snapshot.maxSubmissions !== FACTORY_DELIVERY_POLICY.maxSubmissions ||
    !Number.isInteger(snapshot.submissions) ||
    snapshot.submissions < 0 ||
    snapshot.submissions > snapshot.maxSubmissions ||
    (artifact
      ? snapshot.submissions === 0
      : snapshot.submissions !== 0 ||
        snapshot.review !== null ||
        snapshot.submitter !== null ||
        snapshot.reviewer !== null)
  ) {
    reason = 'INVALID_SNAPSHOT';
    stage = 'blocked';
  } else if (!artifact) {
    reason = 'ARTIFACT_REQUIRED';
    stage = 'implementation';
  } else if (!snapshot.submitter || !authority.submitterActive) {
    reason = 'EXECUTOR_REVOKED';
    stage = 'blocked';
  } else if (headSha && artifact.commitSha !== headSha) {
    reason = 'HEAD_CHANGED';
    stage = 'review';
  } else if (
    FACTORY_DELIVERY_POLICY.requiredChecks.some(
      (key) =>
        artifact.checks.filter((c) => c.key === key && c.status === 'passed')
          .length !== 1
    ) ||
    new Set(artifact.checks.map((c) => c.key)).size !== artifact.checks.length
  ) {
    reason = 'CHECKS_INCOMPLETE';
    stage = 'verification';
  } else if (!review) {
    reason = 'REVIEW_REQUIRED';
    stage = 'review';
  } else if (review.commitSha !== artifact.commitSha) {
    reason = 'REVIEW_STALE';
    stage = 'review';
  } else if (!snapshot.reviewer || snapshot.reviewer === snapshot.submitter) {
    reason = 'INDEPENDENT_REVIEW_REQUIRED';
    stage = 'review';
  } else if (!authority.reviewerActive) {
    reason = 'REVIEWER_REVOKED';
    stage = 'blocked';
  } else if (review.verdict !== 'approve') {
    reason =
      snapshot.submissions >= snapshot.maxSubmissions
        ? 'CORRECTION_LIMIT'
        : 'CHANGES_REQUESTED';
    stage = reason === 'CORRECTION_LIMIT' ? 'blocked' : 'implementation';
  }

  return {
    contract: 'factory.delivery.v1',
    eligible: reason === null,
    stage,
    blockReason: reason,
    submissionsRemaining: Math.max(
      0,
      snapshot.maxSubmissions - snapshot.submissions
    ),
    correctionsRemaining: Math.max(
      0,
      snapshot.maxSubmissions - Math.max(1, snapshot.submissions)
    ),
    commitSha: headSha ?? artifact?.commitSha,
    checkedAt: Number.isFinite(now.getTime())
      ? now.toISOString()
      : new Date().toISOString(),
    // Evidence gate only — NEVER authority to merge, deploy, or execute externally
    externalExecution: false,
    mergeAllowed: false,
    deployAllowed: false,
    deploymentAllowed: false,
  };
}

/**
 * Alias strictly requiring `headSha` (mirroring `quality-gate.mjs` `checkRecord`).
 */
export function checkFactoryDeliveryRecord(
  record: unknown,
  headSha: string,
  now: Date | string = new Date()
): FactoryDeliveryEligibilityResult {
  if (
    typeof headSha !== 'string' ||
    !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(headSha)
  ) {
    throw new FactoryDeliveryValidationError(
      'INVALID_HEAD',
      'headSha is required and must be 40 or 64 lowercase hex characters'
    );
  }
  return evaluateFactoryDeliveryEligibility(record, { headSha, now });
}

// ============================================================================
// 3. COMPANY BRAIN PERSISTENCE RECORDS (STRUCTURALLY ALIGNED WITH CHAINBREAK & JEV)
// ============================================================================

export const StoredChainBreakEvidenceSchema = z
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
    contentSha256: Sha256HexSchema,
    producer: z.string().min(1),
    createdAt: z.string().datetime(),
    commitSha: FlexibleCommitShaSchema.optional(),
    verified: z.boolean(),
    summary: z.string().optional(),
  })
  .passthrough();
export type StoredChainBreakEvidence = z.infer<
  typeof StoredChainBreakEvidenceSchema
>;

export const StoredRemediationSpecSchema = z
  .object({
    remediationId: z.string().min(1),
    analysisId: z.string().min(1),
    tenantId: NonEmptyTenantIdSchema,
    fixtureId: z.string().min(1),
    pathId: z.string().min(1),
    violatedPolicyId: z.string().min(1),
    riskRecommendation: z.enum(['P0', 'P1', 'P2', 'P3', 'UNDETERMINED']),
    minimalChange: z.boolean(),
    actions: z.array(z.record(z.unknown())).min(1),
    breaksUnauthorizedPath: z.boolean(),
    preservesLegitimateOperations: z.boolean(),
    preservedOperationIds: z.array(z.string()),
    acceptanceCriteria: z.array(z.string().min(1)).min(1),
    verificationTests: z.array(z.string().min(1)).min(1),
    requiresHumanApproval: z.literal(true),
    autoApplyAllowed: z.literal(false),
    rationale: z.string().min(1),
    nonTechnicalSummary: z.string().min(1),
    evidenceIds: z.array(z.string().min(1)),
    createdAt: z.string().datetime(),
  })
  .passthrough();
export type StoredRemediationSpec = z.infer<typeof StoredRemediationSpecSchema>;

export const StoredSecurityAnalysisSchema = z
  .object({
    schemaVersion: z.literal('security.analysis.v1'),
    analysisId: z.string().min(1),
    tenantId: NonEmptyTenantIdSchema,
    fixtureId: z.string().min(1),
    commitSha: FlexibleCommitShaSchema.optional(),
    policyVersion: z.string().min(1),
    mode: z.literal('LAB'),
    paths: z.array(z.record(z.unknown())),
    evidenceIds: z.array(z.string().min(1)),
    evidence: z.array(StoredChainBreakEvidenceSchema).default([]),
    remediationSpecs: z.array(StoredRemediationSpecSchema).default([]),
    legitimateOperations: z.array(z.record(z.unknown())).default([]),
    legitimateOperationsPreserved: z.boolean(),
    startedAt: z.string().datetime(),
    completedAt: z.string().datetime().optional(),
    status: z.enum([
      'QUEUED',
      'RUNNING',
      'COMPLETED',
      'INCONCLUSIVE',
      'FAILED',
    ]),
    inputSha256: Sha256HexSchema,
    source: z.literal('DETERMINISTIC_LAB_ANALYSIS'),
    productionTested: z.literal(false),
    budgetStats: z.record(z.unknown()).optional(),
    diagnostics: z.array(z.record(z.unknown())).default([]),
  })
  .passthrough();
export type StoredSecurityAnalysis = z.infer<
  typeof StoredSecurityAnalysisSchema
>;

export const StoredAdjudicationResultSchema = z
  .object({
    evaluationId: z.string().min(1),
    analysisId: z.string().min(1),
    tenantId: NonEmptyTenantIdSchema,
    model: z.string().min(1),
    modelVersion: z.string().min(1),
    rubricVersion: z.string().min(1),
    status: z.enum([
      'ACCEPTED_FOR_TRIAGE',
      'PENDING_REVIEW',
      'BLOCKED',
      'REJECTED',
      'INCONCLUSIVE',
    ]),
    decision: z.string().min(1),
    triage: z
      .enum(['likely_actionable', 'needs_more_evidence', 'likely_irrelevant'])
      .nullable(),
    escalated: z.boolean(),
    escalationReason: z.string().optional(),
    requiresHumanReview: z.boolean(),
    riskRecommendation: z.enum(['P0', 'P1', 'P2', 'P3', 'NONE', 'UNDETERMINED']),
    evidenceIds: z.array(z.string()),
    sourceRefs: z.array(z.string()),
    decisionSource: z.enum(['LIVE', 'MOCK', 'FALLBACK', 'HUMAN_PENDING']),
    providerStatus: z.enum([
      'LIVE',
      'NOT_CONFIGURED',
      'FALLBACK',
      'UNAVAILABLE',
    ]),
    mergeAllowed: z.literal(false),
    deployAllowed: z.literal(false),
    exploitConfirmed: z.literal(false),
    p0DefinedByJevAlone: z.literal(false),
    timestamp: z.string().datetime(),
  })
  .passthrough();
export type StoredAdjudicationResult = z.infer<
  typeof StoredAdjudicationResultSchema
>;

export const PolicySnapshotRecordSchema = z
  .object({
    tenantId: NonEmptyTenantIdSchema,
    policyId: z.string().min(1),
    policyVersion: z.string().min(1),
    sourceRef: z.string().min(1),
    contentSha256: Sha256HexSchema.optional(),
    rules: z.unknown(),
    approvedBy: z.string().min(1),
    approvedAt: z.string().datetime(),
    readOnly: z.literal(true).default(true),
    createdAt: z.string().datetime().optional(),
  })
  .strict();
export type PolicySnapshotRecord = z.infer<typeof PolicySnapshotRecordSchema>;

export const DecisionTypeSchema = z.enum([
  'ANALYSIS',
  'ADJUDICATION',
  'REMEDIATION_SPEC',
  'DELIVERY_ELIGIBILITY',
  'POLICY_SNAPSHOT',
]);
export type DecisionType = z.infer<typeof DecisionTypeSchema>;

export const DecisionHistoryEntrySchema = z
  .object({
    decisionId: z.string().min(1).optional(),
    tenantId: NonEmptyTenantIdSchema,
    analysisId: z.string().min(1).optional(),
    decisionType: DecisionTypeSchema,
    actorPrincipalId: z.string().min(1),
    decision: z.string().min(1),
    status: z.string().min(1),
    sourceRef: z.string().min(1),
    correlationId: z.string().min(1).optional(),
    evidenceIds: z.array(z.string()).default([]),
    metadata: z.record(z.unknown()).optional(),
    createdAt: z.string().datetime().optional(),
  })
  .strict();
export type DecisionHistoryEntry = z.infer<typeof DecisionHistoryEntrySchema>;

export interface StoredAnalysisContext {
  analysis: StoredSecurityAnalysis;
  evidence: StoredChainBreakEvidence[];
  adjudications: StoredAdjudicationResult[];
  remediationSpecs: StoredRemediationSpec[];
  decisionHistory: Array<
    DecisionHistoryEntry & { decisionId: string; createdAt: string; seq: number }
  >;
}
