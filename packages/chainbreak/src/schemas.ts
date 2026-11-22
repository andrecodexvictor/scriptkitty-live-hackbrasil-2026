/**
 * @file packages/chainbreak/src/schemas.ts
 * @description Canonical Zod schemas and TypeScript types for ChainBreak v0
 * (deterministic policy graph & reachability engine for ScriptKitty Live — PatchCat).
 */

import { z } from 'zod';
import type { ValidationResult } from '@script-kitty/contracts';

// ============================================================================
// 1. DATA CLASSIFICATION & TRUST ZONES
// ============================================================================

export const DataClassificationSchema = z.enum([
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
]);
export type DataClassification = z.infer<typeof DataClassificationSchema>;

export const CLASSIFICATION_RANK: Record<DataClassification, number> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  RESTRICTED: 3,
};

export function compareClassifications(
  a: DataClassification,
  b: DataClassification
): number {
  return CLASSIFICATION_RANK[a] - CLASSIFICATION_RANK[b];
}

export const TrustZoneSchema = z.enum(['INTERNAL', 'DMZ', 'EXTERNAL']);
export type TrustZone = z.infer<typeof TrustZoneSchema>;

// ============================================================================
// 2. GRAPH NODES & EDGES
// ============================================================================

export const AttackGraphNodeKindSchema = z.enum([
  'identity',
  'agent',
  'mcp_tool',
  'api',
  'service',
  'data_asset',
  'destination',
]);
export type AttackGraphNodeKind = z.infer<typeof AttackGraphNodeKindSchema>;

export const AttackGraphNodeSchema = z.object({
  nodeId: z.string().min(1, 'nodeId is required'),
  kind: AttackGraphNodeKindSchema,
  label: z.string().min(1, 'label is required'),
  tenantId: z.string().min(1, 'tenantId is required'),
  scope: z.string().min(1, 'scope is required'),
  allowedScopes: z.array(z.string().min(1)).optional(),
  roles: z.array(z.string().min(1)).default([]),
  dataClassification: DataClassificationSchema.optional(),
  allowedClassifications: z.array(DataClassificationSchema).optional(),
  trustZone: TrustZoneSchema.default('INTERNAL'),
  isEntryIdentity: z.boolean().optional(),
  isRestrictedAsset: z.boolean().optional(),
  isUnauthorizedDestination: z.boolean().optional(),
  sourceRef: z.string().default(''),
  metadata: z.record(z.unknown()).optional(),
});
export type AttackGraphNode = z.infer<typeof AttackGraphNodeSchema>;

export const AttackGraphEdgeKindSchema = z.enum([
  'can_invoke',
  'can_read',
  'can_write',
  'transfers_data_to',
  'assumes_role',
  'delegates_to',
]);
export type AttackGraphEdgeKind = z.infer<typeof AttackGraphEdgeKindSchema>;

export const EdgeConditionExpressionSchema = z.object({
  field: z.string().min(1),
  op: z.enum(['eq', 'neq', 'in', 'not_in']),
  value: z.union([z.string(), z.boolean(), z.number(), z.array(z.string())]),
});
export type EdgeConditionExpression = z.infer<typeof EdgeConditionExpressionSchema>;

export const EdgeConditionsSchema = z
  .object({
    effect: z.enum(['ALLOW', 'DENY']).default('ALLOW'),
    active: z.boolean().default(true),
    requiredScopes: z.array(z.string().min(1)).optional(),
    requiredRoles: z.array(z.string().min(1)).optional(),
    grantedRoles: z.array(z.string().min(1)).optional(),
    allowedDataClassifications: z.array(DataClassificationSchema).optional(),
    deniedDataClassifications: z.array(DataClassificationSchema).optional(),
    requiresExplicitGrant: z.boolean().optional(),
    explicitGrantPresent: z.boolean().optional(),
    requiresMfa: z.boolean().optional(),
    mfaVerified: z.boolean().optional(),
    requiresPiiMasking: z.boolean().optional(),
    piiMaskingApplied: z.boolean().optional(),
    allowedPurposes: z.array(z.string().min(1)).optional(),
    purpose: z.string().min(1).optional(),
    networkZone: z.enum(['INTERNAL', 'DMZ', 'EXTERNAL', 'ANY']).optional(),
    expressions: z.array(EdgeConditionExpressionSchema).optional(),
  })
  .default({ effect: 'ALLOW', active: true });
export type EdgeConditions = z.infer<typeof EdgeConditionsSchema>;

/**
 * Strict AttackGraphEdge contract requiring non-empty sourceRef & policyVersion.
 */
export const AttackGraphEdgeSchema = z.object({
  edgeId: z.string().min(1, 'edgeId is required'),
  from: z.string().min(1, 'from nodeId is required'),
  to: z.string().min(1, 'to nodeId is required'),
  kind: AttackGraphEdgeKindSchema,
  tenantId: z.string().min(1, 'tenantId is required'),
  scope: z.string().min(1, 'scope is required'),
  conditions: EdgeConditionsSchema,
  sourceRef: z.string().min(1, 'sourceRef is required'),
  policyId: z.string().min(1).optional(),
  policyVersion: z.string().min(1, 'policyVersion is required'),
  dataClassification: DataClassificationSchema,
});
export type AttackGraphEdge = z.infer<typeof AttackGraphEdgeSchema>;

/**
 * Input edge schema used by the analyzer so missing/empty sourceRef or policy
 * references downgrade candidate paths to INCONCLUSIVE instead of crashing.
 */
export const PolicyGraphEdgeInputSchema = z.object({
  edgeId: z.string().min(1, 'edgeId is required'),
  from: z.string().min(1, 'from nodeId is required'),
  to: z.string().min(1, 'to nodeId is required'),
  kind: AttackGraphEdgeKindSchema,
  tenantId: z.string().min(1, 'tenantId is required'),
  scope: z.string().min(1, 'scope is required'),
  conditions: EdgeConditionsSchema,
  sourceRef: z.string().optional().default(''),
  policyId: z.string().optional(),
  policyVersion: z.string().optional().default(''),
  dataClassification: DataClassificationSchema,
});
export type PolicyGraphEdgeInput = z.infer<typeof PolicyGraphEdgeInputSchema>;

// ============================================================================
// 3. FINDING STATUS, RISK & ATTACK PATHS
// ============================================================================

/**
 * FindingStatus intentionally omits "EXPLOIT_CONFIRMED".
 * PATH_VALIDATED means reachable within the modeled policy graph, never production exploit proof.
 */
export const FindingStatusSchema = z.enum([
  'POTENTIAL',
  'PATH_VALIDATED',
  'INCONCLUSIVE',
  'NOT_REPRODUCED',
]);
export type FindingStatus = z.infer<typeof FindingStatusSchema>;

export const RiskRecommendationSchema = z.enum([
  'P0',
  'P1',
  'P2',
  'P3',
  'UNDETERMINED',
]);
export type RiskRecommendation = z.infer<typeof RiskRecommendationSchema>;

export const AttackPathEdgeSchema = z.object({
  edgeId: z.string().min(1),
  from: z.string().min(1),
  to: z.string().min(1),
  kind: AttackGraphEdgeKindSchema,
  scope: z.string().min(1),
  sourceRef: z.string(),
  policyId: z.string().optional(),
  policyVersion: z.string(),
  dataClassification: DataClassificationSchema,
});
export type AttackPathEdge = z.infer<typeof AttackPathEdgeSchema>;

export const AttackPathSchema = z.object({
  pathId: z.string().min(1),
  startIdentity: z.string().min(1),
  targetAsset: z.string().min(1),
  targetDestination: z.string().min(1).optional(),
  edges: z.array(AttackPathEdgeSchema).min(1),
  violatedPolicyId: z.string().min(1),
  status: FindingStatusSchema,
  evidenceIds: z.array(z.string().min(1)),
  riskRecommendation: RiskRecommendationSchema,
  explanation: z.string().min(1),
  nonTechnicalSummary: z.string().min(1),
  missingReferences: z.array(z.string()).optional(),
});
export type AttackPath = z.infer<typeof AttackPathSchema>;

// ============================================================================
// 4. EVIDENCE, REMEDIATION SPEC & EXECUTION SCOPE
// ============================================================================

export const ChainBreakEvidenceKindSchema = z.enum([
  'POLICY_SNAPSHOT',
  'GRAPH_PATH',
  'TEST_RESULT',
  'QUALITY_RESULT',
]);
export type ChainBreakEvidenceKind = z.infer<typeof ChainBreakEvidenceKindSchema>;

export const ChainBreakEvidenceSchema = z.object({
  evidenceId: z.string().min(1),
  analysisId: z.string().min(1),
  kind: ChainBreakEvidenceKindSchema,
  sourceRef: z.string(),
  contentSha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/i, 'contentSha256 must be a 64-char hex SHA-256'),
  producer: z.string().min(1),
  createdAt: z.string().datetime({ message: 'createdAt must be ISO 8601 UTC' }),
  commitSha: z.string().regex(/^[a-f0-9]{7,64}$/i).optional(),
  verified: z.boolean(),
  summary: z.string().optional(),
});
export type ChainBreakEvidence = z.infer<typeof ChainBreakEvidenceSchema>;

export const RemediationActionTypeSchema = z.enum([
  'REMOVE_EDGE',
  'RESTRICT_DATA_CLASSIFICATION',
  'RESTRICT_SCOPE',
  'ADD_DENY_CONDITION',
]);
export type RemediationActionType = z.infer<typeof RemediationActionTypeSchema>;

export const RemediationActionSchema = z.object({
  actionType: RemediationActionTypeSchema,
  edgeId: z.string().min(1),
  from: z.string().min(1),
  to: z.string().min(1),
  edgeKind: AttackGraphEdgeKindSchema,
  currentScope: z.string().min(1),
  currentDataClassification: DataClassificationSchema,
  proposedChange: z.string().min(1),
  proposedScope: z.string().min(1).optional(),
  proposedDataClassification: DataClassificationSchema.optional(),
  proposedAllowedClassifications: z.array(DataClassificationSchema).optional(),
  sourceRef: z.string(),
});
export type RemediationAction = z.infer<typeof RemediationActionSchema>;

export const RemediationSpecSchema = z.object({
  remediationId: z.string().min(1),
  analysisId: z.string().min(1),
  tenantId: z.string().min(1),
  fixtureId: z.string().min(1),
  pathId: z.string().min(1),
  violatedPolicyId: z.string().min(1),
  riskRecommendation: RiskRecommendationSchema,
  minimalChange: z.boolean(),
  actions: z.array(RemediationActionSchema).min(1),
  breaksUnauthorizedPath: z.boolean(),
  preservesLegitimateOperations: z.boolean(),
  preservedOperationIds: z.array(z.string()),
  acceptanceCriteria: z.array(z.string().min(1)).min(1),
  verificationTests: z.array(z.string().min(1)).min(1),
  requiresHumanApproval: z.literal(true).default(true),
  autoApplyAllowed: z.literal(false).default(false),
  rationale: z.string().min(1),
  nonTechnicalSummary: z.string().min(1),
  evidenceIds: z.array(z.string().min(1)),
  createdAt: z.string().datetime({ message: 'createdAt must be ISO 8601 UTC' }),
});
export type RemediationSpec = z.infer<typeof RemediationSpecSchema>;

export const ExecutionScopeSchema = z.object({
  tenantId: z.string().min(1, 'tenantId is required in ExecutionScope'),
  principalId: z.string().min(1, 'principalId is required in ExecutionScope'),
  mode: z.literal('LAB').default('LAB'),
  allowedFixtures: z
    .array(z.string().min(1))
    .default([
      'payments-lab/baseline',
      'payments-lab/unsafe-rollout',
      'payments-lab/remediated',
      'payments-lab/negative-control',
    ]),
  allowedPolicyVersions: z.array(z.string().min(1)).optional(),
  maxNodes: z.number().int().positive().max(10_000).default(500),
  maxDepth: z.number().int().positive().max(64).default(12),
  maxPaths: z.number().int().positive().max(500).default(50),
  maxDurationMs: z.number().int().positive().max(30_000).default(5_000),
  allowProductionExecution: z.literal(false).default(false),
  allowAutoMergeOrDeploy: z.literal(false).default(false),
});
export type ExecutionScope = z.infer<typeof ExecutionScopeSchema>;

// ============================================================================
// 5. POLICY RULES, LEGITIMATE OPERATIONS & POLICY GRAPH FIXTURE
// ============================================================================

export const PolicyRuleSchema = z.object({
  policyId: z.string().min(1),
  description: z.string().min(1),
  forbiddenTargetClassification: DataClassificationSchema,
  forbiddenDestinationTrustZone: TrustZoneSchema.default('EXTERNAL'),
  riskRecommendation: RiskRecommendationSchema.default('P1'),
  policyVersion: z.string().min(1),
  sourceRef: z.string(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const LegitimateOperationSchema = z.object({
  operationId: z.string().min(1),
  description: z.string().min(1),
  startIdentity: z.string().min(1),
  requiredEdgeIds: z.array(z.string().min(1)).min(1),
  targetNodeId: z.string().min(1),
  expectedDataClassification: DataClassificationSchema.optional(),
  sourceRef: z.string().default(''),
});
export type LegitimateOperation = z.infer<typeof LegitimateOperationSchema>;

export const LegitimateOperationResultSchema = z.object({
  operationId: z.string().min(1),
  description: z.string().min(1),
  preserved: z.boolean(),
  reason: z.string().min(1),
  verifiedEdgeIds: z.array(z.string()),
});
export type LegitimateOperationResult = z.infer<
  typeof LegitimateOperationResultSchema
>;

export const PolicyGraphSchema = z.object({
  schemaVersion: z.literal('chainbreak.graph.v1').default('chainbreak.graph.v1'),
  fixtureId: z.string().min(1),
  tenantId: z.string().min(1),
  policyVersion: z.string().min(1),
  description: z.string().min(1),
  commitSha: z.string().regex(/^[a-f0-9]{7,64}$/i).optional(),
  declaredInputSha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
  startIdentities: z.array(z.string().min(1)).optional(),
  policies: z.array(PolicyRuleSchema).min(1),
  nodes: z.array(AttackGraphNodeSchema).min(1),
  edges: z.array(AttackGraphEdgeSchema),
  legitimateOperations: z.array(LegitimateOperationSchema).default([]),
});
export type PolicyGraph = z.infer<typeof PolicyGraphSchema>;

export const PolicyGraphInputSchema = PolicyGraphSchema.extend({
  edges: z.array(PolicyGraphEdgeInputSchema),
});
export type PolicyGraphInput = z.infer<typeof PolicyGraphInputSchema>;

// ============================================================================
// 6. SECURITY ANALYSIS RESULT
// ============================================================================

export const AnalysisStatusSchema = z.enum([
  'QUEUED',
  'RUNNING',
  'COMPLETED',
  'INCONCLUSIVE',
  'FAILED',
]);
export type AnalysisStatus = z.infer<typeof AnalysisStatusSchema>;

export const AnalysisDiagnosticSchema = z.object({
  code: z.string().min(1),
  severity: z.enum(['INFO', 'WARNING', 'ERROR']),
  message: z.string().min(1),
  refId: z.string().optional(),
});
export type AnalysisDiagnostic = z.infer<typeof AnalysisDiagnosticSchema>;

export const BudgetStatsSchema = z.object({
  nodesVisited: z.number().int().nonnegative(),
  edgesTraversed: z.number().int().nonnegative(),
  maxDepthReached: z.number().int().nonnegative(),
  pathsEvaluated: z.number().int().nonnegative(),
  budgetExceeded: z.boolean(),
});
export type BudgetStats = z.infer<typeof BudgetStatsSchema>;

export const SecurityAnalysisSchema = z.object({
  schemaVersion: z.literal('security.analysis.v1'),
  analysisId: z.string().min(1),
  tenantId: z.string().min(1),
  fixtureId: z.string().min(1),
  commitSha: z.string().regex(/^[a-f0-9]{7,64}$/i).optional(),
  policyVersion: z.string().min(1),
  mode: z.literal('LAB'),
  paths: z.array(AttackPathSchema),
  evidenceIds: z.array(z.string().min(1)),
  evidence: z.array(ChainBreakEvidenceSchema).default([]),
  remediationSpecs: z.array(RemediationSpecSchema).default([]),
  legitimateOperations: z.array(LegitimateOperationResultSchema).default([]),
  legitimateOperationsPreserved: z.boolean(),
  startedAt: z.string().datetime(),
  completedAt: z.string().datetime().optional(),
  status: AnalysisStatusSchema,
  inputSha256: z.string().regex(/^[a-f0-9]{64}$/i),
  source: z
    .literal('DETERMINISTIC_LAB_ANALYSIS')
    .default('DETERMINISTIC_LAB_ANALYSIS'),
  productionTested: z.literal(false).default(false),
  budgetStats: BudgetStatsSchema.optional(),
  diagnostics: z.array(AnalysisDiagnosticSchema).default([]),
});
export type SecurityAnalysis = z.infer<typeof SecurityAnalysisSchema>;

// ============================================================================
// 7. SAFE VALIDATION HELPERS
// ============================================================================

function formatErrors(
  error: z.ZodError
): Array<{ path: string; message: string; code: string }> {
  return error.errors.map((err) => ({
    path: err.path.join('.'),
    message: err.message,
    code: err.code,
  }));
}

function runSafeParse<S extends z.ZodTypeAny>(
  schema: S,
  input: unknown
): ValidationResult<z.infer<S>> {
  const result = schema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data as z.infer<S> };
  }
  return { success: false, errors: formatErrors(result.error) };
}

export function validateAttackGraphNode(
  input: unknown
): ValidationResult<AttackGraphNode> {
  return runSafeParse(AttackGraphNodeSchema, input);
}

export function validateAttackGraphEdge(
  input: unknown
): ValidationResult<AttackGraphEdge> {
  return runSafeParse(AttackGraphEdgeSchema, input);
}

export function validatePolicyGraph(
  input: unknown
): ValidationResult<PolicyGraph> {
  return runSafeParse(PolicyGraphSchema, input);
}

export function validateSecurityAnalysis(
  input: unknown
): ValidationResult<SecurityAnalysis> {
  return runSafeParse(SecurityAnalysisSchema, input);
}

export function validateChainBreakEvidence(
  input: unknown
): ValidationResult<ChainBreakEvidence> {
  return runSafeParse(ChainBreakEvidenceSchema, input);
}

export function validateRemediationSpec(
  input: unknown
): ValidationResult<RemediationSpec> {
  return runSafeParse(RemediationSpecSchema, input);
}

export function validateExecutionScope(
  input: unknown
): ValidationResult<ExecutionScope> {
  return runSafeParse(ExecutionScopeSchema, input);
}
