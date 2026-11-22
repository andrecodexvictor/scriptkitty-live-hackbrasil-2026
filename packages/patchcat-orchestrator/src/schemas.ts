/**
 * @file packages/patchcat-orchestrator/src/schemas.ts
 * @description Canonical Zod schemas and governance invariants for `@script-kitty/patchcat-orchestrator`.
 */

import { z } from 'zod';

export const Sha256HexSchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/, 'Must be a lowercase 64-character SHA-256 hex digest');

export const CommitShaSchema = z
  .string()
  .regex(/^[0-9a-f]{40,64}$/, 'Commit SHA must be 40- or 64-char lowercase hex');

export const OrchestratorEventTypeSchema = z.enum([
  'pr',
  'commit',
  'rollout',
  'lab-event',
]);
export type OrchestratorEventType = z.infer<typeof OrchestratorEventTypeSchema>;

export const OrchestratorEventSchema = z
  .object({
    eventId: z.string().trim().min(1).max(128).optional(),
    type: OrchestratorEventTypeSchema,
    tenantId: z.string().trim().min(1).max(64).default('tenant-payments-lab'),
    actorPrincipalId: z.string().trim().min(1).max(128).default('patchcat-orchestrator'),
    fixtureId: z.string().trim().min(1).max(128).default('payments-lab/unsafe-rollout'),
    verifiedFixtureId: z.string().trim().min(1).max(128).optional(),
    repository: z.string().trim().min(1).max(200).default('script-kitty/payments-lab'),
    branch: z.string().trim().min(1).max(200).default('rollout/report-exporter-pii'),
    commitSha: z
      .string()
      .trim()
      .transform((s) => s.toLowerCase())
      .pipe(CommitShaSchema)
      .default('a'.repeat(40)),
    sourceRef: z.string().trim().min(1).max(200).default('pr://payments-lab/42'),
    prNumber: z.number().int().positive().optional(),
    targetPath: z.string().trim().min(1).max(400).default('fixtures/payments-lab/unsafe-rollout.json'),
    targetHost: z.string().trim().min(1).max(128).default('127.0.0.1'),
    discoveringAgentId: z.string().trim().min(1).max(128).default('agent-discovery-chainbreak'),
    verifyingAgentId: z.string().trim().min(1).max(128).default('agent-verifier-kali'),
    authorizingAgentId: z.string().trim().min(1).max(128).default('agent-authorizer-gate'),
    summary: z.string().trim().min(1).max(1000).optional(),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict();

export type OrchestratorEventInput = z.input<typeof OrchestratorEventSchema>;
export type OrchestratorEvent = z.infer<typeof OrchestratorEventSchema>;

export const TriPartySodAttestationSchema = z
  .object({
    discoveringAgentId: z.string().min(1),
    verifyingAgentId: z.string().min(1),
    authorizingAgentId: z.string().min(1),
    allDistinct: z.literal(true),
    selfCertificationPrevented: z.literal(true),
    invariant: z.literal('A_disc != A_veri != A_auth'),
    sodEvaluation: z.record(z.unknown()),
    attestationSha256: Sha256HexSchema,
  })
  .strict();
export type TriPartySodAttestation = z.infer<typeof TriPartySodAttestationSchema>;

export const BeforeAfterProofSchema = z
  .object({
    beforeFixtureId: z.string().min(1),
    afterFixtureId: z.string().min(1).optional(),
    verifiedFixtureChecked: z.boolean(),
    verifiedFixtureMatchesCounterfactual: z.boolean().optional(),
    counterfactualApplied: z.boolean(),
    beforeForbiddenPathsCount: z.number().int().nonnegative(),
    afterForbiddenPathsCount: z.number().int().nonnegative(),
    forbiddenPathDeltaSummary: z.string().min(1),
    beforeLegitimateOpsTotal: z.number().int().nonnegative(),
    beforeLegitimateOpsPreserved: z.number().int().nonnegative(),
    afterLegitimateOpsTotal: z.number().int().nonnegative(),
    afterLegitimateOpsPreserved: z.number().int().nonnegative(),
    legitimateOperationsSummary: z.string().min(1),
    legitimateOperationsPreserved: z.literal(true),
    beforeInputSha256: Sha256HexSchema,
    afterCounterfactualSha256: Sha256HexSchema,
    removedEdgeIds: z.array(z.string()),
    remediationSpecId: z.string().optional(),
  })
  .strict();
export type BeforeAfterProof = z.infer<typeof BeforeAfterProofSchema>;

export const KaliVerificationSummarySchema = z
  .object({
    executionMode: z.enum(['LAB_SIMULATION', 'LIVE_CONTAINER']),
    simulated: z.boolean(),
    capabilitiesExecuted: z.array(z.string()).min(1),
    ok: z.boolean(),
    findingsCount: z.number().int().nonnegative(),
    evidenceIds: z.array(z.string().min(1)).min(1),
    evidenceChainHashes: z.array(Sha256HexSchema).min(1),
    custodyValid: z.literal(true),
    custodyStandard: z.literal('RFC8785_SHA256_MERKLE'),
    sodValid: z.literal(true),
    scopeId: z.string().min(1),
  })
  .strict();
export type KaliVerificationSummary = z.infer<typeof KaliVerificationSummarySchema>;

export const FactoryDeliverySummarySchema = z
  .object({
    contract: z.literal('factory.delivery.v1'),
    evaluationId: z.string().min(1),
    eligible: z.boolean(),
    stage: z.string().min(1),
    blockReason: z.string().nullable(),
    commitSha: CommitShaSchema.optional(),
    checkedAt: z.string().datetime(),
    externalExecution: z.literal(false),
    mergeAllowed: z.literal(false),
    deployAllowed: z.literal(false),
    deploymentAllowed: z.literal(false),
  })
  .strict();
export type FactoryDeliverySummary = z.infer<typeof FactoryDeliverySummarySchema>;

/**
 * Reviewable ZenPR Advisory Bundle emitted at the end of PatchCat's autonomous
 * orchestration loop. Always human-gated: never merges, deploys, or mutates policy.
 */
export const ZenPrBundleSchema = z
  .object({
    schemaVersion: z.literal('zenpr.advisory.v1'),
    bundleId: z.string().min(1),
    correlationId: z.string().min(1),
    eventId: z.string().min(1),
    eventType: OrchestratorEventTypeSchema,
    tenantId: z.string().min(1),
    fixtureId: z.string().min(1),
    repository: z.string().min(1),
    branch: z.string().min(1),
    commitSha: CommitShaSchema,
    sourceRef: z.string().min(1),
    mode: z.literal('LAB'),
    productionTested: z.literal(false),
    remediationSpecs: z.array(z.record(z.unknown())),
    patchProposals: z.array(z.record(z.unknown())),
    unifiedDiff: z.string(),
    reverseDiff: z.string(),
    beforeAfterProof: BeforeAfterProofSchema,
    kaliVerification: KaliVerificationSummarySchema,
    jevAdvisoryReceipt: z.record(z.unknown()),
    qualityGateDecision: z.record(z.unknown()),
    factoryDelivery: FactoryDeliverySummarySchema,
    triPartySod: TriPartySodAttestationSchema,
    canonicalizationStandard: z.literal('RFC8785_SHA256_MERKLE'),
    merkleLeaves: z.array(Sha256HexSchema).min(1),
    merkleRoot: Sha256HexSchema,
    bundleDigestSha256: Sha256HexSchema,
    policyMutationAllowed: z.literal(false),
    gateMutationAllowed: z.literal(false),
    autoApplyAllowed: z.literal(false),
    mergeAllowed: z.literal(false),
    deployAllowed: z.literal(false),
    requiresHumanApproval: z.literal(true),
    status: z.enum([
      'ADVISORY_READY',
      'REMEDIATION_PROPOSED',
      'ESCALATED_FOR_REVIEW',
      'BLOCKED',
    ]),
    summaryMarkdown: z.string().min(1),
    createdAt: z.string().datetime(),
  })
  .strict();

export type ZenPrBundle = z.infer<typeof ZenPrBundleSchema>;

export const PipelineStageRecordSchema = z
  .object({
    stage: z.enum([
      'governance_guard',
      'runtime_guardian',
      'action_engine',
      'chainbreak_before',
      'kali_sandbox_verification',
      'counterfactual_remediation',
      'company_brain_ledger',
      'jev_judge_cascade',
      'quality_gate',
      'factory_delivery',
      'zenpr_bundle',
    ]),
    status: z.enum(['COMPLETED', 'PASSED', 'BLOCKED']),
    detail: z.string().min(1),
  })
  .strict();

export type PipelineStageRecord = z.infer<typeof PipelineStageRecordSchema>;

export const OrchestrationRunResultSchema = z
  .object({
    correlationId: z.string().min(1),
    event: OrchestratorEventSchema,
    stages: z.array(PipelineStageRecordSchema).min(10),
    analysisId: z.string().min(1),
    guardianAuditMerkleRoot: Sha256HexSchema,
    guardianIntegrityValid: z.literal(true),
    zenPrBundle: ZenPrBundleSchema,
    policyMutationAllowed: z.literal(false),
    gateMutationAllowed: z.literal(false),
    mergeAllowed: z.literal(false),
    deployAllowed: z.literal(false),
  })
  .strict();

export type OrchestrationRunResult = z.infer<typeof OrchestrationRunResultSchema>;
