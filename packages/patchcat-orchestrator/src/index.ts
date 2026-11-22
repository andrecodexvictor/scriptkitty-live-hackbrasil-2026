/**
 * @file packages/patchcat-orchestrator/src/index.ts
 * @description Public entrypoint for `@script-kitty/patchcat-orchestrator`.
 */

export {
  PatchCatGovernanceError,
  type PatchCatGovernanceErrorCode,
  type PatchCatGovernanceErrorOptions,
} from './errors.js';

export {
  BeforeAfterProofSchema,
  CommitShaSchema,
  FactoryDeliverySummarySchema,
  KaliVerificationSummarySchema,
  OrchestrationRunResultSchema,
  OrchestratorEventSchema,
  OrchestratorEventTypeSchema,
  PipelineStageRecordSchema,
  Sha256HexSchema,
  TriPartySodAttestationSchema,
  ZenPrBundleSchema,
  type BeforeAfterProof,
  type FactoryDeliverySummary,
  type KaliVerificationSummary,
  type OrchestrationRunResult,
  type OrchestratorEvent,
  type OrchestratorEventInput,
  type OrchestratorEventType,
  type PipelineStageRecord,
  type TriPartySodAttestation,
  type ZenPrBundle,
} from './schemas.js';

export {
  PatchCatOrchestrator,
  applyCounterfactualRemediation,
  assertNoPolicyOrGateMutation,
  assertTriPartySod,
  runPatchCatOrchestration,
  synthesizeZenPrBundle,
  type OrchestratorRunOptions,
  type PatchCatOrchestratorOptions,
  type SynthesizeZenPrBundleInput,
} from './orchestrator.js';
