/**
 * @file packages/contracts/src/patch.ts
 * @description PatchProposal canonical data contract, Zod schema, and TypeScript types.
 * Connects verified vulnerabilities to actionable remediation, regression rechecks,
 * blast radius assessments, and automated rollback plans.
 */

import { z } from "zod";
import { createHash } from "node:crypto";

/**
 * Recheck verification status of the proposed patch.
 */
export const RecheckStatusSchema = z.enum([
  "passed_clean",
  "reproducer_still_fails",
  "regression_detected",
  "untested",
]);
export type RecheckStatus = z.infer<typeof RecheckStatusSchema>;

/**
 * AST Impact Scope classification.
 */
export const AstImpactScopeSchema = z.enum([
  "LOCAL_FUNCTION",
  "MODULE_PRIVATE",
  "PUBLIC_API",
  "INTERFACE_SIGNATURE",
  "GLOBAL",
]);
export type AstImpactScope = z.infer<typeof AstImpactScopeSchema>;

/**
 * Breaking change risk tier.
 */
export const BreakingChangeRiskSchema = z.enum([
  "NONE",
  "LOW",
  "MEDIUM",
  "HIGH",
]);
export type BreakingChangeRisk = z.infer<typeof BreakingChangeRiskSchema>;

/**
 * Blast Radius assessment schema.
 */
export const BlastRadiusSchema = z.object({
  files_modified: z.number().int().nonnegative({
    message: "files_modified must be a non-negative integer",
  }),
  lines_added: z.number().int().nonnegative({
    message: "lines_added must be a non-negative integer",
  }),
  lines_deleted: z.number().int().nonnegative({
    message: "lines_deleted must be a non-negative integer",
  }),
  ast_impact_scope: AstImpactScopeSchema,
  downstream_dependents: z.array(z.string()).default([]),
  breaking_change_risk: BreakingChangeRiskSchema,
});
export type BlastRadius = z.infer<typeof BlastRadiusSchema>;

/**
 * Rollback Plan schema.
 */
export const RollbackPlanSchema = z.object({
  revert_patch: z.string().min(1, {
    message: "revert_patch must contain non-empty reverse unified diff content",
  }),
  compensating_controls: z.array(z.string()).optional().default([]),
  killswitch_flag: z.string().optional(),
  automated_rollback_trigger: z.string().optional(),
});
export type RollbackPlan = z.infer<typeof RollbackPlanSchema>;

/**
 * Helper to normalize incoming PatchProposal payloads (camelCase or snake_case).
 */
function normalizePatchProposalInput(input: unknown): unknown {
  if (typeof input !== "object" || input === null) return input;
  const raw = input as Record<string, unknown>;

  const blastRaw = (raw.blast_radius ?? raw.blastRadius) as Record<string, unknown> | undefined;
  const rollbackRaw = (raw.rollback_plan ?? raw.rollbackPlan) as Record<string, unknown> | undefined;

  const normalizedBlast = blastRaw
    ? {
        files_modified: blastRaw.files_modified ?? blastRaw.filesModified ?? 0,
        lines_added: blastRaw.lines_added ?? blastRaw.linesAdded ?? 0,
        lines_deleted: blastRaw.lines_deleted ?? blastRaw.linesDeleted ?? 0,
        ast_impact_scope: (blastRaw.ast_impact_scope ?? blastRaw.astImpactScope ?? "LOCAL_FUNCTION"),
        downstream_dependents: blastRaw.downstream_dependents ?? blastRaw.downstreamDependents ?? [],
        breaking_change_risk: (blastRaw.breaking_change_risk ?? blastRaw.breakingChangeRisk ?? "LOW"),
      }
    : undefined;

  const normalizedRollback = rollbackRaw
    ? {
        revert_patch: rollbackRaw.revert_patch ?? rollbackRaw.revertPatch,
        compensating_controls: rollbackRaw.compensating_controls ?? rollbackRaw.compensatingControls ?? [],
        killswitch_flag: rollbackRaw.killswitch_flag ?? rollbackRaw.killswitchFlag,
        automated_rollback_trigger: rollbackRaw.automated_rollback_trigger ?? rollbackRaw.automatedRollbackTrigger,
      }
    : undefined;

  return {
    patch_id: raw.patch_id ?? raw.patchId ?? raw.id,
    finding_id: raw.finding_id ?? raw.findingId,
    author_engine: raw.author_engine ?? raw.authorEngine ?? raw.authorAgentId ?? "manual",
    diff_content: raw.diff_content ?? raw.diffContent ?? raw.unifiedDiff ?? raw.diff,
    affected_files: raw.affected_files ?? raw.affectedFiles ?? [],
    base_commit: raw.base_commit ?? raw.baseCommit,
    patch_sha256: raw.patch_sha256 ?? raw.patchSha256,
    recheck_status: typeof (raw.recheck_status ?? raw.recheckStatus) === "string"
      ? String(raw.recheck_status ?? raw.recheckStatus).toLowerCase()
      : raw.recheck_status ?? raw.recheckStatus,
    recheck_evidence_id: raw.recheck_evidence_id ?? raw.recheckEvidenceId ?? raw.regressionTestEvidenceId ?? null,
    blast_radius: normalizedBlast,
    rollback_plan: normalizedRollback,
    created_at: raw.created_at ?? raw.createdAt ?? new Date().toISOString(),
  };
}

/**
 * Canonical PatchProposal Zod Schema.
 */
export const PatchProposalSchema = z.preprocess(
  normalizePatchProposalInput,
  z.object({
    patch_id: z.string().min(1, { message: "patch_id is required" }).regex(
      /^SK-PATCH-[a-zA-Z0-9_\-]+$/,
      { message: "patch_id must follow the pattern SK-PATCH-<identifier>" }
    ),
    finding_id: z.string().min(1, { message: "finding_id is required" }).regex(
      /^[a-zA-Z0-9_\-\.:]+$/,
      { message: "finding_id must be a valid identifier" }
    ),
    author_engine: z.string().min(1, { message: "author_engine is required" }),
    diff_content: z.string().min(1, { message: "diff_content cannot be empty" }),
    affected_files: z.array(z.string().min(1)).min(1, {
      message: "affected_files must contain at least one file path",
    }),
    base_commit: z.string().regex(
      /^[0-9a-fA-F]{40,64}$/,
      { message: "base_commit must be a 40-character SHA-1 or 64-character SHA-256 hash" }
    ),
    patch_sha256: z.string().regex(
      /^[0-9a-fA-F]{64}$/,
      { message: "patch_sha256 must be a 64-character hexadecimal SHA-256 hash" }
    ),
    recheck_status: RecheckStatusSchema,
    recheck_evidence_id: z.string().regex(/^[a-zA-Z0-9_\-\.:]+$/).nullable().optional(),
    blast_radius: BlastRadiusSchema,
    rollback_plan: RollbackPlanSchema,
    created_at: z.string().datetime({
      message: "created_at must be a valid ISO 8601 UTC timestamp",
    }),
  }).refine((data) => {
    // Invariant: If recheck_status is passed_clean, a valid recheck_evidence_id should ideally be linked
    if (data.recheck_status === "passed_clean" && !data.recheck_evidence_id) {
      return false;
    }
    return true;
  }, {
    message: "recheck_evidence_id is required when recheck_status is 'passed_clean'",
    path: ["recheck_evidence_id"],
  })
);

export type PatchProposal = z.infer<typeof PatchProposalSchema>;

/**
 * Helper: Computes canonical SHA-256 over normalized diff content.
 */
export function computePatchSha256(diffContent: string): string {
  const normalized = diffContent.replace(/\r\n/g, "\n").trim();
  return createHash("sha256").update(normalized, "utf8").digest("hex");
}

/**
 * Helper: Safe parser and validator for PatchProposal instances.
 */
export function validatePatchProposal(input: unknown): PatchProposal {
  return PatchProposalSchema.parse(input);
}

/**
 * Helper: Checks if a patch is eligible for automated release gating.
 */
export function isPatchEligibleForAutoGate(patch: PatchProposal): boolean {
  return (
    patch.recheck_status === "passed_clean" &&
    Boolean(patch.recheck_evidence_id) &&
    (patch.blast_radius.breaking_change_risk === "NONE" ||
      patch.blast_radius.breaking_change_risk === "LOW") &&
    Boolean(patch.rollback_plan.revert_patch)
  );
}
