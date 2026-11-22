/**
 * @file packages/contracts/src/gate.ts
 * @description GateDecision canonical data contract, Zod schema, and TypeScript types.
 * Implements deterministic Zero-Trust policy evaluation, strict Separation of Duties (SoD),
 * and Merkle root audit verification.
 */

import { z } from "zod";
import {
  GateVerdict,
  GateVerdictSchema,
} from "./common.js";

export { GateVerdict, GateVerdictSchema };

/**
 * Individual Rule Evaluation Status.
 */
export const RuleStatusSchema = z.enum(["PASS", "FAIL", "SKIPPED", "ERROR"]);
export type RuleStatus = z.infer<typeof RuleStatusSchema>;

/**
 * Evaluated Rule record.
 */
export const RuleEvaluationSchema = z.object({
  rule_id: z.string().min(1),
  status: RuleStatusSchema,
  reason: z.string().min(1),
  finding_id: z.string().optional(),
});
export type RuleEvaluation = z.infer<typeof RuleEvaluationSchema>;

/**
 * Pure function: Evaluates Separation of Duties across agent identities.
 * Tri-party invariance: Discoverer != Verifier != Authorizer.
 * Enforces case-insensitive identity comparison and whitespace trimming.
 */
export function evaluateSeparationOfDuties(
  discoveringAgentId: string,
  verifyingAgentId: string,
  authorizingAgentId: string
): SeparationOfDutiesEvaluation {
  const dTrimmed = (discoveringAgentId || '').trim();
  const vTrimmed = (verifyingAgentId || '').trim();
  const aTrimmed = (authorizingAgentId || '').trim();

  const d = dTrimmed.toLowerCase();
  const v = vTrimmed.toLowerCase();
  const a = aTrimmed.toLowerCase();

  if (d === v && v === a) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_details: "E_SOD_OMNIPOTENT_AGENT: Single agent attempted discovery, verification, and authorization",
    };
  }

  if (d === v) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_details: "E_SOD_SELF_CERTIFICATION: Discovering agent cannot verify its own finding",
    };
  }

  if (v === a) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_details: "E_SOD_SELF_AUTHORIZATION: Verifying agent cannot authorize the gate release",
    };
  }

  if (d === a) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_details: "E_SOD_DISCOVERER_AUTHORIZATION: Discovering agent cannot authorize the gate release",
    };
  }

  return {
    discovering_agent_id: dTrimmed,
    verifying_agent_id: vTrimmed,
    authorizing_agent_id: aTrimmed,
    is_valid: true,
  };
}

/**
 * Separation of Duties (SoD) evaluation result.
 * Enforces invariance: discovery agent != verification agent != authorization agent.
 */
export const SeparationOfDutiesEvaluationSchema = z.object({
  discovering_agent_id: z.string().min(1, { message: "discovering_agent_id is required" }),
  verifying_agent_id: z.string().min(1, { message: "verifying_agent_id is required" }),
  authorizing_agent_id: z.string().min(1, { message: "authorizing_agent_id is required" }),
  is_valid: z.boolean({ message: "is_valid must indicate if SoD is upheld" }),
  violation_details: z.string().optional(),
}).superRefine((data, ctx) => {
  const sod = evaluateSeparationOfDuties(
    data.discovering_agent_id,
    data.verifying_agent_id,
    data.authorizing_agent_id
  );
  if (!sod.is_valid && data.is_valid) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Separation of Duties violation: is_valid cannot be true when agent identities overlap",
      path: ["is_valid"],
    });
  }
});
export type SeparationOfDutiesEvaluation = {
  discovering_agent_id: string;
  verifying_agent_id: string;
  authorizing_agent_id: string;
  is_valid: boolean;
  violation_details?: string;
};

/**
 * Helper to normalize incoming GateDecision payloads (camelCase or snake_case).
 */
function normalizeGateDecisionInput(input: unknown): unknown {
  if (typeof input !== "object" || input === null) return input;
  const raw = input as Record<string, unknown>;

  const sodRaw = (raw.sod_evaluation ?? raw.separationOfDutiesCheck ?? raw.separationOfDuties) as
    | Record<string, unknown>
    | undefined;

  const normalizedSod = sodRaw
    ? {
        discovering_agent_id: sodRaw.discovering_agent_id ?? sodRaw.discoveringAgentId ?? sodRaw.discovering_agent,
        verifying_agent_id: sodRaw.verifying_agent_id ?? sodRaw.verifyingAgentId ?? sodRaw.verifying_agent,
        authorizing_agent_id: sodRaw.authorizing_agent_id ?? sodRaw.authorizingAgentId ?? sodRaw.authorizing_agent,
        is_valid: sodRaw.is_valid ?? sodRaw.isDistinct ?? sodRaw.isValid ?? false,
        violation_details: sodRaw.violation_details ?? sodRaw.violationDetails,
      }
    : undefined;

  const rawRules = (raw.rules_evaluated ?? raw.rulesEvaluated ?? raw.evaluations ?? []) as unknown[];
  const normalizedRules = Array.isArray(rawRules)
    ? rawRules.map((r) => {
        if (typeof r !== "object" || r === null) return r;
        const ruleObj = r as Record<string, unknown>;
        return {
          rule_id: ruleObj.rule_id ?? ruleObj.ruleId ?? ruleObj.ruleName ?? "UNKNOWN_RULE",
          status: ruleObj.status ?? "PASS",
          reason: ruleObj.reason ?? "",
          finding_id: ruleObj.finding_id ?? ruleObj.findingId,
        };
      })
    : [];

  return {
    decision_id: raw.decision_id ?? raw.decisionId ?? raw.id,
    policy_version: raw.policy_version ?? raw.policyVersion ?? "1.0.0",
    policy_id: raw.policy_id ?? raw.policyId ?? "default-zero-trust-policy",
    target_commit: raw.target_commit ?? raw.targetCommit ?? raw.gitBaseCommit,
    verdict: raw.verdict ?? raw.gateVerdict ?? raw.result,
    blocking_findings: raw.blocking_findings ?? raw.blockingFindings ?? [],
    unverified_findings: raw.unverified_findings ?? raw.unverifiedFindings ?? [],
    audit_merkle_root: raw.audit_merkle_root ?? raw.auditMerkleRoot ?? raw.merkleRoot,
    sod_evaluation: normalizedSod,
    rules_evaluated: normalizedRules,
    evaluation_summary: raw.evaluation_summary ?? raw.evaluationSummary ?? "",
    decided_at: raw.decided_at ?? raw.decidedAt ?? raw.evaluationTimestamp ?? new Date().toISOString(),
  };
}

/**
 * Canonical GateDecision Zod Schema.
 */
export const GateDecisionSchema = z.preprocess(
  normalizeGateDecisionInput,
  z.object({
    decision_id: z.string().min(1, { message: "decision_id is required" }).regex(
      /^SK-GATE-[a-zA-Z0-9_\-]+$/,
      { message: "decision_id must follow the pattern SK-GATE-<identifier>" }
    ),
    policy_version: z.string().min(1, { message: "policy_version is required" }),
    policy_id: z.string().optional().default("default-zero-trust-policy"),
    target_commit: z.string().regex(
      /^[0-9a-fA-F]{40,64}$/,
      { message: "target_commit must be a 40-character SHA-1 or 64-character SHA-256 hash" }
    ),
    verdict: GateVerdictSchema,
    blocking_findings: z.array(z.string()).default([]),
    unverified_findings: z.array(z.string()).default([]),
    audit_merkle_root: z.string().regex(
      /^[0-9a-fA-F]{64}$/,
      { message: "audit_merkle_root must be a 64-character hexadecimal SHA-256 hash" }
    ),
    sod_evaluation: SeparationOfDutiesEvaluationSchema,
    rules_evaluated: z.array(RuleEvaluationSchema).default([]),
    evaluation_summary: z.string().min(1, { message: "evaluation_summary cannot be empty" }),
    decided_at: z.string().datetime({
      message: "decided_at must be a valid ISO 8601 UTC timestamp",
    }),
  }).superRefine((data, ctx) => {
    // Zero-Trust Invariant 1: If verdict is PASS, blocking_findings MUST be empty
    if (data.verdict === "PASS" && data.blocking_findings.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Zero-Trust Violation: Gate cannot PASS when blocking_findings exist",
        path: ["verdict"],
      });
    }

    // Zero-Trust Invariant 2: If verdict is PASS, unverified_findings MUST be empty
    if (data.verdict === "PASS" && data.unverified_findings.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Zero-Trust Violation: Gate cannot PASS when unverified_findings exist",
        path: ["verdict"],
      });
    }

    // Re-evaluate Separation of Duties independently from client assertions
    const computedSod = evaluateSeparationOfDuties(
      data.sod_evaluation.discovering_agent_id,
      data.sod_evaluation.verifying_agent_id,
      data.sod_evaluation.authorizing_agent_id
    );

    const isSodValid = data.sod_evaluation.is_valid && computedSod.is_valid;

    if (!computedSod.is_valid && data.sod_evaluation.is_valid) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Zero-Trust Violation: Separation of Duties violation: cannot assert is_valid=true when agents overlap",
        path: ["sod_evaluation", "is_valid"],
      });
    }

    // Zero-Trust Invariant 3: If verdict is PASS, SoD evaluation MUST be valid
    if (data.verdict === "PASS" && !isSodValid) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Zero-Trust Violation: Gate cannot PASS with Separation of Duties violation",
        path: ["verdict"],
      });
    }

    // Zero-Trust Invariant 4: If SoD is invalid, verdict MUST be REJECT
    if (!isSodValid && data.verdict !== "REJECT") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Invalid State: SoD violation must result in a REJECT verdict",
        path: ["verdict"],
      });
    }
  })
);

export type GateDecision = z.infer<typeof GateDecisionSchema>;

/**
 * Helper: Validates a raw GateDecision payload against schema and invariants.
 */
export function validateGateDecision(input: unknown): GateDecision {
  return GateDecisionSchema.parse(input);
}
