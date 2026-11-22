/**
 * @file packages/contracts/src/index.ts
 * @description Unified public entrypoint, re-exports, and validation helpers for
 * @script-kitty/contracts (ScriptKitty 2.0).
 */

import { z } from 'zod';

// 1. Common Types and Schemas
export * from './common.js';

// 2. Finding Contract
export * from './finding.js';
import { SecurityFindingSchema, type SecurityFinding } from './finding.js';

// 3. Evidence Contract
export * from './evidence.js';
import { EvidenceSchema, type Evidence } from './evidence.js';

// 4. Patch Proposal Contract
export * from './patch.js';
import { PatchProposalSchema, type PatchProposal } from './patch.js';

// 5. Gate Decision Contract
export * from './gate.js';
import { GateDecisionSchema, type GateDecision } from './gate.js';
export { GateVerdict, GateVerdictSchema } from './gate.js';

// 6. Custody, Merkle & Chaining
export * from './custody.js';
import {
  verifyChainIntegrity,
  verifyChainOfCustody as verifyChainOfCustodyBase,
  buildCustodyChain,
  type CustodyNode,
  type ChainOfCustody,
  type ChainVerificationResult,
} from './custody.js';

/**
 * Standard validation result wrapper.
 */
export type ValidationResult<T> =
  | {
      success: true;
      data: T;
      errors?: undefined;
    }
  | {
      success: false;
      data?: undefined;
      errors: Array<{
        path: string;
        message: string;
        code: string;
      }>;
    };

/**
 * Formats Zod errors into a clean, structured array.
 */
function formatZodErrors(error: z.ZodError): Array<{ path: string; message: string; code: string }> {
  return error.errors.map((err) => ({
    path: err.path.join('.'),
    message: err.message,
    code: err.code,
  }));
}

/**
 * Validates a candidate object against SecurityFindingSchema.
 * Safe parser returning structured ValidationResult.
 */
export function validateFinding(input: unknown): ValidationResult<SecurityFinding> {
  const result = SecurityFindingSchema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, errors: formatZodErrors(result.error) };
}

/**
 * Throws a ZodError if input is an invalid SecurityFinding.
 */
export function parseFinding(input: unknown): SecurityFinding {
  return SecurityFindingSchema.parse(input);
}

/**
 * Validates a candidate object against EvidenceSchema.
 * Safe parser returning structured ValidationResult.
 */
export function validateEvidence(input: unknown): ValidationResult<Evidence> {
  const result = EvidenceSchema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, errors: formatZodErrors(result.error) };
}

/**
 * Throws a ZodError if input is an invalid Evidence contract.
 */
export function parseEvidence(input: unknown): Evidence {
  return EvidenceSchema.parse(input);
}

/**
 * Validates a candidate object against PatchProposalSchema.
 * Safe parser returning structured ValidationResult.
 */
export function validatePatch(input: unknown): ValidationResult<PatchProposal> {
  const result = PatchProposalSchema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, errors: formatZodErrors(result.error) };
}

/**
 * Throws a ZodError if input is an invalid PatchProposal.
 */
export function parsePatch(input: unknown): PatchProposal {
  return PatchProposalSchema.parse(input);
}

/**
 * Validates a candidate object against GateDecisionSchema.
 * Safe parser returning structured ValidationResult.
 */
export function validateGateDecision(input: unknown): ValidationResult<GateDecision> {
  const result = GateDecisionSchema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, errors: formatZodErrors(result.error) };
}

/**
 * Throws a ZodError if input is an invalid GateDecision.
 */
export function parseGateDecision(input: unknown): GateDecision {
  return GateDecisionSchema.parse(input);
}

/**
 * Verifies a ChainOfCustody instance or constructs and verifies a custody chain
 * linking finding -> evidence -> patch -> gate.
 */
export function verifyChainOfCustody(
  input:
    | ChainOfCustody
    | {
        nodes: CustodyNode[];
        merkle_root?: string;
      }
    | {
        finding: unknown;
        evidence: unknown;
        patch?: unknown;
        gate?: unknown;
      }
): ChainVerificationResult {
  // If input is already a constructed ChainOfCustody or node list object
  if (typeof input === 'object' && input !== null && 'nodes' in input && Array.isArray((input as { nodes: CustodyNode[] }).nodes)) {
    return verifyChainOfCustodyBase(input as ChainOfCustody);
  }

  // Otherwise, validate individual contract inputs and build chain
  const candidate = input as {
    finding: unknown;
    evidence: unknown;
    patch?: unknown;
    gate?: unknown;
  };

  const findingRes = validateFinding(candidate.finding);
  if (!findingRes.success) {
    return {
      valid: false,
      total_nodes: 0,
      merkle_root: '',
      error: `Invalid finding contract in custody chain: ${findingRes.errors.map((e) => e.message).join('; ')}`,
    };
  }

  const evidenceRes = validateEvidence(candidate.evidence);
  if (!evidenceRes.success) {
    return {
      valid: false,
      total_nodes: 1,
      merkle_root: '',
      error: `Invalid evidence contract in custody chain: ${evidenceRes.errors.map((e) => e.message).join('; ')}`,
    };
  }

  let patchData: PatchProposal | undefined;
  if (candidate.patch) {
    const patchRes = validatePatch(candidate.patch);
    if (!patchRes.success) {
      return {
        valid: false,
        total_nodes: 2,
        merkle_root: '',
        error: `Invalid patch contract in custody chain: ${patchRes.errors.map((e) => e.message).join('; ')}`,
      };
    }
    patchData = patchRes.data;
  }

  let gateData: GateDecision | undefined;
  if (candidate.gate) {
    const gateRes = validateGateDecision(candidate.gate);
    if (!gateRes.success) {
      return {
        valid: false,
        total_nodes: patchData ? 3 : 2,
        merkle_root: '',
        error: `Invalid gate decision contract in custody chain: ${gateRes.errors.map((e) => e.message).join('; ')}`,
      };
    }
    gateData = gateRes.data;
  }

  const chain = buildCustodyChain({
    finding: findingRes.data,
    evidence: evidenceRes.data,
    patch: patchData,
    gate: gateData,
  });

  return verifyChainOfCustodyBase(chain);
}
