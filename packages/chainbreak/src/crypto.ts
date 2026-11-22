/**
 * @file packages/chainbreak/src/crypto.ts
 * @description Deterministic RFC 8785 canonical hashing, ID derivation, and tamper-detection
 * helpers for ChainBreak v0.
 */

import { canonicalStringify, sha256 } from '@script-kitty/contracts';
import type {
  ChainBreakEvidence,
  PolicyGraph,
  PolicyGraphInput,
} from './schemas.js';

export { canonicalStringify, sha256 };

/**
 * Computes the deterministic SHA-256 hash of a PolicyGraph / PolicyGraphInput.
 * Excludes self-referential `declaredInputSha256` so fixtures may embed their expected hash.
 */
export function computePolicyGraphSha256(
  graph: PolicyGraph | PolicyGraphInput | Record<string, unknown>
): string {
  const copy = { ...(graph as Record<string, unknown>) };
  delete copy.declaredInputSha256;
  return sha256(canonicalStringify(copy));
}

/**
 * Computes canonical SHA-256 content digest for ChainBreakEvidence payloads.
 */
export function computeEvidenceContentSha256(payload: unknown): string {
  return sha256(canonicalStringify(payload));
}

/**
 * Derives a deterministic identifier from a prefix and canonical payload parts.
 */
export function deriveDeterministicId(prefix: string, payload: unknown): string {
  const digest = sha256(canonicalStringify(payload)).slice(0, 16);
  return `${prefix}-${digest}`;
}

export interface GraphIntegrityVerificationResult {
  valid: boolean;
  computedInputSha256: string;
  declaredInputSha256?: string;
  expectedInputSha256?: string;
  error?: string;
}

/**
 * Verifies canonical hash integrity of an input graph against any declared or expected SHA-256.
 * Fails closed whenever any hash mismatch is observed.
 */
export function verifyGraphIntegrity(
  graph: PolicyGraph | PolicyGraphInput | Record<string, unknown>,
  expectedInputSha256?: string
): GraphIntegrityVerificationResult {
  const computedInputSha256 = computePolicyGraphSha256(graph);
  const declared =
    typeof (graph as { declaredInputSha256?: unknown }).declaredInputSha256 === 'string'
      ? (graph as { declaredInputSha256: string }).declaredInputSha256.toLowerCase()
      : undefined;
  const expected = expectedInputSha256?.toLowerCase();

  if (declared && declared !== computedInputSha256) {
    return {
      valid: false,
      computedInputSha256,
      declaredInputSha256: declared,
      expectedInputSha256: expected,
      error: `TAMPER_DETECTED: declaredInputSha256 (${declared}) does not match computed SHA-256 (${computedInputSha256})`,
    };
  }

  if (expected && expected !== computedInputSha256) {
    return {
      valid: false,
      computedInputSha256,
      declaredInputSha256: declared,
      expectedInputSha256: expected,
      error: `TAMPER_DETECTED: expectedInputSha256 (${expected}) does not match computed SHA-256 (${computedInputSha256})`,
    };
  }

  return {
    valid: true,
    computedInputSha256,
    declaredInputSha256: declared,
    expectedInputSha256: expected,
  };
}

/**
 * Verifies a ChainBreakEvidence record's contentSha256 against its payload.
 */
export function verifyEvidenceHash(
  evidence: ChainBreakEvidence,
  payload: unknown
): boolean {
  if (!evidence.contentSha256 || !/^[a-f0-9]{64}$/i.test(evidence.contentSha256)) {
    return false;
  }
  const recomputed = computeEvidenceContentSha256(payload);
  return recomputed.toLowerCase() === evidence.contentSha256.toLowerCase();
}
