/**
 * @file packages/evidence/src/crypto.ts
 * @description RFC 8785 canonical JSON hashing, AI-prose rejection guard,
 * SHA-256 receipt creation/verification, and binary Merkle inclusion proof helpers.
 */

import {
  ChainBreakEvidenceSchema,
  type ChainBreakEvidence,
} from '@script-kitty/chainbreak';
import {
  canonicalStringify,
  computeEvidenceChainHash,
  computeMerkleRoot,
  EMPTY_MERKLE_ROOT,
  EvidenceSchema as ContractEvidenceSchema,
  generateMerkleProof,
  hashEvidence,
  sha256,
  verifyMerkleProof,
  type Evidence as ContractEvidence,
} from '@script-kitty/contracts';
import {
  AnalysisMerkleBundleSchema,
  EvidenceIntegrityError,
  EvidenceLedgerError,
  EvidenceReceiptSchema,
  NonEmptyAnalysisIdSchema,
  NonEmptyTenantIdSchema,
  UnverifiedAiProseError,
  type AnalysisMerkleBundle,
  type EvidenceCrossLink,
  type EvidenceReceipt,
  type EvidenceRecordType,
  type MerkleBundleVerificationResult,
  type MerkleInclusionEntry,
  type ReceiptVerificationResult,
  type UnifiedEvidenceKind,
} from './schemas.js';

export {
  canonicalStringify,
  computeEvidenceChainHash,
  computeMerkleRoot,
  EMPTY_MERKLE_ROOT,
  generateMerkleProof,
  hashEvidence,
  sha256,
  verifyMerkleProof,
};

// ============================================================================
// 1. UNVERIFIED AI-GENERATED PROSE DETECTION & REJECTION
// ============================================================================

const PROHIBITED_AI_PROSE_KINDS = new Set([
  'AI_PROSE',
  'LLM_PROSE',
  'LLM_OPINION',
  'AI_OPINION',
  'AI_SUMMARY',
  'LLM_SUMMARY',
  'NARRATIVE_PROOF',
  'TEXT_EXPLANATION',
  'PROMPT_OUTPUT',
  'CHAT_COMPLETION',
]);

const AI_PROSE_PRODUCER_REGEX =
  /^(?:llm|ai[-_:]?prose|llm[-_:]?prose|gpt[-0-9a-z._]*|claude[-0-9a-z._]*|gemini[-0-9a-z._]*|chatgpt|openai[-_:]?prose|anthropic[-_:]?prose|jev[-_:]?prose|unverified[-_:]?ai|narrative[-_:]?only)$/i;

const AI_PROSE_SUBSTRING_REGEX =
  /(?:llm[-_ ]?prose|ai[-_ ]?prose|ai[-_ ]?generated[-_ ]?prose|unverified[-_ ]?(?:ai|llm)|narrative[-_ ]?only|prompt[-_ ]?response[-_ ]?only)/i;

const AI_PROSE_SOURCE_REF_REGEX =
  /^(?:llm|ai|ai-prose|llm-prose|gpt|claude|gemini|chatgpt|prompt|completion|narrative):\/\//i;

const PLACEHOLDER_SOURCE_REF_SET = new Set([
  'missing',
  'unknown',
  'none',
  'n/a',
  'na',
  'ai-generated',
  'llm-generated',
  'llm-prose',
  'ai-prose',
]);

export interface AiProseAssessment {
  isUnverifiedAiProse: boolean;
  reasons: string[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function isPlaceholderSourceRef(sourceRef: string | undefined): boolean {
  if (typeof sourceRef !== 'string') return true;
  const trimmed = sourceRef.trim();
  if (!trimmed) return true;
  return PLACEHOLDER_SOURCE_REF_SET.has(trimmed.toLowerCase());
}

/**
 * Inspects a candidate evidence object or payload and rejects unverified
 * AI-generated prose trying to pose as standalone security proof.
 */
export function assessAiProseProofRisk(
  candidate: unknown,
  payload?: unknown
): AiProseAssessment {
  const reasons: string[] = [];

  if (typeof candidate === 'string') {
    reasons.push('Raw text string cannot serve as standalone security evidence');
    return { isUnverifiedAiProse: true, reasons };
  }

  if (!isPlainObject(candidate)) {
    return { isUnverifiedAiProse: false, reasons };
  }

  const rawKind = typeof candidate.kind === 'string' ? candidate.kind.trim().toUpperCase() : '';
  if (rawKind && PROHIBITED_AI_PROSE_KINDS.has(rawKind)) {
    reasons.push(`Prohibited AI prose evidence kind '${rawKind}'`);
  }

  const provenance =
    typeof candidate.provenance === 'string'
      ? candidate.provenance.trim().toUpperCase()
      : typeof candidate.sourceType === 'string'
        ? candidate.sourceType.trim().toUpperCase()
        : '';
  if (
    provenance &&
    (PROHIBITED_AI_PROSE_KINDS.has(provenance) ||
      provenance === 'UNVERIFIED_AI' ||
      provenance === 'LLM_ONLY')
  ) {
    reasons.push(`Prohibited AI prose provenance '${provenance}'`);
  }

  if (
    candidate.isAiGeneratedProse === true ||
    candidate.aiGeneratedProse === true ||
    candidate.unverifiedAiProse === true ||
    candidate.standaloneAiProse === true
  ) {
    reasons.push('Explicit unverified AI prose marker set on evidence');
  }

  // Raw prose objects lacking structured deterministic schema
  const hasProseFields =
    typeof candidate.prose === 'string' ||
    typeof candidate.llmResponse === 'string' ||
    typeof candidate.narrative === 'string' ||
    typeof candidate.completion === 'string';
  const hasStructuredId =
    typeof candidate.evidenceId === 'string' ||
    typeof candidate.evidence_id === 'string';
  if (hasProseFields && !hasStructuredId) {
    reasons.push('Unstructured AI narrative/prose object rejected as standalone proof');
  }

  const producerCandidates = [
    candidate.producer,
    candidate.verifier_agent_id,
    candidate.verifierAgentId,
  ].filter((v): v is string => typeof v === 'string');

  for (const prod of producerCandidates) {
    const trimmed = prod.trim();
    if (AI_PROSE_PRODUCER_REGEX.test(trimmed) || AI_PROSE_SUBSTRING_REGEX.test(trimmed)) {
      reasons.push(`Producer '${trimmed}' represents unverified AI/LLM prose generation`);
    }
  }

  const sourceRef =
    typeof candidate.sourceRef === 'string'
      ? candidate.sourceRef.trim()
      : typeof candidate.source_ref === 'string'
        ? candidate.source_ref.trim()
        : undefined;

  if (sourceRef !== undefined) {
    if (
      AI_PROSE_SOURCE_REF_REGEX.test(sourceRef) ||
      AI_PROSE_SUBSTRING_REGEX.test(sourceRef) ||
      PLACEHOLDER_SOURCE_REF_SET.has(sourceRef.toLowerCase())
    ) {
      if (
        AI_PROSE_SOURCE_REF_REGEX.test(sourceRef) ||
        AI_PROSE_SUBSTRING_REGEX.test(sourceRef) ||
        sourceRef.toLowerCase().includes('ai') ||
        sourceRef.toLowerCase().includes('llm')
      ) {
        reasons.push(`sourceRef '${sourceRef}' points to unverified AI/LLM text`);
      }
    }
  }

  // Contract Evidence: HEURISTIC claiming positive/refuted proof without empirical artifact
  const verificationType =
    typeof candidate.verification_type === 'string'
      ? candidate.verification_type.trim().toUpperCase()
      : '';
  const status =
    typeof candidate.status === 'string'
      ? candidate.status.trim().toUpperCase()
      : '';
  if (
    verificationType === 'HEURISTIC' &&
    (status === 'VERIFIED_TRUE_POSITIVE' || status === 'REFUTED_FALSE_POSITIVE') &&
    !candidate.reproducer_artifact &&
    !candidate.reproduction_proof
  ) {
    reasons.push(
      `HEURISTIC evidence claiming '${status}' without reproducer_artifact or reproduction_proof cannot act as standalone proof`
    );
  }

  // Raw string payload passed alongside unverified ChainBreakEvidence
  if (typeof payload === 'string' && candidate.verified === false) {
    reasons.push('Unverified raw text payload rejected as standalone proof');
  }
  if (isPlainObject(payload)) {
    if (
      payload.isAiGeneratedProse === true ||
      payload.unverifiedAiProse === true ||
      (typeof payload.prose === 'string' && candidate.verified !== true)
    ) {
      reasons.push('Payload explicitly marked as unverified AI-generated prose');
    }
  }

  return {
    isUnverifiedAiProse: reasons.length > 0,
    reasons,
  };
}

export function assertNotUnverifiedAiProse(
  candidate: unknown,
  payload?: unknown
): void {
  const assessment = assessAiProseProofRisk(candidate, payload);
  if (assessment.isUnverifiedAiProse) {
    throw new UnverifiedAiProseError(assessment.reasons.join('; '));
  }
}

// ============================================================================
// 2. CANONICAL RECEIPT CREATION & DIGEST VERIFICATION
// ============================================================================

export function computeCanonicalDigest(value: unknown): string {
  return sha256(canonicalStringify(value));
}

export function computeChainBreakLeafSha256(evidence: ChainBreakEvidence): string {
  return sha256(canonicalStringify(evidence));
}

export function computeContractSourceRef(
  evidence: ContractEvidence,
  explicitSourceRef?: string
): string {
  if (explicitSourceRef && explicitSourceRef.trim().length > 0) {
    return explicitSourceRef.trim();
  }
  if (evidence.reproducer_artifact?.script_path) {
    return evidence.reproducer_artifact.script_path;
  }
  if (evidence.reproduction_proof?.proof_type) {
    return `proof:${evidence.reproduction_proof.proof_type}:${evidence.finding_id}`;
  }
  return `finding:${evidence.finding_id}:${evidence.verification_type}`;
}

function buildReceiptDigestInput(receipt: {
  schemaVersion: 'evidence.receipt.v1';
  receiptId: string;
  recordType: EvidenceRecordType;
  tenantId: string;
  analysisId: string;
  evidenceId: string;
  findingId?: string;
  pathId?: string;
  kind: UnifiedEvidenceKind;
  sourceRef: string;
  producer: string;
  verified: boolean;
  standaloneProofEligible: boolean;
  contentSha256: string;
  canonicalLeafSha256: string;
  payloadSha256?: string;
  commitSha?: string;
  createdAt: string;
  recordedAt: string;
}): Record<string, unknown> {
  return {
    schemaVersion: receipt.schemaVersion,
    receiptId: receipt.receiptId,
    recordType: receipt.recordType,
    tenantId: receipt.tenantId,
    analysisId: receipt.analysisId,
    evidenceId: receipt.evidenceId,
    ...(receipt.findingId !== undefined ? { findingId: receipt.findingId } : {}),
    ...(receipt.pathId !== undefined ? { pathId: receipt.pathId } : {}),
    kind: receipt.kind,
    sourceRef: receipt.sourceRef,
    producer: receipt.producer,
    verified: receipt.verified,
    standaloneProofEligible: receipt.standaloneProofEligible,
    contentSha256: receipt.contentSha256.toLowerCase(),
    canonicalLeafSha256: receipt.canonicalLeafSha256.toLowerCase(),
    ...(receipt.payloadSha256 !== undefined
      ? { payloadSha256: receipt.payloadSha256.toLowerCase() }
      : {}),
    ...(receipt.commitSha !== undefined ? { commitSha: receipt.commitSha } : {}),
    createdAt: receipt.createdAt,
    recordedAt: receipt.recordedAt,
  };
}

export interface CreateEvidenceReceiptParams {
  tenantId: string;
  analysisId?: string;
  evidence: unknown;
  payload?: unknown;
  pathId?: string;
  sourceRef?: string;
  recordedAt?: string;
  verifyChainHash?: boolean;
}

/**
 * Normalizes either a ChainBreakEvidence or canonical @script-kitty/contracts
 * Evidence into an RFC 8785 canonical SHA-256 signed EvidenceReceipt.
 * Rejects unverified AI-generated prose and SHA-256 payload mismatches fail-closed.
 */
export function createEvidenceReceipt(
  params: CreateEvidenceReceiptParams
): EvidenceReceipt {
  const tenantParsed = NonEmptyTenantIdSchema.safeParse(params.tenantId);
  if (!tenantParsed.success) {
    throw new EvidenceLedgerError('VALIDATION_ERROR', 'tenantId is required');
  }
  const tenantId = tenantParsed.data;

  // Reject unverified AI prose before schema fallback
  assertNotUnverifiedAiProse(params.evidence, params.payload);

  const cbParsed = ChainBreakEvidenceSchema.safeParse(params.evidence);
  if (cbParsed.success) {
    const ev = cbParsed.data;
    const analysisId = params.analysisId?.trim() || ev.analysisId;
    if (analysisId !== ev.analysisId) {
      throw new EvidenceLedgerError(
        'VALIDATION_ERROR',
        `ChainBreakEvidence analysisId '${ev.analysisId}' does not match '${analysisId}'`
      );
    }

    let payloadSha256: string | undefined;
    if (params.payload !== undefined) {
      payloadSha256 = computeCanonicalDigest(params.payload);
      if (payloadSha256 !== ev.contentSha256.toLowerCase()) {
        throw new EvidenceIntegrityError(
          'DIGEST_MISMATCH',
          `ChainBreakEvidence '${ev.evidenceId}' contentSha256 (${ev.contentSha256}) does not match RFC 8785 payload SHA-256 (${payloadSha256})`
        );
      }
    }

    const contentSha256 = ev.contentSha256.toLowerCase();
    const canonicalLeafSha256 = computeChainBreakLeafSha256(ev);
    const recordedAt = params.recordedAt ?? ev.createdAt;
    const standaloneProofEligible =
      ev.verified === true && !isPlaceholderSourceRef(ev.sourceRef);

    const receiptBase = {
      schemaVersion: 'evidence.receipt.v1' as const,
      receiptId: `rcpt-${sha256(
        canonicalStringify({
          tenantId,
          analysisId,
          recordType: 'CHAINBREAK',
          evidenceId: ev.evidenceId,
          canonicalLeafSha256,
        })
      ).slice(0, 16)}`,
      recordType: 'CHAINBREAK' as const,
      tenantId,
      analysisId,
      evidenceId: ev.evidenceId,
      ...(params.pathId ? { pathId: params.pathId } : {}),
      kind: ev.kind as UnifiedEvidenceKind,
      sourceRef: ev.sourceRef,
      producer: ev.producer,
      verified: ev.verified,
      standaloneProofEligible,
      contentSha256,
      canonicalLeafSha256,
      ...(payloadSha256 ? { payloadSha256 } : {}),
      ...(ev.commitSha ? { commitSha: ev.commitSha } : {}),
      createdAt: ev.createdAt,
      recordedAt,
    };

    const receiptSha256 = computeCanonicalDigest(
      buildReceiptDigestInput(receiptBase)
    );

    return {
      ...receiptBase,
      receiptSha256,
      evidence: ev,
    };
  }

  const contractParsed = ContractEvidenceSchema.safeParse(params.evidence);
  if (contractParsed.success) {
    const ev = contractParsed.data;
    const analysisParsed = NonEmptyAnalysisIdSchema.safeParse(
      params.analysisId ?? ev.finding_id
    );
    if (!analysisParsed.success) {
      throw new EvidenceLedgerError(
        'VALIDATION_ERROR',
        'analysisId is required for contract Evidence'
      );
    }
    const analysisId = analysisParsed.data;

    if (params.verifyChainHash && ev.reproducer_artifact?.script_sha256) {
      const expectedChainHash = computeEvidenceChainHash({
        finding_id: ev.finding_id,
        verifier_agent_id: ev.verifier_agent_id,
        status: ev.status,
        script_sha256: ev.reproducer_artifact.script_sha256,
        recorded_at: ev.recorded_at,
      });
      if (expectedChainHash !== ev.chain_hash.toLowerCase()) {
        throw new EvidenceIntegrityError(
          'DIGEST_MISMATCH',
          `Contract Evidence '${ev.evidence_id}' chain_hash (${ev.chain_hash}) does not match computed chain hash (${expectedChainHash})`
        );
      }
    }

    const canonicalLeafSha256 = hashEvidence(ev).toLowerCase();
    const payloadSha256 =
      params.payload !== undefined
        ? computeCanonicalDigest(params.payload)
        : undefined;
    const contentSha256 = payloadSha256 ?? canonicalLeafSha256;
    const sourceRef = computeContractSourceRef(ev, params.sourceRef);
    const verified =
      ev.status === 'VERIFIED_TRUE_POSITIVE' ||
      ev.status === 'REFUTED_FALSE_POSITIVE';
    const standaloneProofEligible =
      verified && !isPlaceholderSourceRef(sourceRef);
    const recordedAt = params.recordedAt ?? ev.recorded_at;

    const receiptBase = {
      schemaVersion: 'evidence.receipt.v1' as const,
      receiptId: `rcpt-${sha256(
        canonicalStringify({
          tenantId,
          analysisId,
          recordType: 'CONTRACT',
          evidenceId: ev.evidence_id,
          canonicalLeafSha256,
        })
      ).slice(0, 16)}`,
      recordType: 'CONTRACT' as const,
      tenantId,
      analysisId,
      evidenceId: ev.evidence_id,
      findingId: ev.finding_id,
      ...(params.pathId ? { pathId: params.pathId } : {}),
      kind: ev.status as UnifiedEvidenceKind,
      sourceRef,
      producer: ev.verifier_agent_id,
      verified,
      standaloneProofEligible,
      contentSha256,
      canonicalLeafSha256,
      ...(payloadSha256 ? { payloadSha256 } : {}),
      createdAt: ev.recorded_at,
      recordedAt,
    };

    const receiptSha256 = computeCanonicalDigest(
      buildReceiptDigestInput(receiptBase)
    );

    return {
      ...receiptBase,
      receiptSha256,
      evidence: ev,
    };
  }

  throw new EvidenceLedgerError(
    'VALIDATION_ERROR',
    'Evidence input matches neither ChainBreakEvidenceSchema nor @script-kitty/contracts EvidenceSchema'
  );
}

export interface VerifyEvidenceReceiptOptions {
  payload?: unknown;
  expectedContentSha256?: string;
  requireVerifiedProof?: boolean;
  verifyChainHash?: boolean;
}

/**
 * Verifies an EvidenceReceipt (or `{ evidence, payload? }` / raw evidence candidate)
 * against RFC 8785 canonical JSON serialization, SHA-256 content digests,
 * and anti-AI-prose standalone proof rules.
 */
export function verifyEvidenceReceipt(
  input: unknown,
  options: VerifyEvidenceReceiptOptions = {}
): ReceiptVerificationResult {
  const reasons: string[] = [];

  // 1. Check direct unverified AI-prose shapes immediately
  const rawPayload =
    options.payload !== undefined
      ? options.payload
      : isPlainObject(input) && 'payload' in input
        ? input.payload
        : undefined;
  const candidateForProse =
    isPlainObject(input) && 'evidence' in input ? input.evidence : input;

  const proseCheckTop = assessAiProseProofRisk(input, rawPayload);
  const proseCheckInner =
    candidateForProse !== input
      ? assessAiProseProofRisk(candidateForProse, rawPayload)
      : { isUnverifiedAiProse: false, reasons: [] };

  if (proseCheckTop.isUnverifiedAiProse || proseCheckInner.isUnverifiedAiProse) {
    return {
      valid: false,
      code: 'UNVERIFIED_AI_PROSE_REJECTED',
      verified: false,
      standaloneProofEligible: false,
      reasons: [...proseCheckTop.reasons, ...proseCheckInner.reasons],
    };
  }

  // 2. Full EvidenceReceipt verification
  const receiptParsed = EvidenceReceiptSchema.safeParse(input);
  if (receiptParsed.success) {
    const receipt = receiptParsed.data as EvidenceReceipt;

    if (receipt.recordType === 'CHAINBREAK') {
      const ev = receipt.evidence as ChainBreakEvidence;
      const recomputedLeaf = computeChainBreakLeafSha256(ev);
      if (recomputedLeaf !== receipt.canonicalLeafSha256.toLowerCase()) {
        reasons.push(
          `Canonical leaf SHA-256 mismatch: stored=${receipt.canonicalLeafSha256}, computed=${recomputedLeaf}`
        );
      }
      if (ev.contentSha256.toLowerCase() !== receipt.contentSha256.toLowerCase()) {
        reasons.push(
          `Evidence contentSha256 mismatch: receipt=${receipt.contentSha256}, evidence=${ev.contentSha256}`
        );
      }

      let recomputedContent = receipt.contentSha256.toLowerCase();
      if (rawPayload !== undefined) {
        recomputedContent = computeCanonicalDigest(rawPayload);
        if (recomputedContent !== ev.contentSha256.toLowerCase()) {
          reasons.push(
            `Payload SHA-256 mismatch: expected=${ev.contentSha256}, computed=${recomputedContent}`
          );
        }
      }
      if (
        options.expectedContentSha256 &&
        options.expectedContentSha256.toLowerCase() !== ev.contentSha256.toLowerCase()
      ) {
        reasons.push(
          `Expected contentSha256 (${options.expectedContentSha256}) does not match (${ev.contentSha256})`
        );
      }

      const recomputedReceiptSha = computeCanonicalDigest(
        buildReceiptDigestInput(receipt)
      );
      if (recomputedReceiptSha !== receipt.receiptSha256.toLowerCase()) {
        reasons.push(
          `Receipt SHA-256 mismatch: stored=${receipt.receiptSha256}, computed=${recomputedReceiptSha}`
        );
      }

      if (reasons.length > 0) {
        return {
          valid: false,
          code: 'DIGEST_MISMATCH',
          recordType: 'CHAINBREAK',
          evidenceId: receipt.evidenceId,
          contentSha256: receipt.contentSha256,
          recomputedContentSha256: recomputedContent,
          canonicalLeafSha256: recomputedLeaf,
          receiptSha256: recomputedReceiptSha,
          verified: false,
          standaloneProofEligible: false,
          reasons,
        };
      }

      if (receipt.verified && isPlaceholderSourceRef(ev.sourceRef)) {
        return {
          valid: false,
          code: 'MISSING_PROVENANCE',
          recordType: 'CHAINBREAK',
          evidenceId: receipt.evidenceId,
          contentSha256: receipt.contentSha256,
          recomputedContentSha256: recomputedContent,
          canonicalLeafSha256: recomputedLeaf,
          receiptSha256: recomputedReceiptSha,
          verified: false,
          standaloneProofEligible: false,
          reasons: ['Verified ChainBreakEvidence cannot have empty or placeholder sourceRef'],
        };
      }

      const eligible = ev.verified === true && !isPlaceholderSourceRef(ev.sourceRef);
      if (options.requireVerifiedProof && !eligible) {
        return {
          valid: false,
          code: 'UNVERIFIED_PROOF',
          recordType: 'CHAINBREAK',
          evidenceId: receipt.evidenceId,
          contentSha256: receipt.contentSha256,
          recomputedContentSha256: recomputedContent,
          canonicalLeafSha256: recomputedLeaf,
          receiptSha256: recomputedReceiptSha,
          verified: ev.verified,
          standaloneProofEligible: false,
          reasons: ['Evidence is not verified for standalone proof'],
        };
      }

      return {
        valid: true,
        code: 'VERIFIED',
        recordType: 'CHAINBREAK',
        evidenceId: receipt.evidenceId,
        contentSha256: receipt.contentSha256,
        recomputedContentSha256: recomputedContent,
        canonicalLeafSha256: recomputedLeaf,
        receiptSha256: recomputedReceiptSha,
        verified: ev.verified,
        standaloneProofEligible: eligible,
        reasons: [],
      };
    }

    // CONTRACT Evidence branch
    const ev = receipt.evidence as ContractEvidence;
    const recomputedLeaf = hashEvidence(ev).toLowerCase();
    if (recomputedLeaf !== receipt.canonicalLeafSha256.toLowerCase()) {
      reasons.push(
        `Canonical leaf SHA-256 mismatch: stored=${receipt.canonicalLeafSha256}, computed=${recomputedLeaf}`
      );
    }

    let recomputedContent = recomputedLeaf;
    if (rawPayload !== undefined) {
      recomputedContent = computeCanonicalDigest(rawPayload);
      if (recomputedContent !== receipt.contentSha256.toLowerCase()) {
        reasons.push(
          `Payload SHA-256 mismatch: stored=${receipt.contentSha256}, computed=${recomputedContent}`
        );
      }
    } else if (receipt.payloadSha256) {
      recomputedContent = receipt.payloadSha256.toLowerCase();
    }

    if (
      options.expectedContentSha256 &&
      options.expectedContentSha256.toLowerCase() !== receipt.contentSha256.toLowerCase()
    ) {
      reasons.push(
        `Expected contentSha256 (${options.expectedContentSha256}) does not match (${receipt.contentSha256})`
      );
    }

    if (options.verifyChainHash && ev.reproducer_artifact?.script_sha256) {
      const expectedChainHash = computeEvidenceChainHash({
        finding_id: ev.finding_id,
        verifier_agent_id: ev.verifier_agent_id,
        status: ev.status,
        script_sha256: ev.reproducer_artifact.script_sha256,
        recorded_at: ev.recorded_at,
      });
      if (expectedChainHash !== ev.chain_hash.toLowerCase()) {
        reasons.push(
          `Contract Evidence chain_hash mismatch: stored=${ev.chain_hash}, computed=${expectedChainHash}`
        );
      }
    }

    const recomputedReceiptSha = computeCanonicalDigest(
      buildReceiptDigestInput(receipt)
    );
    if (recomputedReceiptSha !== receipt.receiptSha256.toLowerCase()) {
      reasons.push(
        `Receipt SHA-256 mismatch: stored=${receipt.receiptSha256}, computed=${recomputedReceiptSha}`
      );
    }

    if (reasons.length > 0) {
      return {
        valid: false,
        code: 'DIGEST_MISMATCH',
        recordType: 'CONTRACT',
        evidenceId: receipt.evidenceId,
        contentSha256: receipt.contentSha256,
        recomputedContentSha256: recomputedContent,
        canonicalLeafSha256: recomputedLeaf,
        receiptSha256: recomputedReceiptSha,
        verified: false,
        standaloneProofEligible: false,
        reasons,
      };
    }

    const verified =
      ev.status === 'VERIFIED_TRUE_POSITIVE' ||
      ev.status === 'REFUTED_FALSE_POSITIVE';
    const eligible = verified && !isPlaceholderSourceRef(receipt.sourceRef);

    if (options.requireVerifiedProof && !eligible) {
      return {
        valid: false,
        code: 'UNVERIFIED_PROOF',
        recordType: 'CONTRACT',
        evidenceId: receipt.evidenceId,
        contentSha256: receipt.contentSha256,
        recomputedContentSha256: recomputedContent,
        canonicalLeafSha256: recomputedLeaf,
        receiptSha256: recomputedReceiptSha,
        verified,
        standaloneProofEligible: false,
        reasons: [`Contract Evidence status '${ev.status}' is not standalone verified proof`],
      };
    }

    return {
      valid: true,
      code: 'VERIFIED',
      recordType: 'CONTRACT',
      evidenceId: receipt.evidenceId,
      contentSha256: receipt.contentSha256,
      recomputedContentSha256: recomputedContent,
      canonicalLeafSha256: recomputedLeaf,
      receiptSha256: recomputedReceiptSha,
      verified,
      standaloneProofEligible: eligible,
      reasons: [],
    };
  }

  // 3. Direct `{ evidence, payload? }` or raw ChainBreakEvidence / ContractEvidence verification
  const rawEvidence = isPlainObject(input) && 'evidence' in input ? input.evidence : input;

  const cbParsed = ChainBreakEvidenceSchema.safeParse(rawEvidence);
  if (cbParsed.success) {
    const ev = cbParsed.data;
    const leaf = computeChainBreakLeafSha256(ev);
    let recomputedContent = ev.contentSha256.toLowerCase();
    if (rawPayload !== undefined) {
      recomputedContent = computeCanonicalDigest(rawPayload);
      if (recomputedContent !== ev.contentSha256.toLowerCase()) {
        return {
          valid: false,
          code: 'DIGEST_MISMATCH',
          recordType: 'CHAINBREAK',
          evidenceId: ev.evidenceId,
          contentSha256: ev.contentSha256,
          recomputedContentSha256: recomputedContent,
          canonicalLeafSha256: leaf,
          verified: false,
          standaloneProofEligible: false,
          reasons: [
            `Payload SHA-256 mismatch: expected=${ev.contentSha256}, computed=${recomputedContent}`,
          ],
        };
      }
    }
    if (
      options.expectedContentSha256 &&
      options.expectedContentSha256.toLowerCase() !== ev.contentSha256.toLowerCase()
    ) {
      return {
        valid: false,
        code: 'DIGEST_MISMATCH',
        recordType: 'CHAINBREAK',
        evidenceId: ev.evidenceId,
        contentSha256: ev.contentSha256,
        recomputedContentSha256: recomputedContent,
        canonicalLeafSha256: leaf,
        verified: false,
        standaloneProofEligible: false,
        reasons: [
          `Expected contentSha256 (${options.expectedContentSha256}) does not match (${ev.contentSha256})`,
        ],
      };
    }

    if (ev.verified && isPlaceholderSourceRef(ev.sourceRef)) {
      return {
        valid: false,
        code: 'MISSING_PROVENANCE',
        recordType: 'CHAINBREAK',
        evidenceId: ev.evidenceId,
        contentSha256: ev.contentSha256,
        recomputedContentSha256: recomputedContent,
        canonicalLeafSha256: leaf,
        verified: false,
        standaloneProofEligible: false,
        reasons: ['Verified ChainBreakEvidence requires non-empty sourceRef'],
      };
    }

    const eligible = ev.verified === true && !isPlaceholderSourceRef(ev.sourceRef);
    if (options.requireVerifiedProof && !eligible) {
      return {
        valid: false,
        code: 'UNVERIFIED_PROOF',
        recordType: 'CHAINBREAK',
        evidenceId: ev.evidenceId,
        contentSha256: ev.contentSha256,
        recomputedContentSha256: recomputedContent,
        canonicalLeafSha256: leaf,
        verified: ev.verified,
        standaloneProofEligible: false,
        reasons: ['ChainBreakEvidence verified flag is false'],
      };
    }

    return {
      valid: true,
      code: 'VERIFIED',
      recordType: 'CHAINBREAK',
      evidenceId: ev.evidenceId,
      contentSha256: ev.contentSha256,
      recomputedContentSha256: recomputedContent,
      canonicalLeafSha256: leaf,
      verified: ev.verified,
      standaloneProofEligible: eligible,
      reasons: [],
    };
  }

  const contractParsed = ContractEvidenceSchema.safeParse(rawEvidence);
  if (contractParsed.success) {
    const ev = contractParsed.data;
    const leaf = hashEvidence(ev).toLowerCase();
    if (options.verifyChainHash && ev.reproducer_artifact?.script_sha256) {
      const expectedChainHash = computeEvidenceChainHash({
        finding_id: ev.finding_id,
        verifier_agent_id: ev.verifier_agent_id,
        status: ev.status,
        script_sha256: ev.reproducer_artifact.script_sha256,
        recorded_at: ev.recorded_at,
      });
      if (expectedChainHash !== ev.chain_hash.toLowerCase()) {
        return {
          valid: false,
          code: 'DIGEST_MISMATCH',
          recordType: 'CONTRACT',
          evidenceId: ev.evidence_id,
          contentSha256: leaf,
          recomputedContentSha256: leaf,
          canonicalLeafSha256: leaf,
          verified: false,
          standaloneProofEligible: false,
          reasons: [
            `Contract Evidence chain_hash mismatch: stored=${ev.chain_hash}, computed=${expectedChainHash}`,
          ],
        };
      }
    }

    const verified =
      ev.status === 'VERIFIED_TRUE_POSITIVE' ||
      ev.status === 'REFUTED_FALSE_POSITIVE';
    if (options.requireVerifiedProof && !verified) {
      return {
        valid: false,
        code: 'UNVERIFIED_PROOF',
        recordType: 'CONTRACT',
        evidenceId: ev.evidence_id,
        contentSha256: leaf,
        recomputedContentSha256: leaf,
        canonicalLeafSha256: leaf,
        verified: false,
        standaloneProofEligible: false,
        reasons: [`Contract Evidence status '${ev.status}' is not verified`],
      };
    }

    return {
      valid: true,
      code: 'VERIFIED',
      recordType: 'CONTRACT',
      evidenceId: ev.evidence_id,
      contentSha256: leaf,
      recomputedContentSha256: leaf,
      canonicalLeafSha256: leaf,
      verified,
      standaloneProofEligible: verified,
      reasons: [],
    };
  }

  return {
    valid: false,
    code: 'SCHEMA_INVALID',
    verified: false,
    standaloneProofEligible: false,
    reasons: ['Input does not conform to EvidenceReceipt, ChainBreakEvidence, or Contract Evidence'],
  };
}

// ============================================================================
// 3. ANALYSIS BINARY MERKLE BUNDLE BUILDER & VERIFIER
// ============================================================================

export interface BuildAnalysisMerkleBundleParams {
  tenantId: string;
  analysisId: string;
  receipts: EvidenceReceipt[];
  crossLinks?: EvidenceCrossLink[];
  generatedAt?: string;
}

function buildBundleDigestInput(bundle: {
  schemaVersion: 'evidence.merkle.bundle.v1';
  bundleId: string;
  tenantId: string;
  analysisId: string;
  merkleRoot: string;
  leafCount: number;
  leaves: string[];
  entries: MerkleInclusionEntry[];
  crossLinks: EvidenceCrossLink[];
  generatedAt: string;
}): Record<string, unknown> {
  return {
    schemaVersion: bundle.schemaVersion,
    bundleId: bundle.bundleId,
    tenantId: bundle.tenantId,
    analysisId: bundle.analysisId,
    merkleRoot: bundle.merkleRoot,
    leafCount: bundle.leafCount,
    leaves: bundle.leaves,
    entries: bundle.entries,
    crossLinks: bundle.crossLinks,
    generatedAt: bundle.generatedAt,
  };
}

/**
 * Computes deterministic RFC 8785 leaves, binary Merkle root, and logarithmic
 * inclusion proofs across every verified receipt belonging to `(tenantId, analysisId)`.
 */
export function buildAnalysisMerkleBundle(
  params: BuildAnalysisMerkleBundleParams
): AnalysisMerkleBundle {
  const tenantId = NonEmptyTenantIdSchema.parse(params.tenantId);
  const analysisId = NonEmptyAnalysisIdSchema.parse(params.analysisId);

  for (const rcpt of params.receipts) {
    if (rcpt.tenantId !== tenantId) {
      throw new EvidenceLedgerError(
        'TENANT_ISOLATION_VIOLATION',
        `Receipt '${rcpt.evidenceId}' tenantId '${rcpt.tenantId}' mismatches bundle tenantId '${tenantId}'`
      );
    }
    if (rcpt.analysisId !== analysisId) {
      throw new EvidenceLedgerError(
        'VALIDATION_ERROR',
        `Receipt '${rcpt.evidenceId}' analysisId '${rcpt.analysisId}' mismatches '${analysisId}'`
      );
    }
    const check = verifyEvidenceReceipt(rcpt);
    if (!check.valid) {
      throw new EvidenceIntegrityError(
        'RECEIPT_VERIFICATION_FAILED',
        `Receipt '${rcpt.evidenceId}' failed integrity check: ${check.reasons.join('; ')}`
      );
    }
  }

  const sortedReceipts = [...params.receipts].sort((a, b) => {
    const cmpTime = a.recordedAt.localeCompare(b.recordedAt);
    if (cmpTime !== 0) return cmpTime;
    const cmpType = a.recordType.localeCompare(b.recordType);
    if (cmpType !== 0) return cmpType;
    return a.evidenceId.localeCompare(b.evidenceId);
  });

  const sortedLinks = [...(params.crossLinks ?? [])].sort((a, b) =>
    a.linkId.localeCompare(b.linkId)
  );
  for (const link of sortedLinks) {
    if (link.tenantId !== tenantId) {
      throw new EvidenceLedgerError(
        'TENANT_ISOLATION_VIOLATION',
        `Cross-link '${link.linkId}' tenantId mismatches '${tenantId}'`
      );
    }
  }

  const leaves = sortedReceipts.map((r) => r.receiptSha256.toLowerCase());
  const merkleRoot = computeMerkleRoot(leaves);
  const entries: MerkleInclusionEntry[] = sortedReceipts.map((receipt, idx) => ({
    leafIndex: idx,
    evidenceId: receipt.evidenceId,
    recordType: receipt.recordType,
    kind: receipt.kind,
    leafHash: leaves[idx],
    canonicalLeafSha256: receipt.canonicalLeafSha256,
    contentSha256: receipt.contentSha256,
    proof: generateMerkleProof(leaves, idx),
    receipt,
  }));

  const generatedAt =
    params.generatedAt ??
    sortedReceipts[sortedReceipts.length - 1]?.recordedAt ??
    new Date().toISOString();

  const bundleId = `merkle-${sha256(
    canonicalStringify({
      tenantId,
      analysisId,
      merkleRoot,
      leafCount: leaves.length,
    })
  ).slice(0, 16)}`;

  const bundleCore = {
    schemaVersion: 'evidence.merkle.bundle.v1' as const,
    bundleId,
    tenantId,
    analysisId,
    merkleRoot,
    leafCount: leaves.length,
    leaves,
    entries,
    crossLinks: sortedLinks,
    generatedAt,
  };

  const bundleSha256 = computeCanonicalDigest(buildBundleDigestInput(bundleCore));

  return {
    ...bundleCore,
    bundleSha256,
  };
}

/**
 * Verifies an AnalysisMerkleBundle end-to-end:
 * 1. Bundle schema & RFC 8785 bundleSha256 seal
 * 2. Every leaf receipt digest & anti-AI-prose check
 * 3. Every leaf's logarithmic Merkle inclusion proof against `merkleRoot`
 * 4. Recomputed binary Merkle root matching `bundle.merkleRoot`
 */
export function verifyAnalysisMerkleBundle(
  bundleInput: unknown,
  options: VerifyEvidenceReceiptOptions = {}
): MerkleBundleVerificationResult {
  const parsed = AnalysisMerkleBundleSchema.safeParse(bundleInput);
  if (!parsed.success) {
    return {
      valid: false,
      merkleRoot: '',
      recomputedMerkleRoot: '',
      leafCount: 0,
      verifiedCount: 0,
      failedEvidenceIds: [],
      errors: parsed.error.errors.map(
        (e) => `${e.path.join('.') || 'bundle'}: ${e.message}`
      ),
    };
  }

  const bundle = parsed.data as AnalysisMerkleBundle;
  const errors: string[] = [];
  const failedEvidenceIds: string[] = [];

  const expectedBundleSha = computeCanonicalDigest(
    buildBundleDigestInput({
      schemaVersion: bundle.schemaVersion,
      bundleId: bundle.bundleId,
      tenantId: bundle.tenantId,
      analysisId: bundle.analysisId,
      merkleRoot: bundle.merkleRoot,
      leafCount: bundle.leafCount,
      leaves: bundle.leaves,
      entries: bundle.entries,
      crossLinks: bundle.crossLinks,
      generatedAt: bundle.generatedAt,
    })
  );

  if (expectedBundleSha !== bundle.bundleSha256.toLowerCase()) {
    errors.push(
      `Bundle SHA-256 mismatch: stored=${bundle.bundleSha256}, computed=${expectedBundleSha}`
    );
  }

  if (
    bundle.leafCount !== bundle.leaves.length ||
    bundle.leafCount !== bundle.entries.length
  ) {
    errors.push(
      `Leaf count mismatch: leafCount=${bundle.leafCount}, leaves=${bundle.leaves.length}, entries=${bundle.entries.length}`
    );
  }

  let verifiedCount = 0;
  for (let i = 0; i < bundle.entries.length; i++) {
    const entry = bundle.entries[i];
    let entryOk = true;

    if (entry.leafIndex !== i) {
      errors.push(`Entry ${entry.evidenceId} leafIndex ${entry.leafIndex} !== ${i}`);
      entryOk = false;
    }
    if (entry.receipt.tenantId !== bundle.tenantId) {
      errors.push(`Entry ${entry.evidenceId} tenantId mismatches bundle`);
      entryOk = false;
    }
    if (entry.receipt.analysisId !== bundle.analysisId) {
      errors.push(`Entry ${entry.evidenceId} analysisId mismatches bundle`);
      entryOk = false;
    }

    const receiptCheck = verifyEvidenceReceipt(entry.receipt, options);
    if (!receiptCheck.valid) {
      errors.push(
        `Entry ${entry.evidenceId} failed receipt verification (${receiptCheck.code}): ${receiptCheck.reasons.join('; ')}`
      );
      entryOk = false;
    }

    if (entry.leafHash.toLowerCase() !== entry.receipt.receiptSha256.toLowerCase()) {
      errors.push(
        `Entry ${entry.evidenceId} leafHash (${entry.leafHash}) !== receiptSha256 (${entry.receipt.receiptSha256})`
      );
      entryOk = false;
    }

    if (
      i < bundle.leaves.length &&
      bundle.leaves[i].toLowerCase() !== entry.leafHash.toLowerCase()
    ) {
      errors.push(`Leaves array mismatch at index ${i}`);
      entryOk = false;
    }

    const proofValid = verifyMerkleProof(
      entry.leafHash,
      entry.proof,
      bundle.merkleRoot
    );
    if (!proofValid) {
      errors.push(`Merkle inclusion proof failed for evidence '${entry.evidenceId}' at index ${i}`);
      entryOk = false;
    }

    if (entryOk) {
      verifiedCount++;
    } else {
      failedEvidenceIds.push(entry.evidenceId);
    }
  }

  const recomputedMerkleRoot = computeMerkleRoot(bundle.leaves);
  if (recomputedMerkleRoot !== bundle.merkleRoot.toLowerCase()) {
    errors.push(
      `Merkle root mismatch: declared=${bundle.merkleRoot}, recomputed=${recomputedMerkleRoot}`
    );
  }

  return {
    valid: errors.length === 0,
    bundleId: bundle.bundleId,
    tenantId: bundle.tenantId,
    analysisId: bundle.analysisId,
    merkleRoot: bundle.merkleRoot,
    recomputedMerkleRoot,
    leafCount: bundle.leafCount,
    verifiedCount,
    failedEvidenceIds,
    errors,
  };
}
