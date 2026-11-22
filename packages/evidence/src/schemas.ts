/**
 * @file packages/evidence/src/schemas.ts
 * @description Canonical Zod schemas, error classes, and TypeScript types for
 * @script-kitty/evidence (Unified Evidence Ledger).
 */

import { z } from 'zod';
import {
  ChainBreakEvidenceKindSchema,
  ChainBreakEvidenceSchema,
  type ChainBreakEvidence,
  type ChainBreakEvidenceKind,
} from '@script-kitty/chainbreak';
import {
  EvidenceSchema as ContractEvidenceSchema,
  VerificationStatusSchema,
  type Evidence as ContractEvidence,
  type MerkleProofStep,
  type VerificationStatus,
} from '@script-kitty/contracts';

export type {
  ChainBreakEvidence,
  ChainBreakEvidenceKind,
  ContractEvidence,
  MerkleProofStep,
  VerificationStatus,
};

export {
  ChainBreakEvidenceKindSchema,
  ChainBreakEvidenceSchema,
  ContractEvidenceSchema,
  VerificationStatusSchema,
};

// ============================================================================
// 1. ERROR HIERARCHY
// ============================================================================

export type EvidenceLedgerErrorCode =
  | 'TENANT_ISOLATION_VIOLATION'
  | 'VALIDATION_ERROR'
  | 'UNVERIFIED_AI_PROSE_REJECTED'
  | 'DIGEST_MISMATCH'
  | 'RECEIPT_VERIFICATION_FAILED'
  | 'IMMUTABLE_EVIDENCE_CONFLICT'
  | 'MERKLE_PROOF_INVALID'
  | 'NOT_FOUND'
  | 'LEDGER_CLOSED';

export class EvidenceLedgerError extends Error {
  readonly code: EvidenceLedgerErrorCode;

  constructor(code: EvidenceLedgerErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'EvidenceLedgerError';
    this.code = code;
  }
}

export class TenantIsolationError extends EvidenceLedgerError {
  constructor(message: string) {
    super('TENANT_ISOLATION_VIOLATION', message);
    this.name = 'TenantIsolationError';
  }
}

export class UnverifiedAiProseError extends EvidenceLedgerError {
  constructor(message: string) {
    super('UNVERIFIED_AI_PROSE_REJECTED', message);
    this.name = 'UnverifiedAiProseError';
  }
}

export class EvidenceIntegrityError extends EvidenceLedgerError {
  constructor(
    code:
      | 'DIGEST_MISMATCH'
      | 'RECEIPT_VERIFICATION_FAILED'
      | 'IMMUTABLE_EVIDENCE_CONFLICT'
      | 'MERKLE_PROOF_INVALID',
    message: string
  ) {
    super(code, message);
    this.name = 'EvidenceIntegrityError';
  }
}

// ============================================================================
// 2. COMMON VALIDATION SCHEMAS
// ============================================================================

export const NonEmptyTenantIdSchema = z
  .string()
  .trim()
  .min(1, 'tenantId is required')
  .max(128, 'tenantId is too long');

export const NonEmptyAnalysisIdSchema = z
  .string()
  .trim()
  .min(1, 'analysisId is required')
  .max(200, 'analysisId is too long');

export const Sha256HexSchema = z
  .string()
  .regex(/^[a-f0-9]{64}$/i, 'Must be a 64-character hex SHA-256 digest');

export const EvidenceRecordTypeSchema = z.enum(['CHAINBREAK', 'CONTRACT']);
export type EvidenceRecordType = z.infer<typeof EvidenceRecordTypeSchema>;

export const UnifiedEvidenceKindSchema = z.enum([
  'POLICY_SNAPSHOT',
  'GRAPH_PATH',
  'TEST_RESULT',
  'QUALITY_RESULT',
  'VERIFIED_TRUE_POSITIVE',
  'REFUTED_FALSE_POSITIVE',
  'INCONCLUSIVE',
  'EXECUTION_ERROR',
]);
export type UnifiedEvidenceKind = z.infer<typeof UnifiedEvidenceKindSchema>;

export const CrossLinkRelationTypeSchema = z.enum([
  'REPRODUCES_PATH',
  'VERIFIES_FINDING',
  'REFUTES_FINDING',
  'POST_PATCH_RECHECK',
  'SUPPORTS_ANALYSIS',
]);
export type CrossLinkRelationType = z.infer<typeof CrossLinkRelationTypeSchema>;

export const MerkleProofStepSchema = z.object({
  position: z.enum(['left', 'right']),
  hash: Sha256HexSchema,
});

// ============================================================================
// 3. RECEIPT, CROSS-LINK & MERKLE BUNDLE SCHEMAS
// ============================================================================

export const EvidenceReceiptSchema = z
  .object({
    schemaVersion: z.literal('evidence.receipt.v1').default('evidence.receipt.v1'),
    receiptId: z.string().min(1),
    recordType: EvidenceRecordTypeSchema,
    tenantId: NonEmptyTenantIdSchema,
    analysisId: NonEmptyAnalysisIdSchema,
    evidenceId: z.string().min(1),
    findingId: z.string().min(1).optional(),
    pathId: z.string().min(1).optional(),
    kind: UnifiedEvidenceKindSchema,
    sourceRef: z.string(),
    producer: z.string().min(1),
    verified: z.boolean(),
    standaloneProofEligible: z.boolean(),
    contentSha256: Sha256HexSchema,
    canonicalLeafSha256: Sha256HexSchema,
    payloadSha256: Sha256HexSchema.optional(),
    receiptSha256: Sha256HexSchema,
    commitSha: z.string().regex(/^[a-f0-9]{7,64}$/i).optional(),
    createdAt: z.string().datetime(),
    recordedAt: z.string().datetime(),
    evidence: z.unknown(),
  })
  .superRefine((data, ctx) => {
    if (data.recordType === 'CHAINBREAK') {
      const parsed = ChainBreakEvidenceSchema.safeParse(data.evidence);
      if (!parsed.success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['evidence'],
          message: `Invalid ChainBreakEvidence payload: ${parsed.error.errors.map((e) => e.message).join('; ')}`,
        });
      }
    } else {
      const parsed = ContractEvidenceSchema.safeParse(data.evidence);
      if (!parsed.success) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['evidence'],
          message: `Invalid Contract Evidence payload: ${parsed.error.errors.map((e) => e.message).join('; ')}`,
        });
      }
    }
  });

export type EvidenceReceipt = Omit<z.infer<typeof EvidenceReceiptSchema>, 'evidence'> & {
  evidence: ChainBreakEvidence | ContractEvidence;
};

export const EvidenceCrossLinkSchema = z.object({
  linkId: z.string().min(1),
  tenantId: NonEmptyTenantIdSchema,
  analysisId: NonEmptyAnalysisIdSchema,
  chainBreakEvidenceId: z.string().min(1),
  contractEvidenceId: z.string().min(1),
  findingId: z.string().min(1),
  pathId: z.string().min(1).optional(),
  relationType: CrossLinkRelationTypeSchema,
  createdAt: z.string().datetime(),
});
export type EvidenceCrossLink = z.infer<typeof EvidenceCrossLinkSchema>;

export const MerkleInclusionEntrySchema = z.object({
  leafIndex: z.number().int().nonnegative(),
  evidenceId: z.string().min(1),
  recordType: EvidenceRecordTypeSchema,
  kind: UnifiedEvidenceKindSchema,
  leafHash: Sha256HexSchema,
  canonicalLeafSha256: Sha256HexSchema,
  contentSha256: Sha256HexSchema,
  proof: z.array(MerkleProofStepSchema),
  receipt: EvidenceReceiptSchema,
});
export type MerkleInclusionEntry = Omit<
  z.infer<typeof MerkleInclusionEntrySchema>,
  'receipt'
> & {
  receipt: EvidenceReceipt;
};

export const AnalysisMerkleBundleSchema = z.object({
  schemaVersion: z.literal('evidence.merkle.bundle.v1'),
  bundleId: z.string().min(1),
  tenantId: NonEmptyTenantIdSchema,
  analysisId: NonEmptyAnalysisIdSchema,
  merkleRoot: Sha256HexSchema,
  leafCount: z.number().int().nonnegative(),
  leaves: z.array(Sha256HexSchema),
  entries: z.array(MerkleInclusionEntrySchema),
  crossLinks: z.array(EvidenceCrossLinkSchema),
  bundleSha256: Sha256HexSchema,
  generatedAt: z.string().datetime(),
});
export type AnalysisMerkleBundle = Omit<
  z.infer<typeof AnalysisMerkleBundleSchema>,
  'entries'
> & {
  entries: MerkleInclusionEntry[];
};

export type ReceiptVerificationErrorCode =
  | 'VERIFIED'
  | 'SCHEMA_INVALID'
  | 'UNVERIFIED_AI_PROSE_REJECTED'
  | 'DIGEST_MISMATCH'
  | 'MISSING_PROVENANCE'
  | 'UNVERIFIED_PROOF';

export interface ReceiptVerificationResult {
  valid: boolean;
  code: ReceiptVerificationErrorCode;
  recordType?: EvidenceRecordType;
  evidenceId?: string;
  contentSha256?: string;
  recomputedContentSha256?: string;
  canonicalLeafSha256?: string;
  receiptSha256?: string;
  verified: boolean;
  standaloneProofEligible: boolean;
  reasons: string[];
}

export interface MerkleBundleVerificationResult {
  valid: boolean;
  bundleId?: string;
  tenantId?: string;
  analysisId?: string;
  merkleRoot: string;
  recomputedMerkleRoot: string;
  leafCount: number;
  verifiedCount: number;
  failedEvidenceIds: string[];
  errors: string[];
}
