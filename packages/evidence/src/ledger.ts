/**
 * @file packages/evidence/src/ledger.ts
 * @description Unified `EvidenceLedger` backed by Node 22 `node:sqlite` (`:memory:` or file path)
 * enforcing strict `tenantId` isolation (`TenantIsolationError`), RFC 8785 canonical receipts,
 * cross-linking between ChainBreak `ChainBreakEvidence` and `@script-kitty/contracts` `Evidence`,
 * rejection of unverified AI prose as standalone proof, and binary Merkle bundle generation.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { ChainBreakEvidenceSchema } from '@script-kitty/chainbreak';
import { EvidenceSchema as ContractEvidenceSchema } from '@script-kitty/contracts';
import {
  assertNotUnverifiedAiProse,
  buildAnalysisMerkleBundle,
  canonicalStringify,
  createEvidenceReceipt,
  sha256,
  verifyAnalysisMerkleBundle,
  verifyEvidenceReceipt,
  type VerifyEvidenceReceiptOptions,
} from './crypto.js';
import {
  CrossLinkRelationTypeSchema,
  EvidenceIntegrityError,
  EvidenceLedgerError,
  NonEmptyAnalysisIdSchema,
  NonEmptyTenantIdSchema,
  TenantIsolationError,
  type AnalysisMerkleBundle,
  type CrossLinkRelationType,
  type EvidenceCrossLink,
  type EvidenceReceipt,
  type MerkleBundleVerificationResult,
  type ReceiptVerificationResult,
} from './schemas.js';

export interface EvidenceLedgerOptions {
  dbPath?: string;
  now?: () => string;
}

export interface RecordChainBreakEvidenceOptions {
  payload?: unknown;
  pathId?: string;
  recordedAt?: string;
  requireVerified?: boolean;
}

export interface RecordContractEvidenceOptions {
  analysisId?: string;
  tenantId?: string;
  payload?: unknown;
  pathId?: string;
  sourceRef?: string;
  recordedAt?: string;
  verifyChainHash?: boolean;
  linkedChainBreakEvidenceIds?: string[];
  relationType?: CrossLinkRelationType;
}

export interface LinkEvidenceParams {
  analysisId: string;
  chainBreakEvidenceId: string;
  contractEvidenceId: string;
  pathId?: string;
  relationType?: CrossLinkRelationType;
  createdAt?: string;
}

export interface EvidenceWithLinks {
  receipt: EvidenceReceipt;
  links: EvidenceCrossLink[];
  linkedReceipts: EvidenceReceipt[];
}

export interface PaginationOptions {
  limit?: number;
  offset?: number;
}

type CachedStatement = ReturnType<DatabaseSync['prepare']>;

const MAX_PREPARED_STATEMENTS = 256;
const SQLITE_IN_CLAUSE_CHUNK_SIZE = 500;
const SQLITE_MAX_TX_RETRIES = 5;

function isSqliteBusyOrLocked(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const msg = String((error as { message?: unknown }).message ?? '');
  const code = String((error as { code?: unknown }).code ?? '');
  return (
    /(SQLITE_BUSY|SQLITE_LOCKED|database is locked|database table is locked)/i.test(
      msg
    ) || /(SQLITE_BUSY|SQLITE_LOCKED)/i.test(code)
  );
}

function pauseSyncMs(ms: number): void {
  if (ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    // Fallback if SharedArrayBuffer/Atomics.wait is unavailable
  }
}

function assertValidAuthTenantId(authTenantId: string): string {
  const parsed = NonEmptyTenantIdSchema.safeParse(authTenantId);
  if (!parsed.success) {
    throw new TenantIsolationError(
      'Authenticated tenantId is missing or invalid'
    );
  }
  return parsed.data;
}

export class EvidenceLedger {
  private readonly db: DatabaseSync;
  private readonly nowFn: () => string;
  private readonly stmtCache = new Map<string, CachedStatement>();
  private closed = false;

  constructor(options: EvidenceLedgerOptions = {}) {
    const dbPath = options.dbPath ?? ':memory:';
    if (dbPath !== ':memory:') {
      const dir = path.dirname(path.resolve(dbPath));
      fs.mkdirSync(dir, { recursive: true });
    }
    this.nowFn = options.now ?? (() => new Date().toISOString());
    this.db = new DatabaseSync(dbPath, {
      enableForeignKeyConstraints: true,
    });
    this.initializeSchema();
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new EvidenceLedgerError(
        'LEDGER_CLOSED',
        'EvidenceLedger has been closed'
      );
    }
  }

  private prepareStmt(sql: string): CachedStatement {
    this.assertOpen();
    let stmt = this.stmtCache.get(sql);
    if (!stmt) {
      if (this.stmtCache.size >= MAX_PREPARED_STATEMENTS) {
        const oldestSql = this.stmtCache.keys().next().value;
        if (oldestSql !== undefined) {
          this.stmtCache.delete(oldestSql);
        }
      }
      stmt = this.db.prepare(sql);
      this.stmtCache.set(sql, stmt);
    }
    return stmt;
  }

  private initializeSchema(): void {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA synchronous = NORMAL;
      PRAGMA foreign_keys = ON;
      PRAGMA temp_store = MEMORY;
      PRAGMA cache_size = -16000;
      PRAGMA wal_autocheckpoint = 1000;

      CREATE TABLE IF NOT EXISTS evidence_receipts (
        evidence_id TEXT PRIMARY KEY,
        receipt_id TEXT NOT NULL UNIQUE,
        tenant_id TEXT NOT NULL,
        analysis_id TEXT NOT NULL,
        record_type TEXT NOT NULL,
        finding_id TEXT,
        path_id TEXT,
        kind TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        producer TEXT NOT NULL,
        verified INTEGER NOT NULL,
        standalone_proof_eligible INTEGER NOT NULL,
        content_sha256 TEXT NOT NULL,
        canonical_leaf_sha256 TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        receipt_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_receipts_tenant_analysis
        ON evidence_receipts (tenant_id, analysis_id, recorded_at);
      CREATE INDEX IF NOT EXISTS idx_receipts_analysis_tenant
        ON evidence_receipts (analysis_id, tenant_id);
      CREATE INDEX IF NOT EXISTS idx_receipts_tenant_finding
        ON evidence_receipts (tenant_id, finding_id);

      CREATE TABLE IF NOT EXISTS evidence_cross_links (
        link_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        analysis_id TEXT NOT NULL,
        chainbreak_evidence_id TEXT NOT NULL,
        contract_evidence_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        path_id TEXT,
        relation_type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        link_json TEXT NOT NULL,
        UNIQUE (tenant_id, chainbreak_evidence_id, contract_evidence_id, relation_type),
        FOREIGN KEY (chainbreak_evidence_id) REFERENCES evidence_receipts (evidence_id),
        FOREIGN KEY (contract_evidence_id) REFERENCES evidence_receipts (evidence_id)
      );
      CREATE INDEX IF NOT EXISTS idx_links_tenant_analysis
        ON evidence_cross_links (tenant_id, analysis_id);
      CREATE INDEX IF NOT EXISTS idx_links_cb_id
        ON evidence_cross_links (tenant_id, chainbreak_evidence_id);
      CREATE INDEX IF NOT EXISTS idx_links_contract_id
        ON evidence_cross_links (tenant_id, contract_evidence_id);
    `);
  }

  private runInTransaction<T>(fn: () => T): T {
    this.assertOpen();
    for (let attempt = 1; attempt <= SQLITE_MAX_TX_RETRIES; attempt += 1) {
      let begun = false;
      try {
        this.db.exec('BEGIN IMMEDIATE');
        begun = true;
        const result = fn();
        this.db.exec('COMMIT');
        return result;
      } catch (error) {
        if (begun) {
          try {
            this.db.exec('ROLLBACK');
          } catch {
            // Ignore rollback failure when connection is closing
          }
        }
        if (attempt < SQLITE_MAX_TX_RETRIES && isSqliteBusyOrLocked(error)) {
          pauseSyncMs(attempt * 5);
          continue;
        }
        throw error;
      }
    }
    throw new EvidenceLedgerError(
      'VALIDATION_ERROR',
      'Transaction exceeded SQLite busy retry budget'
    );
  }

  private assertEvidenceOwnership(evidenceId: string, authTenantId: string): void {
    const row = this.prepareStmt(
      'SELECT tenant_id FROM evidence_receipts WHERE evidence_id = ?'
    ).get(evidenceId) as { tenant_id?: string } | undefined;
    if (row && row.tenant_id !== authTenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for evidenceId '${evidenceId}'`
      );
    }
  }

  private assertAnalysisOwnership(analysisId: string, authTenantId: string): void {
    const row = this.prepareStmt(
      'SELECT tenant_id FROM evidence_receipts WHERE analysis_id = ? LIMIT 1'
    ).get(analysisId) as { tenant_id?: string } | undefined;
    if (row && row.tenant_id !== authTenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for analysisId '${analysisId}'`
      );
    }
  }

  private persistReceiptInternal(receipt: EvidenceReceipt): EvidenceReceipt {
    this.assertEvidenceOwnership(receipt.evidenceId, receipt.tenantId);
    this.assertAnalysisOwnership(receipt.analysisId, receipt.tenantId);

    const existing = this.prepareStmt(
      'SELECT receipt_sha256, receipt_json FROM evidence_receipts WHERE tenant_id = ? AND evidence_id = ?'
    ).get(receipt.tenantId, receipt.evidenceId) as
      | { receipt_sha256: string; receipt_json: string }
      | undefined;

    if (existing) {
      if (existing.receipt_sha256 === receipt.receiptSha256) {
        return JSON.parse(existing.receipt_json) as EvidenceReceipt;
      }
      throw new EvidenceIntegrityError(
        'IMMUTABLE_EVIDENCE_CONFLICT',
        `Evidence '${receipt.evidenceId}' already exists with a different cryptographic receipt digest`
      );
    }

    this.prepareStmt(
      `INSERT INTO evidence_receipts (
        evidence_id, receipt_id, tenant_id, analysis_id, record_type,
        finding_id, path_id, kind, source_ref, producer, verified,
        standalone_proof_eligible, content_sha256, canonical_leaf_sha256,
        receipt_sha256, created_at, recorded_at, receipt_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      receipt.evidenceId,
      receipt.receiptId,
      receipt.tenantId,
      receipt.analysisId,
      receipt.recordType,
      receipt.findingId ?? null,
      receipt.pathId ?? null,
      receipt.kind,
      receipt.sourceRef,
      receipt.producer,
      receipt.verified ? 1 : 0,
      receipt.standaloneProofEligible ? 1 : 0,
      receipt.contentSha256,
      receipt.canonicalLeafSha256,
      receipt.receiptSha256,
      receipt.createdAt,
      receipt.recordedAt,
      canonicalStringify(receipt)
    );

    return receipt;
  }

  /**
   * Records a ChainBreak `ChainBreakEvidence` item (`POLICY_SNAPSHOT`, `GRAPH_PATH`,
   * `TEST_RESULT`, `QUALITY_RESULT`) with RFC 8785 digest verification and tenant isolation.
   */
  recordChainBreakEvidence(
    authTenantId: string,
    evidenceInput: unknown,
    options: RecordChainBreakEvidenceOptions = {}
  ): EvidenceReceipt {
    const tenantId = assertValidAuthTenantId(authTenantId);
    assertNotUnverifiedAiProse(evidenceInput, options.payload);

    const parsed = ChainBreakEvidenceSchema.safeParse(evidenceInput);
    if (!parsed.success) {
      throw new EvidenceLedgerError(
        'VALIDATION_ERROR',
        `Invalid ChainBreakEvidence: ${parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ')}`
      );
    }
    if (options.requireVerified && !parsed.data.verified) {
      throw new EvidenceLedgerError(
        'VALIDATION_ERROR',
        `ChainBreakEvidence '${parsed.data.evidenceId}' is not verified`
      );
    }

    const receipt = createEvidenceReceipt({
      tenantId,
      analysisId: parsed.data.analysisId,
      evidence: parsed.data,
      payload: options.payload,
      pathId: options.pathId,
      recordedAt: options.recordedAt ?? parsed.data.createdAt,
    });

    return this.runInTransaction(() => this.persistReceiptInternal(receipt));
  }

  /**
   * Records a canonical `@script-kitty/contracts` `Evidence` item
   * (`VERIFIED_TRUE_POSITIVE`, `REFUTED_FALSE_POSITIVE`, `INCONCLUSIVE`, `EXECUTION_ERROR`)
   * and optionally cross-links it to existing ChainBreak evidence IDs.
   */
  recordContractEvidence(
    authTenantId: string,
    evidenceInput: unknown,
    options: RecordContractEvidenceOptions = {}
  ): EvidenceReceipt {
    const tenantId = assertValidAuthTenantId(authTenantId);
    if (options.tenantId !== undefined && options.tenantId !== tenantId) {
      throw new TenantIsolationError(
        `Provided tenantId '${options.tenantId}' does not match authenticated tenantId '${tenantId}'`
      );
    }

    assertNotUnverifiedAiProse(evidenceInput, options.payload);

    const parsed = ContractEvidenceSchema.safeParse(evidenceInput);
    if (!parsed.success) {
      throw new EvidenceLedgerError(
        'VALIDATION_ERROR',
        `Invalid Contract Evidence: ${parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ')}`
      );
    }

    const receipt = createEvidenceReceipt({
      tenantId,
      analysisId: options.analysisId ?? parsed.data.finding_id,
      evidence: parsed.data,
      payload: options.payload,
      pathId: options.pathId,
      sourceRef: options.sourceRef,
      recordedAt: options.recordedAt ?? parsed.data.recorded_at,
      verifyChainHash: options.verifyChainHash,
    });

    return this.runInTransaction(() => {
      const stored = this.persistReceiptInternal(receipt);
      if (
        options.linkedChainBreakEvidenceIds &&
        options.linkedChainBreakEvidenceIds.length > 0
      ) {
        this.linkMultipleEvidenceInternal(tenantId, {
          analysisId: stored.analysisId,
          chainBreakEvidenceIds: options.linkedChainBreakEvidenceIds,
          contractEvidenceId: stored.evidenceId,
          pathId: options.pathId,
          relationType:
            options.relationType ??
            (parsed.data.status === 'REFUTED_FALSE_POSITIVE'
              ? 'REFUTES_FINDING'
              : 'VERIFIES_FINDING'),
          createdAt: stored.recordedAt,
        });
      }
      return stored;
    });
  }

  /**
   * Unified ingestion helper that auto-detects ChainBreak vs Contract Evidence
   * and rejects unverified AI-generated prose as standalone proof.
   */
  recordEvidence(
    authTenantId: string,
    evidenceInput: unknown,
    options: RecordChainBreakEvidenceOptions & RecordContractEvidenceOptions = {}
  ): EvidenceReceipt {
    assertNotUnverifiedAiProse(evidenceInput, options.payload);

    if (ChainBreakEvidenceSchema.safeParse(evidenceInput).success) {
      return this.recordChainBreakEvidence(authTenantId, evidenceInput, options);
    }
    if (ContractEvidenceSchema.safeParse(evidenceInput).success) {
      return this.recordContractEvidence(authTenantId, evidenceInput, options);
    }
    throw new EvidenceLedgerError(
      'VALIDATION_ERROR',
      'Evidence input matches neither ChainBreakEvidence nor canonical @script-kitty/contracts Evidence'
    );
  }

  private linkMultipleEvidenceInternal(
    tenantId: string,
    params: {
      analysisId: string;
      chainBreakEvidenceIds: readonly string[];
      contractEvidenceId: string;
      pathId?: string;
      relationType?: CrossLinkRelationType;
      createdAt?: string;
    }
  ): EvidenceCrossLink[] {
    const analysisId = NonEmptyAnalysisIdSchema.parse(params.analysisId);
    const relationType = CrossLinkRelationTypeSchema.parse(
      params.relationType ?? 'VERIFIES_FINDING'
    );
    const uniqueCbIds = Array.from(new Set(params.chainBreakEvidenceIds));
    if (uniqueCbIds.length === 0) {
      return [];
    }

    this.assertAnalysisOwnership(analysisId, tenantId);

    const contractRow = this.prepareStmt(
      `SELECT tenant_id, record_type, analysis_id, finding_id, path_id
       FROM evidence_receipts
       WHERE evidence_id = ?`
    ).get(params.contractEvidenceId) as
      | {
          tenant_id: string;
          record_type: string;
          analysis_id: string;
          finding_id: string | null;
          path_id: string | null;
        }
      | undefined;

    if (!contractRow) {
      throw new EvidenceLedgerError(
        'NOT_FOUND',
        `Contract Evidence '${params.contractEvidenceId}' not found for tenant '${tenantId}'`
      );
    }
    if (contractRow.tenant_id !== tenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for evidenceId '${params.contractEvidenceId}'`
      );
    }
    if (contractRow.record_type !== 'CONTRACT') {
      throw new EvidenceLedgerError(
        'VALIDATION_ERROR',
        `Evidence '${params.contractEvidenceId}' is not a CONTRACT record`
      );
    }

    const cbRowsMap = new Map<
      string,
      {
        tenant_id: string;
        record_type: string;
        path_id: string | null;
      }
    >();
    for (let i = 0; i < uniqueCbIds.length; i += SQLITE_IN_CLAUSE_CHUNK_SIZE) {
      const chunk = uniqueCbIds.slice(i, i + SQLITE_IN_CLAUSE_CHUNK_SIZE);
      const placeholders = chunk.map(() => '?').join(', ');
      const rows = this.prepareStmt(
        `SELECT evidence_id, tenant_id, record_type, path_id
         FROM evidence_receipts
         WHERE evidence_id IN (${placeholders})`
      ).all(...chunk) as Array<{
        evidence_id: string;
        tenant_id: string;
        record_type: string;
        path_id: string | null;
      }>;
      for (const r of rows) {
        cbRowsMap.set(r.evidence_id, r);
      }
    }

    for (const cbId of uniqueCbIds) {
      const cbRow = cbRowsMap.get(cbId);
      if (cbRow && cbRow.tenant_id !== tenantId) {
        throw new TenantIsolationError(
          `Cross-tenant access denied for evidenceId '${cbId}'`
        );
      }
      if (!cbRow) {
        throw new EvidenceLedgerError(
          'NOT_FOUND',
          `ChainBreakEvidence '${cbId}' not found for tenant '${tenantId}'`
        );
      }
      if (cbRow.record_type !== 'CHAINBREAK') {
        throw new EvidenceLedgerError(
          'VALIDATION_ERROR',
          `Evidence '${cbId}' is not a CHAINBREAK record`
        );
      }
    }

    const existingLinksMap = new Map<string, EvidenceCrossLink>();
    for (let i = 0; i < uniqueCbIds.length; i += SQLITE_IN_CLAUSE_CHUNK_SIZE) {
      const chunk = uniqueCbIds.slice(i, i + SQLITE_IN_CLAUSE_CHUNK_SIZE);
      const placeholders = chunk.map(() => '?').join(', ');
      const existingRows = this.prepareStmt(
        `SELECT chainbreak_evidence_id, link_json
         FROM evidence_cross_links
         WHERE tenant_id = ?
           AND contract_evidence_id = ?
           AND relation_type = ?
           AND chainbreak_evidence_id IN (${placeholders})`
      ).all(
        tenantId,
        params.contractEvidenceId,
        relationType,
        ...chunk
      ) as Array<{ chainbreak_evidence_id: string; link_json: string }>;
      for (const er of existingRows) {
        existingLinksMap.set(
          er.chainbreak_evidence_id,
          JSON.parse(er.link_json) as EvidenceCrossLink
        );
      }
    }

    const insertStmt = this.prepareStmt(
      `INSERT INTO evidence_cross_links (
        link_id, tenant_id, analysis_id, chainbreak_evidence_id,
        contract_evidence_id, finding_id, path_id, relation_type,
        created_at, link_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const createdAt = params.createdAt ?? this.nowFn();
    const findingId = contractRow.finding_id ?? contractRow.analysis_id;
    const results: EvidenceCrossLink[] = [];

    for (const cbId of uniqueCbIds) {
      const existing = existingLinksMap.get(cbId);
      if (existing) {
        results.push(existing);
        continue;
      }
      const cbRow = cbRowsMap.get(cbId)!;
      const linkId = `xlink-${sha256(
        canonicalStringify({
          tenantId,
          analysisId,
          chainBreakEvidenceId: cbId,
          contractEvidenceId: params.contractEvidenceId,
          relationType,
        })
      ).slice(0, 16)}`;

      const resolvedPathId =
        params.pathId ?? cbRow.path_id ?? contractRow.path_id ?? undefined;
      const link: EvidenceCrossLink = {
        linkId,
        tenantId,
        analysisId,
        chainBreakEvidenceId: cbId,
        contractEvidenceId: params.contractEvidenceId,
        findingId,
        ...(resolvedPathId ? { pathId: resolvedPathId } : {}),
        relationType,
        createdAt,
      };

      insertStmt.run(
        link.linkId,
        link.tenantId,
        link.analysisId,
        link.chainBreakEvidenceId,
        link.contractEvidenceId,
        link.findingId,
        link.pathId ?? null,
        link.relationType,
        link.createdAt,
        canonicalStringify(link)
      );
      results.push(link);
    }

    return results;
  }

  private linkEvidenceInternal(
    tenantId: string,
    params: LinkEvidenceParams
  ): EvidenceCrossLink {
    const [link] = this.linkMultipleEvidenceInternal(tenantId, {
      analysisId: params.analysisId,
      chainBreakEvidenceIds: [params.chainBreakEvidenceId],
      contractEvidenceId: params.contractEvidenceId,
      pathId: params.pathId,
      relationType: params.relationType,
      createdAt: params.createdAt,
    });
    return link;
  }

  /**
   * Cross-links a ChainBreak evidence record and a canonical Contract evidence record
   * strictly within `authTenantId`.
   */
  linkEvidence(
    authTenantId: string,
    params: LinkEvidenceParams
  ): EvidenceCrossLink {
    const tenantId = assertValidAuthTenantId(authTenantId);
    return this.runInTransaction(() =>
      this.linkEvidenceInternal(tenantId, params)
    );
  }

  getReceipt(authTenantId: string, evidenceId: string): EvidenceReceipt | null {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const row = this.prepareStmt(
      'SELECT tenant_id, receipt_json FROM evidence_receipts WHERE evidence_id = ?'
    ).get(evidenceId) as
      | { tenant_id: string; receipt_json: string }
      | undefined;

    if (!row) {
      return null;
    }
    if (row.tenant_id !== tenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for evidenceId '${evidenceId}'`
      );
    }
    return JSON.parse(row.receipt_json) as EvidenceReceipt;
  }

  private getReceiptsByIds(
    tenantId: string,
    evidenceIds: readonly string[]
  ): EvidenceReceipt[] {
    if (evidenceIds.length === 0) {
      return [];
    }
    const receiptById = new Map<string, EvidenceReceipt>();
    for (let i = 0; i < evidenceIds.length; i += SQLITE_IN_CLAUSE_CHUNK_SIZE) {
      const chunk = evidenceIds.slice(i, i + SQLITE_IN_CLAUSE_CHUNK_SIZE);
      const placeholders = chunk.map(() => '?').join(', ');
      const rows = this.prepareStmt(
        `SELECT evidence_id, tenant_id, receipt_json
         FROM evidence_receipts
         WHERE evidence_id IN (${placeholders})`
      ).all(...chunk) as Array<{
        evidence_id: string;
        tenant_id: string;
        receipt_json: string;
      }>;
      for (const row of rows) {
        if (row.tenant_id !== tenantId) {
          throw new TenantIsolationError(
            `Cross-tenant access denied for evidenceId '${row.evidence_id}'`
          );
        }
        receiptById.set(
          row.evidence_id,
          JSON.parse(row.receipt_json) as EvidenceReceipt
        );
      }
    }
    const ordered: EvidenceReceipt[] = [];
    for (const id of evidenceIds) {
      const found = receiptById.get(id);
      if (found) {
        ordered.push(found);
      }
    }
    return ordered;
  }

  getReceiptOrThrow(authTenantId: string, evidenceId: string): EvidenceReceipt {
    const found = this.getReceipt(authTenantId, evidenceId);
    if (!found) {
      throw new EvidenceLedgerError(
        'NOT_FOUND',
        `Evidence '${evidenceId}' not found for tenant '${authTenantId}'`
      );
    }
    return found;
  }

  listReceipts(
    authTenantId: string,
    pagination?: PaginationOptions
  ): EvidenceReceipt[] {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    if (pagination?.limit !== undefined) {
      const limit = Math.max(0, Math.floor(pagination.limit));
      const offset = Math.max(0, Math.floor(pagination.offset ?? 0));
      const rows = this.prepareStmt(
        'SELECT receipt_json FROM evidence_receipts WHERE tenant_id = ? ORDER BY recorded_at ASC, evidence_id ASC LIMIT ? OFFSET ?'
      ).all(tenantId, limit, offset) as Array<{ receipt_json: string }>;
      return rows.map((r) => JSON.parse(r.receipt_json) as EvidenceReceipt);
    }
    const rows = this.prepareStmt(
      'SELECT receipt_json FROM evidence_receipts WHERE tenant_id = ? ORDER BY recorded_at ASC, evidence_id ASC'
    ).all(tenantId) as Array<{ receipt_json: string }>;
    return rows.map((r) => JSON.parse(r.receipt_json) as EvidenceReceipt);
  }

  getReceiptsForAnalysis(
    authTenantId: string,
    analysisId: string
  ): EvidenceReceipt[] {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    this.assertAnalysisOwnership(analysisId, tenantId);
    const rows = this.prepareStmt(
      'SELECT receipt_json FROM evidence_receipts WHERE tenant_id = ? AND analysis_id = ? ORDER BY recorded_at ASC, record_type ASC, evidence_id ASC'
    ).all(tenantId, analysisId) as Array<{ receipt_json: string }>;
    return rows.map((r) => JSON.parse(r.receipt_json) as EvidenceReceipt);
  }

  getCrossLinks(
    authTenantId: string,
    analysisId?: string
  ): EvidenceCrossLink[] {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    if (analysisId !== undefined) {
      this.assertAnalysisOwnership(analysisId, tenantId);
      const rows = this.prepareStmt(
        'SELECT link_json FROM evidence_cross_links WHERE tenant_id = ? AND analysis_id = ? ORDER BY link_id ASC'
      ).all(tenantId, analysisId) as Array<{ link_json: string }>;
      return rows.map((r) => JSON.parse(r.link_json) as EvidenceCrossLink);
    }

    const rows = this.prepareStmt(
      'SELECT link_json FROM evidence_cross_links WHERE tenant_id = ? ORDER BY link_id ASC'
    ).all(tenantId) as Array<{ link_json: string }>;
    return rows.map((r) => JSON.parse(r.link_json) as EvidenceCrossLink);
  }

  getEvidenceWithLinks(
    authTenantId: string,
    evidenceId: string
  ): EvidenceWithLinks | null {
    const receipt = this.getReceipt(authTenantId, evidenceId);
    if (!receipt) {
      return null;
    }
    const tenantId = assertValidAuthTenantId(authTenantId);
    const linkRows = this.prepareStmt(
      `SELECT link_json FROM evidence_cross_links
       WHERE tenant_id = ? AND (chainbreak_evidence_id = ? OR contract_evidence_id = ?)
       ORDER BY link_id ASC`
    ).all(tenantId, evidenceId, evidenceId) as Array<{ link_json: string }>;

    const links = linkRows.map((r) => JSON.parse(r.link_json) as EvidenceCrossLink);
    const linkedIds = new Set<string>();
    for (const l of links) {
      if (l.chainBreakEvidenceId !== evidenceId) {
        linkedIds.add(l.chainBreakEvidenceId);
      }
      if (l.contractEvidenceId !== evidenceId) {
        linkedIds.add(l.contractEvidenceId);
      }
    }

    const linkedReceipts = this.getReceiptsByIds(
      tenantId,
      Array.from(linkedIds)
    );

    return {
      receipt,
      links,
      linkedReceipts,
    };
  }

  verifyStoredReceipt(
    authTenantId: string,
    evidenceId: string,
    options: VerifyEvidenceReceiptOptions = {}
  ): ReceiptVerificationResult {
    const receipt = this.getReceiptOrThrow(authTenantId, evidenceId);
    return verifyEvidenceReceipt(receipt, options);
  }

  buildAnalysisMerkleBundle(
    authTenantId: string,
    analysisId: string,
    options: { generatedAt?: string } = {}
  ): AnalysisMerkleBundle {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const receipts = this.getReceiptsForAnalysis(tenantId, analysisId);
    const crossLinks = this.getCrossLinks(tenantId, analysisId);
    return buildAnalysisMerkleBundle({
      tenantId,
      analysisId,
      receipts,
      crossLinks,
      generatedAt: options.generatedAt,
    });
  }

  verifyAnalysisMerkleBundle(
    bundle: unknown,
    options: VerifyEvidenceReceiptOptions = {}
  ): MerkleBundleVerificationResult {
    return verifyAnalysisMerkleBundle(bundle, options);
  }

  getStorageMetrics(): {
    journalMode: string;
    busyTimeoutMs: number;
    foreignKeys: boolean;
    cachedStatements: number;
  } {
    this.assertOpen();
    const jm = this.prepareStmt('PRAGMA journal_mode').get() as {
      journal_mode: string;
    };
    const bt = this.prepareStmt('PRAGMA busy_timeout').get() as {
      timeout: number;
    };
    const fk = this.prepareStmt('PRAGMA foreign_keys').get() as {
      foreign_keys: number;
    };
    return {
      journalMode: jm.journal_mode,
      busyTimeoutMs: bt.timeout,
      foreignKeys: fk.foreign_keys === 1,
      cachedStatements: this.stmtCache.size,
    };
  }

  close(): void {
    if (!this.closed) {
      this.stmtCache.clear();
      this.db.close();
      this.closed = true;
    }
  }
}
