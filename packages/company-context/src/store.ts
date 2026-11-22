/**
 * @file packages/company-context/src/store.ts
 * @description Tenant-isolated SQLite persistence store (`CompanyBrainStore`) built on Node 22 `node:sqlite`.
 * Every read and write is strictly scoped by `authTenantId` and fails closed on cross-tenant access.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  DecisionHistoryEntrySchema,
  evaluateFactoryDeliveryEligibility,
  NonEmptyTenantIdSchema,
  PolicySnapshotRecordSchema,
  sha256,
  StoredAdjudicationResultSchema,
  StoredChainBreakEvidenceSchema,
  StoredRemediationSpecSchema,
  StoredSecurityAnalysisSchema,
  type DecisionHistoryEntry,
  type EvaluateFactoryDeliveryOptions,
  type FactoryDeliveryEligibilityResult,
  type PolicySnapshotRecord,
  type StoredAdjudicationResult,
  type StoredAnalysisContext,
  type StoredChainBreakEvidence,
  type StoredRemediationSpec,
  type StoredSecurityAnalysis,
} from './schemas.js';

export type CompanyContextErrorCode =
  | 'TENANT_ISOLATION_VIOLATION'
  | 'NOT_FOUND'
  | 'POLICY_IMMUTABLE'
  | 'VALIDATION_ERROR'
  | 'IDEMPOTENCY_CONFLICT';

export class CompanyContextError extends Error {
  readonly code: CompanyContextErrorCode;

  constructor(code: CompanyContextErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'CompanyContextError';
    this.code = code;
  }
}

export class TenantIsolationError extends CompanyContextError {
  constructor(message: string) {
    super('TENANT_ISOLATION_VIOLATION', message);
    this.name = 'TenantIsolationError';
  }
}

export interface CompanyBrainStoreOptions {
  dbPath?: string;
  now?: () => string;
}

export interface IdempotencyLookupParams {
  fixtureId: string;
  policyVersion: string;
  inputSha256: string;
}

export interface SaveAnalysisOptions {
  actorPrincipalId?: string;
  correlationId?: string;
  sourceRef?: string;
}

export interface SaveAdjudicationOptions {
  actorPrincipalId?: string;
  correlationId?: string;
  sourceRef?: string;
}

export interface SaveRemediationOptions {
  actorPrincipalId?: string;
  correlationId?: string;
  sourceRef?: string;
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

function isUniqueConstraintError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const msg = String((error as { message?: unknown }).message ?? '');
  const code = String((error as { code?: unknown }).code ?? '');
  return (
    /UNIQUE constraint failed/i.test(msg) || /SQLITE_CONSTRAINT_UNIQUE/i.test(code)
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

export interface EvaluateAndRecordDeliveryParams {
  record: unknown;
  headSha?: string;
  now?: Date | string;
  actorPrincipalId: string;
  sourceRef: string;
  correlationId?: string;
  analysisId?: string;
}

export function computeAnalysisIdempotencyKey(params: {
  tenantId: string;
  fixtureId: string;
  policyVersion: string;
  inputSha256: string;
}): string {
  return sha256({
    tenantId: params.tenantId,
    fixtureId: params.fixtureId,
    policyVersion: params.policyVersion,
    inputSha256: params.inputSha256.toLowerCase(),
  });
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

export class CompanyBrainStore {
  private readonly db: DatabaseSync;
  private readonly nowFn: () => string;
  private readonly stmtCache = new Map<string, CachedStatement>();
  private closed = false;

  constructor(options: CompanyBrainStoreOptions = {}) {
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
      throw new CompanyContextError(
        'VALIDATION_ERROR',
        'CompanyBrainStore has been closed'
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

      CREATE TABLE IF NOT EXISTS security_analyses (
        analysis_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        fixture_id TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        input_sha256 TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        status TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        UNIQUE (tenant_id, idempotency_key)
      );
      CREATE INDEX IF NOT EXISTS idx_analyses_tenant
        ON security_analyses (tenant_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_analyses_tenant_created_desc
        ON security_analyses (tenant_id, created_at DESC);

      CREATE TABLE IF NOT EXISTS chainbreak_evidence (
        evidence_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        analysis_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        verified INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_evidence_tenant_analysis
        ON chainbreak_evidence (tenant_id, analysis_id);

      CREATE TABLE IF NOT EXISTS adjudication_results (
        evaluation_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        analysis_id TEXT NOT NULL,
        status TEXT NOT NULL,
        decision_source TEXT NOT NULL,
        provider_status TEXT NOT NULL,
        escalated INTEGER NOT NULL,
        risk_recommendation TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_adjudications_tenant_analysis
        ON adjudication_results (tenant_id, analysis_id);

      CREATE TABLE IF NOT EXISTS remediation_specs (
        remediation_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        analysis_id TEXT NOT NULL,
        path_id TEXT NOT NULL,
        violated_policy_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_remediations_tenant_analysis_path
        ON remediation_specs (tenant_id, analysis_id, path_id);

      CREATE TABLE IF NOT EXISTS policy_snapshots (
        tenant_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        read_only INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, policy_id, policy_version)
      );

      CREATE TABLE IF NOT EXISTS decision_history (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        decision_id TEXT NOT NULL UNIQUE,
        tenant_id TEXT NOT NULL,
        analysis_id TEXT,
        decision_type TEXT NOT NULL,
        actor_principal_id TEXT NOT NULL,
        decision TEXT NOT NULL,
        status TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        correlation_id TEXT,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_history_tenant_analysis
        ON decision_history (tenant_id, analysis_id, seq);

      CREATE TABLE IF NOT EXISTS factory_delivery_evaluations (
        evaluation_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        analysis_id TEXT,
        commit_sha TEXT,
        eligible INTEGER NOT NULL,
        stage TEXT NOT NULL,
        block_reason TEXT,
        source_ref TEXT NOT NULL,
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_delivery_tenant
        ON factory_delivery_evaluations (tenant_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_delivery_tenant_created_desc
        ON factory_delivery_evaluations (tenant_id, created_at DESC);
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
            // Ignore rollback failure if connection is already closing
          }
        }
        if (attempt < SQLITE_MAX_TX_RETRIES && isSqliteBusyOrLocked(error)) {
          pauseSyncMs(attempt * 5);
          continue;
        }
        throw error;
      }
    }
    throw new CompanyContextError(
      'VALIDATION_ERROR',
      'Transaction exceeded SQLite busy retry budget'
    );
  }

  private assertRowOwnership(
    table: string,
    idColumn: string,
    idValue: string,
    authTenantId: string
  ): void {
    const row = this.prepareStmt(
      `SELECT tenant_id FROM ${table} WHERE ${idColumn} = ?`
    ).get(idValue) as { tenant_id?: string } | undefined;
    if (row && row.tenant_id !== authTenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for ${idColumn} '${idValue}'`
      );
    }
  }

  private assertRowsOwnership(
    table:
      | 'security_analyses'
      | 'chainbreak_evidence'
      | 'remediation_specs'
      | 'adjudication_results',
    idColumn: string,
    ids: readonly string[],
    authTenantId: string
  ): void {
    const uniqueIds = Array.from(new Set(ids.filter((id) => id.length > 0)));
    if (uniqueIds.length === 0) {
      return;
    }
    for (let i = 0; i < uniqueIds.length; i += SQLITE_IN_CLAUSE_CHUNK_SIZE) {
      const chunk = uniqueIds.slice(i, i + SQLITE_IN_CLAUSE_CHUNK_SIZE);
      const placeholders = chunk.map(() => '?').join(', ');
      const rows = this.prepareStmt(
        `SELECT ${idColumn} AS row_id, tenant_id FROM ${table} WHERE ${idColumn} IN (${placeholders})`
      ).all(...chunk) as Array<{ row_id: string; tenant_id: string }>;
      for (const row of rows) {
        if (row.tenant_id !== authTenantId) {
          throw new TenantIsolationError(
            `Cross-tenant access denied for ${idColumn} '${row.row_id}'`
          );
        }
      }
    }
  }

  private appendDecisionHistoryInternal(
    authTenantId: string,
    entry: DecisionHistoryEntry
  ): DecisionHistoryEntry & {
    decisionId: string;
    createdAt: string;
    seq: number;
  } {
    const parsed = DecisionHistoryEntrySchema.safeParse(entry);
    if (!parsed.success) {
      throw new CompanyContextError(
        'VALIDATION_ERROR',
        `Invalid decision history entry: ${parsed.error.errors.map((e) => e.message).join('; ')}`
      );
    }
    if (parsed.data.tenantId !== authTenantId) {
      throw new TenantIsolationError(
        'DecisionHistoryEntry tenantId does not match authenticated tenantId'
      );
    }
    const createdAt = parsed.data.createdAt ?? this.nowFn();
    const decisionId =
      parsed.data.decisionId ??
      `dec-${sha256({
        tenantId: authTenantId,
        decisionType: parsed.data.decisionType,
        analysisId: parsed.data.analysisId ?? null,
        decision: parsed.data.decision,
        status: parsed.data.status,
        sourceRef: parsed.data.sourceRef,
        createdAt,
        nonce: randomBytes(8).toString('hex'),
      }).slice(0, 16)}`;

    const fullEntry = {
      ...parsed.data,
      decisionId,
      createdAt,
    };

    const existing = this.prepareStmt(
      'SELECT tenant_id FROM decision_history WHERE decision_id = ?'
    ).get(decisionId) as { tenant_id?: string } | undefined;
    if (existing && existing.tenant_id !== authTenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for decisionId '${decisionId}'`
      );
    }

    const res = this.prepareStmt(
      `INSERT INTO decision_history (
        decision_id, tenant_id, analysis_id, decision_type,
        actor_principal_id, decision, status, source_ref,
        correlation_id, created_at, payload_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
        decisionId,
        authTenantId,
        fullEntry.analysisId ?? null,
        fullEntry.decisionType,
        fullEntry.actorPrincipalId,
        fullEntry.decision,
        fullEntry.status,
        fullEntry.sourceRef,
        fullEntry.correlationId ?? null,
        createdAt,
        JSON.stringify(fullEntry)
      );

    return {
      ...fullEntry,
      seq: Number(res.lastInsertRowid),
    };
  }

  /**
   * Persists a SecurityAnalysis (together with its evidence, remediationSpecs,
   * and an audit DecisionHistory entry), enforcing strict tenant isolation and idempotency.
   */
  saveAnalysis(
    authTenantId: string,
    analysisInput: unknown,
    options: SaveAnalysisOptions = {}
  ): StoredSecurityAnalysis {
    const tenantId = assertValidAuthTenantId(authTenantId);
    const parsed = StoredSecurityAnalysisSchema.safeParse(analysisInput);
    if (!parsed.success) {
      throw new CompanyContextError(
        'VALIDATION_ERROR',
        `Invalid SecurityAnalysis: ${parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ')}`
      );
    }
    const analysis = parsed.data;
    if (analysis.tenantId !== tenantId) {
      throw new TenantIsolationError(
        'SecurityAnalysis tenantId does not match authenticated tenantId'
      );
    }

    for (const ev of analysis.evidence) {
      if (ev.analysisId !== analysis.analysisId) {
        throw new CompanyContextError(
          'VALIDATION_ERROR',
          `Evidence '${ev.evidenceId}' analysisId '${ev.analysisId}' mismatches '${analysis.analysisId}'`
        );
      }
    }
    for (const spec of analysis.remediationSpecs) {
      if (spec.tenantId !== tenantId) {
        throw new TenantIsolationError(
          `RemediationSpec '${spec.remediationId}' tenantId does not match authenticated tenantId`
        );
      }
      if (spec.analysisId !== analysis.analysisId) {
        throw new CompanyContextError(
          'VALIDATION_ERROR',
          `RemediationSpec '${spec.remediationId}' analysisId mismatches '${analysis.analysisId}'`
        );
      }
    }

    const idempotencyKey = computeAnalysisIdempotencyKey({
      tenantId,
      fixtureId: analysis.fixtureId,
      policyVersion: analysis.policyVersion,
      inputSha256: analysis.inputSha256,
    });
    const sourceRef =
      options.sourceRef ??
      (analysis.fixtureId || `analysis:${analysis.analysisId}`);
    const now = analysis.completedAt ?? analysis.startedAt ?? this.nowFn();

    return this.runInTransaction(() => {
      // Fail closed if another tenant owns this analysisId or any nested ID
      this.assertRowOwnership(
        'security_analyses',
        'analysis_id',
        analysis.analysisId,
        tenantId
      );
      this.assertRowsOwnership(
        'chainbreak_evidence',
        'evidence_id',
        analysis.evidence.map((ev) => ev.evidenceId),
        tenantId
      );
      this.assertRowsOwnership(
        'remediation_specs',
        'remediation_id',
        analysis.remediationSpecs.map((spec) => spec.remediationId),
        tenantId
      );

      const existingByIdempotency = this.prepareStmt(
        `SELECT analysis_id, payload_json FROM security_analyses
         WHERE tenant_id = ? AND idempotency_key = ?`
      ).get(tenantId, idempotencyKey) as
        | { analysis_id: string; payload_json: string }
        | undefined;

      if (existingByIdempotency) {
        if (existingByIdempotency.analysis_id === analysis.analysisId) {
          return JSON.parse(
            existingByIdempotency.payload_json
          ) as StoredSecurityAnalysis;
        }
        throw new CompanyContextError(
          'IDEMPOTENCY_CONFLICT',
          `Analysis already exists for tenant idempotency key with analysisId '${existingByIdempotency.analysis_id}'`
        );
      }

      const existingById = this.prepareStmt(
        `SELECT payload_json FROM security_analyses WHERE tenant_id = ? AND analysis_id = ?`
      ).get(tenantId, analysis.analysisId) as
        | { payload_json: string }
        | undefined;

      if (existingById) {
        return JSON.parse(existingById.payload_json) as StoredSecurityAnalysis;
      }

      try {
        this.prepareStmt(
          `INSERT INTO security_analyses (
            analysis_id, tenant_id, fixture_id, policy_version, input_sha256,
            idempotency_key, status, source_ref, created_at, updated_at, payload_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          analysis.analysisId,
          tenantId,
          analysis.fixtureId,
          analysis.policyVersion,
          analysis.inputSha256.toLowerCase(),
          idempotencyKey,
          analysis.status,
          sourceRef,
          analysis.startedAt,
          now,
          JSON.stringify(analysis)
        );
      } catch (insertError) {
        if (isUniqueConstraintError(insertError)) {
          const racedByIdempotency = this.prepareStmt(
            `SELECT analysis_id, payload_json FROM security_analyses
             WHERE tenant_id = ? AND idempotency_key = ?`
          ).get(tenantId, idempotencyKey) as
            | { analysis_id: string; payload_json: string }
            | undefined;
          if (racedByIdempotency) {
            if (racedByIdempotency.analysis_id === analysis.analysisId) {
              return JSON.parse(
                racedByIdempotency.payload_json
              ) as StoredSecurityAnalysis;
            }
            throw new CompanyContextError(
              'IDEMPOTENCY_CONFLICT',
              `Analysis already exists for tenant idempotency key with analysisId '${racedByIdempotency.analysis_id}'`
            );
          }
          const racedById = this.prepareStmt(
            `SELECT payload_json FROM security_analyses WHERE tenant_id = ? AND analysis_id = ?`
          ).get(tenantId, analysis.analysisId) as
            | { payload_json: string }
            | undefined;
          if (racedById) {
            return JSON.parse(racedById.payload_json) as StoredSecurityAnalysis;
          }
        }
        throw insertError;
      }

      const insertEv = this.prepareStmt(
        `INSERT OR IGNORE INTO chainbreak_evidence (
          evidence_id, tenant_id, analysis_id, kind, source_ref,
          content_sha256, verified, created_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const ev of analysis.evidence) {
        insertEv.run(
          ev.evidenceId,
          tenantId,
          analysis.analysisId,
          ev.kind,
          ev.sourceRef,
          ev.contentSha256.toLowerCase(),
          ev.verified ? 1 : 0,
          ev.createdAt,
          JSON.stringify(ev)
        );
      }

      const insertSpec = this.prepareStmt(
        `INSERT OR IGNORE INTO remediation_specs (
          remediation_id, tenant_id, analysis_id, path_id,
          violated_policy_id, created_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      );
      for (const spec of analysis.remediationSpecs) {
        insertSpec.run(
          spec.remediationId,
          tenantId,
          analysis.analysisId,
          spec.pathId,
          spec.violatedPolicyId,
          spec.createdAt,
          JSON.stringify(spec)
        );
      }

      this.appendDecisionHistoryInternal(tenantId, {
        tenantId,
        analysisId: analysis.analysisId,
        decisionType: 'ANALYSIS',
        actorPrincipalId: options.actorPrincipalId ?? 'system:chainbreak',
        decision: `analysis:${analysis.status}:paths=${analysis.paths.length}`,
        status: analysis.status,
        sourceRef,
        correlationId: options.correlationId,
        evidenceIds: analysis.evidenceIds,
        metadata: {
          fixtureId: analysis.fixtureId,
          policyVersion: analysis.policyVersion,
          inputSha256: analysis.inputSha256,
        },
        createdAt: now,
      });

      return analysis;
    });
  }

  /**
   * Looks up an existing analysis for the exact tenant + fixture + policyVersion + inputSha256.
   */
  findAnalysisByIdempotency(
    authTenantId: string,
    params: IdempotencyLookupParams
  ): StoredSecurityAnalysis | null {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const key = computeAnalysisIdempotencyKey({
      tenantId,
      fixtureId: params.fixtureId,
      policyVersion: params.policyVersion,
      inputSha256: params.inputSha256,
    });
    const row = this.prepareStmt(
      `SELECT payload_json FROM security_analyses
       WHERE tenant_id = ? AND idempotency_key = ?`
    ).get(tenantId, key) as { payload_json: string } | undefined;

    return row ? (JSON.parse(row.payload_json) as StoredSecurityAnalysis) : null;
  }

  /**
   * Fetches a SecurityAnalysis strictly within `authTenantId`.
   * Fails closed with `TenantIsolationError` if the analysis belongs to another tenant.
   */
  getAnalysis(
    authTenantId: string,
    analysisId: string
  ): StoredSecurityAnalysis | null {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const row = this.prepareStmt(
      `SELECT tenant_id, payload_json FROM security_analyses WHERE analysis_id = ?`
    ).get(analysisId) as
      | { tenant_id: string; payload_json: string }
      | undefined;

    if (!row) {
      return null;
    }
    if (row.tenant_id !== tenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for analysisId '${analysisId}'`
      );
    }
    return JSON.parse(row.payload_json) as StoredSecurityAnalysis;
  }

  getAnalysisOrThrow(
    authTenantId: string,
    analysisId: string
  ): StoredSecurityAnalysis {
    const found = this.getAnalysis(authTenantId, analysisId);
    if (!found) {
      throw new CompanyContextError(
        'NOT_FOUND',
        `Analysis '${analysisId}' not found for tenant`
      );
    }
    return found;
  }

  listAnalyses(
    authTenantId: string,
    pagination?: PaginationOptions
  ): StoredSecurityAnalysis[] {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    if (pagination?.limit !== undefined) {
      const limit = Math.max(0, Math.floor(pagination.limit));
      const offset = Math.max(0, Math.floor(pagination.offset ?? 0));
      const rows = this.prepareStmt(
        `SELECT payload_json FROM security_analyses WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
      ).all(tenantId, limit, offset) as Array<{ payload_json: string }>;
      return rows.map((r) => JSON.parse(r.payload_json) as StoredSecurityAnalysis);
    }
    const rows = this.prepareStmt(
      `SELECT payload_json FROM security_analyses WHERE tenant_id = ? ORDER BY created_at DESC`
    ).all(tenantId) as Array<{ payload_json: string }>;
    return rows.map((r) => JSON.parse(r.payload_json) as StoredSecurityAnalysis);
  }

  /**
   * Persists additional ChainBreakEvidence strictly scoped to an analysis owned by `authTenantId`.
   */
  saveEvidence(
    authTenantId: string,
    evidenceList: unknown[]
  ): StoredChainBreakEvidence[] {
    const tenantId = assertValidAuthTenantId(authTenantId);
    const validated: StoredChainBreakEvidence[] = evidenceList.map((item) => {
      const parsed = StoredChainBreakEvidenceSchema.safeParse(item);
      if (!parsed.success) {
        throw new CompanyContextError(
          'VALIDATION_ERROR',
          `Invalid ChainBreakEvidence: ${parsed.error.errors.map((e) => e.message).join('; ')}`
        );
      }
      return parsed.data;
    });
    if (validated.length === 0) {
      return [];
    }

    return this.runInTransaction(() => {
      // Batch verify ownership of all evidence_id rows in 1 chunked query
      this.assertRowsOwnership(
        'chainbreak_evidence',
        'evidence_id',
        validated.map((ev) => ev.evidenceId),
        tenantId
      );

      // Batch verify existence & ownership of distinct parent analysis_id rows WITHOUT reading/parsing payload_json
      const uniqueAnalysisIds = Array.from(
        new Set(validated.map((ev) => ev.analysisId))
      );
      const analysisTenantMap = new Map<string, string>();
      for (
        let i = 0;
        i < uniqueAnalysisIds.length;
        i += SQLITE_IN_CLAUSE_CHUNK_SIZE
      ) {
        const chunk = uniqueAnalysisIds.slice(
          i,
          i + SQLITE_IN_CLAUSE_CHUNK_SIZE
        );
        const placeholders = chunk.map(() => '?').join(', ');
        const rows = this.prepareStmt(
          `SELECT analysis_id, tenant_id FROM security_analyses WHERE analysis_id IN (${placeholders})`
        ).all(...chunk) as Array<{ analysis_id: string; tenant_id: string }>;
        for (const row of rows) {
          if (row.tenant_id !== tenantId) {
            throw new TenantIsolationError(
              `Cross-tenant access denied for analysisId '${row.analysis_id}'`
            );
          }
          analysisTenantMap.set(row.analysis_id, row.tenant_id);
        }
      }
      for (const analysisId of uniqueAnalysisIds) {
        if (!analysisTenantMap.has(analysisId)) {
          throw new CompanyContextError(
            'NOT_FOUND',
            `Analysis '${analysisId}' not found for tenant`
          );
        }
      }

      const insert = this.prepareStmt(
        `INSERT OR REPLACE INTO chainbreak_evidence (
          evidence_id, tenant_id, analysis_id, kind, source_ref,
          content_sha256, verified, created_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );

      for (const ev of validated) {
        insert.run(
          ev.evidenceId,
          tenantId,
          ev.analysisId,
          ev.kind,
          ev.sourceRef,
          ev.contentSha256.toLowerCase(),
          ev.verified ? 1 : 0,
          ev.createdAt,
          JSON.stringify(ev)
        );
      }
      return validated;
    });
  }

  getEvidenceById(
    authTenantId: string,
    evidenceId: string
  ): StoredChainBreakEvidence | null {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const row = this.prepareStmt(
      `SELECT tenant_id, payload_json FROM chainbreak_evidence WHERE evidence_id = ?`
    ).get(evidenceId) as
      | { tenant_id: string; payload_json: string }
      | undefined;

    if (!row) {
      return null;
    }
    if (row.tenant_id !== tenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied for evidenceId '${evidenceId}'`
      );
    }
    return JSON.parse(row.payload_json) as StoredChainBreakEvidence;
  }

  getEvidenceForAnalysis(
    authTenantId: string,
    analysisId: string
  ): StoredChainBreakEvidence[] {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    // Reject if analysisId belongs to another tenant
    this.assertRowOwnership(
      'security_analyses',
      'analysis_id',
      analysisId,
      tenantId
    );
    const rows = this.prepareStmt(
      `SELECT payload_json FROM chainbreak_evidence
       WHERE tenant_id = ? AND analysis_id = ?
       ORDER BY created_at ASC`
    ).all(tenantId, analysisId) as Array<{ payload_json: string }>;
    return rows.map(
      (r) => JSON.parse(r.payload_json) as StoredChainBreakEvidence
    );
  }

  /**
   * Persists an AdjudicationResult scoped strictly to `authTenantId`.
   */
  saveAdjudication(
    authTenantId: string,
    adjudicationInput: unknown,
    options: SaveAdjudicationOptions = {}
  ): StoredAdjudicationResult {
    const tenantId = assertValidAuthTenantId(authTenantId);
    const parsed = StoredAdjudicationResultSchema.safeParse(adjudicationInput);
    if (!parsed.success) {
      throw new CompanyContextError(
        'VALIDATION_ERROR',
        `Invalid AdjudicationResult: ${parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ')}`
      );
    }
    const adjudication = parsed.data;
    if (adjudication.tenantId !== tenantId) {
      throw new TenantIsolationError(
        'AdjudicationResult tenantId does not match authenticated tenantId'
      );
    }

    const sourceRef =
      options.sourceRef ??
      adjudication.sourceRefs[0] ??
      `analysis:${adjudication.analysisId}`;

    return this.runInTransaction(() => {
      this.assertRowOwnership(
        'adjudication_results',
        'evaluation_id',
        adjudication.evaluationId,
        tenantId
      );
      this.assertRowOwnership(
        'security_analyses',
        'analysis_id',
        adjudication.analysisId,
        tenantId
      );

      this.prepareStmt(
        `INSERT OR REPLACE INTO adjudication_results (
          evaluation_id, tenant_id, analysis_id, status,
          decision_source, provider_status, escalated,
          risk_recommendation, source_ref, created_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
          adjudication.evaluationId,
          tenantId,
          adjudication.analysisId,
          adjudication.status,
          adjudication.decisionSource,
          adjudication.providerStatus,
          adjudication.escalated ? 1 : 0,
          adjudication.riskRecommendation,
          sourceRef,
          adjudication.timestamp,
          JSON.stringify(adjudication)
        );

      this.appendDecisionHistoryInternal(tenantId, {
        tenantId,
        analysisId: adjudication.analysisId,
        decisionType: 'ADJUDICATION',
        actorPrincipalId: options.actorPrincipalId ?? 'system:jev-judge',
        decision: adjudication.decision,
        status: adjudication.status,
        sourceRef,
        correlationId: options.correlationId,
        evidenceIds: adjudication.evidenceIds,
        metadata: {
          evaluationId: adjudication.evaluationId,
          decisionSource: adjudication.decisionSource,
          providerStatus: adjudication.providerStatus,
          escalated: adjudication.escalated,
          riskRecommendation: adjudication.riskRecommendation,
        },
        createdAt: adjudication.timestamp,
      });

      return adjudication;
    });
  }

  getAdjudicationsForAnalysis(
    authTenantId: string,
    analysisId: string
  ): StoredAdjudicationResult[] {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    this.assertRowOwnership(
      'security_analyses',
      'analysis_id',
      analysisId,
      tenantId
    );
    const rows = this.prepareStmt(
      `SELECT payload_json FROM adjudication_results
       WHERE tenant_id = ? AND analysis_id = ?
       ORDER BY created_at DESC`
    ).all(tenantId, analysisId) as Array<{ payload_json: string }>;
    return rows.map(
      (r) => JSON.parse(r.payload_json) as StoredAdjudicationResult
    );
  }

  saveRemediationSpec(
    authTenantId: string,
    specInput: unknown,
    options: SaveRemediationOptions = {}
  ): StoredRemediationSpec {
    const tenantId = assertValidAuthTenantId(authTenantId);
    const parsed = StoredRemediationSpecSchema.safeParse(specInput);
    if (!parsed.success) {
      throw new CompanyContextError(
        'VALIDATION_ERROR',
        `Invalid RemediationSpec: ${parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ')}`
      );
    }
    const spec = parsed.data;
    if (spec.tenantId !== tenantId) {
      throw new TenantIsolationError(
        'RemediationSpec tenantId does not match authenticated tenantId'
      );
    }

    const sourceRef =
      options.sourceRef ??
      (spec.actions[0] && typeof spec.actions[0].sourceRef === 'string'
        ? spec.actions[0].sourceRef
        : '') ??
      spec.fixtureId;

    return this.runInTransaction(() => {
      this.assertRowOwnership(
        'remediation_specs',
        'remediation_id',
        spec.remediationId,
        tenantId
      );
      this.getAnalysisOrThrow(tenantId, spec.analysisId);

      this.prepareStmt(
        `INSERT OR REPLACE INTO remediation_specs (
          remediation_id, tenant_id, analysis_id, path_id,
          violated_policy_id, created_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(
          spec.remediationId,
          tenantId,
          spec.analysisId,
          spec.pathId,
          spec.violatedPolicyId,
          spec.createdAt,
          JSON.stringify(spec)
        );

      this.appendDecisionHistoryInternal(tenantId, {
        tenantId,
        analysisId: spec.analysisId,
        decisionType: 'REMEDIATION_SPEC',
        actorPrincipalId:
          options.actorPrincipalId ?? 'system:remediation-spec',
        decision: `remediation:${spec.remediationId}:path=${spec.pathId}`,
        status: 'REQUIRES_HUMAN_APPROVAL',
        sourceRef: sourceRef || spec.fixtureId,
        correlationId: options.correlationId,
        evidenceIds: spec.evidenceIds,
        metadata: {
          remediationId: spec.remediationId,
          pathId: spec.pathId,
          violatedPolicyId: spec.violatedPolicyId,
          autoApplyAllowed: false,
          requiresHumanApproval: true,
        },
        createdAt: spec.createdAt,
      });

      return spec;
    });
  }

  getRemediationSpecsForAnalysis(
    authTenantId: string,
    analysisId: string
  ): StoredRemediationSpec[] {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    this.assertRowOwnership(
      'security_analyses',
      'analysis_id',
      analysisId,
      tenantId
    );
    const rows = this.prepareStmt(
      `SELECT payload_json FROM remediation_specs
       WHERE tenant_id = ? AND analysis_id = ?
       ORDER BY created_at ASC`
    ).all(tenantId, analysisId) as Array<{ payload_json: string }>;
    return rows.map(
      (r) => JSON.parse(r.payload_json) as StoredRemediationSpec
    );
  }

  getRemediationSpecForPath(
    authTenantId: string,
    analysisId: string,
    pathId: string
  ): StoredRemediationSpec | null {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    this.assertRowOwnership(
      'security_analyses',
      'analysis_id',
      analysisId,
      tenantId
    );
    const row = this.prepareStmt(
      `SELECT payload_json FROM remediation_specs
       WHERE tenant_id = ? AND analysis_id = ? AND path_id = ?`
    ).get(tenantId, analysisId, pathId) as
      | { payload_json: string }
      | undefined;

    return row
      ? (JSON.parse(row.payload_json) as StoredRemediationSpec)
      : null;
  }

  /**
   * Saves an approved, versioned, read-only policy snapshot for a tenant.
   * Rejects any attempt to silently mutate an existing policy version (`POLICY_IMMUTABLE`).
   */
  savePolicySnapshot(
    authTenantId: string,
    snapshotInput: unknown,
    options: { correlationId?: string } = {}
  ): PolicySnapshotRecord & { contentSha256: string; createdAt: string } {
    const tenantId = assertValidAuthTenantId(authTenantId);
    const parsed = PolicySnapshotRecordSchema.safeParse(snapshotInput);
    if (!parsed.success) {
      throw new CompanyContextError(
        'VALIDATION_ERROR',
        `Invalid PolicySnapshotRecord: ${parsed.error.errors.map((e) => e.message).join('; ')}`
      );
    }
    const snapshot = parsed.data;
    if (snapshot.tenantId !== tenantId) {
      throw new TenantIsolationError(
        'PolicySnapshotRecord tenantId does not match authenticated tenantId'
      );
    }

    const contentSha256 = (
      snapshot.contentSha256 ?? sha256(snapshot.rules)
    ).toLowerCase();
    const createdAt = snapshot.createdAt ?? this.nowFn();
    const record = {
      ...snapshot,
      contentSha256,
      readOnly: true as const,
      createdAt,
    };

    return this.runInTransaction(() => {
      const existing = this.prepareStmt(
        `SELECT content_sha256, payload_json FROM policy_snapshots
         WHERE tenant_id = ? AND policy_id = ? AND policy_version = ?`
      ).get(tenantId, record.policyId, record.policyVersion) as
        | { content_sha256: string; payload_json: string }
        | undefined;

      if (existing) {
        if (existing.content_sha256 === contentSha256) {
          return JSON.parse(existing.payload_json) as PolicySnapshotRecord & {
            contentSha256: string;
            createdAt: string;
          };
        }
        throw new CompanyContextError(
          'POLICY_IMMUTABLE',
          `Policy '${record.policyId}' version '${record.policyVersion}' is immutable and cannot be modified in place`
        );
      }

      this.prepareStmt(
        `INSERT INTO policy_snapshots (
          tenant_id, policy_id, policy_version, source_ref,
          content_sha256, read_only, created_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)`
      ).run(
          tenantId,
          record.policyId,
          record.policyVersion,
          record.sourceRef,
          contentSha256,
          createdAt,
          JSON.stringify(record)
        );

      this.appendDecisionHistoryInternal(tenantId, {
        tenantId,
        decisionType: 'POLICY_SNAPSHOT',
        actorPrincipalId: record.approvedBy,
        decision: `policy:${record.policyId}@${record.policyVersion}`,
        status: 'APPROVED_READ_ONLY',
        sourceRef: record.sourceRef,
        correlationId: options.correlationId,
        evidenceIds: [],
        metadata: {
          policyId: record.policyId,
          policyVersion: record.policyVersion,
          contentSha256,
          approvedAt: record.approvedAt,
        },
        createdAt,
      });

      return record;
    });
  }

  getPolicySnapshot(
    authTenantId: string,
    policyId: string,
    policyVersion: string
  ):
    | (PolicySnapshotRecord & { contentSha256: string; createdAt: string })
    | null {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const row = this.prepareStmt(
      `SELECT payload_json FROM policy_snapshots
       WHERE tenant_id = ? AND policy_id = ? AND policy_version = ?`
    ).get(tenantId, policyId, policyVersion) as
      | { payload_json: string }
      | undefined;

    return row
      ? (JSON.parse(row.payload_json) as PolicySnapshotRecord & {
          contentSha256: string;
          createdAt: string;
        })
      : null;
  }

  recordDecision(
    authTenantId: string,
    entry: DecisionHistoryEntry
  ): DecisionHistoryEntry & {
    decisionId: string;
    createdAt: string;
    seq: number;
  } {
    const tenantId = assertValidAuthTenantId(authTenantId);
    return this.runInTransaction(() => {
      if (entry.analysisId) {
        this.assertRowOwnership(
          'security_analyses',
          'analysis_id',
          entry.analysisId,
          tenantId
        );
      }
      return this.appendDecisionHistoryInternal(tenantId, entry);
    });
  }

  getDecisionHistory(
    authTenantId: string,
    analysisId?: string,
    pagination?: PaginationOptions
  ): Array<
    DecisionHistoryEntry & {
      decisionId: string;
      createdAt: string;
      seq: number;
    }
  > {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const hasLimit = pagination?.limit !== undefined;
    const limit = hasLimit ? Math.max(0, Math.floor(pagination!.limit!)) : 0;
    const offset = hasLimit ? Math.max(0, Math.floor(pagination?.offset ?? 0)) : 0;

    if (analysisId) {
      this.assertRowOwnership(
        'security_analyses',
        'analysis_id',
        analysisId,
        tenantId
      );
      const rows = (
        hasLimit
          ? this.prepareStmt(
              `SELECT seq, payload_json FROM decision_history
               WHERE tenant_id = ? AND analysis_id = ?
               ORDER BY seq ASC LIMIT ? OFFSET ?`
            ).all(tenantId, analysisId, limit, offset)
          : this.prepareStmt(
              `SELECT seq, payload_json FROM decision_history
               WHERE tenant_id = ? AND analysis_id = ?
               ORDER BY seq ASC`
            ).all(tenantId, analysisId)
      ) as Array<{
        seq: number;
        payload_json: string;
      }>;
      return rows.map((r) => ({
        ...(JSON.parse(r.payload_json) as DecisionHistoryEntry & {
          decisionId: string;
          createdAt: string;
        }),
        seq: r.seq,
      }));
    }

    const rows = (
      hasLimit
        ? this.prepareStmt(
            `SELECT seq, payload_json FROM decision_history
             WHERE tenant_id = ?
             ORDER BY seq ASC LIMIT ? OFFSET ?`
          ).all(tenantId, limit, offset)
        : this.prepareStmt(
            `SELECT seq, payload_json FROM decision_history
             WHERE tenant_id = ?
             ORDER BY seq ASC`
          ).all(tenantId)
    ) as Array<{ seq: number; payload_json: string }>;
    return rows.map((r) => ({
      ...(JSON.parse(r.payload_json) as DecisionHistoryEntry & {
        decisionId: string;
        createdAt: string;
      }),
      seq: r.seq,
    }));
  }

  /**
   * Evaluates `factory.delivery.v1` eligibility and records the tenant-scoped evaluation + audit entry.
   */
  evaluateAndRecordDeliveryEligibility(
    authTenantId: string,
    params: EvaluateAndRecordDeliveryParams
  ): FactoryDeliveryEligibilityResult & { evaluationId: string } {
    const tenantId = assertValidAuthTenantId(authTenantId);
    const options: EvaluateFactoryDeliveryOptions = {
      headSha: params.headSha,
      now: params.now,
    };
    const result = evaluateFactoryDeliveryEligibility(params.record, options);
    const evaluationId = `del-${sha256({
      tenantId,
      result,
      sourceRef: params.sourceRef,
      nonce: randomBytes(8).toString('hex'),
    }).slice(0, 16)}`;

    this.runInTransaction(() => {
      if (params.analysisId) {
        this.assertRowOwnership(
          'security_analyses',
          'analysis_id',
          params.analysisId,
          tenantId
        );
      }

      this.prepareStmt(
        `INSERT INTO factory_delivery_evaluations (
          evaluation_id, tenant_id, analysis_id, commit_sha,
          eligible, stage, block_reason, source_ref, created_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
          evaluationId,
          tenantId,
          params.analysisId ?? null,
          result.commitSha ?? null,
          result.eligible ? 1 : 0,
          result.stage,
          result.blockReason,
          params.sourceRef,
          result.checkedAt,
          JSON.stringify({ evaluationId, ...result })
        );

      this.appendDecisionHistoryInternal(tenantId, {
        tenantId,
        analysisId: params.analysisId,
        decisionType: 'DELIVERY_ELIGIBILITY',
        actorPrincipalId: params.actorPrincipalId,
        decision: result.eligible
          ? 'factory.delivery.v1:ELIGIBLE'
          : `factory.delivery.v1:BLOCKED:${result.blockReason}`,
        status: result.eligible ? 'ELIGIBLE' : 'BLOCKED',
        sourceRef: params.sourceRef,
        correlationId: params.correlationId,
        evidenceIds: [],
        metadata: {
          evaluationId,
          stage: result.stage,
          blockReason: result.blockReason,
          mergeAllowed: false,
          deployAllowed: false,
          deploymentAllowed: false,
        },
        createdAt: result.checkedAt,
      });
    });

    return { evaluationId, ...result };
  }

  getDeliveryEvaluations(
    authTenantId: string
  ): Array<FactoryDeliveryEligibilityResult & { evaluationId: string }> {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const rows = this.prepareStmt(
      `SELECT payload_json FROM factory_delivery_evaluations
       WHERE tenant_id = ? ORDER BY created_at DESC`
    ).all(tenantId) as Array<{ payload_json: string }>;
    return rows.map(
      (r) =>
        JSON.parse(r.payload_json) as FactoryDeliveryEligibilityResult & {
          evaluationId: string;
        }
    );
  }

  getAnalysisWithContext(
    authTenantId: string,
    analysisId: string
  ): StoredAnalysisContext | null {
    this.assertOpen();
    const tenantId = assertValidAuthTenantId(authTenantId);
    const analysis = this.getAnalysis(tenantId, analysisId);
    if (!analysis) {
      return null;
    }
    return {
      analysis,
      evidence: this.getEvidenceForAnalysis(tenantId, analysisId),
      adjudications: this.getAdjudicationsForAnalysis(tenantId, analysisId),
      remediationSpecs: this.getRemediationSpecsForAnalysis(
        tenantId,
        analysisId
      ),
      decisionHistory: this.getDecisionHistory(tenantId, analysisId),
    };
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
