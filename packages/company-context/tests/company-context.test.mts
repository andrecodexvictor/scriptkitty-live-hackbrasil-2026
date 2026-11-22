import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import {
  checkFactoryDeliveryRecord,
  CompanyBrainStore,
  CompanyContextError,
  evaluateFactoryDeliveryEligibility,
  FactoryDeliveryValidationError,
  sha256,
  TenantIsolationError,
} from '../dist/index.js';

const HEAD_SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);
const NOW = new Date('2026-11-11T12:00:00.000Z');

function makeDeliveryRecord() {
  return {
    contract: 'factory.delivery.v1' as const,
    snapshot: {
      cancelled: false,
      deadlineAt: '2030-01-01T00:00:00.000Z',
      submissions: 1,
      maxSubmissions: 4 as const,
      artifact: {
        commitSha: HEAD_SHA,
        summary: 'Synthetic verified build with deterministic checks attached.',
        checks: (['tests', 'typecheck', 'build'] as const).map((key) => ({
          key,
          status: 'passed' as const,
          evidenceRef: `synthetic/${key}`,
        })),
      },
      review: {
        commitSha: HEAD_SHA,
        verdict: 'approve' as const,
        summary: 'Independent reviewer verified tests and typecheck evidence.',
        evidenceRefs: ['synthetic/review'],
      },
      submitter: 'service:builder',
      reviewer: 'service:reviewer',
    },
    authority: {
      requesterActive: true,
      submitterActive: true,
      reviewerActive: true,
      enabled: true,
    },
  };
}

function makeSampleAnalysis(tenantId: string, analysisId: string, fixtureId = 'payments-lab/unsafe-rollout') {
  const createdAt = '2026-11-11T12:00:00.000Z';
  const inputSha256 = sha256({ tenantId, fixtureId, v: 'v1' });
  const evPolicySha = sha256({ analysisId, kind: 'POLICY_SNAPSHOT' });
  const evPathSha = sha256({ analysisId, kind: 'GRAPH_PATH' });
  return {
    schemaVersion: 'security.analysis.v1' as const,
    analysisId,
    tenantId,
    fixtureId,
    commitSha: HEAD_SHA,
    policyVersion: '2026-11-11.1',
    mode: 'LAB' as const,
    paths: [
      {
        pathId: `path-${analysisId}`,
        startIdentity: 'id:support-agent',
        targetAsset: 'asset:cardholder-pii',
        targetDestination: 'dest:external-webhook',
        edges: [
          {
            edgeId: 'e-1',
            from: 'id:support-agent',
            to: 'asset:cardholder-pii',
            kind: 'can_read',
            scope: 'payments.export',
            sourceRef: 'policy/payments.json#e-1',
            policyVersion: '2026-11-11.1',
            dataClassification: 'RESTRICTED',
          },
        ],
        violatedPolicyId: 'pol-no-pii-exfil',
        status: 'PATH_VALIDATED',
        evidenceIds: [`ev-pol-${analysisId}`, `ev-path-${analysisId}`],
        riskRecommendation: 'P1',
        explanation: 'Synthetic modeled path',
        nonTechnicalSummary: 'Synthetic summary',
      },
    ],
    evidenceIds: [`ev-pol-${analysisId}`, `ev-path-${analysisId}`],
    evidence: [
      {
        evidenceId: `ev-pol-${analysisId}`,
        analysisId,
        kind: 'POLICY_SNAPSHOT' as const,
        sourceRef: 'policy/payments.json',
        contentSha256: evPolicySha,
        producer: '@script-kitty/chainbreak',
        createdAt,
        commitSha: HEAD_SHA,
        verified: true,
        summary: 'Policy snapshot',
      },
      {
        evidenceId: `ev-path-${analysisId}`,
        analysisId,
        kind: 'GRAPH_PATH' as const,
        sourceRef: 'policy/payments.json#e-1',
        contentSha256: evPathSha,
        producer: '@script-kitty/chainbreak',
        createdAt,
        commitSha: HEAD_SHA,
        verified: true,
        summary: 'Path evidence',
      },
    ],
    remediationSpecs: [
      {
        remediationId: `rem-${analysisId}`,
        analysisId,
        tenantId,
        fixtureId,
        pathId: `path-${analysisId}`,
        violatedPolicyId: 'pol-no-pii-exfil',
        riskRecommendation: 'P1' as const,
        minimalChange: true,
        actions: [
          {
            actionType: 'REMOVE_EDGE',
            edgeId: 'e-1',
            sourceRef: 'policy/payments.json#e-1',
          },
        ],
        breaksUnauthorizedPath: true,
        preservesLegitimateOperations: true,
        preservedOperationIds: ['op-settlement'],
        acceptanceCriteria: ['0 forbidden paths remaining'],
        verificationTests: ['chainbreak:verify-no-path'],
        requiresHumanApproval: true as const,
        autoApplyAllowed: false as const,
        rationale: 'Minimal edge removal breaks unauthorized path.',
        nonTechnicalSummary: 'Remove excessive rollout permission.',
        evidenceIds: [`ev-pol-${analysisId}`, `ev-path-${analysisId}`],
        createdAt,
      },
    ],
    legitimateOperations: [],
    legitimateOperationsPreserved: true,
    startedAt: createdAt,
    completedAt: createdAt,
    status: 'COMPLETED' as const,
    inputSha256,
    source: 'DETERMINISTIC_LAB_ANALYSIS' as const,
    productionTested: false as const,
    diagnostics: [],
  };
}

function makeSampleAdjudication(tenantId: string, analysisId: string, evaluationId: string) {
  return {
    evaluationId,
    analysisId,
    tenantId,
    model: 'mock-offline-v0',
    modelVersion: '0.1.0',
    rubricVersion: 'jev-rubric-v0',
    status: 'PENDING_REVIEW' as const,
    decision: 'escalated_human_review',
    triage: 'likely_actionable' as const,
    escalated: true,
    escalationReason: 'P1 finding requires human review',
    requiresHumanReview: true,
    riskRecommendation: 'P1' as const,
    evidenceIds: [`ev-pol-${analysisId}`, `ev-path-${analysisId}`],
    sourceRefs: ['policy/payments.json#e-1'],
    decisionSource: 'MOCK' as const,
    providerStatus: 'NOT_CONFIGURED' as const,
    mergeAllowed: false as const,
    deployAllowed: false as const,
    exploitConfirmed: false as const,
    p0DefinedByJevAlone: false as const,
    timestamp: '2026-11-11T12:01:00.000Z',
  };
}

test('CompanyBrainStore persists and retrieves full tenant context including SQLite file reload', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sk-company-ctx-'));
  const dbPath = path.join(tmpDir, 'brain.sqlite');

  try {
    const store = new CompanyBrainStore({ dbPath });
    const analysis = makeSampleAnalysis('tenant-alpha', 'cb-alpha-1');

    const saved = store.saveAnalysis('tenant-alpha', analysis, {
      actorPrincipalId: 'user:alice',
      correlationId: 'corr-001',
      sourceRef: 'fixtures/payments-lab/unsafe-rollout.json',
    });
    assert.equal(saved.analysisId, 'cb-alpha-1');

    // Idempotent replay succeeds
    const replayed = store.saveAnalysis('tenant-alpha', analysis);
    assert.equal(replayed.analysisId, 'cb-alpha-1');

    // Idempotency lookup finds the saved analysis
    const byKey = store.findAnalysisByIdempotency('tenant-alpha', {
      fixtureId: analysis.fixtureId,
      policyVersion: analysis.policyVersion,
      inputSha256: analysis.inputSha256,
    });
    assert.ok(byKey);
    assert.equal(byKey.analysisId, 'cb-alpha-1');

    // Adjudication persistence
    const adj = makeSampleAdjudication('tenant-alpha', 'cb-alpha-1', 'jev-alpha-1');
    store.saveAdjudication('tenant-alpha', adj, {
      actorPrincipalId: 'user:alice',
      correlationId: 'corr-002',
    });

    // Policy snapshot persistence (read-only)
    const snap = store.savePolicySnapshot('tenant-alpha', {
      tenantId: 'tenant-alpha',
      policyId: 'pol-no-pii-exfil',
      policyVersion: '2026-11-11.1',
      sourceRef: 'policy/payments.json',
      rules: { maxZone: 'INTERNAL' },
      approvedBy: 'sec-lead:bob',
      approvedAt: '2026-11-11T10:00:00.000Z',
      readOnly: true,
    });
    assert.equal(snap.readOnly, true);

    store.close();

    // Reopen from disk to prove real persistence
    const reopened = new CompanyBrainStore({ dbPath });
    const ctx = reopened.getAnalysisWithContext('tenant-alpha', 'cb-alpha-1');
    assert.ok(ctx);
    assert.equal(ctx.analysis.tenantId, 'tenant-alpha');
    assert.equal(ctx.evidence.length, 2);
    assert.equal(ctx.adjudications.length, 1);
    assert.equal(ctx.remediationSpecs.length, 1);
    assert.ok(ctx.decisionHistory.length >= 2);
    assert.equal(ctx.decisionHistory[0].sourceRef, 'fixtures/payments-lab/unsafe-rollout.json');

    const loadedSpec = reopened.getRemediationSpecForPath(
      'tenant-alpha',
      'cb-alpha-1',
      'path-cb-alpha-1'
    );
    assert.ok(loadedSpec);
    assert.equal(loadedSpec.autoApplyAllowed, false);
    assert.equal(loadedSpec.requiresHumanApproval, true);
    reopened.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('CompanyBrainStore enforces fail-closed cross-tenant isolation on all reads and writes', () => {
  const store = new CompanyBrainStore();
  const analysisA = makeSampleAnalysis('tenant-alpha', 'cb-shared-id-1');
  store.saveAnalysis('tenant-alpha', analysisA);
  store.saveAdjudication(
    'tenant-alpha',
    makeSampleAdjudication('tenant-alpha', 'cb-shared-id-1', 'jev-1')
  );

  // Empty/invalid auth tenantId fails closed
  assert.throws(() => store.getAnalysis('', 'cb-shared-id-1'), TenantIsolationError);
  assert.throws(() => store.listAnalyses('   '), TenantIsolationError);

  // Tenant Beta reading Tenant Alpha's IDs fails closed with TenantIsolationError
  assert.throws(
    () => store.getAnalysis('tenant-beta', 'cb-shared-id-1'),
    TenantIsolationError
  );
  assert.throws(
    () => store.getEvidenceForAnalysis('tenant-beta', 'cb-shared-id-1'),
    TenantIsolationError
  );
  assert.throws(
    () => store.getAdjudicationsForAnalysis('tenant-beta', 'cb-shared-id-1'),
    TenantIsolationError
  );
  assert.throws(
    () => store.getRemediationSpecsForAnalysis('tenant-beta', 'cb-shared-id-1'),
    TenantIsolationError
  );
  assert.throws(
    () => store.getRemediationSpecForPath('tenant-beta', 'cb-shared-id-1', 'path-cb-shared-id-1'),
    TenantIsolationError
  );
  assert.throws(
    () => store.getDecisionHistory('tenant-beta', 'cb-shared-id-1'),
    TenantIsolationError
  );

  // Listing analyses only shows tenant's own rows
  assert.equal(store.listAnalyses('tenant-beta').length, 0);
  assert.equal(store.listAnalyses('tenant-alpha').length, 1);

  // Writing object with mismatched tenantId fails closed
  assert.throws(
    () => store.saveAnalysis('tenant-beta', makeSampleAnalysis('tenant-alpha', 'cb-forged')),
    TenantIsolationError
  );
  assert.throws(
    () => store.saveAdjudication('tenant-beta', makeSampleAdjudication('tenant-alpha', 'cb-shared-id-1', 'jev-forged')),
    TenantIsolationError
  );

  // Writing an existing analysisId/evidenceId under another tenant rejects overwrite
  assert.throws(
    () => store.saveAnalysis('tenant-beta', makeSampleAnalysis('tenant-beta', 'cb-shared-id-1')),
    TenantIsolationError
  );

  // Idempotency lookup is scoped per tenant
  assert.equal(
    store.findAnalysisByIdempotency('tenant-beta', {
      fixtureId: analysisA.fixtureId,
      policyVersion: analysisA.policyVersion,
      inputSha256: analysisA.inputSha256,
    }),
    null
  );

  // SQL injection string cannot bypass query isolation
  const sqliAnalysisId = "cb-shared-id-1' OR '1'='1";
  assert.equal(store.getAnalysis('tenant-beta', sqliAnalysisId), null);

  store.close();
});

test('Policy snapshots are immutable and idempotency conflicts reject mismatched IDs', () => {
  const store = new CompanyBrainStore();
  const baseAnalysis = makeSampleAnalysis('tenant-alpha', 'cb-a');
  store.saveAnalysis('tenant-alpha', baseAnalysis);

  const duplicatePayloadDifferentId = {
    ...makeSampleAnalysis('tenant-alpha', 'cb-b'),
    inputSha256: baseAnalysis.inputSha256,
  };
  assert.throws(
    () => store.saveAnalysis('tenant-alpha', duplicatePayloadDifferentId),
    (err: unknown) =>
      err instanceof CompanyContextError && err.code === 'IDEMPOTENCY_CONFLICT'
  );

  store.savePolicySnapshot('tenant-alpha', {
    tenantId: 'tenant-alpha',
    policyId: 'pol-1',
    policyVersion: 'v1',
    sourceRef: 'policy/v1.json',
    rules: { forbid: ['EXTERNAL'] },
    approvedBy: 'human:sec-admin',
    approvedAt: '2026-11-11T10:00:00.000Z',
    readOnly: true,
  });

  // Identical content replay succeeds
  store.savePolicySnapshot('tenant-alpha', {
    tenantId: 'tenant-alpha',
    policyId: 'pol-1',
    policyVersion: 'v1',
    sourceRef: 'policy/v1.json',
    rules: { forbid: ['EXTERNAL'] },
    approvedBy: 'human:sec-admin',
    approvedAt: '2026-11-11T10:00:00.000Z',
    readOnly: true,
  });

  // Mutating rules for same policy version fails closed
  assert.throws(
    () =>
      store.savePolicySnapshot('tenant-alpha', {
        tenantId: 'tenant-alpha',
        policyId: 'pol-1',
        policyVersion: 'v1',
        sourceRef: 'policy/v1.json',
        rules: { forbid: [] },
        approvedBy: 'agent:attacker',
        approvedAt: '2026-11-11T11:00:00.000Z',
        readOnly: true,
      }),
    (err: unknown) =>
      err instanceof CompanyContextError && err.code === 'POLICY_IMMUTABLE'
  );

  store.close();
});

test('factory.delivery.v1 eligibility enforces mergeAllowed=false, deployAllowed=false, and all starter-kit negative cases', () => {
  const valid = checkFactoryDeliveryRecord(makeDeliveryRecord(), HEAD_SHA, NOW);
  assert.equal(valid.contract, 'factory.delivery.v1');
  assert.equal(valid.eligible, true);
  assert.equal(valid.stage, 'approved');
  assert.equal(valid.blockReason, null);
  assert.equal(valid.mergeAllowed, false);
  assert.equal(valid.deployAllowed, false);
  assert.equal(valid.deploymentAllowed, false);
  assert.equal(valid.externalExecution, false);

  // HEAD_CHANGED
  const staleHead = checkFactoryDeliveryRecord(makeDeliveryRecord(), OTHER_SHA, NOW);
  assert.equal(staleHead.eligible, false);
  assert.equal(staleHead.blockReason, 'HEAD_CHANGED');
  assert.equal(staleHead.mergeAllowed, false);
  assert.equal(staleHead.deployAllowed, false);

  // INDEPENDENT_REVIEW_REQUIRED (submitter === reviewer)
  const selfReview = makeDeliveryRecord();
  selfReview.snapshot.reviewer = selfReview.snapshot.submitter;
  assert.equal(
    checkFactoryDeliveryRecord(selfReview, HEAD_SHA, NOW).blockReason,
    'INDEPENDENT_REVIEW_REQUIRED'
  );

  // REVIEWER_REVOKED
  const revoked = makeDeliveryRecord();
  revoked.authority.reviewerActive = false;
  assert.equal(
    checkFactoryDeliveryRecord(revoked, HEAD_SHA, NOW).blockReason,
    'REVIEWER_REVOKED'
  );

  // DEADLINE_EXPIRED
  assert.equal(
    checkFactoryDeliveryRecord(
      makeDeliveryRecord(),
      HEAD_SHA,
      new Date('2031-01-01T00:00:00.000Z')
    ).blockReason,
    'DEADLINE_EXPIRED'
  );

  // CHECKS_INCOMPLETE
  const missingCheck = makeDeliveryRecord();
  missingCheck.snapshot.artifact.checks.pop();
  assert.equal(
    checkFactoryDeliveryRecord(missingCheck, HEAD_SHA, NOW).blockReason,
    'CHECKS_INCOMPLETE'
  );

  // CORRECTION_LIMIT
  const exhausted = makeDeliveryRecord();
  exhausted.snapshot.submissions = 4;
  exhausted.snapshot.review.verdict = 'changes_requested';
  assert.equal(
    checkFactoryDeliveryRecord(exhausted, HEAD_SHA, NOW).blockReason,
    'CORRECTION_LIMIT'
  );

  // INVALID_DEADLINE (bad date & JS calendar overflow like 2027-02-30)
  const badDate = makeDeliveryRecord();
  badDate.snapshot.deadlineAt = '2026-99-99T00:00:00Z';
  assert.equal(
    checkFactoryDeliveryRecord(badDate, HEAD_SHA, NOW).blockReason,
    'INVALID_DEADLINE'
  );
  const feb30 = makeDeliveryRecord();
  feb30.snapshot.deadlineAt = '2027-02-30T00:00:00Z';
  assert.equal(
    checkFactoryDeliveryRecord(feb30, HEAD_SHA, new Date('2027-03-01T00:00:00Z')).blockReason,
    'INVALID_DEADLINE'
  );
  const leapDay = makeDeliveryRecord();
  leapDay.snapshot.deadlineAt = '2028-02-29T00:00:00Z';
  assert.equal(
    checkFactoryDeliveryRecord(leapDay, HEAD_SHA, new Date('2028-02-28T00:00:00Z')).eligible,
    true
  );

  // INVALID_RECORD on unknown invented fields & whitespace-only summary
  const unknownField = { ...makeDeliveryRecord(), deploy: true };
  assert.throws(
    () => evaluateFactoryDeliveryEligibility(unknownField, { headSha: HEAD_SHA, now: NOW }),
    (err: unknown) =>
      err instanceof FactoryDeliveryValidationError && err.code === 'INVALID_RECORD'
  );
  const blankSummary = makeDeliveryRecord();
  blankSummary.snapshot.artifact.summary = ' '.repeat(30);
  assert.throws(
    () => checkFactoryDeliveryRecord(blankSummary, HEAD_SHA, NOW),
    (err: unknown) =>
      err instanceof FactoryDeliveryValidationError && err.code === 'INVALID_RECORD'
  );

  // Non-mutating whitespace trim preserves original caller string length
  const padded = makeDeliveryRecord();
  padded.snapshot.artifact.summary = ' ' + 'a'.repeat(1000) + ' ';
  assert.equal(checkFactoryDeliveryRecord(padded, HEAD_SHA, NOW).eligible, true);
  assert.equal(padded.snapshot.artifact.summary.length, 1002);

  // CompanyBrainStore records delivery eligibility per tenant
  const store = new CompanyBrainStore();
  const recorded = store.evaluateAndRecordDeliveryEligibility('tenant-alpha', {
    record: makeDeliveryRecord(),
    headSha: HEAD_SHA,
    now: NOW,
    actorPrincipalId: 'ci:quality-gate',
    sourceRef: 'commit/' + HEAD_SHA,
    correlationId: 'corr-del-1',
  });
  assert.equal(recorded.eligible, true);
  assert.equal(recorded.mergeAllowed, false);
  assert.equal(recorded.deployAllowed, false);
  assert.equal(store.getDeliveryEvaluations('tenant-alpha').length, 1);
  assert.equal(store.getDeliveryEvaluations('tenant-beta').length, 0);
  store.close();
});

test('CompanyBrainStore batch ownership, getEvidenceById isolation, pagination, WAL PRAGMAs, and covering indexes', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'script-kitty-brain-idx-'));
  const dbPath = path.join(tmpDir, 'company-brain.sqlite');
  let store1: CompanyBrainStore | undefined;
  let store2: CompanyBrainStore | undefined;
  let inspector: DatabaseSync | undefined;

  try {
    store1 = new CompanyBrainStore({ dbPath });
    store2 = new CompanyBrainStore({ dbPath });

    // Create 3 analyses for pagination + concurrent idempotency verification
    const a1 = makeSampleAnalysis('tenant-alpha', 'an-page-1', 'payments-lab/baseline');
    const a2 = makeSampleAnalysis('tenant-alpha', 'an-page-2', 'payments-lab/unsafe-rollout');
    const a3 = makeSampleAnalysis('tenant-alpha', 'an-page-3', 'payments-lab/remediated');
    a1.startedAt = '2026-11-11T10:00:00.000Z';
    a1.completedAt = '2026-11-11T10:00:01.000Z';
    a2.startedAt = '2026-11-11T11:00:00.000Z';
    a2.completedAt = '2026-11-11T11:00:01.000Z';
    a3.startedAt = '2026-11-11T12:00:00.000Z';
    a3.completedAt = '2026-11-11T12:00:01.000Z';

    store1.saveAnalysis('tenant-alpha', a1);
    store2.saveAnalysis('tenant-alpha', a1); // Idempotent across 2nd connection on WAL DB
    store1.saveAnalysis('tenant-alpha', a2);
    store2.saveAnalysis('tenant-alpha', a3);

    // Batch saveEvidence with 30 items and test getEvidenceById tenant isolation
    const batchEvidence = Array.from({ length: 30 }, (_, idx) => ({
      evidenceId: `ev-batch-${String(idx).padStart(2, '0')}`,
      analysisId: 'an-page-2',
      kind: 'GRAPH_PATH' as const,
      sourceRef: `policy/batch.yaml#L${idx + 1}`,
      contentSha256: sha256({ idx }),
      producer: '@script-kitty/chainbreak',
      createdAt: `2026-11-11T11:00:${String(idx).padStart(2, '0')}.000Z`,
      commitSha: HEAD_SHA,
      verified: true,
      summary: `Batch item ${idx}`,
    }));
    const savedBatch = store1.saveEvidence('tenant-alpha', batchEvidence);
    assert.equal(savedBatch.length, 30);

    const directEv = store2.getEvidenceById('tenant-alpha', 'ev-batch-17');
    assert.ok(directEv !== null);
    assert.equal(directEv.evidenceId, 'ev-batch-17');
    assert.equal(store2.getEvidenceById('tenant-alpha', 'ev-missing-999'), null);
    assert.throws(
      () => store2!.getEvidenceById('tenant-beta', 'ev-batch-17'),
      TenantIsolationError
    );

    // Cross-tenant parent analysis in batch saveEvidence must fail closed
    assert.throws(
      () =>
        store1!.saveEvidence('tenant-beta', [
          {
            ...batchEvidence[0],
            evidenceId: 'ev-beta-hijack-attempt',
          },
        ]),
      TenantIsolationError
    );

    // Pagination checks on listAnalyses and getDecisionHistory
    const pagedAnalyses = store1.listAnalyses('tenant-alpha', {
      limit: 2,
      offset: 1,
    });
    assert.equal(pagedAnalyses.length, 2);
    assert.deepEqual(
      pagedAnalyses.map((a) => a.analysisId),
      ['an-page-2', 'an-page-1']
    );

    const allHistory = store1.getDecisionHistory('tenant-alpha');
    const pagedHistory = store1.getDecisionHistory('tenant-alpha', undefined, {
      limit: 2,
      offset: 1,
    });
    assert.equal(allHistory.length, 3);
    assert.equal(pagedHistory.length, 2);
    assert.deepEqual(
      pagedHistory.map((h) => h.decisionId),
      allHistory.slice(1, 3).map((h) => h.decisionId)
    );

    // Verify WAL PRAGMAs, statement cache, and covering/descending indexes
    const metrics = store1.getStorageMetrics();
    assert.equal(metrics.journalMode.toLowerCase(), 'wal');
    assert.equal(metrics.busyTimeoutMs, 5000);
    assert.equal(metrics.foreignKeys, true);
    assert.ok(metrics.cachedStatements > 0);

    inspector = new DatabaseSync(dbPath, { readOnly: true });
    const journalMode = inspector.prepare('PRAGMA journal_mode').get() as {
      journal_mode: string;
    };
    assert.equal(journalMode.journal_mode.toLowerCase(), 'wal');

    const idxRows = inspector
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('idx_analyses_tenant_created_desc', 'idx_delivery_tenant_created_desc')"
      )
      .all() as Array<{ name: string }>;
    assert.equal(idxRows.length, 2);
  } finally {
    inspector?.close();
    store1?.close();
    store2?.close();
    fs.rmSync(tmpDir, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 50,
    });
  }
});
