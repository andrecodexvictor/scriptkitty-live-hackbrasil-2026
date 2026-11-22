/**
 * @file packages/evidence/tests/evidence-ledger.test.mts
 * @description Comprehensive unit and integration tests for @script-kitty/evidence
 * covering dual ChainBreak + Contract evidence ingestion, RFC 8785 canonical digest
 * verification, cross-linking, strict tenant isolation, AI-prose rejection,
 * binary Merkle inclusion bundles, and file-backed SQLite persistence.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { ChainBreakEvidence } from '@script-kitty/chainbreak';
import type { Evidence as ContractEvidence } from '@script-kitty/contracts';
import {
  EvidenceIntegrityError,
  EvidenceLedger,
  EvidenceLedgerError,
  TenantIsolationError,
  UnverifiedAiProseError,
  assessAiProseProofRisk,
  buildAnalysisMerkleBundle,
  canonicalStringify,
  computeCanonicalDigest,
  computeEvidenceChainHash,
  createEvidenceReceipt,
  sha256,
  verifyAnalysisMerkleBundle,
  verifyEvidenceReceipt,
} from '../dist/index.js';

function makeChainBreakEvidence(
  overrides: Partial<ChainBreakEvidence> & { payload?: unknown } = {}
): { evidence: ChainBreakEvidence; payload: unknown } {
  const payload = overrides.payload ?? {
    rule: 'payments-rollout-guard',
    nodeCount: 4,
    edgeCount: 3,
    pathId: 'path-checkout-001',
  };
  const { payload: _ignored, ...rest } = overrides;
  const contentSha256 =
    rest.contentSha256 ?? computeCanonicalDigest(payload);
  const evidence: ChainBreakEvidence = {
    evidenceId: rest.evidenceId ?? 'ev-cb-001',
    analysisId: rest.analysisId ?? 'analysis-payments-001',
    kind: rest.kind ?? 'GRAPH_PATH',
    sourceRef: rest.sourceRef ?? 'fixtures/payments-lab/unsafe-rollout.json#path-1',
    contentSha256,
    producer: rest.producer ?? '@script-kitty/chainbreak:analyzer-v0',
    verified: rest.verified ?? true,
    createdAt: rest.createdAt ?? '2026-11-12T10:00:00.000Z',
    ...(rest.commitSha ? { commitSha: rest.commitSha } : {}),
  };
  return { evidence, payload };
}

function makeContractEvidence(
  overrides: Partial<ContractEvidence> = {}
): ContractEvidence {
  const finding_id = overrides.finding_id ?? 'finding-payments-001';
  const verifier_agent_id = overrides.verifier_agent_id ?? 'verifier-sandbox-01';
  const status = overrides.status ?? 'VERIFIED_TRUE_POSITIVE';
  const recorded_at = overrides.recorded_at ?? '2026-11-12T10:05:00.000Z';
  const scriptContent = 'assert checkout.requiresAuth === true;';
  const script_sha256 = sha256(scriptContent);

  const chain_hash =
    overrides.chain_hash ??
    computeEvidenceChainHash({
      finding_id,
      verifier_agent_id,
      status,
      script_sha256,
      recorded_at,
    });

  const reproducer_artifact =
    'reproducer_artifact' in overrides
      ? overrides.reproducer_artifact
      : {
          script_path: 'sandbox/reproducers/payments-checkout-poc.mjs',
          script_sha256,
          exit_code: 1,
          stdout: 'VULNERABILITY_CONFIRMED',
          stderr: '',
          execution_duration_ms: 42,
        };

  const reproduction_proof =
    'reproduction_proof' in overrides
      ? overrides.reproduction_proof
      : {
          proof_type: 'EXECUTABLE_POC' as const,
          payload: 'POST /api/payments/export?bypass=1',
          expected_behavior: 'HTTP 403 Forbidden without MFA + idempotency key',
          observed_vulnerable_behavior: 'HTTP 200 OK unauthorized payout export',
        };

  return {
    evidence_id: overrides.evidence_id ?? 'ev-contract-001',
    finding_id,
    verification_type: overrides.verification_type ?? 'REPRODUCER_EXECUTION',
    status,
    verifier_agent_id,
    sandbox_environment: overrides.sandbox_environment ?? {
      runtime: 'docker_isolated',
      network_isolated: true,
      timeout_ms: 30000,
    },
    ...(reproducer_artifact !== undefined ? { reproducer_artifact } : {}),
    ...(reproduction_proof !== undefined ? { reproduction_proof } : {}),
    ...(overrides.refutation_reason !== undefined
      ? { refutation_reason: overrides.refutation_reason }
      : {}),
    chain_hash,
    recorded_at,
  };
}

describe('@script-kitty/evidence: RFC 8785 digests & receipt verification', () => {
  it('computes identical RFC 8785 digests regardless of object key ordering', () => {
    const a = { z: 2, nested: { b: true, a: 'hello' }, a: 1 };
    const b = { a: 1, nested: { a: 'hello', b: true }, z: 2 };

    assert.equal(canonicalStringify(a), canonicalStringify(b));
    assert.equal(computeCanonicalDigest(a), computeCanonicalDigest(b));

    const { evidence, payload } = makeChainBreakEvidence({
      payload: a,
      contentSha256: computeCanonicalDigest(a),
    });

    const receipt = createEvidenceReceipt({
      tenantId: 'tenant-alpha',
      evidence,
      payload: b, // Reordered keys must verify identically
    });

    const verification = verifyEvidenceReceipt(receipt, { payload: b });
    assert.equal(verification.valid, true);
    assert.equal(verification.code, 'VERIFIED');
    assert.equal(verification.verified, true);
    assert.equal(verification.standaloneProofEligible, true);
  });

  it('records and verifies all 4 ChainBreakEvidence kinds (POLICY_SNAPSHOT, GRAPH_PATH, TEST_RESULT, QUALITY_RESULT)', () => {
    const ledger = new EvidenceLedger();
    const kinds = [
      'POLICY_SNAPSHOT',
      'GRAPH_PATH',
      'TEST_RESULT',
      'QUALITY_RESULT',
    ] as const;

    try {
      for (let i = 0; i < kinds.length; i++) {
        const kind = kinds[i];
        const { evidence, payload } = makeChainBreakEvidence({
          evidenceId: `ev-cb-${kind.toLowerCase()}`,
          kind,
          sourceRef: `artifacts/${kind.toLowerCase()}.json`,
          payload: { kind, index: i, status: 'verified' },
          createdAt: `2026-11-12T10:00:0${i}.000Z`,
          commitSha: 'a1b2c3d4e5f6',
        });

        const receipt = ledger.recordChainBreakEvidence('tenant-alpha', evidence, {
          payload,
          pathId: 'path-rollout-01',
        });

        assert.equal(receipt.recordType, 'CHAINBREAK');
        assert.equal(receipt.kind, kind);
        assert.equal(receipt.commitSha, 'a1b2c3d4e5f6');
        assert.equal(receipt.standaloneProofEligible, true);

        const check = ledger.verifyStoredReceipt('tenant-alpha', evidence.evidenceId, {
          payload,
          requireVerifiedProof: true,
        });
        assert.equal(check.valid, true);
        assert.equal(check.code, 'VERIFIED');
      }

      const list = ledger.getReceiptsForAnalysis('tenant-alpha', 'analysis-payments-001');
      assert.equal(list.length, 4);
    } finally {
      ledger.close();
    }
  });

  it('detects payload, contentSha256, and receiptSha256 tampering', () => {
    const { evidence, payload } = makeChainBreakEvidence();
    const receipt = createEvidenceReceipt({
      tenantId: 'tenant-alpha',
      evidence,
      payload,
    });

    const wrongPayloadResult = verifyEvidenceReceipt(receipt, {
      payload: { rule: 'tampered-rule', nodeCount: 99 },
    });
    assert.equal(wrongPayloadResult.valid, false);
    assert.equal(wrongPayloadResult.code, 'DIGEST_MISMATCH');

    const tamperedReceipt = {
      ...receipt,
      sourceRef: 'fixtures/tampered.json',
    };
    const tamperedReceiptResult = verifyEvidenceReceipt(tamperedReceipt);
    assert.equal(tamperedReceiptResult.valid, false);
    assert.equal(tamperedReceiptResult.code, 'DIGEST_MISMATCH');
  });

  it('marks INCONCLUSIVE Contract Evidence as cryptographically valid but NOT standalone-proof-eligible', () => {
    const ledger = new EvidenceLedger();
    try {
      const inconclusive = makeContractEvidence({
        evidence_id: 'ev-contract-inc',
        status: 'INCONCLUSIVE',
        reproduction_proof: undefined,
      });

      const receipt = ledger.recordContractEvidence('tenant-alpha', inconclusive, {
        analysisId: 'analysis-payments-001',
        verifyChainHash: true,
      });

      assert.equal(receipt.verified, false);
      assert.equal(receipt.standaloneProofEligible, false);

      const nonStrict = ledger.verifyStoredReceipt('tenant-alpha', inconclusive.evidence_id, {
        verifyChainHash: true,
      });
      assert.equal(nonStrict.valid, true);
      assert.equal(nonStrict.standaloneProofEligible, false);

      const strict = ledger.verifyStoredReceipt('tenant-alpha', inconclusive.evidence_id, {
        requireVerifiedProof: true,
        verifyChainHash: true,
      });
      assert.equal(strict.valid, false);
      assert.equal(strict.code, 'UNVERIFIED_PROOF');
    } finally {
      ledger.close();
    }
  });

  it('rejects Contract Evidence whose chain_hash does not match when verifyChainHash is true', () => {
    const ledger = new EvidenceLedger();
    try {
      const badChainHash = makeContractEvidence({
        evidence_id: 'ev-bad-chain',
        chain_hash: 'f'.repeat(64),
      });

      assert.throws(
        () =>
          ledger.recordContractEvidence('tenant-alpha', badChainHash, {
            analysisId: 'analysis-payments-001',
            verifyChainHash: true,
          }),
        (err: unknown) =>
          err instanceof EvidenceIntegrityError && err.code === 'DIGEST_MISMATCH'
      );
    } finally {
      ledger.close();
    }
  });
});

describe('@script-kitty/evidence: unverified AI prose rejection', () => {
  it('rejects raw text prose, AI_PROSE kinds, LLM producers, and llm:// sourceRefs', () => {
    const ledger = new EvidenceLedger();
    try {
      assert.throws(
        () =>
          ledger.recordEvidence(
            'tenant-alpha',
            'The AI thinks this endpoint might be vulnerable to SSRF.'
          ),
        (err: unknown) =>
          err instanceof UnverifiedAiProseError &&
          err.code === 'UNVERIFIED_AI_PROSE_REJECTED'
      );

      assert.throws(
        () =>
          ledger.recordEvidence('tenant-alpha', {
            kind: 'AI_PROSE',
            prose: 'Looks risky in checkout.ts',
          }),
        UnverifiedAiProseError
      );

      const { evidence: llmProducerEv } = makeChainBreakEvidence({
        evidenceId: 'ev-llm-prod',
        producer: 'gpt-4o',
      });
      assert.throws(
        () => ledger.recordChainBreakEvidence('tenant-alpha', llmProducerEv),
        UnverifiedAiProseError
      );

      const { evidence: llmRefEv } = makeChainBreakEvidence({
        evidenceId: 'ev-llm-ref',
        sourceRef: 'llm://chat/completion/999',
      });
      assert.throws(
        () => ledger.recordChainBreakEvidence('tenant-alpha', llmRefEv),
        UnverifiedAiProseError
      );

      const heuristicTruePositive = makeContractEvidence({
        evidence_id: 'ev-heuristic-tp',
        verification_type: 'HEURISTIC',
        status: 'VERIFIED_TRUE_POSITIVE',
        reproducer_artifact: undefined,
        reproduction_proof: undefined,
      });
      const risk = assessAiProseProofRisk(heuristicTruePositive);
      assert.equal(risk.isUnverifiedAiProse, true);

      assert.throws(
        () => ledger.recordContractEvidence('tenant-alpha', heuristicTruePositive),
        UnverifiedAiProseError
      );

      const directCheck = verifyEvidenceReceipt({
        kind: 'LLM_SUMMARY',
        narrative: 'Unverified model summary',
      });
      assert.equal(directCheck.valid, false);
      assert.equal(directCheck.code, 'UNVERIFIED_AI_PROSE_REJECTED');
    } finally {
      ledger.close();
    }
  });
});

describe('@script-kitty/evidence: cross-linking, tenant isolation & immutability', () => {
  it('cross-links ChainBreak evidence and Contract evidence within the same tenant', () => {
    const ledger = new EvidenceLedger();
    try {
      const { evidence: cbPolicy, payload: policyPayload } = makeChainBreakEvidence({
        evidenceId: 'ev-cb-policy',
        kind: 'POLICY_SNAPSHOT',
        payload: { policyVersion: '1.0', guardRequired: true },
        createdAt: '2026-11-12T10:00:00.000Z',
      });
      const { evidence: cbPath, payload: pathPayload } = makeChainBreakEvidence({
        evidenceId: 'ev-cb-path',
        kind: 'GRAPH_PATH',
        payload: { pathId: 'path-1', entry: 'public-api', sink: 'payout-exec' },
        createdAt: '2026-11-12T10:01:00.000Z',
      });

      ledger.recordChainBreakEvidence('tenant-alpha', cbPolicy, {
        payload: policyPayload,
      });
      ledger.recordChainBreakEvidence('tenant-alpha', cbPath, {
        payload: pathPayload,
        pathId: 'path-1',
      });

      const verifiedContract = makeContractEvidence({
        evidence_id: 'ev-contract-tp',
        finding_id: 'finding-payout-001',
        status: 'VERIFIED_TRUE_POSITIVE',
        recorded_at: '2026-11-12T10:02:00.000Z',
      });

      const contractReceipt = ledger.recordContractEvidence(
        'tenant-alpha',
        verifiedContract,
        {
          analysisId: 'analysis-payments-001',
          pathId: 'path-1',
          verifyChainHash: true,
          linkedChainBreakEvidenceIds: ['ev-cb-policy', 'ev-cb-path'],
          relationType: 'REPRODUCES_PATH',
        }
      );

      assert.equal(contractReceipt.findingId, 'finding-payout-001');

      const links = ledger.getCrossLinks('tenant-alpha', 'analysis-payments-001');
      assert.equal(links.length, 2);
      assert.ok(links.every((l) => l.relationType === 'REPRODUCES_PATH'));
      assert.ok(links.every((l) => l.findingId === 'finding-payout-001'));

      const expanded = ledger.getEvidenceWithLinks('tenant-alpha', 'ev-contract-tp');
      assert.ok(expanded !== null);
      assert.equal(expanded.links.length, 2);
      assert.equal(expanded.linkedReceipts.length, 2);
      assert.deepEqual(
        expanded.linkedReceipts.map((r) => r.evidenceId).sort(),
        ['ev-cb-path', 'ev-cb-policy']
      );

      // Explicit link call with different relation type is idempotent per relationType
      const refutedContract = makeContractEvidence({
        evidence_id: 'ev-contract-fp',
        finding_id: 'finding-payout-002',
        status: 'REFUTED_FALSE_POSITIVE',
        refutation_reason: 'Middleware enforces Idempotency-Key + MFA before sink',
        recorded_at: '2026-11-12T10:03:00.000Z',
      });
      ledger.recordContractEvidence('tenant-alpha', refutedContract, {
        analysisId: 'analysis-payments-001',
        verifyChainHash: true,
      });
      const refuteLink = ledger.linkEvidence('tenant-alpha', {
        analysisId: 'analysis-payments-001',
        chainBreakEvidenceId: 'ev-cb-path',
        contractEvidenceId: 'ev-contract-fp',
        relationType: 'REFUTES_FINDING',
      });
      assert.equal(refuteLink.relationType, 'REFUTES_FINDING');
    } finally {
      ledger.close();
    }
  });

  it('enforces strict tenant isolation with TenantIsolationError on every cross-tenant vector', () => {
    const ledger = new EvidenceLedger();
    try {
      const { evidence: cbEv, payload } = makeChainBreakEvidence({
        evidenceId: 'ev-shared-check',
        analysisId: 'analysis-shared-check',
      });
      ledger.recordChainBreakEvidence('tenant-alpha', cbEv, { payload });

      const contractEv = makeContractEvidence({
        evidence_id: 'ev-contract-alpha',
      });
      ledger.recordContractEvidence('tenant-alpha', contractEv, {
        analysisId: 'analysis-shared-check',
      });

      // Empty authTenantId rejected
      assert.throws(() => ledger.listReceipts('   '), TenantIsolationError);

      // Mismatched options.tenantId rejected
      assert.throws(
        () =>
          ledger.recordContractEvidence('tenant-alpha', contractEv, {
            tenantId: 'tenant-beta',
            analysisId: 'analysis-shared-check',
          }),
        TenantIsolationError
      );

      // Cross-tenant read by evidenceId rejected
      assert.throws(
        () => ledger.getReceipt('tenant-beta', 'ev-shared-check'),
        TenantIsolationError
      );

      // Cross-tenant read by analysisId rejected
      assert.throws(
        () => ledger.getReceiptsForAnalysis('tenant-beta', 'analysis-shared-check'),
        TenantIsolationError
      );

      // Cross-tenant collision on write rejected
      assert.throws(
        () =>
          ledger.recordChainBreakEvidence('tenant-beta', cbEv, {
            payload,
          }),
        TenantIsolationError
      );

      // Cross-tenant cross-link rejected
      const { evidence: betaCb, payload: betaPayload } = makeChainBreakEvidence({
        evidenceId: 'ev-cb-beta',
        analysisId: 'analysis-beta-only',
      });
      ledger.recordChainBreakEvidence('tenant-beta', betaCb, { payload: betaPayload });

      assert.throws(
        () =>
          ledger.linkEvidence('tenant-beta', {
            analysisId: 'analysis-beta-only',
            chainBreakEvidenceId: 'ev-cb-beta',
            contractEvidenceId: 'ev-contract-alpha',
          }),
        TenantIsolationError
      );

      // Cross-tenant Merkle bundle generation rejected
      assert.throws(
        () => ledger.buildAnalysisMerkleBundle('tenant-beta', 'analysis-shared-check'),
        TenantIsolationError
      );
    } finally {
      ledger.close();
    }
  });

  it('rejects immutable evidence overwrites while permitting idempotent identical replays', () => {
    const ledger = new EvidenceLedger();
    try {
      const { evidence, payload } = makeChainBreakEvidence({
        evidenceId: 'ev-immut-001',
      });
      const first = ledger.recordChainBreakEvidence('tenant-alpha', evidence, {
        payload,
      });
      const replay = ledger.recordChainBreakEvidence('tenant-alpha', evidence, {
        payload,
      });
      assert.equal(replay.receiptSha256, first.receiptSha256);

      const { evidence: mutated, payload: mutatedPayload } = makeChainBreakEvidence({
        evidenceId: 'ev-immut-001',
        payload: { rule: 'modified-after-seal' },
      });
      assert.throws(
        () =>
          ledger.recordChainBreakEvidence('tenant-alpha', mutated, {
            payload: mutatedPayload,
          }),
        (err: unknown) =>
          err instanceof EvidenceIntegrityError &&
          err.code === 'IMMUTABLE_EVIDENCE_CONFLICT'
      );
    } finally {
      ledger.close();
    }
  });
});

describe('@script-kitty/evidence: binary Merkle bundles & SQLite persistence', () => {
  it('builds and verifies empty (0-leaf), 1-leaf, and 3-leaf (odd duplication) Merkle bundles', () => {
    const ledger = new EvidenceLedger();
    try {
      // 0-leaf empty bundle
      const emptyBundle = ledger.buildAnalysisMerkleBundle(
        'tenant-alpha',
        'analysis-empty',
        { generatedAt: '2026-11-12T11:00:00.000Z' }
      );
      assert.equal(emptyBundle.leafCount, 0);
      assert.equal(emptyBundle.leaves.length, 0);
      const emptyCheck = ledger.verifyAnalysisMerkleBundle(emptyBundle);
      assert.equal(emptyCheck.valid, true);
      assert.equal(emptyCheck.leafCount, 0);

      // 3-leaf mixed ChainBreak + Contract bundle (exercises odd-leaf binary tree duplication)
      const { evidence: e1, payload: p1 } = makeChainBreakEvidence({
        evidenceId: 'ev-m-1',
        analysisId: 'analysis-merkle-3',
        kind: 'POLICY_SNAPSHOT',
        payload: { step: 1 },
        createdAt: '2026-11-12T10:00:01.000Z',
      });
      const { evidence: e2, payload: p2 } = makeChainBreakEvidence({
        evidenceId: 'ev-m-2',
        analysisId: 'analysis-merkle-3',
        kind: 'GRAPH_PATH',
        payload: { step: 2 },
        createdAt: '2026-11-12T10:00:02.000Z',
      });
      const e3 = makeContractEvidence({
        evidence_id: 'ev-m-3',
        finding_id: 'finding-merkle-3',
        status: 'VERIFIED_TRUE_POSITIVE',
        recorded_at: '2026-11-12T10:00:03.000Z',
      });

      ledger.recordChainBreakEvidence('tenant-alpha', e1, { payload: p1 });
      ledger.recordChainBreakEvidence('tenant-alpha', e2, { payload: p2 });
      ledger.recordContractEvidence('tenant-alpha', e3, {
        analysisId: 'analysis-merkle-3',
        verifyChainHash: true,
        linkedChainBreakEvidenceIds: ['ev-m-2'],
      });

      const bundle = ledger.buildAnalysisMerkleBundle(
        'tenant-alpha',
        'analysis-merkle-3',
        { generatedAt: '2026-11-12T11:05:00.000Z' }
      );

      assert.equal(bundle.leafCount, 3);
      assert.equal(bundle.entries.length, 3);
      assert.equal(bundle.crossLinks.length, 1);

      const bundleVerification = ledger.verifyAnalysisMerkleBundle(bundle, {
        requireVerifiedProof: true,
        verifyChainHash: true,
      });
      assert.equal(bundleVerification.valid, true);
      assert.equal(bundleVerification.verifiedCount, 3);
      assert.deepEqual(bundleVerification.failedEvidenceIds, []);
      assert.equal(bundleVerification.merkleRoot, bundleVerification.recomputedMerkleRoot);

      // Tampering a leaf receipt breaks both bundleSha256 and Merkle inclusion proof
      const tampered = structuredClone(bundle);
      tampered.entries[1].receipt.sourceRef = 'tampered/source.json';
      const tamperedCheck = verifyAnalysisMerkleBundle(tampered);
      assert.equal(tamperedCheck.valid, false);
      assert.ok(tamperedCheck.failedEvidenceIds.includes('ev-m-2'));
      assert.ok(tamperedCheck.errors.some((e) => e.includes('Bundle SHA-256 mismatch')));

      // Tampering a Merkle proof sibling breaks inclusion verification
      const tamperedProof = structuredClone(bundle);
      tamperedProof.entries[0].proof[0].hash = '0'.repeat(64);
      const tamperedProofCheck = verifyAnalysisMerkleBundle(tamperedProof);
      assert.equal(tamperedProofCheck.valid, false);
      assert.ok(tamperedProofCheck.failedEvidenceIds.includes('ev-m-1'));

      // Single-leaf bundle helper works standalone
      const singleBundle = buildAnalysisMerkleBundle({
        tenantId: 'tenant-alpha',
        analysisId: 'analysis-merkle-3',
        receipts: [bundle.entries[0].receipt],
        generatedAt: '2026-11-12T11:06:00.000Z',
      });
      assert.equal(singleBundle.leafCount, 1);
      assert.equal(singleBundle.entries[0].proof.length, 0);
      assert.equal(verifyAnalysisMerkleBundle(singleBundle).valid, true);
    } finally {
      ledger.close();
    }
  });

  it('persists receipts, cross-links, and Merkle bundles durably across file-backed SQLite reopen', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'script-kitty-evidence-'));
    const dbPath = path.join(tmpDir, 'evidence-ledger.sqlite');
    let ledger1: EvidenceLedger | undefined;
    let ledger2: EvidenceLedger | undefined;

    try {
      ledger1 = new EvidenceLedger({ dbPath });
      const { evidence: cbEv, payload } = makeChainBreakEvidence({
        evidenceId: 'ev-disk-cb',
        analysisId: 'analysis-disk-01',
        kind: 'TEST_RESULT',
        payload: { test: 'payments-lab-negative-control', passed: true },
      });
      ledger1.recordChainBreakEvidence('tenant-disk', cbEv, { payload });

      const contractEv = makeContractEvidence({
        evidence_id: 'ev-disk-contract',
        finding_id: 'finding-disk-01',
        status: 'VERIFIED_TRUE_POSITIVE',
      });
      ledger1.recordContractEvidence('tenant-disk', contractEv, {
        analysisId: 'analysis-disk-01',
        verifyChainHash: true,
        linkedChainBreakEvidenceIds: ['ev-disk-cb'],
      });
      ledger1.close();
      ledger1 = undefined;

      // Reopen on disk and confirm everything persists and verifies
      ledger2 = new EvidenceLedger({ dbPath });
      const persistedCb = ledger2.getReceipt('tenant-disk', 'ev-disk-cb');
      assert.ok(persistedCb !== null);
      assert.equal(persistedCb.contentSha256, cbEv.contentSha256);

      const bundle = ledger2.buildAnalysisMerkleBundle(
        'tenant-disk',
        'analysis-disk-01'
      );
      assert.equal(bundle.leafCount, 2);
      assert.equal(bundle.crossLinks.length, 1);

      const check = ledger2.verifyAnalysisMerkleBundle(bundle, {
        requireVerifiedProof: true,
        verifyChainHash: true,
      });
      assert.equal(check.valid, true);

      // Tenant isolation persists across reopen
      assert.throws(
        () => ledger2!.getReceipt('tenant-intruder', 'ev-disk-cb'),
        TenantIsolationError
      );
    } finally {
      ledger1?.close();
      ledger2?.close();
      fs.rmSync(tmpDir, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 50,
      });
    }
  });

  it('uses covering index idx_receipts_analysis_tenant (zero table SCAN), batches linked evidence without N+1, and supports pagination', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'script-kitty-ev-idx-'));
    const dbPath = path.join(tmpDir, 'evidence-index.sqlite');
    let ledger: EvidenceLedger | undefined;
    let inspector: DatabaseSync | undefined;

    try {
      ledger = new EvidenceLedger({ dbPath });
      const cbIds: string[] = [];
      for (let i = 0; i < 35; i++) {
        const id = `ev-batch-cb-${String(i).padStart(2, '0')}`;
        const { evidence: cbEv, payload } = makeChainBreakEvidence({
          evidenceId: id,
          analysisId: 'analysis-batch-01',
          kind: 'GRAPH_PATH',
          payload: { batchIndex: i, pathId: 'path-batch-01' },
        });
        ledger.recordChainBreakEvidence('tenant-alpha', cbEv, { payload });
        cbIds.push(id);
      }

      const contractEv = makeContractEvidence({
        evidence_id: 'ev-batch-contract',
        finding_id: 'finding-batch-01',
        status: 'VERIFIED_TRUE_POSITIVE',
      });
      ledger.recordContractEvidence('tenant-alpha', contractEv, {
        analysisId: 'analysis-batch-01',
        verifyChainHash: true,
        linkedChainBreakEvidenceIds: cbIds,
      });

      const withLinks = ledger.getEvidenceWithLinks(
        'tenant-alpha',
        'ev-batch-contract'
      );
      assert.ok(withLinks !== null);
      assert.equal(withLinks.links.length, 35);
      assert.equal(withLinks.linkedReceipts.length, 35);
      assert.deepEqual(
        withLinks.linkedReceipts.map((r) => r.evidenceId).sort(),
        cbIds
      );
      assert.deepEqual(
        withLinks.linkedReceipts.map((r) => r.evidenceId),
        withLinks.links.map((l) => l.chainBreakEvidenceId)
      );

      // Cross-tenant linking or reading must fail closed
      const { evidence: betaCb, payload: betaPayload } = makeChainBreakEvidence({
        evidenceId: 'ev-beta-isolated',
        analysisId: 'analysis-beta-01',
        payload: { beta: true },
      });
      ledger.recordChainBreakEvidence('tenant-beta', betaCb, {
        payload: betaPayload,
      });
      assert.throws(
        () =>
          ledger!.linkEvidence('tenant-alpha', {
            analysisId: 'analysis-batch-01',
            chainBreakEvidenceId: 'ev-beta-isolated',
            contractEvidenceId: 'ev-batch-contract',
          }),
        TenantIsolationError
      );

      // Pagination preserves full ordering and slices cleanly
      const all = ledger.listReceipts('tenant-alpha');
      const page = ledger.listReceipts('tenant-alpha', {
        limit: 10,
        offset: 5,
      });
      assert.equal(all.length, 36);
      assert.equal(page.length, 10);
      assert.deepEqual(
        page.map((r) => r.evidenceId),
        all.slice(5, 15).map((r) => r.evidenceId)
      );

      // Verify WAL PRAGMAs, statement cache, and EXPLAIN QUERY PLAN covering index usage
      const metrics = ledger.getStorageMetrics();
      assert.equal(metrics.journalMode.toLowerCase(), 'wal');
      assert.equal(metrics.busyTimeoutMs, 5000);
      assert.equal(metrics.foreignKeys, true);
      assert.ok(metrics.cachedStatements > 0);

      inspector = new DatabaseSync(dbPath, { readOnly: true });
      const journalMode = inspector.prepare('PRAGMA journal_mode').get() as {
        journal_mode: string;
      };
      assert.equal(journalMode.journal_mode.toLowerCase(), 'wal');

      const plan = inspector
        .prepare(
          'EXPLAIN QUERY PLAN SELECT tenant_id FROM evidence_receipts WHERE analysis_id = ? LIMIT 1'
        )
        .all('analysis-batch-01') as Array<{ detail: string }>;
      const planText = plan.map((p) => p.detail).join(' | ');
      assert.match(
        planText,
        /USING COVERING INDEX idx_receipts_analysis_tenant/i
      );
      assert.equal(/SCAN (TABLE )?evidence_receipts/i.test(planText), false);
    } finally {
      inspector?.close();
      ledger?.close();
      fs.rmSync(tmpDir, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 50,
      });
    }
  });
});
