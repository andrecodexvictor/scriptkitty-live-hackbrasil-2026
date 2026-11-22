/**
 * @file packages/contracts/tests/adversarial-challenge.test.mts
 * @description Adversarial Challenge Test Harness for ScriptKitty 2.0 Core Contracts.
 * Stress-tests Zero-Trust Invariants, Separation of Duties (Tri-Party checks),
 * Input Preprocessing, Schema Injection, Boundary Constraints, and Cryptographic Tampering.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  validateFinding,
  parseFinding,
  validateEvidence,
  parseEvidence,
  validatePatch,
  parsePatch,
  validateGateDecision,
  parseGateDecision,
  verifyChainOfCustody,
  buildCustodyChain,
  canonicalStringify,
  sha256,
  computeMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  verifyChainIntegrity,
  hashSecurityFinding,
  hashEvidence,
  hashPatchProposal,
  hashGateDecision,
  computeFindingFingerprint,
  computeEvidenceChainHash,
  computePatchSha256,
  evaluateSeparationOfDuties,
  GateDecisionSchema,
  SeparationOfDutiesEvaluationSchema,
  SecurityFindingSchema,
  EvidenceSchema,
  PatchProposalSchema,
  SourceLocationSchema,
  GENESIS_HASH,
  EMPTY_MERKLE_ROOT,
  Severity,
  Confidence,
  VerificationStatus,
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type GateDecision,
} from '../dist/index.js';

// Base valid fixtures for mutation
const BASE_FINDING: SecurityFinding = {
  finding_id: 'SK-FIND-ADV-001',
  source_engine: 'mantis',
  title: 'Adversarial Test Finding',
  description: 'Test description',
  cwe_id: 'CWE-89',
  owasp_category: 'A03:2021-Injection',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  target_type: 'SOURCE_CODE',
  target: 'src/vuln.ts',
  location: {
    file_path: 'src/vuln.ts',
    start_line: 10,
    end_line: 20,
  },
  fingerprint: 'a'.repeat(64),
  commit_hash: 'b'.repeat(40),
  discovered_at: '2026-11-06T12:00:00.000Z',
  raw_metadata: {},
};

const BASE_EVIDENCE: Evidence = {
  evidence_id: 'SK-EVID-ADV-001',
  finding_id: 'SK-FIND-ADV-001',
  verification_type: 'REPRODUCER_EXECUTION',
  status: 'VERIFIED_TRUE_POSITIVE',
  verifier_agent_id: 'verifier-agent-01',
  sandbox_environment: {
    runtime: 'docker_isolated',
    network_isolated: true,
    timeout_ms: 10000,
  },
  chain_hash: 'c'.repeat(64),
  recorded_at: '2026-11-06T12:05:00.000Z',
};

const BASE_PATCH: PatchProposal = {
  patch_id: 'SK-PATCH-ADV-001',
  finding_id: 'SK-FIND-ADV-001',
  author_engine: 'patch-agent-01',
  diff_content: '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -10,1 +10,1 @@\n- bad\n+ good\n',
  affected_files: ['src/vuln.ts'],
  base_commit: 'b'.repeat(40),
  patch_sha256: 'd'.repeat(64),
  recheck_status: 'passed_clean',
  recheck_evidence_id: 'SK-EVID-ADV-001',
  blast_radius: {
    files_modified: 1,
    lines_added: 1,
    lines_deleted: 1,
    ast_impact_scope: 'LOCAL_FUNCTION',
    downstream_dependents: [],
    breaking_change_risk: 'LOW',
  },
  rollback_plan: {
    revert_patch: '--- b/src/vuln.ts\n+++ a/src/vuln.ts\n@@ -10,1 +10,1 @@\n- good\n+ bad\n',
  },
  created_at: '2026-11-06T12:10:00.000Z',
};

const BASE_GATE: GateDecision = {
  decision_id: 'SK-GATE-ADV-001',
  policy_version: '1.0.0',
  policy_id: 'zero-trust-strict',
  target_commit: 'b'.repeat(40),
  verdict: 'PASS',
  blocking_findings: [],
  unverified_findings: [],
  audit_merkle_root: 'e'.repeat(64),
  sod_evaluation: {
    discovering_agent_id: 'agent-discovery-01',
    verifying_agent_id: 'agent-verifier-02',
    authorizing_agent_id: 'agent-authorizer-03',
    is_valid: true,
  },
  rules_evaluated: [],
  evaluation_summary: 'Clean evaluation',
  decided_at: '2026-11-06T12:15:00.000Z',
};

// ============================================================================
// ADVERSARIAL CHALLENGE SUITES
// ============================================================================

describe('Adversarial Challenge 1: Zero-Trust Gate Invariants', () => {
  it('CHALLENGE 1.1: Cannot PASS with unverified findings', () => {
    const maliciousPayload = {
      ...BASE_GATE,
      verdict: 'PASS',
      unverified_findings: ['SK-FIND-UNVERIFIED-666'],
    };
    const res = validateGateDecision(maliciousPayload);
    assert.equal(res.success, false, 'Expected rejection of PASS with unverified findings');
    assert.ok(res.errors?.some((e) => e.message.includes('Zero-Trust Violation')));
  });

  it('CHALLENGE 1.2: Cannot PASS with blocking findings', () => {
    const maliciousPayload = {
      ...BASE_GATE,
      verdict: 'PASS',
      blocking_findings: ['SK-FIND-BLOCKING-666'],
    };
    const res = validateGateDecision(maliciousPayload);
    assert.equal(res.success, false, 'Expected rejection of PASS with blocking findings');
    assert.ok(res.errors?.some((e) => e.message.includes('Zero-Trust Violation')));
  });

  it('CHALLENGE 1.3: Cannot PASS with both unverified AND blocking findings', () => {
    const maliciousPayload = {
      ...BASE_GATE,
      verdict: 'PASS',
      blocking_findings: ['SK-FIND-BLOCK-1'],
      unverified_findings: ['SK-FIND-UNVERIF-1'],
    };
    const res = validateGateDecision(maliciousPayload);
    assert.equal(res.success, false);
    // Should trigger both zero-trust issues
    const messages = res.errors?.map((e) => e.message) || [];
    assert.ok(messages.some((m) => m.includes('blocking_findings exist')));
    assert.ok(messages.some((m) => m.includes('unverified_findings exist')));
  });

  it('CHALLENGE 1.4: Cannot PASS if SoD evaluation is marked invalid', () => {
    const maliciousPayload = {
      ...BASE_GATE,
      verdict: 'PASS',
      sod_evaluation: {
        discovering_agent_id: 'agent-01',
        verifying_agent_id: 'agent-01',
        authorizing_agent_id: 'agent-02',
        is_valid: false,
        violation_details: 'Self-certification attempt',
      },
    };
    const res = validateGateDecision(maliciousPayload);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('Separation of Duties violation')));
  });

  it('CHALLENGE 1.5: If SoD is invalid, verdict MUST be REJECT (cannot be BLOCK, HOLD, or REQUIRES_HUMAN_APPROVAL)', () => {
    for (const nonRejectVerdict of ['BLOCK', 'HOLD', 'REQUIRES_HUMAN_APPROVAL', 'ERROR']) {
      const maliciousPayload = {
        ...BASE_GATE,
        verdict: nonRejectVerdict,
        sod_evaluation: {
          discovering_agent_id: 'agent-01',
          verifying_agent_id: 'agent-01',
          authorizing_agent_id: 'agent-02',
          is_valid: false,
        },
      };
      const res = validateGateDecision(maliciousPayload);
      assert.equal(
        res.success,
        false,
        `Expected non-REJECT verdict ${nonRejectVerdict} on SoD violation to fail`
      );
      assert.ok(res.errors?.some((e) => e.message.includes('must result in a REJECT verdict')));
    }
  });

  it('CHALLENGE 1.6: Case normalization on verdict preserves Zero-Trust enforcement', () => {
    const maliciousPayload = {
      ...BASE_GATE,
      verdict: ' pass ', // lowercase with whitespace
      unverified_findings: ['SK-FIND-LEAK-01'],
    };
    const res = validateGateDecision(maliciousPayload);
    assert.equal(res.success, false, 'Preprocessed verdict "pass" must still trigger Zero-Trust check');
    assert.ok(res.errors?.some((e) => e.message.includes('Zero-Trust Violation')));
  });

  it('CHALLENGE 1.7: Forged sod_evaluation.is_valid=true is strictly rejected by GateDecisionSchema', () => {
    // Attack scenario: Adversary crafts a GateDecision JSON directly, passing identical agents
    // for discovery, verification, and authorization, but asserting `is_valid: true`.
    const forgedSodPayload = {
      ...BASE_GATE,
      verdict: 'PASS',
      sod_evaluation: {
        discovering_agent_id: 'omnipotent-agent',
        verifying_agent_id: 'omnipotent-agent',
        authorizing_agent_id: 'omnipotent-agent',
        is_valid: true, // FORGED ASSERTION!
      },
    };

    const res = validateGateDecision(forgedSodPayload);
    assert.equal(res.success, false, 'Expected rejection of forged SoD is_valid=true with identical agent IDs');
    assert.ok(res.errors?.some((e) => e.message.includes('Separation of Duties violation')));
  });
});

describe('Adversarial Challenge 2: Separation of Duties (Tri-Party Checks)', () => {
  it('CHALLENGE 2.1: Omnipotent Agent (d == v == a) must be strictly detected and invalidated', () => {
    const sod = evaluateSeparationOfDuties('agent-omni', 'agent-omni', 'agent-omni');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_details?.includes('E_SOD_OMNIPOTENT_AGENT'), true);
  });

  it('CHALLENGE 2.2: Self-Certification (d == v != a) must be detected and invalidated', () => {
    const sod = evaluateSeparationOfDuties('agent-discoverer', 'agent-discoverer', 'agent-authorizer');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_details?.includes('E_SOD_SELF_CERTIFICATION'), true);
  });

  it('CHALLENGE 2.3: Self-Authorization (d != v == a) must be detected and invalidated', () => {
    const sod = evaluateSeparationOfDuties('agent-discoverer', 'agent-verifier', 'agent-verifier');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_details?.includes('E_SOD_SELF_AUTHORIZATION'), true);
  });

  it('CHALLENGE 2.4: Discoverer-Authorization (d == a != v) must be detected and invalidated', () => {
    const sod = evaluateSeparationOfDuties('agent-dual', 'agent-verifier', 'agent-dual');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_details?.includes('E_SOD_DISCOVERER_AUTHORIZATION'), true);
  });

  it('CHALLENGE 2.5: Trimming whitespace around agent IDs prevents evasion', () => {
    const sod = evaluateSeparationOfDuties('  agent-01  ', 'agent-01\t', ' \nagent-01 ');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_details?.includes('E_SOD_OMNIPOTENT_AGENT'), true);
  });

  it('CHALLENGE 2.6: Case-sensitivity evasion prevention (agent-01 vs AGENT-01)', () => {
    const sod = evaluateSeparationOfDuties('agent-01', 'AGENT-01', 'agent-02');
    assert.equal(sod.is_valid, false, 'Case-insensitive matching must reject identical agents differing only by case');
    assert.ok(sod.violation_details?.includes('E_SOD_SELF_CERTIFICATION'));
  });

  it('CHALLENGE 2.7: Valid tri-party distinct agents succeed', () => {
    const sod = evaluateSeparationOfDuties('agent-alpha', 'agent-beta', 'agent-gamma');
    assert.equal(sod.is_valid, true);
    assert.equal(sod.violation_details, undefined);
  });
});

describe('Adversarial Challenge 3: Input Preprocessing & Schema Injection', () => {
  it('CHALLENGE 3.1: Prototype Pollution attack resilience', () => {
    // Attempt prototype pollution via raw JSON payload
    const maliciousJson = JSON.parse(
      '{"__proto__":{"polluted":true},"location":{"__proto__":{"pollutedNested":true}}}'
    );

    // Run through parsers
    try {
      validateFinding({ ...BASE_FINDING, ...maliciousJson });
    } catch (_) {}

    try {
      validateGateDecision({ ...BASE_GATE, ...maliciousJson });
    } catch (_) {}

    try {
      canonicalStringify(maliciousJson);
    } catch (_) {}

    // Verify global Object prototype was not contaminated
    assert.equal((Object.prototype as any).polluted, undefined, 'Object.prototype must not be polluted');
    assert.equal((Object.prototype as any).pollutedNested, undefined, 'Object.prototype must not have nested pollution');
  });

  it('CHALLENGE 3.2: Rejection of negative, zero, and floating line numbers', () => {
    // Negative start line
    const negStart = {
      ...BASE_FINDING,
      location: { file_path: 'src/main.ts', start_line: -1, end_line: 10 },
    };
    assert.equal(validateFinding(negStart).success, false);

    // Zero start line (locations are 1-indexed)
    const zeroStart = {
      ...BASE_FINDING,
      location: { file_path: 'src/main.ts', start_line: 0, end_line: 10 },
    };
    assert.equal(validateFinding(zeroStart).success, false);

    // Negative end line
    const negEnd = {
      ...BASE_FINDING,
      location: { file_path: 'src/main.ts', start_line: 5, end_line: -5 },
    };
    assert.equal(validateFinding(negEnd).success, false);

    // Floating point line numbers
    const floatLine = {
      ...BASE_FINDING,
      location: { file_path: 'src/main.ts', start_line: 1.5, end_line: 10.2 },
    };
    assert.equal(validateFinding(floatLine).success, false);
  });

  it('CHALLENGE 3.3: Rejection of reversed start/end lines', () => {
    const reversedLines = {
      ...BASE_FINDING,
      location: { file_path: 'src/main.ts', start_line: 100, end_line: 50 },
    };
    const res = validateFinding(reversedLines);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('greater than or equal to start_line')));
  });

  it('CHALLENGE 3.4: Rejection of malformed CWE identifiers and injection attempts', () => {
    const invalidCwes = [
      'CWE',
      'CWE-',
      'CWE-ABC',
      'SQL_INJECTION',
      'CWE-89; DROP TABLE users;--',
      'CWE-89\nCWE-78',
      '../CWE-89',
      'CWE- 89',
    ];

    for (const cwe of invalidCwes) {
      const res = validateFinding({ ...BASE_FINDING, cwe_id: cwe });
      assert.equal(res.success, false, `Expected invalid CWE "${cwe}" to fail validation`);
    }
  });

  it('CHALLENGE 3.5: OWASP Category syntax validation & injection defense', () => {
    const invalidOwasp = [
      'INJECTION',
      'A03',
      '<script>alert(1)</script>',
      'A03:2021',
      'OWASP-TOP-10',
    ];

    for (const cat of invalidOwasp) {
      const res = validateFinding({ ...BASE_FINDING, owasp_category: cat });
      assert.equal(res.success, false, `Expected invalid OWASP category "${cat}" to fail validation`);
    }
  });

  it('CHALLENGE 3.6: Rejection of invalid commit hashes', () => {
    const invalidCommits = [
      'abc', // Too short (min 7)
      'g'.repeat(40), // Invalid hex character 'g'
      '1'.repeat(65), // Too long (max 64)
      '../../etc/shadow', // Path traversal payload
    ];

    for (const commit of invalidCommits) {
      const res = validateFinding({ ...BASE_FINDING, commit_hash: commit });
      assert.equal(res.success, false, `Expected invalid commit hash "${commit}" to fail validation`);
    }
  });

  it('CHALLENGE 3.7: PatchProposal negative blast radius rejection', () => {
    const negativeRadius = {
      ...BASE_PATCH,
      blast_radius: {
        files_modified: -1,
        lines_added: -5,
        lines_deleted: -10,
        ast_impact_scope: 'LOCAL_FUNCTION',
        downstream_dependents: [],
        breaking_change_risk: 'LOW',
      },
    };
    const res = validatePatch(negativeRadius);
    assert.equal(res.success, false);
  });

  it('CHALLENGE 3.8: PatchProposal empty revert patch rejection', () => {
    const emptyRevert = {
      ...BASE_PATCH,
      rollback_plan: {
        revert_patch: '',
      },
    };
    const res = validatePatch(emptyRevert);
    assert.equal(res.success, false);
  });

  it('CHALLENGE 3.9: PatchProposal passed_clean without recheck evidence rejection', () => {
    const noEvidence = {
      ...BASE_PATCH,
      recheck_status: 'passed_clean',
      recheck_evidence_id: null,
    };
    const res = validatePatch(noEvidence);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('recheck_evidence_id is required')));
  });

  it('CHALLENGE 3.10: Oversized payload stress test (1MB diff content)', () => {
    const largeDiff = '--- a/test.ts\n+++ b/test.ts\n' + '+ line added\n'.repeat(50000);
    const patchWithLargeDiff = {
      ...BASE_PATCH,
      diff_content: largeDiff,
    };
    const res = validatePatch(patchWithLargeDiff);
    assert.equal(res.success, true);
    assert.ok(res.data?.diff_content.length! > 500000);
  });

  it('CHALLENGE 3.11: PatchProposal accepts harmonized finding_id identifiers', () => {
    const patchWithExternalId = {
      ...BASE_PATCH,
      finding_id: 'MANTIS-FIND-001:sub',
    };
    const res = validatePatch(patchWithExternalId);
    assert.equal(res.success, true);
    assert.equal(res.data?.finding_id, 'MANTIS-FIND-001:sub');
  });
});

describe('Adversarial Challenge 4: Cryptographic Tampering & Custody Invariants', () => {
  it('CHALLENGE 4.1: Tampered leaf hash in custody chain is caught at exact index', () => {
    const chain = buildCustodyChain({
      finding: BASE_FINDING,
      evidence: BASE_EVIDENCE,
      patch: BASE_PATCH,
      gate: BASE_GATE,
    });

    // Tamper Node 2 (Patch)
    const tampered = JSON.parse(JSON.stringify(chain.nodes));
    tampered[2].leaf_hash = 'f'.repeat(64);

    const check = verifyChainIntegrity(tampered);
    assert.equal(check.valid, false);
    assert.equal(check.broken_index, 2);
    assert.ok(check.error?.includes('Chain hash corruption'));
  });

  it('CHALLENGE 4.2: Tampered parent hash breaking genesis linkage is caught at Node 0', () => {
    const chain = buildCustodyChain({
      finding: BASE_FINDING,
      evidence: BASE_EVIDENCE,
    });

    const tampered = JSON.parse(JSON.stringify(chain.nodes));
    tampered[0].parent_hash = 'f'.repeat(64);

    const check = verifyChainIntegrity(tampered);
    assert.equal(check.valid, false);
    assert.equal(check.broken_index, 0);
    assert.ok(check.error?.includes('Parent hash mismatch'));
  });

  it('CHALLENGE 4.3: Merkle proof forged sibling hash rejection', () => {
    const leaves = ['a', 'b', 'c', 'd'].map(sha256);
    const root = computeMerkleRoot(leaves);
    const validProof = generateMerkleProof(leaves, 1);

    // Tamper one sibling in the proof
    const tamperedProof = [{ position: validProof[0].position, hash: sha256('evil-sibling') }];
    const verified = verifyMerkleProof(leaves[1], tamperedProof, root);
    assert.equal(verified, false, 'Tampered Merkle proof must not verify against root');
  });

  it('CHALLENGE 4.4: Canonical serialization key-order invariance with nested structures', () => {
    const obj1 = {
      z: [3, 2, 1],
      a: { nestedB: 'b', nestedA: 'a' },
      m: { x: 1, y: null, z: true },
    };
    const obj2 = {
      m: { z: true, x: 1, y: null },
      a: { nestedA: 'a', nestedB: 'b' },
      z: [3, 2, 1],
    };

    assert.equal(canonicalStringify(obj1), canonicalStringify(obj2));
    assert.equal(sha256(canonicalStringify(obj1)), sha256(canonicalStringify(obj2)));
  });

  it('CHALLENGE 4.5: verifyChainOfCustody rejects chain when merkle_root is tampered', () => {
    const chain = buildCustodyChain({
      finding: BASE_FINDING,
      evidence: BASE_EVIDENCE,
    });
    const tamperedChain = { ...chain, merkle_root: sha256('fraudulent-merkle-root') };
    const res = verifyChainOfCustody(tamperedChain);
    assert.equal(res.valid, false);
    assert.ok(res.error?.includes('Merkle root mismatch'));
  });

  it('CHALLENGE 4.6: Empty custody chain is strictly rejected', () => {
    const res = verifyChainIntegrity([]);
    assert.equal(res.valid, false);
    assert.equal(res.error, 'Custody chain cannot be empty');

    const resChain = verifyChainOfCustody({ nodes: [] } as any);
    assert.equal(resChain.valid, false);
    assert.ok(resChain.error?.includes('Custody chain cannot be empty'));
  });

  it('CHALLENGE 4.7: Delimiter collision resistance in computeEvidenceChainHash', () => {
    const h1 = computeEvidenceChainHash({
      finding_id: 'FIND:A',
      verifier_agent_id: 'B',
      status: 'VERIFIED_TRUE_POSITIVE',
      script_sha256: '0'.repeat(64),
      recorded_at: '2026-01-01T00:00:00.000Z',
    });
    const h2 = computeEvidenceChainHash({
      finding_id: 'FIND',
      verifier_agent_id: 'A:B',
      status: 'VERIFIED_TRUE_POSITIVE',
      script_sha256: '0'.repeat(64),
      recorded_at: '2026-01-01T00:00:00.000Z',
    });
    assert.notEqual(h1, h2, 'Hashes for distinct finding_id and verifier_agent_id must not collide');
  });

  it('CHALLENGE 4.8: canonicalStringify correctly serializes Date objects and undefined in arrays', () => {
    const dateObj = new Date('2026-11-06T12:00:00.000Z');
    assert.equal(canonicalStringify(dateObj), '"2026-11-06T12:00:00.000Z"');
    assert.equal(canonicalStringify([1, undefined, 3]), '[1,null,3]');
  });
});
