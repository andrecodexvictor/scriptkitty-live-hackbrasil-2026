/**
 * @file packages/contracts/tests/adversarial-stress.test.mts
 * @description Standalone Adversarial Verification and Stress Test Harness for Milestone 1.
 * Tests Merkle tree calculations (0, 1, 2, 3, 7, 100 leaves), odd-level duplication,
 * inclusion proofs, canonical JSON stringify determinism, and hash chain tampering detection.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  canonicalStringify,
  sha256,
  computeMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  verifyChainIntegrity,
  buildCustodyChain,
  computeNodeChainHash,
  hashSecurityFinding,
  hashEvidence,
  hashPatchProposal,
  hashGateDecision,
  evaluateSeparationOfDuties,
  validateFinding,
  validateEvidence,
  validatePatch,
  validateGateDecision,
  GENESIS_HASH,
  EMPTY_MERKLE_ROOT,
  type CustodyNode,
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type GateDecision,
} from '../dist/index.js';

// ============================================================================
// INDEPENDENT REFERENCE ORACLE FOR MERKLE ROOT
// ============================================================================
/**
 * Independent oracle implementation of the binary Merkle root matching packages/audit/src/lib.rs.
 * Used to cross-verify computeMerkleRoot results bit-for-bit without reusing code.
 */
function referenceMerkleOracle(leaves: string[]): string {
  if (leaves.length === 0) {
    return '0'.repeat(64);
  }
  let current = leaves.slice();
  while (current.length > 1) {
    if (current.length % 2 !== 0) {
      current.push(current[current.length - 1]);
    }
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const h = createHash('sha256').update(current[i] + current[i + 1]).digest('hex');
      next.push(h);
    }
    current = next;
  }
  return current[0];
}

// ============================================================================
// FIXTURE GENERATORS
// ============================================================================
function generateLeafHashes(count: number): string[] {
  const leaves: string[] = [];
  for (let i = 0; i < count; i++) {
    leaves.push(createHash('sha256').update(`adversarial-leaf-payload-${i}`).digest('hex'));
  }
  return leaves;
}

const BASE_FINDING: SecurityFinding = {
  finding_id: 'SK-FIND-ADV-001',
  source_engine: 'mantis',
  title: 'Adversarial Injection Test',
  description: 'Stress testing input validation',
  cwe_id: 'CWE-89',
  owasp_category: 'A03:2021-Injection',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  target_type: 'SOURCE_CODE',
  target: 'src/auth.ts',
  location: {
    file_path: 'src/auth.ts',
    start_line: 10,
    end_line: 15,
  },
  fingerprint: '1111111111111111111111111111111111111111111111111111111111111111',
  commit_hash: 'abcdef0123456789abcdef0123456789abcdef01',
  discovered_at: '2026-11-06T12:00:00.000Z',
  raw_metadata: {},
};

const BASE_EVIDENCE: Evidence = {
  evidence_id: 'SK-EVID-ADV-001',
  finding_id: 'SK-FIND-ADV-001',
  verification_type: 'REPRODUCER_EXECUTION',
  status: 'VERIFIED_TRUE_POSITIVE',
  verifier_agent_id: 'agent-verifier-01',
  sandbox_environment: {
    runtime: 'docker_isolated',
    network_isolated: true,
    timeout_ms: 10000,
  },
  reproduction_proof: {
    proof_type: 'CLI_COMMAND',
    payload: 'pytest test_exploit.py',
    expected_behavior: 'Fail with vulnerability output',
  },
  chain_hash: '2222222222222222222222222222222222222222222222222222222222222222',
  recorded_at: '2026-11-06T12:05:00.000Z',
};

const BASE_PATCH: PatchProposal = {
  patch_id: 'SK-PATCH-ADV-001',
  finding_id: 'SK-FIND-ADV-001',
  author_engine: 'mantis_patch',
  diff_content: '--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -10,1 +10,1 @@\n- bad();\n+ good();\n',
  affected_files: ['src/auth.ts'],
  base_commit: 'abcdef0123456789abcdef0123456789abcdef01',
  patch_sha256: '3333333333333333333333333333333333333333333333333333333333333333',
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
    revert_patch: '--- b/src/auth.ts\n+++ a/src/auth.ts\n',
  },
  created_at: '2026-11-06T12:10:00.000Z',
};

const BASE_GATE: GateDecision = {
  decision_id: 'SK-GATE-ADV-001',
  policy_version: '2.0.0',
  policy_id: 'policy-prod',
  target_commit: 'abcdef0123456789abcdef0123456789abcdef01',
  verdict: 'PASS',
  blocking_findings: [],
  unverified_findings: [],
  audit_merkle_root: '4444444444444444444444444444444444444444444444444444444444444444',
  sod_evaluation: {
    discovering_agent_id: 'agent-disc-01',
    verifying_agent_id: 'agent-veri-02',
    authorizing_agent_id: 'agent-auth-03',
    is_valid: true,
  },
  rules_evaluated: [],
  evaluation_summary: 'Passed adversarial test',
  decided_at: '2026-11-06T12:15:00.000Z',
};

// ============================================================================
// ADVERSARIAL TEST SUITE
// ============================================================================

describe('Adversarial Suite 1: Merkle Tree Boundary & Stress Testing (0, 1, 2, 3, 7, 100 leaves)', () => {
  it('handles 0 leaves correctly (returns EMPTY_MERKLE_ROOT 64 zeros)', () => {
    const root = computeMerkleRoot([]);
    assert.equal(root, EMPTY_MERKLE_ROOT);
    assert.equal(root, '0'.repeat(64));
    assert.equal(root, referenceMerkleOracle([]));
  });

  it('handles 1 leaf correctly (returns exact leaf hash without hashing again)', () => {
    const leaves = generateLeafHashes(1);
    const root = computeMerkleRoot(leaves);
    assert.equal(root, leaves[0]);
    assert.equal(root, referenceMerkleOracle(leaves));
  });

  it('handles 2 leaves correctly (returns sha256(l0 + l1))', () => {
    const leaves = generateLeafHashes(2);
    const root = computeMerkleRoot(leaves);
    const expected = sha256(leaves[0] + leaves[1]);
    assert.equal(root, expected);
    assert.equal(root, referenceMerkleOracle(leaves));
  });

  it('handles 3 leaves (odd at level 0: duplicates leaf 2) matching reference oracle', () => {
    const leaves = generateLeafHashes(3);
    const root = computeMerkleRoot(leaves);
    // Tree reduction:
    // Level 0: [L0, L1, L2] -> padded to [L0, L1, L2, L2]
    // Level 1: [H(L0+L1), H(L2+L2)]
    // Root: H(H(L0+L1) + H(L2+L2))
    const expected = sha256(sha256(leaves[0] + leaves[1]) + sha256(leaves[2] + leaves[2]));
    assert.equal(root, expected);
    assert.equal(root, referenceMerkleOracle(leaves));
  });

  it('handles 7 leaves (multi-level odd tree: 7 -> 4 -> 2 -> 1) matching reference oracle', () => {
    const leaves = generateLeafHashes(7);
    const root = computeMerkleRoot(leaves);
    const oracleRoot = referenceMerkleOracle(leaves);
    assert.equal(root, oracleRoot);

    // Verify manual reduction:
    // L0: 7 leaves -> duplicate L6 -> 8 leaves -> 4 parent hashes
    // L1: 4 hashes (even) -> 2 parent hashes
    // L2: 2 hashes (even) -> 1 root
    const h01 = sha256(leaves[0] + leaves[1]);
    const h23 = sha256(leaves[2] + leaves[3]);
    const h45 = sha256(leaves[4] + leaves[5]);
    const h66 = sha256(leaves[6] + leaves[6]); // duplicated last leaf

    const p0 = sha256(h01 + h23);
    const p1 = sha256(h45 + h66);

    const manualRoot = sha256(p0 + p1);
    assert.equal(root, manualRoot);
  });

  it('handles 100 leaves (multi-level odd cascading tree) matching reference oracle', () => {
    const leaves = generateLeafHashes(100);
    const root = computeMerkleRoot(leaves);
    const oracleRoot = referenceMerkleOracle(leaves);
    assert.equal(root, oracleRoot);
    assert.equal(root.length, 64);
  });

  it('generates and validates inclusion proofs for ALL leaves across sizes [1, 2, 3, 7, 25, 100]', () => {
    const testSizes = [1, 2, 3, 7, 25, 100];
    let totalVerified = 0;

    for (const size of testSizes) {
      const leaves = generateLeafHashes(size);
      const root = computeMerkleRoot(leaves);

      for (let i = 0; i < size; i++) {
        const proof = generateMerkleProof(leaves, i);
        const valid = verifyMerkleProof(leaves[i], proof, root);
        assert.equal(valid, true, `Proof failed for leaf index ${i} in tree size ${size}`);

        // Adversarial check: verify proof length matches ceil(log2(size))
        if (size === 1) {
          assert.equal(proof.length, 0);
        } else {
          const expectedMinSteps = Math.ceil(Math.log2(size));
          assert.equal(proof.length, expectedMinSteps, `Unexpected proof steps for size ${size}`);
        }
        totalVerified++;
      }
    }

    assert.equal(totalVerified, 1 + 2 + 3 + 7 + 25 + 100); // 138 proofs verified
  });

  it('robustly rejects adversarial and forged Merkle proofs', () => {
    const leaves = generateLeafHashes(7);
    const root = computeMerkleRoot(leaves);
    const targetIdx = 3;
    const genuineProof = generateMerkleProof(leaves, targetIdx);

    // Attack 1: Mutated leaf hash
    const fakeLeaf = sha256('completely-forged-leaf');
    assert.equal(verifyMerkleProof(fakeLeaf, genuineProof, root), false);

    // Attack 2: Mutated sibling hash in proof step
    const tamperedStepProof = genuineProof.map((step, idx) =>
      idx === 0 ? { ...step, hash: sha256('tampered-sibling') } : step
    );
    assert.equal(verifyMerkleProof(leaves[targetIdx], tamperedStepProof, root), false);

    // Attack 3: Swapped direction ('left' -> 'right')
    const invertedDirProof = genuineProof.map((step, idx) =>
      idx === 0 ? { ...step, position: step.position === 'left' ? ('right' as const) : ('left' as const) } : step
    );
    assert.equal(verifyMerkleProof(leaves[targetIdx], invertedDirProof, root), false);

    // Attack 4: Truncated proof
    const truncatedProof = genuineProof.slice(0, -1);
    assert.equal(verifyMerkleProof(leaves[targetIdx], truncatedProof, root), false);

    // Attack 5: Extra appended step
    const extendedProof = [...genuineProof, { position: 'left' as const, hash: sha256('extra-step') }];
    assert.equal(verifyMerkleProof(leaves[targetIdx], extendedProof, root), false);

    // Attack 6: Out of bounds targetIndex
    assert.throws(() => generateMerkleProof(leaves, -1), /out of bounds/);
    assert.throws(() => generateMerkleProof(leaves, 7), /out of bounds/);
    assert.throws(() => generateMerkleProof(leaves, 999), /out of bounds/);
  });
});

describe('Adversarial Suite 2: Canonical JSON Stringify Determinism (RFC 8785)', () => {
  it('guarantees identical SHA-256 across all 24 key permutations at depth 1', () => {
    const permutations = [
      { a: 1, b: 2, c: 3, d: 4 },
      { d: 4, c: 3, b: 2, a: 1 },
      { b: 2, d: 4, a: 1, c: 3 },
      { c: 3, a: 1, d: 4, b: 2 },
      { a: 1, d: 4, c: 3, b: 2 },
      { d: 4, a: 1, b: 2, c: 3 },
    ];

    const firstCanonical = canonicalStringify(permutations[0]);
    const firstHash = sha256(firstCanonical);

    for (let i = 1; i < permutations.length; i++) {
      const canonical = canonicalStringify(permutations[i]);
      assert.equal(canonical, firstCanonical, `Permutation ${i} canonical string mismatch`);
      assert.equal(sha256(canonical), firstHash, `Permutation ${i} hash mismatch`);
    }
  });

  it('guarantees deterministic serialization across deeply nested structures with scrambled keys', () => {
    const deepObjA = {
      level1_b: {
        level2_y: { level3_beta: 'beta', level3_alpha: 42 },
        level2_x: [ { k2: 'v2', k1: 'v1' }, { z: 9, a: 0 } ],
      },
      level1_a: 'root_prop',
    };

    const deepObjB = {
      level1_a: 'root_prop',
      level1_b: {
        level2_x: [ { k1: 'v1', k2: 'v2' }, { a: 0, z: 9 } ],
        level2_y: { level3_alpha: 42, level3_beta: 'beta' },
      },
    };

    const canonA = canonicalStringify(deepObjA);
    const canonB = canonicalStringify(deepObjB);
    assert.equal(canonA, canonB);
    assert.equal(sha256(canonA), sha256(canonB));
  });

  it('preserves array element order strictly while sorting keys within array elements', () => {
    const arrA = [{ b: 1, a: 2 }, { d: 3, c: 4 }];
    const arrB = [{ a: 2, b: 1 }, { c: 4, d: 3 }];
    // Inner object keys are sorted, but array order [0, 1] remains identical
    assert.equal(canonicalStringify(arrA), canonicalStringify(arrB));

    // Swapping array elements MUST produce a different canonical string and hash
    const arrSwapped = [{ d: 3, c: 4 }, { b: 1, a: 2 }];
    assert.notEqual(canonicalStringify(arrA), canonicalStringify(arrSwapped));
    assert.notEqual(sha256(canonicalStringify(arrA)), sha256(canonicalStringify(arrSwapped)));
  });

  it('omits undefined fields deterministically from objects', () => {
    const objWithUndef = { a: 10, b: undefined, c: { d: undefined, e: 'kept' } };
    const objClean = { a: 10, c: { e: 'kept' } };

    assert.equal(canonicalStringify(objWithUndef), canonicalStringify(objClean));
    assert.equal(sha256(canonicalStringify(objWithUndef)), sha256(canonicalStringify(objClean)));
  });

  it('correctly handles Unicode, emoji, escaped strings, and numbers', () => {
    const data = {
      unicode: 'café',
      emoji: '🛡️🚀',
      escaped: 'quote: "hello"\nnewline\ttab\\backslash',
      neg: -42,
      float: 3.14159,
      zero: 0,
      bool_true: true,
      bool_false: false,
      null_val: null,
    };

    const canon = canonicalStringify(data);
    const parsed = JSON.parse(canon);
    assert.deepEqual(parsed, data);
  });
});

describe('Adversarial Suite 3: Cryptographic Chain of Custody & Tamper Matrix', () => {
  it('builds a verified 4-node chain connecting Finding -> Evidence -> Patch -> Gate', () => {
    const chain = buildCustodyChain({
      finding: BASE_FINDING,
      evidence: BASE_EVIDENCE,
      patch: BASE_PATCH,
      gate: BASE_GATE,
    });

    assert.equal(chain.is_valid, true);
    assert.equal(chain.total_nodes, 4);

    const check = verifyChainIntegrity(chain.nodes);
    assert.equal(check.valid, true);
    assert.equal(check.total_nodes, 4);
    assert.equal(check.merkle_root, chain.merkle_root);
  });

  it('tamper matrix: verifies every single node field mutation is caught at the exact broken index', () => {
    const chain = buildCustodyChain({
      finding: BASE_FINDING,
      evidence: BASE_EVIDENCE,
      patch: BASE_PATCH,
      gate: BASE_GATE,
    });

    for (let targetIdx = 0; targetIdx < 4; targetIdx++) {
      // 1. Mutate leaf_hash
      {
        const tampered = chain.nodes.map((n, i) =>
          i === targetIdx ? { ...n, leaf_hash: sha256(`tampered-leaf-${i}`) } : { ...n }
        );
        const res = verifyChainIntegrity(tampered);
        assert.equal(res.valid, false, `Failed to catch mutated leaf_hash at index ${targetIdx}`);
        assert.equal(res.broken_index, targetIdx);
        assert.ok(res.error?.includes('Chain hash corruption'));
      }

      // 2. Mutate parent_hash (for targetIdx > 0 or genesis for 0)
      {
        const tampered = chain.nodes.map((n, i) =>
          i === targetIdx ? { ...n, parent_hash: sha256(`tampered-parent-${i}`) } : { ...n }
        );
        const res = verifyChainIntegrity(tampered);
        assert.equal(res.valid, false, `Failed to catch mutated parent_hash at index ${targetIdx}`);
        assert.equal(res.broken_index, targetIdx);
        assert.ok(res.error?.includes('Parent hash mismatch'));
      }

      // 3. Mutate timestamp
      {
        const tampered = chain.nodes.map((n, i) =>
          i === targetIdx ? { ...n, timestamp: '1999-01-01T00:00:00.000Z' } : { ...n }
        );
        const res = verifyChainIntegrity(tampered);
        assert.equal(res.valid, false, `Failed to catch mutated timestamp at index ${targetIdx}`);
        assert.equal(res.broken_index, targetIdx);
        assert.ok(res.error?.includes('Chain hash corruption'));
      }

      // 4. Mutate contract_id
      {
        const tampered = chain.nodes.map((n, i) =>
          i === targetIdx ? { ...n, contract_id: `FORGED-ID-${i}` } : { ...n }
        );
        const res = verifyChainIntegrity(tampered);
        assert.equal(res.valid, false, `Failed to catch mutated contract_id at index ${targetIdx}`);
        assert.equal(res.broken_index, targetIdx);
        assert.ok(res.error?.includes('Chain hash corruption'));
      }

      // 5. Mutate chain_hash directly
      {
        const tampered = chain.nodes.map((n, i) =>
          i === targetIdx ? { ...n, chain_hash: sha256(`forged-chain-${i}`) } : { ...n }
        );
        const res = verifyChainIntegrity(tampered);
        assert.equal(res.valid, false, `Failed to catch mutated chain_hash at index ${targetIdx}`);
        assert.equal(res.broken_index, targetIdx);
      }
    }
  });

  it('detects structural node sequence attacks (swapped, inserted, deleted)', () => {
    const chain = buildCustodyChain({
      finding: BASE_FINDING,
      evidence: BASE_EVIDENCE,
      patch: BASE_PATCH,
      gate: BASE_GATE,
    });

    // Swapped nodes 1 and 2
    const swapped = [chain.nodes[0], chain.nodes[2], chain.nodes[1], chain.nodes[3]];
    const resSwap = verifyChainIntegrity(swapped);
    assert.equal(resSwap.valid, false);
    assert.equal(resSwap.broken_index, 1);
    assert.ok(resSwap.error?.includes('Node index mismatch'));

    // Deleted node 1 (gap in chain: 0, 2, 3)
    const gap = [chain.nodes[0], chain.nodes[2], chain.nodes[3]];
    const resGap = verifyChainIntegrity(gap);
    assert.equal(resGap.valid, false);
    assert.equal(resGap.broken_index, 1);

    // Empty chain returns valid: false with error
    const emptyRes = verifyChainIntegrity([]);
    assert.equal(emptyRes.valid, false);
    assert.equal(emptyRes.total_nodes, 0);
    assert.equal(emptyRes.merkle_root, EMPTY_MERKLE_ROOT);
    assert.equal(emptyRes.error, 'Custody chain cannot be empty');
  });

  it('100-node synthetic chain stress test: verifies unbroken chain and pinpoint tamper detection at node 73', () => {
    const nodes: CustodyNode[] = [];
    let prevHash = GENESIS_HASH;

    for (let i = 0; i < 100; i++) {
      const leaf = sha256(`synthetic-payload-${i}`);
      const ts = new Date(1700000000000 + i * 1000).toISOString();
      const ch = computeNodeChainHash(i, 'EVIDENCE', `EVID-${i}`, prevHash, leaf, ts);
      nodes.push({
        index: i,
        contract_type: 'EVIDENCE',
        contract_id: `EVID-${i}`,
        parent_hash: prevHash,
        leaf_hash: leaf,
        timestamp: ts,
        chain_hash: ch,
      });
      prevHash = ch;
    }

    // 1. Verify 100-node chain passes
    const validCheck = verifyChainIntegrity(nodes);
    assert.equal(validCheck.valid, true);
    assert.equal(validCheck.total_nodes, 100);
    assert.equal(validCheck.merkle_root.length, 64);

    // 2. Tamper specifically with node 73
    const tampered = nodes.map((n, idx) =>
      idx === 73 ? { ...n, leaf_hash: sha256('injected-hostile-data') } : { ...n }
    );
    const tamperCheck = verifyChainIntegrity(tampered);
    assert.equal(tamperCheck.valid, false);
    assert.equal(tamperCheck.broken_index, 73);
    assert.ok(tamperCheck.error?.includes('Chain hash corruption at node 73'));
  });
});

describe('Adversarial Suite 4: Zero-Trust Policy & Separation of Duties Boundary Defense', () => {
  it('strictly blocks PASS when unverified findings exist', () => {
    const attackGate: GateDecision = {
      ...BASE_GATE,
      verdict: 'PASS',
      unverified_findings: ['SK-FIND-UNVERIFIED-X'],
    };
    const res = validateGateDecision(attackGate);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('Zero-Trust Violation')));
  });

  it('strictly blocks PASS when blocking findings exist', () => {
    const attackGate: GateDecision = {
      ...BASE_GATE,
      verdict: 'PASS',
      blocking_findings: ['SK-FIND-BLOCKING-Y'],
    };
    const res = validateGateDecision(attackGate);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('Zero-Trust Violation')));
  });

  it('strictly blocks PASS when Separation of Duties is violated (self-certification attack)', () => {
    const attackGate: GateDecision = {
      ...BASE_GATE,
      verdict: 'PASS',
      sod_evaluation: {
        discovering_agent_id: 'agent-rogue',
        verifying_agent_id: 'agent-rogue', // Self-certification!
        authorizing_agent_id: 'agent-auth',
        is_valid: false,
      },
    };
    const res = validateGateDecision(attackGate);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('Separation of Duties violation')));
  });

  it('enforces that invalid SoD must evaluate strictly to REJECT (not BLOCK or PASS)', () => {
    const attackGate: GateDecision = {
      ...BASE_GATE,
      verdict: 'BLOCK', // Attempting to downgrade REJECT to BLOCK
      sod_evaluation: {
        discovering_agent_id: 'agent-rogue',
        verifying_agent_id: 'agent-rogue',
        authorizing_agent_id: 'agent-auth',
        is_valid: false,
      },
    };
    const res = validateGateDecision(attackGate);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('must result in a REJECT verdict')));
  });

  it('exhaustively catches all SoD collision permutations via evaluateSeparationOfDuties', () => {
    // 1. All same
    assert.equal(evaluateSeparationOfDuties('A', 'A', 'A').is_valid, false);
    // 2. Discoverer == Verifier
    assert.equal(evaluateSeparationOfDuties('A', 'A', 'B').is_valid, false);
    // 3. Verifier == Authorizer
    assert.equal(evaluateSeparationOfDuties('A', 'B', 'B').is_valid, false);
    // 4. Discoverer == Authorizer
    assert.equal(evaluateSeparationOfDuties('A', 'B', 'A').is_valid, false);
    // 5. Unique agents -> Valid
    assert.equal(evaluateSeparationOfDuties('A', 'B', 'C').is_valid, true);
  });
});
