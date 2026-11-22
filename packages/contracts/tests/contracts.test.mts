/**
 * @file packages/contracts/tests/contracts.test.mts
 * @description Comprehensive Unit Test Suite for ScriptKitty 2.0 Core Contracts.
 * Tests serialization, invalid rejection, schema edge cases, hash chaining,
 * separation of duties, and binary Merkle tree calculations.
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

// ============================================================================
// FIXTURES
// ============================================================================
const VALID_FINDING_APPSEC: SecurityFinding = {
  finding_id: 'SK-FIND-9281a4b2-0193-4812-a128-48291048201a',
  source_engine: 'mantis',
  title: 'Unsanitized SQL Query in User Lookup Endpoint',
  description: 'User input from req.query.id concatenated directly into query',
  cwe_id: 'CWE-89',
  owasp_category: 'A03:2021-Injection',
  severity: 'CRITICAL',
  confidence: 'CERTAIN',
  target_type: 'SOURCE_CODE',
  target: 'src/api/users.ts',
  location: {
    file_path: 'src/api/users.ts',
    start_line: 42,
    end_line: 42,
    start_column: 12,
    end_column: 68,
    symbol: 'findUserById',
  },
  fingerprint: '8f48a1b5d634289a0123456789abcdef8899aabbccddeeff0011223344556677',
  commit_hash: 'a1b2c3d4e5f67890123456789abcdef012345678',
  discovered_at: '2026-11-06T14:10:00.000Z',
  agent_context: {
    discovering_agent_id: 'agent-scanner-mantis-01',
    agent_archetype: 'mantis_explorer',
    session_id: 'sess-discovery-8812',
    tool_call_trace: ['scout_target', 'ast_grep_taint'],
    reasoning_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  raw_metadata: {},
};

const VALID_FINDING_AGENTSEC: SecurityFinding = {
  finding_id: 'SK-FIND-AGENTSEC-001',
  source_engine: 'builtin',
  title: 'Unbounded Shell Execution via MCP Tool execute_command',
  description: 'Agent prompted with indirect injection executed unconstrained shell command',
  cwe_id: 'CWE-78',
  owasp_category: 'LLM07:2025-Insecure Tool Design',
  severity: 'CRITICAL',
  confidence: 'CERTAIN',
  target_type: 'MCP_TOOL',
  target: 'execute_command',
  location: {
    file_path: 'apps/mcp-server/src/index.ts',
    start_line: 98,
    end_line: 110,
    symbol: 'CallToolRequestSchema.execute_command',
  },
  fingerprint: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
  commit_hash: '99887766554433221100aabbccddeeff11223344',
  discovered_at: '2026-11-06T14:20:00.000Z',
  agent_sec: {
    mcp_tool_name: 'execute_command',
    taint_source: 'rag_document',
    taint_id: 'T-992',
    injection_vector: 'confused_deputy',
    affected_parameter: 'command',
    blocked_by_guardrail: false,
  },
  raw_metadata: {},
};

const VALID_EVIDENCE: Evidence = {
  evidence_id: 'SK-EVID-10293847-5647-3829-1029-485720194829',
  finding_id: 'SK-FIND-9281a4b2-0193-4812-a128-48291048201a',
  verification_type: 'REPRODUCER_EXECUTION',
  status: 'VERIFIED_TRUE_POSITIVE',
  verifier_agent_id: 'agent-verifier-pytest-02',
  sandbox_environment: {
    runtime: 'docker_isolated',
    network_isolated: true,
    timeout_ms: 30000,
    container_image_digest: 'sha256:sandbox-runner-node24-safe',
    os_platform: 'linux-x86_64',
  },
  reproduction_proof: {
    proof_type: 'EXECUTABLE_POC',
    payload: "curl 'http://localhost:3000/api/v1/users?id=1%27%20OR%201=1--'",
    expected_behavior: 'HTTP 400 Bad Request or single user object',
    observed_vulnerable_behavior: 'HTTP 200 with complete database dump',
  },
  reproducer_artifact: {
    script_path: 'workspace/poc_reproduce.ts',
    script_sha256: '4a123f890123456789abcdef0123456789abcdef0123456789abcdef01234567',
    exit_code: 1,
    stdout: 'FAILED: SQL syntax error leaked in response',
    stderr: '',
    execution_duration_ms: 420,
  },
  chain_hash: '99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788',
  recorded_at: '2026-11-06T14:12:00.000Z',
};

const VALID_PATCH: PatchProposal = {
  patch_id: 'SK-PATCH-44556677-8899-aabb-ccdd-eeff00112233',
  finding_id: 'SK-FIND-9281a4b2-0193-4812-a128-48291048201a',
  author_engine: 'mantis_patch',
  diff_content: '--- a/src/api/users.ts\n+++ b/src/api/users.ts\n@@ -41,3 +41,3 @@\n-  const query = `SELECT * FROM users WHERE id = \'${req.query.id}\'`;\n+  const result = await db(\'users\').where({ id: req.query.id }).first();\n',
  affected_files: ['src/api/users.ts'],
  base_commit: 'a1b2c3d4e5f67890123456789abcdef012345678',
  patch_sha256: '33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122',
  recheck_status: 'passed_clean',
  recheck_evidence_id: 'SK-EVID-10293847-5647-3829-1029-485720194829',
  blast_radius: {
    files_modified: 1,
    lines_added: 1,
    lines_deleted: 2,
    ast_impact_scope: 'LOCAL_FUNCTION',
    downstream_dependents: ['src/api/router.ts'],
    breaking_change_risk: 'LOW',
  },
  rollback_plan: {
    revert_patch: '--- b/src/api/users.ts\n+++ a/src/api/users.ts\n@@ -41,3 +41,3 @@\n-  const result = await db(\'users\').where({ id: req.query.id }).first();\n+  const query = `SELECT * FROM users WHERE id = \'${req.query.id}\'`;\n',
    killswitch_flag: 'FEATURE_PARAMETRIZED_USER_LOOKUP',
  },
  created_at: '2026-11-06T14:15:00.000Z',
};

const VALID_GATE_DECISION: GateDecision = {
  decision_id: 'SK-GATE-99001122-3344-5566-7788-99aabbccddee',
  policy_version: '2.0.0',
  policy_id: 'policy-zero-trust-prod-v2',
  target_commit: 'a1b2c3d4e5f67890123456789abcdef012345678',
  verdict: 'PASS',
  blocking_findings: [],
  unverified_findings: [],
  audit_merkle_root: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  sod_evaluation: {
    discovering_agent_id: 'agent-scanner-mantis-01',
    verifying_agent_id: 'agent-verifier-pytest-02',
    authorizing_agent_id: 'agent-auth-quality-gate-04',
    is_valid: true,
  },
  rules_evaluated: [
    { rule_id: 'RULE_REPRODUCTION_VERIFIED', status: 'PASS', reason: 'PoC confirmed vulnerability' },
    { rule_id: 'RULE_SEPARATION_OF_DUTIES', status: 'PASS', reason: 'Disc != Veri != Auth' },
  ],
  evaluation_summary: 'All zero-trust criteria satisfied',
  decided_at: '2026-11-06T14:18:00.000Z',
};

// ============================================================================
// TEST SUITES
// ============================================================================

describe('Suite 1: Contract Schema Serialization & Validation', () => {
  it('validates canonical AppSec finding with normalization', () => {
    const res = validateFinding(VALID_FINDING_APPSEC);
    assert.equal(res.success, true);
    assert.equal(res.data?.severity, Severity.CRITICAL);
    assert.equal(res.data?.confidence, Confidence.CERTAIN);
    assert.equal(res.data?.location.file_path, 'src/api/users.ts');
  });

  it('validates canonical AgentSec finding with MCP metadata', () => {
    const res = validateFinding(VALID_FINDING_AGENTSEC);
    assert.equal(res.success, true);
    assert.equal(res.data?.agent_sec?.mcp_tool_name, 'execute_command');
    assert.equal(res.data?.agent_sec?.injection_vector, 'confused_deputy');
  });

  it('validates Evidence contract with execution logs and sandbox config', () => {
    const res = validateEvidence(VALID_EVIDENCE);
    assert.equal(res.success, true);
    assert.equal(res.data?.status, VerificationStatus.VERIFIED_TRUE_POSITIVE);
    assert.equal(res.data?.sandbox_environment.network_isolated, true);
  });

  it('validates PatchProposal contract with unified diff and rollback plan', () => {
    const res = validatePatch(VALID_PATCH);
    assert.equal(res.success, true);
    assert.equal(res.data?.recheck_status, 'passed_clean');
    assert.ok(res.data?.rollback_plan.revert_patch);
  });

  it('validates GateDecision contract with zero-trust passing verdict', () => {
    const res = validateGateDecision(VALID_GATE_DECISION);
    assert.equal(res.success, true);
    assert.equal(res.data?.verdict, 'PASS');
    assert.equal(res.data?.sod_evaluation.is_valid, true);
  });

  it('accepts camelCase fixtures and normalizes to canonical snake_case', () => {
    const camelFinding = {
      findingId: 'SK-FIND-CAMEL-001',
      sourceEngine: 'mantis',
      title: 'XSS in Comment Section',
      description: 'Stored XSS via script tag in comments',
      cweId: 'CWE-79',
      owaspCategory: 'A03:2021-Injection',
      severity: 'high',
      confidence: 'medium',
      targetType: 'SOURCE_CODE',
      target: 'src/comments.ts',
      sourceLocation: {
        filePath: 'src/comments.ts',
        startLine: 15,
        endLine: 20,
      },
      fingerprint: '112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00',
      commitHash: 'abcdef0123456789abcdef0123456789abcdef01',
      discoveredAt: '2026-11-06T14:00:00.000Z',
    };

    const res = validateFinding(camelFinding);
    assert.equal(res.success, true);
    assert.equal(res.data?.finding_id, 'SK-FIND-CAMEL-001');
    assert.equal(res.data?.severity, Severity.HIGH);
    assert.equal(res.data?.confidence, Confidence.FIRM);
    assert.equal(res.data?.location.file_path, 'src/comments.ts');
  });
});

describe('Suite 2: Invalid Contract Rejection & Boundary Constraints', () => {
  it('rejects finding with invalid CWE format', () => {
    const invalid = { ...VALID_FINDING_APPSEC, cwe_id: 'SQL_INJECTION' };
    const res = validateFinding(invalid);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.path === 'cwe_id'));
  });

  it('rejects finding with inverted line bounds (end_line < start_line)', () => {
    const invalid = {
      ...VALID_FINDING_APPSEC,
      location: { ...VALID_FINDING_APPSEC.location, start_line: 50, end_line: 40 },
    };
    const res = validateFinding(invalid);
    assert.equal(res.success, false);
  });

  it('rejects finding with invalid fingerprint hex length', () => {
    const invalid = { ...VALID_FINDING_APPSEC, fingerprint: 'short-fingerprint' };
    const res = validateFinding(invalid);
    assert.equal(res.success, false);
  });

  it('rejects PatchProposal without recheck_evidence_id when status is passed_clean', () => {
    const invalid = { ...VALID_PATCH, recheck_evidence_id: null };
    const res = validatePatch(invalid);
    assert.equal(res.success, false);
  });

  it('rejects PatchProposal with empty diff content', () => {
    const invalid = { ...VALID_PATCH, diff_content: '' };
    const res = validatePatch(invalid);
    assert.equal(res.success, false);
  });

  it('rejects PatchProposal with empty affected files list', () => {
    const invalid = { ...VALID_PATCH, affected_files: [] };
    const res = validatePatch(invalid);
    assert.equal(res.success, false);
  });

  it('rejects PatchProposal with negative blast radius lines', () => {
    const invalid = {
      ...VALID_PATCH,
      blast_radius: { ...VALID_PATCH.blast_radius, lines_added: -5 },
    };
    const res = validatePatch(invalid);
    assert.equal(res.success, false);
  });

  it('rejects GateDecision PASS verdict when unverified_findings exist', () => {
    const invalid = {
      ...VALID_GATE_DECISION,
      unverified_findings: ['SK-FIND-UNVERIFIED-01'],
      verdict: 'PASS',
    };
    const res = validateGateDecision(invalid);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('Zero-Trust Violation')));
  });

  it('rejects GateDecision PASS verdict when blocking_findings exist', () => {
    const invalid = {
      ...VALID_GATE_DECISION,
      blocking_findings: ['SK-FIND-BLOCKING-01'],
      verdict: 'PASS',
    };
    const res = validateGateDecision(invalid);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('Zero-Trust Violation')));
  });

  it('rejects GateDecision PASS verdict on Separation of Duties violation', () => {
    const invalid = {
      ...VALID_GATE_DECISION,
      sod_evaluation: {
        discovering_agent_id: 'agent-01',
        verifying_agent_id: 'agent-01', // Self-certification!
        authorizing_agent_id: 'agent-02',
        is_valid: false,
      },
      verdict: 'PASS',
    };
    const res = validateGateDecision(invalid);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('Separation of Duties violation')));
  });

  it('rejects GateDecision when SoD is invalid but verdict is not REJECT', () => {
    const invalid = {
      ...VALID_GATE_DECISION,
      sod_evaluation: {
        discovering_agent_id: 'agent-01',
        verifying_agent_id: 'agent-01',
        authorizing_agent_id: 'agent-02',
        is_valid: false,
      },
      verdict: 'BLOCK',
    };
    const res = validateGateDecision(invalid);
    assert.equal(res.success, false);
    assert.ok(res.errors?.some((e) => e.message.includes('must result in a REJECT verdict')));
  });

  it('enforces tri-party Separation of Duties evaluation logic', () => {
    // 1. Omnipotent agent
    const omni = evaluateSeparationOfDuties('agent-1', 'agent-1', 'agent-1');
    assert.equal(omni.is_valid, false);
    assert.ok(omni.violation_details?.includes('E_SOD_OMNIPOTENT_AGENT'));

    // 2. Self-certification
    const selfCert = evaluateSeparationOfDuties('agent-1', 'agent-1', 'agent-2');
    assert.equal(selfCert.is_valid, false);
    assert.ok(selfCert.violation_details?.includes('E_SOD_SELF_CERTIFICATION'));

    // 3. Self-authorization
    const selfAuth = evaluateSeparationOfDuties('agent-1', 'agent-2', 'agent-2');
    assert.equal(selfAuth.is_valid, false);
    assert.ok(selfAuth.violation_details?.includes('E_SOD_SELF_AUTHORIZATION'));

    // 4. Discoverer-authorization
    const discAuth = evaluateSeparationOfDuties('agent-1', 'agent-2', 'agent-1');
    assert.equal(discAuth.is_valid, false);
    assert.ok(discAuth.violation_details?.includes('E_SOD_DISCOVERER_AUTHORIZATION'));

    // 5. Valid 3 distinct agents
    const valid = evaluateSeparationOfDuties('agent-1', 'agent-2', 'agent-3');
    assert.equal(valid.is_valid, true);
  });
});

describe('Suite 3: Canonical Serialization & Hash Stability', () => {
  it('produces identical output regardless of object key order', () => {
    const objA = { z: 1, a: { b: 2, a: 3 } };
    const objB = { a: { a: 3, b: 2 }, z: 1 };
    assert.equal(canonicalStringify(objA), canonicalStringify(objB));
    assert.equal(sha256(canonicalStringify(objA)), sha256(canonicalStringify(objB)));
  });

  it('ignores undefined values without mutating string representation', () => {
    const objA = { a: 1, b: undefined };
    const objB = { a: 1 };
    assert.equal(canonicalStringify(objA), canonicalStringify(objB));
  });

  it('correctly serializes nested arrays with primitives and objects', () => {
    const data = { items: [1, { y: 2, x: 1 }] };
    assert.equal(canonicalStringify(data), '{"items":[1,{"x":1,"y":2}]}');
  });

  it('strips self-referential hash fields during leaf hashing', () => {
    const findingWithHash = {
      ...VALID_FINDING_APPSEC,
      fingerprint: '1111111111111111111111111111111111111111111111111111111111111111',
    };
    const findingWithDifferentHash = {
      ...VALID_FINDING_APPSEC,
      fingerprint: '2222222222222222222222222222222222222222222222222222222222222222',
    };
    assert.equal(hashSecurityFinding(findingWithHash), hashSecurityFinding(findingWithDifferentHash));

    const evidenceWithHash = {
      ...VALID_EVIDENCE,
      chain_hash: '3333333333333333333333333333333333333333333333333333333333333333',
    };
    const evidenceWithDiffHash = {
      ...VALID_EVIDENCE,
      chain_hash: '4444444444444444444444444444444444444444444444444444444444444444',
    };
    assert.equal(hashEvidence(evidenceWithHash), hashEvidence(evidenceWithDiffHash));
  });

  it('computes deterministic finding fingerprint matching Quality Engine specs', () => {
    const fp1 = computeFindingFingerprint({
      cwe_id: 'CWE-89',
      file_path: 'src\\api\\users.ts',
      rule_or_match: 'SELECT * FROM users',
    });
    const fp2 = computeFindingFingerprint({
      cwe_id: 'cwe-89',
      file_path: 'src/api/users.ts',
      rule_or_match: 'SELECT * FROM users',
    });
    assert.equal(fp1, fp2);
    assert.equal(fp1.length, 64);
  });

  it('computes deterministic patch and evidence helper hashes', () => {
    const patchHash = computePatchSha256(VALID_PATCH.diff_content);
    assert.equal(patchHash.length, 64);

    const evidChain = computeEvidenceChainHash({
      finding_id: VALID_EVIDENCE.finding_id,
      verifier_agent_id: VALID_EVIDENCE.verifier_agent_id,
      status: VALID_EVIDENCE.status,
      script_sha256: VALID_EVIDENCE.reproducer_artifact?.script_sha256,
      recorded_at: VALID_EVIDENCE.recorded_at,
    });
    assert.equal(evidChain.length, 64);
  });
});

describe('Suite 4: Custody Chaining & Cryptographic Tamper Detection', () => {
  it('constructs an unbroken 4-stage custody chain', () => {
    const chain = buildCustodyChain({
      finding: VALID_FINDING_APPSEC,
      evidence: VALID_EVIDENCE,
      patch: VALID_PATCH,
      gate: VALID_GATE_DECISION,
    });

    assert.equal(chain.is_valid, true);
    assert.equal(chain.total_nodes, 4);
    assert.equal(chain.nodes[0].parent_hash, GENESIS_HASH);
    assert.equal(chain.nodes[1].parent_hash, chain.nodes[0].chain_hash);
    assert.equal(chain.nodes[2].parent_hash, chain.nodes[1].chain_hash);
    assert.equal(chain.nodes[3].parent_hash, chain.nodes[2].chain_hash);
  });

  it('detects tampering when an intermediate leaf hash is modified', () => {
    const chain = buildCustodyChain({
      finding: VALID_FINDING_APPSEC,
      evidence: VALID_EVIDENCE,
      patch: VALID_PATCH,
    });

    // Tamper Node 1
    const tamperedNodes = [...chain.nodes];
    tamperedNodes[1] = { ...tamperedNodes[1], leaf_hash: sha256('tampered_evidence') };

    const verification = verifyChainIntegrity(tamperedNodes);
    assert.equal(verification.valid, false);
    assert.equal(verification.broken_index, 1);
    assert.ok(verification.error?.includes('Chain hash corruption'));
  });

  it('detects tampering when an intermediate parent hash is modified', () => {
    const chain = buildCustodyChain({
      finding: VALID_FINDING_APPSEC,
      evidence: VALID_EVIDENCE,
      patch: VALID_PATCH,
    });

    const tamperedNodes = [...chain.nodes];
    tamperedNodes[2] = { ...tamperedNodes[2], parent_hash: sha256('fake_parent') };

    const verification = verifyChainIntegrity(tamperedNodes);
    assert.equal(verification.valid, false);
    assert.equal(verification.broken_index, 2);
    assert.ok(verification.error?.includes('Parent hash mismatch'));
  });

  it('detects tampering when node index sequence is broken', () => {
    const chain = buildCustodyChain({
      finding: VALID_FINDING_APPSEC,
      evidence: VALID_EVIDENCE,
    });

    const tamperedNodes = [...chain.nodes];
    tamperedNodes[1] = { ...tamperedNodes[1], index: 99 };

    const verification = verifyChainIntegrity(tamperedNodes);
    assert.equal(verification.valid, false);
    assert.equal(verification.broken_index, 1);
    assert.ok(verification.error?.includes('Node index mismatch'));
  });

  it('verifies chain of custody from raw contract objects via verifyChainOfCustody', () => {
    const result = verifyChainOfCustody({
      finding: VALID_FINDING_APPSEC,
      evidence: VALID_EVIDENCE,
      patch: VALID_PATCH,
      gate: VALID_GATE_DECISION,
    });
    assert.equal(result.valid, true);
    assert.equal(result.total_nodes, 4);
    assert.equal(result.merkle_root.length, 64);
  });
});

describe('Suite 5: Binary Merkle Tree Calculations & Inclusion Proofs', () => {
  it('returns 64 zeros for empty leaf set', () => {
    assert.equal(computeMerkleRoot([]), EMPTY_MERKLE_ROOT);
  });

  it('returns exact leaf hash for single-element tree', () => {
    const leaf = sha256('leaf-0');
    assert.equal(computeMerkleRoot([leaf]), leaf);
  });

  it('computes balanced 2-leaf Merkle root matching sha256(leaf0 + leaf1)', () => {
    const l0 = sha256('leaf-0');
    const l1 = sha256('leaf-1');
    assert.equal(computeMerkleRoot([l0, l1]), sha256(l0 + l1));
  });

  it('duplicates last leaf for odd 3-leaf Merkle tree', () => {
    const l0 = sha256('leaf-0');
    const l1 = sha256('leaf-1');
    const l2 = sha256('leaf-2');
    const expected = sha256(sha256(l0 + l1) + sha256(l2 + l2));
    assert.equal(computeMerkleRoot([l0, l1, l2]), expected);
  });

  it('generates and verifies valid Merkle proofs for all leaves in a 5-leaf tree', () => {
    const leaves = ['item-0', 'item-1', 'item-2', 'item-3', 'item-4'].map(sha256);
    const root = computeMerkleRoot(leaves);

    for (let i = 0; i < leaves.length; i++) {
      const proof = generateMerkleProof(leaves, i);
      const isValid = verifyMerkleProof(leaves[i], proof, root);
      assert.equal(isValid, true, `Proof verification failed for leaf index ${i}`);
    }
  });

  it('rejects Merkle proof when leaf data is tampered', () => {
    const leaves = ['item-0', 'item-1', 'item-2', 'item-3'].map(sha256);
    const root = computeMerkleRoot(leaves);
    const proof = generateMerkleProof(leaves, 0);

    const isFakeValid = verifyMerkleProof(sha256('tampered-item'), proof, root);
    assert.equal(isFakeValid, false);
  });

  it('throws error when generating proof for out of bounds index', () => {
    const leaves = ['a', 'b'].map(sha256);
    assert.throws(() => generateMerkleProof(leaves, -1), /out of bounds/);
    assert.throws(() => generateMerkleProof(leaves, 2), /out of bounds/);
  });
});
