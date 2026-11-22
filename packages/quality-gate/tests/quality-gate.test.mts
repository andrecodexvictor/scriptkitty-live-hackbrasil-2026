/**
 * @file packages/quality-gate/tests/quality-gate.test.mts
 * @description Comprehensive unit test suite for @script-kitty/quality-gate.
 * Tests Deterministic Quality Gate Zero-Trust Predicate, Tri-Party Separation of Duties,
 * fail-closed policy enforcement, tamper-evident Merkle auditing, and Quad-State verdicts.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type ChainOfCustody,
  buildCustodyChain,
  sha256,
  GateVerdict,
  EMPTY_MERKLE_ROOT,
} from '@script-kitty/contracts';

import {
  DeterministicQualityGate,
  evaluateQualityGate,
  type GateEvaluationRequest,
  parsePolicy,
  validatePolicy,
  DEFAULT_POLICY,
  insideScope,
  isTargetInScope,
  isExceptionExpired,
  evaluateExceptionsValidity,
  findMatchingException,
  validateSeparationOfDuties,
  validateAgentRoleMapping,
  SoDViolationCode,
  TamperEvidentAuditLogger,
  computeAuditMerkleRoot,
  hashAuditEvent,
} from '../dist/index.js';

// ============================================================================
// FIXTURES
// ============================================================================

const COMMIT_A = 'a1b2c3d4e5f67890123456789abcdef012345678';
const COMMIT_B = 'b1c2d3e4f5a67890123456789abcdef012345679';

const FINDING_SQLI: SecurityFinding = {
  finding_id: 'SK-FIND-SQLI-001',
  source_engine: 'mantis',
  title: 'SQL Injection in User Search API',
  description: 'Unescaped user input passed directly to raw SQL query',
  cwe_id: 'CWE-89',
  owasp_category: 'A03:2021-Injection',
  severity: 'CRITICAL',
  confidence: 'CERTAIN',
  target_type: 'SOURCE_CODE',
  target: 'src/api/search.ts',
  location: {
    file_path: 'src/api/search.ts',
    start_line: 45,
    end_line: 48,
    symbol: 'searchUsers',
  },
  fingerprint: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
  commit_hash: COMMIT_A,
  discovered_at: '2026-11-06T14:00:00.000Z',
  agent_context: {
    discovering_agent_id: 'agent-mantis-discoverer',
  },
  raw_metadata: {},
};

const FINDING_XSS: SecurityFinding = {
  finding_id: 'SK-FIND-XSS-002',
  source_engine: 'codex_security',
  title: 'Reflected Cross-Site Scripting in Render Engine',
  description: 'Unescaped HTML rendering in user profile view',
  cwe_id: 'CWE-79',
  owasp_category: 'A03:2021-Injection',
  severity: 'HIGH',
  confidence: 'CERTAIN',
  target_type: 'SOURCE_CODE',
  target: 'src/views/profile.ts',
  location: {
    file_path: 'src/views/profile.ts',
    start_line: 12,
    end_line: 14,
    symbol: 'renderProfile',
  },
  fingerprint: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
  commit_hash: COMMIT_A,
  discovered_at: '2026-11-06T14:01:00.000Z',
  agent_context: {
    discovering_agent_id: 'agent-codex-discoverer',
  },
  raw_metadata: {},
};

const EVIDENCE_SQLI_VERIFIED: Evidence = {
  evidence_id: 'SK-EVID-SQLI-001',
  finding_id: 'SK-FIND-SQLI-001',
  verification_type: 'REPRODUCER_EXECUTION',
  status: 'VERIFIED_TRUE_POSITIVE',
  verifier_agent_id: 'agent-pytest-verifier',
  sandbox_environment: {
    runtime: 'docker_isolated',
    network_isolated: true,
    timeout_ms: 30000,
  },
  reproduction_proof: {
    proof_type: 'EXECUTABLE_POC',
    payload: "' OR 1=1 --",
    expected_behavior: 'HTTP 400 Bad Request',
    observed_vulnerable_behavior: 'HTTP 200 with full user table dump',
  },
  reproducer_artifact: {
    script_path: 'tests/poc_sqli.ts',
    script_sha256: '4a123f890123456789abcdef0123456789abcdef0123456789abcdef01234567',
    exit_code: 1,
    stdout: 'PoC confirmed vulnerability',
    stderr: '',
    execution_duration_ms: 350,
  },
  chain_hash: '99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788',
  recorded_at: '2026-11-06T14:05:00.000Z',
};

const PATCH_SQLI_CLEAN: PatchProposal = {
  patch_id: 'SK-PATCH-SQLI-001',
  finding_id: 'SK-FIND-SQLI-001',
  author_engine: 'mantis_patch',
  diff_content: '--- a/src/api/search.ts\n+++ b/src/api/search.ts\n- const q = `SELECT * FROM users WHERE name = ${input}`;\n+ const q = await db.query("SELECT * FROM users WHERE name = $1", [input]);\n',
  affected_files: ['src/api/search.ts'],
  base_commit: COMMIT_A,
  patch_sha256: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
  recheck_status: 'passed_clean',
  recheck_evidence_id: 'SK-EVID-SQLI-001',
  blast_radius: {
    files_modified: 1,
    lines_added: 1,
    lines_deleted: 1,
    ast_impact_scope: 'LOCAL_FUNCTION',
    downstream_dependents: [],
    breaking_change_risk: 'LOW',
  },
  rollback_plan: {
    revert_patch: '--- b/src/api/search.ts\n+++ a/src/api/search.ts\n+ const q = `SELECT * FROM users WHERE name = ${input}`;\n- const q = await db.query("SELECT * FROM users WHERE name = $1", [input]);\n',
  },
  created_at: '2026-11-06T14:10:00.000Z',
};

// ============================================================================
// TEST SUITES
// ============================================================================

describe('Suite 1: Clean PASS Gate Evaluation', () => {
  it('evaluates a clean finding with verified reproduction, clean patch, valid custody, and distinct SoD agents to PASS', async () => {
    const gate = new DeterministicQualityGate();

    const custodyChain = buildCustodyChain({
      finding: FINDING_SQLI,
      evidence: EVIDENCE_SQLI_VERIFIED,
      patch: PATCH_SQLI_CLEAN,
    });

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [EVIDENCE_SQLI_VERIFIED],
      patches: [PATCH_SQLI_CLEAN],
      custody_chain: custodyChain,
      discovering_agent_id: 'agent-mantis-discoverer',
      verifying_agent_id: 'agent-pytest-verifier',
      authorizing_agent_id: 'agent-gate-authorizer',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.PASS);
    assert.equal(decision.blocking_findings.length, 0);
    assert.equal(decision.unverified_findings.length, 0);
    assert.equal(decision.sod_evaluation.is_valid, true);
    assert.match(decision.decision_id, /^SK-GATE-/);
    assert.match(decision.audit_merkle_root, /^[0-9a-fA-F]{64}$/);
    assert.notEqual(decision.audit_merkle_root, EMPTY_MERKLE_ROOT);
    assert.ok(decision.rules_evaluated.length >= 4);

    const reproRule = decision.rules_evaluated.find((r) => r.rule_id === 'RULE_REPRODUCER_RESULT');
    assert.ok(reproRule);
    assert.equal(reproRule.status, 'PASS');

    const sodRule = decision.rules_evaluated.find((r) => r.rule_id === 'RULE_SEPARATION_OF_DUTIES');
    assert.ok(sodRule);
    assert.equal(sodRule.status, 'PASS');
  });
});

describe('Suite 2: Rejection of Findings with Missing Evidence (Zero-Trust Gate Predicate)', () => {
  it('strictly rejects finding when empirical reproduction evidence is missing (Zero-Trust invariant)', async () => {
    const gate = new DeterministicQualityGate();

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [], // Zero evidence provided
      patches: [],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REJECT);
    assert.ok(decision.unverified_findings.includes(FINDING_SQLI.finding_id));

    const missingEvidenceRule = decision.rules_evaluated.find(
      (r) => r.rule_id === 'RULE_EMPIRICAL_REPRODUCTION'
    );
    assert.ok(missingEvidenceRule);
    assert.equal(missingEvidenceRule.status, 'FAIL');
    assert.ok(missingEvidenceRule.reason.includes('no independent empirical reproduction evidence'));
  });

  it('rejects evaluation when one finding has evidence but another finding lacks evidence', async () => {
    const gate = new DeterministicQualityGate();

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI, FINDING_XSS],
      evidence: [EVIDENCE_SQLI_VERIFIED], // Only SQLi has evidence; XSS is missing evidence
      patches: [PATCH_SQLI_CLEAN],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REJECT);
    assert.ok(decision.unverified_findings.includes(FINDING_XSS.finding_id));
    assert.ok(!decision.unverified_findings.includes(FINDING_SQLI.finding_id));
  });
});

describe('Suite 3: Rejection of Findings with Inconclusive Reproducer', () => {
  it('blocks the gate when evidence reproducer status is INCONCLUSIVE', async () => {
    const gate = new DeterministicQualityGate();

    const inconclusiveEvidence: Evidence = {
      ...EVIDENCE_SQLI_VERIFIED,
      status: 'INCONCLUSIVE',
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [inconclusiveEvidence],
      patches: [PATCH_SQLI_CLEAN],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.BLOCK);
    assert.ok(decision.blocking_findings.includes(FINDING_SQLI.finding_id));

    const reproducerRule = decision.rules_evaluated.find(
      (r) => r.rule_id === 'RULE_REPRODUCER_DECISIVENESS'
    );
    assert.ok(reproducerRule);
    assert.equal(reproducerRule.status, 'FAIL');
    assert.ok(reproducerRule.reason.includes('inconclusive'));
  });

  it('blocks the gate when evidence reproducer status is EXECUTION_ERROR', async () => {
    const gate = new DeterministicQualityGate();

    const errorEvidence: Evidence = {
      ...EVIDENCE_SQLI_VERIFIED,
      status: 'EXECUTION_ERROR',
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [errorEvidence],
      patches: [PATCH_SQLI_CLEAN],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.BLOCK);
    assert.ok(decision.blocking_findings.includes(FINDING_SQLI.finding_id));
  });
});

describe('Suite 4: Tri-Party Separation of Duties (SoD) Validator', () => {
  it('detects Omnipotent Agent (d == v == a) and rejects under E_SOD_OMNIPOTENT_AGENT', () => {
    const sod = validateSeparationOfDuties('agent-omni', 'agent-omni', 'agent-omni');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_code, SoDViolationCode.E_SOD_OMNIPOTENT_AGENT);
    assert.ok(sod.violation_details?.includes('E_SOD_OMNIPOTENT_AGENT'));
  });

  it('detects Self-Certification (d == v != a) and rejects under E_SOD_SELF_CERTIFICATION', () => {
    const sod = validateSeparationOfDuties('agent-scout', 'agent-scout', 'agent-gate');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_code, SoDViolationCode.E_SOD_SELF_CERTIFICATION);
    assert.ok(sod.violation_details?.includes('E_SOD_SELF_CERTIFICATION'));
  });

  it('detects Self-Authorization (d != v == a) and rejects under E_SOD_SELF_AUTHORIZATION', () => {
    const sod = validateSeparationOfDuties('agent-scout', 'agent-verifier', 'agent-verifier');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_code, SoDViolationCode.E_SOD_SELF_AUTHORIZATION);
    assert.ok(sod.violation_details?.includes('E_SOD_SELF_AUTHORIZATION'));
  });

  it('detects Discoverer-Authorization (d == a != v) and rejects', () => {
    const sod = validateSeparationOfDuties('agent-scout', 'agent-verifier', 'agent-scout');
    assert.equal(sod.is_valid, false);
    assert.ok(sod.violation_details?.includes('E_SOD_OMNIPOTENT_AGENT') || sod.violation_details?.includes('E_SOD_DISCOVERER_AUTHORIZATION'));
  });

  it('enforces case-insensitive comparison and trims whitespace', () => {
    const sod = validateSeparationOfDuties('  Agent-Alpha  ', 'agent-ALPHA\t', 'agent-gamma');
    assert.equal(sod.is_valid, false);
    assert.equal(sod.violation_code, SoDViolationCode.E_SOD_SELF_CERTIFICATION);
  });

  it('rejects when any agent identity is missing or empty string', () => {
    const sod1 = validateSeparationOfDuties('', 'agent-v', 'agent-a');
    assert.equal(sod1.is_valid, false);
    assert.equal(sod1.violation_code, SoDViolationCode.E_SOD_MISSING_AGENT);

    const sod2 = validateSeparationOfDuties('agent-d', '   ', 'agent-a');
    assert.equal(sod2.is_valid, false);
    assert.equal(sod2.violation_code, SoDViolationCode.E_SOD_MISSING_AGENT);
  });

  it('validates AgentRoleMapping properly and detects overlap', () => {
    const invalidMapping = {
      'agent-super': 'discovery',
      'agent-other': 'verification',
      'agent-super-alias': 'authorization',
    };
    const validResult = validateAgentRoleMapping({
      'agent-1': 'discovery',
      'agent-2': 'verification',
      'agent-3': 'authorization',
    });
    assert.equal(validResult.is_valid, true);

    const overlappingMapping = {
      'agent-dual': 'discovery',
      'agent-dual-2': 'authorization',
    };
    const missingResult = validateAgentRoleMapping(overlappingMapping);
    assert.equal(missingResult.is_valid, false);
  });

  it('rejects gate evaluation when discovering agent self-certifies evidence', async () => {
    const gate = new DeterministicQualityGate();

    // Evidence produced by discovering agent
    const selfCertifiedEvidence: Evidence = {
      ...EVIDENCE_SQLI_VERIFIED,
      verifier_agent_id: 'agent-mantis-discoverer', // Same as FINDING_SQLI.agent_context.discovering_agent_id
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [selfCertifiedEvidence],
      patches: [PATCH_SQLI_CLEAN],
      discovering_agent_id: 'agent-mantis-discoverer',
      verifying_agent_id: 'agent-mantis-discoverer', // SoD violation
      authorizing_agent_id: 'agent-gate-authorizer',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REJECT);
    assert.equal(decision.sod_evaluation.is_valid, false);
    assert.ok(decision.sod_evaluation.violation_details?.includes('E_SOD_SELF_CERTIFICATION'));
  });
});

describe('Suite 5: Rejection of Expired Policy Exceptions & Scope Safety', () => {
  it('immediately rejects gate when policy contains an expired exception (expires < today)', async () => {
    const gate = new DeterministicQualityGate();

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [EVIDENCE_SQLI_VERIFIED],
      patches: [PATCH_SQLI_CLEAN],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
      policy: {
        version: 1,
        exceptions: [
          {
            rule_id: 'CWE-89',
            fingerprint: FINDING_SQLI.fingerprint,
            reason: 'Legacy database query under migration',
            expires: '2020-01-01', // Expired
          },
        ],
      },
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REJECT);

    const expiredRule = decision.rules_evaluated.find(
      (r) => r.rule_id === 'RULE_POLICY_EXCEPTIONS'
    );
    assert.ok(expiredRule);
    assert.equal(expiredRule.status, 'FAIL');
    assert.ok(expiredRule.reason.includes('Expired policy exception detected'));
  });

  it('allows unexpired exception to suppress finding and pass the gate', async () => {
    const gate = new DeterministicQualityGate();

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [], // No evidence provided, but finding is exempted by valid unexpired exception
      patches: [],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
      policy: {
        version: 1,
        exceptions: [
          {
            rule_id: 'CWE-89',
            fingerprint: FINDING_SQLI.fingerprint,
            reason: 'Explicitly approved exception for airgapped batch worker',
            expires: '2099-12-31', // Future date
          },
        ],
      },
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.PASS);
    assert.equal(decision.blocking_findings.length, 0);
    assert.equal(decision.unverified_findings.length, 0);

    const suppressedRule = decision.rules_evaluated.find(
      (r) => r.rule_id === 'RULE_EXCEPTION_MATCH'
    );
    assert.ok(suppressedRule);
    assert.equal(suppressedRule.status, 'PASS');
  });

  it('rejects target paths that attempt directory traversal or symlink escapes', async () => {
    const gate = new DeterministicQualityGate();

    const traversalFinding: SecurityFinding = {
      ...FINDING_SQLI,
      finding_id: 'SK-FIND-TRAVERSAL-001',
      location: {
        file_path: '../../../../etc/shadow',
        start_line: 1,
        end_line: 1,
      },
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [traversalFinding],
      evidence: [
        {
          ...EVIDENCE_SQLI_VERIFIED,
          finding_id: 'SK-FIND-TRAVERSAL-001',
        },
      ],
      patches: [],
      scope_root: 'c:/Users/adm/Desktop/Prototipos/Script Kitty/src',
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REJECT);
    const scopeRule = decision.rules_evaluated.find((r) => r.rule_id === 'RULE_SCOPE_BOUNDARY');
    assert.ok(scopeRule);
    assert.equal(scopeRule.status, 'FAIL');
    assert.ok(scopeRule.reason.includes('escapes authorized scope boundaries'));
  });

  it('blocks the gate when max_files or total scanned bytes exceed policy limits', async () => {
    const gate = new DeterministicQualityGate();

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [],
      evidence: [],
      patches: [],
      evaluated_files: new Array(6000).fill('file.ts'), // Exceeds default 5000 max_files
      total_scanned_bytes: 50 * 1024 * 1024,            // 50 MiB exceeds default 32 MiB
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.BLOCK);
    const filesRule = decision.rules_evaluated.find((r) => r.rule_id === 'RULE_LIMIT_MAX_FILES');
    assert.ok(filesRule);
    assert.equal(filesRule.status, 'FAIL');

    const bytesRule = decision.rules_evaluated.find((r) => r.rule_id === 'RULE_LIMIT_MAX_TOTAL_BYTES');
    assert.ok(bytesRule);
    assert.equal(bytesRule.status, 'FAIL');
  });
});

describe('Suite 6: Rejection of Tampered Custody Chains & Merkle Auditing', () => {
  it('rejects gate evaluation when custody chain is tampered or leaf hash is corrupted', async () => {
    const gate = new DeterministicQualityGate();

    const validChain = buildCustodyChain({
      finding: FINDING_SQLI,
      evidence: EVIDENCE_SQLI_VERIFIED,
      patch: PATCH_SQLI_CLEAN,
    });

    // Tamper with intermediate node leaf hash
    const tamperedNodes = validChain.nodes.map((node) => ({ ...node }));
    tamperedNodes[1].leaf_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const tamperedChain: ChainOfCustody = {
      ...validChain,
      nodes: tamperedNodes,
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [EVIDENCE_SQLI_VERIFIED],
      patches: [PATCH_SQLI_CLEAN],
      custody_chain: tamperedChain,
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REJECT);
    const custodyRule = decision.rules_evaluated.find((r) => r.rule_id === 'RULE_CUSTODY_INTEGRITY');
    assert.ok(custodyRule);
    assert.equal(custodyRule.status, 'FAIL');
    assert.ok(custodyRule.reason.includes('Chain of Custody integrity check failed'));
  });

  it('rejects gate when custody chain Merkle root is forged', async () => {
    const gate = new DeterministicQualityGate();

    const validChain = buildCustodyChain({
      finding: FINDING_SQLI,
      evidence: EVIDENCE_SQLI_VERIFIED,
      patch: PATCH_SQLI_CLEAN,
    });

    const forgedChain: ChainOfCustody = {
      ...validChain,
      merkle_root: '0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff', // Forged root
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [EVIDENCE_SQLI_VERIFIED],
      patches: [PATCH_SQLI_CLEAN],
      custody_chain: forgedChain,
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REJECT);
  });

  it('computes tamper-evident SHA-256 Merkle root in TamperEvidentAuditLogger and detects modifications', () => {
    const logger = new TamperEvidentAuditLogger();

    const evt1 = logger.logRuleEvaluation({
      rule_id: 'RULE_TEST_1',
      status: 'PASS',
      reason: 'Rule 1 passed cleanly',
    });

    const evt2 = logger.logRuleEvaluation({
      rule_id: 'RULE_TEST_2',
      status: 'PASS',
      reason: 'Rule 2 passed cleanly',
    });

    const rootBefore = logger.getMerkleRoot();
    assert.match(rootBefore, /^[0-9a-fA-F]{64}$/);

    const integrityBefore = logger.verifyIntegrity();
    assert.equal(integrityBefore.valid, true);
    assert.equal(integrityBefore.total_events, 2);

    // Tamper with first event details
    evt1.details = { rule_id: 'RULE_TAMPERED', status: 'FAIL' };
    const integrityAfter = logger.verifyIntegrity();
    assert.equal(integrityAfter.valid, false);
    assert.equal(integrityAfter.broken_index, 0);
  });
});

describe('Suite 7: Quad-State Result Mapping & Precedence', () => {
  it('maps to REQUIRES_HUMAN_APPROVAL when proposed patch has HIGH breaking change risk', async () => {
    const gate = new DeterministicQualityGate();

    const highBlastPatch: PatchProposal = {
      ...PATCH_SQLI_CLEAN,
      blast_radius: {
        ...PATCH_SQLI_CLEAN.blast_radius,
        breaking_change_risk: 'HIGH',
      },
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [EVIDENCE_SQLI_VERIFIED],
      patches: [highBlastPatch],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.REQUIRES_HUMAN_APPROVAL);
    assert.ok(decision.evaluation_summary.includes('REQUIRES_HUMAN_APPROVAL'));
  });

  it('maps to BLOCK when proposed patch reports regression detected', async () => {
    const gate = new DeterministicQualityGate();

    const regressedPatch: PatchProposal = {
      ...PATCH_SQLI_CLEAN,
      recheck_status: 'regression_detected',
    };

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      findings: [FINDING_SQLI],
      evidence: [EVIDENCE_SQLI_VERIFIED],
      patches: [regressedPatch],
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.BLOCK);
    assert.ok(decision.blocking_findings.includes(FINDING_SQLI.finding_id));

    const regRule = decision.rules_evaluated.find((r) => r.rule_id === 'RULE_PATCH_REGRESSION');
    assert.ok(regRule);
    assert.equal(regRule.status, 'FAIL');
  });

  it('maps to ERROR when policy payload is malformed or invalid', async () => {
    const gate = new DeterministicQualityGate();

    const request: GateEvaluationRequest = {
      commit_hash: COMMIT_A,
      policy: {
        version: 999, // Unsupported version
      },
      discovering_agent_id: 'agent-discovery-01',
      verifying_agent_id: 'agent-verifier-02',
      authorizing_agent_id: 'agent-authorizer-03',
    };

    const decision = await gate.evaluate(request);

    assert.equal(decision.verdict, GateVerdict.ERROR);
    assert.ok(decision.evaluation_summary.includes('Policy configuration error'));
  });
});

describe('Suite 8: Policy Parser, Bounded Limits & Scope Verification', () => {
  it('parses default policy with standard bounded limits', () => {
    const policy = parsePolicy({});
    assert.equal(policy.version, 1);
    assert.equal(policy.max_file_bytes, 2 * 1024 * 1024);
    assert.equal(policy.max_files, 5000);
    assert.equal(policy.max_total_bytes, 32 * 1024 * 1024);
    assert.equal(policy.timeout_ms, 20000);
  });

  it('rejects policy exceeding max_file_bytes ceiling (> 2 MiB)', () => {
    const result = validatePolicy({
      version: 1,
      max_file_bytes: 10 * 1024 * 1024,
    });
    assert.equal(result.success, false);
    assert.ok(result.errors?.some((e) => e.includes('max_file_bytes cannot exceed')));
  });

  it('rejects policy with invalid version', () => {
    const result = validatePolicy({
      version: 2,
    });
    assert.equal(result.success, false);
    assert.ok(result.errors?.some((e) => e.includes('version must strictly be 1')));
  });

  it('evaluates insideScope correctly for relative and absolute paths', () => {
    const root = 'c:/Users/adm/Desktop/Prototipos/Script Kitty';
    assert.equal(insideScope(root, 'src/api/users.ts'), true);
    assert.equal(insideScope(root, 'packages/contracts/src/index.ts'), true);
    assert.equal(insideScope(root, '../outside.txt'), false);
    assert.equal(insideScope(root, '../../../../etc/shadow'), false);
  });

  it('detects target in scope using isTargetInScope', () => {
    const allowed = ['c:/Users/adm/Desktop/Prototipos/Script Kitty/src'];
    assert.equal(isTargetInScope('users.ts', allowed), true);
    assert.equal(isTargetInScope('../../../unauthorized.txt', allowed), false);
  });

  it('correctly matches finding fingerprint with unexpired policy exception', () => {
    const exceptions = [
      {
        rule_id: 'CWE-89',
        fingerprint: FINDING_SQLI.fingerprint,
        reason: 'Migration in flight',
        expires: '2099-12-31',
      },
    ];

    const match = findMatchingException(FINDING_SQLI, exceptions);
    assert.equal(match.matched, true);
    assert.equal(match.isExpired, false);
    assert.equal(match.exception?.rule_id, 'CWE-89');

    const noMatch = findMatchingException(FINDING_XSS, exceptions);
    assert.equal(noMatch.matched, false);
  });
});
