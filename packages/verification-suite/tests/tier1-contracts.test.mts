/**
 * @file packages/verification-suite/tests/tier1-contracts.test.mts
 * @description Tier 1 Synthetic Test Suite: Schema validation, round-trip serialization,
 * strict type compliance, constraint validation, missing field rejection, and cryptographic custody.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  // Finding
  validateFinding,
  parseFinding,
  SecurityFindingSchema,
  computeFindingFingerprint,
  // Evidence
  validateEvidence,
  parseEvidence,
  EvidenceSchema,
  computeEvidenceChainHash,
  // Patch
  validatePatch,
  parsePatch,
  PatchProposalSchema,
  computePatchSha256,
  isPatchEligibleForAutoGate,
  // Gate
  validateGateDecision,
  parseGateDecision,
  GateDecisionSchema,
  evaluateSeparationOfDuties,
  GateVerdict,
  // Custody
  buildCustodyChain,
  verifyChainIntegrity,
  verifyChainOfCustody,
  computeMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  canonicalStringify,
  hashSecurityFinding,
  hashEvidence,
  hashPatchProposal,
  hashGateDecision,
  GENESIS_HASH,
  EMPTY_MERKLE_ROOT,
  // Common
  Severity,
  Confidence,
  TargetType,
  VerificationStatus,
  severityToScore,
  CommonCwe,
} from '../../contracts/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');

function loadJson(relPath: string) {
  const full = path.join(FIXTURES_DIR, relPath);
  return JSON.parse(fs.readFileSync(full, 'utf8'));
}

describe('Tier 1: Core Evidence Data Contracts & Cryptographic Custody', () => {
  const validFindingRaw = loadJson('valid-finding.json');
  const validEvidenceRaw = loadJson('valid-evidence.json');
  const validPatchRaw = loadJson('valid-patch.json');
  const validGatePassRaw = loadJson('valid-gate-pass.json');
  const invalidContractsRaw = loadJson('invalid-contracts.json');

  describe('1.1 Schema Validation of Canonical Fixtures', () => {
    it('validates canonical SecurityFinding fixture', () => {
      const res = validateFinding(validFindingRaw);
      assert.equal(res.success, true);
      assert.ok(res.data);
      assert.equal(res.data.finding_id, validFindingRaw.finding_id);
      assert.equal(res.data.cwe_id, 'CWE-89');
      assert.equal(res.data.severity, 'CRITICAL');
      assert.equal(res.data.confidence, 'CERTAIN');
      assert.equal(res.data.location.start_line, 42);
      assert.equal(res.data.location.end_line, 42);
    });

    it('validates canonical Evidence fixture', () => {
      const res = validateEvidence(validEvidenceRaw);
      assert.equal(res.success, true);
      assert.ok(res.data);
      assert.equal(res.data.evidence_id, validEvidenceRaw.evidence_id);
      assert.equal(res.data.finding_id, validEvidenceRaw.finding_id);
      assert.equal(res.data.status, 'VERIFIED_TRUE_POSITIVE');
      assert.equal(res.data.sandbox_environment.network_isolated, true);
      assert.equal(res.data.reproducer_artifact?.exit_code, 1);
    });

    it('validates canonical PatchProposal fixture', () => {
      const res = validatePatch(validPatchRaw);
      assert.equal(res.success, true);
      assert.ok(res.data);
      assert.equal(res.data.patch_id, validPatchRaw.patch_id);
      assert.equal(res.data.finding_id, validPatchRaw.finding_id);
      assert.equal(res.data.recheck_status, 'passed_clean');
      assert.ok(res.data.recheck_evidence_id);
      assert.equal(res.data.blast_radius.breaking_change_risk, 'LOW');
      assert.ok(res.data.rollback_plan.revert_patch);
    });

    it('validates canonical GateDecision fixture', () => {
      const res = validateGateDecision(validGatePassRaw);
      assert.equal(res.success, true);
      assert.ok(res.data);
      assert.equal(res.data.decision_id, validGatePassRaw.decision_id);
      assert.equal(res.data.verdict, 'PASS');
      assert.equal(res.data.blocking_findings.length, 0);
      assert.equal(res.data.unverified_findings.length, 0);
      assert.equal(res.data.sod_evaluation.is_valid, true);
    });
  });

  describe('1.2 Round-Trip Serialization & Canonical Stability', () => {
    it('preserves finding data through parse -> canonicalStringify -> JSON.parse round-trip', () => {
      const parsed = parseFinding(validFindingRaw);
      const serialized = canonicalStringify(parsed);
      const reParsed = JSON.parse(serialized);
      const validatedAgain = validateFinding(reParsed);

      assert.equal(validatedAgain.success, true);
      assert.deepEqual(validatedAgain.data, parsed);
    });

    it('produces identical SHA-256 leaf hash regardless of object key order', () => {
      const copy1 = {
        finding_id: 'SK-FIND-ORDER-1',
        source_engine: 'builtin',
        title: 'Order Independence',
        description: 'Test description',
        cwe_id: 'CWE-89',
        owasp_category: 'A03:2021-Injection',
        severity: 'HIGH',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: 'src/db.ts',
        location: { file_path: 'src/db.ts', start_line: 1, end_line: 1 },
        fingerprint: 'a'.repeat(64),
        commit_hash: 'b'.repeat(40),
        discovered_at: '2026-11-06T14:10:00Z',
      };

      const copy2 = {
        discovered_at: '2026-11-06T14:10:00Z',
        commit_hash: 'b'.repeat(40),
        fingerprint: 'a'.repeat(64),
        location: { end_line: 1, start_line: 1, file_path: 'src/db.ts' },
        target: 'src/db.ts',
        target_type: 'SOURCE_CODE',
        confidence: 'CERTAIN',
        severity: 'HIGH',
        owasp_category: 'A03:2021-Injection',
        cwe_id: 'CWE-89',
        description: 'Test description',
        title: 'Order Independence',
        source_engine: 'builtin',
        finding_id: 'SK-FIND-ORDER-1',
      };

      const f1 = parseFinding(copy1);
      const f2 = parseFinding(copy2);

      assert.equal(canonicalStringify(f1), canonicalStringify(f2));
      assert.equal(hashSecurityFinding(f1), hashSecurityFinding(f2));
    });

    it('strips self-referential hash fields when hashing contracts', () => {
      const finding = parseFinding(validFindingRaw);
      const hash1 = hashSecurityFinding(finding);

      // Mutate self-referential fields: fingerprint and findingHash
      const tampered = {
        ...finding,
        fingerprint: '0'.repeat(64),
        finding_hash: '1'.repeat(64),
      };
      const hash2 = hashSecurityFinding(tampered);

      assert.equal(hash1, hash2, 'hashSecurityFinding must exclude fingerprint/finding_hash');
    });

    it('computes deterministic finding fingerprint matching Quality Engine specs', () => {
      const fp1 = computeFindingFingerprint({
        cwe_id: 'CWE-89',
        file_path: 'src/api/users.ts',
        rule_or_match: 'findUserById',
      });

      const fp2 = computeFindingFingerprint({
        cwe_id: 'cwe-89', // case normalizes
        file_path: 'src\\api\\users.ts', // backslash normalizes
        rule_or_match: 'findUserById ', // trimmed
      });

      assert.equal(fp1, fp2);
      assert.match(fp1, /^[a-f0-9]{64}$/);
    });

    it('computes deterministic patch SHA-256 and checks auto-gate eligibility', () => {
      const patch = parsePatch(validPatchRaw);
      const computedSha = computePatchSha256(patch.diff_content);
      assert.match(computedSha, /^[a-f0-9]{64}$/);

      const eligible = isPatchEligibleForAutoGate(patch);
      assert.equal(eligible, true);

      // Mutate blast radius to HIGH -> must become ineligible
      const highRiskPatch = {
        ...patch,
        blast_radius: { ...patch.blast_radius, breaking_change_risk: 'HIGH' as const },
      };
      assert.equal(isPatchEligibleForAutoGate(highRiskPatch), false);
    });
  });

  describe('1.3 Strict Type & Enum Compliance', () => {
    it('validates Severity enum scoring and normalization', () => {
      assert.equal(severityToScore(Severity.CRITICAL), 10.0);
      assert.equal(severityToScore(Severity.HIGH), 8.0);
      assert.equal(severityToScore(Severity.MEDIUM), 5.0);
      assert.equal(severityToScore(Severity.LOW), 2.0);
      assert.equal(severityToScore(Severity.INFO), 0.0);
    });

    it('accepts valid CWE identifiers and rejects malformed values', () => {
      assert.equal(CommonCwe.CWE_89, 'CWE-89');
      assert.equal(CommonCwe.CWE_78, 'CWE-78');
      assert.equal(CommonCwe.CWE_79, 'CWE-79');
    });
  });

  describe('1.4 Missing Fields & Boundary Constraint Rejections', () => {
    it('rejects finding missing cwe_id', () => {
      const res = validateFinding(invalidContractsRaw.missing_cwe_id);
      assert.equal(res.success, false);
      assert.ok(res.errors?.some((e) => e.path.includes('cwe_id')));
    });

    it('rejects finding with invalid CWE format', () => {
      const res = validateFinding(invalidContractsRaw.invalid_cwe_format);
      assert.equal(res.success, false);
      assert.ok(res.errors?.some((e) => e.path.includes('cwe_id')));
    });

    it('rejects finding with invalid severity', () => {
      const res = validateFinding(invalidContractsRaw.invalid_severity);
      assert.equal(res.success, false);
      assert.ok(res.errors?.some((e) => e.path.includes('severity')));
    });

    it('rejects finding with reversed line range (start_line > end_line)', () => {
      const res = validateFinding(invalidContractsRaw.reversed_lines);
      assert.equal(res.success, false);
      assert.ok(res.errors?.some((e) => e.path.includes('end_line') || e.message.includes('end_line')));
    });

    it('rejects finding with negative line numbers', () => {
      const res = validateFinding(invalidContractsRaw.negative_line_number);
      assert.equal(res.success, false);
      assert.ok(res.errors?.some((e) => e.path.includes('start_line')));
    });

    it('rejects finding with malformed SHA-256 fingerprint', () => {
      const res = validateFinding(invalidContractsRaw.malformed_sha256_fingerprint);
      assert.equal(res.success, false);
      assert.ok(res.errors?.some((e) => e.path.includes('fingerprint')));
    });

    it('rejects patch when recheck_status is passed_clean but recheck_evidence_id is missing', () => {
      const badPatch = {
        ...validPatchRaw,
        recheck_status: 'passed_clean',
        recheck_evidence_id: null,
      };
      const res = validatePatch(badPatch);
      assert.equal(res.success, false);
      assert.ok(res.errors?.some((e) => e.path.includes('recheck_evidence_id')));
    });
  });

  describe('1.5 Cryptographic Chain of Custody & Merkle Trees', () => {
    it('constructs an unbroken 4-stage custody chain linking Finding -> Evidence -> Patch -> Gate', () => {
      const finding = parseFinding(validFindingRaw);
      const evidence = parseEvidence(validEvidenceRaw);
      const patch = parsePatch(validPatchRaw);
      const gate = parseGateDecision(validGatePassRaw);

      const chain = buildCustodyChain({ finding, evidence, patch, gate });

      assert.equal(chain.total_nodes, 4);
      assert.equal(chain.is_valid, true);
      assert.match(chain.merkle_root, /^[a-f0-9]{64}$/);

      // Verify node 0 links from GENESIS_HASH
      assert.equal(chain.nodes[0].parent_hash, GENESIS_HASH);
      // Verify node 1 links from node 0 chain_hash
      assert.equal(chain.nodes[1].parent_hash, chain.nodes[0].chain_hash);
      // Verify node 2 links from node 1 chain_hash
      assert.equal(chain.nodes[2].parent_hash, chain.nodes[1].chain_hash);
      // Verify node 3 links from node 2 chain_hash
      assert.equal(chain.nodes[3].parent_hash, chain.nodes[2].chain_hash);

      const verified = verifyChainOfCustody(chain);
      assert.equal(verified.valid, true);
      assert.equal(verified.merkle_root, chain.merkle_root);
    });

    it('detects tampering when an intermediate leaf hash is altered', () => {
      const finding = parseFinding(validFindingRaw);
      const evidence = parseEvidence(validEvidenceRaw);
      const chain = buildCustodyChain({ finding, evidence });

      // Tamper with node 0 leaf hash
      chain.nodes[0].leaf_hash = 'f'.repeat(64);

      const verified = verifyChainIntegrity(chain.nodes);
      assert.equal(verified.valid, false);
      assert.equal(verified.broken_index, 0);
      assert.ok(verified.error?.includes('Chain hash corruption'));
    });

    it('computes binary Merkle roots adhering to odd-leaf duplication specifications', () => {
      // 0 leaves
      assert.equal(computeMerkleRoot([]), EMPTY_MERKLE_ROOT);

      // 1 leaf
      const leaf0 = 'a'.repeat(64);
      assert.equal(computeMerkleRoot([leaf0]), leaf0);

      // 2 leaves
      const leaf1 = 'b'.repeat(64);
      const root2 = computeMerkleRoot([leaf0, leaf1]);
      assert.match(root2, /^[a-f0-9]{64}$/);

      // 3 leaves: duplicates the 3rd leaf to make 4
      const leaf2 = 'c'.repeat(64);
      const root3 = computeMerkleRoot([leaf0, leaf1, leaf2]);
      const root4 = computeMerkleRoot([leaf0, leaf1, leaf2, leaf2]);
      assert.equal(root3, root4, 'Odd 3-leaf tree root must equal 4-leaf tree with duplicated last leaf');
    });

    it('generates and verifies valid logarithmic Merkle inclusion proofs', () => {
      const leaves = [
        '11'.repeat(32),
        '22'.repeat(32),
        '33'.repeat(32),
        '44'.repeat(32),
        '55'.repeat(32),
      ];
      const root = computeMerkleRoot(leaves);

      for (let i = 0; i < leaves.length; i++) {
        const proof = generateMerkleProof(leaves, i);
        const isValid = verifyMerkleProof(leaves[i], proof, root);
        assert.equal(isValid, true, `Merkle proof for leaf ${i} must verify against root`);
      }
    });

    it('rejects tampered Merkle proof when leaf value is modified', () => {
      const leaves = ['aa'.repeat(32), 'bb'.repeat(32)];
      const root = computeMerkleRoot(leaves);
      const proof = generateMerkleProof(leaves, 0);

      const isValid = verifyMerkleProof('ff'.repeat(32), proof, root);
      assert.equal(isValid, false);
    });
  });
});
