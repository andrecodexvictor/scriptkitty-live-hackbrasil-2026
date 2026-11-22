/**
 * @file packages/verification-suite/tests/tier4-scenarios.test.mts
 * @description Tier 4 Synthetic Test Suite: End-to-End Real-World Security Pipelines:
 * 1. AppSec Scenario: SQL Injection (CWE-89) autonomous discovery, sandboxed reproduction,
 *    patch generation, regression recheck, Merkle custody, and release gate PASS.
 * 2. AgentSec Scenario: MCP Tool Confused Deputy / Prompt Injection (OWASP LLM01/LLM07)
 *    runtime detection, reproducer containment, gate rejection of self-certified verification,
 *    and resolution via independent verification.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// Contracts
import {
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type GateDecision,
  validateFinding,
  validateEvidence,
  validatePatch,
  validateGateDecision,
  buildCustodyChain,
  verifyChainOfCustody,
  computeFindingFingerprint,
  computePatchSha256,
  computeEvidenceChainHash,
  GateVerdict,
  VerificationStatus,
} from '../../contracts/dist/index.js';

// Adapters
import {
  MantisAdapter,
  CodexSecurityAdapter,
  sanitizeOutput,
  checkSizeBudget,
} from '../../adapters/dist/index.js';

// Quality Gate Engine
import {
  DeterministicQualityGate,
  evaluateSeparationOfDuties,
  type Policy,
} from '../../quality-gate/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');

function loadJson(relPath: string) {
  const full = path.join(FIXTURES_DIR, relPath);
  return JSON.parse(fs.readFileSync(full, 'utf8'));
}

describe('Tier 4: Real-World End-to-End Security Pipelines (AppSec & AgentSec)', () => {
  const mantisMock = loadJson('engine-mocks/mantis-response.json');
  const validPatchRaw = loadJson('valid-patch.json');
  const selfCertifiedFixture = loadJson('self-certified-finding.json');

  describe('4.1 AppSec Pipeline: Autonomous SQL Injection (CWE-89) Discovery, Remediation & Gate PASS', () => {
    const mantis = new MantisAdapter();
    const gate = new DeterministicQualityGate();

    let discoveredFinding: SecurityFinding;
    let reproductionEvidence: Evidence;
    let proposedPatch: PatchProposal;
    let recheckEvidence: Evidence;
    let custodyMerkleRoot: string;

    it('Stage 1 & 2: Autonomous Discovery via Mantis Engine Adapter', async () => {
      const scanTarget = {
        target_type: 'API_ENDPOINT',
        target_url_or_path: 'github.com/org/scriptkitty-target',
        commit_hash: 'a1b2c3d4e5f67890123456789abcdef012345678',
        metadata: {
          raw_findings: mantisMock.raw_findings,
          directory_summaries: [{ path: 'src/api', component: 'api', summary: 'User router', entry_points: ['/api/v1/users'], external_sinks: ['db.raw'] }],
        },
      };

      const scanResult = await mantis.scan(scanTarget);
      assert.equal(scanResult.status, 'success');
      assert.equal(scanResult.findings.length, 1);

      discoveredFinding = scanResult.findings[0];
      assert.equal(discoveredFinding.cwe_id, 'CWE-89');
      assert.equal(discoveredFinding.severity, 'CRITICAL');
      assert.equal(discoveredFinding.location.file_path, 'src/api/users.ts');
      assert.equal(discoveredFinding.location.start_line, 42);

      const validation = validateFinding(discoveredFinding);
      assert.equal(validation.success, true);
    });

    it('Stage 3: Sandboxed PoC Reproduction by Independent Verifier Agent', async () => {
      assert.ok(discoveredFinding, 'Stage 2 finding must exist');

      const verifierAgentId = 'agent-verifier-pytest-02'; // Distinct from Mantis discovery
      assert.notEqual(
        discoveredFinding.agent_context?.discovering_agent_id,
        verifierAgentId,
        'Separation of Duties invariant: Verifier must differ from Discoverer'
      );

      const reproResult = await mantis.reproduce(discoveredFinding, {
        sandbox_runtime: 'docker_isolated',
        network_isolated: true,
        verifier_agent_id: verifierAgentId,
        custom_config: {
          mock_exit_code: 1, // Non-zero exit code confirms vulnerability trigger
          mock_stdout: 'VULNERABILITY_CONFIRMED: syntax error near --',
          mock_script_content: "curl 'http://localhost:3000/api/v1/users?id=1%27%20OR%201=1--'",
        },
      });

      assert.equal(reproResult.status, 'success');
      assert.equal(reproResult.reproduction_verified, true);
      assert.ok(reproResult.evidence);

      reproductionEvidence = reproResult.evidence;
      assert.equal(reproductionEvidence.status, 'VERIFIED_TRUE_POSITIVE');
      assert.equal(reproductionEvidence.reproducer_artifact?.exit_code, 1);
      assert.equal(reproductionEvidence.sandbox_environment.network_isolated, true);

      const validation = validateEvidence(reproductionEvidence);
      assert.equal(validation.success, true);
    });

    it('Stage 4: Autonomous Patch Generation with Rollback Plan & Blast Radius Assessment', async () => {
      assert.ok(discoveredFinding, 'Stage 2 finding must exist');

      const remediationAgentId = 'agent-remediation-patchcat-03';
      const unifiedDiff = mantisMock.patch_proposal.unified_diff;
      const patchSha = computePatchSha256(unifiedDiff);

      // Reverse diff for rollback plan
      const revertDiff = "--- b/src/api/users.ts\n+++ a/src/api/users.ts\n@@ -41,3 +41,3 @@ export async function findUserById(req, res) {\n-  const result = await db('users').where({ id: req.query.id }).first();\n+  const query = `SELECT * FROM users WHERE id = '${req.query.id}'`;\n+  const result = await db.raw(query);\n";

      const candidatePatch: PatchProposal = {
        patch_id: 'SK-PATCH-44556677-8899-aabb-ccdd-eeff00112233',
        finding_id: discoveredFinding.finding_id,
        author_engine: remediationAgentId,
        diff_content: unifiedDiff,
        affected_files: ['src/api/users.ts'],
        base_commit: discoveredFinding.commit_hash,
        patch_sha256: patchSha,
        recheck_status: 'untested',
        blast_radius: {
          files_modified: 1,
          lines_added: 1,
          lines_deleted: 2,
          ast_impact_scope: 'LOCAL_FUNCTION',
          downstream_dependents: ['src/api/router.ts'],
          breaking_change_risk: 'LOW',
        },
        rollback_plan: {
          revert_patch: revertDiff,
          killswitch_flag: 'FEATURE_PARAMETRIZED_USER_LOOKUP',
          compensating_controls: [],
        },
        created_at: new Date().toISOString(),
      };

      const validation = validatePatch(candidatePatch);
      assert.equal(validation.success, true);
      proposedPatch = validation.data!;
    });

    it('Stage 5: Regression Recheck and Mitigation Verification', async () => {
      assert.ok(proposedPatch, 'Stage 4 patch must exist');

      const recheckResult = await mantis.recheck(proposedPatch, {
        verifier_agent_id: 'agent-verifier-pytest-02',
        custom_config: {
          reproducer_still_fails: false, // Reproducer passed clean
          regression_detected: false,    // Zero regressions in test suite
        },
      });

      assert.equal(recheckResult.status, 'success');
      assert.equal(recheckResult.recheck_status, 'passed_clean');
      assert.equal(recheckResult.tests_passed, true);
      assert.equal(recheckResult.reproducer_passed, true);
      assert.ok(recheckResult.evidence);

      recheckEvidence = recheckResult.evidence;

      // Update patch proposal with regression evidence
      proposedPatch = {
        ...proposedPatch,
        recheck_status: 'passed_clean',
        recheck_evidence_id: recheckEvidence.evidence_id,
      };

      const patchValidation = validatePatch(proposedPatch);
      assert.equal(patchValidation.success, true);
    });

    it('Stage 6: Immutable Custody Chaining & Merkle Root Calculation', () => {
      assert.ok(discoveredFinding && reproductionEvidence && proposedPatch);

      const chain = buildCustodyChain({
        finding: discoveredFinding,
        evidence: reproductionEvidence,
        patch: proposedPatch,
      });

      assert.equal(chain.is_valid, true);
      assert.equal(chain.total_nodes, 3);
      assert.match(chain.merkle_root, /^[a-f0-9]{64}$/);

      const chainVerification = verifyChainOfCustody(chain);
      assert.equal(chainVerification.valid, true);
      assert.equal(chainVerification.merkle_root, chain.merkle_root);

      custodyMerkleRoot = chain.merkle_root;
    });

    it('Stage 7: Deterministic Quality Gate Evaluation resolves cleanly to PASS', async () => {
      assert.ok(discoveredFinding && reproductionEvidence && proposedPatch);

      const authorizerAgentId = 'agent-auth-quality-gate-04';

      // Verify Separation of Duties across all 3 roles
      const sodCheck = evaluateSeparationOfDuties(
        discoveredFinding.agent_context?.discovering_agent_id || 'mantis',
        reproductionEvidence.verifier_agent_id,
        authorizerAgentId
      );
      assert.equal(sodCheck.is_valid, true);

      const gateDecision: GateDecision = await gate.evaluate({
        commit_hash: discoveredFinding.commit_hash,
        policy: {
          version: 1,
          max_file_bytes: 2097152,
          max_files: 5000,
          max_total_bytes: 33554432,
          severity_threshold: ['CRITICAL', 'HIGH'],
        },
        findings: [discoveredFinding],
        evidence: [reproductionEvidence],
        patches: [proposedPatch],
        discovering_agent_id: discoveredFinding.agent_context?.discovering_agent_id,
        verifying_agent_id: reproductionEvidence.verifier_agent_id,
        authorizing_agent_id: authorizerAgentId,
      });

      assert.equal(gateDecision.verdict, 'PASS');
      assert.equal(gateDecision.blocking_findings.length, 0);
      assert.equal(gateDecision.unverified_findings.length, 0);
      assert.equal(gateDecision.sod_evaluation.is_valid, true);

      // Validate against strict canonical GateDecision schema
      const gateValidation = validateGateDecision(gateDecision);
      assert.equal(gateValidation.success, true);
    });
  });

  describe('4.2 AgentSec Pipeline: MCP Tool Confused Deputy / Prompt Injection (OWASP LLM01/LLM07)', () => {
    const gate = new DeterministicQualityGate();

    it('Stage 1 & 2: Detection of MCP Tool Shell Injection via Tainted RAG Input', () => {
      const rawFinding = selfCertifiedFixture.finding;
      const findingRes = validateFinding(rawFinding);

      assert.equal(findingRes.success, true);
      const finding = findingRes.data!;

      assert.equal(finding.cwe_id, 'CWE-78');
      assert.equal(finding.owasp_category, 'LLM07:2025-Insecure-Tool-Design');
      assert.equal(finding.severity, 'CRITICAL');
      assert.equal(finding.target_type, 'MCP_TOOL');
      assert.equal(finding.target, 'execute_command');

      // Verify AgentSec metadata tracking
      assert.ok(finding.agent_sec);
      assert.equal(finding.agent_sec.taint_source, 'rag_document');
      assert.equal(finding.agent_sec.injection_vector, 'indirect_prompt_injection');
      assert.equal(finding.agent_sec.affected_parameter, 'arguments.command');
    });

    it('Stage 3: Reproducer Containment & Output Secret Redaction Verification', () => {
      const rawEvidence = selfCertifiedFixture.evidence;
      const evidenceRes = validateEvidence(rawEvidence);
      assert.equal(evidenceRes.success, true);

      const evidence = evidenceRes.data!;
      assert.equal(evidence.verification_type, 'REPRODUCER_EXECUTION');
      assert.equal(evidence.sandbox_environment.network_isolated, true);

      // Verify that secret credentials leaking in tool outputs are sanitized
      const leakyOutput = 'Execution dump: root:x:0:0:root:/root:/bin/bash\nAPI_KEY="sk-ant-api03-live-999988887777"\n';
      const sanitized = sanitizeOutput(leakyOutput);

      assert.ok(sanitized.includes('[REDACTED]'));
      assert.equal(sanitized.includes('sk-ant-api03'), false);
    });

    it('Stage 4: Gate Evaluation REJECTS on Self-Certification (Discoverer == Verifier)', async () => {
      const finding = validateFinding(selfCertifiedFixture.finding).data!;
      const selfCertifiedEvidence = validateEvidence(selfCertifiedFixture.evidence).data!;

      // Notice: finding discovering_agent_id === evidence verifier_agent_id ('agent-adversary-eval-01')
      assert.equal(
        finding.agent_context?.discovering_agent_id,
        selfCertifiedEvidence.verifier_agent_id,
        'Simulated adversarial condition: Discovering agent attempted self-certification'
      );

      const decision = await gate.evaluate({
        commit_hash: finding.commit_hash,
        findings: [finding],
        evidence: [selfCertifiedEvidence],
        discovering_agent_id: finding.agent_context?.discovering_agent_id,
        verifying_agent_id: selfCertifiedEvidence.verifier_agent_id,
        authorizing_agent_id: 'agent-auth-gate-04',
      });

      assert.notEqual(decision.verdict, 'PASS');
      assert.equal(decision.verdict, 'REJECT');
      assert.equal(decision.sod_evaluation.is_valid, false);
      assert.ok(decision.sod_evaluation.violation_details?.includes('E_SOD_SELF_CERTIFICATION'));
      assert.ok(decision.rules_evaluated.some((r) => r.rule_id === 'RULE_SEPARATION_OF_DUTIES' && r.status === 'FAIL'));
    });

    it('Stage 5: Remediation via Guardrail Patch & Independent Verification resolves to PASS', async () => {
      const finding = validateFinding(selfCertifiedFixture.finding).data!;

      // 1. Independent verifier re-executes reproduction
      const independentVerifierId = 'agent-independent-security-verifier-02';
      assert.notEqual(finding.agent_context?.discovering_agent_id, independentVerifierId);

      const verifiedEvidence = validateEvidence({
        ...selfCertifiedFixture.evidence,
        evidence_id: 'SK-EVID-AGENTSEC-INDEPENDENT-002',
        verifier_agent_id: independentVerifierId,
      }).data!;

      // 2. Patch agent applies MCP input guardrail schema
      const guardrailDiff = `--- a/apps/mcp-server/src/index.ts
+++ b/apps/mcp-server/src/index.ts
@@ -102,3 +102,5 @@
-  const cmd = request.params.arguments.command;
-  return execSync(cmd);
+  const ALLOWED_COMMANDS = ['git status', 'git diff', 'npm test'];
+  const cmd = request.params.arguments.command;
+  if (!ALLOWED_COMMANDS.includes(cmd)) throw new Error('E_COMMAND_NOT_ALLOWLISTED');
+  return execSync(cmd);
`;
      const patchSha = computePatchSha256(guardrailDiff);

      const patch = validatePatch({
        patch_id: 'SK-PATCH-AGENTSEC-GUARDRAIL-01',
        finding_id: finding.finding_id,
        author_engine: 'agent-remediation-patchcat-03',
        diff_content: guardrailDiff,
        affected_files: ['apps/mcp-server/src/index.ts'],
        base_commit: finding.commit_hash,
        patch_sha256: patchSha,
        recheck_status: 'passed_clean',
        recheck_evidence_id: verifiedEvidence.evidence_id,
        blast_radius: {
          files_modified: 1,
          lines_added: 4,
          lines_deleted: 2,
          ast_impact_scope: 'LOCAL_FUNCTION',
          downstream_dependents: [],
          breaking_change_risk: 'LOW',
        },
        rollback_plan: {
          revert_patch: '--- b/apps/mcp-server/src/index.ts\n+++ a/apps/mcp-server/src/index.ts\n',
        },
        created_at: new Date().toISOString(),
      }).data!;

      // 3. Gate evaluated with tri-party distinct agents
      const authorizerId = 'agent-auth-gate-04';
      const decision = await gate.evaluate({
        commit_hash: finding.commit_hash,
        findings: [finding],
        evidence: [verifiedEvidence],
        patches: [patch],
        discovering_agent_id: finding.agent_context?.discovering_agent_id,
        verifying_agent_id: independentVerifierId,
        authorizing_agent_id: authorizerId,
      });

      assert.equal(decision.verdict, 'PASS');
      assert.equal(decision.sod_evaluation.is_valid, true);
      assert.equal(decision.blocking_findings.length, 0);
      assert.equal(decision.unverified_findings.length, 0);
    });
  });
});
