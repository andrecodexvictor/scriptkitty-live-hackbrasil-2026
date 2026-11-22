#!/usr/bin/env node
/**
 * @file scripts/demo-wednesday.mjs
 * @description End-to-end ScriptKitty Live (PatchCat) Wednesday / HackBR Demo Script.
 *
 * Demonstrates in isolated LAB mode (zero production mutations, zero hardcoded secrets):
 *  1. Startup status (`security.status`, `HARNESS2_EXPERIMENTS_ENABLED=false`, Kali MCP `NOT_CONFIGURED`)
 *  2. Screen State 1: `payments-lab/baseline` -> 0 forbidden paths, 3/3 legitimate ops preserved
 *  3. Screen State 2: `payments-lab/unsafe-rollout` -> 1 `PATH_VALIDATED` path + edge sourceRefs
 *  4. JEV-as-a-Judge triage (`security.judge.evaluate`) -> explicit MOCK/LIVE provenance, `PENDING_REVIEW`
 *  5. Defensive `RemediationSpec` (`security.remediation.spec`) -> minimal `REMOVE_EDGE`, human approval required
 *  6. Screen State 3: `payments-lab/remediated` + `payments-lab/negative-control` -> 0 paths, 3/3 preserved
 *  7. Invokta MCP Streamable HTTP (`startMcpHttpServer` + `connectSecurityMcpClient`) parity + fail-closed security tests
 *  8. Zero-Trust Quality Gate (`DeterministicQualityGate`), Tri-Party SoD, RFC 8785 Merkle custody & `factory.delivery.v1`
 *  9. Hardened Kali Linux MCP Assessment (`@script-kitty/kali-mcp-assessment`: 4 allowlisted capabilities, zero-shell argv,
 *     Profile A/B isolation, fail-closed `LIVE_CONTAINER`, `RuntimeGuardian` HMAC delegation + Tri-Party SoD)
 * 10. PatchCat Orchestrator (`@script-kitty/patchcat-orchestrator`) + Evidence Ledger (`@script-kitty/evidence`):
 *     Signed ZenPR Advisory Bundle (`zenpr.advisory.v1`) with RFC 8785 binary Merkle inclusion proof,
 *     AI-prose rejection, tenant isolation, and `mergeAllowed=false` / `deployAllowed=false`
 */

import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ActionEngineError,
  SECURITY_CAPABILITY_IDS,
  connectSecurityMcpClient,
  createSecurityActionRuntime,
  startMcpHttpServer,
} from '@script-kitty/security-actions';
import {
  buildCustodyChain,
  computeEvidenceChainHash,
  computeFindingFingerprint,
  computePatchSha256,
  GateVerdict,
  sha256,
  validateEvidence,
  validateFinding,
  verifyChainOfCustody,
  verifyMerkleProof,
} from '@script-kitty/contracts';
import { DeterministicQualityGate } from '@script-kitty/quality-gate';
import { evaluateFactoryDeliveryEligibility } from '@script-kitty/company-context';
import { Harness2Adapter, KaliMcpAdapter } from '../packages/adapters/dist/index.js';
import {
  computeCanonicalDigest,
  EvidenceLedger,
  TenantIsolationError as EvidenceTenantIsolationError,
  UnverifiedAiProseError,
  verifyAnalysisMerkleBundle,
} from '../packages/evidence/dist/index.js';
import {
  assertNoPolicyOrGateMutation,
  assertTriPartySod,
  PatchCatGovernanceError,
  PatchCatOrchestrator,
  ZenPrBundleSchema,
} from '../packages/patchcat-orchestrator/dist/index.js';
import {
  buildSafeKaliArgv,
  createKaliMcpServer,
  executeKaliCapability,
  generateProfileAArgs,
  KALI_CAPABILITY_NAMES,
  KALI_MODE,
  KaliSandboxOrchestrator,
  KaliSecurityError,
  mintKaliDelegationToken,
  validateProfileAArgs,
} from '../packages/kali-mcp-assessment/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

function printHeader(step, title) {
  console.log('\n' + '='.repeat(84));
  console.log(` [${step}] ${title}`);
  console.log('='.repeat(84));
}

function logJson(label, value) {
  console.log(`${label}: ${JSON.stringify(value, null, 2)}`);
}

async function runDemo() {
  const kaliAdapter = new KaliMcpAdapter();
  const harness2Adapter = new Harness2Adapter();
  const kaliStatus = kaliAdapter.getStatus();
  const harness2Status = harness2Adapter.getStatus();

  const runtime = createSecurityActionRuntime({
    dbPath: ':memory:',
    externalAdaptersStatus: () => ({
      patchcat: {
        status: 'ISOLATED_LAB_ONLY',
        mode: 'LAB',
        enabled: true,
        externalExecution: false,
      },
      typesafeJev: {
        status: process.env.TYPESAFE_API_KEY?.trim() ? 'LIVE' : 'NOT_CONFIGURED',
        mode: process.env.TYPESAFE_API_KEY?.trim() ? 'LIVE' : 'MOCK_OFFLINE',
        enabled: Boolean(process.env.TYPESAFE_API_KEY?.trim()),
        externalExecution: false,
      },
      kaliMcp: {
        status: kaliStatus.configuration_status,
        mode: kaliStatus.mode,
        enabled: kaliStatus.enabled,
        externalExecution: false,
        detail: 'Allowlisted defensive verification contract only (zero shell/payload execution)',
      },
      harness2: {
        status: harness2Status.configuration_status,
        mode: harness2Status.mode,
        enabled: harness2Status.enabled,
        externalExecution: false,
      },
      factoryDeliveryGate: {
        status: 'READY',
        mode: 'LAB',
        enabled: true,
        externalExecution: false,
      },
    }),
  });

  const alphaPrincipal = {
    principalId: 'operator-patchcat-alpha',
    tenantId: 'payments-lab',
    roles: ['security-operator'],
    scopes: [
      'security:status',
      'security:analyze',
      'security:read',
      'security:judge',
      'security:remediate',
    ],
  };

  const betaPrincipal = {
    principalId: 'operator-tenant-beta',
    tenantId: 'tenant-beta',
    roles: ['security-operator'],
    scopes: [
      'security:status',
      'security:analyze',
      'security:read',
      'security:judge',
      'security:remediate',
    ],
  };

  const directCtx = {
    principal: alphaPrincipal,
    correlationId: 'demo-wednesday-direct-001',
    source: 'cli',
  };

  let mcpServer;
  let alphaClient;
  let betaClient;

  try {
    // -------------------------------------------------------------------------
    // STEP 1: System Banner & security.status
    // -------------------------------------------------------------------------
    printHeader('1/10', 'ScriptKitty Live (PatchCat) — Readiness & Boundary Check (security.status)');
    const statusRes = await runtime.engine.invoke('security.status', {}, directCtx);

    assert.equal(statusRes.mode, 'LAB');
    assert.equal(statusRes.productionTested, false);
    assert.equal(statusRes.mergeAllowed, false);
    assert.equal(statusRes.deployAllowed, false);
    assert.equal(statusRes.HARNESS2_EXPERIMENTS_ENABLED, false);
    assert.equal(kaliStatus.configuration_status, 'NOT_CONFIGURED');

    logJson('security.status', {
      service: statusRes.service,
      mode: statusRes.mode,
      productionTested: statusRes.productionTested,
      mergeAllowed: statusRes.mergeAllowed,
      deployAllowed: statusRes.deployAllowed,
      HARNESS2_EXPERIMENTS_ENABLED: statusRes.HARNESS2_EXPERIMENTS_ENABLED,
      jevProviderStatus: statusRes.jevProviderStatus,
      kaliMcpStatus: kaliStatus.configuration_status,
      kaliAllowedCapabilities: kaliStatus.capabilities,
      capabilities: statusRes.components.actionEngine.capabilities,
    });

    // -------------------------------------------------------------------------
    // STEP 2: Screen State 1 — Baseline (Clean Policy Graph)
    // -------------------------------------------------------------------------
    printHeader('2/10', 'Screen State 1 — ChainBreak Baseline (`payments-lab/baseline`)');
    const baselineRes = await runtime.engine.invoke(
      'security.chainbreak.analyze',
      { fixtureId: 'payments-lab/baseline' },
      directCtx
    );

    assert.equal(baselineRes.status, 'COMPLETED');
    assert.equal(baselineRes.analysis.paths.length, 0);
    assert.equal(baselineRes.analysis.legitimateOperationsPreserved, true);
    assert.equal(baselineRes.analysis.legitimateOperations.length, 3);
    assert.equal(baselineRes.productionTested, false);

    logJson('baseline.summary', {
      analysisId: baselineRes.analysisId,
      fixtureId: baselineRes.analysis.fixtureId,
      policyVersion: baselineRes.analysis.policyVersion,
      inputSha256: baselineRes.analysis.inputSha256,
      forbiddenPaths: baselineRes.analysis.paths.length,
      legitimateOperationsPreserved: baselineRes.analysis.legitimateOperationsPreserved,
      legitimateOperationsCount: baselineRes.analysis.legitimateOperations.length,
    });

    // -------------------------------------------------------------------------
    // STEP 3: Screen State 2 — Unsafe Rollout (Deterministic Reachability)
    // -------------------------------------------------------------------------
    printHeader('3/10', 'Screen State 2 — ChainBreak Unsafe Rollout (`payments-lab/unsafe-rollout`)');
    const unsafeRes = await runtime.engine.invoke(
      'security.chainbreak.analyze',
      { fixtureId: 'payments-lab/unsafe-rollout' },
      directCtx
    );

    assert.equal(unsafeRes.status, 'COMPLETED');
    assert.equal(unsafeRes.analysis.paths.length, 1);
    const attackPath = unsafeRes.analysis.paths[0];
    assert.equal(attackPath.status, 'PATH_VALIDATED');
    assert.equal(attackPath.violatedPolicyId, 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER');
    assert.ok(attackPath.evidenceIds.length >= 1);

    logJson('unsafe-rollout.summary', {
      analysisId: unsafeRes.analysisId,
      fixtureId: unsafeRes.analysis.fixtureId,
      policyVersion: unsafeRes.analysis.policyVersion,
      inputSha256: unsafeRes.analysis.inputSha256,
      forbiddenPaths: unsafeRes.analysis.paths.length,
      pathId: attackPath.pathId,
      status: attackPath.status,
      semanticNote:
        'PATH_VALIDATED = deterministic reachability in modeled LAB policy graph (NOT EXPLOIT_CONFIRMED)',
      violatedPolicyId: attackPath.violatedPolicyId,
      riskRecommendation: attackPath.riskRecommendation,
      edgeChain: attackPath.edges.map((e) => ({
        edgeId: e.edgeId,
        transition: `${e.from} --[${e.kind}]--> ${e.to}`,
        sourceRef: e.sourceRef,
      })),
      evidenceIds: attackPath.evidenceIds,
      nonTechnicalSummary: attackPath.nonTechnicalSummary,
    });

    // -------------------------------------------------------------------------
    // STEP 4: JEV-as-a-Judge Triage (Bounded, Sanitized, Fail-Closed)
    // -------------------------------------------------------------------------
    printHeader('4/10', 'JEV-as-a-Judge Advisory Evaluation (`security.judge.evaluate`)');
    const judgeRes = await runtime.engine.invoke(
      'security.judge.evaluate',
      {
        analysisId: unsafeRes.analysisId,
        expectedInputSha256: unsafeRes.analysis.inputSha256,
      },
      directCtx
    );

    const adj = judgeRes.adjudication;
    assert.equal(adj.status, 'PENDING_REVIEW');
    assert.equal(adj.escalated, true);
    assert.equal(adj.mergeAllowed, false);
    assert.equal(adj.deployAllowed, false);
    assert.equal(adj.exploitConfirmed, false);
    assert.equal(adj.p0DefinedByJevAlone, false);
    assert.equal(adj.confidenceOrUncertainty.thresholdCalibrated, false);

    logJson('jev.adjudication', {
      evaluationId: adj.evaluationId,
      analysisId: adj.analysisId,
      providerStatus: adj.providerStatus,
      decisionSource: adj.decisionSource,
      model: adj.model,
      preValidationPassed: adj.preValidation.passed,
      triage: adj.triage,
      status: adj.status,
      decision: adj.decision,
      escalated: adj.escalated,
      escalationReasons: adj.escalationReasons,
      riskRecommendation: adj.riskRecommendation,
      thresholdCalibrated: adj.confidenceOrUncertainty.thresholdCalibrated,
      sanitizedStateDigest: adj.sanitizedStateDigest,
      mergeAllowed: adj.mergeAllowed,
      deployAllowed: adj.deployAllowed,
      p0DefinedByJevAlone: adj.p0DefinedByJevAlone,
    });

    // -------------------------------------------------------------------------
    // STEP 5: Counterfactual Minimal RemediationSpec (`security.remediation.spec`)
    // -------------------------------------------------------------------------
    printHeader('5/10', 'Minimal Defensive Remediation Spec (`security.remediation.spec`)');
    const remRes = await runtime.engine.invoke(
      'security.remediation.spec',
      {
        analysisId: unsafeRes.analysisId,
        pathId: attackPath.pathId,
      },
      directCtx
    );

    assert.equal(remRes.requiresHumanApproval, true);
    assert.equal(remRes.autoApplyAllowed, false);
    assert.equal(remRes.mergeAllowed, false);
    assert.equal(remRes.deployAllowed, false);
    assert.equal(remRes.remediationSpec.breaksUnauthorizedPath, true);
    assert.equal(remRes.remediationSpec.preservesLegitimateOperations, true);
    assert.equal(remRes.remediationSpec.actions[0].actionType, 'REMOVE_EDGE');
    assert.equal(remRes.remediationSpec.actions[0].edgeId, 'e-rollout-exporter-read-pii');

    logJson('remediation.spec', {
      remediationId: remRes.remediationSpec.remediationId,
      minimalChange: remRes.remediationSpec.minimalChange,
      action: remRes.remediationSpec.actions[0],
      breaksUnauthorizedPath: remRes.remediationSpec.breaksUnauthorizedPath,
      preservesLegitimateOperations: remRes.remediationSpec.preservesLegitimateOperations,
      preservedOperationIds: remRes.remediationSpec.preservedOperationIds,
      requiresHumanApproval: remRes.requiresHumanApproval,
      autoApplyAllowed: remRes.autoApplyAllowed,
      nonTechnicalSummary: remRes.remediationSpec.nonTechnicalSummary,
      acceptanceCriteria: remRes.remediationSpec.acceptanceCriteria,
      verificationTests: remRes.remediationSpec.verificationTests,
    });

    // -------------------------------------------------------------------------
    // STEP 6: Screen State 3 — Remediated + Negative Control
    // -------------------------------------------------------------------------
    printHeader('6/10', 'Screen State 3 — Remediated (`payments-lab/remediated`) & Negative Control');
    const remediatedRes = await runtime.engine.invoke(
      'security.chainbreak.analyze',
      { fixtureId: 'payments-lab/remediated' },
      directCtx
    );
    const negControlRes = await runtime.engine.invoke(
      'security.chainbreak.analyze',
      { fixtureId: 'payments-lab/negative-control' },
      directCtx
    );

    assert.equal(remediatedRes.status, 'COMPLETED');
    assert.equal(remediatedRes.analysis.paths.length, 0);
    assert.equal(remediatedRes.analysis.legitimateOperationsPreserved, true);
    assert.equal(remediatedRes.analysis.legitimateOperations.length, 3);
    assert.equal(negControlRes.status, 'COMPLETED');
    assert.equal(negControlRes.analysis.paths.length, 0);

    logJson('remediation-and-negative-control', {
      remediated: {
        analysisId: remediatedRes.analysisId,
        fixtureId: remediatedRes.analysis.fixtureId,
        policyVersion: remediatedRes.analysis.policyVersion,
        forbiddenPathsBefore: unsafeRes.analysis.paths.length,
        forbiddenPathsAfter: remediatedRes.analysis.paths.length,
        legitimateOperationsPreserved: remediatedRes.analysis.legitimateOperationsPreserved,
        preservedCount: remediatedRes.analysis.legitimateOperations.length,
      },
      negativeControl: {
        analysisId: negControlRes.analysisId,
        fixtureId: negControlRes.analysis.fixtureId,
        forbiddenPaths: negControlRes.analysis.paths.length,
        status: negControlRes.status,
      },
    });

    // -------------------------------------------------------------------------
    // STEP 7: Live Invokta MCP Streamable HTTP Client Call + Fail-Closed Checks
    // -------------------------------------------------------------------------
    printHeader('7/10', 'MCP Streamable HTTP (`127.0.0.1`) Live Client + Parity + Fail-Closed Tests');
    const tokenAlpha = `sk-demo-alpha-${crypto.randomBytes(12).toString('hex')}`;
    const tokenBeta = `sk-demo-beta-${crypto.randomBytes(12).toString('hex')}`;
    const allowedOrigin = 'http://127.0.0.1:5173';

    mcpServer = await startMcpHttpServer(runtime.engine, {
      host: '127.0.0.1',
      port: 0,
      path: '/mcp',
      allowedOrigins: [allowedOrigin],
      requireOriginHeader: true,
      tokens: {
        [tokenAlpha]: alphaPrincipal,
        [tokenBeta]: betaPrincipal,
      },
    });

    alphaClient = await connectSecurityMcpClient({
      url: mcpServer.url,
      token: tokenAlpha,
      origin: allowedOrigin,
      correlationId: 'demo-mcp-alpha-001',
    });

    const toolsList = await alphaClient.listTools();
    const toolNames = toolsList.tools.map((t) => t.name).sort();
    assert.equal(toolNames.length, 14);
    assert.deepEqual(toolNames, [...SECURITY_CAPABILITY_IDS].sort());

    const mcpAnalyze = await alphaClient.callToolJson('security.chainbreak.analyze', {
      fixtureId: 'payments-lab/unsafe-rollout',
    });
    assert.equal(mcpAnalyze.isError, false);
    assert.equal(mcpAnalyze.parsed.analysisId, unsafeRes.analysisId);
    assert.equal(mcpAnalyze.parsed.idempotentReplay, true);

    const mcpGet = await alphaClient.callToolJson('security.chainbreak.get', {
      analysisId: unsafeRes.analysisId,
    });
    assert.equal(mcpGet.isError, false);
    assert.equal(mcpGet.parsed.analysis.analysisId, unsafeRes.analysisId);
    assert.equal(mcpGet.parsed.adjudications.length, 1);
    assert.equal(mcpGet.parsed.remediationSpecs.length, 1);

    const mcpJudge = await alphaClient.callToolJson('security.judge.evaluate', {
      analysisId: unsafeRes.analysisId,
    });
    assert.equal(mcpJudge.isError, false);
    assert.equal(mcpJudge.parsed.adjudication.status, 'PENDING_REVIEW');

    // Negative HTTP / Security Boundary checks
    // 7a. Cross-tenant access attempt over MCP HTTP
    betaClient = await connectSecurityMcpClient({
      url: mcpServer.url,
      token: tokenBeta,
      origin: allowedOrigin,
      correlationId: 'demo-mcp-beta-cross-tenant',
    });
    const crossTenantRes = await betaClient.callToolJson('security.chainbreak.get', {
      analysisId: unsafeRes.analysisId,
    });
    assert.equal(crossTenantRes.isError, true);
    assert.equal(crossTenantRes.parsed.code, 'FORBIDDEN');

    // 7b. TenantId body injection attempt over MCP HTTP
    const bodyTenantInjectRes = await betaClient.callToolJson('security.chainbreak.analyze', {
      fixtureId: 'payments-lab/baseline',
      tenantId: 'payments-lab',
    });
    assert.equal(bodyTenantInjectRes.isError, true);

    // 7c. Missing Bearer token -> 401
    const unauthResp = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: allowedOrigin,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(unauthResp.status, 401);

    // 7d. Forbidden Origin -> 403
    const badOriginResp = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${tokenAlpha}`,
        origin: 'https://evil.example',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(badOriginResp.status, 403);

    // Verify direct invocation also rejects cross-tenant body spoofing fail-closed
    await assert.rejects(
      () =>
        runtime.engine.invoke(
          'security.chainbreak.get',
          { analysisId: unsafeRes.analysisId },
          { principal: betaPrincipal, source: 'cli' }
        ),
      (err) => err instanceof ActionEngineError && err.code === 'FORBIDDEN'
    );

    logJson('mcp-http.verification', {
      endpoint: mcpServer.url,
      sessionId: alphaClient.sessionId,
      toolsListed: toolNames,
      httpParityAnalysisId: mcpAnalyze.parsed.analysisId,
      idempotentReplay: mcpAnalyze.parsed.idempotentReplay,
      persistedHistoryEvents: mcpGet.parsed.decisionHistory.length,
      failClosedChecks: {
        crossTenantMcpRead: `REJECTED (${crossTenantRes.parsed.code})`,
        payloadTenantIdInjection: 'REJECTED (isError=true)',
        missingBearerToken: `HTTP ${unauthResp.status}`,
        disallowedOrigin: `HTTP ${badOriginResp.status}`,
      },
    });

    // -------------------------------------------------------------------------
    // STEP 8: Quality Gate (SoD + Merkle Custody) & factory.delivery.v1
    // -------------------------------------------------------------------------
    printHeader('8/10', 'Zero-Trust Quality Gate, Tri-Party SoD, Merkle Custody & factory.delivery.v1');
    const commitSha = 'a1b2c3d4e5f67890123456789abcdef012345678';
    const recordedAt = '2026-11-11T12:00:00.000Z';

    const finding = {
      finding_id: 'SK-FIND-CB-PAYMENTS-001',
      source_engine: 'chainbreak-v0',
      title: 'Unauthorized RESTRICTED PII Data Path via Report Exporter Rollout',
      description: 'Unsafe rollout edge e-rollout-exporter-read-pii enables PII reachability to external sink.',
      cwe_id: 'CWE-284',
      owasp_category: 'A01:2021-Broken Access Control',
      severity: 'HIGH',
      confidence: 'CERTAIN',
      target_type: 'CONFIGURATION',
      target: 'fixtures/payments-lab/unsafe-rollout.json',
      location: {
        file_path: 'policies/payments-lab/report-exporter-rollout.yaml',
        start_line: 24,
        end_line: 38,
        symbol: 'report-exporter',
      },
      fingerprint: computeFindingFingerprint({
        cwe_id: 'CWE-284',
        file_path: 'policies/payments-lab/report-exporter-rollout.yaml',
        rule_or_match: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      }),
      commit_hash: commitSha,
      discovered_at: recordedAt,
      agent_context: {
        discovering_agent_id: 'agent-discovery-chainbreak',
        agent_archetype: 'policy_graph_analyzer',
        tool_call_trace: ['security.chainbreak.analyze'],
      },
      raw_metadata: { analysisId: unsafeRes.analysisId, mode: 'LAB' },
    };

    const evidenceScriptHash = sha256(attackPath.pathId);
    const evidence = {
      evidence_id: 'SK-EVID-CB-PAYMENTS-001',
      finding_id: finding.finding_id,
      verification_type: 'REPRODUCER_EXECUTION',
      status: 'VERIFIED_TRUE_POSITIVE',
      verifier_agent_id: 'agent-verifier-sandbox',
      sandbox_environment: {
        runtime: 'node_sandbox',
        network_isolated: true,
        timeout_ms: 5000,
      },
      reproducer_artifact: {
        script_path: 'fixtures/payments-lab/remediated.json',
        script_sha256: evidenceScriptHash,
        exit_code: 1,
        stdout: `PATH_VALIDATED:${attackPath.pathId}`,
        stderr: '',
        execution_duration_ms: 12,
      },
      reproduction_proof: {
        proof_type: 'EXECUTABLE_POC',
        payload: attackPath.pathId,
        expected_behavior: '0 paths violating NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
        observed_vulnerable_behavior: '1 modeled policy path from support-agent to external-report-sink',
      },
      chain_hash: computeEvidenceChainHash({
        finding_id: finding.finding_id,
        verifier_agent_id: 'agent-verifier-sandbox',
        status: 'VERIFIED_TRUE_POSITIVE',
        script_sha256: evidenceScriptHash,
        recorded_at: recordedAt,
      }),
      recorded_at: recordedAt,
    };

    const diffContent = [
      '--- a/policies/payments-lab/report-exporter-rollout.yaml',
      '+++ b/policies/payments-lab/report-exporter-rollout.yaml',
      '@@ -24,3 +24,0 @@',
      '- edge: e-rollout-exporter-read-pii (ALLOW mcp_tool:report-exporter -> data_asset:customer-payment-pii)',
    ].join('\n');

    const patch = {
      patch_id: 'SK-PATCH-CB-PAYMENTS-001',
      finding_id: finding.finding_id,
      author_engine: 'agent-remediation-patchcat',
      diff_content: diffContent,
      affected_files: ['policies/payments-lab/report-exporter-rollout.yaml'],
      base_commit: commitSha,
      patch_sha256: computePatchSha256(diffContent),
      recheck_status: 'passed_clean',
      recheck_evidence_id: evidence.evidence_id,
      blast_radius: {
        files_modified: 1,
        lines_added: 0,
        lines_deleted: 1,
        ast_impact_scope: 'LOCAL_FUNCTION',
        downstream_dependents: [],
        breaking_change_risk: 'LOW',
      },
      rollback_plan: {
        revert_patch: diffContent.replace(/^- /gm, '+ '),
        killswitch_flag: 'REVERT_REPORT_EXPORTER_EDGE_RESTRICTION',
      },
      created_at: recordedAt,
    };

    const custodyChain = buildCustodyChain({ finding, evidence, patch });
    const custodyCheck = verifyChainOfCustody(custodyChain);
    assert.equal(custodyCheck.valid, true);

    const gate = new DeterministicQualityGate();
    const passDecision = await gate.evaluate({
      target_commit: commitSha,
      findings: [finding],
      evidence: [evidence],
      patches: [patch],
      discovering_agent_id: 'agent-discovery-chainbreak',
      verifying_agent_id: 'agent-verifier-sandbox',
      authorizing_agent_id: 'agent-authorizer-gate',
      custody_chain: custodyChain,
    });
    assert.equal(passDecision.verdict, GateVerdict.PASS);

    const selfCertRejectDecision = await gate.evaluate({
      target_commit: commitSha,
      findings: [finding],
      evidence: [evidence],
      patches: [patch],
      discovering_agent_id: 'agent-omnipotent',
      verifying_agent_id: 'agent-omnipotent',
      authorizing_agent_id: 'agent-authorizer-gate',
    });
    assert.equal(selfCertRejectDecision.verdict, GateVerdict.REJECT);

    const deliveryCheck = evaluateFactoryDeliveryEligibility(
      {
        contract: 'factory.delivery.v1',
        snapshot: {
          cancelled: false,
          deadlineAt: '2026-11-12T12:00:00.000Z',
          submissions: 1,
          maxSubmissions: 4,
          submitter: 'agent-remediation-patchcat',
          reviewer: 'human-security-reviewer',
          artifact: {
            commitSha,
            summary: 'Removed unsafe rollout edge e-rollout-exporter-read-pii and verified 0 paths.',
            checks: [
              { key: 'tests', status: 'passed', evidenceRef: 'ci/tests-pass-001' },
              { key: 'typecheck', status: 'passed', evidenceRef: 'ci/tsc-pass-001' },
              { key: 'build', status: 'passed', evidenceRef: 'ci/build-pass-001' },
            ],
          },
          review: {
            commitSha,
            verdict: 'approve',
            summary: 'Independent review confirmed minimal change and preserved legitimate operations.',
            evidenceRefs: [evidence.evidence_id],
          },
        },
        authority: {
          enabled: true,
          requesterActive: true,
          submitterActive: true,
          reviewerActive: true,
        },
      },
      { headSha: commitSha, now: '2026-11-11T12:00:00.000Z' }
    );
    assert.equal(deliveryCheck.eligible, true);
    assert.equal(deliveryCheck.mergeAllowed, false);
    assert.equal(deliveryCheck.deployAllowed, false);
    assert.equal(deliveryCheck.externalExecution, false);

    logJson('quality-gate-and-delivery', {
      custodyChain: {
        chainId: custodyChain.chain_id,
        totalNodes: custodyCheck.total_nodes,
        valid: custodyCheck.valid,
        merkleRoot: custodyCheck.merkle_root,
      },
      qualityGateTriPartyPass: {
        decisionId: passDecision.decision_id,
        verdict: passDecision.verdict,
        sodValid: passDecision.sod_evaluation.is_valid,
        auditMerkleRoot: passDecision.audit_merkle_root,
      },
      qualityGateSelfCertReject: {
        verdict: selfCertRejectDecision.verdict,
        sodValid: selfCertRejectDecision.sod_evaluation.is_valid,
        violation: selfCertRejectDecision.sod_evaluation.violation_details,
      },
      factoryDeliveryV1: {
        contract: deliveryCheck.contract,
        eligible: deliveryCheck.eligible,
        stage: deliveryCheck.stage,
        mergeAllowed: deliveryCheck.mergeAllowed,
        deployAllowed: deliveryCheck.deployAllowed,
        externalExecution: deliveryCheck.externalExecution,
      },
    });

    // -------------------------------------------------------------------------
    // STEP 9: Hardened Kali Linux MCP Assessment (@script-kitty/kali-mcp-assessment)
    // -------------------------------------------------------------------------
    printHeader(
      '9/10',
      'Kali MCP Assessment (`@script-kitty/kali-mcp-assessment`: 4 Allowlisted Tools, Zero-Shell Argv, RuntimeGuardian & Tri-Party SoD)'
    );

    assert.equal(KALI_MODE, 'LAB_SANDBOX_ONLY');
    assert.deepEqual([...KALI_CAPABILITY_NAMES], [
      'security.kali.recon_surface',
      'security.kali.config_audit',
      'security.kali.verify_reproducer',
      'security.kali.sbom_cve_check',
    ]);

    const kaliScope = {
      scope_id: 'SK-SCOPE-DEMO-WED',
      authorized_by: 'agent-quality-gate-authority',
      mode: 'LAB',
      target_allowlist: ['127.0.0.1', 'lab-app.localnet'],
      expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    };

    const sqliReproRelPath = 'apps/lab-app/repro/repro-sqli.mts';
    const sqliReproSha256 = sha256(fs.readFileSync(path.join(REPO_ROOT, sqliReproRelPath)));

    const reconArgvSpec = buildSafeKaliArgv('security.kali.recon_surface', {
      scope: kaliScope,
      target_host: '127.0.0.1',
      ports: [80, 443, 3000],
      probe_profile: 'tcp_connect_ports',
      discovering_agent_id: 'agent-kali-recon-scout',
    });
    const configArgvSpec = buildSafeKaliArgv('security.kali.config_audit', {
      scope: kaliScope,
      audit_mode: 'static_config_tree',
      config_rel_path: 'apps/lab-app/package.json',
      discovering_agent_id: 'agent-kali-recon-scout',
    });
    const sbomArgvSpec = buildSafeKaliArgv('security.kali.sbom_cve_check', {
      scope: kaliScope,
      manifest_rel_path: 'apps/lab-app/package.json',
      scanner_engine: 'trivy_offline',
      severity_filter: ['CRITICAL', 'HIGH'],
      discovering_agent_id: 'agent-kali-recon-scout',
    });
    const verifyArgvSpec = buildSafeKaliArgv('security.kali.verify_reproducer', {
      scope: kaliScope,
      finding_id: 'SK-KALI-DEMO-SQLI-01',
      discovering_agent_id: 'agent-kali-recon-scout',
      verifier_agent_id: 'agent-kali-sandbox-verifier',
      authorizing_agent_id: 'agent-quality-gate-authority',
      reproducer_rel_path: sqliReproRelPath,
      expected_reproducer_sha256: sqliReproSha256,
      reproducer_runtime: 'node',
    });

    // Verify shell/SSRF/flag-injection rejections
    let rejectedImdsCode = '';
    try {
      buildSafeKaliArgv('security.kali.recon_surface', {
        scope: kaliScope,
        target_host: '169.254.169.254',
        discovering_agent_id: 'agent-kali-recon-scout',
      });
    } catch (err) {
      assert.ok(err instanceof KaliSecurityError);
      rejectedImdsCode = err.code;
    }
    assert.equal(rejectedImdsCode, 'KALI_BLOCKED_IMDS_TARGET');

    let rejectedFlagInjCode = '';
    try {
      buildSafeKaliArgv('security.kali.recon_surface', {
        scope: kaliScope,
        target_host: '-spoofed-flag',
        discovering_agent_id: 'agent-kali-recon-scout',
      });
    } catch (err) {
      assert.ok(err instanceof KaliSecurityError);
      rejectedFlagInjCode = err.code;
    }
    assert.equal(rejectedFlagInjCode, 'KALI_FLAG_INJECTION_BLOCKED');

    // Verify Profile A OCI+gVisor isolation & fail-closed LIVE_CONTAINER
    const profileA = generateProfileAArgs({
      workspaceRoot: REPO_ROOT,
      networkMode: 'airgapped',
      hostEnv: { AWS_SECRET_ACCESS_KEY: 'demo-should-strip-never-leak' },
      innerSpec: sbomArgvSpec,
    });
    const profileACheck = validateProfileAArgs(profileA.argv, { requireGvisor: true });
    assert.equal(profileACheck.valid, true);

    const noRuntimeOrchestrator = new KaliSandboxOrchestrator({
      workspaceRoot: REPO_ROOT,
      execFileImpl: async () => ({ exitCode: 1, stdout: '', stderr: 'no gVisor/WSL2 sandbox in demo' }),
    });
    let liveFailClosedCode = '';
    try {
      await executeKaliCapability(
        'security.kali.sbom_cve_check',
        {
          scope: kaliScope,
          manifest_rel_path: 'apps/lab-app/package.json',
          discovering_agent_id: 'agent-kali-recon-scout',
        },
        {
          workspaceRoot: REPO_ROOT,
          requestedExecutionMode: 'LIVE_CONTAINER',
          orchestrator: noRuntimeOrchestrator,
        }
      );
    } catch (err) {
      assert.ok(err instanceof KaliSecurityError);
      liveFailClosedCode = err.code;
    }
    assert.equal(liveFailClosedCode, 'KALI_SANDBOX_UNAVAILABLE');

    // Execute all 4 allowlisted capabilities through RuntimeGuardian MCP wrapper (`LAB_SIMULATION`)
    const kaliHmacSecret = `sk-demo-kali-hmac-${crypto.randomBytes(16).toString('hex')}`;
    const kaliServer = createKaliMcpServer({
      workspaceRoot: REPO_ROOT,
      hmacSecret: kaliHmacSecret,
      requestedExecutionMode: 'LAB_SIMULATION',
      orchestrator: noRuntimeOrchestrator,
    });

    const kaliToolsRes = await kaliServer.listTools({
      session_id: 'demo-kali-session',
      caller_agent_id: 'agent-kali-recon-scout',
    });
    assert.deepEqual(
      kaliToolsRes.tools.map((t) => t.name),
      [...KALI_CAPABILITY_NAMES]
    );

    const kReconTok = mintKaliDelegationToken({
      issuer: 'agent-quality-gate-authority',
      subject: 'agent-kali-recon-scout',
      toolName: 'security.kali.recon_surface',
      hmacSecret: kaliHmacSecret,
    });
    const kReconRes = await kaliServer.callTool({
      name: 'security.kali.recon_surface',
      arguments: {
        scope: kaliScope,
        target_host: '127.0.0.1',
        ports: [80, 3000],
        probe_profile: 'tcp_connect_ports',
        discovering_agent_id: 'agent-kali-recon-scout',
      },
      _meta: { caller_agent_id: 'agent-kali-recon-scout', delegation_token: kReconTok },
    });
    assert.equal(kReconRes.isError, false);
    const kReconData = JSON.parse(kReconRes.content[0].text);
    assert.equal(kReconData.executionMode, 'LAB_SIMULATION');
    assert.equal(validateFinding(kReconData.findings[0]).success, true);

    const kCfgTok = mintKaliDelegationToken({
      issuer: 'agent-quality-gate-authority',
      subject: 'agent-kali-recon-scout',
      toolName: 'security.kali.config_audit',
      hmacSecret: kaliHmacSecret,
    });
    const kCfgRes = await kaliServer.callTool({
      name: 'security.kali.config_audit',
      arguments: {
        scope: kaliScope,
        audit_mode: 'static_config_tree',
        config_rel_path: 'apps/lab-app/package.json',
        discovering_agent_id: 'agent-kali-recon-scout',
      },
      _meta: { caller_agent_id: 'agent-kali-recon-scout', delegation_token: kCfgTok },
    });
    assert.equal(kCfgRes.isError, false);

    const kSbomTok = mintKaliDelegationToken({
      issuer: 'agent-quality-gate-authority',
      subject: 'agent-kali-recon-scout',
      toolName: 'security.kali.sbom_cve_check',
      hmacSecret: kaliHmacSecret,
    });
    const kSbomRes = await kaliServer.callTool({
      name: 'security.kali.sbom_cve_check',
      arguments: {
        scope: kaliScope,
        manifest_rel_path: 'apps/lab-app/package.json',
        scanner_engine: 'trivy_offline',
        severity_filter: ['CRITICAL', 'HIGH'],
        discovering_agent_id: 'agent-kali-recon-scout',
      },
      _meta: { caller_agent_id: 'agent-kali-recon-scout', delegation_token: kSbomTok },
    });
    assert.equal(kSbomRes.isError, false);
    const kSbomData = JSON.parse(kSbomRes.content[0].text);
    assert.equal(kSbomData.networkMode, 'airgapped');
    assert.equal(kSbomData.sbom_summary.bomFormat, 'CycloneDX');

    // Tri-Party SoD Self-Certification Rejection (A_disc === A_veri)
    const selfCertTok = mintKaliDelegationToken({
      issuer: 'agent-quality-gate-authority',
      subject: 'agent-kali-recon-scout',
      toolName: 'security.kali.verify_reproducer',
      hmacSecret: kaliHmacSecret,
      discoveringAgentId: 'agent-kali-recon-scout',
    });
    const selfCertKaliCall = await kaliServer.callTool({
      name: 'security.kali.verify_reproducer',
      arguments: {
        scope: kaliScope,
        finding_id: 'SK-KALI-DEMO-SQLI-01',
        discovering_agent_id: 'agent-kali-recon-scout',
        verifier_agent_id: 'agent-kali-recon-scout',
        authorizing_agent_id: 'agent-quality-gate-authority',
        reproducer_rel_path: sqliReproRelPath,
        expected_reproducer_sha256: sqliReproSha256,
        reproducer_runtime: 'node',
      },
      _meta: {
        caller_agent_id: 'agent-kali-recon-scout',
        discovering_agent_id: 'agent-kali-recon-scout',
        authorizing_agent_id: 'agent-quality-gate-authority',
        delegation_token: selfCertTok,
      },
    });
    assert.equal(selfCertKaliCall.isError, true);
    assert.match(selfCertKaliCall.content[0].text, /E_SOD_SELF_CERTIFICATION/);

    // Valid Tri-Party Verified Reproducer Call (`A_disc != A_veri != A_auth`)
    const kVeriTok = mintKaliDelegationToken({
      issuer: 'agent-quality-gate-authority',
      subject: 'agent-kali-sandbox-verifier',
      toolName: 'security.kali.verify_reproducer',
      hmacSecret: kaliHmacSecret,
      discoveringAgentId: 'agent-kali-recon-scout',
      findingId: kReconData.findings[0].finding_id,
    });
    const kVeriRes = await kaliServer.callTool({
      name: 'security.kali.verify_reproducer',
      arguments: {
        scope: kaliScope,
        finding_id: kReconData.findings[0].finding_id,
        discovering_agent_id: 'agent-kali-recon-scout',
        verifier_agent_id: 'agent-kali-sandbox-verifier',
        authorizing_agent_id: 'agent-quality-gate-authority',
        reproducer_rel_path: sqliReproRelPath,
        expected_reproducer_sha256: sqliReproSha256,
        reproducer_runtime: 'node',
      },
      _meta: {
        caller_agent_id: 'agent-kali-sandbox-verifier',
        discovering_agent_id: 'agent-kali-recon-scout',
        authorizing_agent_id: 'agent-quality-gate-authority',
        delegation_token: kVeriTok,
      },
    });
    assert.equal(kVeriRes.isError, false);
    const kVeriData = JSON.parse(kVeriRes.content[0].text);
    assert.equal(kVeriData.ok, true);
    assert.equal(kVeriData.evidence.status, 'VERIFIED_TRUE_POSITIVE');
    assert.equal(validateEvidence(kVeriData.evidence).success, true);
    assert.equal(verifyChainOfCustody(kVeriData.custody.chain).valid, true);

    const kaliAuditCheck = await kaliServer.guardian.getAuditLogger().verifyIntegrity();
    assert.equal(kaliAuditCheck.valid, true);

    logJson('kali-mcp-assessment.summary', {
      mode: KALI_MODE,
      executionMode: kVeriData.executionMode,
      simulated: kVeriData.simulated,
      pinnedTools: kaliToolsRes.tools.map((t) => t.name),
      staticArgvSamples: {
        recon: reconArgvSpec.argv,
        configAudit: configArgvSpec.argv,
        verifyReproducer: verifyArgvSpec.argv,
        sbomCveCheck: sbomArgvSpec.argv,
      },
      profileAIsolationFlags: profileACheck.securityFlags,
      failClosedChecks: {
        liveContainerWithoutRuntime: liveFailClosedCode,
        imdsSsrfBlocked: rejectedImdsCode,
        cliFlagInjectionBlocked: rejectedFlagInjCode,
        selfCertificationSodBlocked: 'E_SOD_SELF_CERTIFICATION',
      },
      verifiedEvidence: {
        evidenceId: kVeriData.evidence.evidence_id,
        status: kVeriData.evidence.status,
        pinnedScriptSha256: kVeriData.evidence.reproducer_artifact.script_sha256,
        custodyValid: verifyChainOfCustody(kVeriData.custody.chain).valid,
        guardianAuditEvents: kaliAuditCheck.total_events,
        guardianAuditMerkleRoot: kaliAuditCheck.merkle_root,
      },
    });

    // -------------------------------------------------------------------------
    // STEP 10: PatchCat Orchestrator & Unified Evidence Ledger (ZenPR Bundle)
    // -------------------------------------------------------------------------
    printHeader(
      '10/10',
      'PatchCat Orchestrator (`@script-kitty/patchcat-orchestrator`) + Evidence Ledger (`@script-kitty/evidence`) — Signed ZenPR Advisory Bundle'
    );

    const orchestrator = new PatchCatOrchestrator({
      repoRoot: REPO_ROOT,
      fixturesDir: path.join(REPO_ROOT, 'fixtures', 'payments-lab'),
      dbPath: ':memory:',
    });
    const evidenceLedger = new EvidenceLedger({ dbPath: ':memory:' });

    try {
      const orchResult = await orchestrator.run({
        type: 'rollout',
        tenantId: 'payments-lab',
        actorPrincipalId: alphaPrincipal.principalId,
        fixtureId: 'payments-lab/unsafe-rollout',
        verifiedFixtureId: 'payments-lab/remediated',
        targetPath: 'fixtures/payments-lab/unsafe-rollout.json',
        sourceRef: 'rollout://payments-lab/demo-stage-10',
        commitSha,
        discoveringAgentId: 'agent-discovery-chainbreak',
        verifyingAgentId: 'agent-verifier-kali',
        authorizingAgentId: 'agent-authorizer-gate',
      });

      const zenPrBundle = ZenPrBundleSchema.parse(orchResult.zenPrBundle);
      assert.equal(zenPrBundle.schemaVersion, 'zenpr.advisory.v1');
      assert.equal(zenPrBundle.mode, 'LAB');
      assert.equal(zenPrBundle.productionTested, false);
      assert.equal(zenPrBundle.policyMutationAllowed, false);
      assert.equal(zenPrBundle.gateMutationAllowed, false);
      assert.equal(zenPrBundle.autoApplyAllowed, false);
      assert.equal(zenPrBundle.mergeAllowed, false);
      assert.equal(zenPrBundle.deployAllowed, false);
      assert.equal(zenPrBundle.requiresHumanApproval, true);
      assert.equal(zenPrBundle.beforeAfterProof.forbiddenPathDeltaSummary, '1 -> 0');
      assert.equal(zenPrBundle.beforeAfterProof.legitimateOperationsSummary, '3/3');
      assert.equal(zenPrBundle.factoryDelivery.eligible, true);
      assert.equal(zenPrBundle.factoryDelivery.mergeAllowed, false);
      assert.equal(zenPrBundle.factoryDelivery.deployAllowed, false);
      assert.equal(zenPrBundle.triPartySod.allDistinct, true);

      // Seal ChainBreak & Contract evidence into the tenant-isolated EvidenceLedger
      const cbEvidenceId = `ev-demo-cb-${orchResult.analysisId}`;
      evidenceLedger.recordChainBreakEvidence(
        'payments-lab',
        {
          evidenceId: cbEvidenceId,
          analysisId: orchResult.analysisId,
          kind: 'GRAPH_PATH',
          sourceRef: 'fixtures/payments-lab/unsafe-rollout.json#path-1',
          contentSha256: computeCanonicalDigest(zenPrBundle.beforeAfterProof),
          producer: '@script-kitty/chainbreak:analyzer-v0',
          verified: true,
          createdAt: zenPrBundle.createdAt,
          commitSha,
        },
        { payload: zenPrBundle.beforeAfterProof }
      );

      evidenceLedger.recordContractEvidence('payments-lab', evidence, {
        analysisId: orchResult.analysisId,
        verifyChainHash: true,
        linkedChainBreakEvidenceIds: [cbEvidenceId],
        relationType: 'REPRODUCES_PATH',
      });

      const merkleBundle = evidenceLedger.buildAnalysisMerkleBundle(
        'payments-lab',
        orchResult.analysisId,
        { generatedAt: zenPrBundle.createdAt }
      );
      const merkleBundleCheck = verifyAnalysisMerkleBundle(merkleBundle, {
        requireVerifiedProof: true,
        verifyChainHash: true,
      });
      assert.equal(merkleBundleCheck.valid, true);
      assert.equal(merkleBundle.leafCount, 2);
      assert.equal(merkleBundle.crossLinks.length, 1);

      const firstEntry = merkleBundle.entries[0];
      const inclusionValid = verifyMerkleProof(
        firstEntry.leafHash,
        firstEntry.proof,
        merkleBundle.merkleRoot
      );
      assert.equal(inclusionValid, true);

      // Verify fail-closed governance & evidence guards
      let policyMutationCode = '';
      try {
        assertNoPolicyOrGateMutation({ mergeAllowed: true });
      } catch (err) {
        assert.ok(err instanceof PatchCatGovernanceError);
        policyMutationCode = err.code;
      }
      assert.equal(policyMutationCode, 'E_POLICY_MUTATION_FORBIDDEN');

      let sodViolationCode = '';
      try {
        assertTriPartySod('agent-a', 'agent-a', 'agent-c');
      } catch (err) {
        assert.ok(err instanceof PatchCatGovernanceError);
        sodViolationCode = err.code;
      }
      assert.equal(sodViolationCode, 'E_SOD_VIOLATION');

      let aiProseCode = '';
      try {
        evidenceLedger.recordEvidence('payments-lab', 'Unverified LLM prose alone');
      } catch (err) {
        assert.ok(err instanceof UnverifiedAiProseError);
        aiProseCode = err.code;
      }
      assert.equal(aiProseCode, 'UNVERIFIED_AI_PROSE_REJECTED');

      let crossTenantEvidenceCode = '';
      try {
        evidenceLedger.getReceipt('tenant-beta', cbEvidenceId);
      } catch (err) {
        assert.ok(err instanceof EvidenceTenantIsolationError);
        crossTenantEvidenceCode = err.code;
      }
      assert.equal(crossTenantEvidenceCode, 'TENANT_ISOLATION_VIOLATION');

      logJson('zenpr-advisory-and-evidence-ledger', {
        zenPrBundle: {
          bundleId: zenPrBundle.bundleId,
          schemaVersion: zenPrBundle.schemaVersion,
          status: zenPrBundle.status,
          forbiddenPathDeltaSummary: zenPrBundle.beforeAfterProof.forbiddenPathDeltaSummary,
          legitimateOperationsSummary: zenPrBundle.beforeAfterProof.legitimateOperationsSummary,
          merkleRoot: zenPrBundle.merkleRoot,
          bundleDigestSha256: zenPrBundle.bundleDigestSha256,
          policyMutationAllowed: zenPrBundle.policyMutationAllowed,
          gateMutationAllowed: zenPrBundle.gateMutationAllowed,
          autoApplyAllowed: zenPrBundle.autoApplyAllowed,
          mergeAllowed: zenPrBundle.mergeAllowed,
          deployAllowed: zenPrBundle.deployAllowed,
          requiresHumanApproval: zenPrBundle.requiresHumanApproval,
        },
        evidenceLedgerBundle: {
          bundleId: merkleBundle.bundleId,
          schemaVersion: merkleBundle.schemaVersion,
          leafCount: merkleBundle.leafCount,
          crossLinksCount: merkleBundle.crossLinks.length,
          merkleRoot: merkleBundle.merkleRoot,
          bundleSha256: merkleBundle.bundleSha256,
          verified: merkleBundleCheck.valid,
          inclusionProofValid: inclusionValid,
          firstLeafEvidenceId: firstEntry.evidenceId,
          inclusionProofSteps: firstEntry.proof.length,
        },
        failClosedChecks: {
          policyMutationBlocked: policyMutationCode,
          sodViolationBlocked: sodViolationCode,
          unverifiedAiProseBlocked: aiProseCode,
          crossTenantEvidenceBlocked: crossTenantEvidenceCode,
        },
      });
    } finally {
      evidenceLedger.close();
      orchestrator.close();
    }

    console.log('\n' + '='.repeat(84));
    console.log(' DEMO RESULT: ALL 10 STAGES PASSED CLEANLY IN ISOLATED LAB MODE (EXIT CODE 0)');
    console.log(' NOTE: mergeAllowed=false | deployAllowed=false | productionTested=false');
    console.log('='.repeat(84));
  } finally {
    await alphaClient?.close();
    await betaClient?.close();
    await mcpServer?.close();
    runtime.close();
  }
}

runDemo().catch((err) => {
  console.error('\nDEMO FAILED:', err);
  process.exit(1);
});
