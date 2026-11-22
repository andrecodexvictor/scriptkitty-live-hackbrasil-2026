/**
 * @file packages/verification-suite/tests/tier3-adapters.test.mts
 * @description Tier 3 Synthetic Test Suite: Interface compliance, mock execution,
 * output contract mapping, and error isolation for all 4 security engines:
 * Mantis, Codex Security, Cloudflare Security Center, and Quality Engine.
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
  validateFinding,
  validateEvidence,
  validatePatch,
  computeFindingFingerprint,
} from '../../contracts/dist/index.js';

// Adapters
import {
  type ISecurityEngineAdapter,
  type ScanTarget,
  type ScanOptions,
  MantisAdapter,
  CodexSecurityAdapter,
  CloudflareSecurityCenterAdapter,
  QualityEngineAdapter,
} from '../../adapters/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');

function loadJson(relPath: string) {
  const full = path.join(FIXTURES_DIR, relPath);
  return JSON.parse(fs.readFileSync(full, 'utf8'));
}

describe('Tier 3: Security Engine Adapters Interface Compliance & Mock Execution', () => {
  const mantisMock = loadJson('engine-mocks/mantis-response.json');
  const codexMock = loadJson('engine-mocks/codex-response.json');
  const cloudflareMock = loadJson('engine-mocks/cloudflare-response.json');
  const qualityEngineMock = loadJson('engine-mocks/quality-engine-response.json');

  describe('3.1 Google Mantis Adapter (Discovery, Reproduction, Patch Recheck)', () => {
    const adapter: ISecurityEngineAdapter = new MantisAdapter();

    it('complies with ISecurityEngineAdapter interface contract', async () => {
      assert.equal(adapter.engine_name, 'mantis');
      assert.ok(adapter.supported_target_types.includes('SOURCE_CODE'));
      assert.ok(typeof adapter.scan === 'function');
      assert.ok(typeof adapter.reproduce === 'function');
      assert.ok(typeof adapter.recheck === 'function');

      const initialized = await adapter.initialize?.();
      assert.equal(initialized, true);
    });

    it('maps Mantis raw findings into canonical SecurityFinding contracts', async () => {
      const scanTarget: ScanTarget = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'github.com/org/scriptkitty-target',
        commit_hash: mantisMock.scan_summary.commit_hash,
        metadata: {
          raw_findings: mantisMock.raw_findings,
          directory_summaries: [{ path: 'src/api', component: 'api', summary: 'API endpoints', entry_points: ['/api/v1/users'], external_sinks: ['db.raw'] }],
        },
      };

      const scanResult = await adapter.scan(scanTarget);
      assert.equal(scanResult.status, 'success');
      assert.equal(scanResult.findings.length, 1);

      const finding = scanResult.findings[0];
      const validation = validateFinding(finding);
      assert.equal(validation.success, true);
      assert.equal(finding.source_engine, 'mantis');
      assert.equal(finding.cwe_id, 'CWE-89');
      assert.equal(finding.severity, 'CRITICAL');
      assert.equal(finding.location.file_path, 'src/api/users.ts');
      assert.equal(finding.location.start_line, 42);
      assert.match(finding.fingerprint, /^[a-f0-9]{64}$/);
    });

    it('executes sandboxed crash reproducer and produces canonical Evidence', async () => {
      // First get finding from scan
      const scanTarget: ScanTarget = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'github.com/org/scriptkitty-target',
        commit_hash: mantisMock.scan_summary.commit_hash,
        metadata: { raw_findings: mantisMock.raw_findings },
      };
      const scanResult = await adapter.scan(scanTarget);
      const finding = scanResult.findings[0];

      // Execute reproduction
      const reproResult = await adapter.reproduce(finding, {
        sandbox_runtime: 'docker_isolated',
        network_isolated: true,
        verifier_agent_id: 'agent-mantis-verifier-02',
        custom_config: {
          mock_exit_code: mantisMock.reproduction_proof.exit_code,
          mock_stdout: mantisMock.reproduction_proof.stdout,
          mock_stderr: mantisMock.reproduction_proof.stderr,
        },
      });

      assert.equal(reproResult.status, 'success');
      assert.equal(reproResult.reproduction_verified, true);
      assert.ok(reproResult.evidence);

      const evidenceValidation = validateEvidence(reproResult.evidence);
      assert.equal(evidenceValidation.success, true);
      assert.equal(reproResult.evidence.status, 'VERIFIED_TRUE_POSITIVE');
      assert.equal(reproResult.evidence.reproducer_artifact?.exit_code, 1);
      assert.equal(reproResult.evidence.sandbox_environment.network_isolated, true);
    });

    it('executes patch recheck loop: passes clean on successful fix, detects regressions', async () => {
      const validPatchRaw = loadJson('valid-patch.json');
      const patch: PatchProposal = validatePatch(validPatchRaw).data!;

      // Case 1: Clean fix (reproducer passed, regression suite passed)
      const cleanRecheck = await adapter.recheck(patch, {
        verifier_agent_id: 'agent-mantis-verifier-02',
        custom_config: { reproducer_still_fails: false, regression_detected: false },
      });

      assert.equal(cleanRecheck.status, 'success');
      assert.equal(cleanRecheck.recheck_status, 'passed_clean');
      assert.equal(cleanRecheck.tests_passed, true);
      assert.equal(cleanRecheck.reproducer_passed, true);
      assert.ok(cleanRecheck.evidence);

      // Case 2: Regression detected
      const regressionRecheck = await adapter.recheck(patch, {
        verifier_agent_id: 'agent-mantis-verifier-02',
        custom_config: { reproducer_still_fails: false, regression_detected: true },
      });

      assert.equal(regressionRecheck.status, 'success');
      assert.equal(regressionRecheck.recheck_status, 'regression_detected');
      assert.equal(regressionRecheck.tests_passed, false);
    });

    it('isolates execution errors without throwing unhandled exceptions', async () => {
      const throwingTarget: ScanTarget = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'github.com/org/scriptkitty-target',
        get metadata(): any {
          throw new Error('Mantis engine process terminated with exit code 2: Out of Memory');
        },
      };

      const errorResult = await adapter.scan(throwingTarget);
      assert.equal(errorResult.status, 'error');
      assert.ok(errorResult.errors && errorResult.errors.length > 0);
      assert.ok(errorResult.errors[0].includes('Out of Memory'));
    });
  });

  describe('3.2 OpenAI Codex Security Adapter (SARIF 2.1.0, Threat Modeling, Cost Ceiling)', () => {
    const adapter: ISecurityEngineAdapter = new CodexSecurityAdapter();

    it('complies with ISecurityEngineAdapter interface contract', async () => {
      assert.equal(adapter.engine_name, 'codex_security');
      assert.ok(adapter.supported_target_types.includes('SOURCE_CODE'));
      assert.ok(adapter.supported_target_types.includes('MCP_TOOL'));

      const initialized = await adapter.initialize?.();
      assert.equal(initialized, true);
    });

    it('parses SARIF 2.1.0 log and maps reachable attack paths into SecurityFinding contracts', async () => {
      const scanTarget: ScanTarget = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'github.com/org/scriptkitty-target',
        commit_hash: 'b2c3d4e5f678901234567890123456789012345a',
        metadata: {
          sarif: codexMock,
          entry_points: ['src/api/users.ts'],
        },
      };

      const scanResult = await adapter.scan(scanTarget);
      assert.equal(scanResult.status, 'success');
      assert.equal(scanResult.findings.length, 1);

      const finding = scanResult.findings[0];
      const validation = validateFinding(finding);
      assert.equal(validation.success, true);
      assert.equal(finding.source_engine, 'codex_security');
      assert.equal(finding.cwe_id, 'CWE-89');
      assert.equal(finding.severity, 'HIGH');
      assert.equal(finding.location.file_path, 'src/api/users.ts');
      assert.equal(finding.location.start_line, 42);
      assert.equal(finding.raw_metadata?.sarif_rule_id, 'CODEX-SEC-089');
      assert.ok(finding.raw_metadata?.attack_path);
    });

    it('enforces strict max_cost_usd spending ceiling and halts gracefully', async () => {
      const scanTarget: ScanTarget = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'github.com/org/scriptkitty-target',
        metadata: { sarif: codexMock },
      };

      // Set spending ceiling lower than item cost ($0.042)
      const options: ScanOptions = { max_cost_usd: 0.01 };
      const scanResult = await adapter.scan(scanTarget, options);

      assert.equal(scanResult.status, 'partial');
      assert.equal(scanResult.is_partial, true);
      assert.ok(scanResult.warnings?.some((w) => w.includes('Spending ceiling reached')));
    });

    it('evaluates secondary opinion reachability review and produces Evidence', async () => {
      const scanTarget: ScanTarget = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'github.com/org/scriptkitty-target',
        metadata: { sarif: codexMock },
      };
      const scanResult = await adapter.scan(scanTarget);
      const finding = scanResult.findings[0];

      const reproResult = await adapter.reproduce(finding, {
        verifier_agent_id: 'agent-codex-validator-03',
        custom_config: { reachability_opinion: 'REACHABLE', consensus_agreement: true },
      });

      assert.equal(reproResult.status, 'success');
      assert.equal(reproResult.reproduction_verified, true);
      assert.ok(reproResult.evidence);
      assert.equal(reproResult.evidence.verification_type, 'DUAL_OPINION_CONSENSUS');
      assert.equal(reproResult.evidence.status, 'VERIFIED_TRUE_POSITIVE');
    });
  });

  describe('3.3 Cloudflare Security Center Adapter (ASM, API Shield, Logpush)', () => {
    const adapter: ISecurityEngineAdapter = new CloudflareSecurityCenterAdapter();

    it('complies with ISecurityEngineAdapter interface contract', async () => {
      assert.equal(adapter.engine_name, 'cloudflare_security_center');
      assert.ok(adapter.supported_target_types.includes('CLOUD_RESOURCE'));
      assert.ok(adapter.supported_target_types.includes('API_ENDPOINT'));

      const initialized = await adapter.initialize?.();
      assert.equal(initialized, true);
    });

    it('maps Attack Surface Management insights (dangling DNS, deprecated TLS) to SecurityFinding', async () => {
      const scanTarget: ScanTarget = {
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'example.com',
        metadata: {
          account_id: cloudflareMock.account_id,
          zone_id: cloudflareMock.zone_id,
          insights: cloudflareMock.insights,
        },
      };

      const scanResult = await adapter.scan(scanTarget);
      assert.equal(scanResult.status, 'success');
      assert.equal(scanResult.findings.length, 2);

      // Verify Dangling DNS finding
      const dnsFinding = scanResult.findings.find((f) => f.cwe_id === 'CWE-284');
      assert.ok(dnsFinding);
      assert.equal(dnsFinding.severity, 'HIGH');
      assert.equal(dnsFinding.source_engine, 'cloudflare_security_center');
      assert.equal(validateFinding(dnsFinding).success, true);

      // Verify Deprecated TLS finding
      const tlsFinding = scanResult.findings.find((f) => f.cwe_id === 'CWE-326');
      assert.ok(tlsFinding);
      assert.equal(tlsFinding.severity, 'MEDIUM');
      assert.equal(validateFinding(tlsFinding).success, true);
    });

    it('maps Logpush edge event telemetry into canonical Evidence', async () => {
      const scanTarget: ScanTarget = {
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'example.com',
        metadata: { insights: cloudflareMock.insights },
      };
      const scanResult = await adapter.scan(scanTarget);
      const dnsFinding = scanResult.findings[0];

      const reproResult = await adapter.reproduce(dnsFinding, {
        verifier_agent_id: 'agent-cloudflare-telemetry-04',
        custom_config: { logpush_event: cloudflareMock.edge_events[0] },
      });

      assert.equal(reproResult.status, 'success');
      assert.ok(reproResult.evidence);
      assert.equal(reproResult.evidence.verification_type, 'EDGE_TELEMETRY');
      assert.equal(reproResult.evidence.status, 'VERIFIED_TRUE_POSITIVE');
      assert.ok(reproResult.evidence.reproduction_proof?.payload.includes(cloudflareMock.edge_events[0].RayID));
    });

    it('handles authentication failures gracefully with error isolation', async () => {
      const scanTarget: ScanTarget = {
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'example.com',
        metadata: {
          simulate_auth_failure: true,
          auth_token: 'invalid_revoked_token',
        },
      };

      const scanResult = await adapter.scan(scanTarget);
      assert.equal(scanResult.status, 'error');
      assert.ok(scanResult.errors && scanResult.errors.length > 0);
      assert.ok(scanResult.errors[0].includes('403 Forbidden'));
    });
  });

  describe('3.4 Quality Engine Adapter (Deterministic Boundaries & Quad-State)', () => {
    const adapter = new QualityEngineAdapter();

    it('complies with ISecurityEngineAdapter interface contract', async () => {
      assert.equal(adapter.engine_name, 'quality_engine');
      assert.ok(adapter.supported_target_types.includes('SOURCE_CODE'));
      assert.ok(adapter.supported_target_types.includes('CONFIGURATION'));

      const initialized = await adapter.initialize?.();
      assert.equal(initialized, true);
    });

    it('evaluates clean scan with unexpired exceptions to PASS state', () => {
      const validFinding = validateFinding(loadJson('valid-finding.json')).data!;

      const policy = {
        version: 1,
        exceptions: [
          {
            ruleId: 'CWE-89',
            fingerprint: validFinding.fingerprint,
            reason: 'Production hotfix applied and regression tested',
            expires: '2030-12-31',
          },
        ],
      };

      const evalResult = adapter.evaluateQuadState({
        policy,
        findings: [validFinding],
        todayUtc: '2026-11-06',
        totalFiles: 10,
        totalBytes: 5000,
      });

      assert.equal(evalResult.state, 'pass');
      assert.equal(evalResult.suppressedFindings.length, 1);
      assert.equal(evalResult.blockingFindings.length, 0);
    });

    it('evaluates active unsuppressed critical finding to FINDING state', () => {
      const validFinding = validateFinding(loadJson('valid-finding.json')).data!;

      const policy = {
        version: 1,
        exceptions: [], // No exceptions
      };

      const evalResult = adapter.evaluateQuadState({
        policy,
        findings: [validFinding],
        todayUtc: '2026-11-06',
      });

      assert.equal(evalResult.state, 'finding');
      assert.equal(evalResult.blockingFindings.length, 1);
      assert.equal(evalResult.blockingFindings[0], validFinding.finding_id);
    });

    it('evaluates policy parsing error or invalid version to ERROR state', () => {
      const invalidPolicy = {
        version: 2, // Unsupported version
      };

      const evalResult = adapter.evaluateQuadState({
        policy: invalidPolicy,
        findings: [],
      });

      assert.equal(evalResult.state, 'error');
      assert.ok(evalResult.errors.some((e) => e.includes('expected supported version 1')));
    });

    it('evaluates out-of-scope targets to NOT_APPLICABLE state', () => {
      const evalResult = adapter.evaluateQuadState({
        policy: { version: 1 },
        findings: [],
        targetScopeApplicable: false,
      });

      assert.equal(evalResult.state, 'not_applicable');
    });
  });
});
