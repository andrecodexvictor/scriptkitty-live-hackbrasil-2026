/**
 * @file packages/remediation-engine/tests/sandbox.test.mts
 * @description Offline local sandbox isolation test suite:
 * 1. Environment variables isolation & proxy stripping
 * 2. Exit code propagation
 * 3. Timeout handling & process termination
 * 4. Genuine Evidence contract generation adhering to EvidenceSchema
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  OfflineLocalSandbox,
  type SecurityFinding,
  EvidenceSchema,
  VerificationStatus,
} from '../dist/index.js';

describe('Offline Local Sandbox Isolation Test Suite', () => {
  const sandbox = new OfflineLocalSandbox(5000);

  const sampleFinding: SecurityFinding = {
    finding_id: 'SK-FIND-TEST-SANDBOX-001',
    source_engine: 'builtin',
    title: 'SQL Injection in Query Parser',
    description: 'User input concatenates directly into raw SQL query',
    cwe_id: 'CWE-89',
    owasp_category: 'A03:2021-Injection',
    severity: 'CRITICAL',
    confidence: 'CERTAIN',
    target_type: 'SOURCE_CODE',
    target: 'src/routes/search.ts',
    location: {
      file_path: 'src/routes/search.ts',
      start_line: 10,
      end_line: 15,
    },
    fingerprint: 'a'.repeat(64),
    commit_hash: 'b'.repeat(40),
    discovered_at: '2026-11-06T12:00:00.000Z',
    agent_context: {
      discovering_agent_id: 'agent-scanner-mantis',
    },
    raw_metadata: {},
  };

  it('1. Environment variable isolation: strips external proxy and enforces offline loopback flags', async () => {
    // In node -e, inspect process.env
    const inspectScript = `
      const env = process.env;
      const report = {
        hasHttpProxy: 'HTTP_PROXY' in env || 'http_proxy' in env,
        hasHttpsProxy: 'HTTPS_PROXY' in env || 'https_proxy' in env,
        hasAllProxy: 'ALL_PROXY' in env || 'all_proxy' in env,
        noProxy: env.NO_PROXY || env.no_proxy || '',
        isOffline: env.SCRIPTKITTY_OFFLINE === '1',
        customVar: env.MY_CUSTOM_TEST_TOKEN || ''
      };
      console.log(JSON.stringify(report));
    `;

    const result = await sandbox.execute({
      command: 'node',
      args: ['-e', inspectScript],
      env: {
        HTTP_PROXY: 'http://malicious-external-proxy.com:8080',
        HTTPS_PROXY: 'https://malicious-external-proxy.com:8443',
        MY_CUSTOM_TEST_TOKEN: 'token-secret-12345',
      },
      isolated_network: true,
    });

    assert.equal(result.exit_code, 0);
    const report = JSON.parse(result.stdout.trim());
    assert.equal(report.hasHttpProxy, false, 'HTTP_PROXY must be stripped');
    assert.equal(report.hasHttpsProxy, false, 'HTTPS_PROXY must be stripped');
    assert.equal(report.hasAllProxy, false, 'ALL_PROXY must be stripped');
    assert.equal(report.isOffline, true, 'SCRIPTKITTY_OFFLINE must be set');
    assert.equal(report.customVar, 'token-secret-12345', 'Caller custom env vars must be preserved');
  });

  it('2. Exit code propagation: propagates 0, 1, and arbitrary non-zero exit codes accurately', async () => {
    // Test Exit 0
    const res0 = await sandbox.execute({
      command: 'node',
      args: ['-e', 'console.log("SUCCESS"); process.exit(0);'],
    });
    assert.equal(res0.exit_code, 0);
    assert.ok(res0.stdout.includes('SUCCESS'));
    assert.equal(res0.timed_out, false);

    // Test Exit 1 (Exploit Confirmed)
    const res1 = await sandbox.execute({
      command: 'node',
      args: ['-e', 'console.error("VULN_TRIGGERED"); process.exit(1);'],
    });
    assert.equal(res1.exit_code, 1);
    assert.ok(res1.stderr.includes('VULN_TRIGGERED'));
    assert.equal(res1.timed_out, false);

    // Test Exit 42 (Arbitrary Non-Zero)
    const res42 = await sandbox.execute({
      command: 'node',
      args: ['-e', 'process.exit(42);'],
    });
    assert.equal(res42.exit_code, 42);
    assert.equal(res42.timed_out, false);
  });

  it('3. Timeout handling: halts hanging process promptly and marks timed_out = true', async () => {
    const hangingScript = `
      // Infinite busy loop or sleep
      setInterval(() => {}, 1000);
    `;

    const startTime = Date.now();
    const result = await sandbox.execute({
      command: 'node',
      args: ['-e', hangingScript],
      timeout_ms: 600, // Short timeout
    });
    const elapsed = Date.now() - startTime;

    assert.equal(result.timed_out, true, 'Process must be marked timed_out');
    assert.ok(result.exit_code === 124 || result.exit_code === -1, 'Timed out process must exit with 124 or -1');
    assert.ok(elapsed >= 500, 'Must have waited at least timeout duration');
    assert.ok(elapsed < 4000, 'Must not hang indefinitely');
  });

  it('4. Evidence synthesis: generates genuine Evidence contract for confirmed vulnerability', () => {
    const mockResult = {
      exit_code: 1,
      stdout: 'VULNERABILITY_CONFIRMED: SQL Injection leaked admin token',
      stderr: '',
      duration_ms: 125,
      timed_out: false,
      command_executed: 'node repro-sqli.mts',
    };

    const evidence = sandbox.generateEvidence({
      finding: sampleFinding,
      result: mockResult,
      script_path: 'apps/lab-app/repro/repro-sqli.mts',
      verifier_agent_id: 'agent-sandbox-verifier-01',
      is_post_patch: false,
    });

    assert.equal(evidence.finding_id, sampleFinding.finding_id);
    assert.equal(evidence.status, VerificationStatus.VERIFIED_TRUE_POSITIVE);
    assert.equal(evidence.verifier_agent_id, 'agent-sandbox-verifier-01');
    assert.equal(evidence.reproducer_artifact?.exit_code, 1);
    assert.ok(evidence.reproducer_artifact?.stdout.includes('VULNERABILITY_CONFIRMED'));
    assert.match(evidence.chain_hash, /^[a-f0-9]{64}$/i);

    // Validate against EvidenceSchema
    const validated = EvidenceSchema.parse(evidence);
    assert.equal(validated.evidence_id, evidence.evidence_id);
  });

  it('5. Evidence synthesis: generates genuine Evidence contract for post-patch neutralization', () => {
    const mockResultClean = {
      exit_code: 0,
      stdout: 'EXPLOIT_NEUTRALIZED: Query safely parameterized',
      stderr: '',
      duration_ms: 95,
      timed_out: false,
      command_executed: 'node repro-sqli.mts',
    };

    const evidence = sandbox.generateEvidence({
      finding: sampleFinding,
      result: mockResultClean,
      script_path: 'apps/lab-app/repro/repro-sqli.mts',
      verifier_agent_id: 'agent-sandbox-verifier-01',
      is_post_patch: true,
    });

    assert.equal(evidence.finding_id, sampleFinding.finding_id);
    assert.equal(evidence.status, VerificationStatus.REFUTED_FALSE_POSITIVE);
    assert.equal(evidence.reproducer_artifact?.exit_code, 0);
    assert.match(evidence.chain_hash, /^[a-f0-9]{64}$/i);

    const validated = EvidenceSchema.parse(evidence);
    assert.equal(validated.evidence_id, evidence.evidence_id);
  });

  it('6. Evidence synthesis: generates EXECUTION_ERROR evidence upon sandbox timeout', () => {
    const mockResultTimedOut = {
      exit_code: -1,
      stdout: '',
      stderr: 'Process execution deadline exceeded (30000 ms)',
      duration_ms: 30005,
      timed_out: true,
      command_executed: 'node repro-hang.mts',
    };

    const evidence = sandbox.generateEvidence({
      finding: sampleFinding,
      result: mockResultTimedOut,
      script_path: 'apps/lab-app/repro/repro-hang.mts',
      verifier_agent_id: 'agent-sandbox-verifier-01',
      is_post_patch: false,
    });

    assert.equal(evidence.status, VerificationStatus.EXECUTION_ERROR);
    assert.equal(evidence.reproducer_artifact?.exit_code, -1);
    const validated = EvidenceSchema.parse(evidence);
    assert.equal(validated.evidence_id, evidence.evidence_id);
  });
});
