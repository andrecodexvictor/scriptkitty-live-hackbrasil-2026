/**
 * @file packages/verification-suite/tests/tier2-boundaries.test.mts
 * @description Tier 2 Synthetic Test Suite: Execution boundary rejection, wall-clock timeout
 * enforcement, sensitive secret redaction, size budget enforcement, and deterministic gate
 * rejection of unverified or inconclusive evidence.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// Contracts
import {
  parseFinding,
  parseEvidence,
  parsePatch,
  parseGateDecision,
  GateVerdict,
  VerificationStatus,
  buildCustodyChain,
} from '../../contracts/dist/index.js';

// Adapters Execution Boundary
import {
  withTimeout,
  TimeoutError,
  SizeBudgetExceededError,
  sanitizeOutput,
  sanitizeObject,
  checkSizeBudget,
  assertWithinBudget,
  truncateToBudget,
  safeExecute,
  executeInBoundary,
} from '../../adapters/dist/index.js';

// Quality Gate Engine & Policy
import {
  DeterministicQualityGate,
  type Policy,
  parsePolicy,
  validatePolicy,
  isExceptionExpired,
  evaluateExceptionsValidity,
  insideScope,
  isTargetInScope,
  evaluateSeparationOfDuties,
  validateSeparationOfDuties,
} from '../../quality-gate/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../fixtures');

function loadJson(relPath: string) {
  const full = path.join(FIXTURES_DIR, relPath);
  return JSON.parse(fs.readFileSync(full, 'utf8'));
}

describe('Tier 2: Execution Boundaries, Secret Redaction & Deterministic Gate Rejection', () => {
  const validFindingRaw = loadJson('valid-finding.json');
  const validEvidenceRaw = loadJson('valid-evidence.json');
  const validPatchRaw = loadJson('valid-patch.json');
  const unverifiedFindingFixture = loadJson('unverified-finding.json');
  const selfCertifiedFixture = loadJson('self-certified-finding.json');
  const expiredPolicyFixture = loadJson('expired-policy.json');

  describe('2.1 Wall-Clock Timeout Enforcement', () => {
    it('resolves promptly when operation finishes before timeout deadline', async () => {
      const fastPromise = new Promise<string>((resolve) => setTimeout(() => resolve('fast_ok'), 20));
      const result = await withTimeout(fastPromise, 200, 'FastOperation');
      assert.equal(result, 'fast_ok');
    });

    it('rejects with TimeoutError when operation exceeds timeout deadline', async () => {
      const slowPromise = new Promise<string>((resolve) => setTimeout(() => resolve('slow_done'), 300));
      await assert.rejects(
        async () => {
          await withTimeout(slowPromise, 50, 'SlowOperation');
        },
        (err: unknown) => {
          assert.ok(err instanceof TimeoutError);
          assert.equal(err.name, 'TimeoutError');
          assert.equal(err.timeoutMs, 50);
          assert.ok(err.message.includes('timed out after 50ms'));
          return true;
        }
      );
    });

    it('executeInBoundary catches timeouts cleanly without unhandled rejections', async () => {
      const outcome = await executeInBoundary(
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 200));
          return 'should_not_reach';
        },
        { timeoutMs: 30, operationName: 'BoundaryTimeoutTest' }
      );

      assert.equal(outcome.success, false);
      assert.equal(outcome.timedOut, true);
      assert.ok(outcome.error?.includes('timed out after 30ms'));
      assert.ok(outcome.durationMs >= 25);
    });

    it('safeExecute catches exceptions and returns fallback safely', async () => {
      const safeResult = await safeExecute(
        () => {
          throw new Error('Simulated sandbox crash: SIGSEGV');
        },
        (err) => ({ status: 'error', reason: err.message })
      );

      assert.equal(safeResult.status, 'error');
      assert.equal(safeResult.reason, 'Simulated sandbox crash: SIGSEGV');
    });
  });

  describe('2.2 Sensitive Secret Redaction & Sanitization', () => {
    it('redacts Bearer tokens from trace logs', () => {
      const raw = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secretKey1234567890';
      const sanitized = sanitizeOutput(raw);
      assert.equal(sanitized, 'Authorization: Bearer [REDACTED]');
      assert.equal(sanitized.includes('secretKey'), false);
    });

    it('redacts API key and secret assignments', () => {
      const raw = 'Config: api_key="sk-live-9928172635443210" client_secret: "prod-secret-99887766"';
      const sanitized = sanitizeOutput(raw);
      assert.ok(sanitized.includes('api_key="[REDACTED]"'));
      assert.ok(sanitized.includes('client_secret: "[REDACTED]"'));
      assert.equal(sanitized.includes('sk-live'), false);
    });

    it('redacts AWS Access Key IDs', () => {
      const raw = 'AWS credentials detected: AKIAIOSFODNN7EXAMPLE in config';
      const sanitized = sanitizeOutput(raw);
      assert.equal(sanitized, 'AWS credentials detected: AKIA[REDACTED] in config');
    });

    it('redacts GitHub Personal Access Tokens', () => {
      const raw = 'git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/repo';
      const sanitized = sanitizeOutput(raw);
      assert.ok(sanitized.includes('ghp_[REDACTED]'));
      assert.equal(sanitized.includes('ghp_abcdef'), false);
    });

    it('redacts passwords in database connection URIs', () => {
      const raw = 'DATABASE_URL=postgres://dbuser:superSecretPassword123@prod-db.internal:5432/main';
      const sanitized = sanitizeOutput(raw);
      assert.equal(sanitized, 'DATABASE_URL=postgres://dbuser:[REDACTED]@prod-db.internal:5432/main');
      assert.equal(sanitized.includes('superSecretPassword123'), false);
    });

    it('redacts multi-line private key blocks', () => {
      const raw = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3yD7...sample...key...content...
-----END RSA PRIVATE KEY-----`;
      const sanitized = sanitizeOutput(raw);
      assert.ok(sanitized.includes('[REDACTED PRIVATE KEY]'));
      assert.equal(sanitized.includes('sample...key'), false);
    });

    it('recursively sanitizes nested objects and secret keys', () => {
      const nested = {
        toolName: 'ast_grep',
        options: {
          apiKey: 'secret-val-999999',
          url: 'https://admin:pass123456@example.com',
        },
        items: [
          'Authorization: Bearer token-123456789012345',
          { token: 'secret-token-nested' },
        ],
      };

      const sanitized = sanitizeObject(nested);
      assert.equal(sanitized.options.apiKey, '[REDACTED]');
      assert.equal(sanitized.options.url, 'https://admin:[REDACTED]@example.com');
      assert.equal(sanitized.items[0], 'Authorization: Bearer [REDACTED]');
      assert.equal((sanitized.items[1] as any).token, '[REDACTED]');
    });
  });

  describe('2.3 Size Budget Enforcement & Payload Truncation', () => {
    it('validates payloads within size budget', () => {
      const payload = 'Normal output within 200 bytes budget';
      const res = checkSizeBudget(payload, 200, 'TestOutput');
      assert.equal(res.ok, true);
      assert.equal(res.limit, 200);
      assert.doesNotThrow(() => assertWithinBudget(payload, 200, 'TestOutput'));
    });

    it('assertWithinBudget throws SizeBudgetExceededError when limit exceeded', () => {
      const largePayload = 'X'.repeat(500);
      assert.throws(
        () => assertWithinBudget(largePayload, 100, 'OversizedOutput'),
        (err: unknown) => {
          assert.ok(err instanceof SizeBudgetExceededError);
          assert.equal(err.name, 'SizeBudgetExceededError');
          assert.equal(err.currentBytes, 500);
          assert.equal(err.maxBytes, 100);
          return true;
        }
      );
    });

    it('safely truncates oversized payloads with suffix preservation', () => {
      const longString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.repeat(10); // 360 bytes
      const truncated = truncateToBudget(longString, 50, '...[TRUNCATED]');

      assert.equal(truncated.truncated, true);
      assert.ok(Buffer.byteLength(truncated.content, 'utf8') <= 50);
      assert.ok(truncated.content.endsWith('...[TRUNCATED]'));
    });
  });

  describe('2.4 Deterministic Gate Rejection of Unverified Evidence', () => {
    const gate = new DeterministicQualityGate();

    it('strictly REJECTS evaluation when finding lacks empirical reproduction evidence', async () => {
      const finding = parseFinding(unverifiedFindingFixture.finding);

      // Gate evaluation request with finding but empty evidence
      const decision = await gate.evaluate({
        findings: [finding],
        evidence: [],
        discovering_agent_id: 'agent-scanner-regex-01',
        verifying_agent_id: 'agent-verifier-pytest-02',
        authorizing_agent_id: 'agent-auth-quality-gate-04',
      });

      assert.notEqual(decision.verdict, 'PASS', 'Zero-Trust invariant: Unverified finding can NEVER PASS');
      assert.equal(decision.verdict, 'REJECT');
      assert.ok(decision.unverified_findings.includes(finding.finding_id));
      assert.ok(decision.rules_evaluated.some((r) => r.rule_id === 'RULE_EMPIRICAL_REPRODUCTION' && r.status === 'FAIL'));
    });

    it('strictly BLOCKS evaluation when evidence reproducer status is INCONCLUSIVE', async () => {
      const finding = parseFinding(validFindingRaw);
      const evidence = parseEvidence({
        ...validEvidenceRaw,
        status: 'INCONCLUSIVE',
      });

      const decision = await gate.evaluate({
        findings: [finding],
        evidence: [evidence],
        discovering_agent_id: 'agent-scanner-mantis-01',
        verifying_agent_id: 'agent-verifier-pytest-02',
        authorizing_agent_id: 'agent-auth-quality-gate-04',
      });

      assert.notEqual(decision.verdict, 'PASS');
      assert.equal(decision.verdict, 'BLOCK');
      assert.ok(decision.blocking_findings.includes(finding.finding_id));
      assert.ok(decision.rules_evaluated.some((r) => r.rule_id === 'RULE_REPRODUCER_DECISIVENESS' && r.status === 'FAIL'));
    });

    it('strictly BLOCKS evaluation when evidence status is EXECUTION_ERROR', async () => {
      const finding = parseFinding(validFindingRaw);
      const evidence = parseEvidence({
        ...validEvidenceRaw,
        status: 'EXECUTION_ERROR',
      });

      const decision = await gate.evaluate({
        findings: [finding],
        evidence: [evidence],
        discovering_agent_id: 'agent-scanner-mantis-01',
        verifying_agent_id: 'agent-verifier-pytest-02',
        authorizing_agent_id: 'agent-auth-quality-gate-04',
      });

      assert.notEqual(decision.verdict, 'PASS');
      assert.equal(decision.verdict, 'BLOCK');
    });

    it('treats REFUTED_FALSE_POSITIVE as non-blocking for verified clean targets', async () => {
      const finding = parseFinding(validFindingRaw);
      const evidence = parseEvidence({
        ...validEvidenceRaw,
        status: 'REFUTED_FALSE_POSITIVE',
      });

      const decision = await gate.evaluate({
        findings: [finding],
        evidence: [evidence],
        discovering_agent_id: 'agent-scanner-mantis-01',
        verifying_agent_id: 'agent-verifier-pytest-02',
        authorizing_agent_id: 'agent-auth-quality-gate-04',
      });

      // When all findings are refuted false positives, there are no active blocking findings
      assert.equal(decision.blocking_findings.length, 0);
      assert.equal(decision.unverified_findings.length, 0);
    });
  });

  describe('2.5 Tri-Party Separation of Duties (SoD) Rejection', () => {
    it('detects Self-Certification (discovering == verifying) and rejects under E_SOD_SELF_CERTIFICATION', () => {
      const sod = evaluateSeparationOfDuties(
        'agent-adversary-eval-01',
        'agent-adversary-eval-01',
        'agent-auth-gate-04'
      );

      assert.equal(sod.is_valid, false);
      assert.ok(sod.violation_details?.includes('E_SOD_SELF_CERTIFICATION'));
    });

    it('detects Omnipotent Agent (d == v == a) and rejects under E_SOD_OMNIPOTENT_AGENT', () => {
      const sod = evaluateSeparationOfDuties('super-agent', 'super-agent', 'super-agent');
      assert.equal(sod.is_valid, false);
      assert.ok(sod.violation_details?.includes('E_SOD_OMNIPOTENT_AGENT'));
    });

    it('detects Self-Authorization (verifying == authorizing) and rejects under E_SOD_SELF_AUTHORIZATION', () => {
      const sod = evaluateSeparationOfDuties('agent-disc', 'agent-auth', 'agent-auth');
      assert.equal(sod.is_valid, false);
      assert.ok(sod.violation_details?.includes('E_SOD_SELF_AUTHORIZATION'));
    });

    it('detects Discoverer-Authorization (discovering == authorizing) and rejects', () => {
      const sod = evaluateSeparationOfDuties('agent-solo', 'agent-veri', 'agent-solo');
      assert.equal(sod.is_valid, false);
      assert.ok(sod.violation_details?.includes('E_SOD_DISCOVERER_AUTHORIZATION'));
    });

    it('prevents case-sensitivity and whitespace evasion tactics', () => {
      const sod1 = evaluateSeparationOfDuties('  agent-01  ', 'AGENT-01', 'agent-02');
      assert.equal(sod1.is_valid, false, 'Whitespace and case differences must not evade SoD');

      const sod2 = evaluateSeparationOfDuties('agent-01', 'agent-02', 'AGENT-01');
      assert.equal(sod2.is_valid, false);
    });

    it('DeterministicQualityGate rejects self-certified fixture with REJECT verdict', async () => {
      const gate = new DeterministicQualityGate();
      const finding = parseFinding(selfCertifiedFixture.finding);
      const evidence = parseEvidence(selfCertifiedFixture.evidence);

      const decision = await gate.evaluate({
        findings: [finding],
        evidence: [evidence],
        discovering_agent_id: finding.agent_context?.discovering_agent_id,
        verifying_agent_id: evidence.verifier_agent_id,
        authorizing_agent_id: 'agent-auth-gate-04',
      });

      assert.notEqual(decision.verdict, 'PASS');
      assert.equal(decision.verdict, 'REJECT');
      assert.equal(decision.sod_evaluation.is_valid, false);
      assert.ok(decision.rules_evaluated.some((r) => r.rule_id === 'RULE_SEPARATION_OF_DUTIES' && r.status === 'FAIL'));
    });
  });

  describe('2.6 Expired Policy Exception & Scope Safety Rejections', () => {
    it('detects expired exceptions (expires < today)', () => {
      const expiredEx = expiredPolicyFixture.exceptions[0];
      const isExpired = isExceptionExpired(expiredEx, '2026-11-06');
      assert.equal(isExpired, true);

      const validity = evaluateExceptionsValidity(expiredPolicyFixture.exceptions, '2026-11-06');
      assert.equal(validity.valid, false);
      assert.equal(validity.expiredExceptions.length, 1);
    });

    it('DeterministicQualityGate strictly REJECTS gate when policy contains expired exception', async () => {
      const gate = new DeterministicQualityGate();
      const finding = parseFinding(validFindingRaw);
      const evidence = parseEvidence(validEvidenceRaw);
      const patch = parsePatch(validPatchRaw);

      const decision = await gate.evaluate({
        policy: expiredPolicyFixture,
        findings: [finding],
        evidence: [evidence],
        patches: [patch],
        discovering_agent_id: 'agent-scanner-mantis-01',
        verifying_agent_id: 'agent-verifier-pytest-02',
        authorizing_agent_id: 'agent-auth-quality-gate-04',
      });

      assert.notEqual(decision.verdict, 'PASS');
      assert.equal(decision.verdict, 'REJECT');
      assert.ok(decision.rules_evaluated.some((r) => r.rule_id === 'RULE_POLICY_EXCEPTIONS' && r.status === 'FAIL'));
    });

    it('insideScope strictly rejects directory traversal attacks', () => {
      const root = path.resolve('/workspace/repo');
      assert.equal(insideScope(root, 'src/api/users.ts'), true);
      assert.equal(insideScope(root, 'src/../src/api/users.ts'), true);

      // Traversal attacks escaping root
      assert.equal(insideScope(root, '../../etc/passwd'), false);
      assert.equal(insideScope(root, '..\\..\\Windows\\System32'), false);
      assert.equal(insideScope(root, '/etc/shadow'), false);
    });

    it('blocks the gate when max_files or total_scanned_bytes exceed policy budget', async () => {
      const gate = new DeterministicQualityGate();
      const finding = parseFinding(validFindingRaw);
      const evidence = parseEvidence(validEvidenceRaw);

      const decision = await gate.evaluate({
        policy: {
          version: 1,
          max_files: 5,
          max_total_bytes: 1000,
        },
        findings: [finding],
        evidence: [evidence],
        evaluated_files: ['f1.ts', 'f2.ts', 'f3.ts', 'f4.ts', 'f5.ts', 'f6.ts'], // 6 > 5
        total_scanned_bytes: 5000, // 5000 > 1000
        discovering_agent_id: 'agent-scanner-mantis-01',
        verifying_agent_id: 'agent-verifier-pytest-02',
        authorizing_agent_id: 'agent-auth-quality-gate-04',
      });

      assert.notEqual(decision.verdict, 'PASS');
      assert.equal(decision.verdict, 'BLOCK');
      assert.ok(decision.rules_evaluated.some((r) => (r.rule_id === 'RULE_LIMIT_MAX_FILES' || r.rule_id === 'RULE_LIMIT_MAX_TOTAL_BYTES') && r.status === 'FAIL'));
    });
  });
});
