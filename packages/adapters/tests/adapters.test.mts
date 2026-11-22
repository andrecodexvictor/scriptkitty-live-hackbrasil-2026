/**
 * @file packages/adapters/tests/adapters.test.mts
 * @description Comprehensive unit test suite for ScriptKitty 2.0 Security Engine Adapters.
 * Validates execution boundary isolation, timeout enforcement, secret redaction,
 * output contract mapping to @script-kitty/contracts, and specific adapter behaviors for:
 * 1. Execution Boundary
 * 2. Google Mantis Adapter
 * 3. OpenAI Codex Security Adapter
 * 4. Cloudflare Security Center Adapter
 * 5. Quality Engine Adapter
 * 6. End-to-End Chain of Custody Verification
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  MantisAdapter,
  CodexSecurityAdapter,
  CloudflareSecurityCenterAdapter,
  QualityEngineAdapter,
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
  parseSecurityPackPolicy,
  normalizeMantisSeverity,
  invertUnifiedDiff,
  normalizeSarifSeverity,
  extractCweId,
  scoreReachabilityConfidence,
  normalizeCloudflareSeverity,
  type SecurityPackPolicy,
  type SarifLog,
} from '../dist/index.js';

import {
  validateFinding,
  validateEvidence,
  validatePatch,
  buildCustodyChain,
  verifyChainOfCustody,
  computeFindingFingerprint,
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
} from '../../contracts/dist/index.js';

describe('ScriptKitty 2.0 Adapter Architecture Suite', () => {

  // ==========================================================================
  // 1. EXECUTION BOUNDARY & HARDENING
  // ==========================================================================
  describe('Execution Boundary Wrappers', () => {
    it('withTimeout: resolves successfully when operation finishes within budget', async () => {
      const result = await withTimeout(
        new Promise<string>((resolve) => setTimeout(() => resolve('fast_result'), 20)),
        1000,
        'FastOperation'
      );
      assert.equal(result, 'fast_result');
    });

    it('withTimeout: enforces deadline and rejects with TimeoutError when deadline exceeded', async () => {
      await assert.rejects(
        async () => {
          await withTimeout(
            new Promise<string>((resolve) => setTimeout(() => resolve('slow_result'), 200)),
            25,
            'SlowOperation'
          );
        },
        (err: unknown) => {
          assert(err instanceof TimeoutError);
          assert.equal(err.name, 'TimeoutError');
          assert.equal(err.timeoutMs, 25);
          assert.equal(err.operation, 'SlowOperation');
          assert.match(err.message, /SlowOperation timed out after 25ms/);
          return true;
        }
      );
    });

    it('sanitizeOutput: redacts Bearer authorization tokens', () => {
      const raw = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sometokenpayload.signature123';
      const clean = sanitizeOutput(raw);
      assert(!clean.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'));
      assert(clean.includes('Bearer [REDACTED]'));
    });

    it('sanitizeOutput: redacts API keys and secret assignments', () => {
      const raw = 'Config: api_key="sk-live-928190348120349812", secret: \'my_super_secret_password_123\'';
      const clean = sanitizeOutput(raw);
      assert(!clean.includes('sk-live-928190348120349812'));
      assert(!clean.includes('my_super_secret_password_123'));
      assert.match(clean, /api_key="?\[REDACTED\]"?/);
      assert.match(clean, /secret: '?\[REDACTED\]'?/);
    });

    it('sanitizeOutput: redacts AWS Access Keys and GitHub PATs', () => {
      const raw = 'AWS Key AKIAIOSFODNN7EXAMPLE and GitHub token ghp_1234567890abcdefghijklmnopqrstuvwxyz';
      const clean = sanitizeOutput(raw);
      assert(!clean.includes('AKIAIOSFODNN7EXAMPLE'));
      assert(!clean.includes('ghp_1234567890abcdefghijklmnopqrstuvwxyz'));
      assert(clean.includes('AKIA[REDACTED]'));
      assert(clean.includes('ghp_[REDACTED]'));
    });

    it('sanitizeOutput: redacts private key blocks completely', () => {
      const raw = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA04...secretbytes\n-----END RSA PRIVATE KEY-----';
      const clean = sanitizeOutput(raw);
      assert(!clean.includes('secretbytes'));
      assert(clean.includes('[REDACTED PRIVATE KEY]'));
    });

    it('sanitizeOutput: preserves non-secret text and normal code lines', () => {
      const code = 'function calculateTotal(price: number, taxRate: number) { return price * (1 + taxRate); }';
      const clean = sanitizeOutput(code);
      assert.equal(clean, code);
    });

    it('sanitizeObject: deeply redacts nested keys and string values in objects', () => {
      const nested = {
        user: 'alice',
        credentials: {
          password: 'plain_password_123',
          access_token: 'secret_token_abc_12345',
        },
        headers: ['Content-Type: application/json', 'Authorization: Bearer secret_bearer_9876543210'],
      };
      const cleaned = sanitizeObject(nested);
      assert.equal(cleaned.user, 'alice');
      assert.equal(cleaned.credentials.password, '[REDACTED]');
      assert.equal(cleaned.credentials.access_token, '[REDACTED]');
      assert(cleaned.headers[1].includes('Bearer [REDACTED]'));
    });

    it('checkSizeBudget and assertWithinBudget: enforces byte limit boundaries', () => {
      const small = 'Hello World';
      const budgetCheck = checkSizeBudget(small, 100, 'TestString');
      assert.equal(budgetCheck.ok, true);
      assert.equal(budgetCheck.size, 11);

      assert.doesNotThrow(() => {
        assertWithinBudget(small, 100, 'TestString');
      });

      const large = 'X'.repeat(500);
      const largeCheck = checkSizeBudget(large, 200, 'LargeString');
      assert.equal(largeCheck.ok, false);
      assert.equal(largeCheck.size, 500);
      assert.equal(largeCheck.limit, 200);

      assert.throws(
        () => assertWithinBudget(large, 200, 'LargeString'),
        SizeBudgetExceededError
      );
    });

    it('truncateToBudget: cleanly truncates strings exceeding limits', () => {
      const text = 'abcdefghijklmnopqrstuvwxyz0123456789';
      const res = truncateToBudget(text, 20, '...[TRUNCATED]');
      assert.equal(res.truncated, true);
      assert(res.content.endsWith('...[TRUNCATED]'));
      assert(Buffer.byteLength(res.content, 'utf8') <= 20);
    });

    it('safeExecute and executeInBoundary: never let unhandled exceptions escape', async () => {
      const fallbackResult = await safeExecute(
        async () => {
          throw new Error('Fatal network socket drop: secret_token=123456789');
        },
        (err) => ({ recovered: true, error: sanitizeOutput(err.message) })
      );

      assert.equal(fallbackResult.recovered, true);
      assert(fallbackResult.error.includes('[REDACTED]'));

      const boundaryResult = await executeInBoundary(
        async () => {
          throw new Error('Crash in external scanner subprocess');
        },
        { timeoutMs: 500, operationName: 'SubprocessCall' }
      );

      assert.equal(boundaryResult.success, false);
      assert(boundaryResult.error?.includes('Crash in external scanner subprocess'));
      assert.equal(boundaryResult.timedOut, false);
    });
  });

  // ==========================================================================
  // 2. GOOGLE MANTIS ADAPTER
  // ==========================================================================
  describe('Google Mantis Adapter', () => {
    const adapter = new MantisAdapter();

    it('has valid engine metadata and supported target types', () => {
      assert.equal(adapter.engine_name, 'mantis');
      assert(adapter.supported_target_types.includes('SOURCE_CODE'));
    });

    it('normalizeMantisSeverity: converts 1-10 calibrated risk scores to canonical severities', () => {
      assert.equal(normalizeMantisSeverity(10), 'CRITICAL');
      assert.equal(normalizeMantisSeverity(9), 'CRITICAL');
      assert.equal(normalizeMantisSeverity(8), 'HIGH');
      assert.equal(normalizeMantisSeverity(7), 'HIGH');
      assert.equal(normalizeMantisSeverity(5), 'MEDIUM');
      assert.equal(normalizeMantisSeverity(2), 'LOW');
      assert.equal(normalizeMantisSeverity('high'), 'HIGH');
    });

    it('scan: ingests ADK directory context and outputs canonical SecurityFinding contracts', async () => {
      const scanResult = await adapter.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'https://github.com/example/vulnerable-app',
        commit_hash: 'c0ffee1234567890123456789012345678901234',
        threat_model_overlay: '# Living Threat Model\nEntry points: /api/query',
        metadata: {
          directory_summaries: [
            {
              path: 'src/api',
              component: 'API Controller',
              summary: 'Handles user database lookups',
              entry_points: ['/api/query'],
              external_sinks: ['db.query'],
            },
          ],
          raw_findings: [
            {
              id: 'SK-MANTIS-001',
              title: 'SQL Injection in User Lookup',
              description: 'Concatenation of raw user query param into SQL statement: auth_token=secret_xyz12345',
              cwe_id: 'CWE-89',
              owasp_category: 'A03:2021-Injection',
              calibrated_risk_score: 9.5,
              file_path: 'src/api/users.ts',
              start_line: 42,
              end_line: 45,
              symbol: 'getUserById',
              matched_code: 'db.query("SELECT * FROM users WHERE id = " + req.query.id)',
            },
          ],
        },
      });

      assert.equal(scanResult.status, 'success');
      assert.equal(scanResult.engine_name, 'mantis');
      assert.equal(scanResult.findings.length, 1);

      const finding = scanResult.findings[0];
      assert.equal(finding.finding_id, 'SK-MANTIS-001');
      assert.equal(finding.cwe_id, 'CWE-89');
      assert.equal(finding.severity, 'CRITICAL');
      assert.equal(finding.location.file_path, 'src/api/users.ts');
      assert.equal(finding.location.start_line, 42);
      assert.equal(finding.location.end_line, 45);
      assert(!finding.description.includes('secret_xyz12345'));
      assert(finding.description.includes('[REDACTED]'));

      // Validate contract strictly against Zod schema
      const validation = validateFinding(finding);
      assert.equal(validation.success, true);
    });

    it('reproduce: executes sandboxed crash reproducer and produces canonical Evidence', async () => {
      const mockFinding: SecurityFinding = {
        finding_id: 'SK-MANTIS-001',
        source_engine: 'mantis',
        title: 'SQL Injection in User Lookup',
        description: 'Vulnerable SQL concatenation',
        cwe_id: 'CWE-89',
        owasp_category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: 'src/api/users.ts',
        location: { file_path: 'src/api/users.ts', start_line: 42, end_line: 45 },
        fingerprint: computeFindingFingerprint({ cwe_id: 'CWE-89', file_path: 'src/api/users.ts', rule_or_match: 'getUserById' }),
        commit_hash: 'c0ffee1234567890123456789012345678901234',
        discovered_at: new Date().toISOString(),
      };

      const reproResult = await adapter.reproduce(mockFinding, {
        sandbox_runtime: 'docker_isolated',
        network_isolated: true,
        timeout_ms: 5000,
        custom_config: {
          mock_exit_code: 1,
          mock_stderr: 'VulnerabilityTriggerException: SQL syntax error triggered by quote payload',
        },
      });

      assert.equal(reproResult.status, 'success');
      assert.equal(reproResult.reproduction_verified, true);
      assert(reproResult.evidence !== undefined);

      const evidence = reproResult.evidence!;
      assert.equal(evidence.finding_id, 'SK-MANTIS-001');
      assert.equal(evidence.status, 'VERIFIED_TRUE_POSITIVE');
      assert.equal(evidence.verification_type, 'REPRODUCER_EXECUTION');
      assert.equal(evidence.sandbox_environment.network_isolated, true);
      assert.equal(evidence.reproducer_artifact?.exit_code, 1);
      assert(evidence.chain_hash.length === 64);

      // Validate contract strictly
      const validation = validateEvidence(evidence);
      assert.equal(validation.success, true);
    });

    it('recheck: verifies patch recheck loop (passed_clean vs regression_detected)', async () => {
      const patch = adapter.createPatchProposal(
        {
          finding_id: 'SK-MANTIS-001',
          source_engine: 'mantis',
          title: 'SQLi',
          description: '',
          cwe_id: 'CWE-89',
          owasp_category: 'A03:2021-Injection',
          severity: 'CRITICAL',
          confidence: 'CERTAIN',
          target_type: 'SOURCE_CODE',
          target: 'src/api/users.ts',
          location: { file_path: 'src/api/users.ts', start_line: 42, end_line: 45 },
          fingerprint: '0'.repeat(64),
          commit_hash: 'c0ffee1234567890123456789012345678901234',
          discovered_at: new Date().toISOString(),
        },
        '--- a/src/api/users.ts\n+++ b/src/api/users.ts\n@@ -42,1 +42,1 @@\n- db.query("SELECT * FROM users WHERE id = " + req.query.id);\n+ db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);\n'
      );

      // 1. Clean recheck pass
      const cleanResult = await adapter.recheck(patch, {
        custom_config: {
          reproducer_still_fails: false,
          regression_detected: false,
        },
      });
      assert.equal(cleanResult.status, 'success');
      assert.equal(cleanResult.recheck_status, 'passed_clean');
      assert.equal(cleanResult.tests_passed, true);
      assert.equal(cleanResult.reproducer_passed, true);
      assert(cleanResult.evidence !== undefined);

      // 2. Regression detected pass
      const regressionResult = await adapter.recheck(patch, {
        custom_config: {
          reproducer_still_fails: false,
          regression_detected: true,
        },
      });
      assert.equal(regressionResult.status, 'success');
      assert.equal(regressionResult.recheck_status, 'regression_detected');
      assert.equal(regressionResult.tests_passed, false);
    });

    it('createPatchProposal: generates valid PatchProposal with inverted rollback diff', () => {
      const diff = '--- a/src/index.ts\n+++ b/src/index.ts\n- oldBadLine();\n+ newSafeLine();\n';
      const inverted = invertUnifiedDiff(diff);
      assert(inverted.includes('+ oldBadLine();'));
      assert(inverted.includes('- newSafeLine();'));
    });
  });

  // ==========================================================================
  // 3. OPENAI CODEX SECURITY ADAPTER
  // ==========================================================================
  describe('OpenAI Codex Security Adapter', () => {
    const adapter = new CodexSecurityAdapter();

    it('has valid engine metadata and supported target types', () => {
      assert.equal(adapter.engine_name, 'codex_security');
      assert(adapter.supported_target_types.includes('SOURCE_CODE'));
      assert(adapter.supported_target_types.includes('MCP_TOOL'));
    });

    it('scan: parses SARIF 2.1.0 and applies reachability confidence scoring', async () => {
      const mockSarif: SarifLog = {
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'OpenAI Codex Security',
                rules: [
                  {
                    id: 'rule-cmd-injection',
                    shortDescription: { text: 'OS Command Injection via child_process.exec' },
                    properties: {
                      cwe: ['CWE-78'],
                      owasp: ['A03:2021-Injection'],
                      securitySeverity: '8.8',
                    },
                  },
                ],
              },
            },
            results: [
              {
                ruleId: 'rule-cmd-injection',
                level: 'error',
                message: { text: 'Unescaped user input passed directly to child_process.exec' },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'src/controllers/admin.ts' },
                      region: { startLine: 88, endLine: 90 },
                    },
                    logicalLocations: [{ name: 'handleExecuteCommand' }],
                  },
                ],
                properties: {
                  reachability: 'REACHABLE',
                  attackPath: ['GET /admin/exec -> handleExecuteCommand -> child_process.exec'],
                  costUsd: 0.12,
                },
              },
            ],
          },
        ],
      };

      const result = await adapter.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'src/controllers/admin.ts',
        metadata: {
          sarif: mockSarif,
          knowledge_base_path: 'docs/architecture.md',
        },
      });

      assert.equal(result.status, 'success');
      assert.equal(result.findings.length, 1);

      const finding = result.findings[0];
      assert.equal(finding.cwe_id, 'CWE-78');
      assert.equal(finding.severity, 'HIGH');
      assert.equal(finding.confidence, 'CERTAIN'); // Reachable confirmed
      assert.equal(finding.location.file_path, 'src/controllers/admin.ts');
      assert.equal(finding.location.start_line, 88);

      const validation = validateFinding(finding);
      assert.equal(validation.success, true);
    });

    it('scoreReachabilityConfidence: correctly downgrades unreachable patterns to TENTATIVE', () => {
      const threatModel = {
        entry_points: ['src/routes/api.ts'],
        sanitizers: ['src/utils/sanitize.ts'],
        sensitive_sinks: ['child_process.exec'],
        trust_boundaries: ['public_gateway'],
      };

      const reachable = scoreReachabilityConfidence('src/routes/api.ts', 'searchUsers', threatModel, 'REACHABLE');
      assert.equal(reachable.confidence, 'CERTAIN');

      const unreachable = scoreReachabilityConfidence('tests/mocks/fixture.ts', 'unusedHelper', threatModel, 'UNREACHABLE');
      assert.equal(unreachable.confidence, 'TENTATIVE');
    });

    it('scan: enforces strict spending ceiling and flags is_partial = true when cap reached', async () => {
      // Create a SARIF log with 5 items each costing $0.15 (total $0.75)
      const results = [];
      for (let i = 1; i <= 5; i++) {
        results.push({
          ruleId: `rule-sqli-${i}`,
          level: 'error' as const,
          message: { text: `Vulnerability #${i}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: `src/file_${i}.ts` },
                region: { startLine: 10 },
              },
            },
          ],
          properties: {
            costUsd: 0.15,
          },
        });
      }

      const mockSarif: SarifLog = {
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'codex-security' } },
            results,
          },
        ],
      };

      // Set max_cost_usd to $0.20 (permitting at most 1 item of $0.15 before cap is hit)
      const scanResult = await adapter.scan(
        {
          target_type: 'SOURCE_CODE',
          target_url_or_path: 'src/',
          metadata: { sarif: mockSarif },
        },
        { max_cost_usd: 0.20 }
      );

      assert.equal(scanResult.status, 'partial');
      assert.equal(scanResult.is_partial, true);
      assert.equal(scanResult.findings.length, 1);
      assert(scanResult.cost_usd! <= 0.20);
      assert(scanResult.warnings !== undefined && scanResult.warnings.length > 0);
      assert(scanResult.warnings[0].includes('Spending ceiling reached'));
    });

    it('reproduce: provides secondary opinion review (DUAL_OPINION_CONSENSUS)', async () => {
      const finding: SecurityFinding = {
        finding_id: 'SK-CODEX-RULE1-001',
        source_engine: 'codex_security',
        title: 'Command Injection',
        description: 'Vulnerable',
        cwe_id: 'CWE-78',
        owasp_category: 'A03:2021-Injection',
        severity: 'HIGH',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: 'src/admin.ts',
        location: { file_path: 'src/admin.ts', start_line: 1, end_line: 5 },
        fingerprint: '1'.repeat(64),
        commit_hash: 'c0ffee1234567890123456789012345678901234',
        discovered_at: new Date().toISOString(),
      };

      const result = await adapter.reproduce(finding, {
        verifier_agent_id: 'codex-secondary-reviewer',
        custom_config: { consensus_verified: true },
      });

      assert.equal(result.status, 'success');
      assert.equal(result.reproduction_verified, true);
      assert.equal(result.evidence?.verification_type, 'DUAL_OPINION_CONSENSUS');
      assert.equal(result.evidence?.status, 'VERIFIED_TRUE_POSITIVE');

      const validation = validateEvidence(result.evidence!);
      assert.equal(validation.success, true);
    });
  });

  // ==========================================================================
  // 4. CLOUDFLARE SECURITY CENTER ADAPTER
  // ==========================================================================
  describe('Cloudflare Security Center Adapter', () => {
    const adapter = new CloudflareSecurityCenterAdapter();

    it('has valid engine metadata and supported target types', () => {
      assert.equal(adapter.engine_name, 'cloudflare_security_center');
      assert(adapter.supported_target_types.includes('CLOUD_RESOURCE'));
      assert(adapter.supported_target_types.includes('API_ENDPOINT'));
    });

    it('scan: ingests Attack Surface Management insights (dangling DNS, deprecated TLS)', async () => {
      const result = await adapter.scan({
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'example.com',
        metadata: {
          insights: [
            {
              id: 'insight-dangling-01',
              type: 'dangling_dns',
              severity: 'high',
              title: 'Dangling CNAME record pointing to abandoned S3 bucket',
              description: 'CNAME blog.example.com points to unclaimed-bucket.s3.amazonaws.com',
              hostname: 'blog.example.com',
              record_name: 'blog.example.com',
              record_type: 'CNAME',
            },
            {
              id: 'insight-tls-02',
              type: 'deprecated_tls',
              severity: 'moderate',
              title: 'Deprecated TLS 1.0/1.1 enabled on zone',
              description: 'Zone allows legacy TLS protocols vulnerable to cryptographic downgrade',
              hostname: 'api.example.com',
            },
            {
              id: 'insight-api-03',
              type: 'open_api_schema_violation',
              severity: 'high',
              title: 'API Shield detected schema drift on /v1/checkout',
              description: 'Inbound requests contained undocumented administrative parameter',
              hostname: 'api.example.com',
            },
          ],
        },
      });

      assert.equal(result.status, 'success');
      assert.equal(result.findings.length, 3);

      // Verify Dangling DNS mapping
      const dangling = result.findings.find((f) => f.cwe_id === 'CWE-284');
      assert(dangling !== undefined);
      assert.equal(dangling.severity, 'HIGH');
      assert.equal(dangling.target_type, 'CLOUD_RESOURCE');
      assert.equal(dangling.location.file_path, 'dns/records.json');

      // Verify Deprecated TLS mapping
      const tls = result.findings.find((f) => f.cwe_id === 'CWE-326');
      assert(tls !== undefined);
      assert.equal(tls.severity, 'MEDIUM');
      assert.equal(tls.location.file_path, 'ssl/tls-config.json');

      // Verify API Shield mapping
      const apiShield = result.findings.find((f) => f.cwe_id === 'CWE-20');
      assert(apiShield !== undefined);
      assert.equal(apiShield.severity, 'HIGH');
      assert.equal(apiShield.target_type, 'API_ENDPOINT');

      for (const finding of result.findings) {
        const validation = validateFinding(finding);
        assert.equal(validation.success, true);
      }
    });

    it('scan: handles API token authentication failure gracefully with status: error', async () => {
      const result = await adapter.scan({
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'example.com',
        metadata: {
          simulate_auth_failure: true,
          auth_token: 'invalid_revoked_token',
        },
      });

      assert.equal(result.status, 'error');
      assert.equal(result.findings.length, 0);
      assert(result.errors !== undefined);
      assert(result.errors[0].includes('403 Forbidden'));
    });

    it('reproduce: maps Logpush edge event telemetry into canonical Evidence', async () => {
      const finding: SecurityFinding = {
        finding_id: 'SK-CF-insight-dangling-01',
        source_engine: 'cloudflare_security_center',
        title: 'Dangling DNS',
        description: 'Dangling CNAME',
        cwe_id: 'CWE-284',
        owasp_category: 'A05:2021-Security Misconfiguration',
        severity: 'HIGH',
        confidence: 'CERTAIN',
        target_type: 'CLOUD_RESOURCE',
        target: 'blog.example.com',
        location: { file_path: 'dns/records.json', start_line: 1, end_line: 1 },
        fingerprint: '2'.repeat(64),
        commit_hash: 'c0ffee1234567890123456789012345678901234',
        discovered_at: new Date().toISOString(),
      };

      const reproResult = await adapter.reproduce(finding, {
        verifier_agent_id: 'cf-telemetry-verifier',
        custom_config: {
          edge_action: 'block',
          injection_score: 0.95,
        },
      });

      assert.equal(reproResult.status, 'success');
      assert.equal(reproResult.reproduction_verified, true);
      assert.equal(reproResult.evidence?.verification_type, 'EDGE_TELEMETRY');
      assert.equal(reproResult.evidence?.status, 'VERIFIED_TRUE_POSITIVE');

      const validation = validateEvidence(reproResult.evidence!);
      assert.equal(validation.success, true);
    });
  });

  // ==========================================================================
  // 5. QUALITY ENGINE ADAPTER
  // ==========================================================================
  describe('Quality Engine Adapter', () => {
    const adapter = new QualityEngineAdapter();

    it('has valid engine metadata and supported target types', () => {
      assert.equal(adapter.engine_name, 'quality_engine');
      assert(adapter.supported_target_types.includes('SOURCE_CODE'));
      assert(adapter.supported_target_types.includes('CONFIGURATION'));
    });

    it('parseSecurityPackPolicy: strictly requires version 1 and rejects unsupported versions', () => {
      assert.throws(
        () => parseSecurityPackPolicy({ version: 2 }),
        /expected supported version 1, received version=2/
      );
      assert.throws(
        () => parseSecurityPackPolicy({}),
        /expected supported version 1/
      );
      assert.throws(
        () => parseSecurityPackPolicy({ version: 1, allowUnknownRoot: true }),
        /unrecognized root key 'allowUnknownRoot'/
      );
    });

    it('parseSecurityPackPolicy: throws immediate error when an exception is expired', () => {
      const policyWithExpiredException = {
        version: 1,
        exceptions: [
          {
            ruleId: 'SEC-001',
            fingerprint: 'a'.repeat(64),
            reason: 'Temporary exception for legacy endpoint',
            expires: '2024-01-01', // Expired
          },
        ],
      };

      assert.throws(
        () => parseSecurityPackPolicy(policyWithExpiredException, '2026-11-06'),
        /Exception for rule 'SEC-001' expired on 2024-01-01/
      );
    });

    it('parseSecurityPackPolicy: accepts valid unexpired exceptions', () => {
      const validPolicy = {
        version: 1,
        limits: {
          maxFileBytes: 1048576,
          maxFiles: 1000,
        },
        requiredScanners: ['gitleaks'],
        exceptions: [
          {
            ruleId: 'SEC-002',
            fingerprint: 'b'.repeat(64),
            reason: 'Approved test fixture mock secret',
            expires: '2030-01-01',
          },
        ],
      };

      const parsed = parseSecurityPackPolicy(validPolicy, '2026-11-06');
      assert.equal(parsed.version, 1);
      assert.equal(parsed.exceptions?.length, 1);
      assert.equal(parsed.limits?.maxFileBytes, 1048576);
    });

    it('evaluateQuadState: resolves to pass when zero unsuppressed critical/high findings exist', () => {
      const evalResult = adapter.evaluateQuadState({
        policy: { version: 1 },
        findings: [],
        availableScanners: ['gitleaks'],
      });

      assert.equal(evalResult.state, 'pass');
      assert.equal(evalResult.blockingFindings.length, 0);
    });

    it('evaluateQuadState: resolves to finding when unsuppressed critical finding exists', () => {
      const unsuppressedFinding: SecurityFinding = {
        finding_id: 'SK-FIND-SQLI-01',
        source_engine: 'mantis',
        title: 'SQLi',
        description: '',
        cwe_id: 'CWE-89',
        owasp_category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: 'src/db.ts',
        location: { file_path: 'src/db.ts', start_line: 1, end_line: 1 },
        fingerprint: 'c'.repeat(64),
        commit_hash: 'c0ffee1234567890123456789012345678901234',
        discovered_at: new Date().toISOString(),
      };

      const evalResult = adapter.evaluateQuadState({
        policy: { version: 1 },
        findings: [unsuppressedFinding],
        availableScanners: ['gitleaks'],
      });

      assert.equal(evalResult.state, 'finding');
      assert.equal(evalResult.blockingFindings.length, 1);
      assert.equal(evalResult.blockingFindings[0], 'SK-FIND-SQLI-01');
    });

    it('evaluateQuadState: suppresses matching finding when unexpired SHA-256 fingerprint matches', () => {
      const fingerprint = 'd'.repeat(64);
      const suppressedFinding: SecurityFinding = {
        finding_id: 'SK-FIND-SQLI-SUPPRESSED',
        source_engine: 'mantis',
        title: 'SQLi',
        description: '',
        cwe_id: 'CWE-89',
        owasp_category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: 'src/db.ts',
        location: { file_path: 'src/db.ts', start_line: 1, end_line: 1 },
        fingerprint,
        commit_hash: 'c0ffee1234567890123456789012345678901234',
        discovered_at: new Date().toISOString(),
      };

      const evalResult = adapter.evaluateQuadState({
        policy: {
          version: 1,
          exceptions: [
            {
              ruleId: 'SEC-SQLI',
              fingerprint,
              reason: 'Mock database used only in offline unit test harness',
              expires: '2030-12-31',
            },
          ],
        },
        findings: [suppressedFinding],
        availableScanners: ['gitleaks'],
        todayUtc: '2026-11-06',
      });

      assert.equal(evalResult.state, 'pass');
      assert.equal(evalResult.suppressedFindings.length, 1);
      assert.equal(evalResult.blockingFindings.length, 0);
    });

    it('evaluateQuadState: resolves to error when missing required scanner or limits exceeded', () => {
      // 1. Missing scanner
      const missingScannerResult = adapter.evaluateQuadState({
        policy: {
          version: 1,
          requiredScanners: ['gitleaks', 'trivy'],
        },
        findings: [],
        availableScanners: ['gitleaks'], // trivy missing
      });
      assert.equal(missingScannerResult.state, 'error');
      assert(missingScannerResult.errors[0].includes("Missing required security scanner 'trivy'"));

      // 2. Max files exceeded
      const limitExceededResult = adapter.evaluateQuadState({
        policy: {
          version: 1,
          limits: { maxFiles: 100 },
        },
        findings: [],
        totalFiles: 250,
      });
      assert.equal(limitExceededResult.state, 'error');
      assert(limitExceededResult.errors[0].includes('File count limit exceeded'));
    });

    it('evaluateQuadState: resolves to not_applicable when target scope is outside boundary', () => {
      const result = adapter.evaluateQuadState({
        policy: { version: 1 },
        findings: [],
        targetScopeApplicable: false,
      });
      assert.equal(result.state, 'not_applicable');
    });

    it('scan: detects symlink boundary breach and reports error', async () => {
      const scanResult = await adapter.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'src/symlink.ts',
        metadata: {
          is_symlink: true,
          escapes_boundary: true,
        },
      });

      assert.equal(scanResult.status, 'error');
      assert(scanResult.errors !== undefined);
      assert(scanResult.errors[0].includes('Boundary violation'));
    });

    it('recheck: detects path traversal in patch affected files', async () => {
      const patch: PatchProposal = {
        patch_id: 'SK-PATCH-QE-TRAVERSAL',
        finding_id: 'SK-FIND-01',
        author_engine: 'manual',
        diff_content: 'diff content',
        affected_files: ['src/safe.ts', '../../etc/shadow'], // Traversal attack!
        base_commit: 'c0ffee1234567890123456789012345678901234',
        patch_sha256: 'e'.repeat(64),
        recheck_status: 'untested',
        recheck_evidence_id: null,
        blast_radius: {
          files_modified: 2,
          lines_added: 5,
          lines_deleted: 1,
          ast_impact_scope: 'LOCAL_FUNCTION',
          downstream_dependents: [],
          breaking_change_risk: 'HIGH',
        },
        rollback_plan: {
          revert_patch: 'reverse diff',
        },
        created_at: new Date().toISOString(),
      };

      const result = await adapter.recheck(patch);
      assert.equal(result.status, 'error');
      assert.equal(result.recheck_status, 'regression_detected');
      assert(result.error?.includes('Boundary check failed'));
    });
  });

  // ==========================================================================
  // 6. END-TO-END CHAIN OF CUSTODY INTEGRATION
  // ==========================================================================
  describe('Cross-Engine Chain of Custody Integration', () => {
    it('constructs and cryptographically verifies an immutable chain of custody across all stages', async () => {
      const mantis = new MantisAdapter();

      // Step 1: Scan
      const scan = await mantis.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'src/api/users.ts',
        commit_hash: 'c0ffee1234567890123456789012345678901234',
        metadata: {
          raw_findings: [
            {
              id: 'SK-MANTIS-E2E-001',
              title: 'SQL Injection in users controller',
              description: 'req.query.id directly concatenated',
              cwe_id: 'CWE-89',
              owasp_category: 'A03:2021-Injection',
              calibrated_risk_score: 9.5,
              file_path: 'src/api/users.ts',
              start_line: 12,
              end_line: 14,
            },
          ],
        },
      });
      assert.equal(scan.findings.length, 1);
      const finding = scan.findings[0];

      // Step 2: Reproduce
      const repro = await mantis.reproduce(finding, {
        verifier_agent_id: 'mantis-independent-verifier',
        custom_config: { mock_exit_code: 1 },
      });
      assert.equal(repro.status, 'success');
      const evidence = repro.evidence!;

      // Step 3: Patch Proposal
      const patch = mantis.createPatchProposal(
        finding,
        '--- a/src/api/users.ts\n+++ b/src/api/users.ts\n@@ -12,1 +12,1 @@\n- db.query("SELECT * FROM users WHERE id = " + req.query.id);\n+ db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);\n'
      );

      // Step 4: Build & Verify Cryptographic Custody Chain
      const chain = buildCustodyChain({
        finding,
        evidence,
        patch,
      });

      assert.equal(chain.total_nodes, 3);
      assert.equal(chain.is_valid, true);
      assert(chain.merkle_root.length === 64);

      const verification = verifyChainOfCustody(chain);
      assert.equal(verification.valid, true);
      assert.equal(verification.total_nodes, 3);
      assert.equal(verification.merkle_root, chain.merkle_root);
    });
  });
});
