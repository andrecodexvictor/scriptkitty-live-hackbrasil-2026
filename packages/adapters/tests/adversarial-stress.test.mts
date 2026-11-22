/**
 * @file packages/adapters/tests/adversarial-stress.test.mts
 * @description Adversarial stress-testing suite for ScriptKitty 2.0 Security Engine Adapters.
 * Systematically challenges assumptions, edge cases, boundaries, tampering, and malicious payloads
 * across MantisAdapter, CodexSecurityAdapter, CloudflareSecurityCenterAdapter, and QualityEngineAdapter.
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
  extractOwaspCategory,
  scoreReachabilityConfidence,
  normalizeCloudflareSeverity,
  type SecurityPackPolicy,
  type SarifLog,
  type CloudflareInsight,
  type CloudflareLogpushEvent,
} from '../dist/index.js';

import {
  validateFinding,
  validateEvidence,
  validatePatch,
  computeFindingFingerprint,
  computeEvidenceChainHash,
  computePatchSha256,
  sha256,
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
} from '../../contracts/dist/index.js';

describe('ADVERSARIAL STRESS TEST SUITE: Security Engine Adapters', () => {

  // ==========================================================================
  // SECTION 1: GOOGLE MANTIS ADAPTER ADVERSARIAL CHALLENGES
  // ==========================================================================
  describe('MantisAdapter: Adversarial Stress & Boundary Testing', () => {
    const adapter = new MantisAdapter();

    it('Timeout Boundary: Hard wall-clock timeout during reproducer execution triggers graceful status: error', async () => {
      const mockFinding: SecurityFinding = {
        finding_id: 'SK-MANTIS-TIMEOUT-001',
        source_engine: 'mantis',
        title: 'Long-running CPU hang reproducer',
        description: 'Reproducer triggers infinite loop or socket hang in sandbox',
        cwe_id: 'CWE-400',
        owasp_category: 'A05:2021-Security Misconfiguration',
        severity: 'HIGH',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: 'src/hang.ts',
        location: { file_path: 'src/hang.ts', start_line: 10, end_line: 15 },
        fingerprint: 'a'.repeat(64),
        commit_hash: '1111222233334444555566667777888899990000',
        discovered_at: new Date().toISOString(),
      };

      const slowPromise = new Promise<{ status: string }>((resolve) => setTimeout(() => resolve({ status: 'ok' }), 150));
      
      const timeoutResult = await executeInBoundary(async () => {
        return await withTimeout(slowPromise, 25, 'MantisReproducerExecution');
      });

      assert.equal(timeoutResult.success, false);
      assert.equal(timeoutResult.timedOut, true);
      assert.match(timeoutResult.error!, /timed out after 25ms/);

      const reproResult = await adapter.reproduce(mockFinding, {
        timeout_ms: 10,
        custom_config: { mock_exit_code: 1 },
      });

      assert(reproResult.status === 'success' || reproResult.status === 'error');
      assert.equal(typeof reproResult.duration_ms, 'number');
      assert.equal(reproResult.engine_name, 'mantis');
      assert.equal(reproResult.finding_id, mockFinding.finding_id);
    });

    it('Missing File Handling: Schema violation handling (empty path, negative lines, invalid CWE) discarded into warnings', async () => {
      const targetWithInvalidFindings = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'https://github.com/adversary/malformed-repo',
        metadata: {
          raw_findings: [
            // Malformed 1: Empty file_path string
            {
              id: 'SK-BAD-EMPTY-PATH',
              title: 'Finding with empty file_path',
              cwe_id: 'CWE-89',
              file_path: '',
              start_line: 1,
              end_line: 5,
            },
            // Malformed 2: Negative start_line
            {
              id: 'SK-BAD-LINE',
              title: 'Finding with negative line number',
              cwe_id: 'CWE-89',
              file_path: 'src/bad-line.ts',
              start_line: -10,
              end_line: 5,
            },
            // Malformed 3: Invalid CWE ID format
            {
              id: 'SK-BAD-CWE',
              title: 'Finding with malformed CWE',
              cwe_id: 'INVALID-CWE-FORMAT',
              file_path: 'src/bad-cwe.ts',
              start_line: 1,
              end_line: 5,
            },
            // Valid finding: Should be retained
            {
              id: 'SK-GOOD-1',
              title: 'Valid SQL injection finding',
              cwe_id: 'CWE-89',
              file_path: 'src/valid.ts',
              start_line: 10,
              end_line: 15,
              calibrated_risk_score: 9.2,
            },
          ],
        },
      };

      const result = await adapter.scan(targetWithInvalidFindings);
      assert.equal(result.status, 'success');
      assert.equal(result.findings.length, 1);
      assert.equal(result.findings[0].finding_id, 'SK-GOOD-1');
      assert(result.warnings !== undefined);
      assert.equal(result.warnings.length, 3);
      assert(result.warnings[0].includes('Discarded non-compliant Mantis finding'));
    });

    it('Missing File Handling: Undefined file_path triggers isolated status: error without process crash', async () => {
      const targetWithUndefinedPath = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'https://github.com/adversary/malformed-repo',
        metadata: {
          raw_findings: [
            {
              id: 'SK-BAD-UNDEFINED-PATH',
              title: 'Finding with missing file_path key',
              cwe_id: 'CWE-89',
              start_line: 1,
              end_line: 5,
            },
          ],
        },
      };

      const result = await adapter.scan(targetWithUndefinedPath);
      // Fails closed gracefully via safeExecute, capturing TypeError without process crash
      assert.equal(result.status, 'error');
      assert.equal(result.findings.length, 0);
      assert(result.errors !== undefined);
      assert.match(result.errors[0], /Cannot read properties of undefined \(reading 'trim'\)/);
    });

    it('Missing File Handling: Empty metadata, missing directory summaries, and missing target commit hash handled safely', async () => {
      const bareTarget = {
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'relative/local/path',
      };

      const result = await adapter.scan(bareTarget);
      assert.equal(result.status, 'success');
      assert.equal(result.findings.length, 0);
      assert.equal(result.errors, undefined);
    });

    it('Regression Detection: Patch recheck detects reproducer failure, test regression, and dual failures', async () => {
      const mockPatch: PatchProposal = {
        patch_id: 'SK-PATCH-RECHECK-001',
        finding_id: 'SK-FIND-SQLI-001',
        author_engine: 'mantis_patch',
        diff_content: '--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1,1 +1,1 @@\n- badQuery();\n+ safeQuery();\n',
        affected_files: ['src/db.ts'],
        base_commit: '1234567890123456789012345678901234567890',
        patch_sha256: 'b'.repeat(64),
        recheck_status: 'untested',
        recheck_evidence_id: null,
        blast_radius: {
          files_modified: 1,
          lines_added: 1,
          lines_deleted: 1,
          ast_impact_scope: 'LOCAL_FUNCTION',
          downstream_dependents: [],
          breaking_change_risk: 'LOW',
        },
        rollback_plan: {
          revert_patch: '--- b/src/db.ts\n+++ a/src/db.ts\n@@ -1,1 +1,1 @@\n- safeQuery();\n+ badQuery();\n',
        },
        created_at: new Date().toISOString(),
      };

      // Case 1: Reproducer still fails
      const stillFails = await adapter.recheck(mockPatch, {
        custom_config: { reproducer_still_fails: true, regression_detected: false },
      });
      assert.equal(stillFails.status, 'success');
      assert.equal(stillFails.recheck_status, 'reproducer_still_fails');
      assert.equal(stillFails.reproducer_passed, false);
      assert.equal(stillFails.tests_passed, true);
      assert.equal(stillFails.evidence?.status, 'VERIFIED_TRUE_POSITIVE');

      // Case 2: Test regression detected (reproducer passed but broke existing tests)
      const regression = await adapter.recheck(mockPatch, {
        custom_config: { reproducer_still_fails: false, regression_detected: true },
      });
      assert.equal(regression.status, 'success');
      assert.equal(regression.recheck_status, 'regression_detected');
      assert.equal(regression.reproducer_passed, true);
      assert.equal(regression.tests_passed, false);
      assert.equal(regression.evidence?.status, 'VERIFIED_TRUE_POSITIVE');

      // Case 3: Clean pass (reproducer fixed and all tests pass)
      const clean = await adapter.recheck(mockPatch, {
        custom_config: { reproducer_still_fails: false, regression_detected: false },
      });
      assert.equal(clean.status, 'success');
      assert.equal(clean.recheck_status, 'passed_clean');
      assert.equal(clean.reproducer_passed, true);
      assert.equal(clean.tests_passed, true);
      assert.equal(clean.evidence?.status, 'REFUTED_FALSE_POSITIVE');
    });

    it('Diff Inversion: Handles complex multi-hunk diffs, additions-only, deletions-only without corruption', () => {
      const complexDiff = [
        '--- a/src/core.ts',
        '+++ b/src/core.ts',
        '@@ -10,3 +10,4 @@',
        ' context line 1',
        '-deleted line A',
        '+added line X',
        '+added line Y',
        ' context line 2',
        '-deleted line B',
      ].join('\n');

      const inverted = invertUnifiedDiff(complexDiff);
      const lines = inverted.split('\n');

      assert.equal(lines[0], '+++ a/src/core.ts');
      assert.equal(lines[1], '--- b/src/core.ts');
      assert(lines.includes('+deleted line A'));
      assert(lines.includes('-added line X'));
      assert(lines.includes('-added line Y'));
      assert(lines.includes('+deleted line B'));
      assert(lines.includes(' context line 1'));
    });
  });

  // ==========================================================================
  // SECTION 2: OPENAI CODEX SECURITY ADAPTER ADVERSARIAL CHALLENGES
  // ==========================================================================
  describe('CodexSecurityAdapter: Adversarial Stress & Budget Boundaries', () => {
    const adapter = new CodexSecurityAdapter();

    it('Spending Ceiling: Budget exhaustion halts scan gracefully with status: partial and is_partial: true', async () => {
      const results = [];
      for (let i = 1; i <= 10; i++) {
        results.push({
          ruleId: `rule-test-${i}`,
          level: 'error' as const,
          message: { text: `Security issue #${i}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: `src/file_${i}.ts` },
                region: { startLine: i * 10, endLine: i * 10 + 2 },
              },
            },
          ],
          properties: { costUsd: 0.50 },
        });
      }

      const sarif: SarifLog = {
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'codex-security' } }, results }],
      };

      const scanResult = await adapter.scan(
        {
          target_type: 'SOURCE_CODE',
          target_url_or_path: 'src/',
          metadata: { sarif },
        },
        { max_cost_usd: 1.20 }
      );

      assert.equal(scanResult.status, 'partial');
      assert.equal(scanResult.is_partial, true);
      assert.equal(scanResult.findings.length, 2);
      assert.equal(scanResult.cost_usd, 1.00);
      assert(scanResult.warnings !== undefined && scanResult.warnings.length > 0);
      assert.match(scanResult.warnings[0], /Spending ceiling reached/);
      assert.match(scanResult.warnings[0], /exceeds configured ceiling of \$1\.20/);
    });

    it('Spending Ceiling: Zero budget ($0.00) halts immediately before processing any finding', async () => {
      const sarif: SarifLog = {
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'codex-security' } },
            results: [
              {
                ruleId: 'rule-cost-check',
                level: 'error',
                message: { text: 'Expensive finding' },
                properties: { costUsd: 0.05 },
              },
            ],
          },
        ],
      };

      const scanResult = await adapter.scan(
        {
          target_type: 'SOURCE_CODE',
          target_url_or_path: 'src/',
          metadata: { sarif },
        },
        { max_cost_usd: 0.0 }
      );

      assert.equal(scanResult.status, 'partial');
      assert.equal(scanResult.is_partial, true);
      assert.equal(scanResult.findings.length, 0);
      assert.equal(scanResult.cost_usd, 0);
    });

    it('Malformed SARIF Logs: Handles missing runs, missing results, null properties, and missing location objects', async () => {
      // 1. SARIF with no runs
      const noRuns = await adapter.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'src/',
        metadata: { sarif: { version: '2.1.0' } as any },
      });
      assert.equal(noRuns.status, 'success');
      assert.equal(noRuns.findings.length, 0);

      // 2. SARIF with runs having undefined results
      const emptyResults = await adapter.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'src/',
        metadata: {
          sarif: {
            version: '2.1.0',
            runs: [{ tool: { driver: { name: 'codex-sec' } } }],
          } as any,
        },
      });
      assert.equal(emptyResults.status, 'success');
      assert.equal(emptyResults.findings.length, 0);

      // 3. SARIF with result missing locations completely
      const missingLocations = await adapter.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'src/',
        metadata: {
          sarif: {
            version: '2.1.0',
            runs: [
              {
                tool: { driver: { name: 'codex-sec' } },
                results: [
                  {
                    ruleId: 'CWE-89-sqli',
                    level: 'error',
                    message: { text: 'SQL Injection detected' },
                  },
                ],
              },
            ],
          },
        },
      });
      assert.equal(missingLocations.status, 'success');
      assert.equal(missingLocations.findings.length, 1);
      assert.equal(missingLocations.findings[0].location.file_path, 'src/index.ts');
      assert.equal(missingLocations.findings[0].location.start_line, 1);
    });

    it('Malformed SARIF Logs: Missing message key triggers isolated status: error', async () => {
      const missingMessage = await adapter.scan({
        target_type: 'SOURCE_CODE',
        target_url_or_path: 'src/',
        metadata: {
          sarif: {
            version: '2.1.0',
            runs: [
              {
                tool: { driver: { name: 'codex-sec' } },
                results: [
                  {
                    ruleId: 'CWE-89-sqli',
                    level: 'error',
                    // message is undefined
                  } as any,
                ],
              },
            ],
          },
        },
      });
      assert.equal(missingMessage.status, 'error');
      assert.equal(missingMessage.findings.length, 0);
      assert(missingMessage.errors !== undefined);
      assert.match(missingMessage.errors[0], /Cannot read properties of undefined \(reading 'text'\)/);
    });

    it('Reachability Score Edge Cases: Handles unknown strings, partial token matches, and extreme inputs', () => {
      const threatModel = {
        entry_points: ['api/routes', 'controllers/auth.ts'],
        sanitizers: ['sanitizeInput', 'validator.escape'],
        sensitive_sinks: ['db.query', 'eval'],
        trust_boundaries: ['dmz'],
      };

      assert.equal(scoreReachabilityConfidence('file.ts', undefined, threatModel, 'REACHABLE').confidence, 'CERTAIN');
      assert.equal(scoreReachabilityConfidence('file.ts', undefined, threatModel, 'CONDITIONALLY_REACHABLE').confidence, 'FIRM');
      assert.equal(scoreReachabilityConfidence('file.ts', undefined, threatModel, 'UNREACHABLE').confidence, 'TENTATIVE');

      const fallbackEntryNoSanitizer = scoreReachabilityConfidence('api/routes/users.ts', 'getUser', threatModel, undefined);
      assert.equal(fallbackEntryNoSanitizer.confidence, 'CERTAIN');

      const fallbackEntryWithSanitizer = scoreReachabilityConfidence('api/routes/users.ts', 'sanitizeInput', threatModel, undefined);
      assert.equal(fallbackEntryWithSanitizer.confidence, 'FIRM');

      const fallbackInternal = scoreReachabilityConfidence('internal/worker.ts', 'job', threatModel, undefined);
      assert.equal(fallbackInternal.confidence, 'TENTATIVE');
    });

    it('CWE & OWASP Extraction: Handles missing rules, malformed tags, and regex fallback extraction', () => {
      assert.equal(extractCweId(undefined), 'CWE-79');
      assert.equal(extractCweId({ id: 'custom-check-cwe-89-injection' }), 'CWE-89');
      assert.equal(extractCweId({ id: 'no-cwe-here' }), 'CWE-79');

      assert.equal(extractOwaspCategory(undefined, 'CWE-89'), 'A03:2021-Injection');
      assert.equal(extractOwaspCategory(undefined, 'CWE-284'), 'A01:2021-Broken Access Control');
      assert.equal(extractOwaspCategory(undefined, 'CWE-326'), 'A02:2021-Cryptographic Failures');
      assert.equal(extractOwaspCategory(undefined, 'UNKNOWN-CWE'), 'A03:2021-Injection');
    });
  });

  // ==========================================================================
  // SECTION 3: CLOUDFLARE SECURITY CENTER ADAPTER ADVERSARIAL CHALLENGES
  // ==========================================================================
  describe('CloudflareSecurityCenterAdapter: Adversarial Stress & Telemetry Validation', () => {
    const adapter = new CloudflareSecurityCenterAdapter();

    it('HTTP 403 API Errors: Revoked tokens or explicit auth failures cleanly return status: error without leaking tokens', async () => {
      const authFail = await adapter.scan({
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'enterprise.zone',
        metadata: {
          simulate_auth_failure: true,
          auth_token: 'CF_TOKEN=c39184719283719283719283719283',
        },
      });

      assert.equal(authFail.status, 'error');
      assert.equal(authFail.findings.length, 0);
      assert(authFail.errors !== undefined);
      assert.match(authFail.errors[0], /403 Forbidden/);
      assert(!authFail.errors[0].includes('c39184719283719283719283719283'));

      const revokedFail = await adapter.scan({
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'enterprise.zone',
        metadata: {
          auth_token: 'invalid_revoked_token',
        },
      });
      assert.equal(revokedFail.status, 'error');
      assert.match(revokedFail.errors![0], /Token revoked/);
    });

    it('Edge Event Injection Score Boundaries: Exact 0.8 boundary discrimination', async () => {
      const mockFinding: SecurityFinding = {
        finding_id: 'SK-CF-INJECT-01',
        source_engine: 'cloudflare_security_center',
        title: 'Prompt Injection on Cloudflare AI Gateway',
        description: 'Adversarial jailbreak payload detected',
        cwe_id: 'CWE-20',
        owasp_category: 'LLM01:2025-Prompt-Injection',
        severity: 'CRITICAL',
        confidence: 'CERTAIN',
        target_type: 'API_ENDPOINT',
        target: 'gateway.ai.cloudflare.com',
        location: { file_path: 'openapi/schema.json', start_line: 1, end_line: 1 },
        fingerprint: '3'.repeat(64),
        commit_hash: '3333444455556666777788889999000011112222',
        discovered_at: new Date().toISOString(),
      };

      // Boundary Test A: injection_score = 0.800 (boundary pass -> VERIFIED_TRUE_POSITIVE)
      const exactScore = await adapter.reproduce(mockFinding, {
        custom_config: {
          edge_action: 'allow',
          injection_score: 0.80,
        },
      });
      assert.equal(exactScore.status, 'success');
      assert.equal(exactScore.reproduction_verified, true);
      assert.equal(exactScore.evidence?.status, 'VERIFIED_TRUE_POSITIVE');

      // Boundary Test B: injection_score = 0.799 (boundary fail -> REFUTED_FALSE_POSITIVE)
      const belowScore = await adapter.reproduce(mockFinding, {
        custom_config: {
          edge_action: 'allow',
          injection_score: 0.799,
        },
      });
      assert.equal(belowScore.status, 'success');
      assert.equal(belowScore.reproduction_verified, false);
      assert.equal(belowScore.evidence?.status, 'REFUTED_FALSE_POSITIVE');

      // Boundary Test C: Action = 'block' takes precedence even if injection_score is low
      const blockAction = await adapter.reproduce(mockFinding, {
        custom_config: {
          edge_action: 'block',
          injection_score: 0.10,
        },
      });
      assert.equal(blockAction.status, 'success');
      assert.equal(blockAction.reproduction_verified, true);
      assert.equal(blockAction.evidence?.status, 'VERIFIED_TRUE_POSITIVE');
    });

    it('Malformed Telemetry Records: Ingests attack surface management insights with missing or extreme fields', async () => {
      const insights: CloudflareInsight[] = [
        {
          id: 'cf-exposed-port',
          type: 'exposed_origin_port',
          severity: 'moderate',
          title: 'Direct SSH port 22 exposed on origin IP',
          description: 'Bypasses Cloudflare proxy',
          hostname: 'origin.example.com',
        },
        {
          id: 'cf-missing-hsts',
          type: 'missing_hsts' as any,
          severity: 'low',
          title: 'HSTS header missing',
          description: 'Domain does not enforce HTTPS via HSTS preload',
          hostname: 'example.com',
        },
      ];

      const scanResult = await adapter.scan({
        target_type: 'CLOUD_RESOURCE',
        target_url_or_path: 'example.com',
        metadata: { insights },
      });

      assert.equal(scanResult.status, 'success');
      assert.equal(scanResult.findings.length, 2);
      for (const finding of scanResult.findings) {
        const validation = validateFinding(finding);
        assert.equal(validation.success, true);
      }
    });
  });

  // ==========================================================================
  // SECTION 4: QUALITY ENGINE ADAPTER ADVERSARIAL CHALLENGES
  // ==========================================================================
  describe('QualityEngineAdapter: Deterministic Boundary, Version Tampering & Directory Traversal', () => {
    const adapter = new QualityEngineAdapter();

    it('Policy Version Tampering: Rejects all non-1 versions (string "1", 2, 0, -1, float 1.5, null, boolean)', () => {
      const invalidVersions = [
        '1',              // string '1'
        2,                // version 2
        0,                // version 0
        -1,               // negative version
        1.5,              // floating point
        null,             // null
        undefined,        // undefined
        true,             // boolean true
        false,            // boolean false
        {},               // object
        [],               // array
      ];

      for (const badVersion of invalidVersions) {
        assert.throws(
          () => parseSecurityPackPolicy({ version: badVersion }),
          /expected supported version 1/,
          `Failed to reject tampered policy version: ${String(badVersion)}`
        );
      }
    });

    it('Policy Key Tampering: Rejects unauthorized root keys attempting policy bypass or configuration injection', () => {
      const unauthorizedPolicies = [
        { version: 1, bypass_all: true },
        { version: 1, allow_unverified: true },
        { version: 1, ignore_cwe: ['CWE-89'] },
        { version: 1, admin_override: 'enable' },
      ];

      for (const policy of unauthorizedPolicies) {
        assert.throws(
          () => parseSecurityPackPolicy(policy),
          /unrecognized root key/,
          `Failed to reject policy with unauthorized root key: ${JSON.stringify(policy)}`
        );
      }
    });

    it('Expired Policy Exceptions: Immediate rejection of expired exceptions (yesterday vs today)', () => {
      const today = '2026-11-06';
      const yesterday = '2026-11-05';
      const tomorrow = '2026-11-07';

      // 1. Expired exception (yesterday) MUST throw
      assert.throws(
        () => parseSecurityPackPolicy({
          version: 1,
          exceptions: [
            {
              ruleId: 'SEC-SQLI',
              fingerprint: '0'.repeat(64),
              reason: 'Legacy API exception',
              expires: yesterday,
            },
          ],
        }, today),
        /expired on 2026-11-05/
      );

      // 2. Exception expiring today (boundary condition: valid until day ends)
      assert.doesNotThrow(() => {
        parseSecurityPackPolicy({
          version: 1,
          exceptions: [
            {
              ruleId: 'SEC-SQLI',
              fingerprint: '0'.repeat(64),
              reason: 'Expiring today',
              expires: today,
            },
          ],
        }, today);
      });

      // 3. Exception expiring tomorrow (valid future date)
      assert.doesNotThrow(() => {
        parseSecurityPackPolicy({
          version: 1,
          exceptions: [
            {
              ruleId: 'SEC-SQLI',
              fingerprint: '0'.repeat(64),
              reason: 'Valid future exception',
              expires: tomorrow,
            },
          ],
        }, today);
      });

      // 4. Invalid date format must throw
      assert.throws(
        () => parseSecurityPackPolicy({
          version: 1,
          exceptions: [
            {
              ruleId: 'SEC-SQLI',
              fingerprint: '0'.repeat(64),
              reason: 'Bad date format',
              expires: '06-11-2026',
            },
          ],
        }, today),
        /invalid expires date format/
      );
    });

    it('evaluateQuadState: Expired exceptions in evaluateQuadState trigger deterministic state: error', () => {
      const expiredPolicy = {
        version: 1,
        exceptions: [
          {
            ruleId: 'SEC-TEST',
            fingerprint: 'f'.repeat(64),
            reason: 'Old test exemption',
            expires: '2025-01-01',
          },
        ],
      };

      const result = adapter.evaluateQuadState({
        policy: expiredPolicy,
        findings: [],
        todayUtc: '2026-11-06',
      });

      assert.equal(result.state, 'error');
      assert.equal(result.errors.length, 1);
      assert.match(result.errors[0], /Policy parsing failure: Exception for rule 'SEC-TEST' expired/);
    });

    it('Directory Traversal in Exceptions: ruleId, fingerprint, and reason injection rejection', () => {
      const today = '2026-11-06';

      // Traversal attempt 1: ruleId containing ../
      assert.throws(
        () => parseSecurityPackPolicy({
          version: 1,
          exceptions: [
            {
              ruleId: '../../etc/passwd',
              fingerprint: 'a'.repeat(64),
              reason: 'Traversal in ruleId',
              expires: '2030-01-01',
            },
          ],
        }, today),
        /invalid ruleId/
      );

      // Traversal attempt 2: ruleId containing Windows backslash traversal
      assert.throws(
        () => parseSecurityPackPolicy({
          version: 1,
          exceptions: [
            {
              ruleId: '..\\..\\windows\\system32',
              fingerprint: 'a'.repeat(64),
              reason: 'Backslash traversal in ruleId',
              expires: '2030-01-01',
            },
          ],
        }, today),
        /invalid ruleId/
      );

      // Tampering attempt 3: Invalid fingerprint length or non-hex
      assert.throws(
        () => parseSecurityPackPolicy({
          version: 1,
          exceptions: [
            {
              ruleId: 'VALID-RULE',
              fingerprint: 'NOT-A-VALID-HEX-STRING'.padEnd(64, '0'),
              reason: 'Invalid hex in fingerprint',
              expires: '2030-01-01',
            },
          ],
        }, today),
        /invalid fingerprint/
      );
    });

    it('Directory Traversal in Patch Recheck: Rejects patches modifying files outside repo boundaries', async () => {
      const traversalPatches: string[][] = [
        ['../../etc/passwd'],
        ['../sensitive/config.env'],
        ['/etc/shadow'],
        ['\\Windows\\System32\\cmd.exe'],
        ['src/safe.ts', '../../database/credentials.json'],
      ];

      for (const affected_files of traversalPatches) {
        const patch: PatchProposal = {
          patch_id: 'SK-PATCH-TRAVERSAL',
          finding_id: 'SK-FIND-01',
          author_engine: 'adversary',
          diff_content: 'diff content',
          affected_files,
          base_commit: '1234567890123456789012345678901234567890',
          patch_sha256: 'a'.repeat(64),
          recheck_status: 'untested',
          recheck_evidence_id: null,
          blast_radius: {
            files_modified: affected_files.length,
            lines_added: 1,
            lines_deleted: 1,
            ast_impact_scope: 'PUBLIC_API',
            downstream_dependents: [],
            breaking_change_risk: 'HIGH',
          },
          rollback_plan: { revert_patch: 'reverse' },
          created_at: new Date().toISOString(),
        };

        const recheckResult = await adapter.recheck(patch);
        assert.equal(recheckResult.status, 'error');
        assert.equal(recheckResult.recheck_status, 'regression_detected');
        assert.equal(recheckResult.tests_passed, false);
        assert.match(recheckResult.error!, /Boundary check failed/);
      }
    });

    it('Bounded Resource Limits: Rejects payloads exceeding maxFileBytes, maxFiles, and maxTotalBytes', () => {
      // 1. maxFiles exceeded
      const maxFilesResult = adapter.evaluateQuadState({
        policy: {
          version: 1,
          limits: { maxFiles: 50 },
        },
        findings: [],
        totalFiles: 51,
      });
      assert.equal(maxFilesResult.state, 'error');
      assert.match(maxFilesResult.errors[0], /File count limit exceeded: 51 files exceeds maxFiles limit of 50/);

      // 2. maxTotalBytes exceeded
      const maxBytesResult = adapter.evaluateQuadState({
        policy: {
          version: 1,
          limits: { maxTotalBytes: 1024 * 1024 }, // 1 MiB
        },
        findings: [],
        totalBytes: 2 * 1024 * 1024, // 2 MiB
      });
      assert.equal(maxBytesResult.state, 'error');
      assert.match(maxBytesResult.errors[0], /Total size limit exceeded/);

      // 3. Negative limits rejected during policy parsing
      assert.throws(
        () => parseSecurityPackPolicy({
          version: 1,
          limits: { maxFiles: -5 },
        }),
        /limits\.maxFiles must be a positive number/
      );
    });
  });
});
