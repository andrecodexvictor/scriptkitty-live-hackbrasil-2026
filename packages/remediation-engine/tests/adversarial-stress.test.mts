/**
 * @file packages/remediation-engine/tests/adversarial-stress.test.mts
 * @description Consolidated adversarial stress & deep verification suite for
 * @script-kitty/remediation-engine (ProcessSandbox/OfflineLocalSandbox, Patcher diff geometry,
 * blast radius calculation, zero-hunk rejection, 0-byte creation/deletion symmetry,
 * template hardening, and bit-for-bit rollback triggers in isolated temp dirs).
 */

import { describe, it, afterEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {
  ProcessSandbox,
  OfflineLocalSandbox,
  calculateBlastRadius,
  applyUnifiedDiff,
  generateUnifiedDiff,
  generateReverseDiff,
  synthesizePatchProposal,
  Patcher,
  FileSnapshotManager,
  RollbackEngine,
  LabAppRemediationTemplates,
  VerificationStatus,
  type SecurityFinding,
} from '../dist/index.js';

function assertDiffSymmetry(
  orig: string,
  patched: string,
  filePath = 'src/geometry.ts',
  contextLines = 3
): void {
  const normOrig = orig.replace(/\r\n/g, '\n');
  const normPatched = patched.replace(/\r\n/g, '\n');

  const fwdDiff = generateUnifiedDiff(filePath, orig, patched, contextLines);
  const revDiff = generateReverseDiff(filePath, orig, patched, contextLines);

  const normPath = filePath.replace(/\\/g, '/');
  assert.ok(fwdDiff.includes(`--- a/${normPath}`), 'Forward diff missing --- a/ header');
  assert.ok(fwdDiff.includes(`+++ b/${normPath}`), 'Forward diff missing +++ b/ header');
  assert.ok(revDiff.includes(`--- b/${normPath}`), 'Reverse diff missing --- b/ header');
  assert.ok(revDiff.includes(`+++ a/${normPath}`), 'Reverse diff missing +++ a/ header');

  const applyFwd = applyUnifiedDiff(normOrig, fwdDiff);
  assert.equal(applyFwd.success, true, `Forward diff application failed: ${applyFwd.error}`);
  assert.equal(applyFwd.patchedContent, normPatched, 'Forward diff content mismatch');

  const applyRev = applyUnifiedDiff(applyFwd.patchedContent!, revDiff);
  assert.equal(applyRev.success, true, `Reverse diff application failed: ${applyRev.error}`);
  assert.equal(applyRev.patchedContent, normOrig, 'Mathematical asymmetry on reverse diff');
}

describe('Remediation Engine Adversarial Stress Suite', () => {
  const createdDirs: string[] = [];

  function makeTempFile(filename: string, content: string): { dir: string; filePath: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sk-remed-stress-'));
    createdDirs.push(dir);
    const filePath = path.join(dir, filename);
    fs.writeFileSync(filePath, content, 'utf8');
    return { dir, filePath };
  }

  afterEach(() => {
    while (createdDirs.length > 0) {
      const dir = createdDirs.pop()!;
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors on Windows handles
      }
    }
  });

  // =========================================================================
  // 1. SANDBOX ENVIRONMENT ISOLATION, PROXY STRIPPING & CLAMPING
  // =========================================================================
  describe('ProcessSandbox Isolation & Limits', () => {
    const sandbox = new ProcessSandbox(5000);

    it('strips case-insensitive HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, FTP_PROXY, CURL_PROXY permutations', async () => {
      const permutations: Record<string, string> = {
        Http_Proxy: 'http://proxy-1:8080',
        HTTP_proxy: 'http://proxy-2:8080',
        hTTp_pROXy: 'http://proxy-3:8080',
        http_proxy: 'http://proxy-4:8080',
        HTTPS_PROXY: 'https://proxy-5:8443',
        Https_Proxy: 'https://proxy-6:8443',
        hTTps_pROXy: 'https://proxy-7:8443',
        All_Proxy: 'socks5://proxy-8:1080',
        aLL_pROXy: 'socks5://proxy-9:1080',
        Ftp_Proxy: 'ftp://proxy-10:2121',
        FTP_proxy: 'ftp://proxy-11:2121',
        Curl_Proxy: 'http://proxy-12:8080',
        CURL_PROXY: 'http://proxy-13:8080',
      };

      const res = await sandbox.execute({
        command: 'node',
        args: ['-e', 'console.log(JSON.stringify(process.env))'],
        env: {
          ...permutations,
          SAFE_CONFIG_VAR: 'custom-config-value',
          TARGET_PORT: '9000',
          NO_PROXY: 'localhost,127.0.0.1',
          SCRIPTKITTY_OFFLINE: '0',
        },
        isolated_network: true,
      });

      assert.equal(res.exit_code, 0);
      const env = JSON.parse(res.stdout) as Record<string, string>;
      for (const key of Object.keys(permutations)) {
        assert.equal(key in env, false, `Leaked proxy key: ${key}`);
      }
      assert.equal(env.NO_PROXY, '*');
      assert.equal(env.SCRIPTKITTY_OFFLINE, '1');
      assert.equal(env.SAFE_CONFIG_VAR, 'custom-config-value');
      assert.equal(env.TARGET_PORT, '9000');
    });

    it('prevents host process secrets from leaking into isolated sandbox', async () => {
      process.env.SCRIPTKITTY_HOST_SECRET_API_KEY = 'super-secret-token-do-not-leak';
      process.env.AWS_SECRET_ACCESS_KEY = 'aws-secret-key-12345';
      try {
        const res = await sandbox.execute({
          command: 'node',
          args: ['-e', 'console.log(JSON.stringify(process.env))'],
          isolated_network: true,
        });
        assert.equal(res.exit_code, 0);
        const env = JSON.parse(res.stdout) as Record<string, string>;
        assert.equal('SCRIPTKITTY_HOST_SECRET_API_KEY' in env, false);
        assert.equal('AWS_SECRET_ACCESS_KEY' in env, false);
        assert.equal(env.NODE_ENV, 'test');
      } finally {
        delete process.env.SCRIPTKITTY_HOST_SECRET_API_KEY;
        delete process.env.AWS_SECRET_ACCESS_KEY;
      }
    });

    it('preserves proxy env vars only when isolated_network is explicitly false', async () => {
      const res = await sandbox.execute({
        command: 'node',
        args: ['-e', 'console.log(JSON.stringify(process.env))'],
        env: { Http_Proxy: 'http://allowed-proxy:8080' },
        isolated_network: false,
      });
      assert.equal(res.exit_code, 0);
      const env = JSON.parse(res.stdout) as Record<string, string>;
      assert.equal(env.Http_Proxy, 'http://allowed-proxy:8080');
    });

    it('clamps stdout at 1MB to prevent memory exhaustion', async () => {
      const res = await sandbox.execute({
        command: 'node',
        args: ['-e', 'for (let i = 0; i < 3000; i++) { process.stdout.write("A".repeat(1024)); }'],
      });
      assert.equal(res.exit_code, 0);
      assert.ok(res.stdout.length <= 1024 * 1024 + 1024);
    });

    it('halts busy-loop timeouts promptly and distinguishes oracle evidence statuses', async () => {
      const sb = new OfflineLocalSandbox(5000);
      const res = await sb.execute({
        command: 'node',
        args: ['-e', 'while (true) {}'],
        timeout_ms: 400,
      });
      assert.equal(res.timed_out, true);
      assert.ok(res.exit_code === 124 || res.exit_code === -1);

      const evCrash = sb.createEvidence({
        findingId: 'SK-FIND-ORACLE',
        runResult: {
          exitCode: 2,
          stdout: '',
          stderr: 'SyntaxError',
          durationMs: 50,
          scriptPath: 'repro.mts',
          scriptSha256: '0'.repeat(64),
          timedOut: false,
        },
        verifierAgentId: 'agent-verifier',
      });
      assert.equal(evCrash.status, VerificationStatus.EXECUTION_ERROR);
    });
  });

  // =========================================================================
  // 2. BLAST RADIUS CALCULATION ON ++ / -- CODE LINES & HEADERS
  // =========================================================================
  describe('Blast Radius Header & Operator Accuracy', () => {
    it('ignores --- a/, +++ b/, and /dev/null headers while counting ++ and -- code lines', () => {
      const createDiff = [
        '--- /dev/null',
        '+++ b/new-file.ts',
        '@@ -0,0 +1,2 @@',
        '+const a = 1;',
        '+const b = 2;',
      ].join('\n');
      const createBlast = calculateBlastRadius(createDiff);
      assert.equal(createBlast.lines_added, 2);
      assert.equal(createBlast.lines_deleted, 0);

      const mixedDiff = [
        '--- a/src/app.ts',
        '+++ b/src/app.ts',
        '@@ -10,6 +10,6 @@',
        ' const isReady = true;',
        '-for (let i = 0; i < 10; --i) {',
        '-----retryCount;',
        '--- // divider comment',
        '+for (let i = 0; i < 10; ++i) {',
        '++++retryCount;',
        '+++ // divider comment',
        ' }',
      ].join('\n');
      const mixedBlast = calculateBlastRadius(mixedDiff, {
        astImpactScope: 'INTERNAL_MODULE',
        breakingChangeRisk: 'LOW',
      });
      assert.equal(mixedBlast.lines_added, 3);
      assert.equal(mixedBlast.lines_deleted, 3);
      assert.equal(mixedBlast.ast_impact_scope, 'INTERNAL_MODULE');
    });
  });

  // =========================================================================
  // 3. ZERO-HUNK REJECTION & DIFF MATHEMATICAL SYMMETRY
  // =========================================================================
  describe('Unified Diff Zero-Hunk Rejection & Symmetry', () => {
    it('rejects empty string, garbage text, headers-only diff, corrupted hunk, and context mismatch', () => {
      assert.equal(applyUnifiedDiff('const x = 1;', '').success, false);
      assert.equal(applyUnifiedDiff('const x = 1;', 'NOT A VALID DIFF \x00\x01').success, false);
      assert.equal(applyUnifiedDiff('const x = 1;', '--- a/file.ts\n+++ b/file.ts\n').success, false);
      assert.equal(
        applyUnifiedDiff('line 1\nline 2\n', '--- a/f.ts\n+++ b/f.ts\n@@ -invalid @@\n-line 1\n+x\n').success,
        false
      );
      const mismatched = applyUnifiedDiff(
        'const x = 10;\nconst y = 20;\n',
        '--- a/f.ts\n+++ b/f.ts\n@@ -1,2 +1,2 @@\n missing context\n-const y = 20;\n+const y = 99;\n'
      );
      assert.equal(mismatched.success, false);
      assert.ok(mismatched.error?.includes('hunk context lines did not match'));
    });

    it('preserves strict 0-byte symmetry for empty file creation and complete file deletion', () => {
      assertDiffSymmetry('', 'console.log("hello world");\nexport const ready = true;\n', 'new-file.ts');
      assertDiffSymmetry('line 1\nline 2\nline 3\n', '', 'deleted-file.ts');

      // Single-line without trailing newline deletion -> strict SHA-256 of ""
      const orig = 'single line of code';
      const fwd = generateUnifiedDiff('single.ts', orig, '');
      const rev = generateReverseDiff('single.ts', orig, '');
      const fwdRes = applyUnifiedDiff(orig, fwd);
      assert.equal(fwdRes.success, true);
      assert.equal(fwdRes.patchedContent, '');
      assert.equal(
        crypto.createHash('sha256').update(fwdRes.patchedContent!, 'utf8').digest('hex'),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
      const revRes = applyUnifiedDiff(fwdRes.patchedContent!, rev);
      assert.equal(revRes.success, true);
      assert.equal(revRes.patchedContent, orig);
    });

    it('verifies diff symmetry across multi-hunk, CRLF, regex/diff-header strings, unicode, context=0/10, and 500-line files', () => {
      assertDiffSymmetry('export const A = 1;\n', '// prepended\nexport const A = 1;\n', 'src/prepend.ts');
      assertDiffSymmetry('// banner\nexport const A = 1;\n', 'export const A = 1;\n', 'src/del-first.ts');
      assertDiffSymmetry('function test() {\r\n  return 1;\r\n}\r\n', 'function test() {\r\n  return 2;\r\n}\r\n', 'src/crlf.ts');
      assertDiffSymmetry('line 1\nline 2\nline 3\nline 4\nline 5\n', 'line 1\nline 2\nMOD 3\nline 4\nline 5\n', 'src/ctx0.ts', 0);

      const largeOrig = Array.from({ length: 500 }, (_, i) => `export const val_${i} = ${i};`);
      const largePatched = [...largeOrig];
      largePatched[10] = 'export const val_10 = 99999;';
      largePatched[250] = 'export const val_250 = 88888;';
      largePatched[490] = 'export const val_490 = 77777;';
      assertDiffSymmetry(largeOrig.join('\n') + '\n', largePatched.join('\n') + '\n', 'src/large.ts', 10);

      const metaOrig = [
        'export const header = "@@ -1,5 +1,5 @@";',
        'export const prefix = "--- a/file.ts";',
        'export const add = "+++ b/file.ts";',
        'const rawSql = `SELECT * FROM tbl WHERE id = \'${query}\'`;',
        'export const emoji = "café 🔒";',
      ].join('\n') + '\n';
      const metaPatched = [
        'export const header = "@@ -1,5 +1,5 @@";',
        'export const prefix = "--- a/file.ts";',
        'export const add = "+++ b/file.ts";',
        'const rawSql = `SELECT * FROM tbl WHERE id = ?`;',
        'export const emoji = "café 🛡️";',
      ].join('\n') + '\n';
      assertDiffSymmetry(metaOrig, metaPatched, 'src/meta.ts');

      // Reverse diff must fail safely when applied to already-original content
      const revOnly = generateReverseDiff('src/test.ts', 'const a = 1;\n', 'const a = 2;\n');
      assert.equal(applyUnifiedDiff('const a = 1;\n', revOnly).success, false);
    });
  });

  // =========================================================================
  // 4. REVERSE-DIFF ROLLBACK & TEMPLATE VALIDATION (ISOLATED TEMP FILES)
  // =========================================================================
  describe('Reverse-Diff Rollback Strategy & Template Hardening', () => {
    it('restores bit-for-bit pristine file via Strategy 2 REVERSE_DIFF when snapshot manager is omitted', async () => {
      const originalCode =
        'export function executeQuery(db: any, userInput: string): any {\n' +
        '  const query = `SELECT * FROM users WHERE username = \'${userInput}\'`;\n' +
        '  return db.query(query);\n' +
        '}\n';
      const originalHash = crypto.createHash('sha256').update(originalCode, 'utf8').digest('hex');
      const { dir, filePath } = makeTempFile('target.ts', originalCode);

      const finding: SecurityFinding = {
        finding_id: 'SK-FIND-STRESS-ROLLBACK-001',
        source_engine: 'mantis',
        title: 'SQL Injection',
        description: 'Rollback stress test',
        cwe_id: 'CWE-89',
        owasp_category: 'A03:2021-Injection',
        severity: 'CRITICAL',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: filePath,
        location: { file_path: filePath, start_line: 1, end_line: 4 },
        fingerprint: 'a'.repeat(64),
        commit_hash: '1'.repeat(40),
        discovered_at: new Date().toISOString(),
        raw_metadata: {},
      };

      const patchedCode = originalCode.replace(
        'const query = `SELECT * FROM users WHERE username = \'${userInput}\'`;\n  return db.query(query);',
        'const query = \'SELECT * FROM users WHERE username = ?\';\n  return db.query(query, [userInput]);'
      );

      const patch = synthesizePatchProposal(finding, originalCode, patchedCode, filePath);
      fs.writeFileSync(filePath, patchedCode, 'utf8');

      const engine = new RollbackEngine(dir);
      const record = await engine.executeRollback(
        patch,
        'GATE_REJECTED',
        'Testing fallback Strategy 2 REVERSE_DIFF',
        undefined
      );

      assert.equal(record.success, true);
      assert.equal(record.reverted_via, 'REVERSE_DIFF');
      const restored = fs.readFileSync(filePath, 'utf8');
      assert.equal(crypto.createHash('sha256').update(restored, 'utf8').digest('hex'), originalHash);
      assert.equal(restored, originalCode);
    });

    it('rejects malformed/already-patched template inputs and unsupported CWEs cleanly', () => {
      assert.throws(() => LabAppRemediationTemplates.fixSqlInjection(''), /not found/);
      assert.throws(() => LabAppRemediationTemplates.fixCommandInjection(''), /not found/);
      assert.throws(() => LabAppRemediationTemplates.fixBrokenAccessControl(''), /not found/);

      const { dir } = makeTempFile('search.ts', 'export const ok = true;\n');
      const patcher = new Patcher({ workspaceRoot: dir });
      const unsupportedFinding: SecurityFinding = {
        finding_id: 'SK-FIND-UNSUPPORTED-CWE',
        source_engine: 'mantis',
        title: 'XSS in Frontend',
        description: 'Unsupported vulnerability',
        cwe_id: 'CWE-79',
        owasp_category: 'A03:2021-Injection',
        severity: 'MEDIUM',
        confidence: 'CERTAIN',
        target_type: 'SOURCE_CODE',
        target: 'search.ts',
        location: { file_path: 'search.ts', start_line: 1, end_line: 5 },
        fingerprint: 'e'.repeat(64),
        commit_hash: 'f'.repeat(40),
        discovered_at: new Date().toISOString(),
        raw_metadata: {},
      };
      assert.throws(() => patcher.synthesizePatch(unsupportedFinding), /No deterministic remediation template available/);

      const missingFileFinding: SecurityFinding = {
        ...unsupportedFinding,
        finding_id: 'SK-FIND-MISSING-FILE',
        cwe_id: 'CWE-89',
        target: 'non-existent-route.ts',
        location: { file_path: 'non-existent-route.ts', start_line: 1, end_line: 5 },
      };
      assert.throws(() => patcher.synthesizePatch(missingFileFinding), /Target file not found/);
    });
  });
});
