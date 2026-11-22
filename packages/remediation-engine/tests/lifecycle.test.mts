/**
 * @file packages/remediation-engine/tests/lifecycle.test.mts
 * @description Comprehensive 5-stage remediation lifecycle integration test suite:
 * "Find it. Prove it. Fix it. Verify it. Learn from it."
 *
 * Verifies end-to-end autonomous remediation against the synthetic vulnerable lab application
 * across all 3 AppSec vulnerabilities:
 * 1. SQL Injection (CWE-89) in apps/lab-app/src/routes/search.ts
 * 2. OS Command Injection (CWE-78) in apps/lab-app/src/routes/diagnostics.ts
 * 3. Broken Access Control / IDOR (CWE-639) in apps/lab-app/src/routes/reports.ts
 *
 * Also verifies negative lifecycles:
 * 4. Invalid finding rejected at FIND stage
 * 5. Non-exploitable finding rejected at PROVE stage
 * 6. Gate rejection and automated rollback on SoD violation at LEARN stage
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import {
  AutonomousRemediationEngine,
  Patcher,
  type SecurityFinding,
  GateVerdict,
} from '../dist/index.js';
import { verifyChainOfCustody } from '@script-kitty/contracts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('Autonomous Remediation Engine Lifecycle Integration Suite', { timeout: 180000 }, () => {
  const workspaceRoot = fs.existsSync(path.resolve(process.cwd(), 'apps', 'lab-app'))
    ? path.resolve(process.cwd())
    : path.resolve(__dirname, '../../..');

  const searchPath = path.resolve(workspaceRoot, 'apps', 'lab-app', 'src', 'routes', 'search.ts');
  const diagnosticsPath = path.resolve(workspaceRoot, 'apps', 'lab-app', 'src', 'routes', 'diagnostics.ts');
  const reportsPath = path.resolve(workspaceRoot, 'apps', 'lab-app', 'src', 'routes', 'reports.ts');

  const CANONICAL_SEARCH = `import type { DatabaseSync } from 'node:sqlite';\nimport '../types.js';\n\n/**\n * Searches incidents by keyword matching title or description.\n *\n * SECURITY VULNERABILITY (CWE-89 / OWASP A03:2021 - SQL Injection):\n * Direct string interpolation of the user-supplied query string into the raw SQL query\n * allows arbitrary SQL execution (e.g., UNION SELECT credential extraction or boolean bypass).\n */\nexport function searchIncidents(db: DatabaseSync, query: string): Record<string, any>[] {\n  // FLURRED / VULNERABLE: Direct string interpolation into raw SQL statement\n  const rawSql = \`SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE title LIKE '%\${query}%' OR description LIKE '%\${query}%'\`;\n  const stmt = db.prepare(rawSql);\n  return stmt.all();\n}\n`;

  const CANONICAL_DIAGNOSTICS = `import { execSync } from 'node:child_process';\nimport type { DatabaseSync } from 'node:sqlite';\nimport type { PingResult } from '../types.js';\n\nexport function runHostPing(targetHost: string, db?: DatabaseSync): PingResult {\n  const isWindows = process.platform === 'win32';\n  const pingCmd = isWindows ? \`ping -n 1 \${targetHost}\` : \`ping -c 1 \${targetHost}\`;\n\n  try {\n    const stdout = execSync(pingCmd, { encoding: 'utf8', timeout: 5000 });\n    if (db) {\n      try {\n        db.prepare('INSERT INTO diagnostic_logs (host, status, output, created_at) VALUES (?, ?, ?, ?)').run(\n          targetHost,\n          'SUCCESS',\n          stdout.slice(0, 500),\n          new Date().toISOString()\n        );\n      } catch {\n        // Non-fatal logging failure\n      }\n    }\n    return { status: 'SUCCESS', output: stdout };\n  } catch (err: any) {\n    const errorOutput = err.stdout ? String(err.stdout) : (err.message || String(err));\n    if (db) {\n      try {\n        db.prepare('INSERT INTO diagnostic_logs (host, status, output, created_at) VALUES (?, ?, ?, ?)').run(\n          targetHost,\n          'ERROR',\n          errorOutput.slice(0, 500),\n          new Date().toISOString()\n        );\n      } catch {\n        // Non-fatal logging failure\n      }\n    }\n    return { status: 'ERROR', output: errorOutput };\n  }\n}\n`;

  const CANONICAL_REPORTS = `import type { DatabaseSync } from 'node:sqlite';\nimport type { ReportResponse } from '../types.js';\n\n/**\n * Retrieves an incident report by ID.\n *\n * SECURITY VULNERABILITY (CWE-639 / OWASP A01:2021 - Broken Access Control / IDOR):\n * The endpoint verifies that the caller has an authenticated \`x-user-id\`, but retrieves\n * the requested report directly without verifying that \`report.owner_id === requester.id\`\n * or that \`requester.role === 'admin'\`.\n */\nexport function getReportById(\n  db: DatabaseSync,\n  reportId: number,\n  userIdHeader?: string | null\n): ReportResponse {\n  // Authentication: x-user-id header is required\n  if (!userIdHeader) {\n    return {\n      status: 401,\n      body: { error: 'Unauthorized: Missing x-user-id header' }\n    };\n  }\n\n  const userId = parseInt(userIdHeader, 10);\n  if (isNaN(userId)) {\n    return {\n      status: 401,\n      body: { error: 'Unauthorized: Invalid x-user-id header' }\n    };\n  }\n\n  const requester = db.prepare('SELECT id, username, role, email FROM users WHERE id = ?').get(userId);\n  if (!requester) {\n    return {\n      status: 401,\n      body: { error: 'Unauthorized: User not found' }\n    };\n  }\n\n  // FLURRED / VULNERABLE: Missing tenant authorization / access control check!\n  // Directly returns the report even if owned by another user and marked RESTRICTED.\n  const report = db.prepare(\n    'SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE id = ?'\n  ).get(reportId);\n\n  if (!report) {\n    return {\n      status: 404,\n      body: { error: 'Report not found' }\n    };\n  }\n\n  return {\n    status: 200,\n    body: report\n  };\n}\n`;

  let originalSearchContent: string = CANONICAL_SEARCH;
  let originalDiagnosticsContent: string = CANONICAL_DIAGNOSTICS;
  let originalReportsContent: string = CANONICAL_REPORTS;

  before(() => {
    originalSearchContent = CANONICAL_SEARCH;
    originalDiagnosticsContent = CANONICAL_DIAGNOSTICS;
    originalReportsContent = CANONICAL_REPORTS;
    restoreAllFiles();
  });

  const restoreAllFiles = () => {
    fs.writeFileSync(searchPath, originalSearchContent, 'utf8');
    fs.writeFileSync(diagnosticsPath, originalDiagnosticsContent, 'utf8');
    fs.writeFileSync(reportsPath, originalReportsContent, 'utf8');
    try {
      const tscPath = path.resolve(workspaceRoot, 'node_modules', 'typescript', 'bin', 'tsc');
      const tsconfigPath = path.resolve(workspaceRoot, 'apps', 'lab-app', 'tsconfig.json');
      if (fs.existsSync(tscPath) && fs.existsSync(tsconfigPath)) {
        execSync(`node "${tscPath}" -p "${tsconfigPath}"`, {
          cwd: workspaceRoot,
          stdio: 'pipe',
          encoding: 'utf8',
        });
      } else {
        execSync('npm run build --workspace=@script-kitty/lab-app', {
          cwd: workspaceRoot,
          stdio: 'pipe',
          encoding: 'utf8',
        });
      }
    } catch (err: any) {
      console.warn('Warning: restoreAllFiles compilation failed:', err?.message || err);
    }
  };

  afterEach(() => {
    restoreAllFiles();
  });

  after(() => {
    restoreAllFiles();
  });

  it('1. Patcher unit: synthesizes unified diff with standard headers and blast radius', () => {
    const patcher = new Patcher({ workspaceRoot, buildAfterPatch: false });
    const finding: SecurityFinding = {
      finding_id: 'SK-FINDING-SQLI-TEST',
      source_engine: 'mantis',
      title: 'SQL Injection in Search',
      description: 'SQLi in search endpoint',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021-Injection',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: 'apps/lab-app/src/routes/search.ts',
      location: {
        file_path: 'apps/lab-app/src/routes/search.ts',
        start_line: 11,
        end_line: 16,
      },
      fingerprint: '1'.repeat(64),
      commit_hash: '2'.repeat(40),
      discovered_at: new Date().toISOString(),
      raw_metadata: {},
    };

    const synthesis = patcher.synthesizePatch(finding);
    assert.ok(synthesis.patch);
    assert.match(synthesis.patch.patch_id, /^SK-PATCH-/);
    assert.match(synthesis.patch.patch_sha256, /^[0-9a-fA-F]{64}$/);
    assert.ok(synthesis.patch.diff_content.includes('--- a/apps/lab-app/src/routes/search.ts'));
    assert.ok(synthesis.patch.diff_content.includes('+++ b/apps/lab-app/src/routes/search.ts'));
    assert.ok(synthesis.patch.rollback_plan.revert_patch.includes('--- b/apps/lab-app/src/routes/search.ts'));
    assert.ok(synthesis.patch.rollback_plan.revert_patch.includes('+++ a/apps/lab-app/src/routes/search.ts'));
    assert.equal(synthesis.patch.blast_radius.files_modified, 1);
    assert.equal(synthesis.patch.blast_radius.ast_impact_scope, 'LOCAL_FUNCTION');
    assert.equal(synthesis.patch.blast_radius.breaking_change_risk, 'LOW');
  });

  it('2. E2E Remediation: Full 5-stage lifecycle on SQL Injection (CWE-89)', { timeout: 180000 }, async () => {
    const engine = new AutonomousRemediationEngine({
      workspaceRoot,
      discoveringAgentId: 'agent-scanner-mantis',
      verifyingAgentId: 'agent-sandbox-verifier',
      authorizingAgentId: 'agent-quality-gate-authority',
      buildAfterPatch: true,
    });

    const finding: SecurityFinding = {
      finding_id: 'SK-FINDING-LAB-SQLI-001',
      source_engine: 'mantis',
      title: 'SQL Injection in Incident Search Endpoint',
      description: 'Direct string interpolation of query allows arbitrary SQL execution.',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021-Injection',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: 'apps/lab-app/src/routes/search.ts',
      location: {
        file_path: 'apps/lab-app/src/routes/search.ts',
        start_line: 11,
        end_line: 16,
      },
      fingerprint: 'a'.repeat(64),
      commit_hash: 'b'.repeat(40),
      discovered_at: new Date().toISOString(),
      agent_context: { discovering_agent_id: 'agent-scanner-mantis' },
      raw_metadata: {},
    };

    const result = await engine.runLifecycle(finding);
    console.error('DEBUG RESULT:', JSON.stringify(result, null, 2));

    assert.equal(result.success, true);
    assert.equal(result.status, 'AUTHORIZED');
    assert.equal(result.stage, 'LEARN');
    assert.equal(result.rollbackOccurred, false);
    assert.equal(result.errors.length, 0);

    // Initial Evidence
    assert.ok(result.evidence);
    assert.equal(result.evidence.status, 'VERIFIED_TRUE_POSITIVE');
    assert.equal(result.evidence.verifier_agent_id, 'agent-sandbox-verifier');
    assert.equal(result.evidence.reproducer_artifact?.exit_code, 1);

    // Patch proposal
    assert.ok(result.patch);
    assert.equal(result.patch.recheck_status, 'passed_clean');
    assert.equal(result.patch.recheck_evidence_id, result.recheckEvidence?.evidence_id);

    // Recheck Evidence
    assert.ok(result.recheckEvidence);
    assert.equal(result.recheckEvidence.status, 'REFUTED_FALSE_POSITIVE');
    assert.equal(result.recheckEvidence.reproducer_artifact?.exit_code, 0);

    // Quality Gate Decision
    assert.ok(result.gateDecision);
    assert.equal(result.gateDecision.verdict, GateVerdict.PASS);

    // Custody Chain & Merkle Integrity
    assert.ok(result.custodyChain);
    const chainVerification = verifyChainOfCustody(result.custodyChain);
    assert.equal(chainVerification.valid, true);
    assert.equal(chainVerification.total_nodes, 4);
    assert.equal(chainVerification.merkle_root, result.custodyChain.merkle_root);
    assert.ok(result.gateDecision.audit_merkle_root);
  });

  it('3. E2E Remediation: Full 5-stage lifecycle on OS Command Injection (CWE-78)', { timeout: 180000 }, async () => {
    const engine = new AutonomousRemediationEngine({
      workspaceRoot,
      discoveringAgentId: 'agent-scanner-mantis',
      verifyingAgentId: 'agent-sandbox-verifier',
      authorizingAgentId: 'agent-quality-gate-authority',
      buildAfterPatch: true,
    });

    const finding: SecurityFinding = {
      finding_id: 'SK-FINDING-LAB-CMDI-001',
      source_engine: 'mantis',
      title: 'OS Command Injection in Diagnostics Ping Endpoint',
      description: 'Concatenation of targetHost parameter allows arbitrary command execution.',
      cwe_id: 'CWE-78',
      owasp_category: 'A03:2021-Injection',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: 'apps/lab-app/src/routes/diagnostics.ts',
      location: {
        file_path: 'apps/lab-app/src/routes/diagnostics.ts',
        start_line: 12,
        end_line: 47,
      },
      fingerprint: 'c'.repeat(64),
      commit_hash: 'd'.repeat(40),
      discovered_at: new Date().toISOString(),
      agent_context: { discovering_agent_id: 'agent-scanner-mantis' },
      raw_metadata: {},
    };

    const result = await engine.runLifecycle(finding);

    assert.equal(result.success, true);
    assert.equal(result.status, 'AUTHORIZED');
    assert.equal(result.stage, 'LEARN');
    assert.equal(result.rollbackOccurred, false);
    assert.equal(result.gateDecision?.verdict, GateVerdict.PASS);

    const chainVerification = verifyChainOfCustody(result.custodyChain!);
    assert.equal(chainVerification.valid, true);
  });

  it('4. E2E Remediation: Full 5-stage lifecycle on IDOR / Broken Access Control (CWE-639)', { timeout: 180000 }, async () => {
    const engine = new AutonomousRemediationEngine({
      workspaceRoot,
      discoveringAgentId: 'agent-scanner-mantis',
      verifyingAgentId: 'agent-sandbox-verifier',
      authorizingAgentId: 'agent-quality-gate-authority',
      buildAfterPatch: true,
    });

    const finding: SecurityFinding = {
      finding_id: 'SK-FINDING-LAB-IDOR-001',
      source_engine: 'mantis',
      title: 'Broken Access Control in Reports Endpoint',
      description: 'Missing tenant ownership check allows cross-user report access.',
      cwe_id: 'CWE-639',
      owasp_category: 'A01:2021-Broken Access Control',
      severity: 'HIGH',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: 'apps/lab-app/src/routes/reports.ts',
      location: {
        file_path: 'apps/lab-app/src/routes/reports.ts',
        start_line: 12,
        end_line: 58,
      },
      fingerprint: 'e'.repeat(64),
      commit_hash: 'f'.repeat(40),
      discovered_at: new Date().toISOString(),
      agent_context: { discovering_agent_id: 'agent-scanner-mantis' },
      raw_metadata: {},
    };

    const result = await engine.runLifecycle(finding);

    assert.equal(result.success, true);
    assert.equal(result.status, 'AUTHORIZED');
    assert.equal(result.stage, 'LEARN');
    assert.equal(result.rollbackOccurred, false);
    assert.equal(result.gateDecision?.verdict, GateVerdict.PASS);

    const chainVerification = verifyChainOfCustody(result.custodyChain!);
    assert.equal(chainVerification.valid, true);
  });

  it('5. Negative lifecycle: rejects invalid finding at FIND stage', { timeout: 180000 }, async () => {
    const engine = new AutonomousRemediationEngine({
      workspaceRoot,
      discoveringAgentId: 'agent-scanner-mantis',
      verifyingAgentId: 'agent-sandbox-verifier',
      authorizingAgentId: 'agent-quality-gate-authority',
    });

    const invalidFinding = {
      finding_id: 'INVALID_ID_WITHOUT_PREFIX',
      title: 'Invalid',
      cwe_id: 'NOT_A_CWE',
    } as any;

    const result = await engine.runLifecycle(invalidFinding);
    assert.equal(result.success, false);
    assert.equal(result.status, 'ERROR');
    assert.equal(result.stage, 'FIND');
    assert.equal(result.rollbackOccurred, false);
    assert.ok(result.errors.length > 0);
  });

  it('6. Negative lifecycle: rejects non-reproducible finding at PROVE stage', { timeout: 180000 }, async () => {
    const engine = new AutonomousRemediationEngine({
      workspaceRoot,
      discoveringAgentId: 'agent-scanner-mantis',
      verifyingAgentId: 'agent-sandbox-verifier',
      authorizingAgentId: 'agent-quality-gate-authority',
    });

    const finding: SecurityFinding = {
      finding_id: 'SK-FINDING-FALSE-POSITIVE',
      source_engine: 'mantis',
      title: 'False Positive Finding',
      description: 'Does not reproduce',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021-Injection',
      severity: 'LOW',
      confidence: 'TENTATIVE',
      target_type: 'SOURCE_CODE',
      target: 'apps/lab-app/src/routes/search.ts',
      location: { file_path: 'apps/lab-app/src/routes/search.ts', start_line: 1, end_line: 5 },
      fingerprint: '1'.repeat(64),
      commit_hash: '2'.repeat(40),
      discovered_at: new Date().toISOString(),
      raw_metadata: {},
    };

    // Use a dummy script that exits 0 (not vulnerable)
    const dummyScript = path.resolve(__dirname, '__fixtures__', 'safe-script.mjs');
    if (!fs.existsSync(path.dirname(dummyScript))) {
      fs.mkdirSync(path.dirname(dummyScript), { recursive: true });
    }
    fs.writeFileSync(dummyScript, 'process.exit(0);\n', 'utf8');

    try {
      const result = await engine.runLifecycle(finding, dummyScript);
      assert.equal(result.success, false);
      assert.equal(result.status, 'REJECTED');
      assert.equal(result.stage, 'PROVE');
      assert.equal(result.rollbackOccurred, false);
    } finally {
      if (fs.existsSync(dummyScript)) {
        fs.unlinkSync(dummyScript);
      }
    }
  });

  it('7. Negative lifecycle: SoD violation at LEARN stage triggers rollback', { timeout: 180000 }, async () => {
    // Violate Separation of Duties: discovering agent == verifying agent
    const engine = new AutonomousRemediationEngine({
      workspaceRoot,
      discoveringAgentId: 'agent-omnipotent',
      verifyingAgentId: 'agent-omnipotent', // VIOLATION!
      authorizingAgentId: 'agent-quality-gate-authority',
      buildAfterPatch: true,
    });

    const finding: SecurityFinding = {
      finding_id: 'SK-FINDING-SOD-VIOLATION',
      source_engine: 'mantis',
      title: 'SQL Injection SoD Test',
      description: 'Will trigger SoD rejection',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021-Injection',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: 'apps/lab-app/src/routes/search.ts',
      location: { file_path: 'apps/lab-app/src/routes/search.ts', start_line: 11, end_line: 16 },
      fingerprint: '9'.repeat(64),
      commit_hash: '9'.repeat(40),
      discovered_at: new Date().toISOString(),
      agent_context: { discovering_agent_id: 'agent-omnipotent' },
      raw_metadata: {},
    };

    const result = await engine.runLifecycle(finding);

    assert.equal(result.success, false);
    assert.equal(result.status, 'ROLLED_BACK');
    assert.equal(result.stage, 'LEARN');
    assert.equal(result.rollbackOccurred, true);
    assert.notEqual(result.gateDecision?.verdict, GateVerdict.PASS);

    // Verify search.ts was rolled back to original content
    const currentSearch = fs.readFileSync(searchPath, 'utf8');
    assert.equal(currentSearch, originalSearchContent);
  });
});
