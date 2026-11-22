/**
 * @file packages/remediation-engine/tests/rollback.test.mts
 * @description Automated rollback verification test suite across all 4 failure triggers:
 * 1. Snapshot capture & hash-verified restoration
 * 2. Diff generation & reverse diff mathematical symmetry
 * 3. Blast radius assessment
 * 4. Trigger 1: Syntax / hunk collision rollback
 * 5. Trigger 2: Post-patch reproducer failure rollback
 * 6. Trigger 3: Baseline regression failure rollback
 * 7. Trigger 4: Zero-Trust Quality Gate rejection rollback
 * 8. Audit logging of rollback executions
 */

import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  FileSnapshotManager,
  RollbackEngine,
  generateUnifiedDiff,
  generateReverseDiff,
  calculateBlastRadius,
  applyUnifiedDiff,
  synthesizePatchProposal,
  AutonomousRemediationEngine,
  type SecurityFinding,
  type PatchProposal,
  GateVerdict,
} from '../dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('Automated Rollback Engine & Diff Mechanics Suite', () => {
  const workspaceRoot = fs.existsSync(path.resolve(process.cwd(), 'apps', 'lab-app'))
    ? path.resolve(process.cwd())
    : path.resolve(__dirname, '../../..');
  const tempTestDir = path.resolve(__dirname, '__fixtures__');
  const tempTestFile = path.resolve(tempTestDir, 'fixture-code.ts');
  const originalFixtureContent = [
    'export function computeScore(a: number, b: number): number {',
    '  // Initial vulnerable calculation',
    '  const rawResult = a + b;',
    '  return rawResult;',
    '}',
  ].join('\n') + '\n';

  before(() => {
    if (!fs.existsSync(tempTestDir)) {
      fs.mkdirSync(tempTestDir, { recursive: true });
    }
    fs.writeFileSync(tempTestFile, originalFixtureContent, 'utf8');
  });

  after(() => {
    if (fs.existsSync(tempTestFile)) {
      fs.unlinkSync(tempTestFile);
    }
    if (fs.existsSync(tempTestDir)) {
      fs.rmSync(tempTestDir, { recursive: true, force: true });
    }
  });

  it('1. Snapshot capture & hash verification: restores modified file bit-for-bit', async () => {
    const manager = new FileSnapshotManager();
    await manager.takeSnapshot([tempTestFile]);

    const originalHash = crypto.createHash('sha256').update(originalFixtureContent, 'utf8').digest('hex');
    const snapshot = manager.getSnapshot(tempTestFile);
    assert.ok(snapshot);
    assert.equal(snapshot.sha256, originalHash);

    // Mutate file on disk
    fs.writeFileSync(tempTestFile, 'MUTATED CONTENT THAT BREAKS EVERYTHING\n', 'utf8');
    const mutatedContent = fs.readFileSync(tempTestFile, 'utf8');
    assert.notEqual(mutatedContent, originalFixtureContent);

    // Restore snapshot
    const restoreResult = await manager.restore();
    assert.equal(restoreResult.success, true);
    assert.deepEqual(restoreResult.restored, [tempTestFile]);

    const restoredContent = fs.readFileSync(tempTestFile, 'utf8');
    assert.equal(restoredContent, originalFixtureContent);
  });

  it('2. Diff generation & reverse diff mathematical symmetry: applyPatch(applyPatch(orig, patch), revPatch) === orig', () => {
    const orig = 'function greet(name: string): string {\n  return "Hello " + name;\n}\n';
    const patched = 'function greet(name: string): string {\n  const safeName = name.trim();\n  return `Hello ${safeName}`;\n}\n';

    const forwardDiff = generateUnifiedDiff('src/greet.ts', orig, patched, 3);
    assert.ok(forwardDiff.includes('--- a/src/greet.ts'));
    assert.ok(forwardDiff.includes('+++ b/src/greet.ts'));
    assert.ok(forwardDiff.includes('+  const safeName = name.trim();'));

    const reverseDiff = generateReverseDiff('src/greet.ts', orig, patched, 3);
    assert.ok(reverseDiff.includes('--- b/src/greet.ts'));
    assert.ok(reverseDiff.includes('+++ a/src/greet.ts'));
    assert.ok(reverseDiff.includes('-  const safeName = name.trim();'));

    // Apply forward diff
    const applyForward = applyUnifiedDiff(orig, forwardDiff);
    assert.equal(applyForward.success, true);
    assert.equal(applyForward.patchedContent, patched);

    // Apply reverse diff
    const applyReverse = applyUnifiedDiff(applyForward.patchedContent!, reverseDiff);
    assert.equal(applyReverse.success, true);
    assert.equal(applyReverse.patchedContent, orig);
  });

  it('3. Blast radius calculation: accurately assesses lines added/deleted and risk', () => {
    const diff = [
      '--- a/src/file.ts',
      '+++ b/src/file.ts',
      '@@ -1,3 +1,4 @@',
      ' context',
      '-old line 1',
      '-old line 2',
      '+new line 1',
      '+new line 2',
      '+new line 3',
      ' context',
    ].join('\n') + '\n';

    const blast = calculateBlastRadius(diff, {
      astImpactScope: 'LOCAL_FUNCTION',
      breakingChangeRisk: 'LOW',
    });

    assert.equal(blast.files_modified, 1);
    assert.equal(blast.lines_added, 3);
    assert.equal(blast.lines_deleted, 2);
    assert.equal(blast.ast_impact_scope, 'LOCAL_FUNCTION');
    assert.equal(blast.breaking_change_risk, 'LOW');
  });

  it('4. Trigger 1 (Syntax / context rejection): rejects invalid diff and preserves pre-patch state', () => {
    const orig = 'export const x = 1;\n';
    const invalidDiff = [
      '--- a/src/file.ts',
      '+++ b/src/file.ts',
      '@@ -50,3 +50,3 @@',
      ' non-existent context line',
      '-old',
      '+new',
    ].join('\n') + '\n';

    const result = applyUnifiedDiff(orig, invalidDiff);
    assert.equal(result.success, false);
    assert.ok(result.error?.includes('hunk context lines did not match'));
  });

  it('5. Trigger 2 (Reproducer failure rollback): executes rollback when reproducer still fails', async () => {
    const engine = new RollbackEngine(workspaceRoot);
    const finding: SecurityFinding = {
      finding_id: 'SK-FIND-SQLI-ROLLBACK-TEST',
      source_engine: 'mantis',
      title: 'SQL Injection in Search',
      description: 'Test vulnerability for rollback verification',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021-Injection',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: tempTestFile,
      location: { file_path: tempTestFile, start_line: 1, end_line: 5 },
      fingerprint: '1'.repeat(64),
      commit_hash: '2'.repeat(40),
      discovered_at: new Date().toISOString(),
      agent_context: { discovering_agent_id: 'agent-scanner-mantis' },
      raw_metadata: {},
    };

    const dummyPatched = originalFixtureContent + '\n// Dummy ineffective patch\n';
    const patch = synthesizePatchProposal(finding, originalFixtureContent, dummyPatched, tempTestFile);

    const snapshotMgr = new FileSnapshotManager();
    await snapshotMgr.takeSnapshot([tempTestFile]);

    // Apply dummy mutation
    fs.writeFileSync(tempTestFile, dummyPatched, 'utf8');

    // Reproducer still fails -> Trigger rollback
    const record = await engine.executeRollback(
      patch,
      'REPRODUCER_STILL_FAILS',
      'Reproducer still exited with code 1 after patch',
      snapshotMgr
    );

    assert.equal(record.success, true);
    assert.equal(record.trigger, 'REPRODUCER_STILL_FAILS');
    assert.equal(fs.readFileSync(tempTestFile, 'utf8'), originalFixtureContent);
  });

  it('6. Trigger 3 (Regression test failure rollback): executes rollback when regression tests fail', async () => {
    const engine = new RollbackEngine(workspaceRoot);
    const finding: SecurityFinding = {
      finding_id: 'SK-FIND-REGRESSION-TEST',
      source_engine: 'mantis',
      title: 'Regression trigger finding',
      description: 'Finding causing functional regression',
      cwe_id: 'CWE-78',
      owasp_category: 'A03:2021-Injection',
      severity: 'CRITICAL',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: tempTestFile,
      location: { file_path: tempTestFile, start_line: 1, end_line: 5 },
      fingerprint: '3'.repeat(64),
      commit_hash: '4'.repeat(40),
      discovered_at: new Date().toISOString(),
      raw_metadata: {},
    };

    const breakingPatched = 'export function broken() { throw new Error("Regression"); }\n';
    const patch = synthesizePatchProposal(finding, originalFixtureContent, breakingPatched, tempTestFile);

    const snapshotMgr = new FileSnapshotManager();
    await snapshotMgr.takeSnapshot([tempTestFile]);

    fs.writeFileSync(tempTestFile, breakingPatched, 'utf8');

    const record = await engine.executeRollback(
      patch,
      'REGRESSION_DETECTED',
      'Baseline test suite failed with 2 errors',
      snapshotMgr
    );

    assert.equal(record.success, true);
    assert.equal(record.trigger, 'REGRESSION_DETECTED');
    assert.equal(fs.readFileSync(tempTestFile, 'utf8'), originalFixtureContent);
  });

  it('7. Trigger 4 (Quality Gate rejection rollback): executes rollback when Quality Gate rejects', async () => {
    const engine = new RollbackEngine(workspaceRoot);
    const finding: SecurityFinding = {
      finding_id: 'SK-FIND-GATE-REJECT-TEST',
      source_engine: 'mantis',
      title: 'Gate rejection finding',
      description: 'Finding that fails SoD at Quality Gate',
      cwe_id: 'CWE-639',
      owasp_category: 'A01:2021-Broken Access Control',
      severity: 'HIGH',
      confidence: 'CERTAIN',
      target_type: 'SOURCE_CODE',
      target: tempTestFile,
      location: { file_path: tempTestFile, start_line: 1, end_line: 5 },
      fingerprint: '5'.repeat(64),
      commit_hash: '6'.repeat(40),
      discovered_at: new Date().toISOString(),
      raw_metadata: {},
    };

    const proposed = originalFixtureContent + '\n// Secured access check\n';
    const patch = synthesizePatchProposal(finding, originalFixtureContent, proposed, tempTestFile);

    const snapshotMgr = new FileSnapshotManager();
    await snapshotMgr.takeSnapshot([tempTestFile]);
    fs.writeFileSync(tempTestFile, proposed, 'utf8');

    const record = await engine.executeRollback(
      patch,
      'GATE_REJECTED',
      'Quality Gate REJECT: Separation of duties violation detected',
      snapshotMgr
    );

    assert.equal(record.success, true);
    assert.equal(record.trigger, 'GATE_REJECTED');
    assert.equal(fs.readFileSync(tempTestFile, 'utf8'), originalFixtureContent);
  });

  it('8. Audit logging: maintains complete chronological record of rollback events', () => {
    const engine = new RollbackEngine(workspaceRoot);
    const finding: SecurityFinding = {
      finding_id: 'SK-FIND-AUDIT-TEST',
      source_engine: 'mantis',
      title: 'Audit test finding',
      description: 'Verifies audit logging',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021-Injection',
      severity: 'LOW',
      confidence: 'TENTATIVE',
      target_type: 'SOURCE_CODE',
      target: tempTestFile,
      location: { file_path: tempTestFile, start_line: 1, end_line: 5 },
      fingerprint: '7'.repeat(64),
      commit_hash: '8'.repeat(40),
      discovered_at: new Date().toISOString(),
      raw_metadata: {},
    };

    const patch = synthesizePatchProposal(finding, originalFixtureContent, originalFixtureContent + '// mod\n', tempTestFile);
    assert.equal(engine.getAuditLog().length, 0);

    engine.executeRollback(patch, 'PATCH_SYNTAX_ERROR', 'Syntax error');
    assert.equal(engine.getAuditLog().length, 1);
    assert.equal(engine.getAuditLog()[0].trigger, 'PATCH_SYNTAX_ERROR');
    assert.match(engine.getAuditLog()[0].rollback_id, /^SK-ROLLBACK-/);
  });

  it('9. Bounds checkpoints and auditLog, and consumes checkpoint on rollbackCheckpoint()', async () => {
    const boundedEngine = new RollbackEngine(workspaceRoot, 2, 2);
    const cp1 = boundedEngine.createCheckpoint([tempTestFile]);
    const cp2 = boundedEngine.createCheckpoint([tempTestFile]);
    const cp3 = boundedEngine.createCheckpoint([tempTestFile]);
    assert.equal(boundedEngine.getCheckpoint(cp1.checkpoint_id), undefined);
    assert.ok(boundedEngine.getCheckpoint(cp2.checkpoint_id));
    assert.ok(boundedEngine.getCheckpoint(cp3.checkpoint_id));

    const rbRes = boundedEngine.rollbackCheckpoint(cp2.checkpoint_id);
    assert.equal(rbRes.success, true);
    assert.equal(boundedEngine.getCheckpoint(cp2.checkpoint_id), undefined);

    const finding: SecurityFinding = {
      finding_id: 'SK-FIND-BOUND-TEST',
      source_engine: 'mantis',
      title: 'Bounded audit log finding',
      description: 'Verifies auditLog cap',
      cwe_id: 'CWE-89',
      owasp_category: 'A03:2021-Injection',
      severity: 'LOW',
      confidence: 'TENTATIVE',
      target_type: 'SOURCE_CODE',
      target: tempTestFile,
      location: { file_path: tempTestFile, start_line: 1, end_line: 5 },
      fingerprint: '9'.repeat(64),
      commit_hash: '0'.repeat(40),
      discovered_at: new Date().toISOString(),
      raw_metadata: {},
    };
    const patch = synthesizePatchProposal(
      finding,
      originalFixtureContent,
      originalFixtureContent + '// bound\n',
      tempTestFile
    );
    await boundedEngine.executeRollback(patch, 'PATCH_SYNTAX_ERROR', 'e1');
    await boundedEngine.executeRollback(patch, 'REGRESSION_DETECTED', 'e2');
    await boundedEngine.executeRollback(patch, 'GATE_REJECTED', 'e3');
    assert.equal(boundedEngine.getAuditLog().length, 2);
    assert.deepEqual(
      boundedEngine.getAuditLog().map((r) => r.trigger_details),
      ['e2', 'e3']
    );
  });
});
