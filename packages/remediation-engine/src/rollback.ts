import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import type { PatchProposal } from '@script-kitty/contracts';
import { applyUnifiedDiff } from './patcher.js';
import type {
  RollbackTrigger,
  FileSnapshot,
  RollbackRecord,
  RollbackResult,
  RollbackCheckpoint,
} from './types.js';

export type { RollbackCheckpoint };

/**
 * Manages atomic in-memory and disk snapshots of files before patching.
 */
export class FileSnapshotManager {
  private snapshots: Map<string, FileSnapshot> = new Map();

  /**
   * Captures byte-for-byte snapshots of specified files before modification.
   */
  public async takeSnapshot(filePaths: string[]): Promise<void> {
    for (const filePath of filePaths) {
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        const sha256 = createHash('sha256').update(content, 'utf8').digest('hex');
        this.snapshots.set(filePath, {
          filePath,
          file_path: filePath,
          content,
          sha256,
          exists: true,
          mtimeMs: Date.now(),
        });
      } else {
        this.snapshots.set(filePath, {
          filePath,
          file_path: filePath,
          content: '',
          sha256: '0'.repeat(64),
          exists: false,
          mtimeMs: Date.now(),
        });
      }
    }
  }

  /**
   * Restores all captured snapshots to disk and verifies hash integrity.
   */
  public async restore(): Promise<{ success: boolean; restored: string[]; error?: string }> {
    const restored: string[] = [];
    try {
      for (const [filePath, snapshot] of this.snapshots.entries()) {
        if (snapshot.exists && snapshot.content !== null) {
          fs.writeFileSync(filePath, snapshot.content, 'utf8');
          const recheck = fs.readFileSync(filePath, 'utf8');
          const rehash = createHash('sha256').update(recheck, 'utf8').digest('hex');
          if (rehash !== snapshot.sha256) {
            throw new Error(`Hash mismatch after restoring ${filePath}: expected ${snapshot.sha256}, got ${rehash}`);
          }
        } else if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
        restored.push(filePath);
      }
      return { success: true, restored };
    } catch (err: any) {
      return {
        success: false,
        restored,
        error: err.message || String(err),
      };
    }
  }

  /**
   * Returns snapshot for a file path if available.
   */
  public getSnapshot(filePath: string): FileSnapshot | undefined {
    return this.snapshots.get(filePath);
  }

  /**
   * Clears stored snapshots after a successful lifecycle run.
   */
  public clear(): void {
    this.snapshots.clear();
  }
}

/**
 * Automated Rollback Engine executing reverse diffs or snapshot restores across all failure triggers.
 */
export class RollbackEngine {
  private auditLog: RollbackRecord[] = [];
  private checkpoints: Map<string, RollbackCheckpoint> = new Map();
  private readonly maxCheckpoints: number;
  private readonly maxAuditEntries: number;

  constructor(
    private workspaceRoot?: string,
    maxCheckpoints = 100,
    maxAuditEntries = 1_000
  ) {
    this.maxCheckpoints =
      Number.isInteger(maxCheckpoints) && maxCheckpoints > 0
        ? maxCheckpoints
        : 100;
    this.maxAuditEntries =
      Number.isInteger(maxAuditEntries) && maxAuditEntries > 0
        ? maxAuditEntries
        : 1_000;
  }

  /**
   * Captures snapshots of specified files and creates a named checkpoint.
   */
  public createCheckpoint(
    filePaths: string[],
    baseCommit?: string,
    revertPatch?: string
  ): RollbackCheckpoint {
    const checkpointId = `SK-RB-CHECKPOINT-${randomUUID().slice(0, 12)}`;
    const snapshots: Record<string, FileSnapshot> = {};

    for (const rawPath of filePaths) {
      const resolved = this.workspaceRoot
        ? path.resolve(this.workspaceRoot, rawPath)
        : (path.isAbsolute(rawPath) ? rawPath : path.resolve(process.cwd(), rawPath));

      if (fs.existsSync(resolved)) {
        const content = fs.readFileSync(resolved, 'utf8');
        const hash = createHash('sha256').update(content, 'utf8').digest('hex');
        snapshots[resolved] = {
          filePath: resolved,
          file_path: resolved,
          content,
          exists: true,
          sha256: hash,
        };
      } else {
        snapshots[resolved] = {
          filePath: resolved,
          file_path: resolved,
          content: '',
          exists: false,
          sha256: '0'.repeat(64),
        };
      }
    }

    const checkpoint: RollbackCheckpoint = {
      checkpoint_id: checkpointId,
      created_at: new Date().toISOString(),
      base_commit: baseCommit ?? 'HEAD',
      snapshots,
      revert_patch: revertPatch,
    };

    while (this.checkpoints.size >= this.maxCheckpoints) {
      const oldestCheckpointId = this.checkpoints.keys().next().value;
      if (oldestCheckpointId === undefined) break;
      this.checkpoints.delete(oldestCheckpointId);
    }
    this.checkpoints.set(checkpointId, checkpoint);
    return checkpoint;
  }

  private rebuildLabApp(): void {
    if (!this.workspaceRoot) {
      return;
    }
    try {
      const tscPath = path.resolve(this.workspaceRoot, 'node_modules', 'typescript', 'bin', 'tsc');
      const tsconfigPath = path.resolve(this.workspaceRoot, 'apps', 'lab-app', 'tsconfig.json');
      if (fs.existsSync(tscPath) && fs.existsSync(tsconfigPath)) {
        execFileSync(process.execPath, [tscPath, '-p', tsconfigPath], {
          cwd: this.workspaceRoot,
          stdio: 'pipe',
          encoding: 'utf8',
          shell: false,
        });
      }
    } catch {
      // Non-fatal rebuild during rollback cleanup
    }
  }

  /**
   * Direct rollback restoring a single file to its original content and rebuilding the workspace.
   */
  public rollback(targetFilePath: string, originalContent: string, reason: string): void {
    fs.writeFileSync(targetFilePath, originalContent, 'utf8');
    const affectsLabApp = targetFilePath.includes('apps/lab-app') || targetFilePath.includes('apps\\lab-app');
    if (this.workspaceRoot && affectsLabApp) {
      this.rebuildLabApp();
    }
  }

  /**
   * Restores all files associated with a given checkpoint.
   */
  public rollbackCheckpoint(checkpointId: string): RollbackResult {
    const checkpoint = this.checkpoints.get(checkpointId);
    if (!checkpoint) {
      return {
        success: false,
        checkpoint_id: checkpointId,
        restored_files: [],
        error: `Checkpoint '${checkpointId}' not found`,
        timestamp: new Date().toISOString(),
      };
    }

    const restoredFiles: string[] = [];
    try {
      for (const [filePath, snapshot] of Object.entries(checkpoint.snapshots)) {
        if (snapshot.exists && snapshot.content !== null) {
          fs.writeFileSync(filePath, snapshot.content, 'utf8');
        } else if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
        restoredFiles.push(filePath);
      }

      if (this.workspaceRoot) {
        this.rebuildLabApp();
      }

      this.checkpoints.delete(checkpointId);
      return {
        success: true,
        checkpoint_id: checkpointId,
        restored_files: restoredFiles,
        timestamp: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        success: false,
        checkpoint_id: checkpointId,
        restored_files: restoredFiles,
        error: err.message || String(err),
        timestamp: new Date().toISOString(),
      };
    }
  }

  /**
   * Discards a checkpoint once verified and approved.
   */
  public discardCheckpoint(checkpointId: string): boolean {
    return this.checkpoints.delete(checkpointId);
  }

  /**
   * Executes a safe rollback when a patch fails syntax, reproducer, regression, or gate checks.
   */
  public async executeRollback(
    patch: PatchProposal,
    trigger: RollbackTrigger,
    details: string,
    snapshotManager?: FileSnapshotManager
  ): Promise<RollbackRecord> {
    const rollbackId = `SK-ROLLBACK-${randomUUID().slice(0, 16)}`;
    const timestamp = new Date().toISOString();
    let revertedVia: 'REVERSE_DIFF' | 'SNAPSHOT_RESTORE' = 'SNAPSHOT_RESTORE';
    let success = false;
    let restorationError: string | undefined;

    // Strategy 1: If SnapshotManager has captured original files, restore them (highest reliability)
    if (snapshotManager) {
      const restoreResult = await snapshotManager.restore();
      if (restoreResult.success) {
        success = true;
        revertedVia = 'SNAPSHOT_RESTORE';
      } else {
        restorationError = `Snapshot restore failed: ${restoreResult.error}`;
      }
    }

    // Strategy 2: If snapshot not present or failed, attempt reverse diff application
    if (!success && patch.rollback_plan?.revert_patch) {
      try {
        for (const filePath of patch.affected_files) {
          const fullPath = this.workspaceRoot ? path.resolve(this.workspaceRoot, filePath) : filePath;
          const currentContent = fs.readFileSync(fullPath, 'utf8');
          const applyRes = applyUnifiedDiff(currentContent, patch.rollback_plan.revert_patch);
          if (!applyRes.success || !applyRes.patchedContent) {
            throw new Error(`Reverse diff application failed: ${applyRes.error}`);
          }
          fs.writeFileSync(fullPath, applyRes.patchedContent, 'utf8');
        }
        success = true;
        revertedVia = 'REVERSE_DIFF';
      } catch (err: any) {
        restorationError = (restorationError ? `${restorationError}; ` : '') + (err.message || String(err));
      }
    }

    // Rebuild workspace after restoring files
    const affectsLabApp = patch.affected_files.some(
      (f) => f.includes('apps/lab-app') || f.includes('apps\\lab-app')
    );
    if (success && this.workspaceRoot && affectsLabApp) {
      this.rebuildLabApp();
    }

    const record: RollbackRecord = {
      rollback_id: rollbackId,
      patch_id: patch.patch_id,
      finding_id: patch.finding_id,
      trigger,
      trigger_details: details,
      files_affected: patch.affected_files,
      reverted_via: revertedVia,
      success,
      restoration_error: restorationError,
      executed_at: timestamp,
    };

    this.auditLog.push(record);
    while (this.auditLog.length > this.maxAuditEntries) {
      this.auditLog.shift();
    }
    return record;
  }

  /**
   * Retrieves audit log of all rollback executions.
   */
  public getAuditLog(): RollbackRecord[] {
    return [...this.auditLog];
  }

  /**
   * Retrieves a stored checkpoint by ID.
   */
  public getCheckpoint(checkpointId: string): RollbackCheckpoint | undefined {
    return this.checkpoints.get(checkpointId);
  }
}
