import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { structuredPatch, applyPatch as diffApplyPatch } from 'diff';
import {
  type SecurityFinding,
  type PatchProposal,
  type BlastRadius,
  type AstImpactScope,
  type BreakingChangeRisk,
  PatchProposalSchema,
  computePatchSha256,
} from '@script-kitty/contracts';
import type {
  PatcherOptions,
  PatchSynthesisOptions,
  PatchSynthesisResult,
  PatchApplyResult,
  PatchOptions,
} from './types.js';

export type { PatchSynthesisResult, PatchApplyResult, PatchSynthesisOptions, PatcherOptions, PatchOptions };

/**
 * Formats a git-compatible unified diff from original and patched content.
 */
export function generateUnifiedDiff(
  relativePath: string,
  originalContent: string,
  patchedContent: string,
  contextLines: number = 3
): string {
  const normOriginal = originalContent.replace(/\r\n/g, '\n');
  const normPatched = patchedContent.replace(/\r\n/g, '\n');
  const normRel = relativePath.replace(/\\/g, '/');

  const patch = structuredPatch(
    `a/${normRel}`,
    `b/${normRel}`,
    normOriginal,
    normPatched,
    '',
    '',
    { context: contextLines }
  );

  const lines: string[] = [
    `--- a/${normRel}`,
    `+++ b/${normRel}`
  ];

  for (const hunk of patch.hunks) {
    lines.push(`@@ -${hunk.oldStart},${hunk.oldLines} +${hunk.newStart},${hunk.newLines} @@`);
    lines.push(...hunk.lines);
  }

  return lines.join('\n') + '\n';
}

/**
 * Generates an exact reverse unified diff for rollback.
 * Running diff.structuredPatch(b/path, a/path, patchedContent, originalContent)
 * guarantees mathematically exact inverted hunk headers and line counts.
 */
export function generateReverseDiff(
  relativePath: string,
  originalContent: string,
  patchedContent: string,
  contextLines: number = 3
): string {
  const normOriginal = originalContent.replace(/\r\n/g, '\n');
  const normPatched = patchedContent.replace(/\r\n/g, '\n');
  const normRel = relativePath.replace(/\\/g, '/');

  const patch = structuredPatch(
    `b/${normRel}`,
    `a/${normRel}`,
    normPatched,
    normOriginal,
    '',
    '',
    { context: contextLines }
  );

  const lines: string[] = [
    `--- b/${normRel}`,
    `+++ a/${normRel}`
  ];

  for (const hunk of patch.hunks) {
    lines.push(`@@ -${hunk.oldStart},${hunk.oldLines} +${hunk.newStart},${hunk.newLines} @@`);
    lines.push(...hunk.lines);
  }

  return lines.join('\n') + '\n';
}

/**
 * Calculates Blast Radius assessment for a diff.
 */
export function calculateBlastRadius(
  diffContent: string,
  options?: {
    filesCount?: number;
    astImpactScope?: AstImpactScope;
    breakingChangeRisk?: BreakingChangeRisk;
    downstreamDependents?: string[];
  }
): BlastRadius {
  const lines = diffContent.split('\n');
  let linesAdded = 0;
  let linesDeleted = 0;

  const isDiffHeader = (line: string) => /^(---|\+\+\+)\s+([ab]\/|\/dev\/null)/.test(line);

  for (const line of lines) {
    if (isDiffHeader(line)) {
      continue;
    }
    if (line.startsWith('+')) {
      linesAdded++;
    } else if (line.startsWith('-')) {
      linesDeleted++;
    }
  }

  return {
    files_modified: options?.filesCount ?? 1,
    lines_added: linesAdded,
    lines_deleted: linesDeleted,
    ast_impact_scope: options?.astImpactScope ?? 'LOCAL_FUNCTION',
    downstream_dependents: options?.downstreamDependents ?? [],
    breaking_change_risk: options?.breakingChangeRisk ?? 'LOW',
  };
}

/**
 * Programmatically applies a unified diff to a source string.
 */
export function applyUnifiedDiff(source: string, diffContent: string): PatchApplyResult {
  if (!diffContent.includes('@@')) {
    return {
      success: false,
      applied_files: [],
      error: 'Malformed diff: no hunks found',
      patchedContent: source,
    };
  }

  const normSource = source.replace(/\r\n/g, '\n');
  let result = diffApplyPatch(normSource, diffContent);

  if (result === false) {
    return {
      success: false,
      applied_files: [],
      error: 'Failed to apply unified diff: hunk context lines did not match source file',
      patchedContent: source,
    };
  }

  if (result === '\n') {
    const hunkHeaders = diffContent.match(/@@\s+-[0-9,]+\s+\+([0-9]+),([0-9]+)\s+@@/g);
    if (hunkHeaders && hunkHeaders.every(h => {
      const m = h.match(/\+([0-9]+),([0-9]+)/);
      return m && m[2] === '0';
    })) {
      result = '';
    } else {
      const diffLines = diffContent.split('\n');
      const hasAddedLines = diffLines.some(l => l.startsWith('+') && !/^\+\+\+\s+([ab]\/|\/dev\/null)/.test(l));
      if (!hasAddedLines) {
        result = '';
      }
    }
  }

  return {
    success: true,
    applied_files: [],
    patchedContent: result,
  };
}

/**
 * Synthesizes a canonical PatchProposal adhering to PatchProposalSchema.
 */
export function synthesizePatchProposal(
  finding: SecurityFinding,
  originalContent: string,
  patchedContent: string,
  filePath: string,
  options: PatchSynthesisOptions = {}
): PatchProposal {
  const normRel = filePath.replace(/\\/g, '/');
  const diffContent = generateUnifiedDiff(normRel, originalContent, patchedContent, options.contextLines ?? 3);
  const revertDiff = generateReverseDiff(normRel, originalContent, patchedContent, options.contextLines ?? 3);
  const patchSha256 = computePatchSha256(diffContent);
  const blastRadius = calculateBlastRadius(diffContent, {
    astImpactScope: options.astImpactScope ?? 'LOCAL_FUNCTION',
    breakingChangeRisk: options.breakingChangeRisk ?? 'LOW',
  });

  // Base commit must be 40 to 64 hex characters
  let baseCommit = finding.commit_hash ?? '';
  if (!/^[0-9a-fA-F]{40,64}$/.test(baseCommit)) {
    baseCommit = '0'.repeat(40);
  }

  const proposalRaw = {
    patch_id: `SK-PATCH-${randomUUID().slice(0, 16)}`,
    finding_id: finding.finding_id,
    author_engine: options.authorEngine ?? 'script-kitty-remediation-engine',
    diff_content: diffContent,
    affected_files: [normRel],
    base_commit: baseCommit,
    patch_sha256: patchSha256,
    recheck_status: 'untested',
    blast_radius: blastRadius,
    rollback_plan: {
      revert_patch: revertDiff,
      compensating_controls: ['restore_file_snapshot'],
      killswitch_flag: options.killswitchFlag ?? `DISABLE_FIX_${finding.cwe_id.replace(/[^a-zA-Z0-9]/g, '_')}`,
      automated_rollback_trigger: 'SYNTAX_ERROR | REPRODUCER_STILL_FAILS | REGRESSION_DETECTED | GATE_REJECTED',
    },
    created_at: new Date().toISOString(),
  };

  return PatchProposalSchema.parse(proposalRaw);
}

/**
 * Deterministic vulnerability transformation catalog for the synthetic lab app.
 */
export const LabAppRemediationTemplates = {
  /**
   * Fixes SQL Injection in apps/lab-app/src/routes/search.ts (CWE-89)
   */
  fixSqlInjection(source: string): string {
    const norm = source.replace(/\r\n/g, '\n');
    const vulnerablePattern = /const\s+rawSql\s*=\s*`SELECT[\s\S]*?WHERE\s+title\s+LIKE\s+'%[\$]\{query\}%'\s+OR\s+description\s+LIKE\s+'%[\$]\{query\}%'`;\s*const\s+stmt\s*=\s*db\.prepare\(rawSql\);\s*return\s+stmt\.all\(\);/;

    const secureReplacement = `const rawSql = \`SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE title LIKE ? OR description LIKE ?\`;\n  const pattern = \`%\${query}%\`;\n  const stmt = db.prepare(rawSql);\n  return stmt.all(pattern, pattern);`;

    if (!vulnerablePattern.test(norm)) {
      throw new Error('Target SQL injection vulnerability pattern not found in source file');
    }

    return norm.replace(vulnerablePattern, secureReplacement);
  },

  /**
   * Fixes Command Injection in apps/lab-app/src/routes/diagnostics.ts (CWE-78)
   */
  fixCommandInjection(source: string): string {
    const norm = source.replace(/\r\n/g, '\n');
    const originalBlockPattern = /export\s+function\s+runHostPing\(targetHost:\s*string,\s*db\?:?\s*DatabaseSync\):\s*PingResult\s*\{\s*const\s+isWindows\s*=\s*process\.platform\s*===\s*'win32';\s*const\s+pingCmd\s*=\s*isWindows\s*\?\s*`ping\s+-n\s+1\s+[\$]\{targetHost\}`\s*:\s*`ping\s+-c\s+1\s+[\$]\{targetHost\}`;/;

    const secureHeaderAndValidation = `export function runHostPing(targetHost: string, db?: DatabaseSync): PingResult {\n  const isWindows = process.platform === 'win32';\n\n  // SECURED: Validate input to prevent command injection (CWE-78)\n  const HOSTNAME_REGEX = /^[a-zA-Z0-9.-]+$/;\n  if (!targetHost || !HOSTNAME_REGEX.test(targetHost.trim())) {\n    const errorMsg = 'Invalid target host: shell metacharacters rejected';\n    if (db) {\n      try {\n        db.prepare('INSERT INTO diagnostic_logs (host, status, output, created_at) VALUES (?, ?, ?, ?)').run(\n          targetHost,\n          'ERROR',\n          errorMsg,\n          new Date().toISOString()\n        );\n      } catch {\n        // Non-fatal logging failure\n      }\n    }\n    return { status: 'ERROR', output: errorMsg };\n  }\n\n  const sanitizedHost = targetHost.trim();\n  const pingCmd = isWindows ? \`ping -n 1 \${sanitizedHost}\` : \`ping -c 1 \${sanitizedHost}\`;`;

    if (!originalBlockPattern.test(norm)) {
      throw new Error('Target command injection vulnerability pattern not found in source file');
    }

    return norm.replace(originalBlockPattern, secureHeaderAndValidation);
  },

  /**
   * Fixes Broken Access Control / IDOR in apps/lab-app/src/routes/reports.ts (CWE-639)
   */
  fixBrokenAccessControl(source: string): string {
    const norm = source.replace(/\r\n/g, '\n');
    const fullOriginalPattern = /const\s+report\s*=\s*db\.prepare\(\s*'SELECT\s+id,\s*owner_id,\s*title,\s*severity,\s*classification,\s*description,\s*system_target,\s*created_at\s+FROM\s+incidents\s+WHERE\s+id\s*=\s*\?'\s*\)\.get\(reportId\);\s*if\s*\(!report\)\s*\{\s*return\s*\{\s*status:\s*404,\s*body:\s*\{\s*error:\s*'Report not found'\s*\}\s*\};\s*\}/;

    const secureReportBlock = `const report = db.prepare(\n    'SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE id = ?'\n  ).get(reportId) as any;\n\n  if (!report) {\n    return {\n      status: 404,\n      body: { error: 'Report not found' }\n    };\n  }\n\n  // SECURED: Enforce tenant authorization check (CWE-639 / IDOR)\n  const userRole = (requester as any).role;\n  const userIdNum = (requester as any).id;\n  if (userRole !== 'admin' && report.owner_id !== userIdNum) {\n    return {\n      status: 403,\n      body: { error: 'Forbidden: You do not have permission to view this report' }\n    };\n  }`;

    if (!fullOriginalPattern.test(norm)) {
      throw new Error('Target IDOR / Access control pattern not found in source file');
    }

    return norm.replace(fullOriginalPattern, secureReportBlock);
  },
};

export class Patcher {
  constructor(private options: PatcherOptions) {}

  /**
   * Synthesizes fix, unified diff, reverse diff, and PatchProposal for a finding.
   */
  public synthesizePatch(finding: SecurityFinding): PatchSynthesisResult {
    const rawPath = finding.location?.file_path || finding.target;
    if (!rawPath) {
      throw new Error(`Finding ${finding.finding_id} has no valid location.file_path or target`);
    }

    const relPath = path.isAbsolute(rawPath)
      ? path.relative(this.options.workspaceRoot, rawPath).replace(/\\/g, '/')
      : rawPath.replace(/\\/g, '/');

    const absPath = path.resolve(this.options.workspaceRoot, relPath);
    if (!fs.existsSync(absPath)) {
      throw new Error(`Target file not found at: ${absPath}`);
    }

    const originalContent = fs.readFileSync(absPath, 'utf8');
    let patchedContent = originalContent;

    const cwe = (finding.cwe_id || '').toUpperCase();
    if (cwe === 'CWE-89' || (!cwe && relPath.includes('search'))) {
      patchedContent = LabAppRemediationTemplates.fixSqlInjection(originalContent);
    } else if (cwe === 'CWE-78' || (!cwe && relPath.includes('diagnostics'))) {
      patchedContent = LabAppRemediationTemplates.fixCommandInjection(originalContent);
    } else if (cwe === 'CWE-639' || cwe === 'CWE-284' || (!cwe && relPath.includes('reports'))) {
      patchedContent = LabAppRemediationTemplates.fixBrokenAccessControl(originalContent);
    } else {
      throw new Error(`No deterministic remediation template available for finding ${finding.finding_id} (${finding.cwe_id})`);
    }

    if (patchedContent === originalContent) {
      throw new Error(`Remediation patch produced identical content for finding ${finding.finding_id}`);
    }

    const patch = synthesizePatchProposal(
      finding,
      originalContent,
      patchedContent,
      relPath,
      { authorEngine: this.options.authorEngine ?? 'script-kitty-remediation-engine' }
    );

    return {
      patch,
      originalContent,
      patchedContent,
      targetFile: absPath,
    };
  }

  /**
   * Applies patched content to target file and optionally re-builds workspace.
   */
  public applyPatch(synthesis: PatchSynthesisResult | PatchProposal): void {
    if ('targetFile' in synthesis && 'patchedContent' in synthesis) {
      fs.writeFileSync(synthesis.targetFile, synthesis.patchedContent, 'utf8');
    } else {
      // synthesis is a PatchProposal
      for (const relFile of synthesis.affected_files) {
        const absFile = path.resolve(this.options.workspaceRoot, relFile);
        const original = fs.readFileSync(absFile, 'utf8');
        const applied = applyUnifiedDiff(original, synthesis.diff_content);
        if (!applied.success || !applied.patchedContent) {
          throw new Error(`Failed to apply patch diff to ${absFile}: ${applied.error}`);
        }
        fs.writeFileSync(absFile, applied.patchedContent, 'utf8');
      }
    }

    if (this.options.buildAfterPatch) {
      this.rebuildWorkspace();
    }
  }

  /**
   * Recompiles lab application so that dist/ reflects patched TypeScript source.
   */
  public rebuildWorkspace(): void {
    try {
      const tscPath = path.resolve(this.options.workspaceRoot, 'node_modules', 'typescript', 'bin', 'tsc');
      const tsconfigPath = path.resolve(this.options.workspaceRoot, 'apps', 'lab-app', 'tsconfig.json');
      if (!fs.existsSync(tscPath) || !fs.existsSync(tsconfigPath)) {
        throw new Error(`Missing TypeScript compiler (${tscPath}) or tsconfig (${tsconfigPath})`);
      }
      execFileSync(process.execPath, [tscPath, '-p', tsconfigPath], {
        cwd: this.options.workspaceRoot,
        stdio: 'pipe',
        encoding: 'utf8',
        shell: false,
      });
    } catch (err: any) {
      const errorMsg = err.stderr || err.stdout || err.message;
      throw new Error(`Compilation failed after applying patch: ${errorMsg}`);
    }
  }
}

export const AstPatcher = Patcher;

export function createPatchProposal(options: PatchOptions): PatchProposal {
  return synthesizePatchProposal(
    options.finding,
    options.original_content,
    options.patched_content,
    options.target_file,
    {
      authorEngine: options.author_engine,
      baseCommit: options.base_commit,
      astImpactScope: options.ast_impact_scope,
      breakingChangeRisk: options.breaking_change_risk,
      killswitchFlag: options.killswitch_flag,
    }
  );
}

export function applyPatch(targetFileOrSource: string, patchedContentOrDiff: string): PatchApplyResult {
  if (fs.existsSync(targetFileOrSource) || (path.isAbsolute(targetFileOrSource) && !targetFileOrSource.includes('\n'))) {
    try {
      const dir = path.dirname(targetFileOrSource);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      if (patchedContentOrDiff.includes('@@')) {
        const original = fs.existsSync(targetFileOrSource) ? fs.readFileSync(targetFileOrSource, 'utf8') : '';
        const applied = applyUnifiedDiff(original, patchedContentOrDiff);
        if (!applied.success || applied.patchedContent === undefined) {
          return applied;
        }
        fs.writeFileSync(targetFileOrSource, applied.patchedContent, 'utf8');
        return { success: true, applied_files: [targetFileOrSource], patchedContent: applied.patchedContent };
      } else {
        fs.writeFileSync(targetFileOrSource, patchedContentOrDiff, 'utf8');
        return { success: true, applied_files: [targetFileOrSource], patchedContent: patchedContentOrDiff };
      }
    } catch (err: any) {
      return { success: false, applied_files: [], error: err.message || String(err) };
    }
  }
  return applyUnifiedDiff(targetFileOrSource, patchedContentOrDiff);
}
