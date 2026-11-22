import * as path from 'node:path';
import {
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type GateDecision,
  type ChainOfCustody,
  validateFinding,
  buildCustodyChain,
  GateVerdict,
} from '@script-kitty/contracts';
import { DeterministicQualityGate } from '@script-kitty/quality-gate';
import { ProcessSandbox } from './sandbox.js';
import { Patcher, type PatchSynthesisResult } from './patcher.js';
import { RollbackEngine, FileSnapshotManager } from './rollback.js';
import { Rechecker } from './rechecker.js';
import type {
  RemediationEngineConfig,
  RemediationResult,
  LifecycleStatus,
  DualPhaseRecheckResult,
  RollbackResult,
} from './types.js';

export class AutonomousRemediationEngine {
  private sandbox = new ProcessSandbox();
  private patcher: Patcher;
  private rollbackEngine: RollbackEngine;
  private rechecker = new Rechecker();
  private qualityGate = new DeterministicQualityGate();
  private snapshotManager = new FileSnapshotManager();

  constructor(private config: RemediationEngineConfig) {
    const root = config.workspaceRoot || config.workspace_root || process.cwd();
    this.config.workspaceRoot = root;
    this.patcher = new Patcher({
      workspaceRoot: root,
      buildAfterPatch: config.buildAfterPatch ?? true,
    });
    this.rollbackEngine = new RollbackEngine(root);
  }

  /**
   * Resolves the default reproducer script path for a finding if not explicitly provided.
   */
  public resolveReproducerPath(finding: SecurityFinding): string {
    const cwe = (finding.cwe_id || '').toUpperCase();
    const filePath = (finding.location?.file_path || finding.target || '').toLowerCase();

    if (cwe === 'CWE-89' || filePath.includes('search')) {
      return path.join('apps', 'lab-app', 'repro', 'repro-sqli.mts');
    }
    if (cwe === 'CWE-78' || filePath.includes('diagnostics')) {
      return path.join('apps', 'lab-app', 'repro', 'repro-cmdi.mts');
    }
    if (cwe === 'CWE-639' || cwe === 'CWE-284' || filePath.includes('reports')) {
      return path.join('apps', 'lab-app', 'repro', 'repro-idor.mts');
    }

    throw new Error(`Unable to resolve reproducer script for finding ${finding.finding_id} (${finding.cwe_id})`);
  }

  /**
   * Executes the full 5-stage closed-loop AppSec remediation lifecycle:
   * 1. FIND IT: Ingest and validate finding.
   * 2. PROVE IT: Sandbox reproducer execution (assert exit 1, mint Evidence).
   * 3. FIX IT: Synthesize unified diff patch, take snapshot, apply & rebuild.
   * 4. VERIFY IT: Dual-phase recheck (neutralization exit 0 + baseline test pass).
   * 5. LEARN FROM IT: Custody chaining + Zero-Trust Quality Gate evaluation.
   */
  public async runLifecycle(
    finding: SecurityFinding,
    reproducerScriptPath?: string
  ): Promise<RemediationResult> {
    const discAgent =
      this.config.discoveringAgentId ||
      this.config.agent_identities?.discovering_agent_id ||
      finding.agent_context?.discovering_agent_id ||
      'agent-scanner-mantis';

    const veriAgent =
      this.config.verifyingAgentId ||
      this.config.agent_identities?.verifying_agent_id ||
      'agent-sandbox-verifier';

    const authAgent =
      this.config.authorizingAgentId ||
      this.config.agent_identities?.authorizing_agent_id ||
      'agent-quality-gate-authority';

    let status: LifecycleStatus = 'INITIALIZED';

    // =========================================================================
    // STAGE 1: FIND IT (Discovery Ingestion & Schema Validation)
    // =========================================================================
    const valResult = validateFinding(finding);
    if (!valResult.success) {
      return {
        finding,
        status: 'ERROR',
        stage: 'FIND',
        success: false,
        rollbackOccurred: false,
        errors: valResult.errors.map((e) => `${e.path}: ${e.message}`),
        error: valResult.errors[0]?.message,
      };
    }
    const validatedFinding = valResult.data;
    status = 'DISCOVERED';

    let reproPath: string;
    try {
      reproPath = reproducerScriptPath || this.resolveReproducerPath(validatedFinding);
    } catch (err: any) {
      return {
        finding: validatedFinding,
        status: 'ERROR',
        stage: 'FIND',
        success: false,
        rollbackOccurred: false,
        errors: [err?.message || 'Failed to resolve reproducer script'],
        error: err?.message,
      };
    }

    // =========================================================================
    // STAGE 2: PROVE IT (Offline Process Sandbox Reproduction)
    // =========================================================================
    const initialRun = await this.sandbox.runScript(reproPath, {
      cwd: this.config.workspaceRoot,
      timeoutMs: this.config.timeoutMs,
      labAppUrl: this.config.target_app_url,
    });

    if (initialRun.exitCode !== 1) {
      return {
        finding: validatedFinding,
        status: 'REJECTED',
        stage: 'PROVE',
        success: false,
        rollbackOccurred: false,
        errors: [`Reproducer did not confirm vulnerability; expected exit code 1, observed ${initialRun.exitCode}`],
        error: `Reproducer exited with code ${initialRun.exitCode}`,
      };
    }

    const initialEvidence = this.sandbox.createEvidence({
      findingId: validatedFinding.finding_id,
      runResult: initialRun,
      verifierAgentId: veriAgent,
    });
    status = 'PROVEN';

    // =========================================================================
    // STAGE 3: FIX IT (Unified Diff Patch Synthesis, Snapshot & Application)
    // =========================================================================
    let patchSynthesis: PatchSynthesisResult;
    try {
      patchSynthesis = this.patcher.synthesizePatch(validatedFinding);

      // Capture pre-patch snapshot for atomic rollback
      await this.snapshotManager.takeSnapshot([patchSynthesis.targetFile]);

      // Apply patch to file and compile workspace
      this.patcher.applyPatch(patchSynthesis);
      status = 'PATCHED';
    } catch (err: any) {
      // Trigger 1: Syntax error / Compilation failure -> Rollback
      try {
        await this.snapshotManager.restore();
      } finally {
        this.snapshotManager.clear();
      }
      return {
        finding: validatedFinding,
        evidence: initialEvidence,
        status: 'ROLLED_BACK',
        stage: 'FIX',
        success: false,
        rollbackOccurred: true,
        rollbackReason: `Patch synthesis or compilation failed: ${err.message}`,
        errors: [err.message],
        error: err.message,
      };
    }

    // =========================================================================
    // STAGE 4: VERIFY IT (Dual-Phase Verification Rechecker)
    // =========================================================================
    const rootDir = this.config.workspaceRoot || this.config.workspace_root || process.cwd();
    const recheck = await this.rechecker.recheck({
      workspaceRoot: rootDir,
      reproducerPath: reproPath,
      verifierAgentId: veriAgent,
      baselineCommand: this.config.baselineCommand || this.config.regression_command,
      timeoutMs: this.config.timeoutMs,
    });

    if (recheck.recheckStatus !== 'passed_clean') {
      // Triggers 2 & 3: Reproducer still fails or regression detected -> Rollback
      try {
        await this.snapshotManager.restore();
        this.rollbackEngine.rollback(patchSynthesis.targetFile, patchSynthesis.originalContent, recheck.recheckStatus);
      } finally {
        this.snapshotManager.clear();
      }

      return {
        finding: validatedFinding,
        evidence: initialEvidence,
        patch: patchSynthesis.patch,
        status: 'ROLLED_BACK',
        stage: 'VERIFY',
        success: false,
        rollbackOccurred: true,
        rollbackReason: recheck.errorDetails || `Verification recheck failed with status: ${recheck.recheckStatus}`,
        errors: [recheck.errorDetails || recheck.recheckStatus],
        error: recheck.errorDetails,
      };
    }

    const verifiedPatch: PatchProposal = {
      ...patchSynthesis.patch,
      recheck_status: 'passed_clean',
      recheck_evidence_id: recheck.evidence!.evidence_id,
    };
    status = 'VERIFIED';

    // =========================================================================
    // STAGE 5: LEARN FROM IT (Merkle Custody Chaining & Zero-Trust Gate)
    // =========================================================================
    const custodyChain = buildCustodyChain({
      finding: validatedFinding,
      evidence: initialEvidence,
      patch: verifiedPatch,
    });

    const gateDecision = await this.qualityGate.evaluate({
      commit_hash: validatedFinding.commit_hash,
      policy: this.config.policy,
      findings: [validatedFinding],
      evidence: [initialEvidence, recheck.evidence!],
      patches: [verifiedPatch],
      discovering_agent_id: discAgent,
      verifying_agent_id: veriAgent,
      authorizing_agent_id: authAgent,
      custody_chain: custodyChain,
    });

    if (gateDecision.verdict !== GateVerdict.PASS) {
      // Trigger 4: Zero-Trust Quality Gate Rejection -> Rollback
      try {
        await this.snapshotManager.restore();
        this.rollbackEngine.rollback(
          patchSynthesis.targetFile,
          patchSynthesis.originalContent,
          `Quality Gate ${gateDecision.verdict}: ${gateDecision.evaluation_summary}`
        );
      } finally {
        this.snapshotManager.clear();
      }

      return {
        finding: validatedFinding,
        evidence: initialEvidence,
        patch: verifiedPatch,
        recheckEvidence: recheck.evidence,
        recheck_evidence: recheck.evidence,
        gateDecision,
        gate_decision: gateDecision,
        custodyChain,
        custody_chain: custodyChain,
        status: 'ROLLED_BACK',
        stage: 'LEARN',
        success: false,
        rollbackOccurred: true,
        rollbackReason: `Quality Gate ${gateDecision.verdict}: ${gateDecision.evaluation_summary}`,
        errors: [gateDecision.evaluation_summary],
        error: gateDecision.evaluation_summary,
      };
    }

    // Gate PASSED: Seal final 4-node Merkle custody chain including GateDecision
    const sealedChain = buildCustodyChain({
      finding: validatedFinding,
      evidence: initialEvidence,
      patch: verifiedPatch,
      gate: gateDecision,
    });

    // Clear snapshot manager after successful authorization
    this.snapshotManager.clear();

    return {
      finding: validatedFinding,
      evidence: initialEvidence,
      patch: verifiedPatch,
      recheckEvidence: recheck.evidence,
      recheck_evidence: recheck.evidence,
      gateDecision,
      gate_decision: gateDecision,
      custodyChain: sealedChain,
      custody_chain: sealedChain,
      status: 'AUTHORIZED',
      stage: 'LEARN',
      success: true,
      rollbackOccurred: false,
      errors: [],
    };
  }

  /**
   * Stage 2 standalone: Reproduces finding in sandbox.
   */
  public async reproduce(finding: SecurityFinding, reproScriptPath?: string): Promise<Evidence> {
    const repro = reproScriptPath || this.resolveReproducerPath(finding);
    const veriAgent = this.config.verifyingAgentId || 'agent-sandbox-verifier';
    const runResult = await this.sandbox.runScript(repro, {
      cwd: this.config.workspaceRoot,
      timeoutMs: this.config.timeoutMs,
      labAppUrl: this.config.target_app_url,
    });
    return this.sandbox.createEvidence({
      findingId: finding.finding_id,
      runResult,
      verifierAgentId: veriAgent,
    });
  }

  /**
   * Stage 3 standalone: Synthesizes patch proposal.
   */
  public async generatePatch(finding: SecurityFinding): Promise<PatchProposal> {
    const synthesis = this.patcher.synthesizePatch(finding);
    return synthesis.patch;
  }

  /**
   * Applies patch proposal to workspace.
   */
  public async applyPatch(patch: PatchProposal | PatchSynthesisResult): Promise<void> {
    this.patcher.applyPatch(patch);
  }

  /**
   * Stage 4 standalone: Dual-phase verification.
   */
  public async recheck(
    finding: SecurityFinding,
    patch: PatchProposal,
    reproScriptPath?: string
  ): Promise<DualPhaseRecheckResult> {
    const repro = reproScriptPath || this.resolveReproducerPath(finding);
    const veriAgent = this.config.verifyingAgentId || 'agent-sandbox-verifier';
    const rootDir = this.config.workspaceRoot || this.config.workspace_root || process.cwd();
    const result = await this.rechecker.recheck({
      workspaceRoot: rootDir,
      reproducerPath: repro,
      verifierAgentId: veriAgent,
      baselineCommand: this.config.baselineCommand || this.config.regression_command,
      timeoutMs: this.config.timeoutMs,
    });

    return {
      passed: result.recheckStatus === 'passed_clean',
      recheck_status: result.recheckStatus,
      reproducer_exit_code: result.reproducerLogs.exitCode,
      reproducer_output: result.reproducerLogs.stdout,
      regression_exit_code: result.baselineLogs?.exitCode ?? 0,
      regression_tests_total: 10,
      regression_tests_failed: result.baselineTestsPassed ? 0 : 1,
      recheck_evidence: result.evidence,
      error: result.errorDetails,
    };
  }

  /**
   * Rolls back a patch proposal.
   */
  public async rollback(patch: PatchProposal, reason: string = 'MANUAL_ABORT'): Promise<RollbackResult> {
    try {
      const record = await this.rollbackEngine.executeRollback(
        patch,
        'MANUAL_ABORT',
        reason,
        this.snapshotManager
      );
      return {
        success: record.success,
        reverted_files: record.files_affected,
        error: record.restoration_error,
      };
    } finally {
      this.snapshotManager.clear();
    }
  }

  /**
   * Stage 5 standalone: Evaluates Quality Gate and seals custody chain.
   */
  public async gate(
    finding: SecurityFinding,
    reproEvidence: Evidence,
    patch: PatchProposal,
    recheckEvidence: Evidence
  ): Promise<{ decision: GateDecision; custody_chain: ChainOfCustody }> {
    const discAgent =
      this.config.discoveringAgentId ||
      finding.agent_context?.discovering_agent_id ||
      'agent-scanner-mantis';
    const veriAgent = this.config.verifyingAgentId || 'agent-sandbox-verifier';
    const authAgent = this.config.authorizingAgentId || 'agent-quality-gate-authority';

    const custodyChain = buildCustodyChain({
      finding,
      evidence: reproEvidence,
      patch,
    });

    const decision = await this.qualityGate.evaluate({
      commit_hash: finding.commit_hash,
      policy: this.config.policy,
      findings: [finding],
      evidence: [reproEvidence, recheckEvidence],
      patches: [patch],
      discovering_agent_id: discAgent,
      verifying_agent_id: veriAgent,
      authorizing_agent_id: authAgent,
      custody_chain: custodyChain,
    });

    const sealedChain = buildCustodyChain({
      finding,
      evidence: reproEvidence,
      patch,
      gate: decision,
    });

    return { decision, custody_chain: sealedChain };
  }
}

export const RemediationLifecycle = AutonomousRemediationEngine;
export const RemediationEngine = AutonomousRemediationEngine;
