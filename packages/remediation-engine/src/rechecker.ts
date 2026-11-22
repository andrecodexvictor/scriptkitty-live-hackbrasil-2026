import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { ProcessSandbox } from './sandbox.js';
import { VerificationType } from '@script-kitty/contracts';
import type {
  RecheckOptions,
  RecheckResult,
  DualPhaseRecheckResult,
  SecurityFinding,
  Evidence,
} from './types.js';

const execAsync = promisify(exec);

export class Rechecker {
  private sandbox = new ProcessSandbox();

  /**
   * Dual-phase verification:
   * Phase A: Re-executes the reproducer script. Exit code 0 proves exploit neutralization.
   * Phase B: Runs the baseline regression test suite. Exit code 0 proves 100% preservation of legitimate behavior.
   */
  public async recheck(options: RecheckOptions): Promise<RecheckResult> {
    // Phase A: Exploit Neutralization Recheck
    const reproResult = await this.sandbox.runScript(options.reproducerPath, {
      cwd: options.workspaceRoot,
      timeoutMs: options.timeoutMs ?? 30000,
    });

    const reproducerNeutralized = reproResult.exitCode === 0;

    if (!reproducerNeutralized) {
      return {
        recheckStatus: 'reproducer_still_fails',
        reproducerPassed: false,
        baselineTestsPassed: false,
        reproducerLogs: reproResult,
        errorDetails: `Reproducer did not confirm neutralization; exited with code ${reproResult.exitCode}`,
      };
    }

    // Phase B: Baseline Non-Regression Recheck
    const baseCmd = options.baselineCommand || 'node --test apps/lab-app/tests/baseline.test.mts';
    let baselinePassed = false;
    let baselineLogs = { exitCode: 0, stdout: '', stderr: '', durationMs: 0 };
    const startBase = Date.now();

    try {
      const { stdout, stderr } = await execAsync(baseCmd, { cwd: options.workspaceRoot });
      baselineLogs = {
        exitCode: 0,
        stdout: stdout || '',
        stderr: stderr || '',
        durationMs: Date.now() - startBase,
      };
      baselinePassed = true;
    } catch (err: any) {
      baselineLogs = {
        exitCode: err.code || 1,
        stdout: err.stdout || '',
        stderr: err.stderr || err.message,
        durationMs: Date.now() - startBase,
      };
      baselinePassed = false;
    }

    if (!baselinePassed) {
      return {
        recheckStatus: 'regression_detected',
        reproducerPassed: true,
        baselineTestsPassed: false,
        reproducerLogs: reproResult,
        baselineLogs,
        errorDetails: `Baseline test suite failed with exit code ${baselineLogs.exitCode}`,
      };
    }

    // Both Phase A and Phase B passed clean: mint recheck Evidence contract
    const findingIdMatch = options.reproducerPath.match(/repro-([a-z]+)\.mts/);
    const findingId = findingIdMatch ? `FINDING-${findingIdMatch[1].toUpperCase()}` : 'RECHECK-FINDING';

    const evidence = this.sandbox.createEvidence({
      findingId,
      runResult: reproResult,
      verifierAgentId: options.verifierAgentId,
      verificationType: VerificationType.REPRODUCER_EXECUTION,
    });

    return {
      recheckStatus: 'passed_clean',
      reproducerPassed: true,
      baselineTestsPassed: true,
      evidence,
      reproducerLogs: reproResult,
      baselineLogs,
    };
  }
}

export const DualPhaseRechecker = Rechecker;
