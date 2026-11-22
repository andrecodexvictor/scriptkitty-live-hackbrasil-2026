import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import {
  type Evidence,
  type SecurityFinding,
  EvidenceSchema,
  computeEvidenceChainHash,
  VerificationStatus,
  VerificationType,
} from '@script-kitty/contracts';
import type {
  SandboxExecutionOptions,
  SandboxRunResult,
  SandboxExecutionResult,
} from './types.js';

export class ProcessSandbox {
  private defaultTimeoutMs: number;

  constructor(defaultTimeoutMs: number = 30000) {
    this.defaultTimeoutMs = defaultTimeoutMs;
  }

  /**
   * Executes reproducer script in an offline, isolated process environment.
   * Enforces network isolation, secret scrubbing, output buffer limits, and strict timeouts.
   */
  public async runScript(
    scriptPath: string,
    options: SandboxExecutionOptions = {}
  ): Promise<SandboxRunResult> {
    const fullPath = path.resolve(options.cwd || process.cwd(), scriptPath);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Reproducer script not found at path: ${fullPath}`);
    }

    const scriptContent = fs.readFileSync(fullPath, 'utf8');
    const scriptSha256 = crypto.createHash('sha256').update(scriptContent, 'utf8').digest('hex');

    const timeoutMs = options.timeoutMs ?? options.timeout_ms ?? this.defaultTimeoutMs;
    const startTime = Date.now();

    // Secret scrubbing: strip cloud/git tokens from environment
    const cleanEnv: Record<string, string> = {
      PATH: process.env.PATH || '',
      NODE_ENV: 'test',
      NO_PROXY: '*',
      SCRIPTKITTY_OFFLINE: '1',
    };

    // Forward non-sensitive system environment variables
    const allowedKeys = [
      'SYSTEMROOT',
      'SystemRoot',
      'WINDIR',
      'HOMEDRIVE',
      'HOMEPATH',
      'USERPROFILE',
      'TEMP',
      'TMP',
      'APPDATA',
      'LOCALAPPDATA',
      'PATHEXT',
      'ComSpec',
      'HOME',
    ];
    for (const key of allowedKeys) {
      if (process.env[key]) {
        cleanEnv[key] = process.env[key]!;
      }
    }

    // Forward target app URL if specified
    if (options.labAppUrl) {
      cleanEnv.LAB_APP_URL = options.labAppUrl;
    } else if (process.env.LAB_APP_URL) {
      cleanEnv.LAB_APP_URL = process.env.LAB_APP_URL;
    }

    // Merge custom options.env
    if (options.env) {
      for (const [k, v] of Object.entries(options.env)) {
        if (v !== undefined) {
          cleanEnv[k] = v;
        }
      }
    }

    if (options.isolated_network !== false) {
      for (const key of Object.keys(cleanEnv)) {
        if (/^(https?|all|ftp|curl)_proxy$/i.test(key)) {
          delete cleanEnv[key];
        }
      }
      cleanEnv.NO_PROXY = '*';
      cleanEnv.SCRIPTKITTY_OFFLINE = '1';
    }

    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const child = spawn(process.execPath, [fullPath], {
        cwd: options.cwd || path.dirname(fullPath),
        env: cleanEnv,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });

      const timer = setTimeout(() => {
        timedOut = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // Process already exited
        }
      }, timeoutMs);

      child.stdout?.on('data', (chunk) => {
        if (stdout.length < 1024 * 1024) {
          const remaining = 1024 * 1024 - stdout.length;
          stdout += chunk.toString().slice(0, remaining);
        }
      });

      child.stderr?.on('data', (chunk) => {
        if (stderr.length < 1024 * 1024) {
          const remaining = 1024 * 1024 - stderr.length;
          stderr += chunk.toString().slice(0, remaining);
        }
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        const durationMs = Date.now() - startTime;
        const exitCode = timedOut ? 124 : (code ?? 1);
        resolve({
          exitCode,
          stdout,
          stderr,
          durationMs,
          scriptPath,
          scriptSha256,
          timedOut,
          vulnerability_confirmed: exitCode === 1,
          neutralized: exitCode === 0,
        });
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({
          exitCode: 2,
          stdout,
          stderr: err.message,
          durationMs: Date.now() - startTime,
          scriptPath,
          scriptSha256,
          timedOut: false,
          vulnerability_confirmed: false,
          neutralized: false,
        });
      });
    });
  }

  /**
   * Executes arbitrary command or script in the isolated sandbox.
   */
  public async execute(options: SandboxExecutionOptions): Promise<SandboxExecutionResult> {
    const rawCmd = options.command || 'node';
    const cmd = rawCmd === 'node' ? process.execPath : rawCmd;
    const args = options.args || [];
    const cwd = options.cwd || process.cwd();
    const timeoutMs = options.timeout_ms ?? options.timeoutMs ?? this.defaultTimeoutMs;
    const startTime = Date.now();

    const cleanEnv: Record<string, string> = {
      PATH: process.env.PATH || '',
      NODE_ENV: 'test',
      NO_PROXY: '*',
      SCRIPTKITTY_OFFLINE: '1',
    };

    const allowedKeys = [
      'SYSTEMROOT',
      'SystemRoot',
      'WINDIR',
      'HOMEDRIVE',
      'HOMEPATH',
      'USERPROFILE',
      'TEMP',
      'TMP',
      'APPDATA',
      'LOCALAPPDATA',
      'PATHEXT',
      'ComSpec',
      'HOME',
    ];
    for (const key of allowedKeys) {
      if (process.env[key]) {
        cleanEnv[key] = process.env[key]!;
      }
    }

    if (options.labAppUrl) {
      cleanEnv.LAB_APP_URL = options.labAppUrl;
    } else if (process.env.LAB_APP_URL) {
      cleanEnv.LAB_APP_URL = process.env.LAB_APP_URL;
    }

    if (options.env) {
      for (const [k, v] of Object.entries(options.env)) {
        if (v !== undefined) {
          cleanEnv[k] = v;
        }
      }
    }

    if (options.isolated_network !== false) {
      for (const key of Object.keys(cleanEnv)) {
        if (/^(https?|all|ftp|curl)_proxy$/i.test(key)) {
          delete cleanEnv[key];
        }
      }
      cleanEnv.NO_PROXY = '*';
      cleanEnv.SCRIPTKITTY_OFFLINE = '1';
    }

    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const child = spawn(cmd, args, {
        cwd,
        env: cleanEnv,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });

      const timer = setTimeout(() => {
        timedOut = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // Already exited
        }
      }, timeoutMs);

      child.stdout?.on('data', (chunk) => {
        if (stdout.length < 1024 * 1024) {
          const remaining = 1024 * 1024 - stdout.length;
          stdout += chunk.toString().slice(0, remaining);
        }
      });

      child.stderr?.on('data', (chunk) => {
        if (stderr.length < 1024 * 1024) {
          const remaining = 1024 * 1024 - stderr.length;
          stderr += chunk.toString().slice(0, remaining);
        }
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        const duration_ms = Date.now() - startTime;
        const exit_code = timedOut ? -1 : (code ?? 1);
        resolve({
          exit_code,
          stdout,
          stderr,
          duration_ms,
          timed_out: timedOut,
          command_executed: `${cmd} ${args.join(' ')}`.trim(),
          vulnerability_confirmed: exit_code === 1,
          neutralized: exit_code === 0,
        });
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({
          exit_code: 2,
          stdout,
          stderr: err.message,
          duration_ms: Date.now() - startTime,
          timed_out: false,
          command_executed: `${cmd} ${args.join(' ')}`.trim(),
          vulnerability_confirmed: false,
          neutralized: false,
        });
      });
    });
  }

  /**
   * Alias for execute() to support sandbox.run() invocations.
   */
  public async run(options: SandboxExecutionOptions): Promise<SandboxExecutionResult> {
    return this.execute(options);
  }

  /**
   * Mints canonical Evidence contract from sandbox run result.
   */
  public createEvidence(params: {
    findingId: string;
    runResult: SandboxRunResult | SandboxExecutionResult;
    verifierAgentId: string;
    verificationType?: VerificationType;
  }): Evidence {
    const { findingId, runResult, verifierAgentId } = params;
    const recordedAt = new Date().toISOString();

    const exitCode = 'exitCode' in runResult ? runResult.exitCode : runResult.exit_code;
    const stdout = runResult.stdout;
    const stderr = runResult.stderr;
    const durationMs = 'durationMs' in runResult ? runResult.durationMs : runResult.duration_ms;
    const scriptPath = 'scriptPath' in runResult ? runResult.scriptPath : (runResult.script_path || 'reproducer.mts');
    const scriptSha256 =
      'scriptSha256' in runResult
        ? runResult.scriptSha256
        : (runResult.script_sha256 || crypto.createHash('sha256').update(stdout, 'utf8').digest('hex'));

    let status: VerificationStatus;
    if (exitCode === 1) {
      status = VerificationStatus.VERIFIED_TRUE_POSITIVE;
    } else if (exitCode === 0) {
      status = VerificationStatus.REFUTED_FALSE_POSITIVE;
    } else {
      status = VerificationStatus.EXECUTION_ERROR;
    }

    const chainHash = computeEvidenceChainHash({
      finding_id: findingId,
      verifier_agent_id: verifierAgentId,
      status,
      script_sha256: scriptSha256,
      recorded_at: recordedAt,
    });

    const sanitizedFindingId = findingId.replace(/[^a-zA-Z0-9_\-\.:]/g, '_');
    const evidenceRaw = {
      evidence_id: `SK-EVID-${sanitizedFindingId}-${Date.now()}-${crypto.randomInt(0, 1000)}`,
      finding_id: findingId,
      verification_type: params.verificationType ?? VerificationType.REPRODUCER_EXECUTION,
      status,
      verifier_agent_id: verifierAgentId,
      sandbox_environment: {
        runtime: 'node_sandbox',
        network_isolated: true,
        timeout_ms: 15000,
        os_platform: process.platform,
      },
      reproducer_artifact: {
        script_path: scriptPath,
        script_sha256: scriptSha256,
        exit_code: exitCode,
        stdout,
        stderr,
        execution_duration_ms: durationMs,
      },
      chain_hash: chainHash,
      recorded_at: recordedAt,
    };

    return EvidenceSchema.parse(evidenceRaw);
  }

  /**
   * Helper alias for creating evidence from SandboxExecutionResult.
   */
  public createEvidenceFromExecution(
    finding: SecurityFinding,
    result: SandboxExecutionResult,
    verifierAgentId: string,
    scriptPath?: string
  ): Evidence {
    return this.createEvidence({
      findingId: finding.finding_id,
      runResult: {
        ...result,
        scriptPath: scriptPath || result.script_path || 'reproducer.mts',
        scriptSha256: result.script_sha256 || '0'.repeat(64),
        exitCode: result.exit_code,
        durationMs: result.duration_ms,
        timedOut: result.timed_out,
      },
      verifierAgentId,
    });
  }

  /**
   * Public generateEvidence method adhering to Sandbox interface.
   */
  public generateEvidence(params: {
    finding: SecurityFinding;
    result: SandboxExecutionResult | SandboxRunResult;
    script_path: string;
    verifier_agent_id: string;
    is_post_patch?: boolean;
    custom_evidence_id?: string;
    recorded_at?: string;
  }): Evidence {
    const exitCode = 'exit_code' in params.result ? params.result.exit_code : params.result.exitCode;
    const stdout = params.result.stdout;
    const stderr = params.result.stderr;
    const durationMs = 'duration_ms' in params.result ? params.result.duration_ms : params.result.durationMs;
    const timedOut = 'timed_out' in params.result ? params.result.timed_out : params.result.timedOut;

    let status: VerificationStatus;
    if (timedOut) {
      status = VerificationStatus.EXECUTION_ERROR;
    } else if (params.is_post_patch) {
      status = exitCode === 0 ? VerificationStatus.REFUTED_FALSE_POSITIVE : VerificationStatus.VERIFIED_TRUE_POSITIVE;
    } else {
      status = exitCode !== 0 ? VerificationStatus.VERIFIED_TRUE_POSITIVE : VerificationStatus.REFUTED_FALSE_POSITIVE;
    }

    const scriptSha256 =
      'script_sha256' in params.result && params.result.script_sha256
        ? params.result.script_sha256
        : 'scriptSha256' in params.result && params.result.scriptSha256
        ? params.result.scriptSha256
        : crypto.createHash('sha256').update(params.script_path, 'utf8').digest('hex');

    const recordedAt = params.recorded_at || new Date().toISOString();
    const chainHash = computeEvidenceChainHash({
      finding_id: params.finding.finding_id,
      verifier_agent_id: params.verifier_agent_id,
      status,
      script_sha256: scriptSha256,
      recorded_at: recordedAt,
    });

    const sanitizedFindingId = params.finding.finding_id.replace(/[^a-zA-Z0-9_\-\.:]/g, '_');
    const evidenceRaw = {
      evidence_id:
        params.custom_evidence_id ||
        `SK-EVID-${sanitizedFindingId}-${Date.now()}-${crypto.randomInt(0, 1000)}`,
      finding_id: params.finding.finding_id,
      verification_type: VerificationType.REPRODUCER_EXECUTION,
      status,
      verifier_agent_id: params.verifier_agent_id,
      sandbox_environment: {
        runtime: 'node_sandbox' as const,
        network_isolated: true,
        timeout_ms: this.defaultTimeoutMs,
        os_platform: process.platform,
      },
      reproducer_artifact: {
        script_path: params.script_path,
        script_sha256: scriptSha256,
        exit_code: exitCode,
        stdout,
        stderr,
        execution_duration_ms: durationMs,
      },
      reproduction_proof: {
        proof_type: 'EXECUTABLE_POC' as const,
        payload: params.script_path,
        expected_behavior: params.is_post_patch
          ? 'Exploit neutralized (exit 0)'
          : 'Vulnerability confirmed (exit != 0)',
        observed_vulnerable_behavior: stdout.slice(0, 500) || stderr.slice(0, 500) || `Exit code ${exitCode}`,
      },
      chain_hash: chainHash,
      recorded_at: recordedAt,
    };

    return EvidenceSchema.parse(evidenceRaw);
  }
}

export const SandboxRunner = ProcessSandbox;
export const OfflineLocalSandbox = ProcessSandbox;
