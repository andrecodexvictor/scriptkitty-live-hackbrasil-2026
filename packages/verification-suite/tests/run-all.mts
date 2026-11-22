/**
 * @file packages/verification-suite/tests/run-all.mts
 * @description Unified Test Runner for ScriptKitty 2.0 Verification Suite.
 * Executes all 7 test tiers (Contracts, Boundaries, Adapters, Scenarios, Adversarial, PatchCat Live E2E, Full Architecture)
 * and produces a comprehensive summary report with structured metrics.
 */

import { spawn } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TestTierConfig {
  name: string;
  tierNumber: number;
  filePath: string;
  description: string;
}

const TIERS: TestTierConfig[] = [
  {
    name: 'Tier 1: Core Evidence Data Contracts & Cryptographic Custody',
    tierNumber: 1,
    filePath: path.join(__dirname, 'tier1-contracts.test.mts'),
    description: 'Schema validation, round-trip serialization, strict type compliance, missing field rejection, and binary Merkle trees',
  },
  {
    name: 'Tier 2: Execution Boundaries, Secret Redaction & Zero-Trust Gate',
    tierNumber: 2,
    filePath: path.join(__dirname, 'tier2-boundaries.test.mts'),
    description: 'Wall-clock timeouts, secret sanitization, size budgets, unverified evidence rejection, and SoD self-certification checks',
  },
  {
    name: 'Tier 3: Security Engine Adapters Interface Compliance & Mock Execution',
    tierNumber: 3,
    filePath: path.join(__dirname, 'tier3-adapters.test.mts'),
    description: 'Interface compliance, mock execution, output contract mapping, and error isolation for Mantis, Codex, Cloudflare, and Quality Engine',
  },
  {
    name: 'Tier 4: Real-World End-to-End Security Pipelines (AppSec & AgentSec)',
    tierNumber: 4,
    filePath: path.join(__dirname, 'tier4-scenarios.test.mts'),
    description: 'AppSec SQLi remediation lifecycle and AgentSec MCP Confused Deputy runtime protection with SoD resolution',
  },
  {
    name: 'Tier 5: Adversarial Exploit Scenarios & Zero-Trust Stress Harness',
    tierNumber: 5,
    filePath: path.join(__dirname, 'adversarial-exploits.test.mts'),
    description: 'Adversarial exploit scenarios: unverified findings, inconclusive reproducers, SoD evasion, expired policies, and Merkle root tampering',
  },
  {
    name: 'Tier 6: Integrated ScriptKitty 2.0 & PatchCat Live E2E Pipeline',
    tierNumber: 6,
    filePath: path.join(__dirname, 'tier6-patchcat-live.test.mts'),
    description: 'Full integration of extended adapters (Harness², OWASP Skills, Kali Lab & @script-kitty/kali-mcp-assessment, Quality Engine loopback), Remediation Engine, Runtime Guardian, ChainBreak, JEV-as-a-Judge, Company Brain, and Invokta MCP Streamable HTTP into Deterministic Quality Gate',
  },
  {
    name: 'Tier 7: Full Architecture Verification (@script-kitty/evidence, PatchCat Orchestrator, Python Suite & Kali Sandbox)',
    tierNumber: 7,
    filePath: path.join(__dirname, 'tier7-full-architecture.test.mts'),
    description: 'EvidenceLedger tenant isolation & binary Merkle bundles, PatchCatOrchestrator event-to-ZenPR loop & fail-closed governance/SoD, Python 20-test unittest discovery, and rootless Kali Dockerfile/seccomp/compose isolation verification',
  },
];

interface TierResult {
  tier: TestTierConfig;
  passed: boolean;
  testCount: number;
  passCount: number;
  failCount: number;
  durationMs: number;
  stdout: string;
  stderr: string;
}

function runTier(tier: TestTierConfig): Promise<TierResult> {
  return new Promise((resolve) => {
    const start = Date.now();
    const proc = spawn(process.execPath, ['--test', tier.filePath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => {
      stdout += d.toString();
    });

    proc.stderr.on('data', (d) => {
      stderr += d.toString();
    });

    proc.on('close', (code) => {
      const durationMs = Date.now() - start;
      const passed = code === 0;

      // Parse TAP test metrics
      const testsMatch = stdout.match(/# tests (\d+)/);
      const passMatch = stdout.match(/# pass (\d+)/);
      const failMatch = stdout.match(/# fail (\d+)/);

      const testCount = testsMatch ? parseInt(testsMatch[1], 10) : 0;
      const passCount = passMatch ? parseInt(passMatch[1], 10) : (passed ? testCount : 0);
      const failCount = failMatch ? parseInt(failMatch[1], 10) : (passed ? 0 : 1);

      resolve({
        tier,
        passed,
        testCount,
        passCount,
        failCount,
        durationMs,
        stdout,
        stderr,
      });
    });
  });
}

async function main() {
  console.log('='.repeat(80));
  console.log(' SCRIPTKITTY 2.0 AUTONOMOUS SECURITY ENGINEERING PLATFORM');
  console.log(' Comprehensive Synthetic Verification & E2E Test Suite Runner');
  console.log('='.repeat(80));
  console.log(`Node.js Version: ${process.version}`);
  console.log(`Execution Mode : Production-Authentic (Zero Facades, Strict Invariants)`);
  console.log(`Timestamp      : ${new Date().toISOString()}`);
  console.log('='.repeat(80));
  console.log('');

  const results: TierResult[] = [];
  let totalTests = 0;
  let totalPassed = 0;
  let totalFailed = 0;
  const overallStart = Date.now();

  for (const tier of TIERS) {
    process.stdout.write(`Executing Tier ${tier.tierNumber}: ${tier.name}... `);
    const result = await runTier(tier);
    results.push(result);

    totalTests += result.testCount;
    totalPassed += result.passCount;
    totalFailed += result.failCount;

    if (result.passed) {
      console.log(`[PASS] (${result.testCount} tests, ${result.durationMs}ms)`);
    } else {
      console.log(`[FAIL] (${result.failCount} failed, ${result.durationMs}ms)`);
    }
  }

  const overallDuration = Date.now() - overallStart;

  console.log('');
  console.log('='.repeat(80));
  console.log(' TEST EXECUTION SUMMARY REPORT');
  console.log('='.repeat(80));

  for (const r of results) {
    const statusIcon = r.passed ? '✓ PASS' : '✗ FAIL';
    console.log(`Tier ${r.tier.tierNumber}: [${statusIcon}] ${r.tier.name}`);
    console.log(`  Tests   : ${r.passCount} passed / ${r.testCount} total (${r.durationMs}ms)`);
    console.log(`  Scope   : ${r.tier.description}`);
    if (!r.passed) {
      console.log(`  STDERR  : ${r.stderr || r.stdout.slice(-500)}`);
    }
  }

  console.log('-'.repeat(80));
  console.log(`Total Tiers Executed : ${results.length}`);
  console.log(`Total Tests Executed : ${totalTests}`);
  console.log(`Total Tests Passed   : ${totalPassed}`);
  console.log(`Total Tests Failed   : ${totalFailed}`);
  console.log(`Overall Duration     : ${overallDuration}ms`);
  console.log('='.repeat(80));

  if (totalFailed === 0) {
    console.log(' VERDICT: ALL TEST SUITES PASSED CLEANLY (100% PASS RATE, EXIT CODE 0)');
    console.log('='.repeat(80));
    process.exit(0);
  } else {
    console.error(' VERDICT: TEST SUITE FAILED WITH DISCOVERED REGRESSIONS');
    console.log('='.repeat(80));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal test runner execution failure:', err);
  process.exit(1);
});
