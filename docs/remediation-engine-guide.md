# `@script-kitty/remediation-engine` — Closed-Loop Remediation Guide

**Package:** [`packages/remediation-engine`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/index.ts)  
**Key Exports:** [`AutonomousRemediationEngine`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/lifecycle.ts#L25-L428) (aliases `RemediationLifecycle`, `RemediationEngine`), [`ProcessSandbox`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/sandbox.ts#L19-L480) (`SandboxRunner`, `OfflineLocalSandbox`), [`Patcher`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L286-L390) (`AstPatcher`), [`LabAppRemediationTemplates`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L236-L284), [`Rechecker`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rechecker.ts#L15-L100) (`DualPhaseRechecker`), [`FileSnapshotManager`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rollback.ts#L20-L94), [`RollbackEngine`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rollback.ts#L99-L336).

---

## 1. Overview & Purpose

The Autonomous Remediation Engine closes the operational gap between finding a vulnerability and merging a mathematically proven, regression-free patch. Rather than emitting unverified markdown advice, [`AutonomousRemediationEngine.runLifecycle`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/lifecycle.ts#L71-L298) orchestrates a deterministic five-stage state machine where **no fix is authorized unless an independent verifier confirms exploit neutralization, full baseline suite passage, Tri-Party Separation of Duties (SoD), and unbroken RFC 8785 custody**.

```text
  Stage 1: FIND        Stage 2: PROVE        Stage 3: FIX          Stage 4: VERIFY        Stage 5: LEARN
┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Validate     │───▶│ ProcessSandbox   │───▶│ FileSnapshot +   │───▶│ DualPhaseRecheck │───▶│ Custody Chain +  │
│ Finding      │    │ Reproducer Run   │    │ Synthesize Diff  │    │ Phase A: PoC=0   │    │ Quality Gate     │
│ (Zod Schema) │    │ (Assert exit 1)  │    │ + Rebuild Target │    │ Phase B: Suite=0 │    │ (SoD + Merkle)   │
└──────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘
                            │ fails                 │ fails                 │ fails                 │ non-PASS
                            ▼                       ▼                       ▼                       ▼
                        REJECTED               ROLLED_BACK             ROLLED_BACK             ROLLED_BACK
                      (no fix run)          (Trigger 1: Syntax)    (Triggers 2 & 3)        (Trigger 4: Gate)
```

---

## 2. The Five Lifecycle Stages

### Stage 1 — `FIND`: Schema Validation & Reproducer Resolution
1. [`validateFinding`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/index.ts#L74-L80) parses the incoming [`SecurityFinding`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/finding.ts#L99-L142) against canonical Zod rules (valid `finding_id`, `CWE-<n>`, OWASP 2021/2023/LLM 2025 category, 64-char `fingerprint`, git `commit_hash`, ISO-8601 `discovered_at`). Malformed inputs immediately return `{ status: 'ERROR', stage: 'FIND', success: false }`.
2. [`resolveReproducerPath`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/lifecycle.ts#L46-L61) accepts an explicit reproducer script path or maps canonical CWE/route patterns to `apps/lab-app/repro/repro-{sqli,cmdi,idor}.mts`. Status transitions to `DISCOVERED`.

### Stage 2 — `PROVE`: Offline Sandboxed Exploit Reproduction
1. [`ProcessSandbox.runScript`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/sandbox.ts#L30-L168) hashes the reproducer file (`scriptSha256`) and spawns `process.execPath` directly (no shell) under strict containment:
   * **Network/Proxy Scrubbing:** Strips `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, and `CURL_PROXY`; sets `SCRIPTKITTY_OFFLINE='1'` and `NO_PROXY='*'`.
   * **Minimal Env Allowlist:** Forwards only required OS runtime variables (`PATH`, `SYSTEMROOT`, `TEMP`, `HOME`, etc.) plus optional `LAB_APP_URL`; cloud tokens and `.env` secrets are stripped.
   * **Bounded Runtime & Buffers:** Caps `stdout` and `stderr` at `1 MiB` each; enforces `timeoutMs` (default `30,000 ms`) with `SIGKILL` returning exit code `124`.
2. **Pre-Patch Exploit Contract:** The initial run MUST exit with code `1` (`VULNERABILITY_CONFIRMED`). Exit `0` or `2` halts the pipeline fail-closed (`status: 'REJECTED', stage: 'PROVE'`), ensuring false positives never trigger code modifications.
3. [`ProcessSandbox.createEvidence`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/sandbox.ts#L310-L372) mints a canonical [`Evidence`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/evidence.ts#L147-L199) record (`VERIFIED_TRUE_POSITIVE`) bound to `verifierAgentId` and `computeEvidenceChainHash(...)`. Status transitions to `PROVEN`.

### Stage 3 — `FIX`: Unified Diff Synthesis, Snapshot & Target Rebuild
1. [`Patcher.synthesizePatch`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L292-L339) applies a deterministic source transformation from [`LabAppRemediationTemplates`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L236-L284):
   * Uses `diff.structuredPatch` in [`generateUnifiedDiff`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L28-L59) and [`generateReverseDiff`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L66-L97) so forward and inverse unified diffs are mathematically symmetrical with normalized LF line endings.
   * Computes [`calculateBlastRadius`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L102-L136) (`files_modified`, `lines_added`, `lines_deleted`, `ast_impact_scope` defaulting to `'LOCAL_FUNCTION'`, `breaking_change_risk` defaulting to `'LOW'`).
   * Populates `rollback_plan` with `revert_patch`, `compensating_controls: ['restore_file_snapshot']`, `killswitch_flag: 'DISABLE_FIX_CWE_<n>'`, and `automated_rollback_trigger`.
2. Before writing any byte to disk, [`FileSnapshotManager.takeSnapshot`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rollback.ts#L26-L50) captures exact original UTF-8 file contents and their SHA-256 digest.
3. [`Patcher.applyPatch`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L344-L363) writes the transformed code and invokes [`rebuildWorkspace`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L368-L389) (`tsc -p apps/lab-app/tsconfig.json`) when `buildAfterPatch !== false` so compiled `dist/` artifacts immediately reflect the patch. Status transitions to `PATCHED`.

### Stage 4 — `VERIFY`: Dual-Phase Regression Recheck
[`Rechecker.recheck`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rechecker.ts#L23-L97) executes two strictly ordered checks:
* **Phase A — Exploit Neutralization:** Re-runs the Stage 2 reproducer script against the rebuilt application. Exit code MUST be `0` (`EXPLOIT_NEUTRALIZED`). Any non-zero exit yields `recheckStatus: 'reproducer_still_fails'`.
* **Phase B — Functional Non-Regression:** Executes `options.baselineCommand` (default: `node --test apps/lab-app/tests/baseline.test.mts`). Exit code MUST be `0` across all 10 baseline functional assertions. Failure yields `recheckStatus: 'regression_detected'`.
* When both phases pass cleanly, a post-patch verification `Evidence` record (`REFUTED_FALSE_POSITIVE` post-fix) is minted and linked via `recheck_evidence_id` on `verifiedPatch` with `recheck_status: 'passed_clean'`. Status transitions to `VERIFIED`.

### Stage 5 — `LEARN`: Cryptographic Custody Chain & Zero-Trust Gate
1. [`buildCustodyChain`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts#L364-L474) hashes `finding` (Node 0) -> `initialEvidence` (Node 1) -> `verifiedPatch` (Node 2) from `GENESIS_HASH` and computes the Merkle root.
2. [`DeterministicQualityGate.evaluate`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/engine.ts#L79-L551) verifies:
   * Tri-Party SoD ($A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$); note that if a caller passes identical discoverer and verifier IDs, the gate **fails closed with `REJECT`** and triggers rollback.
   * Pre-patch and post-patch evidence validity, unexpired policy exceptions, scope containment, and intact custody chain.
3. On `GateVerdict.PASS`, [`runLifecycle`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/lifecycle.ts#L272-L297) seals a final **4-node custody chain** appending Node 3 (`GATE`), clears temporary snapshots, and returns `{ status: 'AUTHORIZED', stage: 'LEARN', success: true, rollbackOccurred: false }`.

---

## 3. Patch Synthesis & Four Automated Rollback Triggers

Every failure after Stage 2 automatically restores disk state and recompiles `apps/lab-app` so no broken or unverified patch remains applied:

| # | Trigger Constant ([`RollbackTrigger`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/types.ts#L217-L223)) | Pipeline Stage | Condition | Recovery Mechanism |
|---|---|---|---|---|
| 1 | `SYNTAX_ERROR` / `PATCH_SYNTAX_ERROR` | `FIX` | Patch template mismatch or TypeScript compilation (`tsc`) error | [`FileSnapshotManager.restore()`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rollback.ts#L55-L79) verifies SHA-256 hash post-write |
| 2 | `REPRODUCER_STILL_FAILS` | `VERIFY` (Phase A) | Post-patch reproducer exits non-zero (vulnerability persists) | `snapshotManager.restore()` + [`RollbackEngine.rollback()`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rollback.ts#L157-L181) rebuild |
| 3 | `REGRESSION_DETECTED` | `VERIFY` (Phase B) | One or more functional baseline tests fail after patching | `snapshotManager.restore()` + rebuild; returns `status: 'ROLLED_BACK'` |
| 4 | `GATE_REJECTED` | `LEARN` | Quality Gate returns `REJECT`, `BLOCK`, `REQUIRES_HUMAN_APPROVAL`, or `ERROR` (e.g., SoD violation, tampered chain, expired exception) | Full snapshot restore + `tsc` rebuild + custody/gate diagnostics returned |
| — | `MANUAL_ABORT` | Explicit API | Caller invokes `engine.rollback(patch, reason)` or [`RollbackEngine.executeRollback`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/rollback.ts#L248-L321) | Strategy 1: SHA-256 snapshot restore; Strategy 2 fallback: `revert_patch` reverse unified diff via `applyUnifiedDiff` |

---

## 4. `apps/lab-app` Synthetic Target Walkthrough

The [`@script-kitty/lab-app`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/index.ts) Node/SQLite (`node:sqlite` `DatabaseSync`) service intentionally contains three reproducible vulnerability classes and 10 baseline functional tests ([`baseline.test.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/tests/baseline.test.mts)):

| Vulnerability | Route File | Reproducer Script | Vulnerable Pattern -> Remediated Code | Baseline Preservation |
|---|---|---|---|---|
| **SQL Injection (`CWE-89`)** | [`search.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/routes/search.ts) | [`repro-sqli.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/repro/repro-sqli.mts) (UNION credential dump + `' OR 1=1 --`) | Template interpolation ``LIKE '%${query}%'`` -> parameterized SQL `LIKE ?` bound with `stmt.all(pattern, pattern)` | Baselines 2–5 (`Gateway`, `firewall`, empty query=3 rows, non-match=0 rows) remain `200 OK` |
| **OS Command Injection (`CWE-78`)** | [`diagnostics.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/routes/diagnostics.ts) | [`repro-cmdi.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/repro/repro-cmdi.mts) (`127.0.0.1 & echo CANARY`) | Unvalidated `targetHost` passed to `execSync` -> strict `HOSTNAME_REGEX = /^[a-zA-Z0-9.-]+$/` allowlist rejecting shell metacharacters with `'ERROR'` status | Baseline 6 (`127.0.0.1`) succeeds cleanly |
| **Broken Access Control / IDOR (`CWE-639`)** | [`reports.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/routes/reports.ts) | [`repro-idor.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/repro/repro-idor.mts) (Alice user `2` fetches Bob's restricted report `102`) | Authenticated via `x-user-id` only -> enforces `userRole !== 'admin' && report.owner_id !== userIdNum` returning `403 Forbidden` | Baselines 7–10 (Alice reads `101`, admin `1` reads `102`, missing header=`401`, missing report=`404`) pass |

---

## 5. Minimal Usage Example

```ts
import * as path from 'node:path';
import { AutonomousRemediationEngine } from '@script-kitty/remediation-engine';
import { computeFindingFingerprint, type SecurityFinding } from '@script-kitty/contracts';

const engine = new AutonomousRemediationEngine({
  workspaceRoot: process.cwd(),
  discoveringAgentId: 'agent-scanner-mantis',
  verifyingAgentId: 'agent-sandbox-verifier',
  authorizingAgentId: 'agent-quality-gate-authority',
  buildAfterPatch: true,
});

const finding: SecurityFinding = {
  finding_id: 'SK-FIND-LAB-SQLI-001',
  source_engine: 'mantis',
  title: 'SQL Injection in Incident Search',
  description: 'Direct template interpolation in searchIncidents SQL query',
  cwe_id: 'CWE-89',
  owasp_category: 'A03:2021-Injection',
  severity: 'CRITICAL',
  confidence: 'CERTAIN',
  target_type: 'SOURCE_CODE',
  target: 'apps/lab-app/src/routes/search.ts',
  location: { file_path: 'apps/lab-app/src/routes/search.ts', start_line: 13, end_line: 15 },
  fingerprint: computeFindingFingerprint({
    cwe_id: 'CWE-89',
    file_path: 'apps/lab-app/src/routes/search.ts',
    rule_or_match: 'searchIncidents-rawSql',
  }),
  commit_hash: 'a'.repeat(40),
  discovered_at: new Date().toISOString(),
  agent_context: { discovering_agent_id: 'agent-scanner-mantis', tool_call_trace: [] },
  raw_metadata: {},
};

const result = await engine.runLifecycle(finding);
// result.status === 'AUTHORIZED', result.custodyChain.total_nodes === 4
```

---

## 6. Known Operational Boundaries & Honest Limitations

1. **Template-Scoped Patch Synthesis:** [`LabAppRemediationTemplates`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L236-L284) currently matches the three synthetic `apps/lab-app/src/routes/*.ts` patterns deterministically. General arbitrary repositories require custom `applyPatch` diffs or future AST-rewriter integrations before entering Stages 4 and 5.
2. **Process vs. OS Container Sandbox:** `ProcessSandbox` provides offline environment scrubbing, direct binary spawning without shell, output truncation, and `SIGKILL` deadlines inside the local host OS; stronger kernel/network namespace isolation requires container/micro-VM sandboxing (see [KALI_MCP_ARCHITECTURE_PLAN.md](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/docs/KALI_MCP_ARCHITECTURE_PLAN.md)).
3. **Diagnostic Command Template Security Note:** Note that in [`LabAppRemediationTemplates.fixCommandInjection`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L256-L267), defense relies on strict `HOSTNAME_REGEX` allowlist validation (`^[a-zA-Z0-9.-]+$`) prior to executing `ping`; future hardening should also migrate `diagnostics.ts` from `execSync` to argv-array `execFileSync`.
