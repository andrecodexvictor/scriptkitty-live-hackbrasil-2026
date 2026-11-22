# ScriptKitty 2.0 — Empirical E2E Remediation & Verification Report

**Report Date:** `2026-11-11`  
**Target Environment:** Isolated Local `LAB` Environment (`apps/lab-app`, `fixtures/payments-lab/*`)  
**Engine Implementations:** [`@script-kitty/remediation-engine`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/index.ts), [`@script-kitty/chainbreak`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/index.ts), [`@script-kitty/verification-suite`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/verification-suite/tests/run-all.mts)  
**Operational Mode:** `LAB` (`productionTested: false`, `mergeAllowed: false`, `deployAllowed: false`)

---

## 1. Executive Summary

This report records the **empirically observed** results of executing ScriptKitty 2.0's two complementary verification pipelines:

1. **AppSec Autonomous Code Remediation (`@script-kitty/remediation-engine` on `apps/lab-app`):** End-to-end execution of the 5-stage `FIND -> PROVE -> FIX -> VERIFY -> LEARN` pipeline against three real exploitable vulnerabilities (**SQL Injection `CWE-89`**, **OS Command Injection `CWE-78`**, and **Broken Access Control / IDOR `CWE-639`**), plus negative lifecycle checks and rollback verification.
2. **AgentSec / ChainBreak Policy Graph Remediation (`@script-kitty/chainbreak` + `@script-kitty/jev-judge` + `@script-kitty/security-actions` on `fixtures/payments-lab/`):** Deterministic reachability analysis across `baseline -> unsafe-rollout -> remediated -> negative-control`, bounded advisory triage, minimal defensive `RemediationSpec` synthesis, Invokta MCP Streamable HTTP parity + fail-closed rejection checks, Tri-Party SoD gating, and `factory.delivery.v1` eligibility.
3. **Comprehensive 6-Tier Verification Suite (`node packages/verification-suite/tests/run-all.mts`):** Achieved **`112 passed / 112 total (0 failed)`** across all 6 tiers in `11,952 ms`.

---

## 2. Empirical Results: AppSec Autonomous Code Remediation (`apps/lab-app`)

### 2.1 Synthetic Vulnerable Target Specification

[`apps/lab-app`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/index.ts) runs a zero-dependency native Node `node:http` + `node:sqlite` service bound to `127.0.0.1` (`Baseline Functional Suite: 10/10 pass`) seeded with 3 test users (`admin`, `alice`, `bob`) and 3 security incident records, including admin credentials (`sk_live_admin_secret`) and a `RESTRICTED` report (`id=102`) owned by User `3` (`bob`).

### 2.2 Detailed Case Results (Observed in `lifecycle.test.mts`)

#### Case A — SQL Injection (`CWE-89` / `OWASP A03:2021-Injection`)
- **Vulnerable File:** [`apps/lab-app/src/routes/search.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/routes/search.ts) (string interpolation into `SELECT ... WHERE title LIKE '%${query}%'`)
- **Reproducer:** [`apps/lab-app/repro/repro-sqli.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/repro/repro-sqli.mts)
- **Stage 1 (`FIND`):** `SK-FINDING-LAB-SQLI-001` validated by `agent-scanner-mantis`.
- **Stage 2 (`PROVE` Pre-Patch):** Executed offline in `ProcessSandbox` (`network_isolated: true`, env stripped):
  - Payload: `' UNION SELECT id, 1, username, 'CRITICAL', role, api_key, email, created_at FROM users --`
  - **Exit Code:** `1` (`VERIFIED_TRUE_POSITIVE`)
  - **Stdout:** `VULNERABILITY_CONFIRMED: SQL Injection (CWE-89) successfully exploited in search endpoint. Evidence: Leaked admin credential token from users table via UNION SELECT.`
- **Stage 3 (`FIX` AST Diff & Rollback Synthesis):**
  ```diff
  --- a/apps/lab-app/src/routes/search.ts
  +++ b/apps/lab-app/src/routes/search.ts
  @@ -10,7 +10,8 @@
    */
   export function searchIncidents(db: DatabaseSync, query: string): Record<string, any>[] {
     // FLURRED / VULNERABLE: Direct string interpolation into raw SQL statement
  -  const rawSql = `SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE title LIKE '%${query}%' OR description LIKE '%${query}%'`;
  +  const rawSql = `SELECT id, owner_id, title, severity, classification, description, system_target, created_at FROM incidents WHERE title LIKE ? OR description LIKE ?`;
  +  const pattern = `%${query}%`;
     const stmt = db.prepare(rawSql);
  -  return stmt.all();
  +  return stmt.all(pattern, pattern);
   }
  ```
  - **Blast Radius:** `files_modified: 1`, `lines_added: 3`, `lines_deleted: 2`, `ast_impact_scope: "LOCAL_FUNCTION"`, `breaking_change_risk: "LOW"`
  - **Rollback Trigger Guard:** `DISABLE_FIX_CWE_89` + mathematically exact reverse unified diff
- **Stage 4 (`VERIFY` Post-Patch + Regressions):**
  - Re-ran `repro-sqli.mts`: **Exit Code:** `0` (`REFUTED_FALSE_POSITIVE` — `"EXPLOIT_NEUTRALIZED: SQL Injection payload did not execute arbitrary SQL syntax."`)
  - Baseline functional regression suite (`10/10` tests): **`PASS` (`0` regressions)**
- **Stage 5 (`LEARN` Quality Gate & RFC 8785 Custody):**
  - Tri-Party SoD (`agent-scanner-mantis` $\ne$ `agent-sandbox-verifier` $\ne$ `agent-quality-gate-authority`): **`PASS`**
  - Verified 4-node Custody Chain (`FINDING -> EVIDENCE -> PATCH -> GATE`): **`is_valid: true`** (observed sample Merkle root: `6a9bb30360aaf767305b032ef247b5b7262e66a8d4e1edc0a03c948586369a11`).

#### Case B — OS Command Injection (`CWE-78` / `OWASP A03:2021-Injection`)
- **Vulnerable File:** [`apps/lab-app/src/routes/diagnostics.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/routes/diagnostics.ts) (`execSync(\`ping ... \${targetHost}\`)`)
- **Reproducer:** [`apps/lab-app/repro/repro-cmdi.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/repro/repro-cmdi.mts)
- **Observed E2E Result (`lifecycle.test.mts` Test 3):**
  - Pre-patch payload `127.0.0.1 & echo SCRIPTKITTY_CMDI_CANARY_ECHO_CONFIRMED` echoed the canary marker -> **Exit Code `1`** (`VERIFIED_TRUE_POSITIVE`).
  - Synthesized AST patch introduced strict hostname/IP allowlist regex (`HOSTNAME_REGEX = /^[a-zA-Z0-9.-]+$/`) rejecting shell metacharacters prior to `execSync(pingCmd)`.
  - Post-patch re-execution neutralized injection (**Exit Code `0`**) and preserved legitimate `127.0.0.1` loopback ping (`Baseline 6`).
  - Quality Gate: **`PASS`**, `custodyChain.is_valid: true`, **`ok 3`** in `13.62s`.

#### Case C — Broken Access Control / IDOR (`CWE-639` / `OWASP A01:2021`)
- **Vulnerable File:** [`apps/lab-app/src/routes/reports.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/routes/reports.ts) (authenticated caller `x-user-id: 2` could read `owner_id: 3` report `102`)
- **Reproducer:** [`apps/lab-app/repro/repro-idor.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/repro/repro-idor.mts)
- **Observed E2E Result (`lifecycle.test.mts` Test 4):**
  - Pre-patch `GET /api/reports/102` as `Alice (2)` returned **`HTTP 200`** with `Bob`'s `RESTRICTED` report -> **Exit Code `1`** (`VERIFIED_TRUE_POSITIVE`).
  - Synthesized patch enforced `report.owner_id !== requester.id && requester.role !== 'admin'` -> **`HTTP 403 Forbidden`**.
  - Post-patch re-execution returned `HTTP 403` (**Exit Code `0`**) while preserving `Alice`'s access to report `101` and `Admin` access to report `102` (`Baseline 7 & 8`).
  - Quality Gate: **`PASS`**, `custodyChain.is_valid: true`, **`ok 4`** in `12.12s`.

#### Case D — Negative Lifecycle & Rollback Mechanics (`32/32` Clean Run in `111.2s`)
- **Test 5 (Invalid Finding Rejected at `FIND`):** Malformed `INVALID_ID_WITHOUT_PREFIX` / `NOT_A_CWE` failed immediately at schema gate (`status: 'ERROR'`, `stage: 'FIND'`, zero disk modifications) -> **`ok 5`** in `6.42s`.
- **Test 6 (False Positive Rejected at `PROVE`):** Non-reproducing script exiting `0` halted pipeline cleanly (`status: 'REJECTED'`, `stage: 'PROVE'`, zero patches synthesized) -> **`ok 6`** in `6.30s`.
- **Test 7 (SoD Violation at `LEARN` Triggers Rollback):** Passing identical discoverer and verifier identities triggered `REJECT` at Quality Gate and bit-for-bit rollback of patched `apps/lab-app` -> **`ok 7`** in `22.98s` (total `lifecycle.test.mts` `7/7` in `103.15s`).
- **Rollback, Sandbox & Adversarial Stress Suites (`25/25` additional tests):** Suite 1 (`adversarial-stress.test.mts`: `11/11` in `1.81s`), Suite 3 (`8/8` in `0.09s` covering Trigger 1 Syntax/Hunk Rejection, Trigger 2 Reproducer Failure, Trigger 3 Regression Failure, Trigger 4 Quality Gate Rejection, and mathematically symmetric reverse unified diffs), and Suite 4 (`6/6` in `2.14s` verifying `ProcessSandbox` env scrubbing, exit codes, and `SIGKILL` timeout tracking) bring `@script-kitty/remediation-engine` to **`32/32` passing across `8` suites** (`exit 0`). *(Note: under heavy parallel workspace CPU load on Windows, `lifecycle.test.mts` spawns can run close to its `180,000 ms` suite cap.)*

---

## 3. Empirical Results: Payments Lab ChainBreak Governance (`scripts/demo-wednesday.mjs`)

| Screen State / Gate | Analysis ID / Contract ID | Forbidden Paths | Legitimate Ops Preserved | Governance Outcome |
|---|---|---|---|---|
| `payments-lab/baseline` | `cb-39d04f81814395a1` | `0` | `3 / 3` (`true`) | Clean Baseline (`COMPLETED`) |
| `payments-lab/unsafe-rollout` | `cb-6b09ceec48ab6b21` | `1` (`path-4bb9497d66bd3024`) | N/A | **`PATH_VALIDATED`** (`P1`, policy `NO_RESTRICTED_DATA_EXTERNAL_TRANSFER`, edge `e-rollout-exporter-read-pii` @ `report-exporter-rollout.yaml#L24`) |
| `security.judge.evaluate` | `jev-4ba1ec26bcdd03da` | — | — | `status: PENDING_REVIEW`, `providerStatus: NOT_CONFIGURED`, `decisionSource: MOCK`, `p0DefinedByJevAlone: false` |
| `security.remediation.spec` | `rem-1831f4a4aa2e733b` | Targets `e-rollout-exporter-read-pii` | `3 / 3` (`true`) | Minimal `REMOVE_EDGE`, `requiresHumanApproval: true`, `autoApplyAllowed: false` |
| `payments-lab/remediated` | `cb-b04ba60ed258d095` | **`0`** (`1 -> 0`) | **`3 / 3` (`true`)** | Unauthorized PII path severed without business breakage |
| `payments-lab/negative-control` | `cb-4f3a138c21a72a32` | `0` | N/A | Mismatched edge types / unsatisfied conditions produce `0` paths |
| `DeterministicQualityGate` (Tri-Party) | `SK-GATE-...` | `0` | — | **`PASS`** (`sodValid: true`, 3-node RFC 8785 custody `valid: true`) |
| `DeterministicQualityGate` (Self-Cert) | — | — | — | **`REJECT`** (`E_SOD_SELF_CERTIFICATION`) |
| `factory.delivery.v1` | `factory.delivery.v1` | — | — | `eligible: true`, `stage: "approved"`, **`mergeAllowed: false`**, **`deployAllowed: false`** |
| `@script-kitty/kali-mcp-assessment` (Stage 9) | `SK-EVID-KALI-...` | 4 tools (`LAB_SIMULATION`) | — | Zero-shell static `argv`, IMDS/flag-injection blocked, `LIVE_CONTAINER` fails closed (`KALI_SANDBOX_UNAVAILABLE`), SoD `E_SOD_SELF_CERTIFICATION` blocked vs Tri-Party `VERIFIED_TRUE_POSITIVE` |

---

## 4. Comprehensive 6-Tier Verification Suite Breakdown

Executed cleanly via `node packages/verification-suite/tests/run-all.mts`:

| Tier | Suite Focus | Tests Passed | Total | Duration | Verdict |
|---|---|---|---|---|---|
| **Tier 1** | Core Evidence Data Contracts & Cryptographic Custody (RFC 8785, Merkle proofs) | `23` | `23` | `916 ms` | **PASS** |
| **Tier 2** | Execution Boundaries, Secret Redaction & Deterministic Zero-Trust Quality Gate | `28` | `28` | `1,621 ms` | **PASS** |
| **Tier 3** | Security Engine Adapters Interface Compliance & Fail-Closed Mock Execution | `18` | `18` | `1,216 ms` | **PASS** |
| **Tier 4** | Real-World E2E AppSec (SQLi) & AgentSec (MCP Confused Deputy) Pipelines | `10` | `10` | `1,035 ms` | **PASS** |
| **Tier 5** | Adversarial Exploit Scenarios & Zero-Trust Stress Harness | `23` | `23` | `1,432 ms` | **PASS** |
| **Tier 6** | Integrated ScriptKitty 2.0 & PatchCat Live E2E Pipeline (incl. Harness², OWASP Skills, `@script-kitty/kali-mcp-assessment`, Quality Engine loopback, ChainBreak, JEV, Company Brain, Invokta MCP HTTP) | `10` | `10` | `5,729 ms` | **PASS** |
| **TOTAL** | **All 6 Verification Tiers** | **`112`** | **`112`** | **`11,952 ms`** | **PASS (`0` failed, exit `0`)** |

---

## 5. Honest Operational Conclusion

ScriptKitty 2.0's deterministic verification, remediation, MCP runtime defense, Kali assessment guardrails (`LAB_SIMULATION`), policy-graph (`ChainBreak`), Invokta MCP Streamable HTTP boundary, and cryptographic Merkle gate primitives all pass across every TypeScript package, application (`@script-kitty/cli` `4/4`, `@script-kitty/mcp-server` `6/6`, `@script-kitty/ui` `6/6`), and end-to-end suite in isolated **`LAB`** mode without external secrets or production mutations (`@script-kitty/runtime-guardian` `168/168` across `46` suites, `@script-kitty/remediation-engine` `32/32` across `8` suites, `@script-kitty/kali-mcp-assessment` `16/16` across `5` suites, `@script-kitty/verification-suite` `112/112` across Tiers 1–6, `node scripts/demo-wednesday.mjs` `9/9`). Live container execution (`LIVE_CONTAINER` fails closed with `KALI_SANDBOX_UNAVAILABLE`), `docker build` (unexecuted without host Docker daemon), `NOT_CONFIGURED` / `DISABLED_BY_FLAG` external runners, uncompiled Rust crates (`cargo` absent on host), and legacy Python stubs remain transparently disclosed in [`docs/IMPLEMENTATION_INVENTORY.md`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/docs/IMPLEMENTATION_INVENTORY.md).
