# ScriptKitty Live (`PatchCat`) — Reproducible Demo & Cold-Start Runbook

**Product:** ScriptKitty Live  
**Agent:** PatchCat  
**Primary Capability:** ChainBreak  
**Operating Mode:** `LAB` (`productionTested: false`, `mergeAllowed: false`, `deployAllowed: false`, `autoApplyAllowed: false`, `externalExecution: false`)  
**Host Environment:** Windows PowerShell 5.1 · Node.js `>= 22.0.0` (`v22.23.2` verified) · npm `>= 10.x` (`10.9.8` verified) · Python `>= 3.11` (`3.13.x` verified)

> [!IMPORTANT]
> **Windows PowerShell 5.1 Rule:** Never use `&&` to chain commands in Windows PowerShell 5.1. Always run commands on separate lines or chain with `; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }`.

---

## 1. Cold-Start Build & Smoke Verification (60 Seconds)

From a fresh terminal in the repository root (`c:\Users\adm\Desktop\Prototipos\Script Kitty`), execute:

```powershell
# 1. Install workspace dependencies (if not already installed)
npm install; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2. Compile all 16 TypeScript workspaces + standalone vercel-app preview
npm run build; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm --prefix vercel-app run build; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3. Run automated loopback self-test (ephemeral ports, zero lingering processes)
node scripts/start-live-demo.mjs --check --ui-port=0 --mcp-port=0; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

### Expected Output from `node scripts/start-live-demo.mjs --check --ui-port=0 --mcp-port=0`
- Boots both the built **ScriptKitty Live** UI static server and the loopback **MCP Streamable HTTP** server (`@script-kitty/security-actions`) on `127.0.0.1`.
- Verifies:
  1. `GET /` on UI server returns `HTTP 200` and blocks path traversal (`HTTP 403`/`404`).
  2. `GET /api/demo-config` returns `HTTP 200` with loopback `mcpUrl` and no leaked secret token.
  3. Allowed loopback `Origin` CORS preflight (`OPTIONS /mcp`) returns `HTTP 204` with `Mcp-Session-Id` exposed.
  4. Disallowed `Origin` (`https://evil.attacker.example`) is rejected fail-closed with `HTTP 403` on both `OPTIONS` and `POST`.
  5. Missing or invalid Bearer token is rejected fail-closed with `HTTP 401`.
  6. Live MCP `initialize` -> `tools/list` -> `tools/call (security.status)` succeeds with `mode: "LAB"`, `mergeAllowed: false`, `deployAllowed: false`, and `productionTested: false`.
- Prints `{ "check": "PASS", ... }` and exits with code **`0`**, leaving zero listeners on disk or network ports.

---

## 2. Interactive Loopback Live Demo (`npm run demo:live`)

Launch the interactive **ScriptKitty Live** console paired with the loopback **MCP Streamable HTTP** server:

```powershell
npm run demo:live
```

### Default Endpoints & Loopback Credentials
- **ScriptKitty Live Console (UI):** `http://127.0.0.1:5173`
- **Loopback MCP Streamable HTTP Endpoint:** `http://127.0.0.1:3847/mcp`
- **Default LAB Session Bearer Token:** `sk-live-demo-token-2026` *(strictly for `127.0.0.1` loopback session authentication; override via `--token=<token>` or `DEMO_TOKEN`)*
- **Custom Port Flags (Optional):**
  ```powershell
  node scripts/start-live-demo.mjs --ui-port=5173 --mcp-port=3847
  ```

### Step-by-Step Interactive Browser Walkthrough
1. **Open the Console & Connect Live:**
   - Visit `http://127.0.0.1:5173` (or use `http://127.0.0.1:5173/?mcpUrl=http%3A%2F%2F127.0.0.1%3A3847%2Fmcp&token=sk-live-demo-token-2026&autoConnect=1`, which auto-connects and immediately scrubs `token` from the address bar via `history.replaceState`).
   - Confirm `#badge-connection-mode` displays **`MODE: LIVE MCP HTTP`**.
2. **State 1 — `payments-lab/baseline` (Clean Baseline):**
   - **ChainBreak** reports **`0` forbidden attack paths** and **`3/3` legitimate business operations preserved** (`op-finance-process-payments`, `op-non-sensitive-export`, `op-support-read-profile`).
   - **PatchCat** displays the calm `verified` state.
3. **State 2 — `payments-lab/unsafe-rollout` (Multi-Hop Attack Path Detected):**
   - Click the **`unsafe-rollout`** tab (`#tab-unsafe-rollout`) or press `ArrowRight` while focused on the fixture tablist.
   - **ChainBreak** detects **`1` `PATH_VALIDATED` path** (`P1`, policy `NO_RESTRICTED_DATA_EXTERNAL_TRANSFER`):
     `identity:support-agent --[can_invoke]--> mcp_tool:report-exporter --[can_read]--> data_asset:customer-payment-pii --[transfers_data_to]--> destination:external-report-sink`.
   - Expand the **Cryptographic Receipt** (`#details-receipt-chainbreak`) to inspect the exact policy `sourceRef` lines, `inputSha256`, and semantic note (`PATH_VALIDATED`, never `EXPLOIT_CONFIRMED`).
   - Inspect the **Human Risk Review** panel (`#panel-jev`): advisory triage escalates to **`PENDING_REVIEW`** (`p0DefinedByJevAlone: false`), and transparently reports `NOT_CONFIGURED` / `MOCK` when `TYPESAFE_API_KEY` is unset.
4. **State 3 — `payments-lab/remediated` (Counterfactual Verified Remediation):**
   - Click **Preview Fix Diff** (`#btn-pr-suggest`).
   - **PatchCat** synthesizes the minimal counterfactual `RemediationSpec` (`REMOVE_EDGE` on `e-rollout-exporter-read-pii`, `requiresHumanApproval: true`, `autoApplyAllowed: false`).
   - The graph re-evaluates on **`payments-lab/remediated`**, proving forbidden paths drop from **`1 -> 0`** while **`3/3`** legitimate workflows remain preserved.
5. **State 4 — Tri-Party Separation of Duties & Release Gate (`#panel-remediation-gate`):**
   - Click **Simulate Agent Self-Certification** (`#btn-toggle-self-cert`). The deterministic release gate immediately switches `#txt-gate-verdict` to **`REJECT`** (`E_SOD_SELF_CERTIFICATION`).
   - Click the toggle again to restore independent Tri-Party Separation of Duties ($A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$) and click **Validate Release Gate** (`#btn-pr`). The gate returns **`PASS`** with a 64-character hex RFC 8785 Merkle root (`#txt-merkle-root`) while `mergeAllowed: false` and `deployAllowed: false` remain enforced.
6. **Theme, Language & Accessibility Checks:**
   - Toggle Dark Graphite (`#0C121A`) / Light Theme via `#btn-toggle-theme`.
   - Switch between **EN**, **PT-BR**, and **ES** via `#select-lang`.
7. **Clean Shutdown:**
   - Press `Ctrl+C` in the terminal. Both loopback servers close cleanly and use `:memory:` SQLite so zero `.sqlite` files are left on disk.

---

## 3. 10-Stage Deterministic CLI Demo (`npm run demo`)

To run all 10 architecture verification stages in a single non-interactive terminal command:

```powershell
npm run demo; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

This executes [`../scripts/demo-wednesday.mjs`](../scripts/demo-wednesday.mjs) across:
1. `[1/10]` `security.status` fail-closed readiness check (`mode: "LAB"`, `mergeAllowed: false`, `deployAllowed: false`).
2. `[2/10]` ChainBreak `payments-lab/baseline` (`0` forbidden paths, `3/3` legit ops).
3. `[3/10]` ChainBreak `payments-lab/unsafe-rollout` (`1` `PATH_VALIDATED` path, `sourceRef`, `inputSha256`).
4. `[4/10]` Advisory Human Risk Review (`PENDING_REVIEW`, `NOT_CONFIGURED` offline fallback, `p0DefinedByJevAlone: false`).
5. `[5/10]` Counterfactual `RemediationSpec` (`REMOVE_EDGE` on `e-rollout-exporter-read-pii`).
6. `[6/10]` ChainBreak `payments-lab/remediated` (`1 -> 0` paths, `3/3` legit ops) + `payments-lab/negative-control` (`0` paths).
7. `[7/10]` Loopback MCP Streamable HTTP client call + fail-closed `401`, `403`, cross-tenant `FORBIDDEN`, and payload `tenantId` injection checks.
8. `[8/10]` Deterministic Quality Gate (`PASS` under Tri-Party SoD vs. `REJECT` under `E_SOD_SELF_CERTIFICATION`) + RFC 8785 Merkle custody.
9. `[9/10]` Hardened Kali Linux LAB Verification (`@script-kitty/kali-mcp-assessment`: static `--` argv, IMDS SSRF block, flag-injection block, `RuntimeGuardian` wrapper).
10. `[10/10]` `PatchCatOrchestrator` (`zenpr.advisory.v1`) + `EvidenceLedger` binary Merkle inclusion proof (`inclusionProofValid: true`).

---

## 4. Full Quality Gate Runner (`npm run gates`)

To execute all Hack Brasil 2026 verification gates (`G00` through `G14`) and regenerate all evidence artifacts under `evidence/`:

```powershell
npm run gates
```

### Artifacts Produced in `evidence/`
| Gate | Verification Scope | Output Artifact(s) |
|---|---|---|
| **G00** | Hack Brasil repo eligibility (`created_at > 2026-11-04T21:00:00-03:00`, public, non-fork, provenance preflight) | `evidence/submission-preflight.json` |
| **G01** | Workspace `npm run build`, `typecheck`, `npm test`, `npm run test:python`, `vercel-app` build | `evidence/build.log`, `evidence/typecheck.log`, `evidence/unit-tests.log` |
| **G02** | ChainBreak deterministic graph proof (`baseline`, `unsafe-rollout`, `remediated`, `negative-control`) | `evidence/chainbreak-baseline.json`, `evidence/chainbreak-unsafe.json`, `evidence/chainbreak-remediated.json`, `evidence/chainbreak-diff.json` |
| **G03 & G04** | Real loopback MCP Streamable HTTP client (`initialize`, `tools/list`, `tools/call`) + `401` / `403` / cross-tenant `FORBIDDEN` | `evidence/mcp-client-transcript-redacted.json` |
| **G05** | Bounded advisory risk review (`NOT_CONFIGURED` / `PENDING_REVIEW` when `TYPESAFE_API_KEY` is unset) | `evidence/judge-evaluation-redacted.json` |
| **G06 & G08** | SHA-bound Quality Gate (`INCONCLUSIVE != PASS`, `E_SOD_SELF_CERTIFICATION` reject, Tri-Party SoD pass, `1 -> 0` remediation) | `evidence/quality-engine-run-redacted.json` |
| **G07** | Kali `LAB_SYNTHETIC` verification + negative blocks (`evil.example`, `169.254.169.254`, `--script=...`, raw shell rejection) | `evidence/kali-lab-run-redacted.json` |
| **G09** | 5-viewport Chromium UI & landing audit (`1440x900`, `1280x720`, `768x1024`, `390x844`, `360x800`), EN/PT switch, keyboard nav | `evidence/screenshot-desktop.png`, `screenshot-laptop.png`, `screenshot-tablet.png`, `screenshot-mobile.png`, `screenshot-mobile-360.png` |
| **G10** | Production dependency audit (`npm audit --omit=dev`) + source secret scan + `LICENSE` & `PROVENANCE.md` check | `evidence/code-security.log`, `evidence/dependency-audit.log` |
| **G11** | Operational cold-start self-check (`start-live-demo.mjs --check`) + `npm run demo` | Recorded in `evidence/gate-report.json` |
| **G12 & G14** | Public demo URL (`PUBLIC_DEMO_URL`), public video URL (`PUBLIC_VIDEO_URL`), local MP4 `ffprobe` (`<= 180s`), freeze check | Recorded in `evidence/gate-report.json` *(honestly `BLOCKED` until human push/deploy/video upload)* |
| **G13** | Master SHA-bound gate summary report | `evidence/gate-report.json` |
