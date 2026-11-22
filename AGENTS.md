# AGENTS.md — ScriptKitty Live Engineering, Security & QA Invariants

**Product:** ScriptKitty Live  
**Autonomous Security Agent:** PatchCat  
**Primary Capability:** ChainBreak (Deterministic Policy-Graph & Attack-Path Reachability)  
**Companion Capabilities:** Continuous Security Audit · Verified Remediation · Agent & MCP Security  
**Operating Mode:** `LAB` (`productionTested: false`, `mergeAllowed: false`, `deployAllowed: false`, `externalExecution: false`)

---

## 1. Windows PowerShell 5.1 Execution Invariant (CRITICAL)

This workspace runs on **Windows with PowerShell 5.1** as the default command shell.
- **NEVER use `&&` to chain commands in PowerShell 5.1** (it causes a parser error in Windows PowerShell 5.1).
- Always chain sequential commands using `; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }`:

```powershell
npm run build; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; npm test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

---

## 2. Fail-Closed Security & Engineering Invariants

Every agent, contributor, and automated workflow operating in this repository MUST preserve these non-negotiable security rules:

1. **Absence Is Never Passage (Fail-Closed Everywhere):**
   - Missing Bearer tokens (`HTTP 401`), disallowed `Origin` headers (`HTTP 403`), cross-tenant lookups (`FORBIDDEN`), missing `sourceRef` or hash mismatches, expired policy exceptions (`expires < todayUtc`), unconfigured external API credentials (`TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `CLOUDFLARE_API_TOKEN`, `MANTIS_RUNNER`, `QUALITY_ENGINE_URL`), or unavailable container sandboxes (`KALI_SANDBOX_UNAVAILABLE`) MUST evaluate to `REJECT`, `BLOCK`, `INCONCLUSIVE`, `PENDING_REVIEW`, `NOT_CONFIGURED`, or `ERROR` — **never** `PASS` or `ALLOWED`.
   - `INCONCLUSIVE` is **never** equivalent to `PASS`.
2. **Deterministic Boundary Before Any Advisory AI:**
   - Graph reachability (`@script-kitty/chainbreak`), input SHA-256 verification, schema validation (`@script-kitty/contracts`), and sandbox reproducer checks (`@script-kitty/remediation-engine`) run in deterministic TypeScript/Python code.
   - Advisory AI evaluation (`@script-kitty/jev-judge`) operates strictly on secret-scrubbed digests (`sanitizedStateDigest`), never assigns `P0` severity alone (`p0DefinedByJevAlone: false`), and escalates to mandatory human review (`status: "PENDING_REVIEW"`).
   - Unverified LLM prose is rejected by the evidence ledger (`UNVERIFIED_AI_PROSE_REJECTED`).
3. **Strict Semantic Honesty (`PATH_VALIDATED` ≠ `EXPLOIT_CONFIRMED`):**
   - ChainBreak proves deterministic policy-graph reachability (`PATH_VALIDATED`) anchored to exact `sourceRef` lines and `inputSha256`. The status `EXPLOIT_CONFIRMED` is forbidden by schema.
4. **Mathematical Tri-Party Separation of Duties (SoD):**
   - Release gates (`@script-kitty/quality-gate`) and runtime guards (`@script-kitty/runtime-guardian`) enforce $A_{\text{disc}} \ne A_{\text{veri}} \land A_{\text{veri}} \ne A_{\text{auth}} \land A_{\text{disc}} \ne A_{\text{auth}}$. Self-certification triggers immediate `REJECT` (`E_SOD_SELF_CERTIFICATION`).
5. **Loopback-Only Binding & Hardened Kali LAB Containment:**
   - Local MCP Streamable HTTP and UI demo servers bind exclusively to `127.0.0.1` (never `0.0.0.0`).
   - `@script-kitty/kali-mcp-assessment` executes strictly in `LAB_SYNTHETIC` / `LAB_SANDBOX_ONLY` mode using enumerated actions and static `--` `argv` tuples (`shell: false`). Raw shell commands (`run_command`, `execute_shell`, `raw_nmap_args`), out-of-scope domains (`evil.example`), cloud metadata IPs (`169.254.169.254`), and CLI flag injections (`--script=...`, `$(id)`) must fail closed.
6. **Permanent Non-Mutation Locks in LAB Mode:**
   - `mergeAllowed: false`, `deployAllowed: false`, `autoApplyAllowed: false`, `policyMutationAllowed: false`, `gateMutationAllowed: false`, and `externalExecution: false` must remain locked to `false`.
   - Do not modify the canonical vulnerable routes in `apps/lab-app/src/routes/{search,diagnostics,reports}.ts` outside isolated ephemeral test sandboxes.
7. **Human Approval Gate for Public Push & Deploy:**
   - Never autonomously push commits to `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026` or deploy public endpoints without explicit human review of [`PROVENANCE.md`](PROVENANCE.md) and [`docs/SUBMISSION_PACK.md`](docs/SUBMISSION_PACK.md).

---

## 3. UI, Visual System & Copy Discipline

1. **Product Naming Hierarchy:**
   - **Product:** **ScriptKitty Live**
   - **Agent:** **PatchCat**
   - **Primary Capability:** **ChainBreak**
   - **Core Pillars:** Continuous Security Audit · Verified Remediation · Agent & MCP Security
2. **No Internal Engine / Vendor Codenames in Top-Level Product Copy:**
   - Keep internal module/adapter names (`Invokta`, `JEV`, `JEV-as-a-Judge`, `Harness²`, `Mantis`, `Company Brain`, `Factory`, `TypeSafe`) **out** of top-level landing copy, navigation, hero headlines, primary console headers, and demo video captions/narration.
   - Document internal packages and upstream attributions accurately under dedicated technical architecture, collapsible technical receipts (`<details class="tech-receipt">`), and provenance sections ([`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md), [`PROVENANCE.md`](PROVENANCE.md), [`NOTICE.md`](NOTICE.md)).
3. **Visual Design & Anti-AI-Slop Rules:**
   - Color system: Dark graphite (`#0C121A` background, `#111C28` surface, `#162330` elevated surface, `#273A4D` border, `#F2F6FA` primary text, `#9DB0C1` secondary text) with ice-blue (`#79B7F3`), emerald (`#64CDB1`), violet (`#A594F9`), amber (`#EDBA6C`), and coral (`#F08589`) accents, plus `[data-theme="light"]` toggle support.
   - Typography: `IBM Plex Sans` and `IBM Plex Mono` (`font-variant-numeric: tabular-nums`). Never use `Inter`.
   - Zero gradient text (`background-clip: text`), zero neon glow blobs, zero fake macOS window dots, zero `border-left` > 1px card stripes, zero emojis inside UI buttons/tabs/headings, and card border-radius `<= 12px`.
   - All inline SVG child elements in TypeScript templates (`<path />`, `<rect />`, `<circle />`, `<polygon />`) must be self-closing so `apps/ui/tests/ui-controller.test.mts`'s `MockElement` parser passes.

---

## 4. Mandatory Verification Commands

Run these commands from the repository root (`c:\Users\adm\Desktop\Prototipos\Script Kitty`) and verify exit code `0` before declaring any task complete:

```powershell
# 1. Build all compilable workspaces and vercel-app
npm run build; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm --prefix vercel-app run build; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2. Strict TypeScript typecheck across all workspaces
npm run typecheck --workspaces --if-present; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3. Unit & integration tests across all 17 npm workspaces + Python security suite
npm test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run test:python; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 4. 7-Tier E2E & Adversarial Verification Suite (121 checks)
npm run verify; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 5. Live loopback PoC launcher self-check (UI + MCP Streamable HTTP + 401/403/CORS) & 10-stage CLI demo
node scripts/start-live-demo.mjs --check --ui-port=0 --mcp-port=0; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run demo; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 6. Automated Quality Gates (G00 through G14 -> evidence/gate-report.json)
npm run gates

# 7. UI Anti-Slop & Visual Audit Detector (must return [])
node "C:/Users/adm/.agents/skills/impeccable/scripts/detect.mjs" --json apps/ui/index.html apps/ui/src/style.css apps/ui/src/dashboard-view.ts vercel-app/index.html vercel-app/src/style.css
# (or `node impeccable/scripts/detect.mjs --json` if symlinked locally)

# 8. Demo Video Recorder Syntax Check
node --check scripts/record-demo-video.mjs; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```
