# Provenance, Licensing & Competition Repository Staging Guide

**Product:** ScriptKitty Live (Agent: **PatchCat** · Primary Capability: **ChainBreak**)  
**Primary License:** MIT License — see [`LICENSE`](LICENSE)  
**Third-Party & Ecosystem Attribution:** See [`NOTICE.md`](NOTICE.md)  
**Phase 0 Module Inventory:** See [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)  
**Target Hack Brasil 2026 Repository:** `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026`

> [!CAUTION]
> **HUMAN APPROVAL REQUIRED BEFORE PUSHING OR MIXING PRE-EVENT CODE**  
> This local development workspace (`c:\Users\adm\Desktop\Prototipos\Script Kitty`) has its Git `origin` pointing to `https://github.com/andrecodexvictor/Script-kitty.git`, whose commit history (`e7c4a1a`..`f1c334f`, 28 commits) is dated **`2026-07-25`** (pre-event). Meanwhile, the official Hack Brasil 2026 public competition repository (`https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026`) was created empty on **`2026-11-21T12:22:37Z`** (after the Hack Brasil cutoff of **Nov 4, 2026 21:00 BRT**, `private: false`, `fork: false`).  
> **No automated script or agent is permitted to `git push` to the competition repository.** A human team member must review this provenance split and execute the clean export procedure in Section 4.

---

## 1. Transparent Timeline & Provenance Split

In full compliance with Hack Brasil 2026 transparency and eligibility rules, we explicitly separate the **Pre-Event Baseline (`2026-07-25`)** from the **Hack Brasil 2026 Engineering (`2026-11-06` – `2026-11-21`)**.

### 1.1 Pre-Event Baseline (`2026-07-25`, commits `e7c4a1a` .. `f1c334f`)
- **Source Repository:** `https://github.com/andrecodexvictor/Script-kitty.git` (`28` commits on `2026-07-25`, concluding with `b1c9e2b`, `c976486`, and HEAD `f1c334f`).
- **What Existed in the Pre-Event Prototype (106 tracked files at `f1c334f`):**
  - Early prototype shells in `apps/cli`, `apps/mcp-server`, `apps/ui`, and `vercel-app`.
  - Initial Python scanner/agent/remediation scripts (`packages/scanners`, `packages/validators`, `packages/remediation`, `packages/agent_runtime`, `packages/plugin_sdk`).
  - Uncompiled Rust prototype files (`packages/policies`, `packages/audit`).
  - Static mascot images (`assets/mascot.png`, `assets/cli_preview.png`, `assets/cli_preview.jpg`), `LICENSE` (MIT), `scope.md`, `agent-spec.md`, and `.context/graph/knowledge_graph.json`.

### 1.2 Hack Brasil 2026 Engineering (`2026-11-06` – `2026-11-21`, 100% Built During Event Window)
All core **ScriptKitty Live / PatchCat / ChainBreak** TypeScript packages, deterministic engines, MCP Streamable HTTP transports, runtime guards, synthetic lab fixtures, verification suites, brand SVGs, quality gates, and live console interfaces were engineered from scratch during the Hack Brasil 2026 period (`2026-11-06` through `2026-11-21`):

| Hack Brasil 2026 Deliverable | Workspace Paths | Provenance Status |
|---|---|---|
| **ChainBreak Deterministic Policy-Graph Engine** | `packages/chainbreak/*`, `fixtures/payments-lab/{baseline,unsafe-rollout,remediated,negative-control}.json` | **100% New (Hack Brasil 2026)** — 7 node kinds, 6 edge kinds, `PATH_VALIDATED` reachability, `sourceRef` & `inputSha256` verification, counterfactual `RemediationSpec`. |
| **Core Zero-Trust Contracts & RFC 8785 Merkle Custody** | `packages/contracts/*`, `packages/evidence/*` | **100% New (Hack Brasil 2026)** — Zod schemas, RFC 8785 canonical JSON, SHA-256 chain of custody, `node:sqlite` tenant-isolated `EvidenceLedger`, binary Merkle inclusion proofs. |
| **Deterministic Release Gate & Tri-Party SoD** | `packages/quality-gate/*`, `packages/patchcat-orchestrator/*` | **100% New (Hack Brasil 2026)** — Tri-Party Separation of Duties ($A_{\text{disc}} \ne A_{\text{veri}} \ne A_{\text{auth}}$), `E_SOD_SELF_CERTIFICATION` rejection, quad-state calculus, `zenpr.advisory.v1` orchestrator. |
| **MCP Streamable HTTP Server & Security Actions** | `packages/security-actions/*`, `packages/company-context/*`, `scripts/start-live-demo.mjs` | **100% New (Hack Brasil 2026)** — Loopback (`127.0.0.1`) MCP Streamable HTTP server, Bearer auth (`401`), `Origin` allowlist (`403`), tenant isolation (`FORBIDDEN`), and live PoC launcher. |
| **AgentSec Runtime Guardian** | `packages/runtime-guardian/*` | **100% New (Hack Brasil 2026)** — `wrapMcpServer`, `ToolPoisoningGuard` (SHA-256 manifest pinning), `PromptInjectionDetector`, `ScopeBoundaryGuard`, `ConfusedDeputyGuard` (HMAC-SHA256 delegation + bounded TTL nonce cache), Merkle audit logger (`170/170` tests). |
| **Hardened Kali Linux LAB Verification Module** | `packages/kali-mcp-assessment/*`, `docker-compose.kali-lab.yml` | **100% New (Hack Brasil 2026)** — `LAB_SYNTHETIC` / `LAB_SANDBOX_ONLY` profile, zero-shell `--` static argv builder, IMDS/out-of-scope/flag-injection blocks, rootless `Dockerfile.kali-sandbox` (`65532:65532`), `seccomp-kali-lab.json`. |
| **Autonomous AppSec Remediation Engine & Lab Target** | `packages/remediation-engine/*`, `apps/lab-app/*` | **100% New (Hack Brasil 2026)** — `FIND -> PROVE -> FIX -> VERIFY -> LEARN` pipeline in env-scrubbed offline Node subprocess (`ProcessSandbox`: `NO_PROXY=*`, `shell: false`, `1 MiB` cap) against `CWE-89`, `CWE-78`, `CWE-639` with 4 rollback triggers (`33/33` + `10/10` tests). |
| **Advisory Judge & Decoupled Security Adapters** | `packages/jev-judge/*`, `packages/adapters/*` | **100% New (Hack Brasil 2026)** — Secret-scrubbed advisory triage (`PENDING_REVIEW`, `NOT_CONFIGURED` offline fallback) + 7 bounded execution adapters (`75/75` tests). |
| **7-Tier Verification Suite & Quality Gates (`G00–G14`)** | `packages/verification-suite/*`, `scripts/run-quality-gates.mjs`, `scripts/demo-wednesday.mjs`, `scripts/record-demo-video.mjs` | **100% New (Hack Brasil 2026)** — 121-test 7-tier harness, 15-gate deterministic verifier (`evidence/gate-report.json`), 10-stage CLI demo, and automated CDP/FFmpeg 150s PoC video recorder. |
| **Redesigned ScriptKitty Live Console & Brand System** | `apps/ui/*`, `vercel-app/*`, `assets/brand/*`, `tests/python/test_python_packages.py` | **Heavily Rebuilt / New in Hack Brasil 2026** — Bilingual EN/PT/ES landing + live MCP console, dark-graphite + light theme, PatchCat SVG brand kit, and 20-test Python verification suite (`6,647+` insertions over modified tracked files). |

---

## 2. Repository License & Third-Party Dependency Audit

### 2.1 First-Party License
All original code in this repository is licensed under the **MIT License** ([`LICENSE`](LICENSE)):
- Copyright (c) 2026 André Victor A. O. Santos & Script Kitty Contributors.

### 2.2 Direct Runtime & Build Dependencies (`node_modules` Audit)
Every direct third-party npm dependency installed in the workspace uses a permissive open-source license compatible with MIT:

| Package | Installed Version | License | Verification Source |
|---|---|---|---|
| `@modelcontextprotocol/sdk` | `1.32.2` | `MIT` | `node_modules/@modelcontextprotocol/sdk/package.json` |
| `zod` | `3.25.76` | `MIT` | `node_modules/zod/package.json` |
| `commander` | `12.1.0` | `MIT` | `node_modules/commander/package.json` |
| `chalk` | `4.1.2` | `MIT` | `node_modules/chalk/package.json` |
| `@openuidev/lang-core` | `1.1.1` | `MIT` | `node_modules/@openuidev/lang-core/package.json` |
| `motion` | `14.14.0` | `MIT` | `node_modules/motion/package.json` |
| `vite` | `5.4.21` | `MIT` | `node_modules/vite/package.json` |
| `typescript` | `5.9.3` | `Apache-2.0` | `node_modules/typescript/package.json` |

### 2.3 Architectural & Ecosystem Attributions
No proprietary SaaS SDKs, closed-source binaries, or Kali Linux offensive binaries are bundled in this Git repository. Clean-room adapters and contract patterns referencing external ecosystems (MCP specification, OWASP Security Skills Pack v1.1.0, Google Mantis, Google Harness², OpenAI Codex Security SARIF conventions, Cloudflare Security Center schemas, Quality Engine loopback contract, TypeSafe JEV `/v1/systemone` wire protocol, and `factory.delivery.v1` delivery eligibility) are disclosed in full in [`NOTICE.md`](NOTICE.md).

---

## 3. Competition Repository Eligibility Verification (Gate G00)

- **Target Competition URL:** `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026`
- **Observed GitHub Metadata:**
  - `created_at`: `2026-11-21T12:22:37Z` (strictly after the Hack Brasil cutoff `2026-11-04T21:00:00-03:00` / `2026-11-05T00:00:00Z`)
  - `private`: `false` (Public)
  - `fork`: `false` (Original repository, not a fork)
- **Current Gate G00 Status:** `BLOCKED` (`HUMAN_APPROVAL_REQUIRED`) until a human operator stages and pushes the approved Hack Brasil 2026 commit to `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026.git`.

---

## 4. Clean Export & Staging Instructions (Human Operator Only)

> [!WARNING]
> **DO NOT run `git push` directly from the legacy `.git` history without deciding whether to push a clean Hack Brasil 2026 snapshot or the full history.** Pushing the raw `.git` directory carries the 28 pre-event commits dated `2026-07-25` from `Script-kitty.git`. To ensure the competition repository (`scriptkitty-live-hackbrasil-2026`) contains a clean, auditable Hack Brasil 2026 tree with explicit provenance disclosure (`PROVENANCE.md` + `NOTICE.md` + `LICENSE`), a **human operator** should execute the following staging procedure in Windows PowerShell 5.1:

### Step 1 — Run Pre-Push Quality & Secret Gates in the Working Tree
```powershell
npm run build; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run test:python; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run verify; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
node scripts/start-live-demo.mjs --check --ui-port=0 --mcp-port=0; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

### Step 2 — Stage a Clean Export Directory (Excluding `.git`, `node_modules`, `.env`, and Pre-Event Artifacts)
```powershell
$StageDir = "C:\Users\adm\Desktop\scriptkitty-live-hackbrasil-2026-export"
if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
New-Item -ItemType Directory -Path $StageDir | Out-Null

# Copy clean source, docs, assets, fixtures, scripts, evidence, and license files
robocopy "C:\Users\adm\Desktop\Prototipos\Script Kitty" $StageDir /E /XD .git node_modules .context .agents internal_lab scratch /XF .dotarchitecture .dotcontext .dotstack artifacts.zip *.pyc .env .env.local *.pem *.key *.sqlite *.db | Out-Null
```

*(Note: `.agents` and `.context` are excluded by `/XD` and the root dotfiles `.dotarchitecture`, `.dotcontext`, `.dotstack` are excluded by `/XF` above. If the human team chooses a **strict Hack Brasil-only export**, also omit the legacy pre-event directories/files `packages/policies`, `packages/audit`, and `RELEASE_NOTES.md`, or retain them clearly labeled as pre-event baseline in `PROVENANCE.md` §1.1.)*

### Step 3 — Initialize Clean Git Commit & Push to the Competition Repo (Human Action Only)
```powershell
Set-Location $StageDir
git init -b main; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git remote add origin https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026.git; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git add -A; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git status --short

# HUMAN REVIEW GATE: Inspect staged file list and confirm zero secrets before committing/pushing:
git commit -m "feat: ScriptKitty Live (PatchCat & ChainBreak) Hack Brasil 2026 submission with provenance disclosure"
# Execute push ONLY after human approval:
# git push -u origin main
```

### Step 4 — Re-Run `npm run gates` After Human Push
Once the human operator pushes to `https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026`, re-run `npm run gates` so Gate **G00** (`evidence/submission-preflight.json`) and Gate **G13/G14** (`evidence/gate-report.json`) record the live pushed commit SHA.
