# ScriptKitty Live: Phase 0 Implementation Plan & Real Module Inventory

**Product:** ScriptKitty Live · **Agent:** PatchCat · **Main capability:** ChainBreak
**Inspection date:** 2026-11-21 (≈10:18 BRT) · **Host:** Windows, PowerShell 5.1, Node `v22.23.2`, npm `10.9.8`, Python `3.13.x`, no `cargo`, no Docker daemon
**Repo root:** `c:\Users\adm\Desktop\Prototipos\Script Kitty` · **Git HEAD:** `f1c334f` (2026-07-25, pre-event) plus an **uncommitted** working tree. See [`../PROVENANCE.md`](../PROVENANCE.md).

> [!IMPORTANT]
> This inventory comes from reading files on disk, the workspace manifests (`package.json`), and the most recent independent verification run (board #78, `verifier-4`, 2026-11-21 08:25 BRT). Those test counts are a **snapshot**. Treat them as stale until `npm run gates` regenerates `evidence/gate-report.json` against the current HEAD SHA. If a count below disagrees with the gate report, the gate report wins.

---

## 1. Classification legend

| Status | Meaning |
|---|---|
| `WORKS_WITH_TEST` | Source is present, it builds, and an automated test command passed in the last verified run. |
| `PARTIAL` | Source is present, but part of the behaviour is unverified on this host or depends on unfinished Phase 1 work. |
| `STUB/MOCK` | A deterministic local substitute runs in place of a real external system. The substitute is labelled `MOCK` / `NOT_CONFIGURED` / `LAB_SIMULATION`. |
| `NOT_PRESENT` | Referenced somewhere, but absent from disk at inspection time. |

---

## 2. Workspace inventory (npm workspaces `apps/*`, `packages/*`)

| Module | Path | Status | Test command | Last observed | Direct deps (runtime) | Integration risk |
|---|---|---|---|---|---|---|
| `@script-kitty/contracts` | `packages/contracts/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/contracts` | 91/91 | `zod` | Low. Zero-side-effect schema root; every package depends on it. |
| `@script-kitty/chainbreak` | `packages/chainbreak/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/chainbreak` | 18/18 | `contracts`, `zod` | Low. Fixtures in `fixtures/payments-lab/*.json` are the demo's source of truth. Changing them changes the 0/1/0/0 path counts. |
| `@script-kitty/quality-gate` | `packages/quality-gate/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/quality-gate` | 29/29 | `contracts`, `zod` | Low. `INCONCLUSIVE` must never be rendered as `PASS`. |
| `@script-kitty/company-context` | `packages/company-context/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/company-context` | 4/4 | `zod`, `node:sqlite` | Medium. Uses experimental `node:sqlite` (Node ≥ 22). Demos must use `:memory:` or temp paths. |
| `@script-kitty/jev-judge` (advisory review) | `packages/jev-judge/` | `WORKS_WITH_TEST` (offline) / `STUB/MOCK` (provider) | `npm test --workspace=@script-kitty/jev-judge` | 4/4 | `zod`, native `fetch` | Medium. The live provider needs `TYPESAFE_API_KEY` (**NOT_CONFIGURED**). The output is advisory only and never decides P0. |
| `@script-kitty/security-actions` | `packages/security-actions/` | `WORKS_WITH_TEST` (5 tools) / `PARTIAL` (Phase 1 expansion) | `npm test --workspace=@script-kitty/security-actions` | 4/4 | `@modelcontextprotocol/sdk`, `contracts`, `zod` | **High.** The loopback MCP Streamable HTTP transport lives here. `mcp-kali-core` is adding `security.audit.*`, `security.evidence.get` and `security.kali.*` (board #81). Tool-list assertions in `scripts/demo-wednesday.mjs` (L538-L539) and `scripts/start-live-demo.mjs` may pin the exact list. |
| `@script-kitty/kali-mcp-assessment` | `packages/kali-mcp-assessment/` | `WORKS_WITH_TEST` (`LAB_SIMULATION`) / `STUB/MOCK` (live container) | `npm test --workspace=@script-kitty/kali-mcp-assessment` | 16/16 | `@modelcontextprotocol/sdk`, `contracts`, `quality-gate`, `security-actions`, `zod` | **High.** `LIVE_CONTAINER` fails closed with `KALI_SANDBOX_UNAVAILABLE` (no OCI/gVisor/WSL2 sandbox on host). Phase 1 adds the `LAB_SYNTHETIC` profile. |
| `@script-kitty/runtime-guardian` | `packages/runtime-guardian/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/runtime-guardian` | 168/168 | `@modelcontextprotocol/sdk`, `contracts`, `quality-gate`, `zod` | Low. Runs with `--test-concurrency=1`. |
| `@script-kitty/remediation-engine` | `packages/remediation-engine/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/remediation-engine` | 32/32 (~111 s) | `contracts`, `quality-gate`, `zod` | Medium. Slowest suite; Windows CPU contention can push it towards the 180 s limit. |
| `@script-kitty/adapters` | `packages/adapters/` | `WORKS_WITH_TEST` (normalizers) / `STUB/MOCK` (live engines) | `npm test --workspace=@script-kitty/adapters` | 75/75 | `contracts`, `zod` | Medium. Every live external engine is `NOT_CONFIGURED` or `DISABLED_BY_FLAG` by default. |
| `@script-kitty/evidence` | `packages/evidence/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/evidence` | 11/11 | `chainbreak`, `contracts`, `zod`, `node:sqlite` | Low. Tenant-isolated ledger with Merkle bundles. |
| `@script-kitty/patchcat-orchestrator` | `packages/patchcat-orchestrator/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/patchcat-orchestrator` | 6/6 | 7 internal packages + `zod` | Medium. Widest fan-in; breaks first when exports change. |
| `@script-kitty/verification-suite` | `packages/verification-suite/` | `WORKS_WITH_TEST` | `npm run verify` (= `node packages/verification-suite/tests/run-all.mts`) | 121/121 (Tiers 1–7) | `contracts`, `zod` | Medium. Tier 6/7 may assert exact tool lists and artifact paths. |
| `@script-kitty/lab-app` | `apps/lab-app/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/lab-app` | 10/10 | none (`node:http`, `node:sqlite`) | Policy. **Intentionally vulnerable** (`CWE-89`, `CWE-78`, `CWE-639`). Loopback only; never deploy. |
| `@script-kitty/cli` | `apps/cli/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/cli` | 4/4 | `commander`, `chalk` | Low. Legacy v1 subcommands (`scout`, `patch`, …) are `NOT_PRESENT`. |
| `@script-kitty/mcp-server` | `apps/mcp-server/` | `WORKS_WITH_TEST` | `npm test --workspace=@script-kitty/mcp-server` | 6/6 | `@modelcontextprotocol/sdk`, `zod` | Low. stdio transport; HTTP lives in `security-actions`. |
| `@script-kitty/ui` (Live Console) | `apps/ui/` | `WORKS_WITH_TEST` / `PARTIAL` (Phase 1 redesign) | `npm test --workspace=@script-kitty/ui` | 6/6 | `@openuidev/lang-core`, `motion` | **High.** `frontend-landing` is redesigning it (board #82). `ui-controller.test.mts` checks exact selectors and text. `scripts/record-demo-video.mjs` drives `#tab-unsafe-rollout`, `#btn-pr-suggest`, `#btn-toggle-self-cert`, `#btn-pr`, `#panel-*`, `#details-receipt-*` and `window.__PATCHCAT_CONTROLLER__`. |
| `vercel-app` (public landing) | `vercel-app/` (not an npm workspace) | `PARTIAL` | `npm run build` inside `vercel-app/` (`tsc && vite build`) | not in root `npm test` | `vite`, `typescript` (dev) | Medium. **No public deploy configured** (`HUMAN_APPROVAL_REQUIRED`). The `build` script uses `&&`, which is fine inside npm but not in PowerShell 5.1. |

## 3. Non-npm modules

| Module | Path | Status | Test command | Last observed | Integration risk |
|---|---|---|---|---|---|
| Python packages (`scanners`, `validators`, `remediation`, `agent_runtime`, `plugin_sdk`) | `packages/<name>/` (no `package.json`) | `WORKS_WITH_TEST` | `npm run test:python` | 20/20 | Low. Pre-event origin, modified post-event (see provenance). |
| Rust crates (`policies`, `audit`) | `packages/policies/`, `packages/audit/` | `PARTIAL` | `cargo test` | **not run** (no `cargo` on host) | Do not claim these as working. Equivalent guarantees are verified in TypeScript (`contracts`, `quality-gate`). |
| Payments Lab fixtures | `fixtures/payments-lab/{baseline,unsafe-rollout,remediated,negative-control}.json` | `WORKS_WITH_TEST` | covered by `chainbreak` tests and `npm run demo` | 0/1/0/0 forbidden paths, 3/3 legit ops | Synthetic data only (`LAB_SYNTHETIC`). |
| CLI demo (10 stages) | `scripts/demo-wednesday.mjs` | `WORKS_WITH_TEST` | `npm run demo` | 10/10 stages | Asserts the exact MCP tool list. Must be updated together with `security-actions`. |
| Live loopback launcher | `scripts/start-live-demo.mjs` | `WORKS_WITH_TEST` | `node scripts/start-live-demo.mjs --check --ui-port=0 --mcp-port=0` | `"check": "PASS"` | Owned by `mcp-kali-core` in Phase 1. The default token `sk-live-demo-token-2026` is a **loopback-only LAB token**, not a secret. |
| Demo video recorder | `scripts/record-demo-video.mjs` | `WORKS_WITH_TEST` (previous render: 150.0 s, 1920×1080) | `node --check scripts/record-demo-video.mjs`; full render by `gates-runner` | syntax OK | Needs host `ffmpeg`/`ffprobe`/Chromium and a pt-BR SAPI voice. This render is a **product walkthrough, not the team video**. |
| Quality gates runner (`G00–G14`) | `scripts/run-quality-gates.mjs`, `package.json#scripts.gates` | `WORKS_WITH_TEST` | `npm run gates` / `node --check scripts/run-quality-gates.mjs` | syntax OK | Emits `evidence/gate-report.json` and redacted artifacts; executed in Phase B after implementation tasks finish. |
| Impeccable visual detector | `C:/Users/adm/.agents/skills/impeccable/scripts/detect.mjs` | `WORKS_WITH_TEST` | `node C:/Users/adm/.agents/skills/impeccable/scripts/detect.mjs --json` | installed | Invoked by Gate G09 against `apps/ui` and `vercel-app` HTML/CSS/TS files (`[]` required). |
| Root container | `Dockerfile`, `.dockerignore` | `PARTIAL` | `docker build .` | **not run** (no daemon) | Inspected structurally only. |
| Kali sandbox manifests | `packages/kali-mcp-assessment/docker/*`, `docker-compose.kali-lab.yml` | `PARTIAL` | Tier 7 structural checks and Python `TestHardenedKaliSandboxArtifacts` | structural pass | `docker build` / `compose up` not executed. |

## 4. NOT_PRESENT or Awaiting Phase 1 / Human Action

| Item | Expected path | Owner (Phase 1 / Human) | Notes |
|---|---|---|---|
| Final Gate Report & Evidence Logs | `evidence/gate-report.json`, `evidence/*.json` | `gates-runner` | Generated when `npm run gates` runs in Phase B (`evidence/DEMO_RUNBOOK.md` is already present). |
| Brand lockup & avatar SVGs/PNG | `assets/brand/patchcat-lockup-horizontal.svg`, `assets/brand/patchcat-avatar.png` | `brand-mascot` | Referenced by `README.md` and `scripts/record-demo-video.mjs` (which includes a fallback SVG lockup if rendered before `assets/brand/` lands). |
| Public HTTPS deploy | none (`PUBLIC_DEMO_URL`) | **human** | `HUMAN_APPROVAL_REQUIRED` / `NOT_CONFIGURED`. |
| Competition repo content | `github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026` | **human** | Empty public repo (created 2026-11-21T12:22:37Z). Push needs approval; see `PROVENANCE.md`. |
| Team video (≤180 s, 4 members on camera) | none (`PUBLIC_VIDEO_URL`) | **human team** | Script is in [`SUBMISSION_PACK.md`](SUBMISSION_PACK.md). The auto-rendered product walkthrough does **not** satisfy this requirement. |
| `apps/server` backend | referenced in `.dotstack` | none | `NOT_PRESENT` — superseded by the `security-actions` HTTP transport. |
| `@typesafe-ai/sdk` package | none | none | `NOT_PRESENT` — a clean-room `fetch` client is used instead. |
| Legacy CLI subcommands (`scout`, `patch`, `recheck`, `verify-guardrails`, `mcp install`) | `apps/cli/src/index.ts` | none | `NOT_PRESENT` — replaced by `audit`, `scan-secrets`, `scan-headers`, `auth`, `chainbreak`, `judge`, `status`. |

## 5. Dependency & license summary (direct third-party, from `node_modules/*/package.json`)

| Package | Version installed | License | Used by |
|---|---|---|---|
| `@modelcontextprotocol/sdk` | 1.32.2 | MIT | `security-actions`, `mcp-server`, `runtime-guardian`, `kali-mcp-assessment` |
| `zod` | 3.25.76 | MIT | most workspaces |
| `commander` | 12.1.0 | MIT | `apps/cli` |
| `chalk` | 4.1.2 | MIT | `apps/cli` |
| `@openuidev/lang-core` | 1.1.1 | MIT | `apps/ui` |
| `motion` | 14.14.0 | MIT | `apps/ui` |
| `vite` | 5.4.21 | MIT | `apps/ui`, `vercel-app` |
| `typescript` | 5.9.3 | Apache-2.0 | build toolchain |

Project license: MIT ([`../LICENSE`](../LICENSE)). Ecosystem and pattern attributions are in [`../NOTICE.md`](../NOTICE.md). Before any public push, run `npm audit --omit=dev --json`; gate G10 records it.

## 6. Cross-cutting integration risks (Phase 1 watch list)

1. **Tool-list drift.** Expanding `SECURITY_CAPABILITY_IDS` can break exact-array assertions in `scripts/demo-wednesday.mjs`, `scripts/start-live-demo.mjs`, Tier 6/7 of `verification-suite`, and `apps/mcp-server` tests.
2. **UI selector drift.** Redesigning `apps/ui` can break `ui-controller.test.mts` and the CDP-driven video recorder. Both depend on the IDs listed in §2.
3. **Copy discipline.** Internal engine names must stay out of product-facing copy (hero, nav, captions), but they still exist in code identifiers and terminal output. Do not rename package identifiers just to hide them; document them under architecture/provenance instead.
4. **Provenance.** Pre-event commits (2026-07-25) and post-event work share one working tree. A clean export needs human approval (see `PROVENANCE.md` §4).
5. **External credentials.** `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `CLOUDFLARE_API_TOKEN`, `MANTIS_RUNNER`, `QUALITY_ENGINE_URL`, `PUBLIC_DEMO_URL`, `PUBLIC_VIDEO_URL` are all unset, so the related surfaces must report `NOT_CONFIGURED` / `BLOCKED`.
6. **Windows shell.** Use `;` plus `if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }`. Never use `&&` in PowerShell 5.1 command lines.

## 7. Phase plan

| Phase | Scope | Owner | Exit criterion |
|---|---|---|---|
| 0 | Inventory, claims matrix, provenance, AGENTS, README, submission pack, runbook | `docs-governance` | These documents exist and are consistent with each other |
| 1a | MCP tool expansion and Kali `LAB_SYNTHETIC` | `mcp-kali-core` | Builds and tests green; `start-live-demo --check` PASS |
| 1b | Landing and Live Console redesign (EN/PT/ES) | `frontend-landing` | `npm test --workspace=@script-kitty/ui` green; `detect.mjs` `[]` |
| 1c | Brand lockup and mascot | `brand-mascot` | `assets/brand/*.svg` present |
| 2 | Gates G00–G14, evidence, video re-render | `gates-runner` | `evidence/gate-report.json` with honest `overallVerdict` |
| 3 | Push, deploy, team video, form submission | **humans** | Every box in the `SUBMISSION_PACK.md` §5 checklist ticked |
