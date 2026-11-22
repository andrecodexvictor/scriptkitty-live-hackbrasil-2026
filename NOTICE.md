# Third-Party Notices, Provenance & License Verification Checklist

**Project:** ScriptKitty 2.0 / PatchCat Live (`@script-kitty/*` monorepo)  
**Primary Repository License:** MIT License — see [`LICENSE`](LICENSE)  
**Scope & Ethical Boundaries:** See [`scope.md`](scope.md) and [`docs/SECURITY_BOUNDARIES.md`](docs/SECURITY_BOUNDARIES.md)  
**Companion Technical Truth Table:** See [`docs/IMPLEMENTATION_INVENTORY.md`](docs/IMPLEMENTATION_INVENTORY.md)

---

## 1. Honest Provenance Statement

ScriptKitty 2.0 / PatchCat Live is an original, clean-room TypeScript/Python monorepo built for authorized **LAB-only** AppSec and AgentSec/MCP security verification (`mode: "LAB"`, `productionTested: false`, `mergeAllowed: false`, `deployAllowed: false`, `externalExecution: false`).

Several adapters, architectural patterns, protocol wire clients, and policy contracts in this repository interoperate with or draw inspiration from external open-source ecosystems, research publications, commercial security platforms, and hackathon starter kits. **No proprietary source code from commercial SaaS vendors is bundled or redistributed in this repository.** All external integrations default **fail-closed** (`NOT_CONFIGURED`, `MOCK`, or `DISABLED_BY_FLAG`) unless explicitly configured in an isolated operator lab.

This `NOTICE.md` documents:
1. Exact upstream provenance for all **9 referenced / integrated security ecosystems** plus container/runtime dependencies;
2. What is clean-room implemented in this repo vs. externally invoked at runtime;
3. Hard operational/security boundaries enforced by code; and
4. A concrete **Pre-Submission License & Attribution Verification Checklist** prior to public release or Hack Brasil submission.

---

## 2. Referenced & Integrated Ecosystems (9 Core Systems)

### 2.1 Google Mantis
- **Upstream Provenance:** [`github.com/google/mantis`](https://github.com/google/mantis)
- **Upstream License / Terms:** Open-source Apache-2.0 *(verify upstream `LICENSE` and `NOTICE` files before redistributing any Mantis scripts or ADK templates)*.
- **How Used Here:** Clean-room adapter normalization in [`packages/adapters/src/mantis-adapter.ts`](packages/adapters/src/mantis-adapter.ts) (`MantisAdapter`) mapping ADK hierarchical summaries, threat-model artifacts, and sandboxed crash PoCs into `@script-kitty/contracts` (`SecurityFinding`, `Evidence`, `PatchProposal`). No upstream Mantis source files are copied into this repository.
- **Runtime Status & Hard Boundaries:** Defaults fail-closed to `NOT_CONFIGURED` (`status: 'skipped'`) unless a local `MANTIS_RUNNER` / API key is explicitly provided. Strictly restricted to isolated **LAB** AppSec verification; zero production credentials; cannot bypass `DeterministicQualityGate`.

### 2.2 Google Harness²
- **Upstream Provenance:** [`github.com/google-research/harness2`](https://github.com/google-research/harness2)
- **Upstream License / Terms:** Google Research repository license *(verify exact upstream license and notice obligations prior to reusing any upstream code or prompts)*.
- **How Used Here:** Clean-room governed adapter wrapper in [`packages/adapters/src/harness2-adapter.ts`](packages/adapters/src/harness2-adapter.ts) (`Harness2Adapter`) modeling isolated strategy/memory prompt-experiment proposals. No upstream Harness² code is copied into this repository.
- **Runtime Status & Hard Boundaries:** Hard-gated off by default via `HARNESS2_EXPERIMENTS_ENABLED=false` (`DISABLED_BY_FLAG`, `mode: "LAB_ISOLATED"`). Even when explicitly enabled in offline lab benchmarks, code invariants strictly forbid mutating quality gates, `.security-pack.json`, security policies, auth/SoD rules, custody logs, credentials, or production paths (`INVARIANT_BLOCKED`).

### 2.3 OpenAI Codex Security
- **Upstream Provenance:** OpenAI Codex Security commercial platform, CLI contract, and SARIF 2.1.0 reachability conventions (`openai.com`).
- **Upstream License / Terms:** Proprietary OpenAI API / platform terms of service. **No proprietary OpenAI source code, models, or binaries are included or redistributed.**
- **How Used Here:** Clean-room SARIF 2.1.0 parser, reachability normalizer, and cost-capped CLI/API adapter in [`packages/adapters/src/codex-security-adapter.ts`](packages/adapters/src/codex-security-adapter.ts) (`CodexSecurityAdapter`).
- **Runtime Status & Hard Boundaries:** Defaults fail-closed to `NOT_CONFIGURED` when `OPENAI_API_KEY` / Codex binary is absent. Enforces `shell: false`, explicit spending ceilings (`max_cost_usd` -> `is_partial: true`), secret redaction, and operator opt-in before transmitting any code.

### 2.4 Cloudflare Security Center / Audit Skill
- **Upstream Provenance:** Cloudflare Security Center (ASM), API Shield, Logpush telemetry schemas, and public Cloudflare Audit skill patterns (`developers.cloudflare.com`).
- **Upstream License / Terms:** Proprietary Cloudflare APIs and service terms; public schema/skill conventions referenced cleanly. **No proprietary Cloudflare backend code is copied.**
- **How Used Here:** Clean-room read-only telemetry normalizer in [`packages/adapters/src/cloudflare-adapter.ts`](packages/adapters/src/cloudflare-adapter.ts) (`CloudflareSecurityCenterAdapter`) mapping ASM findings, API Shield anomalies, and Logpush Edge injection scores (`AISecurityInjectionScore`, PII tags) into canonical contracts.
- **Runtime Status & Hard Boundaries:** Defaults fail-closed to `NOT_CONFIGURED` without `CLOUDFLARE_API_TOKEN` and account scope. Strictly **read-only** in MVP (zero edge firewall, WAF, or DNS auto-mutation).

### 2.5 Quality Engine
- **Upstream Provenance:** [`github.com/andrecodexvictor/Quality-engine`](https://github.com/andrecodexvictor/Quality-engine) (first-party / collaborator Invokta MCP HTTP quality-gate engine).
- **Upstream License / Terms:** First-party / collaborator repository license *(confirm exact license compatibility with MIT before final public release)*.
- **How Used Here:** Loopback MCP capability client and `.security-pack.json` v1 quad-state integration in [`packages/adapters/src/quality-engine-adapter.ts`](packages/adapters/src/quality-engine-adapter.ts) (`QualityEngineAdapter`, invoking `quality.start`, `quality.get`, `quality.explain`, `release.assess`).
- **Runtime Status & Hard Boundaries:** Defaults to `NOT_CONFIGURED` when `QUALITY_ENGINE_URL` is unset. Because the upstream daemon has no built-in HTTP auth, [`assertLoopbackQualityEngineUrl`](packages/adapters/src/quality-engine-adapter.ts) blocks all non-loopback URLs (`SSRF_BLOCKED`). Never claims Semgrep, Trivy, or SBOM checks ran unless an active runner explicitly confirms them.

### 2.6 OWASP Security Skills Pack
- **Upstream Provenance:** OWASP Security Skills Pack (`security-pack` `v1.1.0` — `29` skills / `24` domains across AppSec, AgentSec/MCP, Supply Chain, and Cloudflare Edge; [`owasp.org`](https://owasp.org/)).
- **Upstream License / Terms:** Open OWASP documentation/policy-pack licensing *(commonly CC BY-SA 4.0 or Apache-2.0/MIT depending on specific OWASP sub-project — verify exact upstream `LICENSE` / `ATTRIBUTION` file before publishing)*.
- **How Used Here:** Clean-room TypeScript catalog metadata and `.security-pack.json` v1 deterministic policy evaluator in [`packages/adapters/src/owasp-skills-adapter.ts`](packages/adapters/src/owasp-skills-adapter.ts) (`OwaspSkillsPackAdapter`) and [`packages/quality-gate/`](packages/quality-gate/src/index.ts).
- **Runtime Status & Hard Boundaries:** Offline-capable deterministic scanner enforcing bounded file limits (`<= 2 MiB`/file, `<= 32 MiB`/run), secret redaction, and unexpired SHA-256 exception matching.

### 2.7 Invokta
- **Upstream Provenance:** [`github.com/vinilana/invokta`](https://github.com/vinilana/invokta) / [`docs.invokta.dev`](https://docs.invokta.dev) (`createEngine` / `defineCapability` / MCP Streamable HTTP execution architecture).
- **Upstream License / Terms:** Third-party ecosystem framework pattern (**action required before final public release: verify upstream `vinilana/invokta` LICENSE text and retain any required copyright/attribution notice**).
- **How Used Here:** Clean-room Security Action Engine (`createEngine`, `defineCapability`, `engine.invoke`) and fail-closed MCP Streamable HTTP server (`startMcpHttpServer`) in [`packages/security-actions/src/engine.ts`](packages/security-actions/src/engine.ts) and [`packages/security-actions/src/mcp-http.ts`](packages/security-actions/src/mcp-http.ts), built on the official `@modelcontextprotocol/sdk` and `zod`.
- **Runtime Status & Hard Boundaries:** Binds strictly to loopback (`127.0.0.1`), enforces DNS-rebinding `Host` checks, fail-closed `Origin` allowlisting (including loopback CORS preflight), Bearer token auth (`401`), session-to-principal binding (`403`), bounded body sizes (`413`), sliding-window rate limits (`429`), and server-derived `tenantId` isolation.

### 2.8 TypeSafe JEV
- **Upstream Provenance:** TypeSafe JEV documentation ([`docs.typesafe.ai/introduction/quickstart`](https://docs.typesafe.ai/introduction/quickstart)) and research paper [arXiv:2609.26550](https://arxiv.org/abs/2609.26550) (`systemOne`, `choice`/`noul` semantics — distinct from `jev-gateway`).
- **Upstream License / Terms:** TypeSafe commercial API terms of service. **`@typesafe-ai/sdk` is NOT installed or bundled**; [`packages/jev-judge/src/typesafe-provider.ts`](packages/jev-judge/src/typesafe-provider.ts) implements an original clean-room wire client directly over Node.js native `fetch` (`/v1/systemone`).
- **Runtime Status & Hard Boundaries:** Strictly **advisory first-pass triage only** ([`packages/jev-judge/src/pipeline.ts`](packages/jev-judge/src/pipeline.ts)). Runs *after* deterministic integrity pre-validation over secret-scrubbed digests (`sanitizedStateDigest`), never defines P0 alone (`p0DefinedByJevAlone: false`), never proves exploitability (`exploitConfirmed: false`), escalates uncalibrated outputs to `PENDING_REVIEW`, and degrades transparently to `MockTypeSafeJevProvider` (`providerStatus: "NOT_CONFIGURED"`, `decisionSource: "MOCK"`) when `TYPESAFE_API_KEY` is absent.

### 2.9 Factory Starter Kit (`factory.delivery.v1`)
- **Upstream Provenance:** `factory-starter-kit.zip` (Sirvi-derived deterministic delivery contract `factory.delivery.v1`, `quality-policy.mjs`, and `quality-gate.mjs` reference architecture).
- **Upstream License / Terms:** Hackathon starter-kit / competition reference pattern (**action required before final Hack Brasil submission: verify starter-kit reuse rules and include exact competition origin notice if required by Hack Brasil organizers**).
- **How Used Here:** Reimplemented in TypeScript/Zod as a deterministic SHA-bound delivery eligibility evaluator (`evaluateFactoryDeliveryEligibility`) in [`packages/company-context/src/schemas.ts`](packages/company-context/src/schemas.ts).
- **Runtime Status & Hard Boundaries:** Used **solely** as an advisory delivery eligibility gate requiring passing checks, independent review, and active authority. `eligible: true` **never** authorizes merge, deployment, or external side effects (`mergeAllowed: false`, `deployAllowed: false`, `externalExecution: false`).

---

## 3. Direct Open-Source Runtime Dependencies & Container References

The workspace relies on standard open-source libraries declared in workspace `package.json` files (not vendored in source control):

| Ecosystem / Package | Typical License | Role in ScriptKitty 2.0 |
|---|---|---|
| [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk) | MIT | Official MCP stdio and Streamable HTTP server/client transports |
| [`zod`](https://github.com/colinhacks/zod) | MIT | Strict runtime schema validation across all TypeScript contracts and capabilities |
| [`commander`](https://github.com/tj/commander.js) | MIT | CLI command parsing in `apps/cli` |
| [`vite`](https://github.com/vitejs/vite) & [`typescript`](https://github.com/microsoft/TypeScript) | MIT / Apache-2.0 | Build toolchain and dev server for `apps/ui` and TypeScript workspaces |
| Node.js Standard Library (`node:http`, `node:crypto`, `node:sqlite`, `node:test`) | MIT | Zero-extra-dependency HTTP servers, SHA-256/HMAC/AES-256-GCM crypto, SQLite stores, and test runner |
| Python Standard Library (`ast`, `hashlib`, `hmac`, `unittest`, `re`) & Pydantic (`packages/plugin_sdk`) | PSF / MIT | Python security runtime, AST remediation, guardrails, and tests |
| Kali Linux Container Reference (`kalilinux/kali-rolling`) & Defensive Tools (`nmap`, `whatweb`, `nikto`, `lynis`) | GPL / Upstream Debian/Kali Licenses | **Container build manifest only** ([`Dockerfile.kali-sandbox`](packages/kali-mcp-assessment/docker/Dockerfile.kali-sandbox), [`seccomp-kali-lab.json`](packages/kali-mcp-assessment/docker/seccomp-kali-lab.json), [`docker-compose.kali-lab.yml`](docker-compose.kali-lab.yml)); **no Kali binaries or packages are bundled in this Git repository**. `LIVE_CONTAINER` execution stays fail-closed (`KALI_SANDBOX_UNAVAILABLE`) without an operator-provisioned rootless gVisor/WSL2 sandbox (see [`docs/KALI_MCP_ARCHITECTURE_PLAN.md`](docs/KALI_MCP_ARCHITECTURE_PLAN.md)). |

---

## 4. Pre-Submission License & Provenance Verification Checklist

Before tagging a public release or submitting the repository to **Hack Brasil**, complete and check off every item below:

- [ ] **MIT License Header & Root `LICENSE`:** Confirm [`LICENSE`](LICENSE) matches the repository copyright holder(s) and Hack Brasil team members.
- [ ] **Invokta (`vinilana/invokta`) License Audit:** Inspect upstream `LICENSE` on `github.com/vinilana/invokta` and verify that our clean-room `@script-kitty/security-actions` pattern requires no additional license text or copyright header; add if applicable.
- [ ] **Factory Starter Kit Attribution Audit:** Verify Hack Brasil / organizer rules for reusing the `factory.delivery.v1` contract pattern from `factory-starter-kit.zip` and confirm attribution accuracy in Section 2.9 above.
- [ ] **OWASP Security Skills Pack Attribution Audit:** Confirm the exact upstream license file (`CC BY-SA 4.0` vs. `Apache-2.0`/`MIT`) for `security-pack` v1.1.0 and ensure any reproduced rule descriptions comply with attribution/share-alike requirements.
- [ ] **Google Mantis & Harness² Notices:** Confirm zero verbatim code files from `google/mantis` or `google-research/harness2` were copied into `packages/`; if any prompt or helper is ever imported later, preserve Apache-2.0 `NOTICE` files verbatim.
- [ ] **Zero Proprietary SDKs or Keys:** Verify `package.json` lockfiles and Git history contain zero proprietary SaaS source code, zero `.env` files, and zero live API keys (`TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `CLOUDFLARE_API_TOKEN`, `ANTHROPIC_API_KEY`, etc.).
- [ ] **Kali Linux Image Digest Pinning:** Before running `docker build` on [`Dockerfile.kali-sandbox`](packages/kali-mcp-assessment/docker/Dockerfile.kali-sandbox), refresh and verify the pinned `kalilinux/kali-rolling@sha256:...` digest against official Offensive Security / Kali Docker Hub signatures and keep offensive frameworks strictly excluded.
- [ ] **Accurate Marketing & Claims Check:** Ensure README, pitch deck, video narration, and HackBR portal text match [`docs/IMPLEMENTATION_INVENTORY.md`](docs/IMPLEMENTATION_INVENTORY.md) — explicitly stating `LAB`-only mode, `PATH_VALIDATED` (never `EXPLOIT_CONFIRMED`), `MOCK`/`NOT_CONFIGURED` offline defaults, and `mergeAllowed: false` / `deployAllowed: false`.
