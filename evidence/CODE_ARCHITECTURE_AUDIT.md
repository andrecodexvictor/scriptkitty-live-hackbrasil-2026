# ScriptKitty Live — Deep Engineering & Architecture Audit

**Auditor:** `@auditor` (Independent Technical, Security & Architecture Auditor)  
**Audit Pass:** Delta Re-Verification Pass #2 (post-hardening, DB/concurrency & lightweight bundle pass)  
**Audit Timestamp (UTC):** `2026-11-21T23:59:13Z` *(Initial pass: `2026-11-21T17:37:01Z`)*  
**Verified Commit SHA:** `f1c334f8c4e58dbe433b45156a0d3491faa60588` (+ dirty working tree: `29` modified, `70` untracked)  
**Scope:** (A) Garbage Collection & Memory Leak Hygiene · (B) API Tokens Hygiene · (C) Rate Limiting & DoS Guardrails · (D) Code Verbosity, Coupling & App Architecture · (E) Database Architecture, N+1 Elimination & Request Concurrency · (F) Frontend Lightweight Bundle & Runtime Efficiency

---

## A. Garbage Collection & Memory Leak Hygiene

### A.1 Subsystem-by-Subsystem State, Handle & Timer Inventory (Delta Pass #2)

| Component / File | Long-Lived Structure / Handle / Timer | Bounded / Cleaned Up? | Verdict & Honest Findings |
|---|---|---|---|
| `packages/security-actions/src/mcp-http.ts` | `sessions: Map` (`maxSessions=128`), `rateLimiter` & `authRateLimiter`, `reaperTimer`, `inFlightRequests` (`L463, L706, L1030`), `httpServer` | **YES (Bounded & Cleaned)** | `maxSessions = 128`, `sessionTtlMs = 900_000` (15m), `maxRateLimitBuckets = 10_000` with `prune(now)` + LRU eviction, `reaperTimer.unref()`. `close()` clears timers, closes all transports/servers, clears `sessions`, and calls `httpServer.closeAllConnections()`. **Pass #2 additions:** `Access-Control-Allow-Methods` now includes `DELETE` (`L697`), `headersTimeout = 10_000` ms & `requestTimeout = 30_000` ms (`L1048-1049`), and `inFlightRequests` decrements cleanly in `finally` (`L1030`). |
| `packages/security-actions/src/engine.ts` | `auditEntries[]`, `combineSignals()` timers/`AbortController`, `execPromise` | **YES (Bounded & Cleaned)** | `auditEntries` capped at `1_000`. `combineSignals` clears timer and removes `abort` listeners in `finally`. **Pass #2 fix:** attached `execPromise.catch(() => {})` (`L469`) to prevent unhandled rejection if a capability throws after losing the timeout race. |
| `packages/security-actions/src/capabilities.ts` | `auditRunIndex: Map`, `store: CompanyBrainStore`, `kaliRunStore: KaliLabRunStore` | **PARTIAL** | `auditRunIndex` bounded (`2_000`, LRU). `createSecurityActionRuntime().close()` closes SQLite cleanly. **Pass #2 fix:** removed `(store as any).db` hack at `L1117` (now calls typed `store.getEvidenceById`). **Remaining minor leak vector:** convenience wrapper `createSecurityActionEngine()` still instantiates an internal `CompanyBrainStore` without returning a `.close()` handle — callers should prefer `createSecurityActionRuntime()`. |
| `packages/kali-mcp-assessment/src/lab-runner.ts` | `KaliLabRunStore.runs: Map`, `defaultSharedKaliRunStore` | **YES (Bounded)** | Bounded to `maxRuns = 1_000` with FIFO/LRU eviction. No timers or open file descriptors retained. |
| `packages/company-context/src/store.ts` & `packages/evidence/src/ledger.ts` | `node:sqlite` `DatabaseSync` + `stmtCache: Map<string, StatementSync>` | **YES (Bounded & Cleaned)** | Both cap `stmtCache` at `MAX_PREPARED_STATEMENTS = 256` (`store.ts:92,195`, `ledger.ts:85,153`), clear `stmtCache` in `close()`, and guard with `this.closed` + `assertOpen()`. |
| `packages/runtime-guardian/src/confused-deputy.ts` | `ConfusedDeputyGuard.nonceCache: Map<string, number>` (`L258`) | **YES — RESOLVED IN PASS #2** | Converted from unbounded `Set<string>` to TTL `Map<string, number>` storing `expiresAt + 2000`. Calls `pruneExpiredNonces(nowMs)` on insert (`L280-289`) and enforces FIFO cap at `maxNonceCacheSize = 10_000` (`L259, L291-295`). Verified via new unit tests (`runtime-guardian` `170/170`). |
| `packages/runtime-guardian/src/audit-logger.ts` | `InMemoryAuditLogger.events[]`, `FileAuditLogger.events[]`, `writeQueue` (`L251-531`) | **YES — RESOLVED IN PASS #2** | Both loggers now enforce `maxInMemoryEvents` ring-buffer cap (default `5_000`, evicting oldest events at `L305, L426-427, L473`) and recover `writeQueue` via `.then(..., () => undefined)` / `.catch(() => undefined)` (`L317, L366, L480, L515`) so one failed write never poisons subsequent logs. |
| `packages/remediation-engine/src/rollback.ts` & `lifecycle.ts` | `RollbackEngine.auditLog[]`, `checkpoints: Map`, `FileSnapshotManager.snapshots: Map` | **YES — RESOLVED IN PASS #2** | `RollbackEngine` now caps `maxCheckpoints = 100` (`L107, L165-168`) and `maxAuditEntries = 1_000` (`L108, L327`), and deletes consumed checkpoints on rollback (`L235`). `lifecycle.ts` now clears `this.snapshotManager.clear()` inside `finally` blocks across all exit paths (`L171-172, L204-205, L259-260, L292, L393-394`). Verified via `remediation-engine` `33/33`. |
| `packages/remediation-engine/src/sandbox.ts` | `child_process.spawn`, `setTimeout`, `stdout`/`stderr` buffers | **YES (Bounded per Run)** | Caps `stdout`/`stderr` strictly at `1 MiB` and clears timers on `close` and `error`. *(Windows caveat remains: `child.kill('SIGKILL')` terminates direct child, not detached grandchild processes.)* |
| `packages/quality-gate/src/audit.ts` & `engine.ts` | `TamperEvidentAuditLogger.events[]` | **BOUNDED IN GATE / UNBOUNDED STANDALONE** | `DeterministicQualityGate.evaluate()` calls `this.auditLogger.clear()` at entry, keeping gate runs bounded. Standalone `TamperEvidentAuditLogger` remains uncapped. |
| `packages/jev-judge/src/typesafe-provider.ts` & `packages/adapters/src/execution-boundary.ts` | `AbortController`, `setTimeout`, `withTimeout` | **YES (Cleaned)** | Clears timers and removes caller `abort` listeners in `finally`; `withTimeout` calls `timer.unref()`. |
| `apps/ui/src/live-controller.ts` & `mcp-browser-client.ts` | `snapshotMap` (`<=50`), `auditLog` (`<=50`), `decisionHistory` (`<=20`), active `McpBrowserClient` session | **YES — RESOLVED IN PASS #2** | `McpBrowserClient.close()` (`L361-395`) sends `DELETE /mcp` to terminate sessions cleanly. `PatchCatLiveController` caches and reuses one active client keyed by `url|token|origin` (`L606`), closing any replaced client (`L617`) and exposing `public async close()` (`L660`). Pass #1 128-session exhaustion leak is **RESOLVED**. |
| `apps/ui/src/mascot3d.ts` & `dashboard-view.ts` | `requestAnimationFrame`, `mousemove`, `visibilitychange`, `IntersectionObserver`, `openDetailsIds` | **YES — ENHANCED IN PASS #2** | `MotionCatMascot3D` binds passive `mousemove`, `document` `visibilitychange` (`L305`), and `IntersectionObserver` (`L307-308`), pausing `rAF` completely when hidden, offscreen, or under `prefers-reduced-motion: reduce`, and throttling idle drawing to `38ms` (~26fps) vs `16ms` (~60fps) during `scanning`/interaction bursts (`L348`). `destroy()` (`L658-675`) removes both event listeners, disconnects `IntersectionObserver`, and cancels `rAF`. |

---

## B. API Tokens Hygiene

### B.1 Positive Controls Verified Independently
1. **Constant-Time Token Comparison Without Early Exit (`packages/security-actions/src/mcp-http.ts`):**
   - `timingSafeStringMatch(a, b)` hashes both inputs with SHA-256 (`32` bytes fixed) and compares with `crypto.timingSafeEqual`.
   - `authenticate()` iterates all configured tokens without `break` on match, preventing length and list-position timing leaks; `authReq.auth.token` is scrubbed to `'[REDACTED]'` before entering transport handlers.
2. **Fail-Closed Auth & Unconfigured Providers:**
   - Missing/invalid `Authorization: Bearer` tokens return `HTTP 401` + `WWW-Authenticate: Bearer` + `Cache-Control: no-store`.
   - Unset `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `CLOUDFLARE_API_TOKEN`, `MANTIS_RUNNER`, and `QUALITY_ENGINE_URL` fail closed as `NOT_CONFIGURED` / `MOCK` / `PENDING_REVIEW`.
3. **Pass #2 Token Hygiene Fixes Verified:**
   - **Private Browser Vault (`apps/ui/src/live-controller.ts:261`):** `readonly #secrets: SecretVault` prevents runtime property enumeration via `window.__PATCHCAT_CONTROLLER__`.
   - **Upstream Error Body Redaction (`packages/jev-judge/src/typesafe-provider.ts:186`):** Runs `sanitizeStringForExternalJev(text)` before slicing upstream HTTP error bodies into `TypeSafeAPIError` (`jev-judge` `5/5`).
   - **CLI KDF Upper-Bound Validation (`apps/cli/src/credentials.ts:96-140, 196, 313`):** `assertValidKdfParams()` rejects tampered envelopes outside `1024 <= N <= 65536`, `r <= 16`, `p <= 4`, `keyLen === 32` (`cli` `5/5`).
4. **Independent Repo-Wide Secret Scan:** **`0` live secrets**, **`0` `.env` files**.

### B.2 Remaining Open Token Hygiene Weaknesses (Honest Findings)
1. **Predictable Default CLI Encryption Key (`apps/cli/src/credentials.ts`):**
   - When `SCRIPT_KITTY_MASTER_KEY` is unset, `deriveLocalMachinePassphrase()` still derives the AES-256-GCM key deterministically from `os.hostname() | username | os.homedir() | platform | arch`. Move to OS keychain or require explicit user passphrase/env key for production.
2. **Bearer Token in Bootstrap Query String & Static Default (`scripts/start-live-demo.mjs:47, 735`):**
   - Still defaults to `'sk-live-demo-token-2026'` and prints `?token=` in the Quick-Connect URL (scrubbed post-load by `apps/ui/src/main.ts`, but traverses initial HTTP request line and browser history). Replace with per-launch random hex token + `#fragment` or manual paste.
3. **Production Dependency Advisory (`npm audit --omit=dev --json`):**
   - `zod@3.25.76` (`GHSA-mrhx-c7xc-m3w5`, High, CVSS `7.5`, `CWE-770`, fix `zod@4.6.7` semver-major).

---

## C. Rate Limiting & DoS Guardrails

### C.1 Verified Controls (`packages/security-actions/src/mcp-http.ts`)
| Guard | Mechanism & Location | Defaults | Independently Verified |
|---|---|---|---|
| **Pre-Auth IP Brute-Force Limiter** | `authRateLimiter` (`peek()` before `authenticate()`, `checkAndConsume()` on failed auth) | `20` failed / `60,000ms` per `remoteAddress` | **PASS** — `[401, 401, 429]` + `Retry-After: 60`. |
| **Post-Auth Principal+IP Limiter** | `rateLimiter` keyed by `${principalId}:${authIpKey}` | `120` req / `60,000ms` (`240` in demo) | **PASS** — `[200, 200, 429]` + `Retry-After: 60`. |
| **Bucket Memory Cap & Pruning** | `SlidingWindowRateLimiter` (`maxBuckets = 10_000`, `prune(now)` + LRU eviction) | `10,000` buckets max | **PASS** — Verified periodic pruning and bounded bucket map. |
| **Request Body DoS Guard** | `readBoundedBody` (`Content-Length` + streaming chunk cap + `req.destroy()`) | `1,048,576` bytes (`1 MiB`) | **PASS** — `1.1 MB` POST returns `HTTP 413`. |
| **In-Flight Concurrency Backpressure** *(New Pass #2)* | `inFlightRequests >= maxConcurrentRequests` guard (`L457-463, L706-716, L1030`) | Configurable (default `64`) | **PASS** — Tested with `maxConcurrentRequests: 1`: overlapping request shed immediately with **`HTTP 503` + `Retry-After: 1`**, `inFlightRequests` returned to `0`. |
| **Slowloris / Socket Timeouts** *(New Pass #2)* | `httpServer.headersTimeout` & `httpServer.requestTimeout` (`L1048-1049`) | `10,000ms` headers / `30,000ms` request | **PASS** — Verified directly on live `httpServer` instance (`10000` / `30000`). |
| **Concurrent Session Cap, CORS `DELETE` & Idle TTL** | `maxSessions = 128` (`503`), `Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS` (`L697`), idle TTL eviction (`404`) | `128` sessions, `900,000ms` TTL | **PASS** — Verified `OPTIONS DELETE` (`204`), `DELETE /mcp` (`200`, `activeSessions: 1 -> 0`), and TTL eviction (`404`, `activeSessions: 0`). |

### C.2 Remaining Production Caveat
- **Reverse Proxy / `X-Forwarded-For`:** `mcp-http.ts` intentionally derives `authIpKey` from `req.socket.remoteAddress ?? 'local'` and ignores `X-Forwarded-For` — correct and fail-closed for loopback `127.0.0.1`, but any future reverse-proxied deployment will need an explicit `trustedProxies` allowlist + rightmost-untrusted `X-Forwarded-For` parser to avoid collapsing all external clients into one proxy IP.

---

## D. Code Verbosity & App Architecture

### D.1 Codebase Scale & Top 15 Largest Source Files

Across `apps/`, `packages/`, `scripts/`, and `vercel-app/` (matching `.ts`, `.mts`, `.js`, `.mjs`, `.css`, `.html`, `.py`, excluding `node_modules/`, `dist/`, `.git/`, `evidence/`, `demo-video/`), the repository contains **`184` source files** totaling **`85,188` lines of code**.

| Rank | Source File | Lines | Bytes | Role / Assessment |
|---:|---|---:|---:|---|
| 1 | `scripts/record-demo-video.mjs` | **2,146** | 92,165 | Monolithic CDP + SAPI TTS + FFmpeg video recorder (candidate to split into scene modules). |
| 2 | `apps/ui/src/lab-evaluator.ts` | **1,935** | 61,286 | Browser-pure mirror of ChainBreak + JEV Mock + Quality Gate + Delivery Gate (intentional offline duplication). |
| 3 | `apps/ui/src/style.css` | **1,897** | 33,998 | Full UI stylesheet (dark/light tokens + landing + console). |
| 4 | `packages/verification-suite/tests/tier6-patchcat-live.test.mts` | **1,896** | 82,141 | Tier-6 E2E test suite. |
| 5 | `scripts/run-quality-gates.mjs` | **1,883** | 104,717 | Monolithic G00–G14 gate harness (candidate to split into `scripts/gates/g00..g14.mjs`). |
| 6 | `apps/ui/src/dashboard-view.ts` | **1,666** | 75,090 | HTML template renderer, i18n dictionary, lazy motion loader, and DOM event binder. |
| 7 | `packages/kali-mcp-assessment/src/lab-runner.ts` | **1,628** | 57,573 | Legacy 4 capabilities + adapter bridge + `LAB_SYNTHETIC` runner/store. |
| 8 | `packages/security-actions/tests/security-actions.test.mts` | **1,586** | 55,708 | MCP HTTP, concurrency, backpressure & Action Engine tests. |
| 9 | `packages/company-context/src/store.ts` | **1,503** | 47,297 | Hardened SQLite `CompanyBrainStore` (WAL, PRAGMAs, covering indexes, batching, typed `getEvidenceById`). |
| 10 | `packages/patchcat-orchestrator/src/orchestrator.ts` | **1,488** | 52,336 | Full 9-stage orchestration pipeline + governance guard + ZenPR synthesis. |
| 11 | `packages/security-actions/src/capabilities.ts` | **1,453** | 46,978 | Registers all 14 capabilities (still duplicates 6 Kali capability wrappers). |
| 12 | `vercel-app/src/style.css` | **1,431** | 25,656 | Duplicated stylesheet for standalone Vercel landing preview. |
| 13 | `packages/kali-mcp-assessment/src/schemas.ts` | **1,388** | 44,891 | Zod schemas + SSRF/flag/shell validators. |
| 14 | `packages/kali-mcp-assessment/tests/kali-mcp-assessment.test.mts` | **1,237** | 48,072 | Kali containment & negative security tests. |
| 15 | `apps/ui/src/lab-fixtures.ts` | **1,202** | 40,424 | Browser-embedded synthetic `payments-lab` fixtures. |

### D.2 Workspace Dependency Graph, Layering & Remaining Coupling
- **Encapsulation Violation (`(store as any).db`) — RESOLVED IN PASS #2:** `packages/security-actions/src/capabilities.ts:1117` now calls typed `store.getEvidenceById(ctx.tenantId, requestedEvId)` (`CompanyBrainStore` enforces tenant ownership cleanly).
- **Declared `package.json` Workspace Graph (`18` packages):** `0` cycles.
- **Actual Import Graph (Still Open for Post-Hackathon P1):**
  - Mutual relative-import cycle `@script-kitty/security-actions <-> @script-kitty/kali-mcp-assessment` (`../../kali-mcp-assessment/dist/...` vs `@script-kitty/security-actions/engine`), plus verbatim 6-tool Kali capability duplication (~180 lines) and relative `../../<pkg>/dist/` bypass imports across 5 packages.
  - Browser duplication remains **`6,172` lines** (`apps/ui` offline engine `3,406` lines + `vercel-app` `2,766` lines) — documented as P2 post-hackathon deduplication.

---

## E. Database Architecture, N+1 Elimination & Request Concurrency (New Pass #2 Audit)

### E.1 SQLite Engine Tuning & Runtime PRAGMA Verification
Both SQLite stores — `CompanyBrainStore` (`packages/company-context/src/store.ts:209-215`) and `EvidenceLedger` (`packages/evidence/src/ledger.ts:167-173`) — apply identical fail-closed durability and concurrency PRAGMAs during `initializeSchema()`, independently verified live against runtime instances:

| PRAGMA | Configured Value | Live Verified Output | Purpose & Engineering Impact |
|---|---|---|---|
| `journal_mode` | `WAL` | `memory` on `:memory:` (per SQLite spec); `wal` on disk-backed DBs | Concurrent readers never block a writer; atomic WAL checkpoints. |
| `busy_timeout` | `5000` | `5000` ms | Kernel/SQLite wait window before returning `SQLITE_BUSY`. |
| `synchronous` | `NORMAL` | `1` (`NORMAL`) | Safe WAL durability without full-fsync per small write penalty. |
| `foreign_keys` | `ON` | `1` (`ON`) | Enforces referential integrity across all relational tables. |
| `temp_store` | `MEMORY` | `2` (`MEMORY`) | Keeps temporary sort/group B-trees in RAM instead of temp disk I/O. |
| `cache_size` | `-16000` | `-16000` (~16 MiB) | Bounded per-connection page cache preventing unbounded SQLite page growth. |
| `wal_autocheckpoint` | `1000` | `1000` pages (~4 MiB) | Prevents unbounded `-wal` file growth under sustained write traffic. |

### E.2 Prepared Statement Cache, `SQLITE_BUSY` Retry & Index Verification (`EXPLAIN QUERY PLAN`)
1. **Bounded Prepared Statement Cache:** Both `CompanyBrainStore` (`L92, L195`) and `EvidenceLedger` (`L85, L153`) memoize `db.prepare(sql)` in `stmtCache` capped at `MAX_PREPARED_STATEMENTS = 256` with oldest-entry eviction and full `stmtCache.clear()` on `.close()`.
2. **Transactional `SQLITE_BUSY` / `SQLITE_LOCKED` Retry Loop:** Both `runInTransaction()` helpers (`store.ts:328-348`, `ledger.ts:228-248`) retry up to `SQLITE_MAX_TX_RETRIES = 5` times on transient lock contention using jittered synchronous `Atomics.wait` backoff before rolling back cleanly.
3. **Composite & Covering Indexes Independently Verified via Live `EXPLAIN QUERY PLAN`:**
   - `EvidenceLedger.assertAnalysisOwnership`:  
     `SEARCH evidence_receipts USING COVERING INDEX idx_receipts_analysis_tenant (analysis_id=?)` *(zero table lookup!)*
   - `CompanyBrainStore.listAnalyses`:  
     `SEARCH security_analyses USING INDEX idx_analyses_tenant_created_desc (tenant_id=?)` *(eliminates `TEMP B-TREE FOR ORDER BY`!)*
   - `CompanyBrainStore.getDeliveryEvaluations`:  
     `SEARCH factory_delivery_evaluations USING INDEX idx_delivery_tenant_created_desc (tenant_id=?)` *(eliminates `TEMP B-TREE FOR ORDER BY`!)*
   - Additional tenant-scoped composite indexes verified in schema: `idx_evidence_tenant_analysis`, `idx_adjudications_tenant_analysis`, `idx_remediations_tenant_analysis_path`, `idx_history_tenant_analysis`, `idx_receipts_tenant_analysis`, `idx_receipts_tenant_finding`.

### E.3 N+1 Query Elimination & Pagination
- **`CompanyBrainStore.assertRowsOwnership()` (`store.ts:373-401`, called at `L543, L549, L803`):** Replaces per-item `SELECT` loops with chunked `WHERE <col> IN (?, ?, ...)` batch queries, asserting exact cross-tenant ownership in $O(\lceil N / \text{chunk}\rceil)$ queries instead of $O(N)$.
- **`EvidenceLedger.getReceiptsByIds()` (`ledger.ts:687`, called at `L819`):** Batch-fetches linked evidence receipts in chunked `IN (...)` queries instead of executing one `SELECT` per receipt ID inside Merkle/bundle verification.
- **`CompanyBrainStore.getEvidenceById()` (`store.ts:870`):** Direct O(log n) indexed point lookup with strict `TenantIsolationError` throw on cross-tenant access (independently verified live: `'tenant-a'` returned typed `StoredChainBreakEvidence`, `'tenant-b'` threw `TenantIsolationError`).
- **Pagination:** List endpoints accept `PaginationOptions` (`limit` / `offset`) to prevent unbounded full-table hydration.

### E.4 Live HTTP Request Concurrency & Backpressure Stress Results
Independently tested against a live `startMcpHttpServer` instance on `127.0.0.1:0`:
- **50-Parallel Stateless `tools/call` (`security.chainbreak.analyze`, `unsafe-rollout`):** **`50/50` HTTP `200`** (`0` errors, `0` `SQLITE_BUSY` failures), **`uniqueAnalysisIds: 1`** (concurrent idempotent writes converged deterministically), and **`inFlightRequests: 0`** immediately post-completion.
- **Explicit Backpressure (`maxConcurrentRequests: 1`):** While request #1 held `midInFlight: 1`, simultaneous request #2 was immediately rejected with **`HTTP 503`** + **`Retry-After: 1`**, request #1 completed **`HTTP 200`**, and **`endInFlight: 0`**.

### E.5 Honest Horizontal Scaling Architecture Caveat
- Because `node:sqlite` (`DatabaseSync`) runs synchronously on the Node event loop thread and `runInTransaction()` uses synchronous `Atomics.wait` backoff on `SQLITE_BUSY`, the current SQLite WAL design is **ideal and rock-solid for single-node loopback/LAB deployments** (verified `50/50` parallel).
- For any future **multi-instance / horizontally scaled cloud production** deployment, SQLite cannot share write locks across containers/VMs: migrate `CompanyBrainStore` and `EvidenceLedger` behind an async repository interface backed by **PostgreSQL** (connection pool + `INSERT ... ON CONFLICT DO NOTHING` idempotency + row-level security) and externalize `SlidingWindowRateLimiter` + MCP sessions to **Redis**.

---

## F. Frontend Lightweight Bundle & Runtime Efficiency (New Pass #2 Audit)

### F.1 Verified Disk Bundle Audit (`apps/ui/dist` & `vercel-app/dist`)
Measured directly on disk across every emitted artifact in `apps/ui/dist` (`12` files) and `vercel-app/dist` (`8` files), cross-checked against `dist/index.html` and `vite.config.ts`:

| App / Metric | Before (Pass #1) | After (Pass #2) | Delta / Verification |
|---|---:|---:|---|
| **`apps/ui` Initial Critical JS (raw)** | `380.53 kB` (`374.76 + 5.77`) | **`297.26 kB`** (`164.14 + 133.11`) | **`-83.27 kB` (`-21.9%`)** |
| **`apps/ui` Initial Critical JS (gzip)** | `114.74 kB` (`112.56 + 2.18`) | **`84.75 kB`** (`43.21 + 41.54`) | **`-29.99 kB` (`-26.1%` gzip)** |
| **`apps/ui` Deferred Lazy JS (`motion`)** | Bundled eagerly in main chunk | **`74.95 kB` raw / `27.54 kB` gzip** (`vendor-motion` `73.48 kB` + `motion-choreography` `1.47 kB`) | Verified **absent** from `apps/ui/dist/index.html`; loaded dynamically via `import('./motion-choreography.ts')` (`dashboard-view.ts:51`) |
| **`apps/ui` CSS (raw / gzip)** | `27.12 kB` / `5.12 kB` | **`27.45 kB` / `5.18 kB`** | Minimal (`+60 B` gzip for laptop chip & polish fixes) |
| **`apps/ui` Total `dist/` (12 files)** | — | **`456,225 B` raw / `156,691 B` gzip** | Includes `5` brand assets (`49.78 kB`); `sourcemap: false`; `0` legacy unused assets |
| **`vercel-app` JS (raw / gzip)** | `49.08 kB` / `14.49 kB` (+ `82.51 kB` `.js.map`) | **`51.28 kB` / `14.86 kB`** (`0 B` `.js.map`) | **Removed `82.51 kB` production `.js.map`** (`sourcemap: false`) |
| **`vercel-app` CSS (raw / gzip)** | `20.89 kB` / `4.16 kB` | **`20.90 kB` / `4.17 kB`** | Ultra-lightweight (`4.17 kB` gzip) |
| **`vercel-app` Total `dist/` (8 files)** | — | **`122,898 B` raw / `56,039 B` gzip** | Includes `5` brand assets (`49.78 kB`); `0` sourcemaps; `0` legacy assets |

### F.2 Vite Build Configuration & Chunk Integrity Verified
- `apps/ui/vite.config.ts:6-24`: `target: 'es2022'`, `minify: 'esbuild'`, `cssMinify: true`, `sourcemap: false`, with `manualChunks` separating `vendor-openui` (`@openuidev` + `zod`), `vendor-motion` (`motion`), and `vendor`.
- `apps/ui/dist/index.html`: Only loads `/assets/index-CVPFzpmo.js`, preloads `/assets/vendor-openui-BCWkkLs_.js`, and loads `/assets/index-UUfuk3fl.css` — confirming `vendor-motion-DXHc17FV.js` and `motion-choreography-C2TSw60O.js` are genuinely off the initial boot path.
- `vercel-app/vite.config.ts:6-9`: `target: 'es2022'`, `minify: 'esbuild'`, `cssMinify: true`, `sourcemap: false` — single `14.86 kB` gzip JS + `4.17 kB` gzip CSS landing bundle.

### F.3 Canvas / Mascot Runtime CPU & Battery Hygiene (`apps/ui/src/mascot3d.ts`)
- **Zero wasted CPU when hidden/offscreen/reduced-motion:** Binds `document` `visibilitychange` (`L305`), `IntersectionObserver` with `threshold: 0.01` (`L307-308`), and checks `prefers-reduced-motion: reduce` (`L279`). Cancels/skips `requestAnimationFrame` completely whenever the tab is backgrounded, the mascot canvas scrolls out of viewport, or reduced-motion is enabled.
- **Adaptive Frame-Rate Throttling (`L348`):** Draws at `16ms` (~60fps) only during `scanning` or a `650ms` user interaction burst (`ts < this.highFpsUntil`), throttling down to `38ms` (~26fps) during calm idle.
- **Leak-Free Teardown (`L658-675`):** `destroy()` cancels `rAF`, removes passive `mousemove` and `visibilitychange`, disconnects `IntersectionObserver`, and removes the `<canvas>`.

---

## G. Prioritized Post-Hackathon Refactor Roadmap (Updated Post-Pass #2)

| Priority | Action | Impact |
|---|---|---|
| **P0 (Security & Release Gate `G10`)** | 1. Upgrade `zod` to `>= 4.6.7` across all workspaces (resolves `G10` `GHSA-mrhx-c7xc-m3w5` High advisory + `@openuidev/lang-core` Vite warning).<br/>2. Move CLI credentials default off predictable machine-derived passphrase to OS keychain or mandatory `SCRIPT_KITTY_MASTER_KEY`, and generate random per-run demo tokens (`#fragment` bootstrap).<br/>3. Move `.dotarchitecture .dotcontext .dotstack` from `/XD` to `/XF` in `PROVENANCE.md:103` before competition export. | Closes remaining High CVE and tightens local credential/export hygiene. |
| **P1 (Clean Architecture & Breaking Cycles)** | 1. Extract `@script-kitty/action-engine-core` (`engine.ts` only, zero domain deps) so `kali-mcp-assessment` depends on `action-engine-core` and `security-actions` imports `createKaliLabSyntheticCapabilities` — breaking the `security-actions <-> kali-mcp-assessment` cycle and deleting ~180 duplicated lines.<br/>2. Replace all `../../<pkg>/dist/` relative imports with explicit npm workspace dependencies and TypeScript project references (`tsc -b`), and deprecate `createSecurityActionEngine()` in favor of `createSecurityActionRuntime()` (which exposes `.close()`).<br/>3. Replace placeholder Kali `@sha256` digest with a verified live image digest and smoke-test `LIVE_CONTAINER`. | Guarantees cold clean builds (`rm -rf **/dist && npm run build`) and clean layered dependencies. |
| **P2 (Duplication Reduction & Cloud Scale)** | 1. Extract browser-pure `@script-kitty/chainbreak-core` (Web Crypto + shared `fixtures/payments-lab/*.json`) so `apps/ui` and `packages/chainbreak` execute the exact same algorithm (eliminating ~3,100 lines of `lab-evaluator.ts`/`lab-fixtures.ts` drift risk).<br/>2. Unify `vercel-app` as a build-mode (`VITE_STATIC_PREVIEW=1`) of `apps/ui` or share `@script-kitty/ui-design-system` CSS/SVG tokens (eliminating ~2,760 duplicated lines).<br/>3. Split `dashboard-view.ts` (`1,666` lines), `run-quality-gates.mjs` (`1,883` lines), and `record-demo-video.mjs` (`2,146` lines) into focused modules (<400 lines each).<br/>4. Introduce async `Repository` interfaces (`PostgreSQL` + `Redis`) behind `CompanyBrainStore`, `EvidenceLedger`, and `mcp-http` before multi-instance cloud deployment. | Eliminates >5,500 lines of frontend/engine duplication and unlocks horizontal multi-node scaling. |
