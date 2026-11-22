# ScriptKitty 2.0 & ScriptKitty Live — Security Boundaries & Fail-Closed Guarantees

**Document Status:** Canonical Security Boundary Specification  
**Scope:** Laboratory verification, local developer tooling, and MCP/Action Engine enforcement  
**Non-Production Warning:** ScriptKitty Live operates exclusively against synthetic fixtures and authorized lab targets (`mode: "LAB"`, `productionTested: false`). Production exploitation, automated production merging/deploying, and credential revocation are strictly prohibited.

---

## 1. Executive Posture & Fail-Closed Philosophy

ScriptKitty enforces a **Zero-Trust, Fail-Closed** posture across both its **AppSec** (autonomous vulnerability reproduction and patching) and **AgentSec** (AI agent and MCP runtime guard) planes:

1. **Absence Is Never Passage:** Missing authentication context, missing empirical evidence, expired exceptions, unconfigured external API keys, malformed JSON/Zod schemas, timeouts, or broken custody hashes MUST evaluate to `BLOCK`, `REJECT`, `INCONCLUSIVE`, `PENDING_REVIEW`, `ERROR`, or `NOT_CONFIGURED` — **never** `PASS` or `ALLOWED`.
2. **Deterministic Boundary Principle:** Security invariants (hashes, separation of duties, path containment, JSON schema checks, policy expiration, graph transition predicates, and regression execution) are evaluated exclusively by deterministic TypeScript code — never delegated to an LLM or probabilistic scorer.
3. **Hexagonal Unidirectional Trust Zones:** Dependencies flow strictly inward from untrusted inputs (Zone 0) through isolated sandboxes (Zone 1) into pure contract/custody models (Zone 2) and deterministic release/policy gates (Zone 3). High-trust zones in [`packages/contracts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/index.ts) and [`packages/quality-gate`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/engine.ts) contain zero network, filesystem-traversal, or subprocess execution side effects.

```text
TRUST ZONE 0 (Untrusted Perimeter)
  HTTP requests, MCP tool arguments, raw repos, RAG docs, LLM outputs, webhook payloads
        │
        ▼
TRUST ZONE 1 (Isolated Execution & Adapter Boundary)
  packages/adapters (execution-boundary.ts), ProcessSandbox (offline/env-scrubbed),
  RuntimeGuardian (input/output inspection), Lab fixtures (apps/lab-app, payments-lab)
        │
        ▼
TRUST ZONE 2 (High-Trust Core Contracts & Evidence Ledger)
  @script-kitty/contracts: Zod validation, RFC 8785 canonicalStringify, SHA-256 chaining,
  binary Merkle trees
        │
        ▼
TRUST ZONE 3 (Deterministic Authority & Gate)
  @script-kitty/quality-gate: Tri-Party SoD, unexpired UTC exceptions, scope bounds,
  quad-state verdict resolution, tamper-evident audit Merkle roots
```

---

## 2. The Six Mandatory Trust Boundaries

Aligned with `SCRIPTKITTY_LIVE_ARCHITECTURE_11NOV2026.md` and enforced across ScriptKitty packages, every request and artifact must cross six explicit trust boundaries without bypassing validation.

### Boundary 1: Ingress, Identity Derivation & Tenant Isolation
*Untrusted callers, clients, HTTP `Origin` headers, and request bodies cannot assert identity or cross tenant lines.*

* **Server-Derived Principal & Tenant:** `tenantId` and `principal` MUST be derived strictly from verified server-side auth/session context — never trusted from a user-supplied JSON body parameter when evaluating multi-tenant analysis or storage (`Company Brain`, ChainBreak runs, or Quality Gate requests).
* **MCP Streamable HTTP Loopback & Origin Defense:** Local Invokta MCP servers bind exclusively to loopback (`127.0.0.1`), never `0.0.0.0`, and fail closed on missing/invalid bearer tokens, forbidden `Origin` headers (DNS rebinding defense), malformed arguments, or cross-tenant resource lookups.
* **No Legacy Unauthenticated Daemon Exposure:** Existing legacy components (such as legacy local Quality Engine HTTP daemons) that run without authentication must only be accessed over trusted local host boundaries and never exposed to external networks.
* **MCP Protocol Pinning (Anti-Rug-Pull):** [`ToolPoisoningGuard`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L166-L270) verifies tools on `tools/list` and `tools/call` using RFC 8785 SHA-256 hashes ([`computeToolDefinitionHash`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L34-L38)), blocking unregistered tools (`E_UNREGISTERED_TOOL`), duplicate/shadowing names (`E_DUPLICATE_TOOL`), poisoned descriptions (`E_DESCRIPTION_POISONING`), and post-pinning schema drift (`E_TOOL_HASH_DRIFT`).

### Boundary 2: Invocation Authorization & Resource Scope Guard
*Even authenticated principals or AI agents operate inside strict least-privilege capability and filesystem boundaries.*

* **Single Invocation Choke Point:** CLI, HTTP REST, MCP tools, and agent callers route domain actions through unified capability schema validation (`engine.invoke` / [`wrapMcpServer`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L331-L474)) rather than duplicating ad-hoc handler logic.
* **Confused Deputy & Taint Barrier:** [`ConfusedDeputyGuard`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L247-L372) blocks tainted contexts (`is_tainted`, `taint_tags`, or `taint_context.is_tainted`) from invoking state-changing tools (`E_TAINTED_CALLER_PRIVILEGE_VIOLATION`, except explicit `dry_run: true`), and verifies short-lived (max `300,000 ms`) HMAC-SHA256 delegation tokens ([`verifyDelegationToken`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L94-L242)) with `timingSafeEqual`, ±2s clock-skew tolerance, subject/audience/scope binding, and single-use nonce replay tracking (`E_TOKEN_REPLAYED`).
* **Canonical Path & Symlink Containment:**
  * [`ScopeBoundaryGuard`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L240-L372) ([`validateAndResolvePath`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L47-L235)) recursively traverses nested objects/arrays and rejects null bytes/control characters (`E_PATH_NULL_BYTE`), double URL encoding (`E_PATH_DOUBLE_ENCODING`), Windows UNC paths (`E_PATH_UNC_FORBIDDEN`), NTFS Alternate Data Streams (`E_PATH_NTFS_ADS`), non-allowlisted URI schemes (`E_INVALID_URI_SCHEME` — default allowlist `['file', 'sqlite']`), resolves NFKC normalization and `fs.realpathSync.native` symlinks against `allowedRoots` (`E_PATH_OUT_OF_BOUNDS`), and blocks sensitive files via [`DEFAULT_BLOCKED_PATTERNS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L18-L27) (`.git`, `.env*`, SSH private keys, `.aws/credentials`, `*.pem`/`*.key`/`*.pfx`/`*.p12`, `/etc/passwd|shadow` -> `E_SENSITIVE_RESOURCE_BLOCKED`).
  * [`insideScope`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/policy.ts#L185-L221) enforces equivalent cross-platform root containment inside [`DeterministicQualityGate`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/engine.ts#L69-L552).
* **Prompt Injection & Egress Inspection:** [`PromptInjectionDetector`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L214-L351) normalizes NFKC, strips Unicode zero-width obfuscation characters, applies leetspeak normalization, and blocks behavioral overrides, delimiter smuggling, webhook/cloud metadata IMDS exfiltration (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`), and credential arguments across nested objects.

### Boundary 3: Sandboxed Execution, Adapter Isolation & Experimental Quarantines
*Untrusted code, PoC reproducers, external security engines, and experimental harnesses must never access production secrets, arbitrary host shells, or public networks.*

* **Offline Subprocess Sandbox:** [`ProcessSandbox`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/sandbox.ts#L19-L480) (alias `OfflineLocalSandbox`) strips `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, and `CURL_PROXY`, injects `NO_PROXY='*'` and `SCRIPTKITTY_OFFLINE='1'`, forwards only an explicit OS environment allowlist (never arbitrary inherited cloud/Git tokens), executes direct binary `spawn(process.execPath, [fullPath])` without shell interpolation, enforces strict wall-clock timeouts (`SIGKILL`, exit `124`), and caps stdout/stderr capture at `1 MiB`.
* **Adapter Hardening Envelope:** [`packages/adapters/src/execution-boundary.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/execution-boundary.ts) wraps adapter calls in [`safeExecute`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/execution-boundary.ts#L275-L285), [`withTimeout`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/execution-boundary.ts#L50-L76), [`checkSizeBudget`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/execution-boundary.ts#L215-L230), and recursive secret redaction via [`sanitizeOutput`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/execution-boundary.ts#L108-L163) and [`sanitizeObject`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/execution-boundary.ts#L168-L200) (redacting Bearer tokens, AWS keys, GitHub PATs, Cloudflare tokens, Slack tokens, JWTs, URL credentials, and PEM private keys).
* **Bounded Policy Resource Limits:** [`PolicySchema`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/policy.ts#L72-L113) and [`parseSecurityPackPolicy`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/quality-engine-adapter.ts#L102-L212) cap resource intake at `max_file_bytes: 2 MiB` (`2,097,152`), `max_files: 5,000`, `max_total_bytes: 32 MiB` (`33,554,432`), and `timeout_ms: 20,000` (with schema cap `600,000`).
* **Experimental & Lab Engine Quarantines:**
  * **Google Mantis:** Restricted to synthetic/lab sandboxes without production credentials or egress; dynamic verification via [`@script-kitty/kali-mcp-assessment`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/src/index.ts) and [`KaliMcpAdapter`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/kali-mcp-adapter.ts) executes deterministic offline `LAB_SIMULATION` unless an airgapped/loopback rootless OCI+gVisor container or hardened WSL2 micro-VM is provisioned (`KALI_SANDBOX_UNAVAILABLE` fail-closed otherwise; see [KALI_MCP_ARCHITECTURE_PLAN.md](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/docs/KALI_MCP_ARCHITECTURE_PLAN.md)).
  * **Google Harness²:** Disabled outside offline research experiments (`HARNESS2_EXPERIMENTS_ENABLED=false` by default) and strictly barred from modifying policies, gates, credentials, or production modules.
  * **Optional Cloud Connectors:** Adapters lacking live credentials (Cloudflare, Codex Security, TypeSafe JEV without `TYPESAFE_API_KEY`) must surface explicit `NOT_CONFIGURED` / `MOCK` / `UNAVAILABLE` provenance rather than impersonating live external validation.

### Boundary 4: Evidence Provenance, Cryptographic Integrity & Untrusted LLM Separation
*Prompt text and model prose are never independent evidence; receipts must bind deterministically to versions, hashes, and verifiers.*

* **Schema Normalization & Invariant Rejection:** [`@script-kitty/contracts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/index.ts) validates every [`SecurityFinding`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/finding.ts#L99-L142), [`Evidence`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/evidence.ts#L147-L199), [`PatchProposal`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/patch.ts#L128-L171), and [`GateDecision`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/gate.ts#L185-L267) via Zod. Notably:
  * `PatchProposalSchema` rejects `recheck_status === "passed_clean"` without a linked `recheck_evidence_id`.
  * `Evidence` requires `network_isolated: boolean`, `script_sha256` / `chain_hash` (64-char hex), `verifier_agent_id`, and `recorded_at`.
  * [`onToolResult`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L287-L320) recursively sanitizes credentials/injections before tool outputs re-enter an LLM context and seals `result_digest` in the Merkle log.
* **ChainBreak Verification Semantics (`PATH_VALIDATED` ≠ `EXPLOIT_CONFIRMED`):** Deterministic graph reachability over a modeled fixture proves that a policy sequence violates a named rule under stated edge conditions (`sourceRef`, `policyVersion`, SHA-256 content hash). It MUST NEVER be reported as live exploitation proof against a production service.
* **RFC 8785 Custody & Merkle Proofs:** [`packages/contracts/src/custody.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts) binds each lifecycle stage (`FINDING -> EVIDENCE -> PATCH -> GATE`) from [`GENESIS_HASH`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts#L16-L17) via `computeNodeChainHash` and [`computeMerkleRoot`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts#L189-L206). Tampered chains or broken Merkle roots cause immediate gate `REJECT`.
* **Persistent Audit Log Integrity:** [`FileAuditLogger`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L351-L481) verifies every NDJSON record hash chain on initialization, throwing `E_AUDIT_LOG_PARSE_CORRUPTED` or `E_AUDIT_LOG_TAMPERED` if any historical record was edited.

### Boundary 5: Decision Escalation, Tri-Party SoD & Deterministic Gate Calculus
*No single agent—and no probabilistic LLM judge—may self-certify security findings or unilaterally assign critical release verdicts.*

* **JEV-as-a-Judge Guardrails:**
  * Deterministic code validates evidence hashes, policy versions, and identity consistency **before** invoking `TypeSafeClient` (`/v1/systemone`).
  * Sensitive credentials and unauthorized private source code must NOT be sent to third-party judge APIs; only sanitized, bounded summaries cross the boundary.
  * Initial confidence thresholds are explicitly documented as **uncalibrated**; any API failure, schema invalidation, ambiguity, low confidence, or high-impact/critical finding escalates to `PENDING_REVIEW` / human review rather than `PASS`.
  * JEV NEVER assigns final `P0` priority solo and NEVER upgrades unverified or deterministically falsified findings.
* **Mathematical Tri-Party Separation of Duties (SoD):** [`validateSeparationOfDuties`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/separation-of-duties.ts#L61-L175) and [`GateDecisionSchema`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/gate.ts#L185-L267) enforce:
  $$A_{\text{disc}} \ne A_{\text{veri}} \land A_{\text{veri}} \ne A_{\text{auth}} \land A_{\text{disc}} \ne A_{\text{auth}}$$
  Violations trigger `E_SOD_MISSING_AGENT`, `E_SOD_OMNIPOTENT_AGENT`, `E_SOD_SELF_CERTIFICATION`, `E_SOD_SELF_AUTHORIZATION`, `E_SOD_DISCOVERER_AUTHORIZATION`, or `E_SOD_SELF_ASSERTED_EVIDENCE` (checked both in the quality gate and live in `ConfusedDeputyGuard`). Even if an untrusted payload supplies `is_valid: true`, `GateDecisionSchema.superRefine` independently recomputes SoD and rejects invalid `PASS` states.
* **Quad-State Precedence:** [`DeterministicQualityGate.evaluate`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/engine.ts#L79-L551) resolves verdicts in strict precedence order:
  1. `ERROR`: Invalid/malformed policy v1 (`RULE_POLICY_PARSER`).
  2. `REJECT`: SoD failure, ANY expired policy exception (`expires < todayUtc`), broken custody chain/Merkle root, out-of-scope file path, or any unverified finding / `untested` patch.
  3. `BLOCK`: `INCONCLUSIVE` or `EXECUTION_ERROR` reproducer evidence, `regression_detected` or `reproducer_still_fails` patch, unremediated blocking finding (`CRITICAL` / `HIGH`), or resource limit overrun.
  4. `REQUIRES_HUMAN_APPROVAL`: Clean checks, but patch has `breaking_change_risk === 'HIGH'` or `ast_impact_scope === 'PUBLIC_API'`.
  5. `PASS`: Only when all zero-trust predicates succeed simultaneously.

### Boundary 6: Non-Intrusive Scope & No Autonomous Production Mutation
*Laboratory verification and local remediation plans stop strictly short of autonomous production changes.*

* **Factory Eligibility vs. Merge/Deploy:** Rules derived from `factory.delivery.v1` govern local build/test/typecheck delivery eligibility only; `eligible=true` NEVER grants permission to push, merge, deploy, publish packages, or revoke/alter IAM credentials in production.
* **Policy Mutation Lock:** Neither `PatchCat`, `AutonomousRemediationEngine`, `JEV-as-a-Judge`, `Harness²`, nor client MCP calls may mutate active security gate policies, add blanket exceptions, or lower `PolicySchema` ceilings during execution.
* **Synthetic Lab Containment:** AppSec end-to-end auto-patching in [`Patcher`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/remediation-engine/src/patcher.ts#L286-L390) is currently constrained to explicit synthetic templates targeting [`apps/lab-app/src/routes`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/src/routes/search.ts) and rollback-protected local sandboxes; production repositories require human review, signed commits, and explicit external CI verification.
* **Tenant-Scoped Memory (`Company Brain`):** Stored policy snapshots and decision history remain read-referenced with source timestamps per `tenantId` — never self-rewriting security policies without human authorization.

---

## 3. Fail-Closed Control Summary Matrix

| Failure / Anomaly Condition | Component Enforcing | Deterministic Outcome |
|---|---|---|
| Missing or expired delegation token / replayed nonce | [`verifyDelegationToken`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L94-L242) | `BLOCK` (`E_TOKEN_EXPIRED`, `E_TOKEN_REPLAYED`, `E_MISSING_DELEGATION_TOKEN`) |
| Same agent discovers & verifies finding | [`ConfusedDeputyGuard`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L247-L372), [`validateSeparationOfDuties`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/separation-of-duties.ts#L61-L175) | `BLOCK` / `REJECT` (`E_SOD_SELF_CERTIFICATION`) |
| Tainted context calls state-changing tool (no `dry_run`) | [`ConfusedDeputyGuard.inspect`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L266-L371) | `BLOCK` (`E_TAINTED_CALLER_PRIVILEGE_VIOLATION`) |
| Symlink / traversal / NTFS ADS / `.env` / `.git` access | [`validateAndResolvePath`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L47-L235) | `BLOCK` (`E_PATH_OUT_OF_BOUNDS`, `E_PATH_NTFS_ADS`, `E_SENSITIVE_RESOURCE_BLOCKED`) |
| Tool definition changed after manifest pin | [`ToolPoisoningGuard.verifyToolList`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L177-L228) | `BLOCK` (`E_TOOL_HASH_DRIFT`, `GuardianSecurityError` if 0 tools safe) |
| Any expired exception (`expires < todayUtc`) | [`evaluateExceptionsValidity`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/policy.ts#L144-L158) | `REJECT` (entire gate invalidated) |
| Missing/inconclusive evidence or failing patch recheck | [`DeterministicQualityGate.evaluate`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/quality-gate/src/engine.ts#L79-L551) | `REJECT` / `BLOCK` (auto-rollback if inside lifecycle) |
| Tampered NDJSON Guardian audit log line | [`FileAuditLogger.init`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L362-L404) | Throws `E_AUDIT_LOG_TAMPERED` or `E_AUDIT_LOG_PARSE_CORRUPTED` |
| Missing external API key (`TYPESAFE_API_KEY`, etc.) | JEV / External Adapters | `NOT_CONFIGURED` / `MOCK` + `PENDING_REVIEW` escalation |
