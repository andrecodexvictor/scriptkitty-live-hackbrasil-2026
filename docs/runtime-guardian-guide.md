# `@script-kitty/runtime-guardian` — AgentSec MCP Runtime Defense Guide

**Package:** [`packages/runtime-guardian`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/index.ts)  
**Primary Entrypoints:** [`RuntimeGuardian`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L28-L321) ([`createGuardianMiddleware`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L323-L325)), [`wrapMcpServer`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L331-L474), [`createGuardianClientInterceptor`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L479-L513).

---

## 1. Architecture & Interception Model

`@script-kitty/runtime-guardian` implements the **AgentSec** runtime defense plane protecting Model Context Protocol (MCP) servers and AI agent tool callers against tool poisoning, confused deputy privilege escalation, path/URI escapes, indirect prompt injection, data exfiltration, and credential leakage.

Every MCP server or client wrapped by `RuntimeGuardian` routes traffic through three deterministic interception hooks backed by a SHA-256 hash-chained & binary Merkle audit logger:

```text
  MCP Client / AI Agent
        │
        ├──▶ [Hook 1: onListTools] ──▶ ToolPoisoningGuard
        │                              (RFC 8785 hash pinning, shadow detection, desc scan)
        │
        ├──▶ [Hook 2: onCallTool]  ──▶ 4 Sequential Security Phases:
        │                              1. ToolPoisoningGuard.verifyToolCall
        │                              2. ConfusedDeputyGuard (Tri-Party SoD, Taint, HMAC Token)
        │                              3. ScopeBoundaryGuard (Paths, URIs, Symlinks, Secrets)
        │                              4. PromptInjectionDetector (Overrides, Delimiters, IMDS/Exfil)
        │
        ├──▶ [Underlying Tool Execution] (receives sanitized args if verdict === 'SANITIZE')
        │
        └──▶ [Hook 3: onToolResult] ──▶ PromptInjectionDetector.sanitize + SHA-256 result_digest
                                        (Redacts keys/injection before entering LLM context)
```

---

## 2. Wrapping Servers and Client Calls

### Server-Side Interception: `wrapMcpServer(server, guardian)`
[`wrapMcpServer`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L331-L474) instruments both pre-registered `_requestHandlers` (`tools/list`, `tools/call`) and future `server.setRequestHandler(schema, handler)` registrations on `@modelcontextprotocol/sdk` Server instances (inspecting Zod v3/v4 `.shape.method` literals first before falling back to title/params inference):
* Extracts attribution metadata from `request.params._meta` (`session_id`, `caller_agent_id`, `discovering_agent_id`, `delegation_token`, `taint_tags`, `taint_context`, `is_tainted`, `trace_id`) and server `extra` context.
* Honors [`GuardianConfig`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/types.ts#L225-L231):
  * `failClosed` (default `true`): Throws [`GuardianSecurityError`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/types.ts#L289-L304) in `onListTools` when violations occur and zero verified tools remain.
  * `errorMode` (default `'tool_result'`): Either returns structured MCP `{ isError: true, content: [{ type: 'text', text: '[GUARDIAN_SECURITY_BLOCK] ...' }] }` or throws `GuardianSecurityError` when `errorMode === 'throw'`.

### Client-Side Interception: `createGuardianClientInterceptor(guardian)`
[`createGuardianClientInterceptor`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/middleware.ts#L479-L513) returns `executeProtectedTool(toolName, toolArgs, executor, context)` for non-MCP direct tool invocations, enforcing `onCallTool` before `executor` and `onToolResult` on its return value (always throwing `GuardianSecurityError` on `BLOCK`).

---

## 3. Defense-in-Depth Guards

### 3.1 Tool Poisoning & Manifest Pinning ([`tool-poisoning.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts))
[`ToolPoisoningGuard`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L166-L270) stops MCP rug-pulls and shadowed tools:
1. **Canonical Definition Hash:** [`computeToolDefinitionHash`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L34-L38) extracts trimmed `{ name, description, inputSchema }` and hashes its RFC 8785 canonical JSON (`sha256(canonicalStringify(normalized))`).
2. **Checks Enforced on `tools/list` ([`validateAndFilterTools`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L70-L161)):**
   * `E_INVALID_SCHEMA`: Missing object or empty `name`.
   * `E_DUPLICATE_TOOL`: Duplicate advertised tool name (shadow tool attempt).
   * `E_UNREGISTERED_TOOL`: Tool absent from `allowedTools` or `manifest.pinned_tools` (unless `allowUnregistered: true`).
   * `E_DESCRIPTION_POISONING`: Matches prompt-injection directives (`ignore previous instructions`, `<|system|>`, `[INST]`, `<system>`) embedded inside tool descriptions ([`scanDescriptionForPoisoning`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L54-L65)).
   * `E_TOOL_HASH_DRIFT`: Live hash differs from pinned manifest or `knownToolHashes`.
3. **Checks Enforced on `tools/call`:** [`verifyToolCall`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/tool-poisoning.ts#L230-L269) enforces `allowedTools` and pinned manifest allowlisting before any other guard executes.

### 3.2 Confused Deputy, Taint Barrier & HMAC Delegation ([`confused-deputy.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts))
[`ConfusedDeputyGuard`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L247-L372) prevents untrusted callers or compromised prompts from misusing privileged tools:
1. **Live Separation of Duties (`E_SOD_SELF_CERTIFICATION`):** When `enforceSeparationOfDuties` is active and a verification tool ([`DEFAULT_VERIFICATION_TOOLS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L22): `verify_finding`, `run_recheck`) is called with `caller_agent_id === discovering_agent_id` (case-insensitive), the call is immediately blocked.
2. **Tainted Context Escalation Barrier (`E_TAINTED_CALLER_PRIVILEGE_VIOLATION`):** Any call carrying `is_tainted: true`, `taint_context.is_tainted: true`, or non-empty `taint_tags` is blocked from invoking state-changing tools ([`DEFAULT_STATE_CHANGING_TOOLS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L23-L29): `verify_finding`, `generate_patch`, `apply_patch`, `execute_command`, `run_recheck`), **unless** `toolArgs.dry_run === true`.
3. **Signed HMAC-SHA256 Delegation Tokens ([`signDelegationToken`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L34-L48) / [`verifyDelegationToken`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/confused-deputy.ts#L94-L242)):**
   * If `requireDelegationToken: true`, missing tokens fail with `E_MISSING_DELEGATION_TOKEN`; missing `hmacSecret` fails closed with `E_MISSING_HMAC_SECRET`.
   * Validates canonical claims (`DelegationTokenClaimsSchema`) and timing-safe HMAC-SHA256 signature (`E_INVALID_TOKEN_SIGNATURE`).
   * Enforces max lifetime of `300,000 ms` (5 min, `E_TOKEN_TTL_EXCEEDED`), ±`2,000 ms` clock skew (`E_TOKEN_EXPIRED`, `E_TOKEN_FUTURE`), consumed-nonce replay cache (`E_TOKEN_REPLAYED`), caller `subject` match (`E_SUBJECT_MISMATCH`), tool `audience` match (`E_AUDIENCE_MISMATCH`), `allowed_scopes` match (`E_UNAUTHORIZED_SCOPE`), taint state-change block (`E_TAINTED_STATE_CHANGE_BLOCKED`), and SoD lineage check (`E_SOD_SELF_CERTIFICATION`).

### 3.3 Resource Scope & Path Boundary Guard ([`scope-guard.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts))
[`ScopeBoundaryGuard`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L240-L372) recursively traverses top-level keys, nested objects, and arrays (depth limit `20`, node limit `10,000` -> `E_SCOPE_PAYLOAD_TOO_COMPLEX`, ancestor cycle protection) inspecting both known path parameter names ([`DEFAULT_PATH_ARGUMENT_NAMES`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L29-L42)) and any string value containing traversal markers, backslashes, null bytes, or non-HTTP URI schemes. [`validateAndResolvePath`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L47-L235) enforces nine sequential checks:
1. Non-empty string (`E_PATH_INVALID`).
2. Control chars `[\x00-\x1F\x7F]` and `%00` rejected (`E_PATH_NULL_BYTE`).
3. Double URL encoding (`decodeURIComponent` idempotence check) rejected (`E_PATH_DOUBLE_ENCODING`, `E_PATH_MALFORMED_ENCODING`).
4. Unicode `NFKC` normalization (neutralizes fullwidth traversal dots like `\uff0e\uff0e\uff0f`).
5. URI scheme allowlisting (`allowedUriSchemes`, default `['file', 'sqlite']`) converting `file://` via `fileURLToPath` (`E_INVALID_URI_SCHEME`).
6. Windows UNC network path rejection (`\\server\share`, `//server/share` -> `E_PATH_UNC_FORBIDDEN`).
7. NTFS Alternate Data Stream blocking (`file.txt::$DATA` -> `E_PATH_NTFS_ADS`).
8. Symlink canonicalization via `fs.realpathSync.native` (including nearest existing ancestor resolution) and root containment check against `allowedRoots` (`E_PATH_OUT_OF_BOUNDS`).
9. Sensitive path blacklist ([`DEFAULT_BLOCKED_PATTERNS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/scope-guard.ts#L18-L27)): `.git`, `.env*`, `id_rsa`/`id_ed25519`/`id_ecdsa`, `.aws/credentials`, `*.pem`/`*.key`/`*.pfx`/`*.p12`, `/etc/passwd`, `/etc/shadow` (`E_SENSITIVE_RESOURCE_BLOCKED`).

### 3.4 Multi-Tier Prompt Injection & Data Exfiltration Defense ([`prompt-injection.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts))
[`PromptInjectionDetector`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L214-L351) recursively walks strings, arrays, and **object keys** up to depth 20 (with cycle `WeakSet` protection):
* **Obfuscation Detection (`E_OBFUSCATION_CHARS`):** Detects zero-width/BiDi directional chars (`OBFUSCATION_CHARS_REGEX`), normalizes `NFKC`, strips zero-width chars, and applies [`normalizeLeetSpeak`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L58-L68) (`1->i`, `0->o`, `3->e`, `4->a`, `5->s`, `7->t`, `@->a`, `$->s`).
* **Critical Always-Block Vectors:**
  * [`BEHAVIORAL_OVERRIDE_PATTERNS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L19-L29) (`E_BEHAVIORAL_OVERRIDE`) — override/jailbreak/DAN/god-mode instructions.
  * [`EXFILTRATION_PATTERNS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L43-L47) (`E_EXFILTRATION_PAYLOAD`) — `webhook.site`, `burpcollaborator.net`, `oastify.com`, `requestbin.net`, `pipedream.net`, `ngrok.io`, `serveo.net`, `localhost.run`, `interact.sh`, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`), and markdown image leak syntax `![...](https://...)`.
  * Even when `policy.action === 'SANITIZE'`, any `BEHAVIORAL` or `EXFILTRATION` match forces `verdict: 'BLOCK'`!
* **Delimiter & Credential Patterns:** [`DELIMITER_PATTERNS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L31-L39) (`E_DELIMITER_INJECTION`) and [`CREDENTIAL_PATTERNS`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L49-L55) (`E_SECRET_ARGUMENT_LEAK`) trigger `BLOCK` or recursive [`sanitizeString`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/prompt-injection.ts#L186-L209) redaction (`[REDACTED_SECRET]`, `[SANITIZED_INJECTION]`, escaped XML tags).
* **`onToolResult` Output Hygiene:** Automatically applies `promptInjection.sanitize(result)` on tool responses before they reach the caller LLM context.

---

## 4. RFC 8785 Hash-Chained & Merkle Audit Custody ([`audit-logger.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts))

Every decision (`ALLOW`, `BLOCK`, `SANITIZE`) across `ON_LIST_TOOLS`, `ON_CALL_TOOL`, and `ON_TOOL_RESULT` is appended via a serialized promise `writeQueue` into either [`InMemoryAuditLogger`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L253-L346) or persistent NDJSON [`FileAuditLogger`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L351-L481):

* **Hash Chain Formula:**
  $$\text{current\_hash}_i = \text{SHA-256}(\text{canonicalStringify}(\text{event}_i \setminus \{\text{current\_hash}\}) + \text{prev\_hash}_i)$$
  starting at `GENESIS_HASH = "GENESIS_" + "0".repeat(64)`.
* **Binary Merkle Root & Inclusion Proofs:** [`computeMerkleRoot`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L81-L95) hashes pairs `sha256(left + right)` with odd-leaf duplication; [`generateMerkleProof`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L100-L129) and [`verifyMerkleProof`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L134-L144) enable $O(\log N)$ inclusion verification.
* **Startup Tamper Check:** When opening an existing NDJSON file, `FileAuditLogger.init()` parses every line and runs [`verifyGuardianAuditChain`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/runtime-guardian/src/audit-logger.ts#L149-L223), failing closed with `E_AUDIT_LOG_PARSE_CORRUPTED` or `E_AUDIT_LOG_TAMPERED` if any historical record was altered.

---

## 5. Configuration Reference

```ts
import {
  RuntimeGuardian,
  wrapMcpServer,
  createDelegationClaims,
  signDelegationToken,
} from '@script-kitty/runtime-guardian';

const guardian = new RuntimeGuardian({
  guardian_id: 'guardian-lab-01',
  environment: 'development',
  failClosed: true,
  errorMode: 'tool_result',
  policy: {
    toolPoisoning: {
      enabled: true,
      allowedTools: ['security.chainbreak.analyze', 'security.chainbreak.get'],
      allowShadowTools: false,
      allowUnregistered: false,
    },
    confusedDeputy: {
      enabled: true,
      enforceSeparationOfDuties: true,
      requireDelegationToken: true,
      hmacSecret: process.env.GUARDIAN_HMAC_SECRET, // never hardcode in prod
    },
    scopeGuard: {
      enabled: true,
      allowedRoots: [process.cwd()],
      allowedUriSchemes: ['file', 'sqlite'],
      allowSensitiveFiles: false,
    },
    promptInjection: {
      enabled: true,
      action: 'BLOCK',
      blockExfiltration: true,
      detectCredentials: true,
    },
    auditLogger: {
      enabled: true,
      logFilePath: '.context/guardian-audit.ndjson',
    },
  },
});

wrapMcpServer(mcpServer, guardian);
```
