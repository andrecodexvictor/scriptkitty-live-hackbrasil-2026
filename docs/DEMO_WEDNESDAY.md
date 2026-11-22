# ScriptKitty Live (`PatchCat`) — Wednesday / HackBR Demo Runbook

**Mode:** `LAB` (`productionTested: false`, `mergeAllowed: false`, `deployAllowed: false`)  
**Primary Executable Script:** [`scripts/demo-wednesday.mjs`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/scripts/demo-wednesday.mjs)  
**Canonical Runtime:** [`packages/security-actions/src/capabilities.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/capabilities.ts) (`createSecurityActionRuntime`)  
**Target Audience:** HackBR judges, technical reviewers, and security engineers running the local end-to-end verification demo.

---

## 1. Purpose & What the Demo Proves

The Wednesday / HackBR live demo exercises the real compiled **ScriptKitty 2.0 / PatchCat** TypeScript workspace in an isolated local **LAB** environment (with in-memory SQLite persistence `:memory:` so running the demo leaves zero uncommitted artifacts in the repository) across **10 sequential stages**:

1. **Fail-Closed Startup Readiness (`security.status`):** Verifies that experimental optimizers (`HARNESS2_EXPERIMENTS_ENABLED=false`) and offensive/external runners (Kali MCP, Mantis, Codex Security, Cloudflare) default strictly to `NOT_CONFIGURED` or `LAB_ISOLATED`, and that `mergeAllowed=false` and `deployAllowed=false` everywhere.
2. **Three Deterministically Modeled Screen States (`@script-kitty/chainbreak`):**
   - **State 1 (`payments-lab/baseline`):** Clean policy graph -> `0` forbidden paths, `3/3` legitimate business operations preserved.
   - **State 2 (`payments-lab/unsafe-rollout`):** Regressed rollout policy -> `1` deterministic reachable path (`PATH_VALIDATED`, *never* `EXPLOIT_CONFIRMED`) with cryptographic `inputSha256`, exact `sourceRef` policy pointers, and evidence hashes.
   - **State 3 (`payments-lab/remediated` + `payments-lab/negative-control`):** Minimal edge removal reduces forbidden paths from `1 -> 0` while preserving all `3/3` legitimate operations; negative control confirms `0` paths on non-traversable mismatched edges/conditions.
3. **Bounded JEV-as-a-Judge Triage (`@script-kitty/jev-judge`):** Sanitizes and bounds ChainBreak state via SHA-256 `sanitizedStateDigest`, validates input integrity, and adjudicates advisory triage (`PENDING_REVIEW`, `escalated: true`, `thresholdCalibrated: false`, `p0DefinedByJevAlone: false`). Transparently reports `providerStatus: "NOT_CONFIGURED"` and `decisionSource: "MOCK"` when `TYPESAFE_API_KEY` is unset.
4. **Counterfactual Defensive `RemediationSpec` (`security.remediation.spec`):** Synthesizes the minimal graph fix (`REMOVE_EDGE` on `e-rollout-exporter-read-pii`), proving it breaks the unauthorized PII transfer path while preserving legitimate payment/support operations and enforcing `requiresHumanApproval: true` (`autoApplyAllowed: false`).
5. **Invokta MCP Streamable HTTP (`127.0.0.1`) & Security Boundaries (`@script-kitty/security-actions`):** Boots an authentic HTTP MCP server on loopback (`127.0.0.1`), connects an official MCP SDK client, verifies HTTP-to-CLI idempotency parity (`idempotentReplay: true`), and verifies **4 fail-closed security rejections**: cross-tenant read (`FORBIDDEN`), JSON-RPC `tenantId` body injection, unauthenticated request (`HTTP 401`), and disallowed `Origin` (`HTTP 403`).
6. **Zero-Trust Quality Gate, Tri-Party SoD, RFC 8785 Custody & `factory.delivery.v1`:** Seals a 3-node SHA-256 / Merkle custody chain, demonstrates `DeterministicQualityGate` `PASS` when `A_disc != A_veri != A_auth` vs. `REJECT` (`E_SOD_SELF_CERTIFICATION`) when an agent self-certifies, and evaluates `factory.delivery.v1` eligibility while holding `mergeAllowed: false` and `deployAllowed: false`.
7. **Hardened Kali MCP Assessment (`@script-kitty/kali-mcp-assessment`):** Demonstrates `LAB_SANDBOX_ONLY`, static `--` `argv` tuple generation across all 4 allowlisted capabilities, instant fail-closed blocks for IMDS SSRF (`KALI_BLOCKED_IMDS_TARGET`) and flag injection (`KALI_FLAG_INJECTION_BLOCKED`), Profile A OCI+gVisor containment flag verification, fail-closed `LIVE_CONTAINER` rejection (`KALI_SANDBOX_UNAVAILABLE`), live `createKaliMcpServer` execution in `LAB_SIMULATION` via `RuntimeGuardian` (`wrapMcpServer`), Tri-Party SoD enforcement (`E_SOD_SELF_CERTIFICATION` rejection vs. `VERIFIED_TRUE_POSITIVE` custody over SHA-256 pinned [`apps/lab-app/repro/repro-sqli.mts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app/repro/repro-sqli.mts)), and Guardian Merkle audit verification.
8. **PatchCat Orchestrator & Unified Evidence Ledger (`@script-kitty/patchcat-orchestrator`, `@script-kitty/evidence`):** Drives the full rollout event-to-ZenPR loop (`zenpr.advisory.v1`) proving `1 -> 0` forbidden paths and `3/3` preserved operations, seals ChainBreak + Contract evidence into a tenant-isolated `EvidenceLedger` binary Merkle bundle with verified cryptographic inclusion proof, and asserts fail-closed blocks for policy/gate mutation (`E_POLICY_MUTATION_FORBIDDEN`), SoD violations (`E_SOD_VIOLATION`), unverified AI prose (`UNVERIFIED_AI_PROSE_REJECTED`), and cross-tenant evidence reads (`TENANT_ISOLATION_VIOLATION`) while holding `mergeAllowed: false` and `deployAllowed: false`.

---

## 2. Prerequisites & Environment Setup

| Requirement | Minimum / Verified Version | Notes |
|---|---|---|
| **Node.js** | `>= 22.0.0` (verified on `v22.23.2`) | Native `node:sqlite`, `node:test`, and ESM module loader required. |
| **npm** | `>= 10.x` (verified on `10.9.8`) | Monorepo workspaces (`packages/*`, `apps/*`). |
| **Network** | **Offline-capable (`127.0.0.1` loopback only)** | No outbound internet access needed unless testing live `TYPESAFE_API_KEY`. |

### Build Before Running

From the repository root (`c:\Users\adm\Desktop\Prototipos\Script Kitty`):

```bash
npm install
npm run build
```

> [!IMPORTANT]
> Wait for `npm run build` to succeed before running `node scripts/demo-wednesday.mjs`. The script imports compiled ESM modules from `@script-kitty/*` workspaces (`evidence`, `contracts`, `chainbreak`, `security-actions`, `quality-gate`, etc.) and compiled `dist/index.js` entrypoints (`packages/adapters/dist/index.js`, `packages/kali-mcp-assessment/dist/index.js`, `packages/patchcat-orchestrator/dist/index.js`).

### Environment Variables (Zero Secret Defaults)

| Variable | Default | Behavior |
|---|---|---|
| `TYPESAFE_API_KEY` | *(unset)* | Uses [`MockTypeSafeJevProvider`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/typesafe-provider.ts) offline (`providerStatus: "NOT_CONFIGURED"`, `decisionSource: "MOCK"`). If set cleanly in shell, switches JEV calls to `TypeSafeClient` HTTP (`/v1/systemone`). |
| `TYPESAFE_API_URL` | `https://api.typesafe.ai` | Base URL if live TypeSafe JEV mode is enabled. |
| `HARNESS2_EXPERIMENTS_ENABLED` | `false` | Hard-gated off in demo and default runtime. |
| `KALI_MCP_SANDBOX_ENABLED` | `false` | Keeps [`KaliMcpAdapter`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/adapters/src/kali-mcp-adapter.ts) in fail-closed `NOT_CONFIGURED` / `LAB_SANDBOX_ONLY` contract mode. |
| `SQLITE_DB` | `:memory:` inside demo script | No `.sqlite` files are created in the working tree by `demo-wednesday.mjs`. |

---

## 3. Execute the Demo

```bash
node scripts/demo-wednesday.mjs
```

Expected exit code: **`0`**.

---

## 4. Walkthrough of Expected Outputs by Stage

### `[1/10]` Readiness & Boundary Check (`security.status`)

Verifies platform operating bounds at startup:

```json
security.status: {
  "service": "@script-kitty/security-actions",
  "mode": "LAB",
  "productionTested": false,
  "mergeAllowed": false,
  "deployAllowed": false,
  "HARNESS2_EXPERIMENTS_ENABLED": false,
  "jevProviderStatus": "NOT_CONFIGURED",
  "kaliMcpStatus": "NOT_CONFIGURED",
  "kaliAllowedCapabilities": [
    "recon_surface",
    "config_audit",
    "verify_reproducer",
    "sbom_cve_check"
  ],
  "capabilities": [
    "security.chainbreak.analyze",
    "security.chainbreak.get",
    "security.judge.evaluate",
    "security.remediation.spec",
    "security.status"
  ]
}
```

### `[2/10]` Screen State 1 — Clean Baseline (`payments-lab/baseline`)

Fixture source: [`fixtures/payments-lab/baseline.json`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/fixtures/payments-lab/baseline.json)

```json
baseline.summary: {
  "analysisId": "cb-39d04f81814395a1",
  "fixtureId": "payments-lab/baseline",
  "policyVersion": "2026.11.09-baseline",
  "inputSha256": "76c07c4340acfc748443a496435867c819354f99241cd361cd585d2dc85a8bbc",
  "forbiddenPaths": 0,
  "legitimateOperationsPreserved": true,
  "legitimateOperationsCount": 3
}
```

### `[3/10]` Screen State 2 — Unsafe Rollout (`payments-lab/unsafe-rollout`)

Fixture source: [`fixtures/payments-lab/unsafe-rollout.json`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/fixtures/payments-lab/unsafe-rollout.json)

A single rollout permission grant (`mcp_tool:report-exporter --[can_read]--> data_asset:customer-payment-pii`) connects the external `support-agent` entrypoint to `external-report-sink`, violating `NO_RESTRICTED_DATA_EXTERNAL_TRANSFER`:

```json
unsafe-rollout.summary: {
  "analysisId": "cb-6b09ceec48ab6b21",
  "fixtureId": "payments-lab/unsafe-rollout",
  "policyVersion": "2026.11.09-unsafe-rollout",
  "inputSha256": "142cdbbd10b23de6967672f56587b29a5ef028dc727213810a85cc8bcf5b3da0",
  "forbiddenPaths": 1,
  "pathId": "path-4bb9497d66bd3024",
  "status": "PATH_VALIDATED",
  "semanticNote": "PATH_VALIDATED = deterministic reachability in modeled LAB policy graph (NOT EXPLOIT_CONFIRMED)",
  "violatedPolicyId": "NO_RESTRICTED_DATA_EXTERNAL_TRANSFER",
  "riskRecommendation": "P1",
  "edgeChain": [
    {
      "edgeId": "e-support-invoke-exporter",
      "transition": "identity:support-agent --[can_invoke]--> mcp_tool:report-exporter",
      "sourceRef": "policies/payments-lab/unsafe-rollout.policy.yaml#edges.support_invoke_exporter"
    },
    {
      "edgeId": "e-rollout-exporter-read-pii",
      "transition": "mcp_tool:report-exporter --[can_read]--> data_asset:customer-payment-pii",
      "sourceRef": "policies/payments-lab/report-exporter-rollout.yaml#L24"
    },
    {
      "edgeId": "e-exporter-transfer-external",
      "transition": "mcp_tool:report-exporter --[transfers_data_to]--> destination:external-report-sink",
      "sourceRef": "policies/payments-lab/report-exporter-rollout.yaml#L38"
    }
  ],
  "evidenceIds": [
    "ev-policy-2dcc3a767620df40",
    "ev-path-31fa82db6996753f"
  ]
}
```

### `[4/10]` JEV-as-a-Judge Advisory Evaluation (`security.judge.evaluate`)

JEV receives ONLY bounded, secret-scrubbed summaries + SHA-256 digests (`sanitizedStateDigest`) and returns non-binding triage requiring human review (`PENDING_REVIEW`):

```json
jev.adjudication: {
  "evaluationId": "jev-4ba1ec26bcdd03da",
  "analysisId": "cb-6b09ceec48ab6b21",
  "providerStatus": "NOT_CONFIGURED",
  "decisionSource": "MOCK",
  "model": "mock-offline-v0",
  "preValidationPassed": true,
  "triage": "likely_actionable",
  "status": "PENDING_REVIEW",
  "decision": "escalated_human_review",
  "escalated": true,
  "escalationReasons": [
    "JEV_FLAGGED_MANUAL_REVIEW: needs_manual_review=0.92 >= threshold 0.5",
    "CRITICAL_OR_UNDETERMINED_RISK: deterministic risk=P1 requires mandatory human review"
  ],
  "riskRecommendation": "P1",
  "thresholdCalibrated": false,
  "sanitizedStateDigest": "53260c975c0503dea2affbb7fced13987881713e64d88225cbdad5aa523dcced",
  "mergeAllowed": false,
  "deployAllowed": false,
  "p0DefinedByJevAlone": false
}
```

### `[5/10]` Minimal Defensive `RemediationSpec` (`security.remediation.spec`)

Produces a human-approval-gated minimal intervention targeting ONLY the unsafe edge while preserving all 3 legitimate business operations (`op-finance-process-payments`, `op-non-sensitive-export`, `op-support-read-profile`):

```json
remediation.spec: {
  "remediationId": "rem-1831f4a4aa2e733b",
  "minimalChange": true,
  "action": {
    "actionType": "REMOVE_EDGE",
    "edgeId": "e-rollout-exporter-read-pii",
    "from": "mcp_tool:report-exporter",
    "to": "data_asset:customer-payment-pii",
    "edgeKind": "can_read",
    "currentScope": "reporting-public",
    "currentDataClassification": "RESTRICTED",
    "proposedChange": "Remove or disable edge 'e-rollout-exporter-read-pii' (mcp_tool:report-exporter --[can_read]--> data_asset:customer-payment-pii) in scope 'reporting-public'",
    "sourceRef": "policies/payments-lab/report-exporter-rollout.yaml#L24"
  },
  "breaksUnauthorizedPath": true,
  "preservesLegitimateOperations": true,
  "preservedOperationIds": [
    "op-finance-process-payments",
    "op-non-sensitive-export",
    "op-support-read-profile"
  ],
  "requiresHumanApproval": true,
  "autoApplyAllowed": false
}
```

### `[6/10]` Screen State 3 — Remediated (`payments-lab/remediated`) & Negative Control

Fixtures: [`remediated.json`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/fixtures/payments-lab/remediated.json) & [`negative-control.json`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/fixtures/payments-lab/negative-control.json)

- `remediated`: `cb-b04ba60ed258d095` -> **`forbiddenPathsBefore: 1` -> `forbiddenPathsAfter: 0`**, `legitimateOperationsPreserved: true`, `preservedCount: 3`.
- `negative-control`: `cb-4f3a138c21a72a32` -> **`forbiddenPaths: 0`** (`COMPLETED`), proving non-traversable conditions/edge types are not misclassified as attack chains.

### `[7/10]` Live MCP Streamable HTTP (`127.0.0.1`) Invocation & Fail-Closed Tests

Binds [`startMcpHttpServer`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/mcp-http.ts) to `http://127.0.0.1:<ephemeral-port>/mcp` and tests both authorized SDK client parity and 4 adversarial rejections:

| Check | Transport / Request | Observed Enforcement |
|---|---|---|
| `tools/list` (Alpha tenant) | Valid Bearer + allowed `Origin: http://127.0.0.1:5173` | Lists 5 `security.*` tools |
| `security.chainbreak.analyze` (`payments-lab/unsafe-rollout`) | Valid Bearer (`payments-lab`) | `analysisId: "cb-6b09ceec48ab6b21"`, `idempotentReplay: true` |
| `security.chainbreak.get` | Valid Bearer (`payments-lab`) | Returns persisted analysis, `1` adjudication, `1` spec, `2` history events |
| Cross-tenant MCP read (`tenant-beta` reading `payments-lab` ID) | Valid Bearer for wrong tenant | **REJECTED (`isError: true`, `code: "FORBIDDEN"`)** |
| Payload `tenantId` body injection (`{ tenantId: "payments-lab" }`) | Strict Zod `.strict()` + server tenant derivation | **REJECTED (`isError: true`)** |
| Missing Bearer header | Unauthenticated HTTP `POST` | **`HTTP 401 Unauthorized`** |
| Untrusted `Origin: https://evil.example` | DNS-rebinding defense | **`HTTP 403 Forbidden`** |

### `[8/10]` Zero-Trust Quality Gate, Tri-Party SoD, RFC 8785 Custody & `factory.delivery.v1`

- **RFC 8785 Custody Chain:** 3 linked nodes (`FINDING -> EVIDENCE -> PATCH`) anchored to `GENESIS_...` with deterministic binary Merkle root (`valid: true`).
- **`DeterministicQualityGate` (Tri-Party SoD `A_disc != A_veri != A_auth`):** Evaluates to **`PASS`**.
- **Adversarial Self-Certification Test (`A_disc == A_veri == "agent-omnipotent"`):** Immediately evaluates to **`REJECT`** (`sodValid: false`, `E_SOD_SELF_CERTIFICATION: Discovering agent cannot verify its own finding`).
- **`factory.delivery.v1` Contract:** Evaluates `eligible: true`, `stage: "approved"` when checks and independent review pass — while strictly maintaining **`mergeAllowed: false`**, **`deployAllowed: false`**, **`externalExecution: false`**.

### `[9/10]` Hardened Kali MCP Assessment (`@script-kitty/kali-mcp-assessment`)

Exercises [`@script-kitty/kali-mcp-assessment`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/src/index.ts) end-to-end across static `argv` hardening, isolation profile flags, fail-closed `LIVE_CONTAINER` probing, and live `RuntimeGuardian`-wrapped MCP calls in explicit `LAB_SIMULATION`:

```json
kali-mcp-assessment.summary: {
  "mode": "LAB_SANDBOX_ONLY",
  "executionMode": "LAB_SIMULATION",
  "simulated": true,
  "pinnedTools": [
    "security.kali.recon_surface",
    "security.kali.config_audit",
    "security.kali.verify_reproducer",
    "security.kali.sbom_cve_check"
  ],
  "staticArgvSamples": {
    "recon": ["nmap", "-sT", "-Pn", "-n", "--max-retries", "1", "--host-timeout", "20s", "-p", "80,443,3000", "-oX", "-", "--", "127.0.0.1"],
    "configAudit": ["trivy", "config", "--offline-scan", "--format", "json", "--quiet", "--", "/workspace/apps/lab-app/package.json"],
    "verifyReproducer": ["node", "--disallow-code-generation-from-strings", "--", "/workspace/apps/lab-app/repro/repro-sqli.mts"],
    "sbomCveCheck": ["trivy", "fs", "--offline-scan", "--skip-db-update", "--format", "json", "--quiet", "--severity", "CRITICAL,HIGH", "--", "/workspace/apps/lab-app/package.json"]
  },
  "failClosedChecks": {
    "liveContainerWithoutRuntime": "KALI_SANDBOX_UNAVAILABLE",
    "imdsSsrfBlocked": "KALI_BLOCKED_IMDS_TARGET",
    "cliFlagInjectionBlocked": "KALI_FLAG_INJECTION_BLOCKED",
    "selfCertificationSodBlocked": "E_SOD_SELF_CERTIFICATION"
  },
  "verifiedEvidence": {
    "evidenceId": "SK-EVID-KALI-ee5e0cf93a0bfeed",
    "status": "VERIFIED_TRUE_POSITIVE",
    "pinnedScriptSha256": "171566139088fd8c8f61cd016802e37cd792a82a3bf754a4095e905f2f4554ae",
    "custodyValid": true,
    "guardianAuditEvents": 10
  }
}
```

- Verifies Profile A (`OCI + gVisor runsc`, `--cap-drop=ALL`, `--read-only`, `--user=65532:65532`, pinned digest) via `validateProfileAArgs`.
- Confirms `KaliSandboxOrchestrator` fails closed with `KALI_SANDBOX_UNAVAILABLE` in `LIVE_CONTAINER` mode when no host OCI/gVisor or WSL2 sandbox exists.
- Runs all 4 allowlisted tools via `createKaliMcpServer` (`wrapMcpServer`, HMAC delegation, Tri-Party SoD, RFC 8785 custody) and validates the 10-event Guardian audit Merkle root (`bf7e678d...`).

### `[10/10]` PatchCat Orchestrator & Unified Evidence Ledger (`@script-kitty/patchcat-orchestrator`, `@script-kitty/evidence`)

Exercises [`PatchCatOrchestrator`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/patchcat-orchestrator/src/orchestrator.ts) and [`EvidenceLedger`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/evidence/src/ledger.ts) in `:memory:` mode to emit a schema-validated signed `zenpr.advisory.v1` bundle paired with a binary Merkle evidence bundle and verified cryptographic inclusion proof:

```json
zenpr-advisory-and-evidence-ledger: {
  "zenPrBundle": {
    "bundleId": "zenpr-c96d79fb0fe2b02b",
    "schemaVersion": "zenpr.advisory.v1",
    "status": "REMEDIATION_PROPOSED",
    "forbiddenPathDeltaSummary": "1 -> 0",
    "legitimateOperationsSummary": "3/3",
    "merkleRoot": "8fc754e773585e26525473fb72b075eb0261ee4973d11b0f1d4edfca6f0502b6",
    "bundleDigestSha256": "623ac40e96e9ae3c9c14becb92cb0156c314008f86dc960fcf4c4f8349db71e8",
    "policyMutationAllowed": false,
    "gateMutationAllowed": false,
    "autoApplyAllowed": false,
    "mergeAllowed": false,
    "deployAllowed": false,
    "requiresHumanApproval": true
  },
  "evidenceLedgerBundle": {
    "bundleId": "merkle-ececf08bffadd6bf",
    "schemaVersion": "evidence.merkle.bundle.v1",
    "leafCount": 2,
    "crossLinksCount": 1,
    "merkleRoot": "0618d487f876b5b3f5cdf7ba48b7385f1da2ca54ec3b18f9cc1d402e9e1d797e",
    "bundleSha256": "852a752b56716b3b5bfb80e628bc5e96f2db7733edcca3d96935479843e4475d",
    "verified": true,
    "inclusionProofValid": true,
    "firstLeafEvidenceId": "SK-EVID-CB-PAYMENTS-001",
    "inclusionProofSteps": 1
  },
  "failClosedChecks": {
    "policyMutationBlocked": "E_POLICY_MUTATION_FORBIDDEN",
    "sodViolationBlocked": "E_SOD_VIOLATION",
    "unverifiedAiProseBlocked": "UNVERIFIED_AI_PROSE_REJECTED",
    "crossTenantEvidenceBlocked": "TENANT_ISOLATION_VIOLATION"
  }
}
```

- Verifies `ZenPrBundleSchema.parse(...)`, `beforeAfterProof` (`1 -> 0` forbidden paths, `3/3` legitimate operations), `triPartySod.allDistinct: true`, and `factory.delivery.v1` non-merging locks (`mergeAllowed: false`, `deployAllowed: false`).
- Records both ChainBreak graph evidence (`GRAPH_PATH`) and verified Contract evidence (`REPRODUCES_PATH`) into [`EvidenceLedger`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/evidence/src/ledger.ts), verifying `evidence.merkle.bundle.v1` and single-leaf inclusion proof via `verifyAnalysisMerkleBundle` and `verifyMerkleProof`.
- Proves fail-closed rejection across all four adversarial boundaries: `E_POLICY_MUTATION_FORBIDDEN`, `E_SOD_VIOLATION`, `UNVERIFIED_AI_PROSE_REJECTED`, and `TENANT_ISOLATION_VIOLATION`.

---

## 5. Additional Live AppSec Verification Commands (Optional Deep Dive)

To demonstrate real code patching on [`apps/lab-app`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/apps/lab-app) (`CWE-89`, `CWE-78`, `CWE-639`), `@script-kitty/kali-mcp-assessment`, `@script-kitty/evidence`, `@script-kitty/patchcat-orchestrator`, the Python security packages, interactive UI/CLI/MCP apps, or the unified 7-tier suite:

```bash
# Run intentional-vulnerability lab baseline tests (10/10 pass)
npm test --workspace=@script-kitty/lab-app

# Run autonomous FIND -> PROVE -> FIX -> VERIFY -> LEARN remediation lifecycle tests (32/32 pass)
npm test --workspace=@script-kitty/remediation-engine

# Run hardened Kali MCP Assessment unit & negative security tests (16/16 pass)
npm test --workspace=@script-kitty/kali-mcp-assessment

# Run Unified Evidence Ledger & binary Merkle bundle tests (11/11 pass)
npm test --workspace=@script-kitty/evidence

# Run PatchCat Orchestrator event-to-ZenPR & fail-closed SoD tests (6/6 pass)
npm test --workspace=@script-kitty/patchcat-orchestrator

# Run unified 7-tier verification suite (121/121 pass across Tiers 1-7)
node packages/verification-suite/tests/run-all.mts

# Run Python security packages & hardened Kali Docker/seccomp verification (20/20 pass)
python -m unittest discover -s tests/python -p "test_*.py" -v

# Run CLI, MCP stdio server v0.2.0, and PatchCat Live UI suites
npm test --workspace=@script-kitty/cli
npm test --workspace=@script-kitty/mcp-server
npm test --workspace=@script-kitty/ui

# Optional interactive UI dev server (127.0.0.1 loopback / LAB fallback)
npm run dev --workspace=@script-kitty/ui
```

---

## 6. Honest Limitations (Explicit Disclosure for Judges)

1. **`LAB` Mode Only (`productionTested: false`):** All targets (`fixtures/payments-lab/*` and `apps/lab-app/*`) are synthetic/local laboratory targets. No live production infrastructure is scanned or mutated.
2. **Offline Mock JEV Default (`NOT_CONFIGURED` / `MOCK`):** Unless `TYPESAFE_API_KEY` is provided in the host environment, `TypeSafeClient` is not contacted and `MockTypeSafeJevProvider` supplies fail-closed escalated mock triage (`decisionSource: "MOCK"`).
3. **`PATH_VALIDATED` Semantics:** ChainBreak proves deterministic reachability inside the modeled policy graph fixture; it does **not** execute live remote exploits (`EXPLOIT_CONFIRMED` is strictly prohibited in MVP).
4. **No Autonomous Production Merge/Deploy or Policy Mutation:** Across all modules (`ChainBreak`, `JEV-as-a-Judge`, `RemediationSpec`, `DeterministicQualityGate`, `factory.delivery.v1`, `@script-kitty/patchcat-orchestrator`, `ZenPR`), `policyMutationAllowed`, `gateMutationAllowed`, `autoApplyAllowed`, `mergeAllowed`, and `deployAllowed` remain hard-locked to `false`, and `@script-kitty/evidence` rejects unverified AI prose (`UNVERIFIED_AI_PROSE_REJECTED`).
5. **External Adapters & Host Container Runtimes Gated Fail-Closed:** [`@script-kitty/kali-mcp-assessment`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/src/index.ts) runs deterministic offline `LAB_SIMULATION` (`simulated: true`) until a host OCI+gVisor or hardened `scriptkitty-kali-sandbox` WSL2 runtime is provisioned (`LIVE_CONTAINER` fails closed with `KALI_SANDBOX_UNAVAILABLE`); `KaliMcpAdapter` (`NOT_CONFIGURED`), `Harness2Adapter` (`HARNESS2_EXPERIMENTS_ENABLED=false`), `MantisAdapter`, `CodexSecurityAdapter`, and `CloudflareAdapter` fail closed unless explicitly configured; and although root [`Dockerfile`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/Dockerfile) plus [`Dockerfile.kali-sandbox`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/docker/Dockerfile.kali-sandbox), [`seccomp-kali-lab.json`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/kali-mcp-assessment/docker/seccomp-kali-lab.json), and [`docker-compose.kali-lab.yml`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/docker-compose.kali-lab.yml) are structurally verified on disk, container images have not been built/booted on a host lacking a Docker daemon.
