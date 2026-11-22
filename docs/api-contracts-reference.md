# ScriptKitty 2.0 & ScriptKitty Live — API Contracts Reference

**Packages Documented:**
- [`@script-kitty/contracts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/index.ts) (`security-finding`, `evidence`, `patch-proposal`, `gate-decision`, RFC 8785 custody & Merkle tree)
- [`@script-kitty/chainbreak`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/index.ts) (`chainbreak.graph.v1`, `security.analysis.v1`, `RemediationSpec`, `ExecutionScope`)
- [`@script-kitty/jev-judge`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/index.ts) (`AdjudicationResult`, `PreValidationResult`, `AtomicJevAnswers`, escalation policy)
- [`@script-kitty/company-context`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/company-context/src/index.ts) (`factory.delivery.v1`, tenant-isolated `CompanyBrainStore`)
- [`@script-kitty/security-actions`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/index.ts) (Action Engine capabilities & MCP Streamable HTTP transport)

All contracts enforce strict **Zod** validation at runtime and embed deterministic fail-closed invariants so probabilistic models, missing provenance, or tampered artifacts can never silently authorize a merge or deployment.

---

## 1. `@script-kitty/contracts` (AppSec & AgentSec Core Evidence Fabric)

Entrypoint: [`packages/contracts/src/index.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/index.ts)

### 1.1 Common Enumerations & Taxonomies ([`common.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts))

| Symbol | Values / Constraint | Notes |
|---|---|---|
| [`Severity`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L8-L21) / `SeveritySchema` | `'CRITICAL' \| 'HIGH' \| 'MEDIUM' \| 'LOW' \| 'INFO'` | [`severityToScore`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L26-L39) maps `10.0 / 8.0 / 5.0 / 2.0 / 0.0`. |
| [`Confidence`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L46-L63) / `ConfidenceSchema` | `'CERTAIN' \| 'FIRM' \| 'TENTATIVE'` | Preprocess coerces `'HIGH' -> 'CERTAIN'`, `'MEDIUM' -> 'FIRM'`, `'LOW' -> 'TENTATIVE'`. |
| [`TargetType`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L70-L97) / `TargetTypeSchema` | `'SOURCE_CODE' \| 'DEPENDENCY' \| 'API_ENDPOINT' \| 'MCP_TOOL' \| 'LLM_PROMPT' \| 'AGENT_MEMORY' \| 'CONFIGURATION' \| 'CONTAINER_IMAGE' \| 'CLOUD_RESOURCE'` | Default in findings: `'SOURCE_CODE'`. |
| [`VerificationStatus`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L104-L121) | `'VERIFIED_TRUE_POSITIVE' \| 'REFUTED_FALSE_POSITIVE' \| 'INCONCLUSIVE' \| 'EXECUTION_ERROR'` | Only `VERIFIED_TRUE_POSITIVE` establishes exploitability/reproducibility. |
| [`VerificationType`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L128-L149) | `'REPRODUCER_EXECUTION' \| 'DETERMINISTIC_AST' \| 'EDGE_TELEMETRY' \| 'DUAL_OPINION_CONSENSUS' \| 'SYNTHETIC_BENCHMARK_PROBE' \| 'HEURISTIC'` | Empirical proof classification. |
| [`GateVerdict`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L177-L191) | `'PASS' \| 'BLOCK' \| 'REJECT' \| 'REQUIRES_HUMAN_APPROVAL' \| 'HOLD' \| 'ERROR'` | Re-exported from [`gate.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/gate.ts#L14). |
| [`CweIdSchema`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L215-L218) | Regex `/^CWE-\d+$/` | Includes `CommonCwe` constants (`CWE-22`, `CWE-78`, `CWE-89`, `CWE-639`, `CWE-918`, etc.). |
| [`OwaspCategorySchema`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/common.ts#L268-L274) | Regex `/^(A\d{2}:2021\|API\d{1,2}:2023\|LLM\d{2}:2025)[-:][\w\s-]+$/i` | Pre-defined maps: `OwaspWeb2021`, `OwaspApi2023`, `OwaspLlm2025`. |

### 1.2 Core Domain Schemas & Cryptographic Custody

| Contract | File & Symbol | Required Core Fields & Structural Invariants |
|---|---|---|
| **`SecurityFinding`** | [`finding.ts#L99-L142`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/finding.ts#L99-L142) | `finding_id`, `source_engine`, `title` (1..500), `cwe_id`, `owasp_category`, `severity`, `confidence`, `target`, `location` (`file_path`, 1-indexed `start_line <= end_line`), 64-hex `fingerprint`, `commit_hash` (7..64 hex), ISO-8601 UTC `discovered_at`, optional `agent_context` & `agent_sec`. Safe helper: [`validateFinding`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/index.ts#L74-L80), fingerprint via [`computeFindingFingerprint`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/finding.ts#L148-L157). |
| **`Evidence`** | [`evidence.ts#L147-L199`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/evidence.ts#L147-L199) | `evidence_id`, `finding_id`, `verification_type`, `status`, `verifier_agent_id`, `sandbox_environment` (`runtime`, mandatory boolean `network_isolated`, `timeout_ms`), optional `reproducer_artifact` (64-hex `script_sha256`, `exit_code`, `stdout`, `stderr`), optional `reproduction_proof`, `system_trace`, 64-hex `chain_hash`, optional Ed25519 `signature`, ISO-8601 UTC `recorded_at`. Hash helper: [`computeEvidenceChainHash`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/evidence.ts#L205-L222). |
| **`PatchProposal`** | [`patch.ts#L128-L171`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/patch.ts#L128-L171) | `patch_id` (`/^SK-PATCH-[a-zA-Z0-9_\-]+$/`), `finding_id`, `author_engine`, `diff_content`, non-empty `affected_files`, `base_commit`, 64-hex `patch_sha256`, `recheck_status` (`passed_clean \| reproducer_still_fails \| regression_detected \| untested`), `blast_radius` (`ast_impact_scope`, `breaking_change_risk`), non-empty `rollback_plan.revert_patch`. **Invariant:** `recheck_status === 'passed_clean'` requires non-null `recheck_evidence_id`. Helpers: [`computePatchSha256`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/patch.ts#L176-L179), [`isPatchEligibleForAutoGate`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/patch.ts#L191-L199). |
| **`GateDecision`** | [`gate.ts#L185-L267`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/gate.ts#L185-L267) | `decision_id` (`/^SK-GATE-[a-zA-Z0-9_\-]+$/`), `policy_version`, `policy_id`, `target_commit`, `verdict`, `blocking_findings`, `unverified_findings`, 64-hex `audit_merkle_root`, `sod_evaluation`, `rules_evaluated`, `evaluation_summary`, `decided_at`. **Zero-Trust `superRefine` Invariants:** (1) `verdict === 'PASS'` forbids non-empty `blocking_findings` or `unverified_findings`; (2) `evaluateSeparationOfDuties(A_disc, A_veri, A_auth)` is independently recomputed; (3) SoD overlap forces `verdict === 'REJECT'` and cannot be overridden by client `is_valid: true`. |
| **Custody & Merkle** | [`custody.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts) | [`canonicalStringify`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts#L92-L112) (RFC 8785 lexicographical key sorting, whitespace removal, `undefined` omission), leaf hashers stripping self-referential fields (`hashSecurityFinding`, `hashEvidence`, `hashPatchProposal`, `hashGateDecision`), [`buildCustodyChain`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts#L364-L474), [`verifyChainOfCustody`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/index.ts#L150-L233), binary Merkle tree [`computeMerkleRoot`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/contracts/src/custody.ts) (duplicates odd leaf), `generateMerkleProof`, `verifyMerkleProof`. |

---

## 2. `@script-kitty/chainbreak` (`chainbreak.graph.v1` & `security.analysis.v1`)

Entrypoint: [`packages/chainbreak/src/index.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/index.ts) · Schemas: [`packages/chainbreak/src/schemas.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts)

### 2.1 Graph & Analysis Schemas

| Schema | Allowed Values / Key Constraints | Source |
|---|---|---|
| `AttackGraphNodeSchema` | `nodeId`, `kind` (`identity \| agent \| mcp_tool \| api \| service \| data_asset \| destination`), `label`, `tenantId`, `scope`, `allowedScopes?`, `roles`, `dataClassification?` (`PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`), `allowedClassifications?`, `trustZone` (`INTERNAL \| DMZ \| EXTERNAL`), `sourceRef`. | [`schemas.ts#L43-L71`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L43-L71) |
| `AttackGraphEdgeSchema` | `edgeId`, `from`, `to`, `kind` (`can_invoke \| can_read \| can_write \| transfers_data_to \| assumes_role \| delegates_to`), `tenantId`, `scope`, `conditions` (`effect: ALLOW \| DENY`, `active`, `requiredScopes`, `requiredRoles`, `requiresMfa/mfaVerified`, `requiresPiiMasking/piiMaskingApplied`, `allowedDataClassifications`, `expressions`), **non-empty `sourceRef` & `policyVersion`**, `dataClassification`. *(Input variant `PolicyGraphEdgeInputSchema` defaults missing refs to `''` so the analyzer downgrades paths to `INCONCLUSIVE` instead of crashing.)* | [`schemas.ts#L73-L148`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L73-L148) |
| `FindingStatusSchema` | `'POTENTIAL' \| 'PATH_VALIDATED' \| 'INCONCLUSIVE' \| 'NOT_REPRODUCED'` — **strictly forbids `'EXPLOIT_CONFIRMED'`**. `PATH_VALIDATED` denotes deterministic reachability inside the modeled policy graph only. | [`schemas.ts#L158-L164`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L158-L164) |
| `AttackPathSchema` | `pathId`, `startIdentity`, `targetAsset`, `targetDestination?`, ordered `edges` (`AttackPathEdge[]` citing `edgeId`, `kind`, `scope`, `sourceRef`, `policyVersion`), `violatedPolicyId`, `status`, `evidenceIds`, `riskRecommendation` (`P0 \| P1 \| P2 \| P3 \| UNDETERMINED`), `explanation`, `nonTechnicalSummary`, `missingReferences?`. | [`schemas.ts#L188-L202`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L188-L202) |
| `ChainBreakEvidenceSchema` | `evidenceId`, `analysisId`, `kind` (`POLICY_SNAPSHOT \| GRAPH_PATH \| TEST_RESULT \| QUALITY_RESULT`), `sourceRef`, 64-hex `contentSha256`, `producer`, `createdAt` (ISO-8601), `commitSha?`, `verified`. | [`schemas.ts#L208-L230`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L208-L230) |
| `RemediationSpecSchema` | `remediationId`, `analysisId`, `tenantId`, `fixtureId`, `pathId`, `violatedPolicyId`, `riskRecommendation`, `minimalChange`, non-empty `actions` (`REMOVE_EDGE \| RESTRICT_DATA_CLASSIFICATION \| RESTRICT_SCOPE \| ADD_DENY_CONDITION`), `breaksUnauthorizedPath`, `preservesLegitimateOperations`, `preservedOperationIds`, `acceptanceCriteria`, `verificationTests`, **`requiresHumanApproval: z.literal(true)`**, **`autoApplyAllowed: z.literal(false)`**, `rationale`, `nonTechnicalSummary`, `evidenceIds`, `createdAt`. | [`schemas.ts#L232-L278`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L232-L278) |
| `ExecutionScopeSchema` | `tenantId`, `principalId`, **`mode: z.literal('LAB')`**, allowlisted `allowedFixtures` (`payments-lab/baseline`, `payments-lab/unsafe-rollout`, `payments-lab/remediated`, `payments-lab/negative-control`), `maxNodes <= 10_000` (default `500`), `maxDepth <= 64` (default `12`), `maxPaths <= 500` (default `50`), `maxDurationMs <= 30_000` (default `5_000`), **`allowProductionExecution: z.literal(false)`**, **`allowAutoMergeOrDeploy: z.literal(false)`**. | [`schemas.ts#L280-L300`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L280-L300) |
| `SecurityAnalysisSchema` | `schemaVersion: 'security.analysis.v1'`, `analysisId`, `tenantId`, `fixtureId`, `policyVersion`, **`mode: 'LAB'`**, `paths`, `evidenceIds`, `evidence`, `remediationSpecs`, `legitimateOperations`, `legitimateOperationsPreserved`, `startedAt`, `completedAt?`, `status` (`QUEUED \| RUNNING \| COMPLETED \| INCONCLUSIVE \| FAILED`), 64-hex `inputSha256`, **`source: 'DETERMINISTIC_LAB_ANALYSIS'`**, **`productionTested: false`**, `budgetStats?`, `diagnostics`. | [`schemas.ts#L390-L415`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/schemas.ts#L390-L415) |

### 2.2 Analyzer & Verification APIs
- `analyzeFixture(fixtureId, options?)` ([`analyzer.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/analyzer.ts)): Rejects any non-allowlisted fixture with `ChainBreakError('DISALLOWED_FIXTURE')` before disk access, binds `tenantId` to the authenticated `executionScope` while keeping fixture `inputSha256` intact.
- `analyzePolicyGraph(input, options?)`: Computes deterministic input hash (`computePolicyGraphSha256`), detects tampering (`TAMPER_DETECTED`), checks tenant uniformity (`TENANT_MISMATCH`), explores policy-constrained reachability ([`reachability.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/reachability.ts)), verifies legitimate operations, and synthesizes minimal `RemediationSpec` via counterfactual removal simulation ([`remediation.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/chainbreak/src/remediation.ts)).

---

## 3. `@script-kitty/jev-judge` (JEV-as-a-Judge Advisory Pipeline)

Entrypoint: [`packages/jev-judge/src/index.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/index.ts) · Schemas: [`packages/jev-judge/src/schemas.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/schemas.ts) · Pipeline: [`packages/jev-judge/src/pipeline.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/pipeline.ts)

### 3.1 Atomic JEV Output & Adjudication Schemas

- **`JEV_RUBRIC_VERSION`**: `'jev-rubric-v0'`
- **`AtomicJevAnswersSchema`** ([`schemas.ts#L94-L99`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/schemas.ts#L94-L99)):
  - `evidence_sufficient`: `{ type: 'noul', noul: number (0..1) }`
  - `needs_manual_review`: `{ type: 'noul', noul: number (0..1) }`
  - `triage`: `{ type: 'choice', choice: 'likely_actionable' | 'needs_more_evidence' | 'likely_irrelevant', confidence: number (0..1), probabilities: Record<string, number> }`
- **`PreValidationResultSchema`** ([`schemas.ts#L109-L122`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/schemas.ts#L109-L122)): Records 5 mandatory deterministic gate checks executed *before* calling JEV (`identityAndTenantScope`, `labModeBoundary`, `hashIntegrity`, `evidenceCompletenessAndVerification`, `policyAndSourceRefs`) and `blockingOutcome` (`NONE | BLOCKED | REJECTED`).
- **`JevEscalationPolicyConfigSchema`** ([`schemas.ts#L124-L130`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/schemas.ts#L124-L130)): Defaults `{ confidenceThreshold: 0.75, evidenceSufficiencyThreshold: 0.75, manualReviewThreshold: 0.5, escalateOnCriticalRisk: true, fallbackOnProviderError: 'HUMAN_PENDING' }`.
- **`ConfidenceOrUncertaintySchema`** ([`schemas.ts#L242-L250`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/schemas.ts#L242-L250)): Nested inside `AdjudicationResultSchema` (`confidenceOrUncertainty`), binding `confidence`, `uncertainty`, `evidenceSufficiencyScore`, `manualReviewScore`, `threshold`, **`thresholdCalibrated: z.literal(false)`**, and `calibrationNote` to prevent claiming unverified calibration.
- **`AdjudicationResultSchema`** ([`schemas.ts#L255-L294`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/schemas.ts#L255-L294)):
  - `status`: `'ACCEPTED_FOR_TRIAGE' | 'PENDING_REVIEW' | 'BLOCKED' | 'REJECTED' | 'INCONCLUSIVE'`
  - `decisionSource`: `'LIVE' | 'MOCK' | 'FALLBACK' | 'HUMAN_PENDING'`
  - `providerStatus`: `'LIVE' | 'NOT_CONFIGURED' | 'FALLBACK' | 'UNAVAILABLE'`
  - `riskRecommendation`: `'P0' | 'P1' | 'P2' | 'P3' | 'NONE' | 'UNDETERMINED'`
  - **Hard Non-Authorization Literals:** `mergeAllowed: false`, `deployAllowed: false`, `exploitConfirmed: false`, `p0DefinedByJevAlone: false`.

### 3.2 Sanitization & Provider Interfaces
- [`sanitizeStateForJev`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/sanitizer.ts) constructs `jev.sanitized.state.v1` containing strictly allowlisted graph metadata (`analysisId`, `fixtureId`, `policyVersion`, sanitized paths/edge classifications/counts, evidence refs) — **throws `SANITIZATION_FAILED`** if any credential, private key, JWT, raw SQL, or local filesystem path survives sterilization.
- [`TypeSafeClient`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/jev-judge/src/typesafe-provider.ts) posts to `${baseURL}/v1/systemone` using Bearer `TYPESAFE_API_KEY` via Node built-in `fetch`; absent an API key, `resolveDefaultJevProvider` returns `MockTypeSafeJevProvider` (`decisionSource: 'MOCK'`, `providerStatus: 'NOT_CONFIGURED'`). *(Note: `@typesafe-ai/sdk` npm dependency is not installed; client is wire-compatible via HTTP JSON API.)*

---

## 4. `@script-kitty/company-context` (`factory.delivery.v1` & CompanyBrainStore)

Entrypoint: [`packages/company-context/src/index.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/company-context/src/index.ts) · Schemas: [`packages/company-context/src/schemas.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/company-context/src/schemas.ts) · Store: [`packages/company-context/src/store.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/company-context/src/store.ts)

### 4.1 `factory.delivery.v1` Eligibility Contract ([`schemas.ts#L61-L423`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/company-context/src/schemas.ts#L61-L423))
- **`FACTORY_DELIVERY_POLICY`**: `contract: 'factory.delivery.v1'`, `deadlineHours: 24`, `maxSubmissions: 4`, `requiredChecks: ['tests', 'typecheck', 'build']`, `externalExecution: false`, `mergeAllowed: false`, `deployAllowed: false`, `deploymentAllowed: false`.
- **Input (`FactoryDeliveryRecordSchema`, `.strict()`):** `{ contract: 'factory.delivery.v1', snapshot: { cancelled, deadlineAt, submissions (0..4), maxSubmissions: 4, artifact, review, submitter, reviewer }, authority: { requesterActive, submitterActive, reviewerActive, enabled } }`.
- **Output (`FactoryDeliveryEligibilityResultSchema`):** `{ contract: 'factory.delivery.v1', eligible, stage, blockReason, submissionsRemaining, correctionsRemaining, commitSha?, checkedAt, externalExecution: false, mergeAllowed: false, deployAllowed: false, deploymentAllowed: false }`.
- **Evaluator Functions:** `normalizeDeliveryRecord`, `evaluateFactoryDeliveryEligibility`, `checkFactoryDeliveryRecord` (requires 40/64-hex `headSha`). Fails closed on all 16 `DeliveryBlockReason` cases including self-review (`INDEPENDENT_REVIEW_REQUIRED`), stale commit (`HEAD_CHANGED` / `REVIEW_STALE`), expired UTC deadline (`DEADLINE_EXPIRED`), or revoked actors.

### 4.2 Tenant-Isolated Persistence (`CompanyBrainStore`)
- Backed by Node 22 built-in `node:sqlite` (`DatabaseSync`) with 7 relational tables (`security_analyses`, `chainbreak_evidence`, `adjudication_results`, `remediation_specs`, `policy_snapshots`, `decision_history`, `factory_delivery_evaluations`).
- **Tenant Binding:** Every query and insert takes `authTenantId` explicitly; any mismatch raises [`TenantIsolationError`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/company-context/src/store.ts). Read-only policy snapshots reject mutation (`POLICY_IMMUTABLE`), and idempotent re-analysis prevents conflicting rewrites (`IDEMPOTENCY_CONFLICT`).

---

## 5. `@script-kitty/security-actions` (Action Engine & MCP Streamable HTTP)

Entrypoint: [`packages/security-actions/src/index.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/index.ts)

### 5.1 Registered Security Capabilities ([`capabilities.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/capabilities.ts))

Both programmatic callers and MCP Streamable HTTP route strictly through `engine.invoke(capabilityId, input, authContext)` ([`engine.ts#L286-L531`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/engine.ts#L286-L531)). Specifying `tenantId` inside `rawInput` is rejected (`FORBIDDEN`); `tenantId` is derived solely from `authContext.principal`.

| Capability ID | Required Scope | Cost / Timeout | Strict Input Schema | Key Output Fields & Invariants |
|---|---|---|---|---|
| `security.chainbreak.analyze` | `security:analyze` | `10` / `10_000 ms` | `{ fixtureId: string, policyVersion?: string }` | `analysisId`, `status`, `idempotentReplay`, `stored: true`, `analysis`, `evidence[]`, **`mode: 'LAB'`**, **`productionTested: false`**, **`mergeAllowed: false`**, **`deployAllowed: false`** |
| `security.chainbreak.get` | `security:read` | `1` / `5_000 ms` | `{ analysisId: string }` | `analysis`, `evidence[]`, `adjudications[]`, `remediationSpecs[]`, `decisionHistory[]`, **`mode: 'LAB'`**, **`productionTested: false`** |
| `security.judge.evaluate` | `security:judge` | `15` / `15_000 ms` | `{ analysisId: string, expectedInputSha256?: 64-hex, model?: string }` | `analysisId`, `adjudication` (`AdjudicationResultSchema`), **`mode: 'LAB'`**, **`mergeAllowed: false`**, **`deployAllowed: false`** |
| `security.remediation.spec` | `security:remediate` | `5` / `5_000 ms` | `{ analysisId: string, pathId: string }` | `analysisId`, `pathId`, `remediationSpec`, **`requiresHumanApproval: true`**, **`autoApplyAllowed: false`**, **`mergeAllowed: false`**, **`deployAllowed: false`** |
| `security.status` | `security:status` | `0` / `2_000 ms` | `{}` (`.strict()`) | `service`, `version`, **`mode: 'LAB'`**, **`productionTested: false`**, **`HARNESS2_EXPERIMENTS_ENABLED: false`**, **`mergeAllowed: false`**, **`deployAllowed: false`**, `jevProviderStatus` (`LIVE \| NOT_CONFIGURED`), `components`, `adapters` (`externalExecution: false`) |

### 5.2 ActionEngine Error Codes & MCP Streamable HTTP Transport ([`mcp-http.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/mcp-http.ts), [`mcp-client.ts`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/mcp-client.ts))

- **`ActionEngineErrorCode`**: `'CAPABILITY_NOT_FOUND' | 'UNAUTHENTICATED' | 'FORBIDDEN' | 'INPUT_INVALID' | 'OUTPUT_INVALID' | 'CANCELLED' | 'TIMEOUT' | 'BUDGET_EXCEEDED' | 'NOT_FOUND' | 'EXECUTION_FAILED'`.
- **`startMcpHttpServer(engine, options)` Security Enforcement:**
  - **Loopback Guard:** Rejects non-loopback `host` bindings (`127.0.0.1`, `localhost`, `::1`, `[::1]`) unless `allowNonLoopback: true`.
  - **DNS Rebinding & CSRF:** Validates `Host` against `allowedHosts` (`403`) and `Origin` against `allowedOrigins` (`403`).
  - **Authentication:** Requires `Authorization: Bearer <token>` using constant-time SHA-256 digest comparison (`401` with `WWW-Authenticate: Bearer` on failure).
  - **Session Binding:** Stateful `Mcp-Session-Id` sessions verify `(session.principalId === principal.principalId && session.tenantId === principal.tenantId)` (`403` on cross-tenant/cross-principal session reuse).
  - **Abuse Bounds:** Enforces `maxRequestBodyBytes` (`413`, default 1 MiB) and sliding-window rate limiting (`429` with `Retry-After`).
  - **Protocol Operations:** Handles `initialize`, `tools/list` (converting Zod schemas via [`zodToJsonSchemaSimple`](file:///c:/Users/adm/Desktop/Prototipos/Script%20Kitty/packages/security-actions/src/mcp-http.ts#L90-L178)), and `tools/call` returning both serialized text JSON and `structuredContent`.
