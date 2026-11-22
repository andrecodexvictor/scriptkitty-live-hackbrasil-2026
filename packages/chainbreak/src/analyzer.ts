/**
 * @file packages/chainbreak/src/analyzer.ts
 * @description ChainBreak v0 deterministic policy graph & reachability analyzer.
 * Validates schema, tenant isolation, hash integrity, sourceRef/policy provenance,
 * transition semantics, legitimate business operations, and minimal remediation plans.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  computeEvidenceContentSha256,
  computePolicyGraphSha256,
  deriveDeterministicId,
  verifyGraphIntegrity,
} from './crypto.js';
import {
  DEFAULT_REACHABILITY_BUDGET,
  evaluateLegitimateOperations,
  findForbiddenPaths,
  type ReachabilityBudget,
} from './reachability.js';
import { generateRemediationSpec } from './remediation.js';
import {
  ExecutionScopeSchema,
  PolicyGraphInputSchema,
  type AnalysisDiagnostic,
  type AnalysisStatus,
  type AttackPath,
  type ChainBreakEvidence,
  type ExecutionScope,
  type FindingStatus,
  type PolicyGraphInput,
  type RemediationSpec,
  type RiskRecommendation,
  type SecurityAnalysis,
} from './schemas.js';

export class ChainBreakError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'ChainBreakError';
    this.code = code;
  }
}

export const CANONICAL_FIXTURE_IDS = [
  'payments-lab/baseline',
  'payments-lab/unsafe-rollout',
  'payments-lab/remediated',
  'payments-lab/negative-control',
] as const;

export type CanonicalFixtureId = (typeof CANONICAL_FIXTURE_IDS)[number];

export const ALLOWED_FIXTURE_IDS: Record<
  string,
  { fileName: string; canonicalId: CanonicalFixtureId }
> = {
  'payments-lab/baseline': {
    fileName: 'baseline.json',
    canonicalId: 'payments-lab/baseline',
  },
  'payments-lab/unsafe-rollout': {
    fileName: 'unsafe-rollout.json',
    canonicalId: 'payments-lab/unsafe-rollout',
  },
  'payments-lab/remediated': {
    fileName: 'remediated.json',
    canonicalId: 'payments-lab/remediated',
  },
  'payments-lab/negative-control': {
    fileName: 'negative-control.json',
    canonicalId: 'payments-lab/negative-control',
  },
  baseline: {
    fileName: 'baseline.json',
    canonicalId: 'payments-lab/baseline',
  },
  'unsafe-rollout': {
    fileName: 'unsafe-rollout.json',
    canonicalId: 'payments-lab/unsafe-rollout',
  },
  remediated: {
    fileName: 'remediated.json',
    canonicalId: 'payments-lab/remediated',
  },
  'negative-control': {
    fileName: 'negative-control.json',
    canonicalId: 'payments-lab/negative-control',
  },
  'payments-baseline': {
    fileName: 'baseline.json',
    canonicalId: 'payments-lab/baseline',
  },
  'payments-unsafe-rollout': {
    fileName: 'unsafe-rollout.json',
    canonicalId: 'payments-lab/unsafe-rollout',
  },
  'payments-remediated': {
    fileName: 'remediated.json',
    canonicalId: 'payments-lab/remediated',
  },
  'payments-negative-control': {
    fileName: 'negative-control.json',
    canonicalId: 'payments-lab/negative-control',
  },
};

export function isAllowedFixtureId(fixtureId: string): boolean {
  const normalized = fixtureId.trim().replace(/\.json$/i, '');
  return Object.prototype.hasOwnProperty.call(ALLOWED_FIXTURE_IDS, normalized);
}

function getDefaultFixturesDir(): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const relativeCandidate = path.resolve(
    __dirname,
    '../../../fixtures/payments-lab'
  );
  if (fs.existsSync(relativeCandidate)) {
    return relativeCandidate;
  }
  return path.resolve(process.cwd(), 'fixtures/payments-lab');
}

/**
 * Resolves an allowlisted fixture ID to a contained realpath inside the payments-lab directory.
 * Rejects path traversal and unknown fixture identifiers fail-closed.
 */
export function resolveFixturePath(
  fixtureId: string,
  fixturesDir?: string
): { filePath: string; canonicalId: CanonicalFixtureId } {
  if (typeof fixtureId !== 'string' || !fixtureId.trim()) {
    throw new ChainBreakError(
      'DISALLOWED_FIXTURE',
      'Fixture ID must be a non-empty string'
    );
  }
  const normalized = fixtureId.trim().replace(/\.json$/i, '');
  const entry = ALLOWED_FIXTURE_IDS[normalized];
  if (!entry) {
    throw new ChainBreakError(
      'DISALLOWED_FIXTURE',
      `Fixture ID '${fixtureId}' is not in the authorized ChainBreak LAB fixture allowlist`
    );
  }

  const baseDir = path.resolve(fixturesDir ?? getDefaultFixturesDir());
  if (!fs.existsSync(baseDir)) {
    throw new ChainBreakError(
      'FIXTURE_NOT_FOUND',
      `Fixtures directory not found: ${baseDir}`
    );
  }
  const realBase = fs.realpathSync(baseDir);
  const candidate = path.resolve(realBase, entry.fileName);

  if (!fs.existsSync(candidate)) {
    throw new ChainBreakError(
      'FIXTURE_NOT_FOUND',
      `Authorized fixture file not found: ${entry.fileName}`
    );
  }
  const realCandidate = fs.realpathSync(candidate);
  const rel = path.relative(realBase, realCandidate);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new ChainBreakError(
      'DISALLOWED_FIXTURE',
      `Path containment check failed for fixture '${fixtureId}'`
    );
  }

  return { filePath: realCandidate, canonicalId: entry.canonicalId };
}

/**
 * Loads and returns the raw parsed JSON object of an authorized lab fixture.
 */
export function loadFixtureGraph(
  fixtureId: string,
  fixturesDir?: string
): Record<string, unknown> {
  const { filePath } = resolveFixturePath(fixtureId, fixturesDir);
  const raw = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(raw) as Record<string, unknown>;
}

export interface AnalyzePolicyGraphOptions {
  analysisId?: string;
  tenantId?: string;
  policyVersion?: string;
  expectedInputSha256?: string;
  overrideInputSha256?: string;
  executionScope?: ExecutionScope;
  budget?: Partial<ReachabilityBudget>;
  now?: string;
  producer?: string;
}

export interface AnalyzeFixtureOptions extends AnalyzePolicyGraphOptions {
  fixturesDir?: string;
  /**
   * When true (default), binds a synthetic lab fixture to the caller's authenticated tenantId
   * after verifying internal fixture consistency and hash integrity.
   */
  bindToAuthenticatedTenant?: boolean;
}

function buildFailClosedAnalysis(params: {
  analysisId: string;
  tenantId: string;
  fixtureId: string;
  policyVersion: string;
  commitSha?: string;
  inputSha256: string;
  startedAt: string;
  completedAt: string;
  status: Extract<AnalysisStatus, 'FAILED' | 'INCONCLUSIVE'>;
  diagnostics: AnalysisDiagnostic[];
  producer: string;
}): SecurityAnalysis {
  const snapshotPayload = {
    status: params.status,
    fixtureId: params.fixtureId,
    policyVersion: params.policyVersion,
    inputSha256: params.inputSha256,
    diagnostics: params.diagnostics,
  };
  const evidenceId = deriveDeterministicId('ev-snapshot', {
    analysisId: params.analysisId,
    inputSha256: params.inputSha256,
    status: params.status,
  });

  const evidence: ChainBreakEvidence = {
    evidenceId,
    analysisId: params.analysisId,
    kind: 'POLICY_SNAPSHOT',
    sourceRef: params.fixtureId,
    contentSha256: computeEvidenceContentSha256(snapshotPayload),
    producer: params.producer,
    createdAt: params.completedAt,
    commitSha: params.commitSha,
    verified: false,
    summary: params.diagnostics.map((d) => `${d.code}: ${d.message}`).join('; '),
  };

  return {
    schemaVersion: 'security.analysis.v1',
    analysisId: params.analysisId,
    tenantId: params.tenantId,
    fixtureId: params.fixtureId,
    commitSha: params.commitSha,
    policyVersion: params.policyVersion,
    mode: 'LAB',
    paths: [],
    evidenceIds: [evidenceId],
    evidence: [evidence],
    remediationSpecs: [],
    legitimateOperations: [],
    legitimateOperationsPreserved: false,
    startedAt: params.startedAt,
    completedAt: params.completedAt,
    status: params.status,
    inputSha256: params.inputSha256,
    source: 'DETERMINISTIC_LAB_ANALYSIS',
    productionTested: false,
    diagnostics: params.diagnostics,
  };
}

function validateTenantConsistency(
  graph: PolicyGraphInput,
  expectedTenantId?: string
): AnalysisDiagnostic[] {
  const diagnostics: AnalysisDiagnostic[] = [];

  if (expectedTenantId && graph.tenantId !== expectedTenantId) {
    diagnostics.push({
      code: 'TENANT_MISMATCH',
      severity: 'ERROR',
      message: `Graph tenantId '${graph.tenantId}' does not match authenticated tenant '${expectedTenantId}'`,
      refId: graph.tenantId,
    });
  }

  for (const node of graph.nodes) {
    if (node.tenantId !== graph.tenantId) {
      diagnostics.push({
        code: 'TENANT_MISMATCH',
        severity: 'ERROR',
        message: `Node '${node.nodeId}' tenantId '${node.tenantId}' does not match graph tenantId '${graph.tenantId}'`,
        refId: node.nodeId,
      });
    }
  }

  for (const edge of graph.edges) {
    if (edge.tenantId !== graph.tenantId) {
      diagnostics.push({
        code: 'TENANT_MISMATCH',
        severity: 'ERROR',
        message: `Edge '${edge.edgeId}' tenantId '${edge.tenantId}' does not match graph tenantId '${graph.tenantId}'`,
        refId: edge.edgeId,
      });
    }
  }

  return diagnostics;
}

function validateStructuralIntegrity(
  graph: PolicyGraphInput
): AnalysisDiagnostic[] {
  const diagnostics: AnalysisDiagnostic[] = [];
  const nodeIds = new Set<string>();
  for (const node of graph.nodes) {
    if (nodeIds.has(node.nodeId)) {
      diagnostics.push({
        code: 'DUPLICATE_NODE_ID',
        severity: 'ERROR',
        message: `Duplicate nodeId '${node.nodeId}'`,
        refId: node.nodeId,
      });
    }
    nodeIds.add(node.nodeId);
  }

  const edgeIds = new Set<string>();
  for (const edge of graph.edges) {
    if (edgeIds.has(edge.edgeId)) {
      diagnostics.push({
        code: 'DUPLICATE_EDGE_ID',
        severity: 'ERROR',
        message: `Duplicate edgeId '${edge.edgeId}'`,
        refId: edge.edgeId,
      });
    }
    edgeIds.add(edge.edgeId);

    if (!nodeIds.has(edge.from)) {
      diagnostics.push({
        code: 'INVALID_GRAPH_REFERENCE',
        severity: 'ERROR',
        message: `Edge '${edge.edgeId}' references unknown source node '${edge.from}'`,
        refId: edge.edgeId,
      });
    }
    if (!nodeIds.has(edge.to)) {
      diagnostics.push({
        code: 'INVALID_GRAPH_REFERENCE',
        severity: 'ERROR',
        message: `Edge '${edge.edgeId}' references unknown target node '${edge.to}'`,
        refId: edge.edgeId,
      });
    }
  }

  if (graph.startIdentities) {
    for (const id of graph.startIdentities) {
      if (!nodeIds.has(id)) {
        diagnostics.push({
          code: 'INVALID_GRAPH_REFERENCE',
          severity: 'ERROR',
          message: `startIdentity '${id}' not found in graph nodes`,
          refId: id,
        });
      }
    }
  }

  return diagnostics;
}

function isMissingReference(val: string | undefined): boolean {
  if (!val) return true;
  const trimmed = val.trim();
  if (!trimmed) return true;
  const lower = trimmed.toLowerCase();
  return lower === 'missing' || lower === 'unknown' || lower === 'none';
}

/**
 * Deterministically analyzes an in-memory PolicyGraph / PolicyGraphInput.
 * Enforces schema, hash integrity, tenant consistency, sourceRef/policy references,
 * transition semantics, legitimate operations preservation, and minimal RemediationSpec generation.
 */
export function analyzePolicyGraph(
  input: PolicyGraphInput | Record<string, unknown> | unknown,
  options: AnalyzePolicyGraphOptions = {}
): SecurityAnalysis {
  const timestamp = options.now ?? new Date().toISOString();
  const producer = options.producer ?? '@script-kitty/chainbreak';

  // Validate ExecutionScope if provided
  let validatedScope: ExecutionScope | undefined;
  if (options.executionScope !== undefined) {
    const scopeParse = ExecutionScopeSchema.safeParse(options.executionScope);
    if (!scopeParse.success) {
      const fallbackHash = computePolicyGraphSha256(
        typeof input === 'object' && input !== null
          ? (input as Record<string, unknown>)
          : { raw: String(input) }
      );
      return buildFailClosedAnalysis({
        analysisId:
          options.analysisId ??
          deriveDeterministicId('cb-failed', { fallbackHash, timestamp }),
        tenantId: options.tenantId ?? 'unknown-tenant',
        fixtureId: 'unknown-fixture',
        policyVersion: options.policyVersion ?? 'unknown',
        inputSha256: fallbackHash,
        startedAt: timestamp,
        completedAt: timestamp,
        status: 'FAILED',
        diagnostics: scopeParse.error.errors.map((e) => ({
          code: 'INVALID_EXECUTION_SCOPE',
          severity: 'ERROR',
          message: `${e.path.join('.') || 'executionScope'}: ${e.message}`,
        })),
        producer,
      });
    }
    validatedScope = scopeParse.data;
  }

  const effectiveTenantId = validatedScope?.tenantId ?? options.tenantId;

  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    const fallbackHash = computePolicyGraphSha256({ raw: String(input) });
    return buildFailClosedAnalysis({
      analysisId:
        options.analysisId ??
        deriveDeterministicId('cb-failed', { fallbackHash }),
      tenantId: effectiveTenantId ?? 'unknown-tenant',
      fixtureId: 'unknown-fixture',
      policyVersion: options.policyVersion ?? 'unknown',
      inputSha256: fallbackHash,
      startedAt: timestamp,
      completedAt: timestamp,
      status: 'FAILED',
      diagnostics: [
        {
          code: 'SCHEMA_VALIDATION_FAILED',
          severity: 'ERROR',
          message: 'Policy graph input must be a non-null JSON object',
        },
      ],
      producer,
    });
  }

  const rawObj = input as Record<string, unknown>;
  const integrity = verifyGraphIntegrity(rawObj, options.expectedInputSha256);
  const effectiveInputSha256 =
    options.overrideInputSha256 ?? integrity.computedInputSha256;

  const rawFixtureId =
    typeof rawObj.fixtureId === 'string' && rawObj.fixtureId.trim()
      ? rawObj.fixtureId.trim()
      : 'unknown-fixture';
  const rawTenantId =
    effectiveTenantId ??
    (typeof rawObj.tenantId === 'string' && rawObj.tenantId.trim()
      ? rawObj.tenantId.trim()
      : 'unknown-tenant');
  const rawPolicyVersion =
    typeof rawObj.policyVersion === 'string' && rawObj.policyVersion.trim()
      ? rawObj.policyVersion.trim()
      : (options.policyVersion ?? 'unknown');
  const rawCommitSha =
    typeof rawObj.commitSha === 'string' &&
    /^[a-f0-9]{7,64}$/i.test(rawObj.commitSha)
      ? rawObj.commitSha
      : undefined;

  const analysisId =
    options.analysisId ??
    deriveDeterministicId('cb', {
      tenantId: rawTenantId,
      fixtureId: rawFixtureId,
      policyVersion: rawPolicyVersion,
      inputSha256: effectiveInputSha256,
    });

  // 1. Fail closed on input hash tampering
  if (!integrity.valid) {
    return buildFailClosedAnalysis({
      analysisId,
      tenantId: rawTenantId,
      fixtureId: rawFixtureId,
      policyVersion: rawPolicyVersion,
      commitSha: rawCommitSha,
      inputSha256: effectiveInputSha256,
      startedAt: timestamp,
      completedAt: timestamp,
      status: 'FAILED',
      diagnostics: [
        {
          code: 'TAMPER_DETECTED',
          severity: 'ERROR',
          message: integrity.error ?? 'Input SHA-256 verification failed',
        },
      ],
      producer,
    });
  }

  // 2. Validate JSON Schema via Zod
  const parsed = PolicyGraphInputSchema.safeParse(rawObj);
  if (!parsed.success) {
    return buildFailClosedAnalysis({
      analysisId,
      tenantId: rawTenantId,
      fixtureId: rawFixtureId,
      policyVersion: rawPolicyVersion,
      commitSha: rawCommitSha,
      inputSha256: effectiveInputSha256,
      startedAt: timestamp,
      completedAt: timestamp,
      status: 'FAILED',
      diagnostics: parsed.error.errors.map((e) => ({
        code: 'SCHEMA_VALIDATION_FAILED',
        severity: 'ERROR',
        message: `${e.path.join('.') || 'graph'}: ${e.message}`,
      })),
      producer,
    });
  }

  const graph = parsed.data;

  // 3. Enforce ExecutionScope allowlists & PolicyVersion consistency
  if (validatedScope && validatedScope.allowedFixtures.length > 0) {
    const normFixture = graph.fixtureId.trim().replace(/\.json$/i, '');
    const mappedCanonical = ALLOWED_FIXTURE_IDS[normFixture]?.canonicalId;
    const isAllowed =
      validatedScope.allowedFixtures.includes(graph.fixtureId) ||
      validatedScope.allowedFixtures.includes(normFixture) ||
      (mappedCanonical !== undefined &&
        validatedScope.allowedFixtures.includes(mappedCanonical));

    if (!isAllowed) {
      return buildFailClosedAnalysis({
        analysisId,
        tenantId: rawTenantId,
        fixtureId: graph.fixtureId,
        policyVersion: graph.policyVersion,
        commitSha: graph.commitSha,
        inputSha256: effectiveInputSha256,
        startedAt: timestamp,
        completedAt: timestamp,
        status: 'FAILED',
        diagnostics: [
          {
            code: 'SCOPE_VIOLATION',
            severity: 'ERROR',
            message: `Fixture '${graph.fixtureId}' is not permitted by caller ExecutionScope`,
            refId: graph.fixtureId,
          },
        ],
        producer,
      });
    }
  }

  if (
    validatedScope?.allowedPolicyVersions &&
    !validatedScope.allowedPolicyVersions.includes(graph.policyVersion)
  ) {
    return buildFailClosedAnalysis({
      analysisId,
      tenantId: rawTenantId,
      fixtureId: graph.fixtureId,
      policyVersion: graph.policyVersion,
      commitSha: graph.commitSha,
      inputSha256: effectiveInputSha256,
      startedAt: timestamp,
      completedAt: timestamp,
      status: 'FAILED',
      diagnostics: [
        {
          code: 'POLICY_VERSION_NOT_ALLOWED',
          severity: 'ERROR',
          message: `Policy version '${graph.policyVersion}' is not permitted by caller ExecutionScope`,
          refId: graph.policyVersion,
        },
      ],
      producer,
    });
  }

  if (options.policyVersion && options.policyVersion !== graph.policyVersion) {
    return buildFailClosedAnalysis({
      analysisId,
      tenantId: rawTenantId,
      fixtureId: graph.fixtureId,
      policyVersion: graph.policyVersion,
      commitSha: graph.commitSha,
      inputSha256: effectiveInputSha256,
      startedAt: timestamp,
      completedAt: timestamp,
      status: 'FAILED',
      diagnostics: [
        {
          code: 'POLICY_VERSION_MISMATCH',
          severity: 'ERROR',
          message: `Requested policyVersion '${options.policyVersion}' does not match graph policyVersion '${graph.policyVersion}'`,
          refId: graph.policyVersion,
        },
      ],
      producer,
    });
  }

  // 4. Tenant Isolation & Structural Consistency
  const tenantDiagnostics = validateTenantConsistency(graph, effectiveTenantId);
  if (tenantDiagnostics.length > 0) {
    return buildFailClosedAnalysis({
      analysisId,
      tenantId: effectiveTenantId ?? graph.tenantId,
      fixtureId: graph.fixtureId,
      policyVersion: graph.policyVersion,
      commitSha: graph.commitSha,
      inputSha256: effectiveInputSha256,
      startedAt: timestamp,
      completedAt: timestamp,
      status: 'FAILED',
      diagnostics: tenantDiagnostics,
      producer,
    });
  }

  const structDiagnostics = validateStructuralIntegrity(graph);
  if (structDiagnostics.length > 0) {
    return buildFailClosedAnalysis({
      analysisId,
      tenantId: graph.tenantId,
      fixtureId: graph.fixtureId,
      policyVersion: graph.policyVersion,
      commitSha: graph.commitSha,
      inputSha256: effectiveInputSha256,
      startedAt: timestamp,
      completedAt: timestamp,
      status: 'FAILED',
      diagnostics: structDiagnostics,
      producer,
    });
  }

  // 5. Run Deterministic Reachability & Legitimate Operations Evaluation
  const budget: ReachabilityBudget = {
    maxNodes:
      options.budget?.maxNodes ??
      validatedScope?.maxNodes ??
      DEFAULT_REACHABILITY_BUDGET.maxNodes,
    maxDepth:
      options.budget?.maxDepth ??
      validatedScope?.maxDepth ??
      DEFAULT_REACHABILITY_BUDGET.maxDepth,
    maxPaths:
      options.budget?.maxPaths ??
      validatedScope?.maxPaths ??
      DEFAULT_REACHABILITY_BUDGET.maxPaths,
    maxDurationMs:
      options.budget?.maxDurationMs ??
      validatedScope?.maxDurationMs ??
      DEFAULT_REACHABILITY_BUDGET.maxDurationMs,
  };

  const reachability = findForbiddenPaths(graph, budget);
  const legitEval = evaluateLegitimateOperations(graph);

  const diagnostics: AnalysisDiagnostic[] = [];
  const evidence: ChainBreakEvidence[] = [];

  // Check policy snapshot provenance
  const policiesMissingRef = graph.policies
    .filter(
      (p) =>
        isMissingReference(p.sourceRef) ||
        p.policyVersion !== graph.policyVersion
    )
    .map((p) => p.policyId);

  if (policiesMissingRef.length > 0) {
    diagnostics.push({
      code: 'POLICY_REFERENCE_MISSING',
      severity: 'WARNING',
      message: `Policy rule(s) [${policiesMissingRef.join(', ')}] lack valid sourceRef or matching policyVersion`,
    });
  }

  const policySnapshotPayload = {
    fixtureId: graph.fixtureId,
    tenantId: graph.tenantId,
    policyVersion: graph.policyVersion,
    inputSha256: effectiveInputSha256,
    policies: graph.policies.map((p) => ({
      policyId: p.policyId,
      policyVersion: p.policyVersion,
      sourceRef: p.sourceRef,
    })),
  };
  const policySnapshotEvidenceId = deriveDeterministicId('ev-policy', {
    analysisId,
    inputSha256: effectiveInputSha256,
  });
  evidence.push({
    evidenceId: policySnapshotEvidenceId,
    analysisId,
    kind: 'POLICY_SNAPSHOT',
    sourceRef: graph.policies[0]?.sourceRef || graph.fixtureId,
    contentSha256: computeEvidenceContentSha256(policySnapshotPayload),
    producer,
    createdAt: timestamp,
    commitSha: graph.commitSha,
    verified: policiesMissingRef.length === 0,
    summary: `Policy snapshot (${graph.policyVersion}) across ${graph.nodes.length} nodes and ${graph.edges.length} edges`,
  });

  // Check edges in graph missing sourceRef or policyVersion
  const edgesMissingSourceRef = graph.edges
    .filter((e) => isMissingReference(e.sourceRef))
    .map((e) => e.edgeId);
  const edgesMissingPolicyVersion = graph.edges
    .filter(
      (e) =>
        isMissingReference(e.policyVersion) ||
        e.policyVersion !== graph.policyVersion
    )
    .map((e) => e.edgeId);

  if (edgesMissingSourceRef.length > 0) {
    diagnostics.push({
      code: 'MISSING_SOURCE_REF',
      severity: 'WARNING',
      message: `Edge(s) missing sourceRef: [${edgesMissingSourceRef.join(', ')}]`,
    });
  }
  if (edgesMissingPolicyVersion.length > 0) {
    diagnostics.push({
      code: 'MISSING_OR_MISMATCHED_POLICY_VERSION',
      severity: 'WARNING',
      message: `Edge(s) missing or mismatched policyVersion: [${edgesMissingPolicyVersion.join(', ')}]`,
    });
  }

  // 6. Build AttackPaths + GRAPH_PATH Evidence + RemediationSpecs
  const paths: AttackPath[] = [];
  const remediationSpecs: RemediationSpec[] = [];
  let hasInconclusivePath = false;

  for (let i = 0; i < reachability.paths.length; i++) {
    const rawPath = reachability.paths[i];
    const missingRefs: string[] = [];

    for (const edge of rawPath.edges) {
      if (isMissingReference(edge.sourceRef)) {
        missingRefs.push(`edge:${edge.edgeId}:missing_sourceRef`);
      }
      if (
        isMissingReference(edge.policyVersion) ||
        edge.policyVersion !== graph.policyVersion
      ) {
        missingRefs.push(`edge:${edge.edgeId}:invalid_policyVersion`);
      }
      if (edge.policyId !== undefined && isMissingReference(edge.policyId)) {
        missingRefs.push(`edge:${edge.edgeId}:empty_policyId`);
      }
    }

    if (isMissingReference(rawPath.violatedPolicy.sourceRef)) {
      missingRefs.push(
        `policy:${rawPath.violatedPolicy.policyId}:missing_sourceRef`
      );
    }
    if (rawPath.violatedPolicy.policyVersion !== graph.policyVersion) {
      missingRefs.push(
        `policy:${rawPath.violatedPolicy.policyId}:invalid_policyVersion`
      );
    }

    const pathId = deriveDeterministicId('path', {
      analysisId,
      startIdentity: rawPath.startIdentity,
      targetAssetId: rawPath.targetAssetId,
      targetDestinationId: rawPath.targetDestinationId,
      violatedPolicyId: rawPath.violatedPolicy.policyId,
      edgeIds: rawPath.edges.map((e) => e.edgeId),
    });

    const isProvenanceComplete = missingRefs.length === 0;
    const status: FindingStatus = isProvenanceComplete
      ? 'PATH_VALIDATED'
      : 'INCONCLUSIVE';
    const riskRecommendation: RiskRecommendation = isProvenanceComplete
      ? rawPath.violatedPolicy.riskRecommendation
      : 'UNDETERMINED';

    if (!isProvenanceComplete) {
      hasInconclusivePath = true;
      diagnostics.push({
        code: 'PATH_PROVENANCE_INCOMPLETE',
        severity: 'WARNING',
        message: `Candidate path '${pathId}' downgraded to INCONCLUSIVE due to missing provenance: ${missingRefs.join(', ')}`,
        refId: pathId,
      });
    }

    const pathEdges = rawPath.edges.map((e) => ({
      edgeId: e.edgeId,
      from: e.from,
      to: e.to,
      kind: e.kind,
      scope: e.scope,
      sourceRef: e.sourceRef,
      policyId: e.policyId,
      policyVersion: e.policyVersion,
      dataClassification: e.dataClassification,
    }));

    const pathPayload = {
      pathId,
      startIdentity: rawPath.startIdentity,
      targetAsset: rawPath.targetAssetId,
      targetDestination: rawPath.targetDestinationId,
      violatedPolicyId: rawPath.violatedPolicy.policyId,
      edges: pathEdges,
    };

    const pathEvidenceId = deriveDeterministicId('ev-path', pathPayload);
    const sourceRefsCombined = rawPath.edges
      .map((e) => e.sourceRef)
      .filter((s) => !isMissingReference(s))
      .join(', ');

    evidence.push({
      evidenceId: pathEvidenceId,
      analysisId,
      kind: 'GRAPH_PATH',
      sourceRef: sourceRefsCombined,
      contentSha256: computeEvidenceContentSha256(pathPayload),
      producer,
      createdAt: timestamp,
      commitSha: graph.commitSha,
      verified: isProvenanceComplete,
      summary: `Graph path ${rawPath.startIdentity} -> ${rawPath.targetAssetId} -> ${rawPath.targetDestinationId} (${status})`,
    });

    const edgeTraceText = rawPath.edges
      .map(
        (e) =>
          `${e.edgeId} (${e.from} --[${e.kind}; scope=${e.scope}; class=${e.dataClassification}]--> ${e.to}; ref=${e.sourceRef || 'MISSING'})`
      )
      .join(' -> ');

    const explanation = isProvenanceComplete
      ? `Modeled policy reachability path (${status}) violating '${rawPath.violatedPolicy.policyId}': starting from '${rawPath.startIdentity}', ordered transitions [${edgeTraceText}] allow '${rawPath.carriedClassification}' asset '${rawPath.targetAssetId}' to reach '${rawPath.targetDestinationId}'. Note: PATH_VALIDATED proves reachability within the modeled policy graph, not production exploitation.`
      : `Candidate policy path downgraded to INCONCLUSIVE (never PATH_VALIDATED) because provenance references are incomplete [${missingRefs.join(', ')}]. Ordered transitions: [${edgeTraceText}].`;

    const nonTechnicalSummary = isProvenanceComplete
      ? `Under the tested policy rollout, an authorized identity (${rawPath.startIdentity}) can trigger a chain of permissions that moves restricted data (${rawPath.targetAssetId}) to an external destination (${rawPath.targetDestinationId}) that is not permitted to receive it. This finding is derived deterministically from the modeled permission rules and has not been run against production systems.`
      : `A potential data-exposure chain to ${rawPath.targetDestinationId} was observed in the graph, but missing policy or source references prevent deterministic validation. A human reviewer must verify the underlying policy source before relying on this result.`;

    const attackPath: AttackPath = {
      pathId,
      startIdentity: rawPath.startIdentity,
      targetAsset: rawPath.targetAssetId,
      targetDestination: rawPath.targetDestinationId,
      edges: pathEdges,
      violatedPolicyId: rawPath.violatedPolicy.policyId,
      status,
      evidenceIds: [policySnapshotEvidenceId, pathEvidenceId],
      riskRecommendation,
      explanation,
      nonTechnicalSummary,
      ...(missingRefs.length > 0 ? { missingReferences: missingRefs } : {}),
    };

    paths.push(attackPath);
    remediationSpecs.push(
      generateRemediationSpec({
        graph,
        analysisId,
        path: attackPath,
        createdAt: timestamp,
        budget,
      })
    );
  }

  // 7. Legitimate Operations TEST_RESULT Evidence
  const legitPayload = {
    preserved: legitEval.preserved,
    operations: legitEval.results,
  };
  const legitEvidenceId = deriveDeterministicId('ev-test', {
    analysisId,
    legitPayload,
  });
  const legitVerified =
    legitEval.preserved && legitEval.missingSourceRefs.length === 0;
  evidence.push({
    evidenceId: legitEvidenceId,
    analysisId,
    kind: 'TEST_RESULT',
    sourceRef:
      graph.legitimateOperations
        .map((o) => o.sourceRef)
        .filter((s) => !isMissingReference(s))
        .join(', ') || graph.fixtureId,
    contentSha256: computeEvidenceContentSha256(legitPayload),
    producer,
    createdAt: timestamp,
    commitSha: graph.commitSha,
    verified: legitVerified,
    summary: `Legitimate operations check: ${legitEval.results.filter((r) => r.preserved).length}/${legitEval.results.length} preserved`,
  });

  if (reachability.stats.budgetExceeded) {
    diagnostics.push({
      code: 'BUDGET_EXCEEDED',
      severity: 'WARNING',
      message: `Graph traversal exceeded execution budget (nodesVisited=${reachability.stats.nodesVisited}, paths=${paths.length}); result marked INCONCLUSIVE`,
    });
  }

  if (!legitEval.preserved) {
    diagnostics.push({
      code: 'LEGITIMATE_OPERATION_BROKEN',
      severity: 'ERROR',
      message: `One or more legitimate operations failed under the tested policy graph`,
    });
  }

  // Fail closed to INCONCLUSIVE if provenance is incomplete or budget truncated traversal
  const finalStatus: AnalysisStatus =
    hasInconclusivePath ||
    reachability.stats.budgetExceeded ||
    legitEval.missingSourceRefs.length > 0 ||
    policiesMissingRef.length > 0
      ? 'INCONCLUSIVE'
      : 'COMPLETED';

  return {
    schemaVersion: 'security.analysis.v1',
    analysisId,
    tenantId: graph.tenantId,
    fixtureId: graph.fixtureId,
    commitSha: graph.commitSha,
    policyVersion: graph.policyVersion,
    mode: 'LAB',
    paths,
    evidenceIds: evidence.map((e) => e.evidenceId),
    evidence,
    remediationSpecs,
    legitimateOperations: legitEval.results,
    legitimateOperationsPreserved: legitEval.preserved,
    startedAt: timestamp,
    completedAt: timestamp,
    status: finalStatus,
    inputSha256: effectiveInputSha256,
    source: 'DETERMINISTIC_LAB_ANALYSIS',
    productionTested: false,
    budgetStats: reachability.stats,
    diagnostics,
  };
}

/**
 * Loads an allowlisted payments-lab fixture and runs deterministic ChainBreak analysis.
 * Supports authenticated tenant binding without losing original fixture SHA-256 verification.
 */
export function analyzeFixture(
  fixtureId: string,
  options: AnalyzeFixtureOptions = {}
): SecurityAnalysis {
  const { canonicalId } = resolveFixturePath(fixtureId, options.fixturesDir);
  const rawObj = loadFixtureGraph(fixtureId, options.fixturesDir);

  // Verify raw fixture integrity first before any tenant rebinding
  const rawIntegrity = verifyGraphIntegrity(
    rawObj,
    options.expectedInputSha256
  );
  const originalInputSha256 = rawIntegrity.computedInputSha256;

  // Check raw internal tenant consistency before tenant projection
  const rawParsed = PolicyGraphInputSchema.safeParse(rawObj);
  if (!rawIntegrity.valid) {
    return analyzePolicyGraph(rawObj, options);
  }
  if (!rawParsed.success) {
    return analyzePolicyGraph(rawObj, options);
  }

  const rawTenantErrors = validateTenantConsistency(rawParsed.data);
  if (rawTenantErrors.length > 0) {
    return analyzePolicyGraph(rawObj, options);
  }

  const authTenantId =
    options.executionScope?.tenantId ?? options.tenantId;
  const shouldBind = options.bindToAuthenticatedTenant !== false;

  if (authTenantId && shouldBind && authTenantId !== rawParsed.data.tenantId) {
    const reboundNodes = rawParsed.data.nodes.map((n) => ({
      ...n,
      tenantId: authTenantId,
    }));
    const reboundEdges = rawParsed.data.edges.map((e) => ({
      ...e,
      tenantId: authTenantId,
    }));
    const reboundGraph: Record<string, unknown> = {
      ...rawObj,
      fixtureId: canonicalId,
      tenantId: authTenantId,
      nodes: reboundNodes,
      edges: reboundEdges,
    };
    delete reboundGraph.declaredInputSha256;

    return analyzePolicyGraph(reboundGraph, {
      ...options,
      overrideInputSha256: originalInputSha256,
      expectedInputSha256: undefined,
    });
  }

  const normalizedGraph: Record<string, unknown> = {
    ...rawObj,
    fixtureId:
      typeof rawObj.fixtureId === 'string' && rawObj.fixtureId.trim()
        ? rawObj.fixtureId
        : canonicalId,
  };

  return analyzePolicyGraph(normalizedGraph, {
    ...options,
    overrideInputSha256: originalInputSha256,
  });
}
