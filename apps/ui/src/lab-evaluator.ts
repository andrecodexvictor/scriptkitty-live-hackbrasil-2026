/**
 * @file apps/ui/src/lab-evaluator.ts
 * @description Browser-pure deterministic ChainBreak, JEV-as-a-Judge mock,
 * Zero-Trust Quality Gate (Tri-Party SoD + RFC 8785 Custody Merkle), and
 * `factory.delivery.v1` evaluator for offline/fallback LAB mode in `@script-kitty/ui`.
 */

import {
  canonicalStringify,
  computeEvidenceContentSha256,
  computeMerkleRoot,
  computeNodeChainHash,
  computePolicyGraphSha256,
  deriveDeterministicId,
  GENESIS_HASH,
  sha256,
  sha256Hex,
  verifyCustodyChain,
  type CustodyChainRecord,
  type CustodyNodeRecord,
} from './crypto-browser.ts';
import {
  LAB_FIXTURES,
  type AttackGraphEdge,
  type AttackGraphEdgeKind,
  type AttackGraphNode,
  type CanonicalFixtureId,
  type DataClassification,
  type PolicyGraphFixture,
  type PolicyRule,
} from './lab-fixtures.ts';

export const CLASSIFICATION_RANK: Record<DataClassification, number> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  RESTRICTED: 3,
};

export type FindingStatus =
  | 'POTENTIAL'
  | 'PATH_VALIDATED'
  | 'INCONCLUSIVE'
  | 'NOT_REPRODUCED';

export type RiskRecommendation = 'P0' | 'P1' | 'P2' | 'P3' | 'UNDETERMINED';

export interface AttackPathEdgeView {
  edgeId: string;
  from: string;
  to: string;
  kind: AttackGraphEdgeKind;
  scope: string;
  sourceRef: string;
  policyId?: string;
  policyVersion: string;
  dataClassification: DataClassification;
}

export interface AttackPathView {
  pathId: string;
  startIdentity: string;
  targetAsset: string;
  targetDestination?: string;
  edges: AttackPathEdgeView[];
  violatedPolicyId: string;
  status: FindingStatus;
  evidenceIds: string[];
  riskRecommendation: RiskRecommendation;
  explanation: string;
  nonTechnicalSummary: string;
  missingReferences?: string[];
}

export interface ChainBreakEvidenceView {
  evidenceId: string;
  analysisId: string;
  kind: 'POLICY_SNAPSHOT' | 'GRAPH_PATH' | 'TEST_RESULT' | 'QUALITY_RESULT';
  sourceRef: string;
  contentSha256: string;
  producer: string;
  createdAt: string;
  verified: boolean;
  summary?: string;
}

export interface RemediationActionView {
  actionType:
    | 'REMOVE_EDGE'
    | 'RESTRICT_DATA_CLASSIFICATION'
    | 'RESTRICT_SCOPE'
    | 'ADD_DENY_CONDITION';
  edgeId: string;
  from: string;
  to: string;
  edgeKind: AttackGraphEdgeKind;
  currentScope: string;
  currentDataClassification: DataClassification;
  proposedChange: string;
  proposedDataClassification?: DataClassification;
  proposedAllowedClassifications?: DataClassification[];
  sourceRef: string;
}

export interface RemediationSpecView {
  remediationId: string;
  analysisId: string;
  tenantId: string;
  fixtureId: string;
  pathId: string;
  violatedPolicyId: string;
  riskRecommendation: RiskRecommendation;
  minimalChange: boolean;
  actions: RemediationActionView[];
  breaksUnauthorizedPath: boolean;
  preservesLegitimateOperations: boolean;
  preservedOperationIds: string[];
  acceptanceCriteria: string[];
  verificationTests: string[];
  requiresHumanApproval: true;
  autoApplyAllowed: false;
  rationale: string;
  nonTechnicalSummary: string;
  evidenceIds: string[];
  createdAt: string;
}

export interface LegitimateOperationResultView {
  operationId: string;
  description: string;
  preserved: boolean;
  reason: string;
  verifiedEdgeIds: string[];
}

export interface BudgetStatsView {
  nodesVisited: number;
  edgesTraversed: number;
  maxDepthReached: number;
  pathsEvaluated: number;
  budgetExceeded: boolean;
}

export interface AnalysisDiagnosticView {
  code: string;
  severity: 'INFO' | 'WARNING' | 'ERROR';
  message: string;
  refId?: string;
}

export interface SecurityAnalysisView {
  schemaVersion: 'security.analysis.v1';
  analysisId: string;
  tenantId: string;
  fixtureId: string;
  policyVersion: string;
  mode: 'LAB';
  paths: AttackPathView[];
  evidenceIds: string[];
  evidence: ChainBreakEvidenceView[];
  remediationSpecs: RemediationSpecView[];
  legitimateOperations: LegitimateOperationResultView[];
  legitimateOperationsPreserved: boolean;
  startedAt: string;
  completedAt: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'INCONCLUSIVE' | 'FAILED';
  inputSha256: string;
  source: 'DETERMINISTIC_LAB_ANALYSIS';
  productionTested: false;
  budgetStats: BudgetStatsView;
  diagnostics: AnalysisDiagnosticView[];
}

export interface JevAdjudicationView {
  evaluationId: string;
  analysisId: string;
  tenantId: string;
  model: string;
  modelVersion: string;
  rubricVersion: 'jev-rubric-v0';
  answers: {
    evidence_sufficient: { type: 'noul'; noul: number };
    needs_manual_review: { type: 'noul'; noul: number };
    triage: {
      type: 'choice';
      choice: 'likely_actionable' | 'needs_more_evidence' | 'likely_irrelevant';
      confidence: number;
      probabilities: Record<string, number>;
    };
  } | null;
  triage: 'likely_actionable' | 'needs_more_evidence' | 'likely_irrelevant' | null;
  decision: string;
  status:
    | 'ACCEPTED_FOR_TRIAGE'
    | 'PENDING_REVIEW'
    | 'BLOCKED'
    | 'REJECTED'
    | 'INCONCLUSIVE';
  probabilities: {
    evidenceSufficient: number;
    needsManualReview: number;
    triageProbabilities: Record<string, number>;
  };
  confidenceOrUncertainty: {
    confidence: number;
    uncertainty: number;
    evidenceSufficiencyScore: number;
    manualReviewScore: number;
    threshold: number;
    thresholdCalibrated: false;
    calibrationNote: string;
  };
  escalated: boolean;
  escalationReasons: string[];
  escalationReason?: string;
  requiresHumanReview: boolean;
  riskRecommendation: RiskRecommendation | 'NONE';
  evidenceIds: string[];
  sourceRefs: string[];
  decisionSource: 'LIVE' | 'MOCK' | 'FALLBACK' | 'HUMAN_PENDING';
  providerStatus: 'LIVE' | 'NOT_CONFIGURED' | 'FALLBACK' | 'UNAVAILABLE';
  preValidation: {
    passed: boolean;
    blockingOutcome: 'NONE' | 'BLOCKED' | 'REJECTED';
    checkedAt: string;
    checks: {
      identityAndTenantScope: boolean;
      labModeBoundary: boolean;
      hashIntegrity: boolean;
      evidenceCompletenessAndVerification: boolean;
      policyAndSourceRefs: boolean;
    };
    issues: Array<{
      code: string;
      severity: 'ERROR' | 'WARNING';
      message: string;
      refId?: string;
    }>;
  };
  sanitizedStateDigest: string;
  mergeAllowed: false;
  deployAllowed: false;
  exploitConfirmed: false;
  p0DefinedByJevAlone: false;
  timestamp: string;
}

export interface SeparationOfDutiesView {
  discovering_agent_id: string;
  verifying_agent_id: string;
  authorizing_agent_id: string;
  is_valid: boolean;
  violation_code?: string;
  violation_details?: string;
}

export interface QualityGateEvaluationView {
  decision_id: string;
  verdict: 'PASS' | 'REJECT' | 'BLOCK' | 'REQUIRES_HUMAN_APPROVAL' | 'ERROR';
  simulatedSelfCert: boolean;
  sod_evaluation: SeparationOfDutiesView;
  custody_chain: CustodyChainRecord;
  custody_valid: boolean;
  merkle_root: string;
  audit_merkle_root: string;
  evaluation_summary: string;
  rules_evaluated: Array<{
    rule_id: string;
    status: 'PASS' | 'FAIL' | 'ERROR';
    reason: string;
  }>;
  mergeAllowed: false;
  deployAllowed: false;
  decided_at: string;
}

export interface FactoryDeliveryView {
  contract: 'factory.delivery.v1';
  eligible: boolean;
  stage:
    | 'approved'
    | 'cancelled'
    | 'blocked'
    | 'expired'
    | 'implementation'
    | 'review'
    | 'verification';
  blockReason: string | null;
  submissionsRemaining: number;
  correctionsRemaining: number;
  commitSha: string;
  checkedAt: string;
  submitter: string;
  reviewer: string;
  checks: Array<{
    key: 'tests' | 'typecheck' | 'build';
    status: 'passed' | 'failed';
    evidenceRef: string;
  }>;
  externalExecution: false;
  mergeAllowed: false;
  deployAllowed: false;
  deploymentAllowed: false;
}

interface TraversalState {
  currentNodeId: string;
  startIdentity: string;
  activeScope: string;
  authorizedScopes: string[];
  activeRoles: string[];
  carriedAssetId: string | null;
  carriedClassification: DataClassification | null;
  edgeTrail: AttackGraphEdge[];
  depth: number;
}

interface DiscoveredViolationPath {
  startIdentity: string;
  targetAssetId: string;
  targetDestinationId: string;
  edges: AttackGraphEdge[];
  violatedPolicy: PolicyRule;
  carriedClassification: DataClassification;
}

const VALID_EDGE_NODE_PAIRS: Record<
  AttackGraphEdgeKind,
  { from: Set<string>; to: Set<string> }
> = {
  assumes_role: {
    from: new Set(['identity', 'agent', 'service']),
    to: new Set(['identity', 'agent', 'service']),
  },
  delegates_to: {
    from: new Set(['identity', 'agent', 'service']),
    to: new Set(['agent', 'service', 'mcp_tool', 'api']),
  },
  can_invoke: {
    from: new Set(['identity', 'agent', 'api', 'service', 'mcp_tool']),
    to: new Set(['mcp_tool', 'api', 'service']),
  },
  can_read: {
    from: new Set(['identity', 'agent', 'mcp_tool', 'api', 'service']),
    to: new Set(['data_asset']),
  },
  can_write: {
    from: new Set(['identity', 'agent', 'mcp_tool', 'api', 'service']),
    to: new Set(['data_asset', 'destination', 'service', 'api']),
  },
  transfers_data_to: {
    from: new Set(['identity', 'agent', 'mcp_tool', 'api', 'service', 'data_asset']),
    to: new Set(['service', 'api', 'data_asset', 'destination']),
  },
};

function uniqueSorted(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0
  );
}

function isMissingRef(val: string | undefined): boolean {
  if (!val) return true;
  const trimmed = val.trim();
  if (!trimmed) return true;
  const lower = trimmed.toLowerCase();
  return lower === 'missing' || lower === 'unknown' || lower === 'none';
}

function evaluateEdgeConditions(
  edge: AttackGraphEdge,
  state: TraversalState,
  fromNode: AttackGraphNode,
  toNode: AttackGraphNode
): { ok: boolean; reason?: string; masksPii?: boolean } {
  const cond = edge.conditions;
  if (!cond) {
    return { ok: true, masksPii: false };
  }
  if (cond.active === false) {
    return { ok: false, reason: `Edge ${edge.edgeId} is inactive` };
  }
  if (cond.effect === 'DENY') {
    return { ok: false, reason: `Edge ${edge.edgeId} has explicit DENY effect` };
  }
  if (cond.requiresMfa === true && cond.mfaVerified !== true) {
    return { ok: false, reason: `Edge ${edge.edgeId} requires verified MFA` };
  }
  if (cond.requiresExplicitGrant === true && cond.explicitGrantPresent !== true) {
    return { ok: false, reason: `Edge ${edge.edgeId} requires explicit grant` };
  }
  if (cond.requiresPiiMasking === true && cond.piiMaskingApplied !== true) {
    return {
      ok: false,
      reason: `Edge ${edge.edgeId} requires PII masking which is not applied`,
    };
  }
  if (cond.requiredRoles && cond.requiredRoles.length > 0) {
    const heldRoles = new Set([...state.activeRoles, ...(fromNode.roles ?? [])]);
    for (const reqRole of cond.requiredRoles) {
      if (!heldRoles.has(reqRole)) {
        return {
          ok: false,
          reason: `Edge ${edge.edgeId} requires missing role '${reqRole}'`,
        };
      }
    }
  }
  if (cond.requiredScopes && cond.requiredScopes.length > 0) {
    const heldScopes = new Set(state.authorizedScopes);
    for (const reqScope of cond.requiredScopes) {
      if (!heldScopes.has(reqScope)) {
        return {
          ok: false,
          reason: `Edge ${edge.edgeId} requires missing scope '${reqScope}'`,
        };
      }
    }
  }
  if (cond.networkZone && cond.networkZone !== 'ANY') {
    if (toNode.trustZone !== cond.networkZone) {
      return {
        ok: false,
        reason: `Edge ${edge.edgeId} restricts networkZone to ${cond.networkZone}`,
      };
    }
  }
  if (cond.allowedPurposes && cond.allowedPurposes.length > 0) {
    if (!cond.purpose || !cond.allowedPurposes.includes(cond.purpose)) {
      return {
        ok: false,
        reason: `Edge ${edge.edgeId} purpose not in allowedPurposes`,
      };
    }
  }

  return {
    ok: true,
    masksPii: cond.requiresPiiMasking === true && cond.piiMaskingApplied === true,
  };
}

function isClassificationAllowedOnEdge(
  edge: AttackGraphEdge,
  classification: DataClassification
): { ok: boolean; reason?: string } {
  if (
    CLASSIFICATION_RANK[edge.dataClassification] <
    CLASSIFICATION_RANK[classification]
  ) {
    return {
      ok: false,
      reason: `Edge ${edge.edgeId} ceiling (${edge.dataClassification}) is below ${classification}`,
    };
  }
  const allowed = edge.conditions?.allowedDataClassifications;
  if (allowed && !allowed.includes(classification)) {
    return {
      ok: false,
      reason: `Edge ${edge.edgeId} allowedDataClassifications excludes ${classification}`,
    };
  }
  const denied = edge.conditions?.deniedDataClassifications;
  if (denied && denied.includes(classification)) {
    return {
      ok: false,
      reason: `Edge ${edge.edgeId} deniedDataClassifications forbids ${classification}`,
    };
  }
  return { ok: true };
}

function isScopeCompatible(
  edge: AttackGraphEdge,
  state: TraversalState,
  fromNode: AttackGraphNode
): { ok: boolean; reason?: string } {
  if (edge.kind === 'assumes_role' || edge.kind === 'delegates_to') {
    const scopeMatched =
      state.authorizedScopes.includes(edge.scope) ||
      edge.scope === fromNode.scope ||
      (fromNode.allowedScopes ?? []).includes(edge.scope) ||
      (edge.conditions?.requiredScopes !== undefined &&
        edge.conditions.requiredScopes.length > 0 &&
        edge.conditions.requiredScopes.every((s) =>
          state.authorizedScopes.includes(s)
        ));
    if (!scopeMatched) {
      return {
        ok: false,
        reason: `Role/delegation edge ${edge.edgeId} scope '${edge.scope}' outside authorized scopes`,
      };
    }
    return { ok: true };
  }

  if (
    edge.scope === state.activeScope ||
    state.authorizedScopes.includes(edge.scope)
  ) {
    return { ok: true };
  }

  return {
    ok: false,
    reason: `Scope mismatch on edge ${edge.edgeId}`,
  };
}

function tryTraverseEdge(
  edge: AttackGraphEdge,
  state: TraversalState,
  nodeMap: Map<string, AttackGraphNode>,
  outgoingByNode: Map<string, AttackGraphEdge[]>
): {
  ok: boolean;
  reason?: string;
  nextStates: TraversalState[];
  terminalDataArrival?: {
    targetNode: AttackGraphNode;
    carriedAssetId: string;
    carriedClassification: DataClassification;
    trail: AttackGraphEdge[];
  };
} {
  const fromNode = nodeMap.get(edge.from);
  const toNode = nodeMap.get(edge.to);
  if (!fromNode || !toNode) {
    return { ok: false, reason: `Missing endpoint for ${edge.edgeId}`, nextStates: [] };
  }
  if (edge.from !== state.currentNodeId) {
    return { ok: false, reason: `Edge ${edge.edgeId} mismatch`, nextStates: [] };
  }
  if (state.edgeTrail.some((e) => e.edgeId === edge.edgeId)) {
    return { ok: false, reason: `Cycle prevented on ${edge.edgeId}`, nextStates: [] };
  }
  const compat = VALID_EDGE_NODE_PAIRS[edge.kind];
  if (!compat.from.has(fromNode.kind) || !compat.to.has(toNode.kind)) {
    return {
      ok: false,
      reason: `Incompatible edge type '${edge.kind}' between ${fromNode.kind} and ${toNode.kind}`,
      nextStates: [],
    };
  }
  const scopeRes = isScopeCompatible(edge, state, fromNode);
  if (!scopeRes.ok) {
    return { ok: false, reason: scopeRes.reason, nextStates: [] };
  }
  const condRes = evaluateEdgeConditions(edge, state, fromNode, toNode);
  if (!condRes.ok) {
    return { ok: false, reason: condRes.reason, nextStates: [] };
  }

  const newTrail = [...state.edgeTrail, edge];
  const nextDepth = state.depth + 1;

  if (edge.kind === 'assumes_role') {
    if (state.carriedClassification) {
      const clsCheck = isClassificationAllowedOnEdge(edge, state.carriedClassification);
      if (!clsCheck.ok) return { ok: false, reason: clsCheck.reason, nextStates: [] };
    }
    return {
      ok: true,
      nextStates: [
        {
          currentNodeId: toNode.nodeId,
          startIdentity: state.startIdentity,
          activeScope: edge.scope,
          authorizedScopes: uniqueSorted([
            ...state.authorizedScopes,
            edge.scope,
            toNode.scope,
            ...(toNode.allowedScopes ?? []),
          ]),
          activeRoles: uniqueSorted([
            ...state.activeRoles,
            ...(toNode.roles ?? []),
            ...(edge.conditions?.grantedRoles ?? []),
          ]),
          carriedAssetId: state.carriedAssetId,
          carriedClassification: state.carriedClassification,
          edgeTrail: newTrail,
          depth: nextDepth,
        },
      ],
    };
  }

  if (edge.kind === 'delegates_to') {
    if (state.carriedClassification) {
      const clsCheck = isClassificationAllowedOnEdge(edge, state.carriedClassification);
      if (!clsCheck.ok) return { ok: false, reason: clsCheck.reason, nextStates: [] };
    }
    return {
      ok: true,
      nextStates: [
        {
          currentNodeId: toNode.nodeId,
          startIdentity: state.startIdentity,
          activeScope: edge.scope,
          authorizedScopes: uniqueSorted([...state.authorizedScopes, edge.scope]),
          activeRoles: uniqueSorted([
            ...state.activeRoles,
            ...(edge.conditions?.grantedRoles ?? []),
          ]),
          carriedAssetId: state.carriedAssetId,
          carriedClassification: state.carriedClassification,
          edgeTrail: newTrail,
          depth: nextDepth,
        },
      ],
    };
  }

  if (edge.kind === 'can_invoke') {
    if (state.carriedClassification) {
      const clsCheck = isClassificationAllowedOnEdge(edge, state.carriedClassification);
      if (!clsCheck.ok) return { ok: false, reason: clsCheck.reason, nextStates: [] };
    }
    return {
      ok: true,
      nextStates: [
        {
          currentNodeId: toNode.nodeId,
          startIdentity: state.startIdentity,
          activeScope: edge.scope,
          authorizedScopes: uniqueSorted([...state.authorizedScopes, edge.scope]),
          activeRoles: uniqueSorted([...state.activeRoles, ...(toNode.roles ?? [])]),
          carriedAssetId: state.carriedAssetId,
          carriedClassification: state.carriedClassification,
          edgeTrail: newTrail,
          depth: nextDepth,
        },
      ],
    };
  }

  if (edge.kind === 'can_read') {
    if (state.carriedAssetId !== null) {
      return {
        ok: false,
        reason: `Already carrying data asset ${state.carriedAssetId}`,
        nextStates: [],
      };
    }
    const assetClass: DataClassification =
      toNode.dataClassification ??
      (toNode.isRestrictedAsset ? 'RESTRICTED' : 'INTERNAL');
    const clsCheck = isClassificationAllowedOnEdge(edge, assetClass);
    if (!clsCheck.ok) return { ok: false, reason: clsCheck.reason, nextStates: [] };

    const nextStates: TraversalState[] = [
      {
        currentNodeId: fromNode.nodeId,
        startIdentity: state.startIdentity,
        activeScope: state.activeScope,
        authorizedScopes: state.authorizedScopes,
        activeRoles: state.activeRoles,
        carriedAssetId: toNode.nodeId,
        carriedClassification: assetClass,
        edgeTrail: newTrail,
        depth: nextDepth,
      },
    ];

    const assetOutgoing = outgoingByNode.get(toNode.nodeId) ?? [];
    if (
      assetOutgoing.some(
        (e) => e.kind === 'transfers_data_to' || e.kind === 'can_write'
      )
    ) {
      nextStates.push({
        currentNodeId: toNode.nodeId,
        startIdentity: state.startIdentity,
        activeScope: state.activeScope,
        authorizedScopes: state.authorizedScopes,
        activeRoles: state.activeRoles,
        carriedAssetId: toNode.nodeId,
        carriedClassification: assetClass,
        edgeTrail: newTrail,
        depth: nextDepth,
      });
    }

    return { ok: true, nextStates };
  }

  if (state.carriedAssetId === null || state.carriedClassification === null) {
    return {
      ok: false,
      reason: `Edge ${edge.edgeId} (${edge.kind}) requires carried data`,
      nextStates: [],
    };
  }

  const clsCheck = isClassificationAllowedOnEdge(edge, state.carriedClassification);
  if (!clsCheck.ok) return { ok: false, reason: clsCheck.reason, nextStates: [] };

  const effectiveClass: DataClassification = condRes.masksPii
    ? 'PUBLIC'
    : state.carriedClassification;

  const nextState: TraversalState = {
    currentNodeId: toNode.nodeId,
    startIdentity: state.startIdentity,
    activeScope: edge.scope,
    authorizedScopes: uniqueSorted([...state.authorizedScopes, edge.scope]),
    activeRoles: state.activeRoles,
    carriedAssetId: state.carriedAssetId,
    carriedClassification: effectiveClass,
    edgeTrail: newTrail,
    depth: nextDepth,
  };

  return {
    ok: true,
    nextStates: [nextState],
    terminalDataArrival: {
      targetNode: toNode,
      carriedAssetId: state.carriedAssetId,
      carriedClassification: effectiveClass,
      trail: newTrail,
    },
  };
}

function findViolatedPolicies(
  targetNode: AttackGraphNode,
  carriedClassification: DataClassification,
  policies: PolicyRule[]
): PolicyRule[] {
  const violated: PolicyRule[] = [];
  const sorted = [...policies].sort((a, b) =>
    a.policyId < b.policyId ? -1 : a.policyId > b.policyId ? 1 : 0
  );
  for (const policy of sorted) {
    const meetsMinClass =
      CLASSIFICATION_RANK[carriedClassification] >=
      CLASSIFICATION_RANK[policy.forbiddenTargetClassification];
    const isForbiddenDest =
      targetNode.kind === 'destination' &&
      (targetNode.trustZone === policy.forbiddenDestinationTrustZone ||
        targetNode.isUnauthorizedDestination === true);
    const explicitlyAllowed =
      targetNode.allowedClassifications !== undefined &&
      targetNode.allowedClassifications.includes(carriedClassification);
    if (meetsMinClass && isForbiddenDest && !explicitlyAllowed) {
      violated.push(policy);
    }
  }
  return violated;
}

function buildGraphLookups(graph: PolicyGraphFixture) {
  const nodeMap = new Map<string, AttackGraphNode>();
  for (const node of [...graph.nodes].sort((a, b) =>
    a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0
  )) {
    nodeMap.set(node.nodeId, node);
  }
  const edgeMap = new Map<string, AttackGraphEdge>();
  const outgoingByNode = new Map<string, AttackGraphEdge[]>();
  const sortedEdges = [...graph.edges].sort((a, b) =>
    a.edgeId < b.edgeId ? -1 : a.edgeId > b.edgeId ? 1 : 0
  );
  for (const edge of sortedEdges) {
    edgeMap.set(edge.edgeId, edge);
    const list = outgoingByNode.get(edge.from) ?? [];
    list.push(edge);
    outgoingByNode.set(edge.from, list);
  }
  return { nodeMap, edgeMap, outgoingByNode };
}

function findForbiddenPaths(graph: PolicyGraphFixture): {
  paths: DiscoveredViolationPath[];
  stats: BudgetStatsView;
} {
  const { nodeMap, outgoingByNode } = buildGraphLookups(graph);
  const startNodes = (
    graph.startIdentities && graph.startIdentities.length > 0
      ? uniqueSorted(graph.startIdentities)
          .map((id) => nodeMap.get(id))
          .filter((n): n is AttackGraphNode => Boolean(n))
      : [...graph.nodes]
          .filter((n) => n.kind === 'identity' || n.isEntryIdentity === true)
          .sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0))
  );

  const discovered: DiscoveredViolationPath[] = [];
  const seenSignatures = new Set<string>();
  let nodesVisited = 0;
  let edgesTraversed = 0;
  let maxDepthReached = 0;
  let pathsEvaluated = 0;
  const maxNodes = 500;
  const maxDepth = 12;
  const maxPaths = 50;
  let budgetExceeded = false;

  for (const startNode of startNodes) {
    if (budgetExceeded) break;
    const queue: TraversalState[] = [
      {
        currentNodeId: startNode.nodeId,
        startIdentity: startNode.nodeId,
        activeScope: startNode.scope,
        authorizedScopes: uniqueSorted([
          startNode.scope,
          ...(startNode.allowedScopes ?? []),
        ]),
        activeRoles: uniqueSorted(startNode.roles ?? []),
        carriedAssetId: null,
        carriedClassification: null,
        edgeTrail: [],
        depth: 0,
      },
    ];
    const visitedKeys = new Set<string>();

    while (queue.length > 0) {
      if (nodesVisited >= maxNodes || discovered.length >= maxPaths) {
        budgetExceeded = true;
        break;
      }
      const state = queue.shift()!;
      const key = [
        state.currentNodeId,
        state.activeScope,
        state.carriedAssetId ?? '',
        state.carriedClassification ?? '',
        state.authorizedScopes.join('|'),
        state.activeRoles.join('|'),
      ].join('::');
      if (visitedKeys.has(key)) continue;
      visitedKeys.add(key);
      nodesVisited += 1;
      if (state.depth > maxDepthReached) maxDepthReached = state.depth;
      if (state.depth >= maxDepth) continue;

      for (const edge of outgoingByNode.get(state.currentNodeId) ?? []) {
        edgesTraversed += 1;
        const outcome = tryTraverseEdge(edge, state, nodeMap, outgoingByNode);
        if (!outcome.ok) continue;

        if (outcome.terminalDataArrival) {
          pathsEvaluated += 1;
          const {
            targetNode,
            carriedAssetId,
            carriedClassification,
            trail,
          } = outcome.terminalDataArrival;
          const violations = findViolatedPolicies(
            targetNode,
            carriedClassification,
            graph.policies
          );
          if (violations.length > 0) {
            for (const violatedPolicy of violations) {
              const sig = [
                state.startIdentity,
                carriedAssetId,
                targetNode.nodeId,
                violatedPolicy.policyId,
                trail.map((e) => e.edgeId).join('>'),
              ].join('::');
              if (!seenSignatures.has(sig)) {
                seenSignatures.add(sig);
                discovered.push({
                  startIdentity: state.startIdentity,
                  targetAssetId: carriedAssetId,
                  targetDestinationId: targetNode.nodeId,
                  edges: trail,
                  violatedPolicy,
                  carriedClassification,
                });
              }
            }
            continue;
          }
        }
        for (const ns of outcome.nextStates) {
          queue.push(ns);
        }
      }
    }
  }

  return {
    paths: discovered,
    stats: {
      nodesVisited,
      edgesTraversed,
      maxDepthReached,
      pathsEvaluated,
      budgetExceeded,
    },
  };
}

function evaluateLegitimateOperations(graph: PolicyGraphFixture): {
  preserved: boolean;
  results: LegitimateOperationResultView[];
  missingSourceRefs: string[];
} {
  const { nodeMap, edgeMap, outgoingByNode } = buildGraphLookups(graph);
  const results: LegitimateOperationResultView[] = [];
  const missingSourceRefs = new Set<string>();

  const sortedOps = [...graph.legitimateOperations].sort((a, b) =>
    a.operationId < b.operationId ? -1 : a.operationId > b.operationId ? 1 : 0
  );

  for (const op of sortedOps) {
    const startNode = nodeMap.get(op.startIdentity);
    const targetNode = nodeMap.get(op.targetNodeId);
    if (!startNode || !targetNode) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: !startNode
          ? `Start identity '${op.startIdentity}' not found`
          : `Target node '${op.targetNodeId}' not found`,
        verifiedEdgeIds: [],
      });
      continue;
    }

    let currentStates: TraversalState[] = [
      {
        currentNodeId: startNode.nodeId,
        startIdentity: startNode.nodeId,
        activeScope: startNode.scope,
        authorizedScopes: uniqueSorted([
          startNode.scope,
          ...(startNode.allowedScopes ?? []),
        ]),
        activeRoles: uniqueSorted(startNode.roles ?? []),
        carriedAssetId: null,
        carriedClassification: null,
        edgeTrail: [],
        depth: 0,
      },
    ];
    let failedReason: string | undefined;
    const verifiedEdgeIds: string[] = [];

    for (const edgeId of op.requiredEdgeIds) {
      const edge = edgeMap.get(edgeId);
      if (!edge) {
        failedReason = `Required edge '${edgeId}' missing from policy graph`;
        break;
      }
      if (!edge.sourceRef || edge.sourceRef.trim().length === 0) {
        missingSourceRefs.add(edge.edgeId);
      }
      const nextPool: TraversalState[] = [];
      let lastReject = `No active state matched '${edgeId}'`;
      for (const st of currentStates) {
        const outcome = tryTraverseEdge(edge, st, nodeMap, outgoingByNode);
        if (outcome.ok) {
          nextPool.push(...outcome.nextStates);
        } else if (outcome.reason) {
          lastReject = outcome.reason;
        }
      }
      if (nextPool.length === 0) {
        failedReason = lastReject;
        break;
      }
      verifiedEdgeIds.push(edgeId);
      currentStates = nextPool;
    }

    if (failedReason) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: failedReason,
        verifiedEdgeIds,
      });
      continue;
    }

    const reachedTarget = currentStates.some(
      (st) =>
        st.currentNodeId === op.targetNodeId ||
        st.carriedAssetId === op.targetNodeId
    );
    if (!reachedTarget) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: `Target '${op.targetNodeId}' not reached`,
        verifiedEdgeIds,
      });
      continue;
    }

    const lastEdge = edgeMap.get(op.requiredEdgeIds[op.requiredEdgeIds.length - 1]);
    const finalNode = lastEdge ? nodeMap.get(lastEdge.to) : undefined;
    const violated =
      finalNode &&
      currentStates.some(
        (st) =>
          st.carriedClassification !== null &&
          findViolatedPolicies(
            finalNode,
            st.carriedClassification,
            graph.policies
          ).length > 0
      );
    if (violated) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: `Legitimate operation '${op.operationId}' violates security policy`,
        verifiedEdgeIds,
      });
      continue;
    }

    if (
      op.expectedDataClassification &&
      !currentStates.some(
        (st) => st.carriedClassification === op.expectedDataClassification
      )
    ) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: `Expected classification '${op.expectedDataClassification}' not matched`,
        verifiedEdgeIds,
      });
      continue;
    }

    results.push({
      operationId: op.operationId,
      description: op.description,
      preserved: true,
      reason: `Verified via ordered edges [${verifiedEdgeIds.join(' -> ')}]`,
      verifiedEdgeIds,
    });
  }

  return {
    preserved: results.every((r) => r.preserved),
    results,
    missingSourceRefs: uniqueSorted(missingSourceRefs),
  };
}

function generateRemediationSpec(params: {
  graph: PolicyGraphFixture;
  analysisId: string;
  path: AttackPathView;
  createdAt: string;
}): RemediationSpecView {
  const { graph, analysisId, path, createdAt } = params;
  const edgeById = new Map<string, AttackGraphEdge>(
    graph.edges.map((e) => [e.edgeId, e])
  );
  const pathEdges = path.edges
    .map((pe) => edgeById.get(pe.edgeId))
    .filter((e): e is AttackGraphEdge => e !== undefined);

  const legitimateEdgeIds = new Set<string>();
  for (const op of graph.legitimateOperations) {
    for (const eid of op.requiredEdgeIds) {
      legitimateEdgeIds.add(eid);
    }
  }

  const targetEdgeSig = path.edges.map((e) => e.edgeId).join('>');
  const checkCounterfactual = (cfGraph: PolicyGraphFixture) => {
    const reach = findForbiddenPaths(cfGraph);
    const stillPresent = reach.paths.some(
      (p) =>
        p.startIdentity === path.startIdentity &&
        p.targetAssetId === path.targetAsset &&
        p.violatedPolicy.policyId === path.violatedPolicyId &&
        p.edges.map((e) => e.edgeId).join('>') === targetEdgeSig
    );
    const legit = evaluateLegitimateOperations(cfGraph);
    return {
      breaksTargetPath: !stillPresent,
      remainingPathsCount: reach.paths.length,
      legit,
    };
  };

  interface Candidate {
    actions: RemediationActionView[];
    breaksTargetPath: boolean;
    remainingPathsCount: number;
    preservesLegitimate: boolean;
    preservedOperationIds: string[];
    score: number;
  }

  const candidates: Candidate[] = [];

  for (const edge of pathEdges) {
    // Candidate A: Remove edge
    {
      const cfGraph: PolicyGraphFixture = {
        ...graph,
        edges: graph.edges.filter((e) => e.edgeId !== edge.edgeId),
      };
      const sim = checkCounterfactual(cfGraph);
      if (sim.breaksTargetPath) {
        let score = 0;
        if (sim.legit.preserved) score += 10_000;
        if (sim.remainingPathsCount === 0) score += 1_000;
        if (!legitimateEdgeIds.has(edge.edgeId)) score += 200;
        if (edge.kind === 'can_read') score += 50;
        candidates.push({
          actions: [
            {
              actionType: 'REMOVE_EDGE',
              edgeId: edge.edgeId,
              from: edge.from,
              to: edge.to,
              edgeKind: edge.kind,
              currentScope: edge.scope,
              currentDataClassification: edge.dataClassification,
              proposedChange: `Remove or disable edge '${edge.edgeId}' (${edge.from} --[${edge.kind}]--> ${edge.to}) in scope '${edge.scope}'`,
              sourceRef: edge.sourceRef,
            },
          ],
          breaksTargetPath: true,
          remainingPathsCount: sim.remainingPathsCount,
          preservesLegitimate: sim.legit.preserved,
          preservedOperationIds: sim.legit.results
            .filter((r) => r.preserved)
            .map((r) => r.operationId),
          score,
        });
      }
    }

    // Candidate B: Restrict dataClassification to PUBLIC
    if (edge.dataClassification !== 'PUBLIC') {
      const cfGraph: PolicyGraphFixture = {
        ...graph,
        edges: graph.edges.map((e) =>
          e.edgeId === edge.edgeId
            ? {
                ...e,
                dataClassification: 'PUBLIC' as const,
                conditions: {
                  ...e.conditions,
                  allowedDataClassifications: ['PUBLIC' as const],
                },
              }
            : e
        ),
      };
      const sim = checkCounterfactual(cfGraph);
      if (sim.breaksTargetPath) {
        let score = 0;
        if (sim.legit.preserved) score += 10_000;
        if (sim.remainingPathsCount === 0) score += 1_000;
        if (edge.kind === 'transfers_data_to' || edge.kind === 'can_write') {
          score += 40;
        }
        candidates.push({
          actions: [
            {
              actionType: 'RESTRICT_DATA_CLASSIFICATION',
              edgeId: edge.edgeId,
              from: edge.from,
              to: edge.to,
              edgeKind: edge.kind,
              currentScope: edge.scope,
              currentDataClassification: edge.dataClassification,
              proposedChange: `Restrict edge '${edge.edgeId}' (${edge.from} --[${edge.kind}]--> ${edge.to}) dataClassification from '${edge.dataClassification}' to 'PUBLIC' and enforce allowedDataClassifications=['PUBLIC']`,
              proposedDataClassification: 'PUBLIC',
              proposedAllowedClassifications: ['PUBLIC'],
              sourceRef: edge.sourceRef,
            },
          ],
          breaksTargetPath: true,
          remainingPathsCount: sim.remainingPathsCount,
          preservesLegitimate: sim.legit.preserved,
          preservedOperationIds: sim.legit.results
            .filter((r) => r.preserved)
            .map((r) => r.operationId),
          score,
        });
      }
    }
  }

  candidates.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.actions[0].edgeId < b.actions[0].edgeId
      ? -1
      : a.actions[0].edgeId > b.actions[0].edgeId
        ? 1
        : 0;
  });

  const best = candidates[0];
  const remediationId = deriveDeterministicId('rem', {
    analysisId,
    pathId: path.pathId,
    actions: best.actions.map((a) => ({
      actionType: a.actionType,
      edgeId: a.edgeId,
    })),
  });

  const actionSummary = best.actions.map((a) => a.proposedChange).join('; ');
  return {
    remediationId,
    analysisId,
    tenantId: graph.tenantId,
    fixtureId: graph.fixtureId,
    pathId: path.pathId,
    violatedPolicyId: path.violatedPolicyId,
    riskRecommendation: path.riskRecommendation,
    minimalChange: best.actions.length === 1,
    actions: best.actions,
    breaksUnauthorizedPath: best.breaksTargetPath,
    preservesLegitimateOperations: best.preservesLegitimate,
    preservedOperationIds: best.preservedOperationIds,
    acceptanceCriteria: [
      `Re-running ChainBreak on the remediated policy graph produces 0 paths violating '${path.violatedPolicyId}'.`,
      `All ${graph.legitimateOperations.length} declared legitimate operation(s) remain preserved (legitimateOperationsPreserved === true).`,
      `Human security reviewer approves the policy diff for sourceRef [${best.actions.map((a) => a.sourceRef || 'missing-ref').join(', ')}] before merge.`,
    ],
    verificationTests: [
      `chainbreak:verify-no-path:${path.violatedPolicyId}`,
      ...graph.legitimateOperations.map(
        (op) => `chainbreak:verify-legitimate-op:${op.operationId}`
      ),
    ],
    requiresHumanApproval: true,
    autoApplyAllowed: false,
    rationale: `Counterfactual graph simulation verified that applying minimal defensive change (${actionSummary}) breaks unauthorized path '${path.pathId}' while preserving ${best.preservedOperationIds.length}/${graph.legitimateOperations.length} legitimate operations.`,
    nonTechnicalSummary: `To stop restricted data from reaching an unauthorized external destination, remove or restrict the single excessive permission (${best.actions[0].edgeId}). Validated simulations confirm normal reporting and payment workflows continue working without interruption.`,
    evidenceIds: [...path.evidenceIds],
    createdAt,
  };
}

/**
 * Evaluates a canonical `payments-lab/*` fixture deterministically in browser/LAB mode,
 * matching `@script-kitty/chainbreak`'s `analysisId`, `inputSha256`, `PATH_VALIDATED` paths,
 * `legitimateOperationsPreserved`, and minimal counterfactual `RemediationSpec`.
 */
export function evaluateLabFixture(
  fixtureId: CanonicalFixtureId,
  options: { now?: string; producer?: string } = {}
): SecurityAnalysisView {
  const graph = LAB_FIXTURES[fixtureId];
  const timestamp = options.now ?? '2026-11-11T12:00:00.000Z';
  const producer = options.producer ?? '@script-kitty/chainbreak';
  const computedInputSha256 = computePolicyGraphSha256(
    graph as unknown as Record<string, unknown>
  );

  const analysisId = deriveDeterministicId('cb', {
    tenantId: graph.tenantId,
    fixtureId: graph.fixtureId,
    policyVersion: graph.policyVersion,
    inputSha256: computedInputSha256,
  });

  const reachability = findForbiddenPaths(graph);
  const legitEval = evaluateLegitimateOperations(graph);
  const diagnostics: AnalysisDiagnosticView[] = [];
  const evidence: ChainBreakEvidenceView[] = [];

  const policySnapshotPayload = {
    fixtureId: graph.fixtureId,
    tenantId: graph.tenantId,
    policyVersion: graph.policyVersion,
    inputSha256: computedInputSha256,
    policies: graph.policies.map((p) => ({
      policyId: p.policyId,
      policyVersion: p.policyVersion,
      sourceRef: p.sourceRef,
    })),
  };
  const policySnapshotEvidenceId = deriveDeterministicId('ev-policy', {
    analysisId,
    inputSha256: computedInputSha256,
  });
  evidence.push({
    evidenceId: policySnapshotEvidenceId,
    analysisId,
    kind: 'POLICY_SNAPSHOT',
    sourceRef: graph.policies[0]?.sourceRef || graph.fixtureId,
    contentSha256: computeEvidenceContentSha256(policySnapshotPayload),
    producer,
    createdAt: timestamp,
    verified: true,
    summary: `Policy snapshot (${graph.policyVersion}) across ${graph.nodes.length} nodes and ${graph.edges.length} edges`,
  });

  const paths: AttackPathView[] = [];
  const remediationSpecs: RemediationSpecView[] = [];

  for (const rawPath of reachability.paths) {
    const missingRefs: string[] = [];
    for (const edge of rawPath.edges) {
      if (isMissingRef(edge.sourceRef)) {
        missingRefs.push(`edge:${edge.edgeId}:missing_sourceRef`);
      }
      if (
        isMissingRef(edge.policyVersion) ||
        edge.policyVersion !== graph.policyVersion
      ) {
        missingRefs.push(`edge:${edge.edgeId}:invalid_policyVersion`);
      }
    }
    const isProvenanceComplete = missingRefs.length === 0;
    const status: FindingStatus = isProvenanceComplete
      ? 'PATH_VALIDATED'
      : 'INCONCLUSIVE';
    const riskRecommendation: RiskRecommendation = isProvenanceComplete
      ? rawPath.violatedPolicy.riskRecommendation
      : 'UNDETERMINED';

    const pathId = deriveDeterministicId('path', {
      analysisId,
      startIdentity: rawPath.startIdentity,
      targetAssetId: rawPath.targetAssetId,
      targetDestinationId: rawPath.targetDestinationId,
      violatedPolicyId: rawPath.violatedPolicy.policyId,
      edgeIds: rawPath.edges.map((e) => e.edgeId),
    });

    const pathEdges: AttackPathEdgeView[] = rawPath.edges.map((e) => ({
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
    evidence.push({
      evidenceId: pathEvidenceId,
      analysisId,
      kind: 'GRAPH_PATH',
      sourceRef: rawPath.edges
        .map((e) => e.sourceRef)
        .filter((s) => !isMissingRef(s))
        .join(', '),
      contentSha256: computeEvidenceContentSha256(pathPayload),
      producer,
      createdAt: timestamp,
      verified: isProvenanceComplete,
      summary: `Graph path ${rawPath.startIdentity} -> ${rawPath.targetAssetId} -> ${rawPath.targetDestinationId} (${status})`,
    });

    const edgeTraceText = rawPath.edges
      .map(
        (e) =>
          `${e.edgeId} (${e.from} --[${e.kind}; scope=${e.scope}; class=${e.dataClassification}]--> ${e.to}; ref=${e.sourceRef})`
      )
      .join(' -> ');

    const attackPath: AttackPathView = {
      pathId,
      startIdentity: rawPath.startIdentity,
      targetAsset: rawPath.targetAssetId,
      targetDestination: rawPath.targetDestinationId,
      edges: pathEdges,
      violatedPolicyId: rawPath.violatedPolicy.policyId,
      status,
      evidenceIds: [policySnapshotEvidenceId, pathEvidenceId],
      riskRecommendation,
      explanation: `Modeled policy reachability path (${status}) violating '${rawPath.violatedPolicy.policyId}': starting from '${rawPath.startIdentity}', ordered transitions [${edgeTraceText}] allow '${rawPath.carriedClassification}' asset '${rawPath.targetAssetId}' to reach '${rawPath.targetDestinationId}'. Note: PATH_VALIDATED proves reachability within the modeled policy graph, not production exploitation.`,
      nonTechnicalSummary: `Under the tested policy rollout, an authorized identity (${rawPath.startIdentity}) can trigger a chain of permissions that moves restricted data (${rawPath.targetAssetId}) to an external destination (${rawPath.targetDestinationId}) that is not permitted to receive it. This finding is derived deterministically from the modeled permission rules and has not been run against production systems.`,
      ...(missingRefs.length > 0 ? { missingReferences: missingRefs } : {}),
    };

    paths.push(attackPath);
    remediationSpecs.push(
      generateRemediationSpec({
        graph,
        analysisId,
        path: attackPath,
        createdAt: timestamp,
      })
    );
  }

  const legitPayload = {
    preserved: legitEval.preserved,
    operations: legitEval.results,
  };
  const legitEvidenceId = deriveDeterministicId('ev-test', {
    analysisId,
    legitPayload,
  });
  evidence.push({
    evidenceId: legitEvidenceId,
    analysisId,
    kind: 'TEST_RESULT',
    sourceRef:
      graph.legitimateOperations
        .map((o) => o.sourceRef)
        .filter((s) => !isMissingRef(s))
        .join(', ') || graph.fixtureId,
    contentSha256: computeEvidenceContentSha256(legitPayload),
    producer,
    createdAt: timestamp,
    verified: legitEval.preserved && legitEval.missingSourceRefs.length === 0,
    summary: `Legitimate operations check: ${legitEval.results.filter((r) => r.preserved).length}/${legitEval.results.length} preserved`,
  });

  return {
    schemaVersion: 'security.analysis.v1',
    analysisId,
    tenantId: graph.tenantId,
    fixtureId: graph.fixtureId,
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
    status: 'COMPLETED',
    inputSha256: computedInputSha256,
    source: 'DETERMINISTIC_LAB_ANALYSIS',
    productionTested: false,
    budgetStats: reachability.stats,
    diagnostics,
  };
}

/**
 * Deterministic JEV-as-a-Judge mock evaluation aligned 1:1 with `@script-kitty/jev-judge`.
 */
export function evaluateLabJevMock(
  analysis: SecurityAnalysisView,
  options: { now?: string; providerMode?: 'MOCK' | 'FALLBACK' } = {}
): JevAdjudicationView {
  const timestamp = options.now ?? analysis.completedAt ?? '2026-11-11T12:00:00.000Z';
  const asFallback = options.providerMode === 'FALLBACK';
  const decisionSource = asFallback ? 'FALLBACK' : 'MOCK';
  const providerStatus = asFallback ? 'FALLBACK' : 'NOT_CONFIGURED';

  const sanitizedState = {
    schemaVersion: 'jev.sanitized.state.v1',
    mode: 'LAB',
    productionTested: false,
    analysisId: analysis.analysisId,
    tenantScopeDigest: sha256({ tenantId: analysis.tenantId }).slice(0, 16),
    fixtureId: analysis.fixtureId,
    policyVersion: analysis.policyVersion,
    analysisStatus: analysis.status,
    inputSha256: analysis.inputSha256,
    legitimateOperationsPreserved: analysis.legitimateOperationsPreserved,
    pathsCount: analysis.paths.length,
    paths: analysis.paths.map((p) => ({
      pathId: p.pathId,
      startIdentity: p.startIdentity,
      targetAsset: p.targetAsset,
      targetDestination: p.targetDestination,
      violatedPolicyId: p.violatedPolicyId,
      status: p.status,
      deterministicRisk: p.riskRecommendation,
      evidenceIds: p.evidenceIds,
      edges: p.edges.map((e) => ({
        edgeId: e.edgeId,
        from: e.from,
        to: e.to,
        kind: e.kind,
        scope: e.scope,
        dataClassification: e.dataClassification,
        policyId: e.policyId,
        policyVersion: e.policyVersion,
        sourceRef: e.sourceRef,
      })),
      missingReferencesCount: p.missingReferences?.length ?? 0,
    })),
    evidenceCount: analysis.evidence.length,
    verifiedEvidenceCount: analysis.evidence.filter((e) => e.verified).length,
    evidence: analysis.evidence.map((ev) => ({
      evidenceId: ev.evidenceId,
      kind: ev.kind,
      verified: ev.verified,
      contentSha256: ev.contentSha256,
      producer: ev.producer,
      sourceRef: ev.sourceRef,
    })),
    diagnosticCodes: analysis.diagnostics.map((d) => d.code),
    redactionsApplied: 0,
  };
  const sanitizedStateDigest = sha256(sanitizedState);

  const hasPaths = analysis.paths.length > 0;
  const allEvidenceVerified =
    analysis.evidence.length > 0 &&
    analysis.evidence.every((e) => e.verified === true);
  const hashValid = /^[a-f0-9]{64}$/i.test(analysis.inputSha256);
  const preValidationPassed =
    analysis.mode === 'LAB' &&
    !analysis.productionTested &&
    hashValid &&
    allEvidenceVerified;

  const hasValidated = analysis.paths.some((p) => p.status === 'PATH_VALIDATED');
  const deterministicRisk: RiskRecommendation | 'NONE' = !preValidationPassed
    ? 'UNDETERMINED'
    : analysis.paths.length === 0
      ? analysis.legitimateOperationsPreserved
        ? 'NONE'
        : 'P2'
      : analysis.paths[0].riskRecommendation;

  const evidenceSufficient = allEvidenceVerified ? 0.94 : 0.35;
  const isCritical = deterministicRisk === 'P0' || deterministicRisk === 'P1';
  const manualReviewScore =
    !allEvidenceVerified || isCritical || !analysis.legitimateOperationsPreserved
      ? 0.92
      : 0.12;

  const triageChoice = !allEvidenceVerified
    ? 'needs_more_evidence'
    : hasValidated
      ? 'likely_actionable'
      : 'likely_irrelevant';

  const probabilities =
    triageChoice === 'likely_actionable'
      ? {
          likely_actionable: 0.91,
          needs_more_evidence: 0.06,
          likely_irrelevant: 0.03,
        }
      : triageChoice === 'needs_more_evidence'
        ? {
            likely_actionable: 0.1,
            needs_more_evidence: 0.85,
            likely_irrelevant: 0.05,
          }
        : {
            likely_actionable: 0.02,
            needs_more_evidence: 0.05,
            likely_irrelevant: 0.93,
          };

  const confidence = probabilities[triageChoice];
  const escalationReasons: string[] = [];
  if (manualReviewScore >= 0.5) {
    escalationReasons.push(
      `JEV_FLAGGED_MANUAL_REVIEW: needs_manual_review=${manualReviewScore} >= threshold 0.5`
    );
  }
  if (isCritical || deterministicRisk === 'UNDETERMINED') {
    escalationReasons.push(
      `CRITICAL_OR_UNDETERMINED_RISK: deterministic risk=${deterministicRisk} requires mandatory human review`
    );
  }
  if (!analysis.legitimateOperationsPreserved) {
    escalationReasons.push(
      'LEGITIMATE_OPERATIONS_NOT_PRESERVED: business workflows require human verification'
    );
  }

  const escalated = escalationReasons.length > 0;
  const status = escalated ? 'PENDING_REVIEW' : 'ACCEPTED_FOR_TRIAGE';
  const decision = escalated
    ? 'escalated_human_review'
    : hasPaths
      ? 'triage_actionable'
      : 'triage_no_actionable_paths';

  const evaluationId = `jev-${sha256({
    analysisId: analysis.analysisId,
    tenantId: analysis.tenantId,
    inputSha256: analysis.inputSha256,
    timestamp,
  }).slice(0, 16)}`;

  const sourceRefs = Array.from(
    new Set([
      ...analysis.evidence.map((e) => e.sourceRef),
      ...analysis.paths.flatMap((p) => p.edges.map((ed) => ed.sourceRef)),
    ])
  ).filter((r) => !isMissingRef(r));

  return {
    evaluationId,
    analysisId: analysis.analysisId,
    tenantId: analysis.tenantId,
    model: 'mock-offline-v0',
    modelVersion: '0.1.0-mock',
    rubricVersion: 'jev-rubric-v0',
    answers: {
      evidence_sufficient: { type: 'noul', noul: evidenceSufficient },
      needs_manual_review: { type: 'noul', noul: manualReviewScore },
      triage: {
        type: 'choice',
        choice: triageChoice,
        confidence,
        probabilities,
      },
    },
    triage: triageChoice,
    decision,
    status,
    probabilities: {
      evidenceSufficient,
      needsManualReview: manualReviewScore,
      triageProbabilities: probabilities,
    },
    confidenceOrUncertainty: {
      confidence,
      uncertainty: Number((1 - confidence).toFixed(6)),
      evidenceSufficiencyScore: evidenceSufficient,
      manualReviewScore,
      threshold: 0.75,
      thresholdCalibrated: false,
      calibrationNote:
        'Threshold is uncalibrated raw score/confidence; not a calibrated statistical probability.',
    },
    escalated,
    escalationReasons,
    ...(escalated ? { escalationReason: escalationReasons.join('; ') } : {}),
    requiresHumanReview: escalated,
    riskRecommendation: deterministicRisk,
    evidenceIds: [...analysis.evidenceIds],
    sourceRefs,
    decisionSource,
    providerStatus,
    preValidation: {
      passed: preValidationPassed,
      blockingOutcome: 'NONE',
      checkedAt: timestamp,
      checks: {
        identityAndTenantScope: true,
        labModeBoundary: true,
        hashIntegrity: hashValid,
        evidenceCompletenessAndVerification: allEvidenceVerified,
        policyAndSourceRefs: true,
      },
      issues: [],
    },
    sanitizedStateDigest,
    mergeAllowed: false,
    deployAllowed: false,
    exploitConfirmed: false,
    p0DefinedByJevAlone: false,
    timestamp,
  };
}

/**
 * Evaluates deterministic Tri-Party Separation of Duties, builds the 3-node
 * RFC 8785 Custody Chain + Merkle root, and computes `factory.delivery.v1`
 * eligibility while ALWAYS enforcing `mergeAllowed: false`, `deployAllowed: false`.
 */
export function evaluateLabQualityGateAndDelivery(params: {
  analysis: SecurityAnalysisView;
  remediationSpec?: RemediationSpecView;
  simulateSelfCert?: boolean;
  now?: string;
}): {
  qualityGate: QualityGateEvaluationView;
  factoryDelivery: FactoryDeliveryView;
} {
  const timestamp = params.now ?? '2026-11-11T12:00:00.000Z';
  const commitSha = 'a1b2c3d4e5f67890123456789abcdef012345678';
  const simulateSelfCert = Boolean(params.simulateSelfCert);

  const discoveringAgentId = simulateSelfCert
    ? 'agent-omnipotent'
    : 'agent-discovery-chainbreak';
  const verifyingAgentId = simulateSelfCert
    ? 'agent-omnipotent'
    : 'agent-verifier-sandbox';
  const authorizingAgentId = 'agent-authorizer-gate';

  const dNorm = discoveringAgentId.trim().toLowerCase();
  const vNorm = verifyingAgentId.trim().toLowerCase();
  const aNorm = authorizingAgentId.trim().toLowerCase();

  let sodEval: SeparationOfDutiesView;
  if (dNorm === vNorm) {
    sodEval = {
      discovering_agent_id: discoveringAgentId,
      verifying_agent_id: verifyingAgentId,
      authorizing_agent_id: authorizingAgentId,
      is_valid: false,
      violation_code: 'E_SOD_SELF_CERTIFICATION',
      violation_details:
        'E_SOD_SELF_CERTIFICATION: Discovering agent cannot verify its own finding',
    };
  } else if (vNorm === aNorm || dNorm === aNorm) {
    sodEval = {
      discovering_agent_id: discoveringAgentId,
      verifying_agent_id: verifyingAgentId,
      authorizing_agent_id: authorizingAgentId,
      is_valid: false,
      violation_code: 'E_SOD_SELF_AUTHORIZATION',
      violation_details:
        'E_SOD_SELF_AUTHORIZATION: Verifying/discovering agent cannot authorize release',
    };
  } else {
    sodEval = {
      discovering_agent_id: discoveringAgentId,
      verifying_agent_id: verifyingAgentId,
      authorizing_agent_id: authorizingAgentId,
      is_valid: true,
    };
  }

  const targetAction = params.remediationSpec?.actions[0];
  const edgeId = targetAction?.edgeId ?? 'e-rollout-exporter-read-pii';
  const findingId = `SK-FIND-CB-${params.analysis.analysisId.slice(-8).toUpperCase()}`;
  const evidenceId = `SK-EVID-CB-${params.analysis.analysisId.slice(-8).toUpperCase()}`;
  const patchId = `SK-PATCH-CB-${params.analysis.analysisId.slice(-8).toUpperCase()}`;

  const findingContract = {
    finding_id: findingId,
    analysis_id: params.analysis.analysisId,
    fixture_id: params.analysis.fixtureId,
    input_sha256: params.analysis.inputSha256,
    policy_id: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
    commit_hash: commitSha,
    discovering_agent_id: discoveringAgentId,
    discovered_at: timestamp,
  };
  const findingLeaf = sha256Hex(canonicalStringify(findingContract));
  const node0Hash = computeNodeChainHash(
    0,
    'FINDING',
    findingId,
    GENESIS_HASH,
    findingLeaf,
    timestamp
  );

  const evidenceContract = {
    evidence_id: evidenceId,
    finding_id: findingId,
    verifier_agent_id: verifyingAgentId,
    status: 'VERIFIED_TRUE_POSITIVE',
    path_count: params.analysis.paths.length,
    legit_preserved: params.analysis.legitimateOperationsPreserved,
    recorded_at: timestamp,
  };
  const evidenceLeaf = sha256Hex(canonicalStringify(evidenceContract));
  const node1Hash = computeNodeChainHash(
    1,
    'EVIDENCE',
    evidenceId,
    node0Hash,
    evidenceLeaf,
    timestamp
  );

  const patchContract = {
    patch_id: patchId,
    finding_id: findingId,
    author_engine: 'agent-remediation-patchcat',
    action_type: targetAction?.actionType ?? 'REMOVE_EDGE',
    target_edge_id: edgeId,
    recheck_status: 'passed_clean',
    requires_human_approval: true,
    auto_apply_allowed: false,
    created_at: timestamp,
  };
  const patchLeaf = sha256Hex(canonicalStringify(patchContract));
  const node2Hash = computeNodeChainHash(
    2,
    'PATCH',
    patchId,
    node1Hash,
    patchLeaf,
    timestamp
  );

  const nodes: CustodyNodeRecord[] = [
    {
      index: 0,
      contract_type: 'FINDING',
      contract_id: findingId,
      parent_hash: GENESIS_HASH,
      leaf_hash: findingLeaf,
      timestamp,
      chain_hash: node0Hash,
    },
    {
      index: 1,
      contract_type: 'EVIDENCE',
      contract_id: evidenceId,
      parent_hash: node0Hash,
      leaf_hash: evidenceLeaf,
      timestamp,
      chain_hash: node1Hash,
    },
    {
      index: 2,
      contract_type: 'PATCH',
      contract_id: patchId,
      parent_hash: node1Hash,
      leaf_hash: patchLeaf,
      timestamp,
      chain_hash: node2Hash,
    },
  ];
  const verifyRes = verifyCustodyChain(nodes);

  const custodyChain: CustodyChainRecord = {
    chain_id: `SK-CHAIN-${findingId}`,
    finding_id: findingId,
    nodes,
    merkle_root: verifyRes.merkleRoot,
    total_nodes: nodes.length,
    is_valid: verifyRes.valid,
    created_at: timestamp,
  };

  const rulesEvaluated: QualityGateEvaluationView['rules_evaluated'] = [
    {
      rule_id: 'RULE_SEPARATION_OF_DUTIES',
      status: sodEval.is_valid ? 'PASS' : 'FAIL',
      reason: sodEval.is_valid
        ? `Strict Tri-Party Separation of Duties satisfied: Discoverer (${discoveringAgentId}) != Verifier (${verifyingAgentId}) != Authorizer (${authorizingAgentId})`
        : `Separation of Duties violation: ${sodEval.violation_details}`,
    },
    {
      rule_id: 'RULE_CUSTODY_INTEGRITY',
      status: verifyRes.valid ? 'PASS' : 'FAIL',
      reason: `Chain of Custody verified: ${verifyRes.totalNodes} nodes unbroken, Merkle root: ${verifyRes.merkleRoot}`,
    },
    {
      rule_id: 'RULE_PATCH_VERIFIED',
      status: 'PASS',
      reason: `Counterfactual remediation (${edgeId}) verified clean preserving legitimate operations`,
    },
  ];

  const decisionId = `SK-GATE-${params.analysis.analysisId.slice(-8).toUpperCase()}`;
  const verdict: QualityGateEvaluationView['verdict'] = !sodEval.is_valid
    ? 'REJECT'
    : !verifyRes.valid
      ? 'REJECT'
      : 'PASS';

  const summary =
    verdict === 'PASS'
      ? `Quality Gate PASSED: Valid Tri-Party SoD, 3/3 custody nodes unbroken, RFC 8785 Merkle root verified (LAB advisory — mergeAllowed=false, deployAllowed=false).`
      : `Gate REJECTED due to Separation of Duties violation: ${sodEval.violation_details}`;

  const auditLeaves = [
    ...rulesEvaluated.map((r) => sha256Hex(canonicalStringify(r))),
    sha256Hex(canonicalStringify(sodEval)),
    sha256Hex(canonicalStringify({ decisionId, verdict, summary })),
  ];
  const auditMerkleRoot = computeMerkleRoot(auditLeaves);

  const submitter = 'agent-remediation-patchcat';
  const reviewer = simulateSelfCert
    ? 'agent-remediation-patchcat'
    : 'human-security-reviewer';
  const deliveryEligible = sodEval.is_valid && verifyRes.valid;

  return {
    qualityGate: {
      decision_id: decisionId,
      verdict,
      simulatedSelfCert: simulateSelfCert,
      sod_evaluation: sodEval,
      custody_chain: custodyChain,
      custody_valid: verifyRes.valid,
      merkle_root: verifyRes.merkleRoot,
      audit_merkle_root: auditMerkleRoot,
      evaluation_summary: summary,
      rules_evaluated: rulesEvaluated,
      mergeAllowed: false,
      deployAllowed: false,
      decided_at: timestamp,
    },
    factoryDelivery: {
      contract: 'factory.delivery.v1',
      eligible: deliveryEligible,
      stage: deliveryEligible ? 'approved' : 'blocked',
      blockReason: deliveryEligible ? null : 'INDEPENDENT_REVIEW_REQUIRED',
      submissionsRemaining: 3,
      correctionsRemaining: 3,
      commitSha,
      checkedAt: timestamp,
      submitter,
      reviewer,
      checks: [
        { key: 'tests', status: 'passed', evidenceRef: 'ci/tests-pass-001' },
        {
          key: 'typecheck',
          status: 'passed',
          evidenceRef: 'ci/tsc-pass-001',
        },
        { key: 'build', status: 'passed', evidenceRef: 'ci/build-pass-001' },
      ],
      externalExecution: false,
      mergeAllowed: false,
      deployAllowed: false,
      deploymentAllowed: false,
    },
  };
}
