/**
 * @file packages/chainbreak/src/reachability.ts
 * @description Deterministic policy-graph reachability, transition-semantics evaluator,
 * and legitimate business operations verifier for ChainBreak v0.
 */

import {
  CLASSIFICATION_RANK,
  type AttackGraphEdgeKind,
  type AttackGraphNode,
  type BudgetStats,
  type DataClassification,
  type LegitimateOperation,
  type LegitimateOperationResult,
  type PolicyGraphEdgeInput,
  type PolicyGraphInput,
  type PolicyRule,
} from './schemas.js';

export interface ReachabilityBudget {
  maxNodes: number;
  maxDepth: number;
  maxPaths: number;
  maxDurationMs: number;
}

export const DEFAULT_REACHABILITY_BUDGET: ReachabilityBudget = {
  maxNodes: 500,
  maxDepth: 12,
  maxPaths: 50,
  maxDurationMs: 5_000,
};

export interface TraversalState {
  currentNodeId: string;
  startIdentity: string;
  activeScope: string;
  authorizedScopes: string[];
  activeRoles: string[];
  carriedAssetId: string | null;
  carriedClassification: DataClassification | null;
  edgeTrail: PolicyGraphEdgeInput[];
  depth: number;
}

export interface DiscoveredViolationPath {
  startIdentity: string;
  targetAssetId: string;
  targetDestinationId: string;
  edges: PolicyGraphEdgeInput[];
  violatedPolicy: PolicyRule;
  carriedClassification: DataClassification;
}

export interface ReachabilityRunResult {
  paths: DiscoveredViolationPath[];
  stats: BudgetStats;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function resolveDotPath(obj: Record<string, unknown>, dotPath: string): unknown {
  const parts = dotPath.split('.');
  let cur: unknown = obj;
  for (const part of parts) {
    if (cur === null || cur === undefined || typeof cur !== 'object') {
      return undefined;
    }
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/**
 * Deterministically evaluates all edge preconditions against the current traversal state and endpoints.
 */
export function evaluateEdgeConditions(
  edge: PolicyGraphEdgeInput,
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
    const heldRoles = new Set([...state.activeRoles, ...fromNode.roles]);
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
        reason: `Edge ${edge.edgeId} restricts networkZone to ${cond.networkZone}, target is ${toNode.trustZone}`,
      };
    }
  }

  if (cond.allowedPurposes && cond.allowedPurposes.length > 0) {
    if (!cond.purpose || !cond.allowedPurposes.includes(cond.purpose)) {
      return {
        ok: false,
        reason: `Edge ${edge.edgeId} purpose '${cond.purpose ?? 'none'}' not in allowedPurposes`,
      };
    }
  }

  if (cond.expressions && cond.expressions.length > 0) {
    const context: Record<string, unknown> = {
      edge,
      from: fromNode,
      to: toNode,
      activeScope: state.activeScope,
      carriedClassification: state.carriedClassification,
      metadata: {
        ...(fromNode.metadata ?? {}),
        ...(toNode.metadata ?? {}),
      },
    };
    for (const expr of cond.expressions) {
      const actual = resolveDotPath(context, expr.field);
      if (expr.op === 'eq' && actual !== expr.value) {
        return { ok: false, reason: `Condition ${expr.field} == ${String(expr.value)} failed` };
      }
      if (expr.op === 'neq' && actual === expr.value) {
        return { ok: false, reason: `Condition ${expr.field} != ${String(expr.value)} failed` };
      }
      if (
        expr.op === 'in' &&
        (!Array.isArray(expr.value) ||
          typeof actual !== 'string' ||
          !expr.value.includes(actual))
      ) {
        return { ok: false, reason: `Condition ${expr.field} in [...] failed` };
      }
      if (
        expr.op === 'not_in' &&
        Array.isArray(expr.value) &&
        typeof actual === 'string' &&
        expr.value.includes(actual)
      ) {
        return { ok: false, reason: `Condition ${expr.field} not_in [...] failed` };
      }
    }
  }

  const masksPii =
    cond.requiresPiiMasking === true && cond.piiMaskingApplied === true;
  return { ok: true, masksPii };
}

function isClassificationAllowedOnEdge(
  edge: PolicyGraphEdgeInput,
  classification: DataClassification
): { ok: boolean; reason?: string } {
  if (CLASSIFICATION_RANK[edge.dataClassification] < CLASSIFICATION_RANK[classification]) {
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
  edge: PolicyGraphEdgeInput,
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
        reason: `Role/delegation edge ${edge.edgeId} scope '${edge.scope}' outside authorized scopes [${state.authorizedScopes.join(', ')}]`,
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
    reason: `Scope mismatch on edge ${edge.edgeId}: edge requires '${edge.scope}', active scope is '${state.activeScope}'`,
  };
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

export interface EdgeTransitionOutcome {
  ok: boolean;
  reason?: string;
  nextStates: TraversalState[];
  terminalDataArrival?: {
    targetNode: AttackGraphNode;
    carriedAssetId: string;
    carriedClassification: DataClassification;
    trail: PolicyGraphEdgeInput[];
  };
}

/**
 * Attempts a single semantically-validated edge transition from `state`.
 * Enforces edge/node compatibility, scope rules, conditions, and data classification compatibility.
 */
export function tryTraverseEdge(
  edge: PolicyGraphEdgeInput,
  state: TraversalState,
  nodeMap: Map<string, AttackGraphNode>,
  outgoingByNode: Map<string, PolicyGraphEdgeInput[]>
): EdgeTransitionOutcome {
  const fromNode = nodeMap.get(edge.from);
  const toNode = nodeMap.get(edge.to);
  if (!fromNode || !toNode) {
    return { ok: false, reason: `Missing endpoint node for edge ${edge.edgeId}`, nextStates: [] };
  }

  if (edge.from !== state.currentNodeId) {
    return {
      ok: false,
      reason: `Edge ${edge.edgeId} starts at ${edge.from}, expected ${state.currentNodeId}`,
      nextStates: [],
    };
  }

  if (state.edgeTrail.some((e) => e.edgeId === edge.edgeId)) {
    return { ok: false, reason: `Cycle prevented on edge ${edge.edgeId}`, nextStates: [] };
  }

  const kindCompat = VALID_EDGE_NODE_PAIRS[edge.kind];
  if (!kindCompat.from.has(fromNode.kind) || !kindCompat.to.has(toNode.kind)) {
    return {
      ok: false,
      reason: `Incompatible edge type '${edge.kind}' between ${fromNode.kind} and ${toNode.kind}`,
      nextStates: [],
    };
  }

  const scopeResult = isScopeCompatible(edge, state, fromNode);
  if (!scopeResult.ok) {
    return { ok: false, reason: scopeResult.reason, nextStates: [] };
  }

  const condResult = evaluateEdgeConditions(edge, state, fromNode, toNode);
  if (!condResult.ok) {
    return { ok: false, reason: condResult.reason, nextStates: [] };
  }

  const newTrail = [...state.edgeTrail, edge];
  const nextDepth = state.depth + 1;

  if (edge.kind === 'assumes_role') {
    if (state.carriedClassification) {
      const clsCheck = isClassificationAllowedOnEdge(edge, state.carriedClassification);
      if (!clsCheck.ok) {
        return { ok: false, reason: clsCheck.reason, nextStates: [] };
      }
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
            ...toNode.roles,
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
      if (!clsCheck.ok) {
        return { ok: false, reason: clsCheck.reason, nextStates: [] };
      }
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
          ]),
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
      if (!clsCheck.ok) {
        return { ok: false, reason: clsCheck.reason, nextStates: [] };
      }
    }
    return {
      ok: true,
      nextStates: [
        {
          currentNodeId: toNode.nodeId,
          startIdentity: state.startIdentity,
          activeScope: edge.scope,
          authorizedScopes: uniqueSorted([...state.authorizedScopes, edge.scope]),
          activeRoles: uniqueSorted([...state.activeRoles, ...toNode.roles]),
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

    const assetClassification: DataClassification =
      toNode.dataClassification ??
      (toNode.isRestrictedAsset ? 'RESTRICTED' : 'INTERNAL');
    const clsCheck = isClassificationAllowedOnEdge(edge, assetClassification);
    if (!clsCheck.ok) {
      return { ok: false, reason: clsCheck.reason, nextStates: [] };
    }

    const actorState: TraversalState = {
      currentNodeId: fromNode.nodeId,
      startIdentity: state.startIdentity,
      activeScope: state.activeScope,
      authorizedScopes: state.authorizedScopes,
      activeRoles: state.activeRoles,
      carriedAssetId: toNode.nodeId,
      carriedClassification: assetClassification,
      edgeTrail: newTrail,
      depth: nextDepth,
    };

    const nextStates: TraversalState[] = [actorState];

    // Also allow outgoing transfers directly modeled on the data_asset node itself
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
        carriedClassification: assetClassification,
        edgeTrail: newTrail,
        depth: nextDepth,
      });
    }

    return { ok: true, nextStates };
  }

  // 'can_write' or 'transfers_data_to'
  if (state.carriedAssetId === null || state.carriedClassification === null) {
    return {
      ok: false,
      reason: `Edge ${edge.edgeId} (${edge.kind}) cannot fire without previously read data`,
      nextStates: [],
    };
  }

  const clsCheck = isClassificationAllowedOnEdge(edge, state.carriedClassification);
  if (!clsCheck.ok) {
    return { ok: false, reason: clsCheck.reason, nextStates: [] };
  }

  const effectiveClassification: DataClassification = condResult.masksPii
    ? 'PUBLIC'
    : state.carriedClassification;

  const nextState: TraversalState = {
    currentNodeId: toNode.nodeId,
    startIdentity: state.startIdentity,
    activeScope: edge.scope,
    authorizedScopes: uniqueSorted([...state.authorizedScopes, edge.scope]),
    activeRoles: state.activeRoles,
    carriedAssetId: state.carriedAssetId,
    carriedClassification: effectiveClassification,
    edgeTrail: newTrail,
    depth: nextDepth,
  };

  return {
    ok: true,
    nextStates: [nextState],
    terminalDataArrival: {
      targetNode: toNode,
      carriedAssetId: state.carriedAssetId,
      carriedClassification: effectiveClassification,
      trail: newTrail,
    },
  };
}

/**
 * Checks whether arriving at `targetNode` carrying `carriedClassification` violates any PolicyRule.
 */
export function findViolatedPolicies(
  targetNode: AttackGraphNode,
  carriedClassification: DataClassification,
  policies: PolicyRule[]
): PolicyRule[] {
  const violated: PolicyRule[] = [];
  const sortedPolicies = [...policies].sort((a, b) =>
    a.policyId < b.policyId ? -1 : a.policyId > b.policyId ? 1 : 0
  );

  for (const policy of sortedPolicies) {
    const meetsMinClass =
      CLASSIFICATION_RANK[carriedClassification] >=
      CLASSIFICATION_RANK[policy.forbiddenTargetClassification];
    const isForbiddenDestination =
      targetNode.kind === 'destination' &&
      (targetNode.trustZone === policy.forbiddenDestinationTrustZone ||
        targetNode.isUnauthorizedDestination === true);
    const explicitlyAllowed =
      targetNode.allowedClassifications !== undefined &&
      targetNode.allowedClassifications.includes(carriedClassification);

    if (meetsMinClass && isForbiddenDestination && !explicitlyAllowed) {
      violated.push(policy);
    }
  }

  return violated;
}

export function buildGraphLookups(graph: PolicyGraphInput): {
  nodeMap: Map<string, AttackGraphNode>;
  edgeMap: Map<string, PolicyGraphEdgeInput>;
  outgoingByNode: Map<string, PolicyGraphEdgeInput[]>;
} {
  const nodeMap = new Map<string, AttackGraphNode>();
  for (const node of [...graph.nodes].sort((a, b) =>
    a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0
  )) {
    nodeMap.set(node.nodeId, node);
  }

  const edgeMap = new Map<string, PolicyGraphEdgeInput>();
  const outgoingByNode = new Map<string, PolicyGraphEdgeInput[]>();

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

export function resolveStartIdentities(
  graph: PolicyGraphInput,
  nodeMap: Map<string, AttackGraphNode>
): AttackGraphNode[] {
  if (graph.startIdentities && graph.startIdentities.length > 0) {
    const selected: AttackGraphNode[] = [];
    for (const id of uniqueSorted(graph.startIdentities)) {
      const node = nodeMap.get(id);
      if (node) selected.push(node);
    }
    return selected;
  }

  return [...graph.nodes]
    .filter((n) => n.kind === 'identity' || n.isEntryIdentity === true)
    .sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
}

/**
 * Deterministic BFS reachability over valid policy-graph transitions with cycle prevention
 * and node/depth/path/time budgets.
 */
export function findForbiddenPaths(
  graph: PolicyGraphInput,
  budget: ReachabilityBudget = DEFAULT_REACHABILITY_BUDGET
): ReachabilityRunResult {
  const { nodeMap, outgoingByNode } = buildGraphLookups(graph);
  const startNodes = resolveStartIdentities(graph, nodeMap);

  const discovered: DiscoveredViolationPath[] = [];
  const seenPathSignatures = new Set<string>();

  const startTimeMs = Date.now();
  let nodesVisited = 0;
  let edgesTraversed = 0;
  let maxDepthReached = 0;
  let pathsEvaluated = 0;
  let budgetExceeded = false;

  for (const startNode of startNodes) {
    if (budgetExceeded) break;

    const initialState: TraversalState = {
      currentNodeId: startNode.nodeId,
      startIdentity: startNode.nodeId,
      activeScope: startNode.scope,
      authorizedScopes: uniqueSorted([
        startNode.scope,
        ...(startNode.allowedScopes ?? []),
      ]),
      activeRoles: uniqueSorted(startNode.roles),
      carriedAssetId: null,
      carriedClassification: null,
      edgeTrail: [],
      depth: 0,
    };

    const queue: TraversalState[] = [initialState];
    const visitedStateKeys = new Set<string>();

    while (queue.length > 0) {
      if (
        Date.now() - startTimeMs > budget.maxDurationMs ||
        nodesVisited >= budget.maxNodes ||
        discovered.length >= budget.maxPaths
      ) {
        budgetExceeded = true;
        break;
      }

      const state = queue.shift()!;
      const stateKey = [
        state.currentNodeId,
        state.activeScope,
        state.carriedAssetId ?? '',
        state.carriedClassification ?? '',
        state.authorizedScopes.join('|'),
        state.activeRoles.join('|'),
      ].join('::');

      if (visitedStateKeys.has(stateKey)) {
        continue;
      }
      visitedStateKeys.add(stateKey);
      nodesVisited += 1;
      if (state.depth > maxDepthReached) {
        maxDepthReached = state.depth;
      }

      if (state.depth >= budget.maxDepth) {
        continue;
      }

      const outgoing = outgoingByNode.get(state.currentNodeId) ?? [];
      for (const edge of outgoing) {
        edgesTraversed += 1;
        const outcome = tryTraverseEdge(edge, state, nodeMap, outgoingByNode);
        if (!outcome.ok) {
          continue;
        }

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

              if (!seenPathSignatures.has(sig)) {
                seenPathSignatures.add(sig);
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
            // Do not expand past a policy violation destination
            continue;
          }
        }

        for (const nextState of outcome.nextStates) {
          queue.push(nextState);
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

/**
 * Evaluates all declared legitimate business operations using the exact same transition
 * semantics to prove whether a policy rollout or remediation preserves valid workflows.
 */
export function evaluateLegitimateOperations(
  graph: PolicyGraphInput
): {
  preserved: boolean;
  results: LegitimateOperationResult[];
  missingSourceRefs: string[];
} {
  const { nodeMap, edgeMap, outgoingByNode } = buildGraphLookups(graph);
  const results: LegitimateOperationResult[] = [];
  const missingSourceRefs = new Set<string>();

  const sortedOps = [...graph.legitimateOperations].sort((a, b) =>
    a.operationId < b.operationId ? -1 : a.operationId > b.operationId ? 1 : 0
  );

  for (const op of sortedOps) {
    const startNode = nodeMap.get(op.startIdentity);
    const targetNode = nodeMap.get(op.targetNodeId);

    if (!startNode) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: `Start identity '${op.startIdentity}' not found in graph`,
        verifiedEdgeIds: [],
      });
      continue;
    }

    if (!targetNode) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: `Target node '${op.targetNodeId}' not found in graph`,
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
        activeRoles: uniqueSorted(startNode.roles),
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
      let lastRejectReason = `No active state matched edge '${edgeId}'`;
      for (const st of currentStates) {
        const outcome = tryTraverseEdge(edge, st, nodeMap, outgoingByNode);
        if (outcome.ok) {
          for (const ns of outcome.nextStates) {
            nextPool.push(ns);
          }
        } else if (outcome.reason) {
          lastRejectReason = outcome.reason;
        }
      }

      if (nextPool.length === 0) {
        failedReason = lastRejectReason;
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
        reason: `Sequence completed without reaching or reading target '${op.targetNodeId}'`,
        verifiedEdgeIds,
      });
      continue;
    }

    // Ensure the legitimate operation itself does not trigger any forbidden policy violation
    const lastEdge = edgeMap.get(op.requiredEdgeIds[op.requiredEdgeIds.length - 1]);
    const finalNode = lastEdge ? nodeMap.get(lastEdge.to) : undefined;
    const violatedDuringLegit =
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

    if (violatedDuringLegit) {
      results.push({
        operationId: op.operationId,
        description: op.description,
        preserved: false,
        reason: `Legitimate operation '${op.operationId}' violates a security policy`,
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
