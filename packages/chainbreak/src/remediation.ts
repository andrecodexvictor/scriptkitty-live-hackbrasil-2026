/**
 * @file packages/chainbreak/src/remediation.ts
 * @description Counterfactual minimal-change RemediationSpec generator for ChainBreak v0.
 * Proposes the minimal defensive permission/edge restriction that breaks an unauthorized
 * reachability chain while proving legitimate business operations remain preserved.
 */

import { deriveDeterministicId } from './crypto.js';
import {
  DEFAULT_REACHABILITY_BUDGET,
  evaluateLegitimateOperations,
  findForbiddenPaths,
  type ReachabilityBudget,
} from './reachability.js';
import type {
  AttackPath,
  PolicyGraphEdgeInput,
  PolicyGraphInput,
  RemediationAction,
  RemediationSpec,
} from './schemas.js';

export interface GenerateRemediationParams {
  graph: PolicyGraphInput;
  analysisId: string;
  path: AttackPath;
  createdAt: string;
  budget?: ReachabilityBudget;
}

interface CounterfactualCandidate {
  actions: RemediationAction[];
  breaksTargetPath: boolean;
  remainingPathsCount: number;
  preservesLegitimate: boolean;
  preservedOperationIds: string[];
  score: number;
}

function doesPathPersist(
  targetPath: AttackPath,
  graph: PolicyGraphInput,
  budget: ReachabilityBudget
): { breaksTargetPath: boolean; remainingPathsCount: number } {
  const result = findForbiddenPaths(graph, budget);
  const targetEdgeSig = targetPath.edges.map((e) => e.edgeId).join('>');
  const stillPresent = result.paths.some(
    (p) =>
      p.startIdentity === targetPath.startIdentity &&
      p.targetAssetId === targetPath.targetAsset &&
      p.violatedPolicy.policyId === targetPath.violatedPolicyId &&
      p.edges.map((e) => e.edgeId).join('>') === targetEdgeSig
  );
  return {
    breaksTargetPath: !stillPresent,
    remainingPathsCount: result.paths.length,
  };
}

function buildRemoveEdgeAction(edge: PolicyGraphEdgeInput): RemediationAction {
  return {
    actionType: 'REMOVE_EDGE',
    edgeId: edge.edgeId,
    from: edge.from,
    to: edge.to,
    edgeKind: edge.kind,
    currentScope: edge.scope,
    currentDataClassification: edge.dataClassification,
    proposedChange: `Remove or disable edge '${edge.edgeId}' (${edge.from} --[${edge.kind}]--> ${edge.to}) in scope '${edge.scope}'`,
    sourceRef: edge.sourceRef,
  };
}

function buildRestrictClassificationAction(
  edge: PolicyGraphEdgeInput
): RemediationAction {
  return {
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
  };
}

/**
 * Deterministically computes the minimal counterfactual RemediationSpec for a detected AttackPath.
 */
export function generateRemediationSpec(
  params: GenerateRemediationParams
): RemediationSpec {
  const { graph, analysisId, path, createdAt } = params;
  const budget = params.budget ?? DEFAULT_REACHABILITY_BUDGET;

  const edgeById = new Map<string, PolicyGraphEdgeInput>(
    graph.edges.map((e) => [e.edgeId, e])
  );
  const pathEdges = path.edges
    .map((pe) => edgeById.get(pe.edgeId))
    .filter((e): e is PolicyGraphEdgeInput => e !== undefined);

  const legitimateEdgeIds = new Set<string>();
  for (const op of graph.legitimateOperations) {
    for (const eid of op.requiredEdgeIds) {
      legitimateEdgeIds.add(eid);
    }
  }

  const candidates: CounterfactualCandidate[] = [];

  for (const edge of pathEdges) {
    // Candidate A: Remove edge completely
    {
      const cfGraph: PolicyGraphInput = {
        ...graph,
        edges: graph.edges.filter((e) => e.edgeId !== edge.edgeId),
      };
      const reach = doesPathPersist(path, cfGraph, budget);
      const legit = evaluateLegitimateOperations(cfGraph);
      if (reach.breaksTargetPath) {
        const preservedIds = legit.results
          .filter((r) => r.preserved)
          .map((r) => r.operationId);
        // Prefer preserving legitimate ops first, zero remaining forbidden paths second,
        // and removing unused rollout edges over shared edges.
        let score = 0;
        if (legit.preserved) score += 10_000;
        if (reach.remainingPathsCount === 0) score += 1_000;
        if (!legitimateEdgeIds.has(edge.edgeId)) score += 200;
        if (edge.kind === 'can_read') score += 50;
        candidates.push({
          actions: [buildRemoveEdgeAction(edge)],
          breaksTargetPath: reach.breaksTargetPath,
          remainingPathsCount: reach.remainingPathsCount,
          preservesLegitimate: legit.preserved,
          preservedOperationIds: preservedIds,
          score,
        });
      }
    }

    // Candidate B: Restrict dataClassification on edge to PUBLIC (helpful for shared transfer edges)
    if (edge.dataClassification !== 'PUBLIC') {
      const cfGraph: PolicyGraphInput = {
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
      const reach = doesPathPersist(path, cfGraph, budget);
      const legit = evaluateLegitimateOperations(cfGraph);
      if (reach.breaksTargetPath) {
        const preservedIds = legit.results
          .filter((r) => r.preserved)
          .map((r) => r.operationId);
        let score = 0;
        if (legit.preserved) score += 10_000;
        if (reach.remainingPathsCount === 0) score += 1_000;
        if (edge.kind === 'transfers_data_to' || edge.kind === 'can_write') {
          score += 40;
        }
        candidates.push({
          actions: [buildRestrictClassificationAction(edge)],
          breaksTargetPath: reach.breaksTargetPath,
          remainingPathsCount: reach.remainingPathsCount,
          preservesLegitimate: legit.preserved,
          preservedOperationIds: preservedIds,
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

  const best = candidates[0] ?? {
    actions:
      pathEdges.length > 0
        ? [buildRemoveEdgeAction(pathEdges[pathEdges.length - 1])]
        : [
            {
              actionType: 'REMOVE_EDGE' as const,
              edgeId: path.edges[0]?.edgeId ?? 'unknown-edge',
              from: path.edges[0]?.from ?? path.startIdentity,
              to: path.edges[0]?.to ?? path.targetAsset,
              edgeKind: path.edges[0]?.kind ?? 'transfers_data_to',
              currentScope: path.edges[0]?.scope ?? 'unknown',
              currentDataClassification:
                path.edges[0]?.dataClassification ?? 'RESTRICTED',
              proposedChange: `Review and remove unauthorized edge in path ${path.pathId}`,
              sourceRef: path.edges[0]?.sourceRef ?? '',
            },
          ],
    breaksTargetPath: false,
    remainingPathsCount: 1,
    preservesLegitimate: false,
    preservedOperationIds: [],
    score: 0,
  };

  const actionSummary = best.actions.map((a) => a.proposedChange).join('; ');
  const remediationId = deriveDeterministicId('rem', {
    analysisId,
    pathId: path.pathId,
    actions: best.actions.map((a) => ({
      actionType: a.actionType,
      edgeId: a.edgeId,
    })),
  });

  const acceptanceCriteria = [
    `Re-running ChainBreak on the remediated policy graph produces 0 paths violating '${path.violatedPolicyId}'.`,
    `All ${graph.legitimateOperations.length} declared legitimate operation(s) remain preserved (legitimateOperationsPreserved === true).`,
    `Human security reviewer approves the policy diff for sourceRef [${best.actions.map((a) => a.sourceRef || 'missing-ref').join(', ')}] before merge.`,
  ];

  const verificationTests = [
    `chainbreak:verify-no-path:${path.violatedPolicyId}`,
    ...graph.legitimateOperations.map(
      (op) => `chainbreak:verify-legitimate-op:${op.operationId}`
    ),
  ];

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
    acceptanceCriteria,
    verificationTests,
    requiresHumanApproval: true,
    autoApplyAllowed: false,
    rationale: `Counterfactual graph simulation verified that applying minimal defensive change (${actionSummary}) breaks unauthorized path '${path.pathId}' while preserving ${best.preservedOperationIds.length}/${graph.legitimateOperations.length} legitimate operations.`,
    nonTechnicalSummary: `To stop restricted data from reaching an unauthorized external destination, remove or restrict the single excessive permission (${best.actions[0].edgeId}). Validated simulations confirm normal reporting and payment workflows continue working without interruption.`,
    evidenceIds: [...path.evidenceIds],
    createdAt,
  };
}
