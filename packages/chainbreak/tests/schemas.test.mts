/**
 * @file packages/chainbreak/tests/schemas.test.mts
 * @description Schema validation and invariant tests for @script-kitty/chainbreak.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

import {
  FindingStatusSchema,
  ExecutionScopeSchema,
  RemediationSpecSchema,
  SecurityAnalysisSchema,
  validateAttackGraphNode,
  validateAttackGraphEdge,
  validateChainBreakEvidence,
  validateExecutionScope,
  validateRemediationSpec,
  validateSecurityAnalysis,
} from '../dist/index.js';

describe('ChainBreak v0 Zod Schemas & Safety Invariants', () => {
  it('accepts all valid FindingStatus values and strictly forbids EXPLOIT_CONFIRMED', () => {
    for (const valid of [
      'POTENTIAL',
      'PATH_VALIDATED',
      'INCONCLUSIVE',
      'NOT_REPRODUCED',
    ]) {
      assert.equal(FindingStatusSchema.safeParse(valid).success, true);
    }
    assert.equal(FindingStatusSchema.safeParse('EXPLOIT_CONFIRMED').success, false);
    assert.equal(FindingStatusSchema.safeParse('CONFIRMED').success, false);
  });

  it('validates AttackGraphNode across all 7 allowed node kinds', () => {
    const kinds = [
      'identity',
      'agent',
      'mcp_tool',
      'api',
      'service',
      'data_asset',
      'destination',
    ] as const;

    for (const kind of kinds) {
      const res = validateAttackGraphNode({
        nodeId: `${kind}:sample`,
        kind,
        label: `Sample ${kind}`,
        tenantId: 'tenant-1',
        scope: 'default-scope',
      });
      assert.equal(res.success, true, `Expected ${kind} to pass validation`);
    }

    const bad = validateAttackGraphNode({
      nodeId: 'bad:1',
      kind: 'kubernetes_pod',
      label: 'Bad',
      tenantId: 'tenant-1',
      scope: 'default-scope',
    });
    assert.equal(bad.success, false);
  });

  it('validates AttackGraphEdge and rejects missing sourceRef at strict contract level', () => {
    const valid = validateAttackGraphEdge({
      edgeId: 'edge-1',
      from: 'identity:a',
      to: 'mcp_tool:b',
      kind: 'can_invoke',
      tenantId: 'tenant-1',
      scope: 'ops',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef: 'policies/sample.yaml#L10',
      policyVersion: 'v1',
      dataClassification: 'PUBLIC',
    });
    assert.equal(valid.success, true);

    const missingSourceRef = validateAttackGraphEdge({
      edgeId: 'edge-1',
      from: 'identity:a',
      to: 'mcp_tool:b',
      kind: 'can_invoke',
      tenantId: 'tenant-1',
      scope: 'ops',
      conditions: { effect: 'ALLOW', active: true },
      sourceRef: '',
      policyVersion: 'v1',
      dataClassification: 'PUBLIC',
    });
    assert.equal(missingSourceRef.success, false);
  });

  it('enforces ExecutionScope non-production & non-auto-deploy invariants', () => {
    const validScope = validateExecutionScope({
      tenantId: 'tenant-1',
      principalId: 'user:alice',
    });
    assert.equal(validScope.success, true);
    if (validScope.success) {
      assert.equal(validScope.data.mode, 'LAB');
      assert.equal(validScope.data.allowProductionExecution, false);
      assert.equal(validScope.data.allowAutoMergeOrDeploy, false);
    }

    assert.equal(
      ExecutionScopeSchema.safeParse({
        tenantId: 'tenant-1',
        principalId: 'user:alice',
        mode: 'PROD',
      }).success,
      false
    );
    assert.equal(
      ExecutionScopeSchema.safeParse({
        tenantId: 'tenant-1',
        principalId: 'user:alice',
        allowProductionExecution: true,
      }).success,
      false
    );
    assert.equal(
      ExecutionScopeSchema.safeParse({
        tenantId: 'tenant-1',
        principalId: 'user:alice',
        allowAutoMergeOrDeploy: true,
      }).success,
      false
    );
  });

  it('enforces RemediationSpec human approval & no-auto-apply invariants', () => {
    const validSpec = validateRemediationSpec({
      remediationId: 'rem-1',
      analysisId: 'cb-1',
      tenantId: 'tenant-1',
      fixtureId: 'payments-lab/unsafe-rollout',
      pathId: 'path-1',
      violatedPolicyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      riskRecommendation: 'P1',
      minimalChange: true,
      actions: [
        {
          actionType: 'REMOVE_EDGE',
          edgeId: 'e-1',
          from: 'mcp_tool:report-exporter',
          to: 'data_asset:customer-payment-pii',
          edgeKind: 'can_read',
          currentScope: 'reporting-public',
          currentDataClassification: 'RESTRICTED',
          proposedChange: 'Remove excessive can_read edge',
          sourceRef: 'policies/rollout.yaml#L24',
        },
      ],
      breaksUnauthorizedPath: true,
      preservesLegitimateOperations: true,
      preservedOperationIds: ['op-non-sensitive-export'],
      acceptanceCriteria: ['0 forbidden paths'],
      verificationTests: ['chainbreak:verify'],
      rationale: 'Counterfactual simulation verified removal.',
      nonTechnicalSummary: 'Remove excessive read permission.',
      evidenceIds: ['ev-1'],
      createdAt: '2026-11-11T12:00:00.000Z',
    });
    assert.equal(validSpec.success, true);

    const autoApplyAttempt = RemediationSpecSchema.safeParse({
      remediationId: 'rem-1',
      analysisId: 'cb-1',
      tenantId: 'tenant-1',
      fixtureId: 'payments-lab/unsafe-rollout',
      pathId: 'path-1',
      violatedPolicyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
      riskRecommendation: 'P1',
      minimalChange: true,
      actions: [
        {
          actionType: 'REMOVE_EDGE',
          edgeId: 'e-1',
          from: 'a',
          to: 'b',
          edgeKind: 'can_read',
          currentScope: 's',
          currentDataClassification: 'RESTRICTED',
          proposedChange: 'remove',
          sourceRef: 'ref',
        },
      ],
      breaksUnauthorizedPath: true,
      preservesLegitimateOperations: true,
      preservedOperationIds: [],
      acceptanceCriteria: ['ok'],
      verificationTests: ['test'],
      autoApplyAllowed: true,
      rationale: 'x',
      nonTechnicalSummary: 'y',
      evidenceIds: ['ev-1'],
      createdAt: '2026-11-11T12:00:00.000Z',
    });
    assert.equal(autoApplyAttempt.success, false);
  });

  it('validates ChainBreakEvidence and SecurityAnalysis v1 contract', () => {
    const ev = validateChainBreakEvidence({
      evidenceId: 'ev-1',
      analysisId: 'cb-1',
      kind: 'GRAPH_PATH',
      sourceRef: 'policies/rollout.yaml#L24',
      contentSha256: 'a'.repeat(64),
      producer: '@script-kitty/chainbreak',
      createdAt: '2026-11-11T12:00:00.000Z',
      verified: true,
    });
    assert.equal(ev.success, true);

    const analysis = validateSecurityAnalysis({
      schemaVersion: 'security.analysis.v1',
      analysisId: 'cb-1',
      tenantId: 'tenant-1',
      fixtureId: 'payments-lab/baseline',
      policyVersion: '2026.11.09-baseline',
      mode: 'LAB',
      paths: [],
      evidenceIds: ['ev-1'],
      legitimateOperationsPreserved: true,
      startedAt: '2026-11-11T12:00:00.000Z',
      completedAt: '2026-11-11T12:00:01.000Z',
      status: 'COMPLETED',
      inputSha256: 'b'.repeat(64),
    });
    assert.equal(analysis.success, true);

    assert.equal(
      SecurityAnalysisSchema.safeParse({
        schemaVersion: 'security.analysis.v2',
      }).success,
      false
    );
  });
});
