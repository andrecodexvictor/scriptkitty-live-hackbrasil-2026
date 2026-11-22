/**
 * @file packages/chainbreak/tests/determinism-and-adversarial.test.mts
 * @description Tests determinism, tamper detection, missing sourceRef/policyRef handling,
 * transition semantics edge cases, cycle detection, tenant isolation, and traversal budgets.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

import {
  analyzeFixture,
  analyzePolicyGraph,
  loadFixtureGraph,
  verifyEvidenceHash,
  type PolicyGraphInput,
} from '../dist/index.js';

describe('ChainBreak v0 Determinism, Tamper & Transition Invariants', () => {
  it('produces identical deterministic outputs across repeated runs and reordered graph arrays', () => {
    const fixedNow = '2026-11-11T12:00:00.000Z';
    const run1 = analyzeFixture('payments-lab/unsafe-rollout', { now: fixedNow });
    const run2 = analyzeFixture('payments-lab/unsafe-rollout', { now: fixedNow });

    assert.deepEqual(run1, run2);

    // Reorder nodes & edges in memory (excluding declaredInputSha256 which covers raw order)
    const raw = loadFixtureGraph('payments-lab/unsafe-rollout') as Record<
      string,
      unknown
    >;
    const clone = structuredClone(raw) as unknown as PolicyGraphInput;
    delete clone.declaredInputSha256;
    clone.nodes.reverse();
    clone.edges.reverse();
    clone.legitimateOperations.reverse();

    const reordered = analyzePolicyGraph(clone, { now: fixedNow });
    assert.equal(reordered.status, 'COMPLETED');
    assert.equal(reordered.paths.length, run1.paths.length);
    assert.equal(
      reordered.paths[0].edges.map((e) => e.edgeId).join('>'),
      run1.paths[0].edges.map((e) => e.edgeId).join('>')
    );
    assert.equal(
      reordered.remediationSpecs[0].actions[0].edgeId,
      run1.remediationSpecs[0].actions[0].edgeId
    );
    assert.equal(
      reordered.legitimateOperationsPreserved,
      run1.legitimateOperationsPreserved
    );
  });

  it('fails closed on tampered input graph (declaredInputSha256 or expectedInputSha256 mismatch)', () => {
    const raw = loadFixtureGraph('payments-lab/unsafe-rollout') as Record<
      string,
      unknown
    >;
    const tampered = structuredClone(raw) as unknown as PolicyGraphInput;
    // Tamper with an edge description/scope without updating declaredInputSha256
    tampered.edges[0].scope = 'tampered-scope';

    const result = analyzePolicyGraph(tampered);
    assert.equal(result.status, 'FAILED');
    assert.equal(result.paths.length, 0);
    assert.equal(result.legitimateOperationsPreserved, false);
    assert.ok(result.diagnostics.some((d) => d.code === 'TAMPER_DETECTED'));
    assert.equal(result.evidence[0].verified, false);

    // Also test expectedInputSha256 mismatch
    const cleanNoDeclared = structuredClone(raw) as Record<string, unknown>;
    delete cleanNoDeclared.declaredInputSha256;
    const expectedMismatch = analyzePolicyGraph(cleanNoDeclared, {
      expectedInputSha256: '0'.repeat(64),
    });
    assert.equal(expectedMismatch.status, 'FAILED');
    assert.ok(
      expectedMismatch.diagnostics.some((d) => d.code === 'TAMPER_DETECTED')
    );
  });

  it('detects ChainBreakEvidence contentSha256 tampering', () => {
    const raw = loadFixtureGraph('payments-lab/unsafe-rollout');
    const analysis = analyzeFixture('payments-lab/unsafe-rollout');
    const policyEv = analysis.evidence.find((e) => e.kind === 'POLICY_SNAPSHOT');
    assert.ok(policyEv);

    const payload = {
      fixtureId: raw.fixtureId,
      tenantId: raw.tenantId,
      policyVersion: raw.policyVersion,
      inputSha256: analysis.inputSha256,
      policies: (raw.policies as Array<Record<string, unknown>>).map((p) => ({
        policyId: p.policyId,
        policyVersion: p.policyVersion,
        sourceRef: p.sourceRef,
      })),
    };
    assert.equal(verifyEvidenceHash(policyEv, payload), true);

    const tamperedEv = { ...policyEv, contentSha256: 'f'.repeat(64) };
    assert.equal(verifyEvidenceHash(tamperedEv, payload), false);
  });

  it('never assigns PATH_VALIDATED when an edge on a reachable path is missing sourceRef or policyVersion', () => {
    const raw = loadFixtureGraph('payments-lab/unsafe-rollout') as Record<
      string,
      unknown
    >;

    // Case 1: missing sourceRef on the rollout edge
    const missingRefGraph = structuredClone(raw) as unknown as PolicyGraphInput;
    delete missingRefGraph.declaredInputSha256;
    const rolloutEdge = missingRefGraph.edges.find(
      (e) => e.edgeId === 'e-rollout-exporter-read-pii'
    )!;
    rolloutEdge.sourceRef = '';

    const resMissingRef = analyzePolicyGraph(missingRefGraph);
    assert.equal(resMissingRef.status, 'INCONCLUSIVE');
    assert.equal(resMissingRef.paths.length, 1);
    assert.equal(resMissingRef.paths[0].status, 'INCONCLUSIVE');
    assert.notEqual(resMissingRef.paths[0].status, 'PATH_VALIDATED');
    assert.equal(resMissingRef.paths[0].riskRecommendation, 'UNDETERMINED');
    assert.ok(
      (resMissingRef.paths[0].missingReferences ?? []).some((r) =>
        r.includes('missing_sourceRef')
      )
    );
    const pathEv1 = resMissingRef.evidence.find((e) => e.kind === 'GRAPH_PATH');
    assert.equal(pathEv1?.verified, false);

    // Case 2: missing/mismatched policyVersion on edge
    const missingPolVerGraph = structuredClone(raw) as unknown as PolicyGraphInput;
    delete missingPolVerGraph.declaredInputSha256;
    const transferEdge = missingPolVerGraph.edges.find(
      (e) => e.edgeId === 'e-exporter-transfer-external'
    )!;
    transferEdge.policyVersion = '';

    const resMissingPol = analyzePolicyGraph(missingPolVerGraph);
    assert.equal(resMissingPol.status, 'INCONCLUSIVE');
    assert.equal(resMissingPol.paths.length, 1);
    assert.equal(resMissingPol.paths[0].status, 'INCONCLUSIVE');
    assert.equal(resMissingPol.paths[0].riskRecommendation, 'UNDETERMINED');
  });

  it('enforces tenant isolation on nodes, edges, and caller ExecutionScope', () => {
    const raw = loadFixtureGraph('payments-lab/baseline') as Record<
      string,
      unknown
    >;
    const crossTenantGraph = structuredClone(raw) as unknown as PolicyGraphInput;
    delete crossTenantGraph.declaredInputSha256;
    crossTenantGraph.edges[0].tenantId = 'evil-tenant';

    const resInternalMismatch = analyzePolicyGraph(crossTenantGraph);
    assert.equal(resInternalMismatch.status, 'FAILED');
    assert.equal(resInternalMismatch.paths.length, 0);
    assert.ok(
      resInternalMismatch.diagnostics.some((d) => d.code === 'TENANT_MISMATCH')
    );

    const cleanGraph = structuredClone(raw) as unknown as PolicyGraphInput;
    delete cleanGraph.declaredInputSha256;
    const resScopeMismatch = analyzePolicyGraph(cleanGraph, {
      executionScope: {
        tenantId: 'different-tenant',
        principalId: 'user:bob',
        mode: 'LAB',
        allowedFixtures: ['payments-lab/baseline'],
        maxNodes: 500,
        maxDepth: 12,
        maxPaths: 50,
        maxDurationMs: 5000,
        allowProductionExecution: false,
        allowAutoMergeOrDeploy: false,
      },
    });
    assert.equal(resScopeMismatch.status, 'FAILED');
    assert.ok(
      resScopeMismatch.diagnostics.some((d) => d.code === 'TENANT_MISMATCH')
    );
  });

  it('handles cycles safely, checks PII masking, and fails closed when traversal budget is exceeded', () => {
    const cyclicGraph: PolicyGraphInput = {
      schemaVersion: 'chainbreak.graph.v1',
      fixtureId: 'synthetic-cycle-test',
      tenantId: 'tenant-cycle',
      policyVersion: 'v1',
      description: 'Tests cycle safety and PII masking semantics',
      startIdentities: ['identity:agent-a'],
      policies: [
        {
          policyId: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER',
          description: 'No unmasked restricted data external transfer',
          forbiddenTargetClassification: 'RESTRICTED',
          forbiddenDestinationTrustZone: 'EXTERNAL',
          riskRecommendation: 'P1',
          policyVersion: 'v1',
          sourceRef: 'policies/cycle.yaml#L1',
        },
      ],
      nodes: [
        {
          nodeId: 'identity:agent-a',
          kind: 'identity',
          label: 'Agent A',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          roles: [],
          trustZone: 'INTERNAL',
          sourceRef: 'policies/cycle.yaml#L5',
        },
        {
          nodeId: 'service:svc-b',
          kind: 'service',
          label: 'Service B',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          roles: [],
          trustZone: 'INTERNAL',
          sourceRef: 'policies/cycle.yaml#L6',
        },
        {
          nodeId: 'data_asset:pii',
          kind: 'data_asset',
          label: 'PII',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          roles: [],
          dataClassification: 'RESTRICTED',
          trustZone: 'INTERNAL',
          sourceRef: 'policies/cycle.yaml#L7',
        },
        {
          nodeId: 'destination:ext',
          kind: 'destination',
          label: 'External',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          roles: [],
          allowedClassifications: ['PUBLIC'],
          trustZone: 'EXTERNAL',
          sourceRef: 'policies/cycle.yaml#L8',
        },
      ],
      edges: [
        {
          edgeId: 'e1-a-to-b',
          from: 'identity:agent-a',
          to: 'service:svc-b',
          kind: 'can_invoke',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          conditions: { effect: 'ALLOW', active: true },
          sourceRef: 'policies/cycle.yaml#L10',
          policyVersion: 'v1',
          dataClassification: 'RESTRICTED',
        },
        {
          edgeId: 'e2-b-to-a-cycle',
          from: 'service:svc-b',
          to: 'identity:agent-a',
          kind: 'delegates_to',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          conditions: { effect: 'ALLOW', active: true },
          sourceRef: 'policies/cycle.yaml#L11',
          policyVersion: 'v1',
          dataClassification: 'RESTRICTED',
        },
        {
          edgeId: 'e3-b-reads-pii',
          from: 'service:svc-b',
          to: 'data_asset:pii',
          kind: 'can_read',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          conditions: { effect: 'ALLOW', active: true },
          sourceRef: 'policies/cycle.yaml#L12',
          policyVersion: 'v1',
          dataClassification: 'RESTRICTED',
        },
        {
          edgeId: 'e4-b-masked-transfer',
          from: 'service:svc-b',
          to: 'destination:ext',
          kind: 'transfers_data_to',
          tenantId: 'tenant-cycle',
          scope: 'ops',
          conditions: {
            effect: 'ALLOW',
            active: true,
            requiresPiiMasking: true,
            piiMaskingApplied: true,
          },
          sourceRef: 'policies/cycle.yaml#L13',
          policyVersion: 'v1',
          dataClassification: 'RESTRICTED',
        },
      ],
      legitimateOperations: [],
    };

    const maskedResult = analyzePolicyGraph(cyclicGraph);
    assert.equal(maskedResult.status, 'COMPLETED');
    assert.equal(
      maskedResult.paths.length,
      0,
      'Masked transfer + cycle must terminate cleanly with 0 leaked paths'
    );

    // Now test budget exhaustion failing closed as INCONCLUSIVE
    const budgetExhausted = analyzePolicyGraph(cyclicGraph, {
      budget: { maxNodes: 1 },
    });
    assert.equal(budgetExhausted.status, 'INCONCLUSIVE');
    assert.equal(budgetExhausted.budgetStats?.budgetExceeded, true);
    assert.ok(
      budgetExhausted.diagnostics.some((d) => d.code === 'BUDGET_EXCEEDED')
    );
  });
});
