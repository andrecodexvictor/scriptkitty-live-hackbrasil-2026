/**
 * @file packages/chainbreak/tests/fixtures.test.mts
 * @description End-to-end tests for all 4 synthetic payments-lab fixtures
 * (baseline, unsafe-rollout, remediated, negative-control), allowlists, and tenant binding.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

import {
  analyzeFixture,
  loadFixtureGraph,
  computePolicyGraphSha256,
  validateSecurityAnalysis,
  isAllowedFixtureId,
  ChainBreakError,
} from '../dist/index.js';

describe('Payments Lab Synthetic Fixtures (ChainBreak v0)', () => {
  it('baseline.json returns 0 forbidden paths and preserves all legitimate operations', () => {
    const analysis = analyzeFixture('payments-lab/baseline');

    const schemaCheck = validateSecurityAnalysis(analysis);
    assert.equal(schemaCheck.success, true);

    assert.equal(analysis.schemaVersion, 'security.analysis.v1');
    assert.equal(analysis.mode, 'LAB');
    assert.equal(analysis.productionTested, false);
    assert.equal(analysis.status, 'COMPLETED');
    assert.equal(analysis.paths.length, 0);
    assert.equal(analysis.remediationSpecs.length, 0);
    assert.equal(analysis.legitimateOperationsPreserved, true);
    assert.equal(analysis.legitimateOperations.length, 3);
    assert.ok(
      analysis.legitimateOperations.every((op) => op.preserved === true),
      'All baseline legitimate operations must succeed'
    );

    const raw = loadFixtureGraph('payments-lab/baseline');
    assert.equal(analysis.inputSha256, raw.declaredInputSha256);
    assert.equal(analysis.inputSha256, computePolicyGraphSha256(raw));
    assert.ok(analysis.evidence.every((e) => e.verified === true));
  });

  it('unsafe-rollout.json detects 1 PATH_VALIDATED path on mcp_tool:report-exporter and produces minimal RemediationSpec', () => {
    const analysis = analyzeFixture('payments-lab/unsafe-rollout');

    const schemaCheck = validateSecurityAnalysis(analysis);
    assert.equal(schemaCheck.success, true);

    assert.equal(analysis.status, 'COMPLETED');
    assert.equal(analysis.paths.length, 1);
    assert.equal(analysis.legitimateOperationsPreserved, true);

    const path = analysis.paths[0];
    assert.equal(path.status, 'PATH_VALIDATED');
    assert.notEqual(path.status as string, 'EXPLOIT_CONFIRMED');
    assert.equal(path.startIdentity, 'identity:support-agent');
    assert.equal(path.targetAsset, 'data_asset:customer-payment-pii');
    assert.equal(path.targetDestination, 'destination:external-report-sink');
    assert.equal(path.violatedPolicyId, 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER');
    assert.equal(path.riskRecommendation, 'P1');
    assert.ok(path.evidenceIds.length >= 2);
    assert.ok(path.explanation.includes('PATH_VALIDATED'));
    assert.ok(path.nonTechnicalSummary.length > 20);

    // Ordered edges citing sourceRef
    assert.deepEqual(
      path.edges.map((e) => e.edgeId),
      [
        'e-support-invoke-exporter',
        'e-rollout-exporter-read-pii',
        'e-exporter-transfer-external',
      ]
    );
    assert.ok(path.edges.every((e) => e.sourceRef.trim().length > 0));

    // RemediationSpec proposes minimal edge removal while preserving legitimate operations
    assert.equal(analysis.remediationSpecs.length, 1);
    const rem = analysis.remediationSpecs[0];
    assert.equal(rem.pathId, path.pathId);
    assert.equal(rem.minimalChange, true);
    assert.equal(rem.breaksUnauthorizedPath, true);
    assert.equal(rem.preservesLegitimateOperations, true);
    assert.equal(rem.requiresHumanApproval, true);
    assert.equal(rem.autoApplyAllowed, false);
    assert.equal(rem.actions[0].actionType, 'REMOVE_EDGE');
    assert.equal(rem.actions[0].edgeId, 'e-rollout-exporter-read-pii');
    assert.equal(rem.preservedOperationIds.length, 3);
  });

  it('remediated.json returns 0 forbidden paths and preserves non-sensitive export and payment processing', () => {
    const analysis = analyzeFixture('payments-lab/remediated');

    assert.equal(analysis.status, 'COMPLETED');
    assert.equal(analysis.paths.length, 0);
    assert.equal(analysis.remediationSpecs.length, 0);
    assert.equal(analysis.legitimateOperationsPreserved, true);
    assert.equal(analysis.legitimateOperations.length, 3);
    assert.ok(
      analysis.legitimateOperations.every((op) => op.preserved === true),
      'All legitimate operations must remain preserved after remediation'
    );
  });

  it('negative-control.json returns 0 paths despite incompatible edge types, mismatched scope, and unsatisfied conditions', () => {
    const analysis = analyzeFixture('payments-lab/negative-control');

    assert.equal(analysis.status, 'COMPLETED');
    assert.equal(analysis.paths.length, 0);
    assert.equal(analysis.remediationSpecs.length, 0);
    assert.ok(analysis.evidence.every((e) => e.verified === true));
  });

  it('supports canonical aliases and binds to authenticated tenantId while preserving fixture inputSha256', () => {
    assert.equal(isAllowedFixtureId('payments-lab/unsafe-rollout'), true);
    assert.equal(isAllowedFixtureId('payments-unsafe-rollout'), true);
    assert.equal(isAllowedFixtureId('../secrets'), false);

    const direct = analyzeFixture('unsafe-rollout', {
      now: '2026-11-11T12:00:00.000Z',
    });
    const bound = analyzeFixture('payments-unsafe-rollout', {
      now: '2026-11-11T12:00:00.000Z',
      tenantId: 'tenant-acme',
      executionScope: {
        tenantId: 'tenant-acme',
        principalId: 'user:sec-lead',
        mode: 'LAB',
        allowedFixtures: ['payments-lab/unsafe-rollout'],
        maxNodes: 500,
        maxDepth: 12,
        maxPaths: 50,
        maxDurationMs: 5000,
        allowProductionExecution: false,
        allowAutoMergeOrDeploy: false,
      },
    });

    assert.equal(bound.tenantId, 'tenant-acme');
    assert.equal(bound.inputSha256, direct.inputSha256);
    assert.equal(bound.paths.length, 1);
    assert.equal(bound.paths[0].status, 'PATH_VALIDATED');
    assert.notEqual(bound.analysisId, direct.analysisId);
  });

  it('rejects path traversal and unauthorized fixture IDs fail-closed', () => {
    assert.throws(
      () => analyzeFixture('../../package.json'),
      (err: unknown) =>
        err instanceof ChainBreakError && err.code === 'DISALLOWED_FIXTURE'
    );

    assert.throws(
      () => analyzeFixture('non-existent-fixture'),
      (err: unknown) =>
        err instanceof ChainBreakError && err.code === 'DISALLOWED_FIXTURE'
    );
  });
});
