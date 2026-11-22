import assert from 'node:assert/strict';
import * as path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { analyzeFixture } from '../../chainbreak/dist/index.js';
import {
  applyEscalationAndRiskPolicy,
  buildJevAtomicQuestions,
  containsSensitiveMaterial,
  evaluateWithJevJudge,
  LiveTypeSafeJevProvider,
  resolveJevProviderStatus,
  sanitizeStateForJev,
  sha256,
  TypeSafeAPIError,
  TypeSafeClient,
  type JevProvider,
  type TypeSafeClientLike,
} from '../dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../../../fixtures/payments-lab');

const TENANT_A = 'tenant-alpha';
const AUTH_A = { principalId: 'user:alice', tenantId: TENANT_A };
const NOW = '2026-11-11T12:00:00.000Z';

test('Offline mock provider (TYPESAFE_API_KEY absent) transparently labels MOCK + NOT_CONFIGURED across ChainBreak fixtures', async () => {
  const prevKey = process.env.TYPESAFE_API_KEY;
  delete process.env.TYPESAFE_API_KEY;

  try {
    assert.equal(resolveJevProviderStatus(), 'NOT_CONFIGURED');

    const baselineAnalysis = analyzeFixture('payments-lab/baseline', {
      tenantId: TENANT_A,
      fixturesDir: FIXTURES_DIR,
      now: NOW,
    });
    const baselineAdj = await evaluateWithJevJudge({
      analysis: baselineAnalysis,
      authContext: AUTH_A,
      now: NOW,
    });

    assert.equal(baselineAdj.decisionSource, 'MOCK');
    assert.equal(baselineAdj.providerStatus, 'NOT_CONFIGURED');
    assert.equal(baselineAdj.preValidation.passed, true);
    assert.equal(baselineAdj.status, 'ACCEPTED_FOR_TRIAGE');
    assert.equal(baselineAdj.triage, 'likely_irrelevant');
    assert.equal(baselineAdj.riskRecommendation, 'NONE');
    assert.equal(baselineAdj.escalated, false);
    assert.equal(baselineAdj.mergeAllowed, false);
    assert.equal(baselineAdj.deployAllowed, false);
    assert.equal(baselineAdj.exploitConfirmed, false);
    assert.equal(baselineAdj.p0DefinedByJevAlone, false);
    assert.equal(baselineAdj.confidenceOrUncertainty.thresholdCalibrated, false);

    // Unsafe rollout P1 finding MUST escalate to PENDING_REVIEW
    const unsafeAnalysis = analyzeFixture('payments-lab/unsafe-rollout', {
      tenantId: TENANT_A,
      fixturesDir: FIXTURES_DIR,
      now: NOW,
    });
    const unsafeAdj = await evaluateWithJevJudge({
      analysis: unsafeAnalysis,
      authContext: AUTH_A,
      now: NOW,
    });

    assert.equal(unsafeAdj.decisionSource, 'MOCK');
    assert.equal(unsafeAdj.providerStatus, 'NOT_CONFIGURED');
    assert.equal(unsafeAdj.preValidation.passed, true);
    assert.equal(unsafeAdj.triage, 'likely_actionable');
    assert.equal(unsafeAdj.riskRecommendation, 'P1');
    assert.equal(unsafeAdj.status, 'PENDING_REVIEW');
    assert.equal(unsafeAdj.escalated, true);
    assert.equal(unsafeAdj.requiresHumanReview, true);
    assert.equal(unsafeAdj.mergeAllowed, false);
    assert.equal(unsafeAdj.deployAllowed, false);
    assert.equal(unsafeAdj.exploitConfirmed, false);
    assert.equal(unsafeAdj.p0DefinedByJevAlone, false);

    // Remediated returns to clean non-escalated triage
    const remediatedAnalysis = analyzeFixture('payments-lab/remediated', {
      tenantId: TENANT_A,
      fixturesDir: FIXTURES_DIR,
      now: NOW,
    });
    const remediatedAdj = await evaluateWithJevJudge({
      analysis: remediatedAnalysis,
      authContext: AUTH_A,
      now: NOW,
    });
    assert.equal(remediatedAdj.status, 'ACCEPTED_FOR_TRIAGE');
    assert.equal(remediatedAdj.riskRecommendation, 'NONE');
    assert.equal(remediatedAdj.escalated, false);
  } finally {
    if (prevKey !== undefined) {
      process.env.TYPESAFE_API_KEY = prevKey;
    }
  }
});

test('Live TypeSafeClient HTTP wire contract (/v1/systemone) & state secret/code sanitization', async () => {
  const analysis = analyzeFixture('payments-lab/baseline', {
    tenantId: TENANT_A,
    fixturesDir: FIXTURES_DIR,
    now: NOW,
  });

  // Inject sensitive values inside non-verified-critical text/producer fields and verify sanitizer strips them
  const dirtyAnalysis = {
    ...analysis,
    paths: analysis.paths,
    evidence: analysis.evidence.map((ev, idx) =>
      idx === 0
        ? {
            ...ev,
            producer: 'runner AKIAIOSFODNN7EXAMPLE Bearer supersecret123456 C:\\Users\\adm\\secret.ts',
          }
        : ev
    ),
  };

  const sanitized = sanitizeStateForJev(dirtyAnalysis);
  const serialized = JSON.stringify(sanitized.state);
  assert.equal(containsSensitiveMaterial(serialized), false);
  assert.equal(serialized.includes('AKIAIOSFODNN7EXAMPLE'), false);
  assert.equal(serialized.includes('supersecret123456'), false);
  assert.equal(serialized.includes('C:\\Users\\adm'), false);
  assert.ok(sanitized.redactionsApplied >= 3);

  let capturedUrl = '';
  let capturedAuth = '';
  let capturedBody: Record<string, unknown> | undefined;

  const mockFetch: typeof globalThis.fetch = async (url, init) => {
    capturedUrl = String(url);
    const headers = init?.headers as Record<string, string>;
    capturedAuth = headers.Authorization;
    capturedBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(
      JSON.stringify({
        model: 'jev-latest',
        answers: {
          evidence_sufficient: { type: 'noul', noul: 0.95 },
          needs_manual_review: { type: 'noul', noul: 0.08 },
          triage: {
            type: 'choice',
            choice: 'likely_irrelevant',
            confidence: 0.94,
            probabilities: {
              likely_actionable: 0.02,
              needs_more_evidence: 0.04,
              likely_irrelevant: 0.94,
            },
          },
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } }
    );
  };

  const client = new TypeSafeClient({
    apiKey: 'ts_live_unit_test_secret_value',
    baseURL: 'https://api.typesafe.local',
    fetch: mockFetch,
  });

  const liveAdj = await evaluateWithJevJudge({
    analysis: dirtyAnalysis,
    authContext: AUTH_A,
    client,
    now: NOW,
  });

  assert.equal(capturedUrl, 'https://api.typesafe.local/v1/systemone');
  assert.equal(capturedAuth, 'Bearer ts_live_unit_test_secret_value');
  assert.ok(capturedBody);
  assert.equal(capturedBody.model, 'jev-latest');
  const sentJson = JSON.stringify(capturedBody.state);
  assert.equal(sentJson.includes('ts_live_unit_test_secret_value'), false);
  assert.equal(sentJson.includes('AKIAIOSFODNN7EXAMPLE'), false);
  assert.equal(sentJson.includes('C:\\Users\\adm'), false);
  const questions = capturedBody.questions as Record<string, { type: string }>;
  assert.equal(questions.evidence_sufficient.type, 'noul');
  assert.equal(questions.needs_manual_review.type, 'noul');
  assert.equal(questions.triage.type, 'choice');

  assert.equal(liveAdj.decisionSource, 'LIVE');
  assert.equal(liveAdj.providerStatus, 'LIVE');
  assert.equal(liveAdj.status, 'ACCEPTED_FOR_TRIAGE');
  assert.equal(liveAdj.mergeAllowed, false);
  assert.equal(liveAdj.deployAllowed, false);
  assert.equal(liveAdj.exploitConfirmed, false);
});

test('Safety invariant: deterministic pre-validation failure blocks/rejects BEFORE calling JEV even with 99% JEV confidence', async () => {
  const analysis = analyzeFixture('payments-lab/unsafe-rollout', {
    tenantId: TENANT_A,
    fixturesDir: FIXTURES_DIR,
    now: NOW,
  });

  let callCount = 0;
  const spyingClient: TypeSafeClientLike = {
    async systemOne() {
      callCount += 1;
      return {
        model: 'jev-latest',
        answers: {
          evidence_sufficient: { type: 'noul', noul: 0.99 },
          needs_manual_review: { type: 'noul', noul: 0.01 },
          triage: {
            type: 'choice',
            choice: 'likely_irrelevant',
            confidence: 0.99,
            probabilities: {
              likely_actionable: 0.005,
              needs_more_evidence: 0.005,
              likely_irrelevant: 0.99,
            },
          },
        },
      };
    },
  };

  // 1. Unverified evidence -> BLOCKED, JEV NOT invoked
  const unverifiedAnalysis = {
    ...analysis,
    evidence: analysis.evidence.map((ev, i) =>
      i === 0 ? { ...ev, verified: false } : ev
    ),
  };
  const unverifiedRes = await evaluateWithJevJudge({
    analysis: unverifiedAnalysis,
    authContext: AUTH_A,
    client: spyingClient,
    now: NOW,
  });
  assert.equal(unverifiedRes.preValidation.passed, false);
  assert.equal(unverifiedRes.status, 'BLOCKED');
  assert.equal(unverifiedRes.escalated, true);
  assert.equal(unverifiedRes.decisionSource, 'HUMAN_PENDING');
  assert.equal(callCount, 0);

  // 2. Missing sourceRef -> BLOCKED, JEV NOT invoked
  const missingRefAnalysis = {
    ...analysis,
    paths: analysis.paths.map((p) => ({
      ...p,
      edges: p.edges.map((e, idx) => (idx === 0 ? { ...e, sourceRef: 'missing' } : e)),
    })),
  };
  const missingRefRes = await evaluateWithJevJudge({
    analysis: missingRefAnalysis,
    authContext: AUTH_A,
    client: spyingClient,
    now: NOW,
  });
  assert.equal(missingRefRes.preValidation.passed, false);
  assert.equal(missingRefRes.status, 'BLOCKED');
  assert.equal(callCount, 0);

  // 3. Tampered input hash -> REJECTED, JEV NOT invoked
  const tamperedRes = await evaluateWithJevJudge({
    analysis,
    expectedInputSha256: 'f'.repeat(64),
    authContext: AUTH_A,
    client: spyingClient,
    now: NOW,
  });
  assert.equal(tamperedRes.preValidation.passed, false);
  assert.equal(tamperedRes.status, 'REJECTED');
  assert.equal(tamperedRes.escalated, true);
  assert.equal(callCount, 0);

  // 4. Cross-tenant caller -> REJECTED, JEV NOT invoked
  const crossTenantRes = await evaluateWithJevJudge({
    analysis,
    authContext: { principalId: 'user:eve', tenantId: 'tenant-beta' },
    client: spyingClient,
    now: NOW,
  });
  assert.equal(crossTenantRes.preValidation.passed, false);
  assert.equal(crossTenantRes.status, 'REJECTED');
  assert.equal(callCount, 0);

  // 5. Defense-in-depth: even if post-policy receives preValidation.passed=false alongside 99% JEV output, still BLOCKED
  const forcedPost = applyEscalationAndRiskPolicy({
    evaluationId: 'jev-defense-check',
    analysis: unverifiedAnalysis,
    evidence: unverifiedAnalysis.evidence,
    preValidation: unverifiedRes.preValidation,
    sanitizedStateDigest: sha256({ test: true }),
    inference: {
      model: 'jev-latest',
      modelVersion: '1.0',
      answers: {
        evidence_sufficient: { type: 'noul', noul: 0.99 },
        needs_manual_review: { type: 'noul', noul: 0.01 },
        triage: {
          type: 'choice',
          choice: 'likely_irrelevant',
          confidence: 0.99,
          probabilities: { likely_irrelevant: 0.99 },
        },
      },
      decisionSource: 'LIVE',
      providerStatus: 'LIVE',
    },
    providerStatus: 'LIVE',
    config: {
      confidenceThreshold: 0.75,
      evidenceSufficiencyThreshold: 0.75,
      manualReviewThreshold: 0.5,
      escalateOnCriticalRisk: true,
      fallbackOnProviderError: 'HUMAN_PENDING',
    },
    timestamp: NOW,
  });
  assert.equal(forcedPost.status, 'BLOCKED');
  assert.equal(forcedPost.escalated, true);
});

test('Safety invariant: low confidence, contradictory answers, provider outage, and uncalibrated threshold escalate to PENDING_REVIEW', async () => {
  const baseline = analyzeFixture('payments-lab/baseline', {
    tenantId: TENANT_A,
    fixturesDir: FIXTURES_DIR,
    now: NOW,
  });

  // 1. Low confidence (< uncalibrated threshold 0.85) escalates
  const lowConfProvider: JevProvider = new LiveTypeSafeJevProvider({
    async systemOne() {
      return {
        model: 'jev-latest',
        answers: {
          evidence_sufficient: { type: 'noul', noul: 0.9 },
          needs_manual_review: { type: 'noul', noul: 0.1 },
          triage: {
            type: 'choice',
            choice: 'likely_irrelevant',
            confidence: 0.62,
            probabilities: {
              likely_irrelevant: 0.62,
              needs_more_evidence: 0.3,
              likely_actionable: 0.08,
            },
          },
        },
      };
    },
  });
  const lowConfRes = await evaluateWithJevJudge({
    analysis: baseline,
    authContext: AUTH_A,
    provider: lowConfProvider,
    escalationPolicy: { confidenceThreshold: 0.85 },
    now: NOW,
  });
  assert.equal(lowConfRes.status, 'PENDING_REVIEW');
  assert.equal(lowConfRes.escalated, true);
  assert.equal(lowConfRes.requiresHumanReview, true);
  assert.equal(lowConfRes.confidenceOrUncertainty.thresholdCalibrated, false);
  assert.ok(lowConfRes.escalationReasons.some((r) => r.startsWith('LOW_CONFIDENCE')));

  // 2. Contradictory answers (claims likely_irrelevant on PATH_VALIDATED unsafe-rollout)
  const unsafe = analyzeFixture('payments-lab/unsafe-rollout', {
    tenantId: TENANT_A,
    fixturesDir: FIXTURES_DIR,
    now: NOW,
  });
  const p2OnlyAnalysis = {
    ...unsafe,
    paths: unsafe.paths.map((p) => ({ ...p, riskRecommendation: 'P2' as const })),
  };
  const contradictoryProvider: JevProvider = new LiveTypeSafeJevProvider({
    async systemOne() {
      return {
        model: 'jev-latest',
        answers: {
          evidence_sufficient: { type: 'noul', noul: 0.96 },
          needs_manual_review: { type: 'noul', noul: 0.05 },
          triage: {
            type: 'choice',
            choice: 'likely_irrelevant',
            confidence: 0.96,
            probabilities: {
              likely_irrelevant: 0.96,
              likely_actionable: 0.03,
              needs_more_evidence: 0.01,
            },
          },
        },
      };
    },
  });
  const contraRes = await evaluateWithJevJudge({
    analysis: p2OnlyAnalysis,
    authContext: AUTH_A,
    provider: contradictoryProvider,
    now: NOW,
  });
  assert.equal(contraRes.status, 'PENDING_REVIEW');
  assert.equal(contraRes.escalated, true);
  assert.ok(
    contraRes.escalationReasons.some((r) =>
      r.startsWith('CONTRADICTION_IRRELEVANT_VALIDATED_PATH')
    )
  );
  // P2 stays P2, JEV never invents P0 or confirms exploitation
  assert.equal(contraRes.riskRecommendation, 'P2');
  assert.equal(contraRes.p0DefinedByJevAlone, false);
  assert.equal(contraRes.exploitConfirmed, false);

  // 3. Provider error without fallback -> PENDING_REVIEW, HUMAN_PENDING, UNAVAILABLE
  const failingProvider: JevProvider = {
    mode: 'LIVE',
    getStatus: () => 'LIVE',
    async evaluate() {
      throw new Error('upstream timeout');
    },
  };
  const outageRes = await evaluateWithJevJudge({
    analysis: baseline,
    authContext: AUTH_A,
    provider: failingProvider,
    escalationPolicy: { fallbackOnProviderError: 'HUMAN_PENDING' },
    now: NOW,
  });
  assert.equal(outageRes.status, 'PENDING_REVIEW');
  assert.equal(outageRes.escalated, true);
  assert.equal(outageRes.decisionSource, 'HUMAN_PENDING');
  assert.equal(outageRes.providerStatus, 'UNAVAILABLE');
  assert.equal(outageRes.mergeAllowed, false);
  assert.equal(outageRes.deployAllowed, false);

  // Verify buildJevAtomicQuestions exposes the exact 3 atomic questions
  const q = buildJevAtomicQuestions();
  assert.deepEqual(Object.keys(q), [
    'evidence_sufficient',
    'needs_manual_review',
    'triage',
  ]);
});

test('TypeSafeClient redacts secrets from upstream non-OK HTTP error bodies before throwing TypeSafeAPIError', async () => {
  const client = new TypeSafeClient({
    apiKey: 'ts_live_dummy_client_key_999',
    baseURL: 'https://typesafe.invalid',
    fetch: async () =>
      new Response(
        'Upstream auth error: Authorization Bearer top-secret-bearer-token-value and sk-live-secret-1234567890abcdef',
        { status: 502, statusText: 'Bad Gateway' }
      ),
  });

  await assert.rejects(
    async () =>
      client.systemOne({
        state: 'sanitized-state',
        questions: buildJevAtomicQuestions(),
      }),
    (err: unknown) => {
      assert.ok(err instanceof TypeSafeAPIError);
      assert.equal(err.status, 502);
      assert.equal(err.message.includes('top-secret-bearer-token-value'), false);
      assert.equal(err.message.includes('sk-live-secret-1234567890abcdef'), false);
      assert.ok(err.message.includes('[REDACTED'));
      return true;
    }
  );
});
