import assert from 'node:assert/strict';
import * as path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { sha256 } from '../../company-context/dist/index.js';
import type { JevProvider } from '../../jev-judge/dist/index.js';
import { KaliLabRunStore } from '../../kali-mcp-assessment/dist/lab-runner.js';
import {
  ActionEngineError,
  connectSecurityMcpClient,
  createEngine,
  createSecurityActionRuntime,
  defineCapability,
  SECURITY_CAPABILITY_IDS,
  SlidingWindowRateLimiter,
  startMcpHttpServer,
  type AuthPrincipal,
} from '../dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../../../fixtures/payments-lab');

const PRINCIPAL_ALPHA: AuthPrincipal = {
  principalId: 'user:alice',
  tenantId: 'tenant-alpha',
  roles: ['security-analyst'],
  scopes: [
    'security:analyze',
    'security:read',
    'security:judge',
    'security:remediate',
    'security:status',
  ],
};

const PRINCIPAL_BETA: AuthPrincipal = {
  principalId: 'user:bob',
  tenantId: 'tenant-beta',
  roles: ['security-analyst'],
  scopes: [
    'security:analyze',
    'security:read',
    'security:judge',
    'security:remediate',
    'security:status',
  ],
};

const PRINCIPAL_READ_ONLY: AuthPrincipal = {
  principalId: 'user:viewer',
  tenantId: 'tenant-alpha',
  roles: ['viewer'],
  scopes: ['security:read', 'security:status'],
};

const TOKEN_ALPHA = 'sk-token-alpha-secret-value';
const TOKEN_BETA = 'sk-token-beta-secret-value';

test('Direct engine.invoke runs all 5 capabilities with idempotency, budget/cancellation guards, and LAB/safety invariants', async () => {
  const prevKey = process.env.TYPESAFE_API_KEY;
  delete process.env.TYPESAFE_API_KEY;

  const runtime = createSecurityActionRuntime({ fixturesDir: FIXTURES_DIR });

  try {
    // 1. security.status
    const statusRes = await runtime.engine.invoke<{
      mode: string;
      productionTested: boolean;
      HARNESS2_EXPERIMENTS_ENABLED: boolean;
      mergeAllowed: boolean;
      deployAllowed: boolean;
      jevProviderStatus: string;
    }>(
      'security.status',
      {},
      { principal: PRINCIPAL_ALPHA, correlationId: 'corr-status-1' }
    );
    assert.equal(statusRes.mode, 'LAB');
    assert.equal(statusRes.productionTested, false);
    assert.equal(statusRes.HARNESS2_EXPERIMENTS_ENABLED, false);
    assert.equal(statusRes.mergeAllowed, false);
    assert.equal(statusRes.deployAllowed, false);
    assert.equal(statusRes.jevProviderStatus, 'NOT_CONFIGURED');

    // 2. security.chainbreak.analyze on unsafe-rollout + idempotency
    const analyzeFirst = await runtime.engine.invoke<{
      analysisId: string;
      status: string;
      idempotentReplay: boolean;
      analysis: { paths: Array<{ pathId: string; riskRecommendation: string }> };
      mode: string;
      mergeAllowed: boolean;
      deployAllowed: boolean;
    }>(
      'security.chainbreak.analyze',
      { fixtureId: 'payments-lab/unsafe-rollout' },
      { principal: PRINCIPAL_ALPHA, correlationId: 'corr-analyze-1' }
    );
    assert.equal(analyzeFirst.status, 'COMPLETED');
    assert.equal(analyzeFirst.idempotentReplay, false);
    assert.equal(analyzeFirst.mode, 'LAB');
    assert.equal(analyzeFirst.mergeAllowed, false);
    assert.equal(analyzeFirst.deployAllowed, false);
    assert.equal(analyzeFirst.analysis.paths.length, 1);
    const pathId = analyzeFirst.analysis.paths[0].pathId;

    const analyzeReplay = await runtime.engine.invoke<{
      analysisId: string;
      idempotentReplay: boolean;
    }>(
      'security.chainbreak.analyze',
      { fixtureId: 'unsafe-rollout' },
      { principal: PRINCIPAL_ALPHA, correlationId: 'corr-analyze-2' }
    );
    assert.equal(analyzeReplay.idempotentReplay, true);
    assert.equal(analyzeReplay.analysisId, analyzeFirst.analysisId);

    // 3. security.chainbreak.get
    const getRes = await runtime.engine.invoke<{
      analysis: { analysisId: string; tenantId: string };
      evidence: Array<{ verified: boolean }>;
    }>(
      'security.chainbreak.get',
      { analysisId: analyzeFirst.analysisId },
      { principal: PRINCIPAL_ALPHA, correlationId: 'corr-get-1' }
    );
    assert.equal(getRes.analysis.analysisId, analyzeFirst.analysisId);
    assert.equal(getRes.analysis.tenantId, 'tenant-alpha');
    assert.ok(getRes.evidence.length >= 2);
    assert.ok(getRes.evidence.every((e) => e.verified));

    // 4. security.judge.evaluate (P1 -> PENDING_REVIEW, MOCK/NOT_CONFIGURED)
    const evalRes = await runtime.engine.invoke<{
      adjudication: {
        status: string;
        escalated: boolean;
        riskRecommendation: string;
        decisionSource: string;
        providerStatus: string;
        mergeAllowed: boolean;
        deployAllowed: boolean;
        exploitConfirmed: boolean;
      };
    }>(
      'security.judge.evaluate',
      { analysisId: analyzeFirst.analysisId },
      { principal: PRINCIPAL_ALPHA, correlationId: 'corr-eval-1' }
    );
    assert.equal(evalRes.adjudication.status, 'PENDING_REVIEW');
    assert.equal(evalRes.adjudication.escalated, true);
    assert.equal(evalRes.adjudication.riskRecommendation, 'P1');
    assert.equal(evalRes.adjudication.decisionSource, 'MOCK');
    assert.equal(evalRes.adjudication.providerStatus, 'NOT_CONFIGURED');
    assert.equal(evalRes.adjudication.mergeAllowed, false);
    assert.equal(evalRes.adjudication.deployAllowed, false);
    assert.equal(evalRes.adjudication.exploitConfirmed, false);

    // 5. security.remediation.spec
    const remRes = await runtime.engine.invoke<{
      requiresHumanApproval: boolean;
      autoApplyAllowed: boolean;
      remediationSpec: {
        minimalChange: boolean;
        breaksUnauthorizedPath: boolean;
        preservesLegitimateOperations: boolean;
        actions: Array<{ actionType: string; edgeId: string }>;
      };
    }>(
      'security.remediation.spec',
      { analysisId: analyzeFirst.analysisId, pathId },
      { principal: PRINCIPAL_ALPHA, correlationId: 'corr-rem-1' }
    );
    assert.equal(remRes.requiresHumanApproval, true);
    assert.equal(remRes.autoApplyAllowed, false);
    assert.equal(remRes.remediationSpec.minimalChange, true);
    assert.equal(remRes.remediationSpec.breaksUnauthorizedPath, true);
    assert.equal(remRes.remediationSpec.preservesLegitimateOperations, true);
    assert.equal(remRes.remediationSpec.actions[0].edgeId, 'e-rollout-exporter-read-pii');

    // Clean remediated fixture triage returns ACCEPTED_FOR_TRIAGE
    const remAnalyze = await runtime.engine.invoke<{ analysisId: string }>(
      'security.chainbreak.analyze',
      { fixtureId: 'payments-lab/remediated' },
      { principal: PRINCIPAL_ALPHA }
    );
    const remJudge = await runtime.engine.invoke<{
      adjudication: { status: string; escalated: boolean; riskRecommendation: string };
    }>(
      'security.judge.evaluate',
      { analysisId: remAnalyze.analysisId },
      { principal: PRINCIPAL_ALPHA }
    );
    assert.equal(remJudge.adjudication.status, 'ACCEPTED_FOR_TRIAGE');
    assert.equal(remJudge.adjudication.escalated, false);
    assert.equal(remJudge.adjudication.riskRecommendation, 'NONE');

    // Security controls: scope denied, budget exceeded, abort cancelled, tenantId injection denied
    await assert.rejects(
      () =>
        runtime.engine.invoke(
          'security.chainbreak.analyze',
          { fixtureId: 'payments-lab/baseline' },
          { principal: PRINCIPAL_READ_ONLY }
        ),
      (err: unknown) => err instanceof ActionEngineError && err.code === 'FORBIDDEN'
    );

    await assert.rejects(
      () =>
        runtime.engine.invoke(
          'security.chainbreak.analyze',
          { fixtureId: 'payments-lab/baseline' },
          { principal: PRINCIPAL_ALPHA, budget: { maxCostUnits: 2 } }
        ),
      (err: unknown) => err instanceof ActionEngineError && err.code === 'BUDGET_EXCEEDED'
    );

    const aborted = new AbortController();
    aborted.abort();
    await assert.rejects(
      () =>
        runtime.engine.invoke(
          'security.status',
          {},
          { principal: PRINCIPAL_ALPHA, signal: aborted.signal }
        ),
      (err: unknown) => err instanceof ActionEngineError && err.code === 'CANCELLED'
    );

    await assert.rejects(
      () =>
        runtime.engine.invoke(
          'security.chainbreak.analyze',
          { fixtureId: 'payments-lab/baseline', tenantId: 'tenant-beta' },
          { principal: PRINCIPAL_ALPHA }
        ),
      (err: unknown) => err instanceof ActionEngineError && err.code === 'FORBIDDEN'
    );

    // Audit log preserves correlationIds scoped per tenant
    const auditAlpha = runtime.engine.getAuditLog('tenant-alpha');
    assert.ok(auditAlpha.some((e) => e.correlationId === 'corr-eval-1' && e.status === 'SUCCESS'));
  } finally {
    runtime.close();
    if (prevKey !== undefined) {
      process.env.TYPESAFE_API_KEY = prevKey;
    }
  }
});

test('Real MCP Streamable HTTP Server & Client integration: initialize -> tools/list -> tools/call (all 5 tools)', async () => {
  const prevKey = process.env.TYPESAFE_API_KEY;
  delete process.env.TYPESAFE_API_KEY;

  const runtime = createSecurityActionRuntime({ fixturesDir: FIXTURES_DIR });
  const mcpServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    tokens: {
      [TOKEN_ALPHA]: PRINCIPAL_ALPHA,
      [TOKEN_BETA]: PRINCIPAL_BETA,
    },
  });

  const clientAlpha = await connectSecurityMcpClient({
    url: mcpServer.url,
    token: TOKEN_ALPHA,
    origin: `http://127.0.0.1:${mcpServer.port}`,
    correlationId: 'corr-mcp-e2e',
  });

  try {
    assert.ok(clientAlpha.sessionId);

    // 1. tools/list
    const toolsRes = await clientAlpha.listTools();
    const toolNames = toolsRes.tools.map((t) => t.name).sort();
    assert.deepEqual(toolNames, [...SECURITY_CAPABILITY_IDS].sort());
    assert.deepEqual(toolNames, [
      'security.audit.get',
      'security.audit.start',
      'security.chainbreak.analyze',
      'security.chainbreak.get',
      'security.evidence.get',
      'security.judge.evaluate',
      'security.kali.get_run',
      'security.kali.lab_run',
      'security.kali.local_code_scan',
      'security.kali.service_inventory',
      'security.kali.tls_review',
      'security.kali.web_passive_baseline',
      'security.remediation.spec',
      'security.status',
    ]);

    // 2. tools/call -> analyze (unsafe-rollout)
    const analyzeCall = await clientAlpha.callToolJson<{
      analysisId: string;
      status: string;
      analysis: { tenantId: string; paths: Array<{ pathId: string }> };
    }>('security.chainbreak.analyze', {
      fixtureId: 'payments-lab/unsafe-rollout',
    });
    assert.equal(analyzeCall.isError, false);
    assert.equal(analyzeCall.parsed.status, 'COMPLETED');
    assert.equal(analyzeCall.parsed.analysis.tenantId, 'tenant-alpha');
    const analysisId = analyzeCall.parsed.analysisId;
    const pathId = analyzeCall.parsed.analysis.paths[0].pathId;

    // 3. tools/call -> get
    const getCall = await clientAlpha.callToolJson<{
      analysis: { analysisId: string };
      evidence: Array<{ verified: boolean }>;
    }>('security.chainbreak.get', { analysisId });
    assert.equal(getCall.isError, false);
    assert.equal(getCall.parsed.analysis.analysisId, analysisId);
    assert.ok(getCall.parsed.evidence.length >= 2);

    // 4. tools/call -> judge.evaluate
    const judgeCall = await clientAlpha.callToolJson<{
      adjudication: {
        status: string;
        escalated: boolean;
        riskRecommendation: string;
        decisionSource: string;
        providerStatus: string;
        mergeAllowed: boolean;
        deployAllowed: boolean;
      };
    }>('security.judge.evaluate', { analysisId });
    assert.equal(judgeCall.isError, false);
    assert.equal(judgeCall.parsed.adjudication.status, 'PENDING_REVIEW');
    assert.equal(judgeCall.parsed.adjudication.escalated, true);
    assert.equal(judgeCall.parsed.adjudication.riskRecommendation, 'P1');
    assert.equal(judgeCall.parsed.adjudication.decisionSource, 'MOCK');
    assert.equal(judgeCall.parsed.adjudication.providerStatus, 'NOT_CONFIGURED');
    assert.equal(judgeCall.parsed.adjudication.mergeAllowed, false);
    assert.equal(judgeCall.parsed.adjudication.deployAllowed, false);

    // 5. tools/call -> remediation.spec
    const remCall = await clientAlpha.callToolJson<{
      requiresHumanApproval: boolean;
      autoApplyAllowed: boolean;
      remediationSpec: { minimalChange: boolean; breaksUnauthorizedPath: boolean };
    }>('security.remediation.spec', { analysisId, pathId });
    assert.equal(remCall.isError, false);
    assert.equal(remCall.parsed.requiresHumanApproval, true);
    assert.equal(remCall.parsed.autoApplyAllowed, false);
    assert.equal(remCall.parsed.remediationSpec.minimalChange, true);
    assert.equal(remCall.parsed.remediationSpec.breaksUnauthorizedPath, true);

    // 6. tools/call -> status
    const statusCall = await clientAlpha.callToolJson<{
      mode: string;
      HARNESS2_EXPERIMENTS_ENABLED: boolean;
      jevProviderStatus: string;
    }>('security.status', {});
    assert.equal(statusCall.isError, false);
    assert.equal(statusCall.parsed.mode, 'LAB');
    assert.equal(statusCall.parsed.HARNESS2_EXPERIMENTS_ENABLED, false);
    assert.equal(statusCall.parsed.jevProviderStatus, 'NOT_CONFIGURED');

    // Audit log proves single path execution from mcp-http
    const audit = runtime.engine.getAuditLog('tenant-alpha');
    assert.ok(audit.filter((e) => e.source === 'mcp-http' && e.status === 'SUCCESS').length >= 5);
    // Ensure bearer token never leaks into audit logs
    assert.equal(JSON.stringify(audit).includes(TOKEN_ALPHA), false);

    // Cross-tenant client fails closed on alpha's analysisId
    const clientBeta = await connectSecurityMcpClient({
      url: mcpServer.url,
      token: TOKEN_BETA,
      origin: `http://127.0.0.1:${mcpServer.port}`,
    });
    try {
      const crossGet = await clientBeta.callToolJson<{ code: string }>(
        'security.chainbreak.get',
        { analysisId }
      );
      assert.equal(crossGet.isError, true);
      assert.equal(crossGet.parsed.code, 'FORBIDDEN');

      const crossEval = await clientBeta.callToolJson<{ code: string }>(
        'security.judge.evaluate',
        { analysisId }
      );
      assert.equal(crossEval.isError, true);
      assert.equal(crossEval.parsed.code, 'FORBIDDEN');

      const crossRem = await clientBeta.callToolJson<{ code: string }>(
        'security.remediation.spec',
        { analysisId, pathId }
      );
      assert.equal(crossRem.isError, true);
      assert.equal(crossRem.parsed.code, 'FORBIDDEN');

      // Malformed / traversal fixtureId rejected
      const badFixture = await clientBeta.callToolJson<{ code: string }>(
        'security.chainbreak.analyze',
        { fixtureId: '../../etc/passwd' }
      );
      assert.equal(badFixture.isError, true);
      assert.equal(badFixture.parsed.code, 'INPUT_INVALID');

      // Injected tenantId inside payload rejected
      const forgedTenant = await clientBeta.callToolJson<{ code: string }>(
        'security.chainbreak.analyze',
        { fixtureId: 'payments-lab/baseline', tenantId: 'tenant-alpha' }
      );
      assert.equal(forgedTenant.isError, true);
      assert.equal(forgedTenant.parsed.code, 'FORBIDDEN');
    } finally {
      await clientBeta.close();
    }
  } finally {
    await clientAlpha.close();
    await mcpServer.close();
    runtime.close();
    if (prevKey !== undefined) {
      process.env.TYPESAFE_API_KEY = prevKey;
    }
  }
});

test('Negative HTTP & JEV invariants: bad token (401), forbidden Origin (403), session hijack (403), size limit (413), rate limit (429), unverified evidence (BLOCKED)', async () => {
  let jevCallCount = 0;
  const spyingProvider: JevProvider = {
    mode: 'LIVE',
    getStatus: () => 'LIVE',
    async evaluate() {
      jevCallCount += 1;
      throw new Error('Should not be called on unverified evidence');
    },
  };

  const runtime = createSecurityActionRuntime({
    fixturesDir: FIXTURES_DIR,
    jevProvider: spyingProvider,
  });

  // 1. Unverified evidence saved in tenant-alpha must BLOCK before JEV is invoked
  const unverifiedAnalysisId = 'cb-unverified-neg-1';
  const unverifiedCreatedAt = '2026-11-11T12:00:00.000Z';
  const evHash = sha256({ kind: 'POLICY_SNAPSHOT', unverified: true });
  runtime.store.saveAnalysis('tenant-alpha', {
    schemaVersion: 'security.analysis.v1',
    analysisId: unverifiedAnalysisId,
    tenantId: 'tenant-alpha',
    fixtureId: 'payments-lab/baseline',
    policyVersion: '2026-11-11.1',
    mode: 'LAB',
    paths: [],
    evidenceIds: ['ev-unverified-1'],
    evidence: [
      {
        evidenceId: 'ev-unverified-1',
        analysisId: unverifiedAnalysisId,
        kind: 'POLICY_SNAPSHOT',
        sourceRef: 'policy/payments.json',
        contentSha256: evHash,
        producer: 'test',
        createdAt: unverifiedCreatedAt,
        verified: false,
      },
    ],
    remediationSpecs: [],
    legitimateOperations: [],
    legitimateOperationsPreserved: true,
    startedAt: unverifiedCreatedAt,
    completedAt: unverifiedCreatedAt,
    status: 'COMPLETED',
    inputSha256: sha256({ unverifiedAnalysisId }),
    source: 'DETERMINISTIC_LAB_ANALYSIS',
    productionTested: false,
    diagnostics: [],
  });

  // Non-loopback host binding refused
  await assert.rejects(
    () => startMcpHttpServer(runtime.engine, { host: '0.0.0.0', tokens: { [TOKEN_ALPHA]: PRINCIPAL_ALPHA } }),
    /loopback/i
  );

  const mcpServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    maxRequestBodyBytes: 4096,
    rateLimit: { maxRequests: 10, windowMs: 10_000 },
    tokens: {
      [TOKEN_ALPHA]: PRINCIPAL_ALPHA,
      [TOKEN_BETA]: PRINCIPAL_BETA,
    },
  });

  try {
    // Missing / invalid Bearer token -> 401
    const noAuthRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
    assert.equal(noAuthRes.status, 401);

    const badAuthRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer wrong-token',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
    assert.equal(badAuthRes.status, 401);

    // Forbidden Origin -> 403
    const badOriginRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TOKEN_ALPHA}`,
        Origin: 'https://evil.attacker.example',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
    assert.equal(badOriginRes.status, 403);

    // Request exceeding maxRequestBodyBytes -> 413
    const hugeBody = JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: { pad: 'x'.repeat(5000) },
    });
    const tooLargeRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TOKEN_ALPHA}`,
      },
      body: hugeBody,
    });
    assert.equal(tooLargeRes.status, 413);

    // Test unverified evidence via MCP client (uses rate limit slots gently; separate beta vs alpha)
    const clientAlpha = await connectSecurityMcpClient({
      url: mcpServer.url,
      token: TOKEN_ALPHA,
      origin: `http://127.0.0.1:${mcpServer.port}`,
    });
    try {
      const blockedEval = await clientAlpha.callToolJson<{
        adjudication: {
          status: string;
          escalated: boolean;
          preValidation: { passed: boolean };
          decisionSource: string;
        };
      }>('security.judge.evaluate', { analysisId: unverifiedAnalysisId });
      assert.equal(blockedEval.isError, false);
      assert.equal(blockedEval.parsed.adjudication.preValidation.passed, false);
      assert.equal(blockedEval.parsed.adjudication.status, 'BLOCKED');
      assert.equal(blockedEval.parsed.adjudication.escalated, true);
      assert.equal(blockedEval.parsed.adjudication.decisionSource, 'HUMAN_PENDING');
      assert.equal(jevCallCount, 0);

      // Session hijacking by another tenant/principal using Alpha's Mcp-Session-Id -> 403
      const hijackRes = await fetch(mcpServer.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: `Bearer ${TOKEN_BETA}`,
          'Mcp-Session-Id': clientAlpha.sessionId!,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} }),
      });
      assert.equal(hijackRes.status, 403);
    } finally {
      await clientAlpha.close();
    }

    // Rate limit enforcement (TOKEN_BETA gets 10 requests allowed within window, exceeding -> 429)
    let got429 = false;
    for (let i = 0; i < 15; i++) {
      const rlRes = await fetch(mcpServer.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: `Bearer ${TOKEN_BETA}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 100 + i, method: 'tools/list', params: {} }),
      });
      if (rlRes.status === 429) {
        got429 = true;
        break;
      }
    }
    assert.equal(got429, true);
  } finally {
    await mcpServer.close();
    runtime.close();
  }
});

test('Browser-ready fail-closed loopback CORS: OPTIONS preflight, POST initialize/tools/call, disallowed Origin 403, missing Bearer 401', async () => {
  const runtime = createSecurityActionRuntime({ fixturesDir: FIXTURES_DIR });
  const mcpServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    allowedOrigins: ['http://127.0.0.1:5173', 'http://localhost:5173'],
    tokens: {
      [TOKEN_ALPHA]: PRINCIPAL_ALPHA,
    },
  });

  try {
    // 1. Allowed loopback OPTIONS preflight (no Bearer token, per Fetch/CORS spec)
    const preflightOk = await fetch(mcpServer.url, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://127.0.0.1:5173',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers':
          'authorization, content-type, mcp-session-id, x-correlation-id',
      },
    });
    assert.equal(preflightOk.status, 204);
    assert.equal(
      preflightOk.headers.get('access-control-allow-origin'),
      'http://127.0.0.1:5173'
    );
    assert.equal(preflightOk.headers.get('vary'), 'Origin');
    assert.equal(
      preflightOk.headers.get('access-control-allow-methods'),
      'POST, GET, DELETE, OPTIONS'
    );
    const allowHeaders =
      preflightOk.headers.get('access-control-allow-headers') ?? '';
    for (const requiredHeader of [
      'Content-Type',
      'Authorization',
      'Mcp-Session-Id',
      'Accept',
      'X-Correlation-Id',
    ]) {
      assert.ok(
        allowHeaders.toLowerCase().includes(requiredHeader.toLowerCase()),
        `Expected Access-Control-Allow-Headers to include ${requiredHeader}, got '${allowHeaders}'`
      );
    }
    assert.equal(
      preflightOk.headers.get('access-control-expose-headers'),
      'Mcp-Session-Id'
    );

    // 2. Alternate allowlisted loopback origin (localhost:5173) echoes strictly that origin
    const preflightLocalhost = await fetch(mcpServer.url, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:5173',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.equal(preflightLocalhost.status, 204);
    assert.equal(
      preflightLocalhost.headers.get('access-control-allow-origin'),
      'http://localhost:5173'
    );

    // 3. Disallowed Origin on OPTIONS preflight -> 403 and NO ACAO header
    const preflightEvil = await fetch(mcpServer.url, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil.attacker.example',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.equal(preflightEvil.status, 403);
    assert.equal(preflightEvil.headers.get('access-control-allow-origin'), null);

    // 4. Missing Origin on OPTIONS preflight -> 403 and NO ACAO header
    const preflightNoOrigin = await fetch(mcpServer.url, {
      method: 'OPTIONS',
    });
    assert.equal(preflightNoOrigin.status, 403);
    assert.equal(
      preflightNoOrigin.headers.get('access-control-allow-origin'),
      null
    );

    // 5. Allowed Origin on POST without Bearer token -> 401 (with echoed ACAO so browser sees 401)
    const unauthCors = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        Origin: 'http://127.0.0.1:5173',
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {},
      }),
    });
    assert.equal(unauthCors.status, 401);
    assert.equal(
      unauthCors.headers.get('access-control-allow-origin'),
      'http://127.0.0.1:5173'
    );

    // 6. Disallowed Origin on POST even with valid Bearer token -> 403 and NO ACAO
    const evilPost = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        Origin: 'https://evil.attacker.example',
        Authorization: `Bearer ${TOKEN_ALPHA}`,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      }),
    });
    assert.equal(evilPost.status, 403);
    assert.equal(evilPost.headers.get('access-control-allow-origin'), null);

    // 7. Authenticated POST initialize -> tools/call (security.status) with allowed Origin
    const initRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        Origin: 'http://127.0.0.1:5173',
        Authorization: `Bearer ${TOKEN_ALPHA}`,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'X-Correlation-Id': 'corr-browser-cors-1',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 10,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'browser-cors-test', version: '0.1.0' },
        },
      }),
    });
    assert.equal(initRes.status, 200);
    assert.equal(
      initRes.headers.get('access-control-allow-origin'),
      'http://127.0.0.1:5173'
    );
    assert.equal(
      initRes.headers.get('access-control-expose-headers'),
      'Mcp-Session-Id'
    );
    const sessionId = initRes.headers.get('mcp-session-id');
    assert.ok(sessionId && sessionId.length > 0);

    const statusRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        Origin: 'http://127.0.0.1:5173',
        Authorization: `Bearer ${TOKEN_ALPHA}`,
        'Mcp-Session-Id': sessionId,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'X-Correlation-Id': 'corr-browser-cors-2',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 11,
        method: 'tools/call',
        params: { name: 'security.status', arguments: {} },
      }),
    });
    assert.equal(statusRes.status, 200);
    assert.equal(
      statusRes.headers.get('access-control-allow-origin'),
      'http://127.0.0.1:5173'
    );
    const statusPayload = (await statusRes.json()) as {
      result?: { structuredContent?: { mode?: string; mergeAllowed?: boolean } };
    };
    assert.equal(statusPayload.result?.structuredContent?.mode, 'LAB');
    assert.equal(statusPayload.result?.structuredContent?.mergeAllowed, false);

    // 8. Non-browser POST without Origin header does NOT leak Access-Control-Allow-Origin
    const noOriginPost = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${TOKEN_ALPHA}`,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 12,
        method: 'tools/list',
        params: {},
      }),
    });
    assert.equal(noOriginPost.status, 200);
    assert.equal(noOriginPost.headers.get('access-control-allow-origin'), null);
  } finally {
    await mcpServer.close();
    runtime.close();
  }
});

test('E3 & E4 Expanded MCP Toolset: security.audit.{start,get}, security.evidence.get, and security.kali.{lab_run,service_inventory,tls_review,web_passive_baseline,local_code_scan,get_run} with cross-tenant FORBIDDEN, out-of-scope, and flag-injection fail-closed guards', async () => {
  const prevKey = process.env.TYPESAFE_API_KEY;
  delete process.env.TYPESAFE_API_KEY;

  const runtime = createSecurityActionRuntime({ fixturesDir: FIXTURES_DIR });
  const mcpServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    tokens: {
      [TOKEN_ALPHA]: PRINCIPAL_ALPHA,
      [TOKEN_BETA]: PRINCIPAL_BETA,
    },
  });

  const clientAlpha = await connectSecurityMcpClient({
    url: mcpServer.url,
    token: TOKEN_ALPHA,
    origin: `http://127.0.0.1:${mcpServer.port}`,
    correlationId: 'corr-e3-e4-alpha',
  });
  const clientBeta = await connectSecurityMcpClient({
    url: mcpServer.url,
    token: TOKEN_BETA,
    origin: `http://127.0.0.1:${mcpServer.port}`,
    correlationId: 'corr-e3-e4-beta',
  });

  try {
    // 1. security.audit.start & security.audit.get + security.evidence.get
    const auditStart = await clientAlpha.callToolJson<{
      auditId: string;
      analysisId: string;
      tenantId: string;
      status: string;
      redacted: boolean;
      findingCount: number;
      evidenceIds: string[];
      adjudication: { status: string; providerStatus: string; requiresHumanReview: boolean };
      mode: string;
      productionTested: boolean;
      mergeAllowed: boolean;
      deployAllowed: boolean;
      externalExecution: boolean;
    }>('security.audit.start', {
      fixtureId: 'payments-lab/unsafe-rollout',
    });
    assert.equal(auditStart.isError, false);
    assert.equal(auditStart.parsed.status, 'COMPLETED');
    assert.equal(auditStart.parsed.tenantId, 'tenant-alpha');
    assert.equal(auditStart.parsed.redacted, true);
    assert.equal(auditStart.parsed.findingCount, 1);
    assert.equal(auditStart.parsed.mode, 'LAB');
    assert.equal(auditStart.parsed.productionTested, false);
    assert.equal(auditStart.parsed.mergeAllowed, false);
    assert.equal(auditStart.parsed.deployAllowed, false);
    assert.equal(auditStart.parsed.externalExecution, false);
    assert.equal(auditStart.parsed.adjudication.providerStatus, 'NOT_CONFIGURED');
    assert.equal(auditStart.parsed.adjudication.status, 'PENDING_REVIEW');
    assert.equal(auditStart.parsed.adjudication.requiresHumanReview, true);

    const auditGet = await clientAlpha.callToolJson<{
      auditId: string;
      analysisId: string;
      tenantId: string;
      redacted: boolean;
    }>('security.audit.get', {
      auditId: auditStart.parsed.auditId,
    });
    assert.equal(auditGet.isError, false);
    assert.equal(auditGet.parsed.auditId, auditStart.parsed.auditId);
    assert.equal(auditGet.parsed.analysisId, auditStart.parsed.analysisId);
    assert.equal(auditGet.parsed.tenantId, 'tenant-alpha');
    assert.equal(auditGet.parsed.redacted, true);

    const firstEvidenceId = auditStart.parsed.evidenceIds[0];
    const evidenceGet = await clientAlpha.callToolJson<{
      tenantId: string;
      analysisId: string;
      evidenceId: string;
      redacted: boolean;
      verified: boolean;
      evidence: Array<{ evidenceId: string }>;
    }>('security.evidence.get', {
      evidenceId: firstEvidenceId,
    });
    assert.equal(evidenceGet.isError, false);
    assert.equal(evidenceGet.parsed.tenantId, 'tenant-alpha');
    assert.equal(evidenceGet.parsed.evidenceId, firstEvidenceId);
    assert.equal(evidenceGet.parsed.redacted, true);
    assert.equal(evidenceGet.parsed.verified, true);
    assert.equal(evidenceGet.parsed.evidence.length, 1);

    // Cross-tenant security.audit.get & security.evidence.get fail closed with FORBIDDEN
    const crossAuditGet = await clientBeta.callToolJson<{ code: string }>(
      'security.audit.get',
      { auditId: auditStart.parsed.auditId }
    );
    assert.equal(crossAuditGet.isError, true);
    assert.equal(crossAuditGet.parsed.code, 'FORBIDDEN');

    const crossEvGet = await clientBeta.callToolJson<{ code: string }>(
      'security.evidence.get',
      { evidenceId: firstEvidenceId }
    );
    assert.equal(crossEvGet.isError, true);
    assert.equal(crossEvGet.parsed.code, 'FORBIDDEN');

    // 2. Enumerated Kali LAB_SYNTHETIC tools over MCP HTTP
    const labRun = await clientAlpha.callToolJson<{
      ok: boolean;
      runId: string;
      tenantId: string;
      actionId: string;
      profile: string;
      mode: string;
      executionMode: string;
      redacted: boolean;
      productionTested: boolean;
      mergeAllowed: boolean;
      deployAllowed: boolean;
      externalExecution: boolean;
      argv: string[];
      findings: Array<{ finding_id: string }>;
    }>('security.kali.lab_run', {
      actionId: 'service_inventory',
      scopeRef: 'SK-SCOPE-LAB-SYNTHETIC-001',
      targetRef: '127.0.0.1',
      budgetRef: 'LAB_DEFAULT_BUDGET',
    });
    assert.equal(labRun.isError, false);
    assert.equal(labRun.parsed.ok, true);
    assert.equal(labRun.parsed.tenantId, 'tenant-alpha');
    assert.equal(labRun.parsed.actionId, 'service_inventory');
    assert.equal(labRun.parsed.profile, 'LAB_SYNTHETIC');
    assert.equal(labRun.parsed.mode, 'LAB');
    assert.equal(labRun.parsed.executionMode, 'LAB_SYNTHETIC');
    assert.equal(labRun.parsed.redacted, true);
    assert.equal(labRun.parsed.productionTested, false);
    assert.equal(labRun.parsed.mergeAllowed, false);
    assert.equal(labRun.parsed.deployAllowed, false);
    assert.equal(labRun.parsed.externalExecution, false);
    assert.ok(labRun.parsed.argv.includes('--'));

    const serviceInv = await clientAlpha.callToolJson<{ runId: string; profile: string }>(
      'security.kali.service_inventory',
      { targetRef: '127.0.0.1', scopeRef: 'SK-SCOPE-LAB-001' }
    );
    assert.equal(serviceInv.isError, false);
    assert.equal(serviceInv.parsed.profile, 'LAB_SYNTHETIC');

    const tlsRev = await clientAlpha.callToolJson<{ runId: string; profile: string }>(
      'security.kali.tls_review',
      { targetRef: '127.0.0.1:443', scopeRef: 'SK-SCOPE-LAB-001' }
    );
    assert.equal(tlsRev.isError, false);
    assert.equal(tlsRev.parsed.profile, 'LAB_SYNTHETIC');

    const webBase = await clientAlpha.callToolJson<{ runId: string; profile: string }>(
      'security.kali.web_passive_baseline',
      { targetRef: '127.0.0.1:3000', scopeRef: 'SK-SCOPE-LAB-001' }
    );
    assert.equal(webBase.isError, false);
    assert.equal(webBase.parsed.profile, 'LAB_SYNTHETIC');

    const localScan = await clientAlpha.callToolJson<{
      runId: string;
      profile: string;
      networkMode: string;
    }>('security.kali.local_code_scan', {
      targetRef: 'package.json',
      scopeRef: 'SK-SCOPE-LAB-001',
    });
    assert.equal(localScan.isError, false);
    assert.equal(localScan.parsed.profile, 'LAB_SYNTHETIC');
    assert.equal(localScan.parsed.networkMode, 'airgapped');

    // Same-tenant security.kali.get_run succeeds
    const getRunOk = await clientAlpha.callToolJson<{
      runId: string;
      tenantId: string;
      redacted: boolean;
    }>('security.kali.get_run', {
      runId: labRun.parsed.runId,
    });
    assert.equal(getRunOk.isError, false);
    assert.equal(getRunOk.parsed.runId, labRun.parsed.runId);
    assert.equal(getRunOk.parsed.tenantId, 'tenant-alpha');
    assert.equal(getRunOk.parsed.redacted, true);

    // Cross-tenant security.kali.get_run fails closed with FORBIDDEN
    const crossGetRun = await clientBeta.callToolJson<{ code: string }>(
      'security.kali.get_run',
      { runId: labRun.parsed.runId }
    );
    assert.equal(crossGetRun.isError, true);
    assert.equal(crossGetRun.parsed.code, 'FORBIDDEN');

    // 3. Negative Kali security checks over MCP HTTP: out-of-scope (evil.example, 169.254.169.254) & flag injection (--script=..., $(id))
    const evilDomainCall = await clientAlpha.callToolJson<{ code: string; message: string }>(
      'security.kali.lab_run',
      {
        actionId: 'service_inventory',
        scopeRef: 'SK-SCOPE-LAB-001',
        targetRef: 'evil.example',
      }
    );
    assert.equal(evilDomainCall.isError, true);
    assert.equal(evilDomainCall.parsed.code, 'FORBIDDEN');

    const metadataCall = await clientAlpha.callToolJson<{ code: string; message: string }>(
      'security.kali.service_inventory',
      {
        scopeRef: 'SK-SCOPE-LAB-001',
        targetRef: '169.254.169.254',
      }
    );
    assert.equal(metadataCall.isError, true);
    assert.equal(metadataCall.parsed.code, 'FORBIDDEN');

    const flagInjectCall = await clientAlpha.callToolJson<{ code: string; message: string }>(
      'security.kali.lab_run',
      {
        actionId: 'service_inventory',
        scopeRef: 'SK-SCOPE-LAB-001',
        targetRef: '--script=vuln',
      }
    );
    assert.equal(flagInjectCall.isError, true);
    assert.equal(flagInjectCall.parsed.code, 'INPUT_INVALID');

    const shellInjectCall = await clientAlpha.callToolJson<{ code: string; message: string }>(
      'security.kali.tls_review',
      {
        scopeRef: 'SK-SCOPE-LAB-001',
        targetRef: '$(id)',
      }
    );
    assert.equal(shellInjectCall.isError, true);
    assert.equal(shellInjectCall.parsed.code, 'INPUT_INVALID');
  } finally {
    await clientAlpha.close();
    await clientBeta.close();
    await mcpServer.close();
    runtime.close();
    if (prevKey !== undefined) {
      process.env.TYPESAFE_API_KEY = prevKey;
    }
  }
});

test('E3/E4 HTTP hardening: pre-auth 429 + Retry-After before token verification, post-auth 429, and multi-token constant-time auth', async () => {
  const runtime = createSecurityActionRuntime({ fixturesDir: FIXTURES_DIR });
  let authVerifyCount = 0;

  const preAuthServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    authRateLimit: { maxRequests: 3, windowMs: 60_000 },
    rateLimit: { maxRequests: 50, windowMs: 60_000 },
    authenticateToken: async (token) => {
      authVerifyCount += 1;
      return token === 'valid-alpha-secret-token' ? PRINCIPAL_ALPHA : null;
    },
  });

  const postAuthServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    authRateLimit: { maxRequests: 50, windowMs: 60_000 },
    rateLimit: { maxRequests: 2, windowMs: 60_000 },
    tokens: {
      'short-tok': PRINCIPAL_BETA,
      'much-longer-valid-alpha-token-0123456789': PRINCIPAL_ALPHA,
      'another-unrelated-token-xyz': PRINCIPAL_BETA,
    },
  });

  try {
    const rpcBody = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {},
    });

    // 1. First 3 invalid auth attempts return 401 and invoke authenticateToken
    for (let i = 0; i < 3; i += 1) {
      const badRes = await fetch(preAuthServer.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: `Bearer bad-attempt-${i}`,
        },
        body: rpcBody,
      });
      assert.equal(badRes.status, 401);
      await badRes.text();
    }
    assert.equal(authVerifyCount, 3);

    // 2. 4th request from same IP fails BEFORE authenticateToken with HTTP 429 + Retry-After
    const throttledPreAuth = await fetch(preAuthServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer valid-alpha-secret-token',
      },
      body: rpcBody,
    });
    assert.equal(throttledPreAuth.status, 429);
    const preRetryAfter = Number(throttledPreAuth.headers.get('retry-after'));
    assert.ok(Number.isFinite(preRetryAfter) && preRetryAfter >= 1);
    assert.equal(
      authVerifyCount,
      3,
      'Pre-auth rate limit must short-circuit before invoking authenticateToken'
    );

    // 3. Multi-token constant-time auth works with varying lengths & triggers post-auth 429 on burst
    const badMultiRes = await fetch(postAuthServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer wrong-token-that-never-leaks',
      },
      body: rpcBody,
    });
    assert.equal(badMultiRes.status, 401);
    const badMultiBody = await badMultiRes.text();
    assert.equal(badMultiBody.includes('wrong-token-that-never-leaks'), false);
    assert.equal(badMultiBody.includes('short-tok'), false);

    for (let i = 0; i < 2; i += 1) {
      const okRes = await fetch(postAuthServer.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: 'Bearer much-longer-valid-alpha-token-0123456789',
        },
        body: rpcBody,
      });
      assert.equal(okRes.status, 200);
      await okRes.text();
    }

    const throttledPostAuth = await fetch(postAuthServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer much-longer-valid-alpha-token-0123456789',
      },
      body: rpcBody,
    });
    assert.equal(throttledPostAuth.status, 429);
    const postRetryAfter = Number(throttledPostAuth.headers.get('retry-after'));
    assert.ok(Number.isFinite(postRetryAfter) && postRetryAfter >= 1);
  } finally {
    await preAuthServer.close();
    await postAuthServer.close();
    runtime.close();
  }
});

test('E3/E4 GC & session TTL: idle MCP sessions evict with 404, rate-limit buckets prune, and KaliLabRunStore bounds growth', async () => {
  const runtime = createSecurityActionRuntime({ fixturesDir: FIXTURES_DIR });
  const mcpServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    sessionTtlMs: 90,
    cleanupIntervalMs: 30,
    rateLimit: { maxRequests: 10, windowMs: 90 },
    authRateLimit: { maxRequests: 10, windowMs: 90 },
    tokens: { 'ttl-test-token': PRINCIPAL_ALPHA },
  });

  try {
    // Seed an auth-rate-limit bucket via one bad request
    const badRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer bad-token',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
    assert.equal(badRes.status, 401);
    await badRes.text();

    // Open a stateful MCP session via initialize
    const initRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer ttl-test-token',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'initialize',
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'ttl-test', version: '1.0.0' },
        },
      }),
    });
    assert.equal(initRes.status, 200);
    const sessionId = initRes.headers.get('mcp-session-id');
    assert.ok(sessionId && sessionId.length > 0);
    await initRes.text();

    const statsBefore = mcpServer.getStats();
    assert.equal(statsBefore.activeSessions, 1);
    assert.ok(statsBefore.rateLimitBuckets >= 1);
    assert.ok(statsBefore.authRateLimitBuckets >= 1);

    const preflightRes = await fetch(mcpServer.url, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://127.0.0.1:5173',
        'Access-Control-Request-Method': 'DELETE',
      },
    });
    assert.equal(preflightRes.status, 204);
    assert.equal(
      preflightRes.headers.get('access-control-allow-methods'),
      'POST, GET, DELETE, OPTIONS'
    );
    assert.equal(mcpServer.server.headersTimeout, 10_000);
    assert.equal(mcpServer.server.requestTimeout, 30_000);

    // Wait past TTL + cleanup interval so background reaper evicts idle session and expired buckets
    await new Promise((resolve) => setTimeout(resolve, 200));

    const statsAfter = mcpServer.getStats();
    assert.equal(statsAfter.activeSessions, 0);
    assert.equal(statsAfter.rateLimitBuckets, 0);
    assert.equal(statsAfter.authRateLimitBuckets, 0);

    // Reusing the expired session ID must return 404
    const expiredSessionRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer ttl-test-token',
        'Mcp-Session-Id': sessionId,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }),
    });
    assert.equal(expiredSessionRes.status, 404);
    await expiredSessionRes.text();
  } finally {
    await mcpServer.close();
    runtime.close();
  }

  // Unit check for SlidingWindowRateLimiter maxBuckets cap & KaliLabRunStore FIFO cap
  const limiter = new SlidingWindowRateLimiter(5, 100, 2);
  assert.equal(limiter.checkAndConsume('k1', 1000).allowed, true);
  assert.equal(limiter.checkAndConsume('k2', 1001).allowed, true);
  assert.equal(limiter.checkAndConsume('k3', 1002).allowed, true);
  assert.equal(limiter.bucketCount, 2);
  assert.equal(limiter.prune(1200), 2);
  assert.equal(limiter.bucketCount, 0);

  const boundedStore = new KaliLabRunStore(2);
  for (const idx of [1, 2, 3]) {
    boundedStore.saveRun('tenant-alpha', {
      runId: `run-${idx}`,
      tenantId: 'tenant-alpha',
      principalId: 'user:alice',
      actionId: 'service_inventory',
      profile: 'LAB_SYNTHETIC',
      mode: 'LAB',
      executionMode: 'LAB_SYNTHETIC',
      scopeId: 'SK-SCOPE-LAB-001',
      target: '127.0.0.1:8080',
      networkMode: 'localhost-only',
      argv: ['nmap', '--', '127.0.0.1'],
      redacted: true,
      budgetRemainingMs: 1000,
      startedAtUtc: '2026-01-01T00:00:00.000Z',
      completedAtUtc: '2026-01-01T00:00:01.000Z',
      summary: { totalChecks: 1, passed: 1, findingCount: 0, riskScore: 0 },
      findings: [],
      evidence: [],
      custody: {
        custody_standard: 'RFC8785_SHA256_MERKLE',
        merkle_root: 'a'.repeat(64),
        evidence_count: 0,
      },
      productionTested: false,
      mergeAllowed: false,
      deployAllowed: false,
      externalExecution: false,
    });
  }
  assert.throws(
    () => boundedStore.getRun('tenant-alpha', 'run-1'),
    /not found/i
  );
  assert.equal(boundedStore.getRun('tenant-alpha', 'run-3').runId, 'run-3');
});

test('Concurrency hardening: 50 parallel MCP requests (idempotent DB writes + cross-tenant checks), HTTP 503 backpressure, and timeout rejection hygiene', async () => {
  const runtime = createSecurityActionRuntime({ fixturesDir: FIXTURES_DIR });
  const mcpServer = await startMcpHttpServer(runtime.engine, {
    host: '127.0.0.1',
    port: 0,
    maxConcurrentRequests: 64,
    rateLimit: { maxRequests: 250, windowMs: 60_000 },
    authRateLimit: { maxRequests: 50, windowMs: 60_000 },
    tokens: {
      'conc-alpha-tok': PRINCIPAL_ALPHA,
      'conc-beta-tok': PRINCIPAL_BETA,
    },
  });

  try {
    // Seed an alpha analysis so cross-tenant reads run deterministically in the 50-way storm
    const seedRes = await fetch(mcpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer conc-alpha-tok',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'security.chainbreak.analyze',
          arguments: { fixtureId: 'payments-lab/unsafe-rollout' },
        },
      }),
    });
    assert.equal(seedRes.status, 200);
    const seedJson = (await seedRes.json()) as {
      result: { structuredContent: { analysisId: string } };
    };
    const alphaAnalysisId = seedJson.result.structuredContent.analysisId;

    // Fire 50 concurrent HTTP JSON-RPC calls (mixed status, idempotent analyze storm, audit.start, Kali, cross-tenant FORBIDDEN)
    const callToolHttp = async (
      idx: number,
      token: string,
      name: string,
      args: Record<string, unknown>
    ) => {
      const res = await fetch(mcpServer.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: idx + 10,
          method: 'tools/call',
          params: { name, arguments: args },
        }),
      });
      const body = (await res.json()) as {
        result?: {
          isError?: boolean;
          structuredContent?: Record<string, unknown>;
          content?: Array<{ type: string; text?: string }>;
        };
      };
      return { status: res.status, result: body.result };
    };

    const batch = await Promise.all(
      Array.from({ length: 50 }, (_, i) => {
        const kind = i % 5;
        if (kind === 0) {
          return callToolHttp(i, 'conc-alpha-tok', 'security.status', {});
        }
        if (kind === 1) {
          return callToolHttp(i, 'conc-alpha-tok', 'security.chainbreak.analyze', {
            fixtureId: 'payments-lab/unsafe-rollout',
          });
        }
        if (kind === 2) {
          return callToolHttp(i, 'conc-alpha-tok', 'security.audit.start', {
            fixtureId: 'payments-lab/baseline',
          });
        }
        if (kind === 3) {
          return callToolHttp(i, 'conc-alpha-tok', 'security.kali.service_inventory', {
            scopeRef: 'SK-SCOPE-LAB-001',
            targetRef: '127.0.0.1:8080',
          });
        }
        return callToolHttp(i, 'conc-beta-tok', 'security.chainbreak.get', {
          analysisId: alphaAnalysisId,
        });
      })
    );

    assert.equal(batch.length, 50);
    for (let i = 0; i < batch.length; i++) {
      const entry = batch[i];
      assert.equal(entry.status, 200);
      if (i % 5 === 4) {
        assert.equal(entry.result?.isError, true);
        const errPayload = JSON.parse(entry.result?.content?.[0]?.text ?? '{}') as {
          code?: string;
        };
        assert.equal(errPayload.code, 'FORBIDDEN');
      } else {
        assert.notEqual(entry.result?.isError, true);
      }
    }
    assert.equal(mcpServer.getStats().inFlightRequests, 0);
  } finally {
    await mcpServer.close();
    runtime.close();
  }

  // Backpressure (503 + Retry-After) & timeout dangling rejection test
  let releaseGate!: () => void;
  const gatePromise = new Promise<void>((resolve) => {
    releaseGate = resolve;
  });
  let slowStartedCount = 0;
  let notifyTwoStarted!: () => void;
  const twoStartedPromise = new Promise<void>((resolve) => {
    notifyTwoStarted = resolve;
  });

  const testEngine = createEngine({
    name: 'concurrency-test-engine',
    version: '0.1.0',
    capabilities: [
      defineCapability({
        id: 'test.slow',
        title: 'Slow test cap',
        description: 'Waits for test barrier',
        inputSchema: z.object({}),
        outputSchema: z.object({ ok: z.boolean() }),
        access: { requiredScopes: ['security:read'], costUnits: 1, timeoutMs: 5_000 },
        async run() {
          slowStartedCount += 1;
          if (slowStartedCount === 2) {
            notifyTwoStarted();
          }
          await gatePromise;
          return { ok: true };
        },
      }),
      defineCapability({
        id: 'test.late_fail',
        title: 'Late failing cap',
        description: 'Rejects after abort timeout to verify unhandledRejection safety',
        inputSchema: z.object({}),
        outputSchema: z.object({ ok: z.boolean() }),
        access: { requiredScopes: ['security:read'], costUnits: 1, timeoutMs: 5_000 },
        async run() {
          await new Promise((resolve) => setTimeout(resolve, 60));
          throw new Error('late failure after timeout');
        },
      }),
    ],
  });

  const bpServer = await startMcpHttpServer(testEngine, {
    host: '127.0.0.1',
    port: 0,
    maxConcurrentRequests: 2,
    tokens: { 'bp-tok': PRINCIPAL_ALPHA },
  });

  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown) => {
    unhandled.push(reason);
  };
  process.on('unhandledRejection', onUnhandled);

  try {
    const req1 = fetch(bpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer bp-tok',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'test.slow', arguments: {} },
      }),
    });
    const req2 = fetch(bpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer bp-tok',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'test.slow', arguments: {} },
      }),
    });

    await twoStartedPromise;
    assert.equal(bpServer.getStats().inFlightRequests, 2);

    const req3 = await fetch(bpServer.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        Authorization: 'Bearer bp-tok',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/list',
        params: {},
      }),
    });
    assert.equal(req3.status, 503);
    assert.equal(req3.headers.get('retry-after'), '1');
    await req3.text();

    releaseGate();
    const [r1, r2] = await Promise.all([req1, req2]);
    assert.equal(r1.status, 200);
    assert.equal(r2.status, 200);
    await r1.text();
    await r2.text();
    assert.equal(bpServer.getStats().inFlightRequests, 0);

    // Timeout rejection test on testEngine
    await assert.rejects(
      async () =>
        testEngine.invoke(
          'test.late_fail',
          {},
          { principal: PRINCIPAL_ALPHA, source: 'test', budget: { timeoutMs: 10 } }
        ),
      (err: unknown) =>
        err instanceof ActionEngineError && err.code === 'TIMEOUT'
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(unhandled.length, 0);
  } finally {
    process.off('unhandledRejection', onUnhandled);
    releaseGate();
    await bpServer.close();
  }
});

