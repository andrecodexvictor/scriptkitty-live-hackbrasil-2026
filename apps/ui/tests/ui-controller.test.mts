/**
 * @file apps/ui/tests/ui-controller.test.mts
 * @description End-to-end verification of `@script-kitty/ui` live controller,
 * browser crypto/evaluator parity against `@script-kitty/chainbreak` & `@script-kitty/contracts`,
 * Invokta MCP Streamable HTTP integration & fail-closed fallbacks, DOM button/tab handlers,
 * and `MotionCatMascot3D` telemetry transitions.
 */

import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { analyzeFixture } from '@script-kitty/chainbreak';
import { computeMerkleRoot as contractsComputeMerkleRoot } from '@script-kitty/contracts';
import {
  connectSecurityMcpClient,
  createSecurityActionRuntime,
  startMcpHttpServer,
} from '@script-kitty/security-actions';

import {
  computeMerkleRoot,
  computePolicyGraphSha256,
  verifyCustodyChain,
} from '../src/crypto-browser.ts';
import { mountPatchCatDashboard } from '../src/dashboard-view.ts';
import { evaluateLabFixture } from '../src/lab-evaluator.ts';
import {
  CANONICAL_FIXTURE_IDS,
  LAB_FIXTURES,
  type CanonicalFixtureId,
} from '../src/lab-fixtures.ts';
import {
  CONNECTION_MODE_LABELS,
  MAX_SNAPSHOT_CACHE,
  PatchCatLiveController,
} from '../src/live-controller.ts';
import {
  MotionCatMascot3D,
  type MascotState,
} from '../src/mascot3d.ts';
import {
  McpClientError,
  validateLoopbackMcpUrl,
} from '../src/mcp-browser-client.ts';
import { compilePatchCatOpenUiBrief } from '../src/openui-catalog.ts';
import {
  mapMascotStateToPose,
  renderPatchCatSvg,
  type PatchCatPose,
} from '../src/patchcat-mascot.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '../../../fixtures/payments-lab');

// ============================================================================
// Lightweight Headless DOM Shim for testing `dashboard-view.ts` & `MotionCatMascot3D`
// ============================================================================

class MockCanvasContext2D {
  fillStyle: unknown = '';
  strokeStyle: unknown = '';
  lineWidth = 1;
  shadowColor = '';
  shadowBlur = 0;

  clearRect() {}
  createRadialGradient() {
    return { addColorStop() {} };
  }
  beginPath() {}
  arc() {}
  fill() {}
  stroke() {}
  save() {}
  restore() {}
  translate() {}
  rotate() {}
  moveTo() {}
  lineTo() {}
  closePath() {}
}

const VOID_TAGS = new Set(['img', 'input', 'br', 'hr', 'meta', 'link', 'line']);

class MockElement {
  readonly tagName: string;
  id = '';
  width = 240;
  height = 240;
  value = '';
  style: Record<string, string> = {};
  parentElement: MockElement | null = null;
  private attrs = new Map<string, string>();
  private listeners = new Map<string, Array<(event: unknown) => void>>();
  private _innerHTML = '';
  private _textContent: string | null = null;
  private _children: MockElement[] = [];

  constructor(tagName: string) {
    this.tagName = tagName.toLowerCase();
  }

  get innerHTML(): string {
    return this._innerHTML;
  }

  set innerHTML(html: string) {
    this._innerHTML = html;
    this._textContent = null;
    this._children = [];
    this.parseDescendantsFromHtml(html);
  }

  get textContent(): string {
    if (this._textContent !== null) return this._textContent;
    return this._innerHTML
      .replace(/<[^>]+>/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/\s+/g, ' ')
      .trim();
  }

  set textContent(val: string) {
    this._textContent = val;
    this._innerHTML = val;
    this._children = [];
  }

  private parseDescendantsFromHtml(html: string): void {
    const stack: Array<{ el: MockElement; contentStart: number }> = [
      { el: this, contentStart: 0 },
    ];
    const tokenRegex = /<(\/?)([a-zA-Z0-9-]+)([^>]*?)(\/?)>/g;
    let match: RegExpExecArray | null;

    while ((match = tokenRegex.exec(html)) !== null) {
      const [full, isClose, rawTag, attrStr, selfClose] = match;
      const tag = rawTag.toLowerCase();

      if (isClose === '/') {
        for (let i = stack.length - 1; i >= 1; i--) {
          if (stack[i].el.tagName === tag) {
            const closed = stack.splice(i)[0];
            closed.el._innerHTML = html.slice(closed.contentStart, match.index);
            break;
          }
        }
        continue;
      }

      const child = new MockElement(tag);
      const attrRegex = /([a-zA-Z0-9_-]+)="([^"]*)"/g;
      let aMatch: RegExpExecArray | null;
      while ((aMatch = attrRegex.exec(attrStr)) !== null) {
        const [, name, value] = aMatch;
        child.attrs.set(name, value);
        if (name === 'id') child.id = value;
        if (name === 'value') child.value = value;
      }

      const parent = stack[stack.length - 1].el;
      child.parentElement = parent;
      parent._children.push(child);

      const isSelfClosing = selfClose === '/' || VOID_TAGS.has(tag);
      if (!isSelfClosing) {
        stack.push({
          el: child,
          contentStart: match.index + full.length,
        });
      }
    }
  }

  appendChild(child: MockElement): MockElement {
    child.parentElement = this;
    this._children.push(child);
    return child;
  }

  removeChild(child: MockElement): MockElement {
    this._children = this._children.filter((c) => c !== child);
    child.parentElement = null;
    return child;
  }

  setAttribute(name: string, value: string): void {
    this.attrs.set(name, value);
    if (name === 'id') this.id = value;
  }

  getAttribute(name: string): string | null {
    return this.attrs.get(name) ?? null;
  }

  getContext(type: string): MockCanvasContext2D | null {
    return type === '2d' ? new MockCanvasContext2D() : null;
  }

  getBoundingClientRect() {
    return { left: 0, top: 0, width: this.width, height: this.height };
  }

  querySelector(selector: string): MockElement | null {
    const cleanId = selector.startsWith('#') ? selector.slice(1) : selector;
    if (this.id === cleanId) return this;
    for (const child of this._children) {
      const found = child.querySelector(selector);
      if (found) return found;
    }
    return null;
  }

  addEventListener(event: string, cb: (ev: unknown) => void): void {
    const list = this.listeners.get(event) ?? [];
    list.push(cb);
    this.listeners.set(event, list);
  }

  dispatchEvent(event: string, payload: unknown = {}): void {
    for (const cb of this.listeners.get(event) ?? []) {
      cb(payload);
    }
  }

  click(): void {
    this.dispatchEvent('click', { target: this });
  }
}

function setupMockDomGlobals(): {
  root: MockElement;
  cleanup: () => void;
} {
  const root = new MockElement('div');
  root.id = 'app';

  const prevDoc = (globalThis as { document?: unknown }).document;
  const prevWin = (globalThis as { window?: unknown }).window;
  const prevRaf = (globalThis as { requestAnimationFrame?: unknown })
    .requestAnimationFrame;
  const prevCaf = (globalThis as { cancelAnimationFrame?: unknown })
    .cancelAnimationFrame;

  const mockDoc = {
    createElement: (tag: string) => new MockElement(tag),
    getElementById: (id: string) => root.querySelector(`#${id}`),
    querySelector: (sel: string) => root.querySelector(sel),
  };
  const mockWin = {
    addEventListener: () => {},
    removeEventListener: () => {},
  };

  Object.assign(globalThis, {
    document: mockDoc,
    window: mockWin,
    requestAnimationFrame: () => 0,
    cancelAnimationFrame: () => {},
  });

  return {
    root,
    cleanup: () => {
      Object.assign(globalThis, {
        document: prevDoc,
        window: prevWin,
        requestAnimationFrame: prevRaf,
        cancelAnimationFrame: prevCaf,
      });
    },
  };
}

// ============================================================================
// TEST SUITES
// ============================================================================

describe('@script-kitty/ui — Crypto & Fixture Parity', () => {
  it('browser fixtures match on-disk payments-lab JSON and @script-kitty/chainbreak SHA-256 / IDs', () => {
    const fileMap: Record<CanonicalFixtureId, string> = {
      'payments-lab/baseline': 'baseline.json',
      'payments-lab/unsafe-rollout': 'unsafe-rollout.json',
      'payments-lab/remediated': 'remediated.json',
      'payments-lab/negative-control': 'negative-control.json',
    };

    for (const fixtureId of CANONICAL_FIXTURE_IDS) {
      const diskRaw = fs.readFileSync(
        path.join(FIXTURES_DIR, fileMap[fixtureId]),
        'utf8'
      );
      const diskJson = JSON.parse(diskRaw);
      const uiFixture = LAB_FIXTURES[fixtureId];

      assert.deepEqual(uiFixture, diskJson);

      const computedHash = computePolicyGraphSha256(
        uiFixture as unknown as Record<string, unknown>
      );
      assert.equal(computedHash, uiFixture.declaredInputSha256);

      const backendAnalysis = analyzeFixture(fixtureId, {
        fixturesDir: FIXTURES_DIR,
        now: '2026-11-11T12:00:00.000Z',
      });
      const uiAnalysis = evaluateLabFixture(fixtureId, {
        now: '2026-11-11T12:00:00.000Z',
      });

      assert.equal(uiAnalysis.analysisId, backendAnalysis.analysisId);
      assert.equal(uiAnalysis.inputSha256, backendAnalysis.inputSha256);
      assert.equal(uiAnalysis.paths.length, backendAnalysis.paths.length);
      assert.equal(
        uiAnalysis.legitimateOperationsPreserved,
        backendAnalysis.legitimateOperationsPreserved
      );
      if (backendAnalysis.paths.length > 0) {
        assert.equal(uiAnalysis.paths[0].pathId, backendAnalysis.paths[0].pathId);
        assert.equal(uiAnalysis.paths[0].status, 'PATH_VALIDATED');
        assert.equal(
          uiAnalysis.remediationSpecs[0].remediationId,
          backendAnalysis.remediationSpecs[0].remediationId
        );
      }
    }
  });

  it('browser computeMerkleRoot matches @script-kitty/contracts RFC 8785 binary Merkle root', () => {
    const leaves = ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)];
    assert.equal(computeMerkleRoot(leaves), contractsComputeMerkleRoot(leaves));
  });
});

describe('@script-kitty/ui — Canonical State Transitions & Fail-Closed Invariants', () => {
  it('transitions baseline -> unsafe-rollout -> remediated -> negative-control with exact DEMO_WEDNESDAY fields', async () => {
    const controller = new PatchCatLiveController({
      initialFixture: 'payments-lab/baseline',
      mcpAutoProbe: false,
      now: () => '2026-11-11T12:00:00.000Z',
    });

    // 1. Baseline
    const sBaseline = controller.getState();
    assert.equal(sBaseline.activeFixtureId, 'payments-lab/baseline');
    assert.equal(sBaseline.connectionMode, 'LAB_DETERMINISTIC');
    assert.equal(sBaseline.modeBadge, CONNECTION_MODE_LABELS.LAB_DETERMINISTIC);
    assert.equal(sBaseline.analysis.paths.length, 0);
    assert.equal(sBaseline.analysis.legitimateOperationsPreserved, true);
    assert.equal(sBaseline.analysis.legitimateOperations.length, 3);
    assert.equal(sBaseline.adjudication.status, 'ACCEPTED_FOR_TRIAGE');
    assert.equal(sBaseline.adjudication.triage, 'likely_irrelevant');
    assert.equal(sBaseline.mascotState, 'idle');

    // 2. Unsafe Rollout
    const sUnsafe = await controller.selectFixture('payments-lab/unsafe-rollout');
    assert.equal(sUnsafe.activeFixtureId, 'payments-lab/unsafe-rollout');
    assert.equal(sUnsafe.analysis.paths.length, 1);
    assert.equal(sUnsafe.analysis.paths[0].status, 'PATH_VALIDATED');
    assert.equal(
      sUnsafe.analysis.paths[0].violatedPolicyId,
      'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER'
    );
    assert.equal(sUnsafe.analysis.paths[0].riskRecommendation, 'P1');
    assert.deepEqual(
      sUnsafe.analysis.paths[0].edges.map((e) => e.sourceRef),
      [
        'policies/payments-lab/unsafe-rollout.policy.yaml#edges.support_invoke_exporter',
        'policies/payments-lab/report-exporter-rollout.yaml#L24',
        'policies/payments-lab/report-exporter-rollout.yaml#L38',
      ]
    );
    assert.equal(sUnsafe.analysis.legitimateOperationsPreserved, true);
    assert.equal(sUnsafe.analysis.legitimateOperations.length, 3);

    // JEV assertions on unsafe-rollout
    assert.equal(sUnsafe.adjudication.decisionSource, 'MOCK');
    assert.equal(sUnsafe.adjudication.providerStatus, 'NOT_CONFIGURED');
    assert.equal(sUnsafe.adjudication.status, 'PENDING_REVIEW');
    assert.equal(sUnsafe.adjudication.probabilities.evidenceSufficient, 0.94);
    assert.equal(sUnsafe.adjudication.probabilities.needsManualReview, 0.92);
    assert.equal(sUnsafe.adjudication.triage, 'likely_actionable');
    assert.equal(sUnsafe.adjudication.p0DefinedByJevAlone, false);
    assert.equal(sUnsafe.adjudication.confidenceOrUncertainty.thresholdCalibrated, false);

    // RemediationSpec on unsafe-rollout
    assert.ok(sUnsafe.activeRemediationSpec);
    assert.equal(
      sUnsafe.activeRemediationSpec.actions[0].actionType,
      'REMOVE_EDGE'
    );
    assert.equal(
      sUnsafe.activeRemediationSpec.actions[0].edgeId,
      'e-rollout-exporter-read-pii'
    );
    assert.equal(sUnsafe.activeRemediationSpec.breaksUnauthorizedPath, true);
    assert.equal(
      sUnsafe.activeRemediationSpec.preservesLegitimateOperations,
      true
    );
    assert.equal(sUnsafe.activeRemediationSpec.requiresHumanApproval, true);
    assert.equal(sUnsafe.activeRemediationSpec.autoApplyAllowed, false);
    assert.equal(sUnsafe.mascotState, 'alert');

    // 3. Remediated
    const sRemediated = await controller.selectFixture('payments-lab/remediated');
    assert.equal(sRemediated.analysis.paths.length, 0);
    assert.equal(sRemediated.analysis.legitimateOperationsPreserved, true);
    assert.equal(sRemediated.analysis.legitimateOperations.length, 3);
    assert.equal(sRemediated.adjudication.status, 'ACCEPTED_FOR_TRIAGE');
    assert.equal(sRemediated.qualityGate.verdict, 'PASS');
    assert.equal(sRemediated.qualityGate.custody_valid, true);
    assert.equal(
      verifyCustodyChain(sRemediated.qualityGate.custody_chain.nodes).valid,
      true
    );
    assert.match(sRemediated.qualityGate.merkle_root, /^[a-f0-9]{64}$/);
    assert.equal(sRemediated.factoryDelivery.contract, 'factory.delivery.v1');
    assert.equal(sRemediated.factoryDelivery.eligible, true);
    assert.equal(sRemediated.factoryDelivery.mergeAllowed, false);
    assert.equal(sRemediated.factoryDelivery.deployAllowed, false);
    assert.equal(sRemediated.factoryDelivery.externalExecution, false);
    assert.equal(sRemediated.mascotState, 'success');

    // 4. Negative Control
    const sNeg = await controller.selectFixture('payments-lab/negative-control');
    assert.equal(sNeg.analysis.paths.length, 0);
    assert.equal(sNeg.mascotState, 'idle');

    // Verify EXPLOIT_CONFIRMED never appears as a status anywhere in controller state
    for (const st of [sBaseline, sUnsafe, sRemediated, sNeg]) {
      for (const p of st.analysis.paths) {
        assert.notEqual(p.status as string, 'EXPLOIT_CONFIRMED');
      }
      assert.equal(st.invariants.productionTested, false);
      assert.equal(st.invariants.mergeAllowed, false);
      assert.equal(st.invariants.deployAllowed, false);
      assert.equal(st.invariants.autoApplyAllowed, false);
      assert.equal(st.invariants.p0DefinedByJevAlone, false);
    }
  });
});

describe('@script-kitty/ui — Invokta MCP Streamable HTTP Live & Fallback', () => {
  it('connects to live MCP HTTP server, redacts Bearer token, and falls back fail-closed on errors/401/403/SSRF', async () => {
    const runtime = createSecurityActionRuntime({ dbPath: ':memory:' });
    const secretToken = `sk-ui-live-${crypto.randomBytes(10).toString('hex')}`;
    const allowedOrigin = 'http://127.0.0.1:5173';
    const principal = {
      principalId: 'ui-operator-alpha',
      tenantId: 'payments-lab',
      roles: ['security-operator'],
      scopes: [
        'security:status',
        'security:analyze',
        'security:read',
        'security:judge',
        'security:remediate',
      ],
    };

    const server = await startMcpHttpServer(runtime.engine, {
      host: '127.0.0.1',
      port: 0,
      path: '/mcp',
      allowedOrigins: [allowedOrigin],
      requireOriginHeader: true,
      tokens: {
        [secretToken]: principal,
      },
    });

    try {
      // Sanity check using official server client that server is up
      const probe = await connectSecurityMcpClient({
        url: server.url,
        token: secretToken,
        origin: allowedOrigin,
      });
      await probe.close();

      // 1. Live MCP HTTP mode via PatchCatLiveController
      const controller = new PatchCatLiveController({
        initialFixture: 'payments-lab/baseline',
        mcpUrl: server.url,
        bearerToken: secretToken,
        mcpOrigin: allowedOrigin,
        mcpAutoProbe: true,
      });

      const liveState = await controller.selectFixture(
        'payments-lab/unsafe-rollout'
      );
      assert.equal(liveState.connectionMode, 'LIVE_MCP_HTTP');
      assert.equal(liveState.modeBadge, CONNECTION_MODE_LABELS.LIVE_MCP_HTTP);
      assert.ok(liveState.mcp.sessionId);
      assert.equal(liveState.mcp.serverStatus?.mode, 'LAB');
      assert.equal(liveState.mcp.serverStatus?.harness2ExperimentsEnabled, false);
      assert.ok(
        liveState.mcp.availableTools.includes('security.chainbreak.analyze')
      );
      assert.equal(liveState.analysis.paths.length, 1);
      assert.equal(liveState.analysis.paths[0].status, 'PATH_VALIDATED');
      assert.equal(liveState.adjudication.status, 'PENDING_REVIEW');
      assert.equal(
        liveState.activeRemediationSpec?.actions[0].edgeId,
        'e-rollout-exporter-read-pii'
      );

      // Token must NEVER leak in serialized dashboard state or audit log
      const serialized = JSON.stringify(liveState);
      assert.equal(serialized.includes(secretToken), false);

      // View Memory pulls live persisted decision history via security.chainbreak.get
      // and reuses the single active MCP session without spawning extra sessions
      const firstSessionId = liveState.mcp.sessionId;
      const memState = await controller.viewMemory(true);
      assert.equal(memState.memoryDrawerOpen, true);
      assert.ok(memState.decisionHistory.length >= 1);
      const reusedState = await controller.selectFixture('payments-lab/remediated');
      assert.equal(reusedState.mcp.sessionId, firstSessionId);
      assert.equal(server.getStats().activeSessions, 1);

      // Explicitly closing controller sends DELETE /mcp and drops server activeSessions to 0
      await controller.close();
      assert.equal(server.getStats().activeSessions, 0);

      // Re-open live session, then switch token -> cleanly closes old session via DELETE /mcp before 401
      const reconnected = await controller.selectFixture('payments-lab/unsafe-rollout');
      assert.ok(reconnected.mcp.sessionId);
      assert.notEqual(reconnected.mcp.sessionId, firstSessionId);
      assert.equal(server.getStats().activeSessions, 1);

      // 2. HTTP 401 unauthorized token -> seamless fallback + secret redaction + zero leaked sessions
      controller.setMcpConnectionConfig({ token: 'wrong-bearer-secret-999' });
      const authFailFallback = await controller.selectFixture(
        'payments-lab/unsafe-rollout'
      );
      assert.equal(server.getStats().activeSessions, 0);
      assert.equal(authFailFallback.connectionMode, 'LAB_DETERMINISTIC');
      assert.equal(
        authFailFallback.modeBadge,
        CONNECTION_MODE_LABELS.LAB_DETERMINISTIC
      );
      assert.match(authFailFallback.mcp.lastFallbackReason ?? '', /UNAUTHORIZED/);
      assert.equal(
        (authFailFallback.mcp.lastFallbackReason ?? '').includes(
          'wrong-bearer-secret-999'
        ),
        false
      );
      assert.equal(authFailFallback.analysis.paths.length, 1);

      // 3. HTTP 403 disallowed Origin -> seamless fallback
      const badOriginController = new PatchCatLiveController({
        mcpUrl: server.url,
        bearerToken: secretToken,
        mcpOrigin: 'https://evil.example',
        mcpAutoProbe: true,
      });
      const originFallback = await badOriginController.selectFixture(
        'payments-lab/remediated'
      );
      assert.equal(originFallback.connectionMode, 'LAB_DETERMINISTIC');
      assert.match(originFallback.mcp.lastFallbackReason ?? '', /FORBIDDEN/);
      assert.equal(originFallback.analysis.paths.length, 0);

      // 4. SSRF non-loopback URL blocked fail-closed without network request
      let fetchCalled = false;
      const ssrfController = new PatchCatLiveController({
        mcpUrl: 'https://evil.example/mcp',
        mcpAutoProbe: true,
        fetchImpl: async () => {
          fetchCalled = true;
          throw new Error('Should not have called fetch on non-loopback URL');
        },
      });
      assert.throws(
        () => validateLoopbackMcpUrl('http://169.254.169.254/latest/meta-data'),
        (e: unknown) => e instanceof McpClientError && e.code === 'SSRF_BLOCKED'
      );
      const ssrfFallback = await ssrfController.selectFixture(
        'payments-lab/unsafe-rollout'
      );
      assert.equal(fetchCalled, false);
      assert.equal(ssrfFallback.connectionMode, 'LAB_DETERMINISTIC');
      assert.match(ssrfFallback.mcp.lastFallbackReason ?? '', /SSRF_BLOCKED/);

      // 5. Unreachable loopback port -> seamless fallback
      const unreachableController = new PatchCatLiveController({
        mcpUrl: 'http://127.0.0.1:1/mcp',
        mcpAutoProbe: true,
        timeoutMs: 400,
      });
      const unreachableState = await unreachableController.runFullScout();
      assert.equal(unreachableState.connectionMode, 'LAB_DETERMINISTIC');
      assert.ok(unreachableState.mcp.lastFallbackReason);
      assert.equal(unreachableState.analysis.paths.length, 0);
    } finally {
      await server.close();
      runtime.close();
    }
  });
});

describe('@script-kitty/ui — DOM Mounting, All 4 Buttons, Tabs & Mascot States', () => {
  it('wires #btn-scout, #btn-learn, #btn-pr, #btn-pr-suggest, fixture tabs, self-cert toggle, and MotionCatMascot3D', async () => {
    const dom = setupMockDomGlobals();
    try {
      const observedMascotStates: MascotState[] = [];
      let realMascotRef: MotionCatMascot3D | null = null;

      const controller = new PatchCatLiveController({
        initialFixture: 'payments-lab/baseline',
        mcpAutoProbe: false,
        now: () => '2026-11-11T12:00:00.000Z',
      });

      const mounted = mountPatchCatDashboard(
        dom.root as unknown as Element,
        controller,
        {
          mascotFactory: (containerId, initialState) => {
            const mascot = new MotionCatMascot3D(containerId, initialState);
            realMascotRef = mascot;
            observedMascotStates.push(mascot.getState());
            const origSetState = mascot.setState.bind(mascot);
            mascot.setState = (next: MascotState) => {
              observedMascotStates.push(next);
              origSetState(next);
            };
            return mascot;
          },
        }
      );

      assert.ok(realMascotRef);
      assert.equal(
        dom.root.querySelector('#badge-connection-mode')?.textContent,
        'MODE: LAB DETERMINISTIC'
      );
      assert.equal(realMascotRef!.getState(), 'idle');

      // 1. Click scenario tab -> unsafe-rollout
      dom.root.querySelector('#tab-unsafe-rollout')?.click();
      await Promise.resolve();

      assert.equal(controller.getState().activeFixtureId, 'payments-lab/unsafe-rollout');
      assert.equal(realMascotRef!.getState(), 'alert');
      const chainbreakText = dom.root.querySelector('#panel-chainbreak')?.textContent ?? '';
      assert.match(chainbreakText, /NO_RESTRICTED_DATA_EXTERNAL_TRANSFER/);
      assert.match(chainbreakText, /PATH_VALIDATED/);
      assert.match(chainbreakText, /NEVER EXPLOIT_CONFIRMED/);
      assert.match(chainbreakText, /3\/3/);
      assert.equal(
        controller.getState().analysis.paths.every((p) => (p.status as string) !== 'EXPLOIT_CONFIRMED'),
        true
      );

      const jevText = dom.root.querySelector('#panel-jev')?.textContent ?? '';
      assert.match(jevText, /PENDING_REVIEW/);
      assert.match(jevText, /MOCK/);
      assert.match(jevText, /p0DefinedByJevAlone: false/);

      // 2. Click #btn-scout -> passes through 'scanning' -> 'alert'
      const initialAuditCount = controller.getState().auditLog.length;
      dom.root.querySelector('#btn-scout')?.click();
      await new Promise((r) => setTimeout(r, 10));

      assert.ok(observedMascotStates.includes('scanning'));
      assert.equal(realMascotRef!.getState(), 'alert');
      assert.ok(controller.getState().auditLog.length > initialAuditCount);

      // 3. Click #btn-learn -> opens Company Brain memory panel
      dom.root.querySelector('#btn-learn')?.click();
      await Promise.resolve();

      assert.equal(controller.getState().memoryDrawerOpen, true);
      const memPanelHtml = dom.root.querySelector('#panel-memory')?.innerHTML ?? '';
      assert.match(memPanelHtml, /payments-lab\/unsafe-rollout/);

      // 4. Click #btn-pr-suggest -> creates diff, proves 1 -> 0 paths & 3/3 legit preserved, mascot -> success
      dom.root.querySelector('#btn-pr-suggest')?.click();
      await new Promise((r) => setTimeout(r, 10));

      assert.equal(controller.getState().activeFixtureId, 'payments-lab/remediated');
      assert.equal(controller.getState().prSuggestionOpen, true);
      assert.equal(realMascotRef!.getState(), 'success');
      const prSuggestText = dom.root.querySelector('#panel-pr-suggestion')?.textContent ?? '';
      assert.match(prSuggestText, /e-rollout-exporter-read-pii/);
      assert.match(prSuggestText, /requiresHumanApproval: true/);
      assert.match(prSuggestText, /autoApplyAllowed: false/);
      assert.match(prSuggestText, /Paths 1 → 0/);

      // 5. Click #btn-pr -> Quality Gate + RFC 8785 Merkle + factory.delivery.v1
      dom.root.querySelector('#btn-pr')?.click();
      await Promise.resolve();

      assert.equal(dom.root.querySelector('#txt-gate-verdict')?.textContent, 'PASS');
      const merkleText = dom.root.querySelector('#txt-merkle-root')?.textContent ?? '';
      assert.match(merkleText, /^[a-f0-9]{64}$/);
      const deliveryText = dom.root.querySelector('#panel-factory-delivery')?.textContent ?? '';
      assert.match(deliveryText, /factory\.delivery\.v1/);
      assert.match(deliveryText, /eligible:\s*true/);
      assert.match(deliveryText, /mergeAllowed: false/);
      assert.match(deliveryText, /deployAllowed: false/);
      assert.equal(realMascotRef!.getState(), 'success');

      // 6. Toggle SoD self-certification fail-closed test -> REJECT + alert
      dom.root.querySelector('#btn-toggle-self-cert')?.click();
      await Promise.resolve();

      assert.equal(dom.root.querySelector('#txt-gate-verdict')?.textContent, 'REJECT');
      assert.match(
        dom.root.querySelector('#panel-remediation-gate')?.textContent ?? '',
        /E_SOD_SELF_CERTIFICATION/
      );
      assert.match(
        dom.root.querySelector('#panel-factory-delivery')?.textContent ?? '',
        /eligible:\s*false/
      );
      assert.equal(realMascotRef!.getState(), 'alert');

      // Restore Tri-Party SoD -> PASS + success
      dom.root.querySelector('#btn-toggle-self-cert')?.click();
      await Promise.resolve();
      assert.equal(dom.root.querySelector('#txt-gate-verdict')?.textContent, 'PASS');
      assert.equal(realMascotRef!.getState(), 'success');

      // Verify all 4 mascot states were exercised through real UI interaction
      assert.deepEqual(
        Array.from(new Set(observedMascotStates)).sort(),
        ['alert', 'idle', 'scanning', 'success']
      );

      mounted.unmount();
      await controller.close();
    } finally {
      dom.cleanup();
    }
  });

  it('handles i18n language switching, AI keys modal with volatile secret isolation, and MCP connect/reset UI controls', async () => {
    const dom = setupMockDomGlobals();
    const runtime = createSecurityActionRuntime({ dbPath: ':memory:' });
    const secretToken = `sk-ui-dom-${crypto.randomBytes(8).toString('hex')}`;
    const apiSecretSample = 'sk-proj-DO-NOT-LEAK-TO-DOM-OR-STATE-999';
    const server = await startMcpHttpServer(runtime.engine, {
      host: '127.0.0.1',
      port: 0,
      path: '/mcp',
      requireOriginHeader: false,
      tokens: {
        [secretToken]: {
          principalId: 'ui-dom-operator',
          tenantId: 'payments-lab',
          roles: ['security-operator'],
          scopes: [
            'security:status',
            'security:analyze',
            'security:read',
            'security:judge',
            'security:remediate',
          ],
        },
      },
    });

    try {
      const controller = new PatchCatLiveController({
        initialFixture: 'payments-lab/unsafe-rollout',
        mcpAutoProbe: false,
        now: () => '2026-11-11T12:00:00.000Z',
      });
      const mounted = mountPatchCatDashboard(
        dom.root as unknown as Element,
        controller
      );

      // 1. i18n language selector -> PT & ES
      const langSelect = dom.root.querySelector('#select-lang')!;
      langSelect.value = 'pt';
      langSelect.dispatchEvent('change', { target: langSelect });
      assert.match(
        dom.root.querySelector('#txt-hero-title')?.textContent ?? '',
        /Explorador PatchCat/
      );

      const langSelectEs = dom.root.querySelector('#select-lang')!;
      langSelectEs.value = 'es';
      langSelectEs.dispatchEvent('change', { target: langSelectEs });
      assert.match(
        dom.root.querySelector('#btn-scout')?.textContent ?? '',
        /Ejecutar Escaneo/
      );

      // 2. AI Keys modal open, save (secret never serialized), toast dismiss
      dom.root.querySelector('#btn-open-keys')?.click();
      assert.equal(controller.getState().showKeyModal, true);
      assert.ok(dom.root.querySelector('#modal-overlay'));

      const providerSel = dom.root.querySelector('#key-provider')!;
      providerSel.value = 'codex';
      const openaiInput = dom.root.querySelector('#input-openai')!;
      openaiInput.value = apiSecretSample;
      dom.root.querySelector('#btn-save-keys')?.click();

      assert.equal(controller.getState().showKeyModal, false);
      assert.equal(controller.getState().aiConfig.activeProvider, 'codex');
      assert.equal(controller.getState().aiConfig.hasOpenaiKey, true);
      assert.ok(dom.root.querySelector('#toast-banner'));
      assert.equal(
        JSON.stringify(controller.getState()).includes(apiSecretSample),
        false
      );
      assert.equal(
        (dom.root.querySelector('#audit-terminal')?.innerHTML ?? '').includes(
          apiSecretSample
        ),
        false
      );

      dom.root.querySelector('#btn-dismiss-toast')?.click();
      assert.equal(dom.root.querySelector('#toast-banner'), null);

      // 3. Sidebar MCP Connect / Reset UI controls
      const waitForLive = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          unsub();
          reject(
            new Error(
              `Timed out waiting for LIVE_MCP_HTTP (mode=${controller.getState().connectionMode}, fallback=${controller.getState().mcp.lastFallbackReason})`
            )
          );
        }, 3000);
        const unsub = controller.subscribe((st) => {
          if (st.connectionMode === 'LIVE_MCP_HTTP') {
            clearTimeout(timer);
            unsub();
            resolve();
          } else if (st.mcp.lastFallbackReason) {
            clearTimeout(timer);
            unsub();
            reject(
              new Error(
                `Unexpected MCP fallback during connect: ${st.mcp.lastFallbackReason}`
              )
            );
          }
        });
      });

      const urlInput = dom.root.querySelector('#input-mcp-url')!;
      const tokenInput = dom.root.querySelector('#input-mcp-token')!;
      urlInput.value = server.url;
      tokenInput.value = secretToken;
      dom.root.querySelector('#btn-mcp-connect')?.click();

      await waitForLive;

      assert.equal(
        dom.root.querySelector('#badge-connection-mode')?.textContent,
        'MODE: LIVE MCP HTTP'
      );
      assert.equal(controller.getState().connectionMode, 'LIVE_MCP_HTTP');
      assert.equal(
        JSON.stringify(controller.getState()).includes(secretToken),
        false
      );

      dom.root.querySelector('#btn-mcp-reset')?.click();
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(
        dom.root.querySelector('#badge-connection-mode')?.textContent,
        'MODE: LAB DETERMINISTIC'
      );
      assert.equal(controller.getState().connectionMode, 'LAB_DETERMINISTIC');
      assert.equal(server.getStats().activeSessions, 0);

      // Verify mounted.unmount() automatically closes any live MCP session via DELETE /mcp
      dom.root.querySelector('#btn-mcp-connect')?.click();
      await new Promise((r) => setTimeout(r, 40));
      assert.equal(server.getStats().activeSessions, 1);
      mounted.unmount();
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(server.getStats().activeSessions, 0);
      await controller.close();
    } finally {
      await server.close();
      runtime.close();
      dom.cleanup();
    }
  });

  it('renders validated OpenUI brief, supports theme & sandbox popover controls, and maintains Class-A product copy discipline', () => {
    const dom = setupMockDomGlobals();
    const docAttrs = new Map<string, string>();
    const themeDoc = {
      documentElement: {
        setAttribute: (name: string, value: string) => {
          docAttrs.set(name, value);
        },
        getAttribute: (name: string) => docAttrs.get(name) ?? null,
      },
    } as unknown as Document;

    try {
      const controller = new PatchCatLiveController({
        initialFixture: 'payments-lab/unsafe-rollout',
        mcpAutoProbe: false,
        now: () => '2026-11-21T12:00:00.000Z',
      });
      const mounted = mountPatchCatDashboard(
        dom.root as unknown as Element,
        controller,
        { doc: themeDoc }
      );

      // 1. OpenUI brief compiled & rendered with zero schema errors
      const panelsHtml = dom.root.querySelector('#mount-panels')?.innerHTML ?? '';
      assert.ok(dom.root.querySelector('#panel-openui-brief'));
      assert.match(panelsHtml, /id="panel-openui-brief"[^>]*data-openui-root="PolicySummary"/);
      assert.match(panelsHtml, /id="panel-openui-brief"[^>]*data-openui-errors="0"/);
      const briefEl = dom.root.querySelector('#panel-openui-brief') as unknown as {
        getAttribute?: (n: string) => string | null;
      };
      if (typeof briefEl.getAttribute === 'function') {
        assert.equal(briefEl.getAttribute('data-openui-root'), 'PolicySummary');
        assert.equal(briefEl.getAttribute('data-openui-errors'), '0');
      }

      // 2. Theme toggle cycles dark (default) -> light -> dark cleanly
      assert.equal(docAttrs.get('data-theme'), 'dark');
      dom.root.querySelector('#btn-toggle-theme')?.click();
      assert.equal(docAttrs.get('data-theme'), 'light');
      dom.root.querySelector('#btn-toggle-theme')?.click();
      assert.equal(docAttrs.get('data-theme'), 'dark');

      // 3. Sandbox boundary popover toggles via #badge-lab-boundary
      const initialHeaderHtml = dom.root.querySelector('#mount-header')?.innerHTML ?? '';
      assert.match(initialHeaderHtml, /id="badge-lab-boundary"[^>]*aria-expanded="false"/);
      dom.root.querySelector('#badge-lab-boundary')?.click();
      const openHeaderHtml = dom.root.querySelector('#mount-header')?.innerHTML ?? '';
      assert.match(openHeaderHtml, /id="badge-lab-boundary"[^>]*aria-expanded="true"/);

      // 4. Product copy discipline: clean headlines while preserving verifiable receipts
      const jevHtml = dom.root.querySelector('#panel-jev')?.innerHTML ?? '';
      const jevText = dom.root.querySelector('#panel-jev')?.textContent ?? '';
      assert.match(jevHtml, /<span class="panel-title">Human Risk Review<\/span>/);
      assert.equal(jevText.includes('JEV-as-a-Judge'), false);
      assert.match(jevText, /PENDING_REVIEW/);
      assert.match(jevText, /MOCK/);
      assert.match(jevText, /p0DefinedByJevAlone: false/);

      const visibleLandingText = [
        dom.root.querySelector('#mount-header')?.textContent ?? '',
        dom.root.querySelector('#mount-hero-landing')?.textContent ?? '',
        dom.root.querySelector('#mount-hero-text')?.textContent ?? '',
        dom.root.querySelector('#mount-editorial')?.textContent ?? '',
      ].join(' ');
      for (const forbidden of ['Invokta', 'JEV-as-a-Judge', 'Harness²', 'Mantis', 'Company Brain', 'TypeSafe']) {
        assert.equal(visibleLandingText.includes(forbidden), false, `Visible landing copy must exclude '${forbidden}'`);
      }

      const sidebarText = dom.root.querySelector('#mount-sidebar')?.textContent ?? '';
      assert.equal(sidebarText.includes('.dotstack'), false);
      assert.equal(sidebarText.includes('.dotarchitecture'), false);

      mounted.unmount();
    } finally {
      dom.cleanup();
    }
  });

  it('supports EN/PT bilingual landing copy, keyboard ArrowRight/ArrowLeft tabs, PatchCat 5-pose rendering, OpenUI brief compilation, and FIFO snapshot cache cap', async () => {
    const dom = setupMockDomGlobals();
    try {
      const controller = new PatchCatLiveController({
        initialFixture: 'payments-lab/baseline',
        mcpAutoProbe: false,
        now: () => '2026-11-21T12:00:00.000Z',
      });
      const mounted = mountPatchCatDashboard(
        dom.root as unknown as Element,
        controller
      );

      // 1. EN default landing copy & PT bilingual switch
      assert.equal(
        dom.root.querySelector('#txt-landing-h1')?.textContent,
        'Security that sees the whole attack path.'
      );
      const langSelect = dom.root.querySelector('#select-lang')!;
      langSelect.value = 'pt';
      langSelect.dispatchEvent('change', { target: langSelect });
      assert.equal(
        dom.root.querySelector('#txt-landing-h1')?.textContent,
        'Segurança que enxerga o caminho inteiro do ataque.'
      );

      // 2. Keyboard ArrowRight / ArrowLeft scenario switching
      dom.root.querySelector('#tab-baseline')?.dispatchEvent('keydown', {
        key: 'ArrowRight',
        preventDefault: () => {},
      });
      await Promise.resolve();
      assert.equal(controller.getState().activeFixtureId, 'payments-lab/unsafe-rollout');

      dom.root.querySelector('#tab-unsafe-rollout')?.dispatchEvent('keydown', {
        key: 'ArrowLeft',
        preventDefault: () => {},
      });
      await Promise.resolve();
      assert.equal(controller.getState().activeFixtureId, 'payments-lab/baseline');

      // 3. PatchCat 5-pose rendering & mapping
      const poses: PatchCatPose[] = ['idle', 'scanning', 'alert', 'verified', 'needs_review'];
      const stripHtml = dom.root.querySelector('#patchcat-pose-strip')?.innerHTML ?? '';
      for (const pose of poses) {
        assert.match(stripHtml, new RegExp(`data-patchcat-pose="${pose}"`));
        const svg = renderPatchCatSvg(pose, { size: 48 });
        assert.match(svg, /role="img"/);
      }
      assert.equal(mapMascotStateToPose('idle', false), 'idle');
      assert.equal(mapMascotStateToPose('scanning', false), 'scanning');
      assert.equal(mapMascotStateToPose('alert', true), 'alert');
      assert.equal(mapMascotStateToPose('success', false), 'verified');
      assert.equal(mapMascotStateToPose('idle', true), 'needs_review');

      // 4. OpenUI brief compilation across all languages & states with 0 schema errors
      for (const lang of ['en', 'pt', 'es'] as const) {
        controller.setLanguage(lang);
        for (const fid of CANONICAL_FIXTURE_IDS) {
          await controller.selectFixture(fid);
          const compiled = compilePatchCatOpenUiBrief(controller.getState());
          assert.equal(compiled.errorCount, 0);
          assert.equal(compiled.root?.typeName, 'PolicySummary');
        }
      }

      // 5. Snapshot cache FIFO cap (max 50 entries)
      const internal = controller as unknown as {
        recordMemorySnapshot: (
          a: ReturnType<typeof evaluateLabFixture>,
          j: ReturnType<PatchCatLiveController['getState']>['adjudication'],
          m: 'LAB_DETERMINISTIC'
        ) => void;
      };
      const baseAnalysis = evaluateLabFixture('payments-lab/baseline', {
        now: '2026-11-21T12:00:00.000Z',
      });
      const baseAdj = controller.getState().adjudication;
      for (let i = 0; i < MAX_SNAPSHOT_CACHE + 15; i++) {
        internal.recordMemorySnapshot(
          { ...baseAnalysis, analysisId: `synthetic-analysis-${i}` },
          baseAdj,
          'LAB_DETERMINISTIC'
        );
      }
      assert.equal(controller.getState().memorySnapshots.length, MAX_SNAPSHOT_CACHE);
      assert.equal(
        controller.getState().memorySnapshots.some((s) => s.analysisId === 'synthetic-analysis-0'),
        false
      );
      assert.equal(
        controller.getState().memorySnapshots.some((s) => s.analysisId === `synthetic-analysis-${MAX_SNAPSHOT_CACHE + 14}`),
        true
      );

      // 6. Registered MCP Tools offline fallback aligns with all 14 canonical SECURITY_CAPABILITY_IDS
      const mcpToolsText = dom.root.querySelector('#panel-mcp-tools')?.textContent ?? '';
      for (const expectedTool of [
        'security.status',
        'security.chainbreak.analyze',
        'security.chainbreak.get',
        'security.judge.evaluate',
        'security.remediation.spec',
        'security.audit.start',
        'security.audit.get',
        'security.evidence.get',
        'security.kali.lab_run',
        'security.kali.service_inventory',
        'security.kali.tls_review',
        'security.kali.web_passive_baseline',
        'security.kali.local_code_scan',
        'security.kali.get_run',
      ]) {
        assert.match(mcpToolsText, new RegExp(expectedTool.replace(/\./g, '\\.')));
      }

      // 7. ECMAScript private #secrets non-enumerability & clean runtime audit/toast copy
      controller.saveAiConfig({
        activeProvider: 'openai',
        openaiApiKey: 'sk-test-nonenum-secret-1234',
      });
      controller.setMcpConnectionConfig({ token: 'bearer-nonenum-secret-5678' });
      assert.equal(Object.keys(controller).includes('secrets'), false);
      assert.equal(Object.getOwnPropertyNames(controller).includes('secrets'), false);
      assert.equal('secrets' in controller, false);
      const serializedCtrl = JSON.stringify(controller);
      assert.equal(serializedCtrl.includes('sk-test-nonenum-secret-1234'), false);
      assert.equal(serializedCtrl.includes('bearer-nonenum-secret-5678'), false);

      await controller.runFullScout();
      await controller.viewMemory(true);
      await controller.submitPrReviewGate();
      const runtimeAuditText = controller
        .getState()
        .auditLog.map((entry) => entry.message)
        .join(' | ');
      const runtimeSurfaceText = [
        runtimeAuditText,
        controller.getState().toastMessage ?? '',
        controller.getState().lastActionLabel,
      ].join(' | ');
      for (const codename of ['JEV=', 'ChainBreak + JEV scout', 'Company Brain', 'CompanyBrain', 'factory.delivery.v1']) {
        assert.equal(runtimeSurfaceText.includes(codename), false, `Runtime copy must exclude '${codename}'`);
      }
      assert.match(runtimeSurfaceText, /Human Risk Review/);
      assert.match(runtimeSurfaceText, /Audit History/);
      assert.match(runtimeSurfaceText, /Remediation Bundle/);

      mounted.unmount();
      await controller.close();
    } finally {
      dom.cleanup();
    }
  });
});
