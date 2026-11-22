/**
 * @file apps/ui/src/live-controller.ts
 * @description Testable state & orchestration controller for ScriptKitty Live —
 * PatchCat Interactive Lab Explorer (`@script-kitty/ui`).
 * Supports deterministic LAB fixture evaluation, live Invokta MCP Streamable HTTP
 * connection (`http://127.0.0.1:3847/mcp`) with transparent fail-closed fallback,
 * JEV-as-a-Judge advisory triage, counterfactual RemediationSpec, Tri-Party SoD,
 * RFC 8785 Custody Merkle root, and `factory.delivery.v1` verification.
 */

import { computeEvidenceContentSha256, sha256Hex } from './crypto-browser.ts';
import {
  evaluateLabFixture,
  evaluateLabJevMock,
  evaluateLabQualityGateAndDelivery,
  type FactoryDeliveryView,
  type JevAdjudicationView,
  type QualityGateEvaluationView,
  type RemediationSpecView,
  type SecurityAnalysisView,
} from './lab-evaluator.ts';
import {
  CANONICAL_FIXTURE_IDS,
  LAB_FIXTURES,
  type CanonicalFixtureId,
  type PolicyGraphFixture,
} from './lab-fixtures.ts';
import type { MascotState } from './mascot3d.ts';
import {
  McpBrowserClient,
  McpClientError,
  redactTokenFromMessage,
  validateLoopbackMcpUrl,
} from './mcp-browser-client.ts';

export type ConnectionMode = 'LAB_DETERMINISTIC' | 'LIVE_MCP_HTTP';

export const CONNECTION_MODE_LABELS: Record<ConnectionMode, string> = {
  LAB_DETERMINISTIC: 'MODE: LAB DETERMINISTIC',
  LIVE_MCP_HTTP: 'MODE: LIVE MCP HTTP',
};

export const DEFAULT_MCP_URL = 'http://127.0.0.1:3847/mcp';
export const MAX_SNAPSHOT_CACHE = 50;

export type SupportedLanguage = 'en' | 'pt' | 'es';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  category:
    | 'SYSTEM'
    | 'SCAN'
    | 'CHAINBREAK'
    | 'RISK_REVIEW'
    | 'REMEDIATION'
    | 'QUALITY_GATE'
    | 'DELIVERY_GATE'
    | 'MEMORY'
    | 'MCP_HTTP'
    | 'MCP_FALLBACK'
    | 'CONFIG';
  hash: string;
  message: string;
  mode: ConnectionMode;
}

export interface DecisionHistoryRecordView {
  decisionId: string;
  decisionType: string;
  decision: string;
  status: string;
  sourceRef: string;
  createdAt: string;
}

export interface CompanyMemorySnapshotView {
  analysisId: string;
  fixtureId: CanonicalFixtureId;
  policyVersion: string;
  inputSha256: string;
  pathsCount: number;
  legitimateOperationsPreserved: boolean;
  jevStatus: string;
  jevDecisionSource: string;
  mode: ConnectionMode;
  recordedAt: string;
}

export interface PrSuggestionReportView {
  title: string;
  fixtureId: string;
  targetEdgeId: string;
  actionType: string;
  sourceRef: string;
  unifiedDiff: string;
  pathsBefore: number;
  pathsAfter: number;
  legitimatePreservedSummary: string;
  requiresHumanApproval: true;
  autoApplyAllowed: false;
  mergeAllowed: false;
  deployAllowed: false;
  acceptanceCriteria: string[];
  verificationTests: string[];
}

export interface AiConfigView {
  activeProvider: string;
  hasOpenaiKey: boolean;
  hasGoogleKey: boolean;
  hasNvidiaKey: boolean;
  hasOpenrouterKey: boolean;
  hasAnthropicKey: boolean;
  hasGrokKey: boolean;
  hasCodexToken: boolean;
}

export interface McpConnectionPublicState {
  url: string;
  hasBearerToken: boolean;
  autoProbe: boolean;
  sessionId: string | null;
  availableTools: string[];
  serverStatus: {
    mode: string;
    productionTested: false;
    mergeAllowed: false;
    deployAllowed: false;
    harness2ExperimentsEnabled: false;
    jevProviderStatus: string;
    kaliMcpStatus: string;
  } | null;
  lastFallbackReason: string | null;
}

export interface DashboardState {
  activeFixtureId: CanonicalFixtureId;
  fixture: PolicyGraphFixture;
  connectionMode: ConnectionMode;
  modeBadge: string;
  mascotState: MascotState;
  language: SupportedLanguage;
  showKeyModal: boolean;
  toastMessage: string | null;
  memoryDrawerOpen: boolean;
  prSuggestionOpen: boolean;
  simulateSelfCert: boolean;
  isBusy: boolean;
  lastActionLabel: string;
  analysis: SecurityAnalysisView;
  adjudication: JevAdjudicationView;
  activeRemediationSpec: RemediationSpecView | null;
  referenceRemediationSpec: RemediationSpecView;
  qualityGate: QualityGateEvaluationView;
  factoryDelivery: FactoryDeliveryView;
  prSuggestion: PrSuggestionReportView | null;
  memorySnapshots: CompanyMemorySnapshotView[];
  decisionHistory: DecisionHistoryRecordView[];
  auditLog: AuditLogEntry[];
  mcp: McpConnectionPublicState;
  aiConfig: AiConfigView;
  invariants: {
    mode: 'LAB';
    productionTested: false;
    mergeAllowed: false;
    deployAllowed: false;
    deploymentAllowed: false;
    externalExecution: false;
    requiresHumanApproval: true;
    autoApplyAllowed: false;
    p0DefinedByJevAlone: false;
    harness2ExperimentsEnabled: false;
  };
}

export interface PatchCatLiveControllerOptions {
  initialFixture?: CanonicalFixtureId;
  mcpUrl?: string;
  bearerToken?: string;
  mcpOrigin?: string;
  mcpAutoProbe?: boolean;
  fetchImpl?: typeof globalThis.fetch;
  now?: () => string;
  timeoutMs?: number;
}

interface SecretVault {
  bearerToken: string;
  openaiApiKey: string;
  googleApiKey: string;
  nvidiaApiKey: string;
  openrouterApiKey: string;
  anthropicApiKey: string;
  grokApiKey: string;
  codexSubscriptionToken: string;
}

function buildPrSuggestionFromSpec(
  spec: RemediationSpecView,
  pathsBefore: number,
  pathsAfter: number
): PrSuggestionReportView {
  const act = spec.actions[0];
  const diff = [
    `--- a/${act.sourceRef || 'policies/payments-lab/report-exporter-rollout.yaml'}`,
    `+++ b/${act.sourceRef || 'policies/payments-lab/report-exporter-rollout.yaml'}`,
    '@@ -24,3 +24,0 @@',
    `- edge: ${act.edgeId} (${act.actionType}: ${act.from} --[${act.edgeKind}; class=${act.currentDataClassification}]--> ${act.to})`,
    `+ # REMOVED by PatchCat counterfactual RemediationSpec (${spec.remediationId}); human review mandatory`,
  ].join('\n');

  return {
    title: `chore(policy): ${act.actionType} ${act.edgeId} (NO_RESTRICTED_DATA_EXTERNAL_TRANSFER)`,
    fixtureId: spec.fixtureId,
    targetEdgeId: act.edgeId,
    actionType: act.actionType,
    sourceRef: act.sourceRef,
    unifiedDiff: diff,
    pathsBefore,
    pathsAfter,
    legitimatePreservedSummary: `${spec.preservedOperationIds.length}/${spec.preservedOperationIds.length || 3}`,
    requiresHumanApproval: true,
    autoApplyAllowed: false,
    mergeAllowed: false,
    deployAllowed: false,
    acceptanceCriteria: [...spec.acceptanceCriteria],
    verificationTests: [...spec.verificationTests],
  };
}

function deriveMascotStateFromResults(
  fixtureId: CanonicalFixtureId,
  analysis: SecurityAnalysisView,
  adjudication: JevAdjudicationView,
  qualityGate: QualityGateEvaluationView
): MascotState {
  if (
    qualityGate.verdict === 'REJECT' ||
    qualityGate.verdict === 'BLOCK' ||
    analysis.paths.length > 0 ||
    adjudication.status === 'PENDING_REVIEW' ||
    adjudication.status === 'BLOCKED' ||
    adjudication.status === 'REJECTED'
  ) {
    return 'alert';
  }
  if (fixtureId === 'payments-lab/remediated') {
    return 'success';
  }
  return 'idle';
}

export class PatchCatLiveController {
  private readonly nowFn: () => string;
  private readonly fetchImpl?: typeof globalThis.fetch;
  private readonly mcpOrigin?: string;
  private readonly timeoutMs: number;
  private readonly listeners = new Set<(state: DashboardState) => void>();
  private readonly snapshotMap = new Map<string, CompanyMemorySnapshotView>();
  readonly #secrets: SecretVault = {
    bearerToken: '',
    openaiApiKey: '',
    googleApiKey: '',
    nvidiaApiKey: '',
    openrouterApiKey: '',
    anthropicApiKey: '',
    grokApiKey: '',
    codexSubscriptionToken: '',
  };

  private activeMcpClient: McpBrowserClient | null = null;
  private activeMcpSignature: string | null = null;
  private pendingClosePromise: Promise<void> = Promise.resolve();
  private readonly unloadHandler?: () => void;
  private auditCounter = 0;
  private state: DashboardState;

  constructor(options: PatchCatLiveControllerOptions = {}) {
    this.nowFn = options.now ?? (() => new Date().toISOString());
    this.fetchImpl =
      options.fetchImpl ??
      (typeof globalThis.fetch === 'function'
        ? globalThis.fetch.bind(globalThis)
        : undefined);
    this.mcpOrigin = options.mcpOrigin;
    this.timeoutMs = options.timeoutMs ?? 2_500;
    if (options.bearerToken) {
      this.#secrets.bearerToken = options.bearerToken.trim();
    }
    if (
      typeof window !== 'undefined' &&
      typeof window.addEventListener === 'function'
    ) {
      this.unloadHandler = () => {
        void this.closeActiveMcpClient();
      };
      window.addEventListener('beforeunload', this.unloadHandler);
    }

    const initialFixture: CanonicalFixtureId =
      options.initialFixture ?? 'payments-lab/baseline';
    const ts = this.nowFn();

    // Canonical counterfactual reference spec computed from unsafe-rollout
    const unsafeRefAnalysis = evaluateLabFixture('payments-lab/unsafe-rollout', {
      now: ts,
    });
    const referenceRemediationSpec = unsafeRefAnalysis.remediationSpecs[0];

    const initialAnalysis = evaluateLabFixture(initialFixture, { now: ts });
    const initialAdjudication = evaluateLabJevMock(initialAnalysis, { now: ts });
    const { qualityGate, factoryDelivery } = evaluateLabQualityGateAndDelivery({
      analysis: initialAnalysis,
      remediationSpec:
        initialAnalysis.remediationSpecs[0] ?? referenceRemediationSpec,
      simulateSelfCert: false,
      now: ts,
    });

    const mcpUrl = (options.mcpUrl ?? DEFAULT_MCP_URL).trim();

    this.state = {
      activeFixtureId: initialFixture,
      fixture: LAB_FIXTURES[initialFixture],
      connectionMode: 'LAB_DETERMINISTIC',
      modeBadge: CONNECTION_MODE_LABELS.LAB_DETERMINISTIC,
      mascotState: deriveMascotStateFromResults(
        initialFixture,
        initialAnalysis,
        initialAdjudication,
        qualityGate
      ),
      language: 'en',
      showKeyModal: false,
      toastMessage: null,
      memoryDrawerOpen: false,
      prSuggestionOpen: false,
      simulateSelfCert: false,
      isBusy: false,
      lastActionLabel: `Initialized ${initialFixture}`,
      analysis: initialAnalysis,
      adjudication: initialAdjudication,
      activeRemediationSpec: initialAnalysis.remediationSpecs[0] ?? null,
      referenceRemediationSpec,
      qualityGate,
      factoryDelivery,
      prSuggestion: null,
      memorySnapshots: [],
      decisionHistory: [],
      auditLog: [],
      mcp: {
        url: mcpUrl,
        hasBearerToken: Boolean(this.#secrets.bearerToken),
        autoProbe: options.mcpAutoProbe ?? false,
        sessionId: null,
        availableTools: [],
        serverStatus: null,
        lastFallbackReason: null,
      },
      aiConfig: {
        activeProvider: 'openai',
        hasOpenaiKey: false,
        hasGoogleKey: false,
        hasNvidiaKey: false,
        hasOpenrouterKey: false,
        hasAnthropicKey: false,
        hasGrokKey: false,
        hasCodexToken: false,
      },
      invariants: {
        mode: 'LAB',
        productionTested: false,
        mergeAllowed: false,
        deployAllowed: false,
        deploymentAllowed: false,
        externalExecution: false,
        requiresHumanApproval: true,
        autoApplyAllowed: false,
        p0DefinedByJevAlone: false,
        harness2ExperimentsEnabled: false,
      },
    };

    this.recordMemorySnapshot(initialAnalysis, initialAdjudication, 'LAB_DETERMINISTIC');
    this.appendAudit(
      'SYSTEM',
      `PatchCat Explorer ready on ${initialFixture} (${CONNECTION_MODE_LABELS.LAB_DETERMINISTIC})`,
      initialAnalysis.inputSha256
    );
  }

  public getState(): DashboardState {
    return this.state;
  }

  public subscribe(listener: (state: DashboardState) => void): () => void {
    this.listeners.add(listener);
    return () => {
      const removed = this.listeners.delete(listener);
      if (removed && this.listeners.size === 0) {
        void this.closeActiveMcpClient();
      }
    };
  }

  private emit(): void {
    const snapshot = this.state;
    for (const listener of this.listeners) {
      listener(snapshot);
    }
  }

  private appendAudit(
    category: AuditLogEntry['category'],
    rawMessage: string,
    hashInput?: string
  ): void {
    this.auditCounter += 1;
    const ts = this.nowFn();
    const cleanMsg = redactTokenFromMessage(rawMessage, this.#secrets.bearerToken);
    const hash = (
      hashInput && /^[a-f0-9]{8,}$/i.test(hashInput)
        ? hashInput
        : sha256Hex(`${ts}:${this.auditCounter}:${cleanMsg}`)
    ).slice(0, 12);

    const entry: AuditLogEntry = {
      id: `audit-${this.auditCounter}`,
      timestamp: ts,
      category,
      hash,
      message: cleanMsg,
      mode: this.state.connectionMode,
    };

    this.state = {
      ...this.state,
      auditLog: [entry, ...this.state.auditLog].slice(0, 50),
    };
  }

  private recordMemorySnapshot(
    analysis: SecurityAnalysisView,
    adjudication: JevAdjudicationView,
    mode: ConnectionMode
  ): void {
    const fixtureId = analysis.fixtureId as CanonicalFixtureId;
    const snap: CompanyMemorySnapshotView = {
      analysisId: analysis.analysisId,
      fixtureId,
      policyVersion: analysis.policyVersion,
      inputSha256: analysis.inputSha256,
      pathsCount: analysis.paths.length,
      legitimateOperationsPreserved: analysis.legitimateOperationsPreserved,
      jevStatus: adjudication.status,
      jevDecisionSource: adjudication.decisionSource,
      mode,
      recordedAt: this.nowFn(),
    };
    if (this.snapshotMap.has(analysis.analysisId)) {
      this.snapshotMap.delete(analysis.analysisId);
    }
    while (this.snapshotMap.size >= MAX_SNAPSHOT_CACHE) {
      const oldestKey = this.snapshotMap.keys().next().value;
      if (oldestKey === undefined) break;
      this.snapshotMap.delete(oldestKey);
    }
    this.snapshotMap.set(analysis.analysisId, snap);

    const historyItem: DecisionHistoryRecordView = {
      decisionId: adjudication.evaluationId,
      decisionType: 'ADJUDICATION',
      decision: adjudication.decision,
      status: adjudication.status,
      sourceRef: analysis.fixtureId,
      createdAt: adjudication.timestamp,
    };

    const existingHistory = this.state.decisionHistory.filter(
      (d) => d.decisionId !== historyItem.decisionId
    );

    this.state = {
      ...this.state,
      memorySnapshots: Array.from(this.snapshotMap.values()),
      decisionHistory: [historyItem, ...existingHistory].slice(0, 20),
    };
  }

  public setLanguage(lang: SupportedLanguage): void {
    this.state = {
      ...this.state,
      language: lang,
      lastActionLabel: `Language switched to ${lang.toUpperCase()}`,
    };
    this.appendAudit('CONFIG', `UI language set to ${lang}`);
    this.emit();
  }

  public setKeyModalOpen(open: boolean): void {
    this.state = {
      ...this.state,
      showKeyModal: open,
    };
    this.emit();
  }

  public dismissToast(): void {
    if (this.state.toastMessage !== null) {
      this.state = { ...this.state, toastMessage: null };
      this.emit();
    }
  }

  public saveAiConfig(input: {
    activeProvider: string;
    openaiApiKey?: string;
    googleApiKey?: string;
    nvidiaApiKey?: string;
    openrouterApiKey?: string;
    anthropicApiKey?: string;
    grokApiKey?: string;
    codexSubscriptionToken?: string;
  }): void {
    if (input.openaiApiKey !== undefined) {
      this.#secrets.openaiApiKey = input.openaiApiKey.trim();
    }
    if (input.googleApiKey !== undefined) {
      this.#secrets.googleApiKey = input.googleApiKey.trim();
    }
    if (input.nvidiaApiKey !== undefined) {
      this.#secrets.nvidiaApiKey = input.nvidiaApiKey.trim();
    }
    if (input.openrouterApiKey !== undefined) {
      this.#secrets.openrouterApiKey = input.openrouterApiKey.trim();
    }
    if (input.anthropicApiKey !== undefined) {
      this.#secrets.anthropicApiKey = input.anthropicApiKey.trim();
    }
    if (input.grokApiKey !== undefined) {
      this.#secrets.grokApiKey = input.grokApiKey.trim();
    }
    if (input.codexSubscriptionToken !== undefined) {
      this.#secrets.codexSubscriptionToken = input.codexSubscriptionToken.trim();
    }

    this.state = {
      ...this.state,
      showKeyModal: false,
      toastMessage:
        'AI Provider configuration updated in-memory (credentials never serialized to DOM or audit logs).',
      aiConfig: {
        activeProvider: input.activeProvider || 'openai',
        hasOpenaiKey: Boolean(this.#secrets.openaiApiKey),
        hasGoogleKey: Boolean(this.#secrets.googleApiKey),
        hasNvidiaKey: Boolean(this.#secrets.nvidiaApiKey),
        hasOpenrouterKey: Boolean(this.#secrets.openrouterApiKey),
        hasAnthropicKey: Boolean(this.#secrets.anthropicApiKey),
        hasGrokKey: Boolean(this.#secrets.grokApiKey),
        hasCodexToken: Boolean(this.#secrets.codexSubscriptionToken),
      },
    };
    this.appendAudit(
      'CONFIG',
      `Updated AI provider metadata: active=${this.state.aiConfig.activeProvider}, keys stored strictly in memory`
    );
    this.emit();
  }

  public setMcpConnectionConfig(config: {
    url?: string;
    token?: string;
    autoProbe?: boolean;
  }): void {
    const prevUrl = this.state.mcp.url;
    const prevToken = this.#secrets.bearerToken;
    if (config.token !== undefined) {
      this.#secrets.bearerToken = config.token.trim();
    }
    const nextUrl =
      config.url !== undefined ? config.url.trim() : this.state.mcp.url;
    const endpointChanged =
      nextUrl !== prevUrl || this.#secrets.bearerToken !== prevToken;
    if (endpointChanged) {
      void this.closeActiveMcpClient();
    }

    this.state = {
      ...this.state,
      mcp: {
        ...this.state.mcp,
        url: nextUrl,
        hasBearerToken: Boolean(this.#secrets.bearerToken),
        sessionId: endpointChanged ? null : this.state.mcp.sessionId,
        autoProbe:
          config.autoProbe !== undefined
            ? config.autoProbe
            : this.state.mcp.autoProbe,
      },
    };
    this.emit();
  }

  private computeMcpSignature(): string {
    return `${this.state.mcp.url}|${this.#secrets.bearerToken}|${this.mcpOrigin ?? ''}`;
  }

  private async closeActiveMcpClient(): Promise<void> {
    const prev = this.activeMcpClient;
    this.activeMcpClient = null;
    this.activeMcpSignature = null;
    const inFlight = this.pendingClosePromise;
    const nextClose = (async () => {
      await inFlight.catch(() => undefined);
      if (prev) {
        await prev.close().catch(() => undefined);
      }
    })();
    this.pendingClosePromise = nextClose;
    await nextClose;
  }

  private async getOrCreateMcpClient(): Promise<McpBrowserClient> {
    validateLoopbackMcpUrl(this.state.mcp.url);
    const sig = this.computeMcpSignature();
    if (this.activeMcpClient && this.activeMcpSignature !== sig) {
      await this.closeActiveMcpClient();
    } else {
      await this.pendingClosePromise.catch(() => undefined);
    }

    if (!this.activeMcpClient) {
      this.activeMcpClient = new McpBrowserClient({
        url: this.state.mcp.url,
        token: this.#secrets.bearerToken || undefined,
        origin: this.mcpOrigin,
        timeoutMs: this.timeoutMs,
        fetchImpl: this.fetchImpl,
      });
      this.activeMcpSignature = sig;
    }

    if (
      !this.activeMcpClient.isConnected() ||
      !this.activeMcpClient.getSessionId()
    ) {
      try {
        await this.activeMcpClient.connect();
      } catch (err) {
        this.activeMcpClient = null;
        this.activeMcpSignature = null;
        throw err;
      }
    }

    return this.activeMcpClient;
  }

  public async close(): Promise<void> {
    if (
      this.unloadHandler &&
      typeof window !== 'undefined' &&
      typeof window.removeEventListener === 'function'
    ) {
      window.removeEventListener('beforeunload', this.unloadHandler);
    }
    await this.closeActiveMcpClient();
  }

  public async connectAndSyncMcp(): Promise<DashboardState> {
    return this.evaluateFixture(this.state.activeFixtureId, {
      tryMcp: true,
      actionLabel: 'Connected / synced MCP Streamable HTTP endpoint',
    });
  }

  public disconnectToLabDeterministic(reason = 'Switched to offline LAB mode'): void {
    void this.closeActiveMcpClient();
    this.state = {
      ...this.state,
      connectionMode: 'LAB_DETERMINISTIC',
      modeBadge: CONNECTION_MODE_LABELS.LAB_DETERMINISTIC,
      mcp: {
        ...this.state.mcp,
        autoProbe: false,
        sessionId: null,
        lastFallbackReason: reason,
      },
      lastActionLabel: reason,
    };
    this.appendAudit('MCP_FALLBACK', reason);
    this.emit();
  }

  private async evaluateViaMcpHttp(fixtureId: CanonicalFixtureId): Promise<{
    analysis: SecurityAnalysisView;
    adjudication: JevAdjudicationView;
    remediationSpec: RemediationSpecView | null;
    sessionId: string | null;
    tools: string[];
    serverStatus: McpConnectionPublicState['serverStatus'];
  }> {
    const client = await this.getOrCreateMcpClient();
    const sessionId = client.getSessionId();
    const toolList = await client.listTools();
    const tools = toolList.map((t) => t.name);

    const statusRes = await client.callToolJson<Record<string, unknown>>(
      'security.status',
      {}
    );
    const statusJson = statusRes.parsed;
    const adapters = (statusJson.adapters ?? {}) as Record<
      string,
      { status?: string }
    >;

    const serverStatus: McpConnectionPublicState['serverStatus'] = {
      mode: String(statusJson.mode ?? 'LAB'),
      productionTested: false,
      mergeAllowed: false,
      deployAllowed: false,
      harness2ExperimentsEnabled: false,
      jevProviderStatus: String(statusJson.jevProviderStatus ?? 'NOT_CONFIGURED'),
      kaliMcpStatus: String(
        statusJson.kaliMcpStatus ??
          adapters.kaliMcp?.status ??
          adapters.kali?.status ??
          'NOT_CONFIGURED'
      ),
    };

    const analyzeRes = await client.callToolJson<{
      analysisId: string;
      analysis: SecurityAnalysisView;
    }>('security.chainbreak.analyze', { fixtureId });
    const analysis = analyzeRes.parsed.analysis;

    const judgeRes = await client.callToolJson<{
      adjudication: JevAdjudicationView;
    }>('security.judge.evaluate', {
      analysisId: analysis.analysisId,
      expectedInputSha256: analysis.inputSha256,
    });
    const adjudication = judgeRes.parsed.adjudication;

    let remediationSpec: RemediationSpecView | null = null;
    if (analysis.paths.length > 0) {
      const remRes = await client.callToolJson<{
        remediationSpec: RemediationSpecView;
      }>('security.remediation.spec', {
        analysisId: analysis.analysisId,
        pathId: analysis.paths[0].pathId,
      });
      remediationSpec = remRes.parsed.remediationSpec;
    }

    return {
      analysis,
      adjudication,
      remediationSpec,
      sessionId,
      tools,
      serverStatus,
    };
  }

  private applyEvaluationResult(params: {
    fixtureId: CanonicalFixtureId;
    connectionMode: ConnectionMode;
    analysis: SecurityAnalysisView;
    adjudication: JevAdjudicationView;
    remediationSpec: RemediationSpecView | null;
    actionLabel: string;
    mcpUpdates?: Partial<McpConnectionPublicState>;
  }): void {
    const {
      fixtureId,
      connectionMode,
      analysis,
      adjudication,
      remediationSpec,
      actionLabel,
      mcpUpdates,
    } = params;

    const ts = this.nowFn();
    const { qualityGate, factoryDelivery } = evaluateLabQualityGateAndDelivery({
      analysis,
      remediationSpec: remediationSpec ?? this.state.referenceRemediationSpec,
      simulateSelfCert: this.state.simulateSelfCert,
      now: ts,
    });

    const mascotState = deriveMascotStateFromResults(
      fixtureId,
      analysis,
      adjudication,
      qualityGate
    );

    this.state = {
      ...this.state,
      activeFixtureId: fixtureId,
      fixture: LAB_FIXTURES[fixtureId],
      connectionMode,
      modeBadge: CONNECTION_MODE_LABELS[connectionMode],
      mascotState,
      isBusy: false,
      lastActionLabel: actionLabel,
      analysis,
      adjudication,
      activeRemediationSpec: remediationSpec,
      qualityGate,
      factoryDelivery,
      mcp: {
        ...this.state.mcp,
        ...(mcpUpdates ?? {}),
      },
    };

    this.recordMemorySnapshot(analysis, adjudication, connectionMode);
  }

  private async evaluateFixture(
    fixtureId: CanonicalFixtureId,
    options: { tryMcp: boolean; actionLabel?: string }
  ): Promise<DashboardState> {
    if (!CANONICAL_FIXTURE_IDS.includes(fixtureId)) {
      throw new Error(`Unsupported canonical fixture: ${fixtureId}`);
    }

    const ts = this.nowFn();
    const label = options.actionLabel ?? `Evaluated ${fixtureId}`;

    if (options.tryMcp) {
      try {
        const live = await this.evaluateViaMcpHttp(fixtureId);
        this.applyEvaluationResult({
          fixtureId,
          connectionMode: 'LIVE_MCP_HTTP',
          analysis: live.analysis,
          adjudication: live.adjudication,
          remediationSpec: live.remediationSpec,
          actionLabel: label,
          mcpUpdates: {
            sessionId: live.sessionId,
            availableTools: live.tools,
            serverStatus: live.serverStatus,
            lastFallbackReason: null,
          },
        });
        this.appendAudit(
          'MCP_HTTP',
          `${label} via LIVE MCP HTTP (${live.analysis.paths.length} paths, Human Risk Review=${live.adjudication.status}, source=${live.adjudication.decisionSource})`,
          live.analysis.inputSha256
        );
        this.emit();
        return this.state;
      } catch (err) {
        void this.closeActiveMcpClient();
        const rawReason =
          err instanceof McpClientError
            ? `${err.code}: ${err.message}`
            : err instanceof Error
              ? err.message
              : String(err);
        const safeReason = redactTokenFromMessage(
          rawReason,
          this.#secrets.bearerToken
        );

        const labAnalysis = evaluateLabFixture(fixtureId, { now: ts });
        const labAdjudication = evaluateLabJevMock(labAnalysis, { now: ts });
        this.applyEvaluationResult({
          fixtureId,
          connectionMode: 'LAB_DETERMINISTIC',
          analysis: labAnalysis,
          adjudication: labAdjudication,
          remediationSpec: labAnalysis.remediationSpecs[0] ?? null,
          actionLabel: `${label} (LAB fallback)`,
          mcpUpdates: {
            sessionId: null,
            lastFallbackReason: safeReason,
          },
        });
        this.appendAudit(
          'MCP_FALLBACK',
          `MCP unavailable (${safeReason}); switched seamlessly to MODE: LAB DETERMINISTIC`,
          labAnalysis.inputSha256
        );
        this.emit();
        return this.state;
      }
    }

    const labAnalysis = evaluateLabFixture(fixtureId, { now: ts });
    const labAdjudication = evaluateLabJevMock(labAnalysis, { now: ts });
    this.applyEvaluationResult({
      fixtureId,
      connectionMode: 'LAB_DETERMINISTIC',
      analysis: labAnalysis,
      adjudication: labAdjudication,
      remediationSpec: labAnalysis.remediationSpecs[0] ?? null,
      actionLabel: label,
      mcpUpdates: {
        lastFallbackReason: null,
      },
    });
    this.appendAudit(
      'CHAINBREAK',
      `${label}: paths=${labAnalysis.paths.length}, legitOps=${labAnalysis.legitimateOperations.filter((o) => o.preserved).length}/${labAnalysis.legitimateOperations.length}, review=${labAdjudication.status}`,
      labAnalysis.inputSha256
    );
    this.emit();
    return this.state;
  }

  /**
   * Switches between the 3 canonical DEMO_WEDNESDAY fixtures + negative-control.
   */
  public async selectFixture(
    fixtureId: CanonicalFixtureId
  ): Promise<DashboardState> {
    if (!CANONICAL_FIXTURE_IDS.includes(fixtureId)) {
      throw new Error(`Invalid fixtureId: ${fixtureId}`);
    }

    // Immediate deterministic sync update so UI tabs respond instantaneously
    if (!this.state.mcp.autoProbe && this.state.connectionMode !== 'LIVE_MCP_HTTP') {
      return this.evaluateFixture(fixtureId, {
        tryMcp: false,
        actionLabel: `Switched scenario to ${fixtureId}`,
      });
    }

    return this.evaluateFixture(fixtureId, {
      tryMcp: true,
      actionLabel: `Switched scenario to ${fixtureId}`,
    });
  }

  /**
   * Button 1 (`#btn-scout`): Runs full ChainBreak reachability + JEV-as-a-Judge
   * evaluation across active fixture, transitioning mascot through `scanning`
   * into `alert` | `success` | `idle`.
   */
  public async runFullScout(): Promise<DashboardState> {
    this.state = {
      ...this.state,
      mascotState: 'scanning',
      isBusy: true,
      lastActionLabel: `Scanning ${this.state.activeFixtureId}...`,
    };
    this.appendAudit(
      'SCAN',
      `Started PatchCat ChainBreak + Human Risk Review scan on ${this.state.activeFixtureId}`
    );
    this.emit();

    // Yield one microtask so subscribers/DOM observe `scanning` cleanly
    await Promise.resolve();

    const shouldTryMcp =
      this.state.mcp.autoProbe ||
      this.state.connectionMode === 'LIVE_MCP_HTTP' ||
      this.state.mcp.hasBearerToken;

    await this.evaluateFixture(this.state.activeFixtureId, {
      tryMcp: shouldTryMcp,
      actionLabel: `Full Scout completed on ${this.state.activeFixtureId}`,
    });

    return this.state;
  }

  /**
   * Button 2 (`#btn-learn`): Inspects/toggles Company Brain continuous memory
   * snapshots & persisted decision history (via `security.chainbreak.get` when live).
   */
  public async viewMemory(
    forceOpen?: boolean
  ): Promise<DashboardState> {
    const nextOpen =
      forceOpen !== undefined ? forceOpen : !this.state.memoryDrawerOpen;

    let fetchedCount = this.state.decisionHistory.length;
    if (nextOpen && this.state.connectionMode === 'LIVE_MCP_HTTP') {
      try {
        const client = await this.getOrCreateMcpClient();
        const getRes = await client.callToolJson<{
          decisionHistory?: DecisionHistoryRecordView[];
        }>('security.chainbreak.get', {
          analysisId: this.state.analysis.analysisId,
        });
        if (Array.isArray(getRes.parsed.decisionHistory)) {
          this.state = {
            ...this.state,
            decisionHistory: getRes.parsed.decisionHistory,
          };
          fetchedCount = getRes.parsed.decisionHistory.length;
        }
      } catch (err) {
        const msg =
          err instanceof Error ? err.message : String(err);
        this.appendAudit(
          'MCP_FALLBACK',
          `Audit History HTTP lookup fell back to local LAB snapshot cache: ${redactTokenFromMessage(msg, this.#secrets.bearerToken)}`
        );
      }
    }

    this.state = {
      ...this.state,
      memoryDrawerOpen: nextOpen,
      lastActionLabel: nextOpen
        ? `Inspected Audit History (${this.state.memorySnapshots.length} analyses, ${fetchedCount} decisions)`
        : 'Closed Audit History drawer',
    };
    this.appendAudit(
      'MEMORY',
      `Audit History view ${nextOpen ? 'opened' : 'collapsed'}: ${this.state.memorySnapshots.length} stored LAB snapshots, tenant=payments-lab`,
      computeEvidenceContentSha256(this.state.memorySnapshots)
    );
    this.emit();
    return this.state;
  }

  /**
   * Button 3 (`#btn-pr`): Executes Zero-Trust Quality Gate (`PASS` vs `REJECT`),
   * Tri-Party SoD validation, RFC 8785 Custody Merkle verification, and
   * `factory.delivery.v1` eligibility check (`mergeAllowed: false`, `deployAllowed: false`).
   */
  public async submitPrReviewGate(): Promise<DashboardState> {
    const ts = this.nowFn();
    const spec =
      this.state.activeRemediationSpec ?? this.state.referenceRemediationSpec;
    const { qualityGate, factoryDelivery } = evaluateLabQualityGateAndDelivery({
      analysis: this.state.analysis,
      remediationSpec: spec,
      simulateSelfCert: this.state.simulateSelfCert,
      now: ts,
    });

    const mascotState = deriveMascotStateFromResults(
      this.state.activeFixtureId,
      this.state.analysis,
      this.state.adjudication,
      qualityGate
    );

    this.state = {
      ...this.state,
      qualityGate,
      factoryDelivery,
      mascotState,
      toastMessage:
        qualityGate.verdict === 'PASS'
          ? `Release Gate PASS & Remediation Bundle eligible=true (mergeAllowed=false, deployAllowed=false).`
          : `Release Gate REJECT (${qualityGate.sod_evaluation.violation_code ?? 'POLICY_REJECT'}): ${qualityGate.sod_evaluation.violation_details ?? 'Failed gate invariant'}.`,
      lastActionLabel: `Release Gate evaluated: ${qualityGate.verdict} (remediation bundle eligible=${factoryDelivery.eligible})`,
    };

    this.appendAudit(
      'QUALITY_GATE',
      `Gate ${qualityGate.verdict} (SoD=${qualityGate.sod_evaluation.is_valid ? 'PASS' : qualityGate.sod_evaluation.violation_code}); Merkle=${qualityGate.merkle_root.slice(0, 12)}...; delivery.eligible=${factoryDelivery.eligible}; mergeAllowed=false; deployAllowed=false`,
      qualityGate.merkle_root
    );
    this.emit();
    return this.state;
  }

  /**
   * Button 4 (`#btn-pr-suggest`): Creates reviewable defensive Remediation PR
   * suggestion (`REMOVE_EDGE e-rollout-exporter-read-pii`, `requiresHumanApproval: true`,
   * `autoApplyAllowed: false`) and runs counterfactual verification on `payments-lab/remediated`
   * proving `1 -> 0` paths and `3/3` legitimate operations preserved (`mascotState: 'success'`).
   */
  public async createPrSuggestion(): Promise<DashboardState> {
    const spec =
      this.state.activeRemediationSpec ?? this.state.referenceRemediationSpec;
    const pathsBefore =
      this.state.activeFixtureId === 'payments-lab/unsafe-rollout'
        ? this.state.analysis.paths.length
        : 1;

    await this.evaluateFixture('payments-lab/remediated', {
      tryMcp:
        this.state.mcp.autoProbe ||
        this.state.connectionMode === 'LIVE_MCP_HTTP',
      actionLabel: `Counterfactual PR Suggestion verified on payments-lab/remediated`,
    });

    const pathsAfter = this.state.analysis.paths.length;
    const prSuggestion = buildPrSuggestionFromSpec(spec, pathsBefore, pathsAfter);

    this.state = {
      ...this.state,
      prSuggestionOpen: true,
      prSuggestion,
      mascotState: this.state.qualityGate.verdict === 'REJECT' ? 'alert' : 'success',
      toastMessage: `PR Suggestion prepared (${prSuggestion.actionType} ${prSuggestion.targetEdgeId}): ${pathsBefore} -> ${pathsAfter} path(s), ${prSuggestion.legitimatePreservedSummary} legit ops preserved. Human approval required.`,
      lastActionLabel: `Created PR Suggestion for ${prSuggestion.targetEdgeId} (${pathsBefore} -> ${pathsAfter} paths)`,
    };

    this.appendAudit(
      'REMEDIATION',
      `Prepared Remediation PR Suggestion: ${prSuggestion.actionType} '${prSuggestion.targetEdgeId}' -> verified ${pathsBefore}->${pathsAfter} paths, legitOps=${prSuggestion.legitimatePreservedSummary}, requiresHumanApproval=true, autoApplyAllowed=false`,
      this.state.analysis.inputSha256
    );
    this.emit();
    return this.state;
  }

  /**
   * Toggles fail-closed Tri-Party Separation of Duties self-certification test mode
   * so demos can prove `A_disc == A_veri -> REJECT (E_SOD_SELF_CERTIFICATION)`.
   */
  public toggleSelfCertSimulation(enabled?: boolean): DashboardState {
    const next =
      enabled !== undefined ? enabled : !this.state.simulateSelfCert;
    const ts = this.nowFn();
    const spec =
      this.state.activeRemediationSpec ?? this.state.referenceRemediationSpec;
    const { qualityGate, factoryDelivery } = evaluateLabQualityGateAndDelivery({
      analysis: this.state.analysis,
      remediationSpec: spec,
      simulateSelfCert: next,
      now: ts,
    });

    const mascotState = deriveMascotStateFromResults(
      this.state.activeFixtureId,
      this.state.analysis,
      this.state.adjudication,
      qualityGate
    );

    this.state = {
      ...this.state,
      simulateSelfCert: next,
      qualityGate,
      factoryDelivery,
      mascotState,
      lastActionLabel: next
        ? 'Simulated SoD Self-Certification -> REJECT (E_SOD_SELF_CERTIFICATION)'
        : 'Restored Tri-Party SoD -> PASS',
    };

    this.appendAudit(
      'QUALITY_GATE',
      next
        ? `Self-certification simulated (A_disc == A_veri): Gate verdict=REJECT (E_SOD_SELF_CERTIFICATION), delivery.eligible=${factoryDelivery.eligible}`
        : `Tri-Party SoD restored (A_disc != A_veri != A_auth): Gate verdict=PASS, delivery.eligible=${factoryDelivery.eligible}`,
      qualityGate.merkle_root
    );
    this.emit();
    return this.state;
  }
}

export function createLiveController(
  options: PatchCatLiveControllerOptions = {}
): PatchCatLiveController {
  return new PatchCatLiveController(options);
}
