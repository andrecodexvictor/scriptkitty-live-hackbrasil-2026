import './style.css';
import {
  mapMascotStateToPose,
  MotionCatMascot3D,
  renderPatchCatSvg,
  type MascotState,
  type PatchCatPose,
} from './mascot3d';
import {
  renderScenarioGraphSvg,
  VERCEL_SCENARIOS,
  type ScenarioId,
} from './scenarios';

type Lang = 'en' | 'pt';
type Theme = 'dark' | 'light';

const REPO_URL = 'https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026';

const COPY: Record<
  Lang,
  {
    skip: string;
    navHow: string;
    navFeatures: string;
    navTrust: string;
    navConsole: string;
    simBadge: string;
    themeLight: string;
    themeDark: string;
    eyebrow: string;
    heroH1: string;
    heroLead: string;
    ctaExplore: string;
    ctaGithub: string;
    discSynthetic: string;
    discLocks: string;
    poseStripLabel: string;
    postureHeading: string;
    postureSub: string;
    scenariosHeading: string;
    mcpToolsHeading: string;
    mcpToolsNote: string;
    consoleTitle: string;
    consoleDesc: string;
    btnDiff: string;
    btnGate: string;
    graphTitle: string;
    clearBanner: string;
    workflowsTitle: string;
    noWorkflows: string;
    preservedWorkflow: string;
    brokenWorkflow: string;
    fixtureMetadata: string;
    simulationNote: string;
    reviewTitle: string;
    gateTitle: string;
    testSelfCert: string;
    restoreSod: string;
    problemHeading: string;
    problemLead: string;
    howHeading: string;
    howLead: string;
    trustHeading: string;
    trustLead: string;
    statusHeading: string;
    faqHeading: string;
    footerText: string;
  }
> = {
  en: {
    skip: 'Skip to content',
    navHow: 'How It Works',
    navFeatures: 'Capabilities',
    navTrust: 'Boundaries',
    navConsole: 'Scenario Explorer',
    simBadge: 'SIMULATED LAB DATA',
    themeLight: 'Light',
    themeDark: 'Dark',
    eyebrow: 'AUTONOMOUS SECURITY ENGINEERING · LAB PREVIEW',
    heroH1: 'Security that sees the whole attack path.',
    heroLead:
      'ScriptKitty Live pairs deterministic policy-graph reachability (ChainBreak) with PatchCat counterfactual verification and fail-closed MCP access controls before any rollout reaches review.',
    ctaExplore: 'Explore the scenario lab',
    ctaGithub: 'View source on GitHub',
    discSynthetic: 'Laboratory demonstration · Synthetic data · No live targets scanned',
    discLocks: 'Human approval mandatory · Auto-merge locked',
    poseStripLabel: 'PatchCat 5-State Telemetry',
    postureHeading: 'Posture Monitor',
    postureSub: 'Static Scenario Preview',
    scenariosHeading: 'ChainBreak Scenarios',
    mcpToolsHeading: 'Registered MCP Capabilities',
    mcpToolsNote: 'Loopback-only HTTP server runs locally via npm run demo:live',
    consoleTitle: 'ChainBreak Scenario Explorer',
    consoleDesc:
      'Switch between synthetic payment-lab policy states to inspect reachable exposure chains, counterfactual 1-edge diffs, and 3-party release gates.',
    btnDiff: 'Compare Rollout Fix',
    btnGate: 'View Gate Simulation',
    graphTitle: 'Access Reachability Graph',
    clearBanner: 'This scenario has no unauthorized export routes.',
    workflowsTitle: 'Business Workflows',
    noWorkflows: 'This scenario defines no business workflows.',
    preservedWorkflow: 'Preserved',
    brokenWorkflow: 'Broken',
    fixtureMetadata: 'Fixture Metadata',
    simulationNote: 'This example shows the separation-of-duties check. Release approval is outside the simulation.',
    reviewTitle: 'Human Risk Review',
    gateTitle: 'Separation of Duties Simulation',
    testSelfCert: 'Test Self-Cert Guard',
    restoreSod: 'Restore Independent Review',
    problemHeading: 'Why probabilistic scanners miss chained agent risk',
    problemLead:
      'Point-in-time scanners flag isolated lines without proving whether an identity can actually chain an MCP tool to restricted payment data and an external sink.',
    howHeading: 'How deterministic verification works',
    howLead:
      'Every finding passes through explicit graph proof, minimal-diff synthesis, and independent separation of duties.',
    trustHeading: 'Trust and execution boundaries',
    trustLead:
      'ScriptKitty Live runs strictly in LAB mode with non-mutation locks and fail-closed defaults for all unconfigured external providers.',
    statusHeading: 'Honest prototype maturity status',
    faqHeading: 'Frequently asked questions',
    footerText: 'Hack Brasil 2026 · ScriptKitty Live & PatchCat · MIT License · Simulated Lab Data Only',
  },
  pt: {
    skip: 'Ir para o conteúdo',
    navHow: 'Como Funciona',
    navFeatures: 'Capacidades',
    navTrust: 'Limites',
    navConsole: 'Explorador de Cenários',
    simBadge: 'DADOS SIMULADOS DE LAB',
    themeLight: 'Claro',
    themeDark: 'Escuro',
    eyebrow: 'ENGENHARIA DE SEGURANÇA AUTÔNOMA · PRÉVIA DE LAB',
    heroH1: 'Segurança que enxerga o caminho inteiro do ataque.',
    heroLead:
      'ScriptKitty Live combina alcançabilidade determinística em grafos de política (ChainBreak) com verificação contrafactual do PatchCat e controles MCP fail-closed antes de qualquer rollout.',
    ctaExplore: 'Explorar laboratório de cenários',
    ctaGithub: 'Ver código no GitHub',
    discSynthetic: 'Demonstração de laboratório · Dados sintéticos · Nenhum alvo real escaneado',
    discLocks: 'Aprovação humana obrigatória · Auto-merge bloqueado',
    poseStripLabel: 'Telemetria PatchCat em 5 Estados',
    postureHeading: 'Monitor de Postura',
    postureSub: 'Prévia Estática de Cenário',
    scenariosHeading: 'Cenários ChainBreak',
    mcpToolsHeading: 'Capacidades MCP Registradas',
    mcpToolsNote: 'Servidor HTTP loopback executa localmente via npm run demo:live',
    consoleTitle: 'Explorador de Cenários ChainBreak',
    consoleDesc:
      'Alterne entre estados sintéticos do laboratório de pagamentos para inspecionar cadeias alcançáveis, diffs mínimos de 1 aresta e portões tripartites de release.',
    btnDiff: 'Comparar Correção do Rollout',
    btnGate: 'Ver Simulação do Gate',
    graphTitle: 'Grafo de Alcançabilidade de Acesso',
    clearBanner: 'Este cenário não tem rotas de exportação não autorizadas.',
    workflowsTitle: 'Fluxos de Negócio',
    noWorkflows: 'Este cenário não define fluxos de negócio.',
    preservedWorkflow: 'Preservado',
    brokenWorkflow: 'Interrompido',
    fixtureMetadata: 'Metadados da Fixture',
    simulationNote: 'Este exemplo mostra a checagem de separação de deveres. A aprovação de release fica fora da simulação.',
    reviewTitle: 'Revisão Humana de Risco',
    gateTitle: 'Simulação de Separação de Deveres',
    testSelfCert: 'Testar Bloqueio de Auto-Certificação',
    restoreSod: 'Restaurar Revisão Independente',
    problemHeading: 'Por que scanners probabilísticos perdem riscos encadeados em agentes',
    problemLead:
      'Scanners isolados geram alertas sem provar se uma identidade realmente consegue encadear uma ferramenta MCP até dados restritos e um destino externo.',
    howHeading: 'Como a verificação determinística funciona',
    howLead:
      'Cada achado passa por prova explícita em grafo, síntese de diff mínimo e separação independente de deveres.',
    trustHeading: 'Limites de confiança e execução',
    trustLead:
      'ScriptKitty Live opera estritamente em modo LAB com travas permanentes de não-mutação e falha fechada para provedores externos não configurados.',
    statusHeading: 'Status honesto de maturidade do protótipo',
    faqHeading: 'Perguntas frequentes',
    footerText: 'Hack Brasil 2026 · ScriptKitty Live & PatchCat · Licença MIT · Apenas Dados Simulados de Lab',
  },
};

const MCP_TOOLS_PREVIEW = [
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
];

const POSES: PatchCatPose[] = ['idle', 'scanning', 'alert', 'verified', 'needs_review'];

function readSession(key: string): string | null {
  try {
    return typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(key) : null;
  } catch {
    return null;
  }
}

function writeSession(key: string, val: string): void {
  try {
    if (typeof sessionStorage !== 'undefined') sessionStorage.setItem(key, val);
  } catch {
    // ignore
  }
}

let currentLang: Lang = readSession('scriptkitty.vercel.lang') === 'pt' ? 'pt' : 'en';
let currentTheme: Theme = readSession('scriptkitty.vercel.theme') === 'light' ? 'light' : 'dark';
let activeScenarioId: ScenarioId = 'payments-lab/unsafe-rollout';
let diffPreviewOpen = false;
let simulateSelfCert = false;
let mascot: MotionCatMascot3D | null = null;

function applyDocumentTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
  document.documentElement.lang = currentLang === 'pt' ? 'pt-BR' : 'en';
}

function getMascotState(): MascotState {
  const sc = VERCEL_SCENARIOS[activeScenarioId];
  if (simulateSelfCert || sc.pathsCount > 0) return 'alert';
  if (activeScenarioId === 'payments-lab/remediated') return 'success';
  return 'idle';
}

function renderSrTable(sc: (typeof VERCEL_SCENARIOS)[ScenarioId]): string {
  return `
    <div class="sr-only">
      <table class="sr-table">
        <caption>ChainBreak access graph edges for ${sc.id}</caption>
        <thead><tr><th>Edge</th><th>From</th><th>Kind</th><th>To</th><th>Classification</th><th>Source</th></tr></thead>
        <tbody>
          ${sc.edges
            .map(
              (e) =>
                `<tr><td>${e.edgeId}</td><td>${e.from}</td><td>${e.kind}</td><td>${e.to}</td><td>${e.classification}</td><td>${e.sourceRef}</td></tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>`;
}

function render(focusId = document.activeElement?.id): void {
  applyDocumentTheme(currentTheme);
  const t = COPY[currentLang];
  const sc = VERCEL_SCENARIOS[activeScenarioId];
  const mState = getMascotState();
  const activePose = mapMascotStateToPose(mState, sc.reviewStatus === 'PENDING_REVIEW');
  const sodPass = !simulateSelfCert;
  const workflowCount = `${sc.operations.filter((operation) => operation.preserved).length}/${sc.operations.length}`;
  const isPt = currentLang === 'pt';

  const app = document.getElementById('app');
  if (!app) return;

  const scenariosOrder: ScenarioId[] = [
    'payments-lab/baseline',
    'payments-lab/unsafe-rollout',
    'payments-lab/remediated',
    'payments-lab/negative-control',
  ];

  const tabsHtml = scenariosOrder
    .map((id) => {
      const item = VERCEL_SCENARIOS[id];
      const active = id === activeScenarioId;
      return `
        <button
          type="button"
          role="tab"
          id="${item.domId}"
          data-scenario="${item.id}"
          class="scenario-tab ${active ? 'active' : ''}"
          aria-selected="${active ? 'true' : 'false'}"
          tabindex="${active ? '0' : '-1'}"
        >
          <span class="scenario-tab-left">
            <span class="tab-title">${item.label}</span>
            <span class="tab-sub">${item.id}</span>
          </span>
          <span class="tab-pill ${item.pillTone === 'risk' ? 'tab-pill-risk' : 'tab-pill-ok'}">${item.pill}</span>
        </button>`;
    })
    .join('');

  const poseStripHtml = POSES.map(
    (pose) => `
      <div class="pose-chip ${pose === activePose ? 'active' : ''}" data-pose="${pose}">
        ${renderPatchCatSvg(pose, { size: 36, label: `PatchCat ${pose}` })}
        <span class="pose-chip-label">${pose}</span>
      </div>`
  ).join('');

  const violatedEdges = sc.edges.filter((e) => e.violated);

  app.innerHTML = `
    <a class="skip-link" href="#main-content">${t.skip}</a>
    <header class="topbar">
      <div class="topbar-left">
        <a class="brand-mark" href="#main-content">
          <img src="/brand/favicon.svg" alt="PatchCat logo" width="28" height="28" decoding="async" />
          <span class="brand-name">ScriptKitty Live</span>
          <span class="brand-agent-tag">/ PatchCat</span>
        </a>
      </div>

      <nav class="topbar-nav" aria-label="Primary sections">
        <a class="nav-link" href="#how">${t.navHow}</a>
        <a class="nav-link" href="#features">${t.navFeatures}</a>
        <a class="nav-link" href="#trust">${t.navTrust}</a>
        <a class="nav-link" href="#console">${t.navConsole}</a>
      </nav>

      <div class="topbar-right">
        <span class="pill pill-lab" id="badge-sim-mode">
          <span class="status-dot ${mState === 'alert' ? 'dot-alert' : mState === 'success' ? 'dot-ok' : ''}" aria-hidden="true"></span>
          <span>${t.simBadge}</span>
        </span>
        <button class="icon-btn" id="btn-toggle-theme" type="button">
          ${currentTheme === 'dark' ? t.themeLight : t.themeDark}
        </button>
        <select id="select-lang" class="topbar-select" aria-label="Interface Language">
          <option value="en" ${currentLang === 'en' ? 'selected' : ''}>EN</option>
          <option value="pt" ${currentLang === 'pt' ? 'selected' : ''}>PT</option>
        </select>
      </div>
    </header>

    <main id="main-content">
      <section class="hero-section">
        <div class="hero-grid">
          <div class="hero-copy-col">
            <p class="hero-eyebrow">${t.eyebrow}</p>
            <h1 class="hero-display-title">${t.heroH1}</h1>
            <p class="hero-lead">${t.heroLead}</p>
            <div class="hero-cta-row">
              <a class="btn btn-primary" href="#console">${t.ctaExplore}</a>
              <a class="btn btn-secondary" href="${REPO_URL}" target="_blank" rel="noopener noreferrer">${t.ctaGithub}</a>
            </div>
            <div class="hero-disclosure-row">
              <span class="disclosure-pill">${t.discSynthetic}</span>
              <span class="disclosure-pill">${t.discLocks}</span>
            </div>
          </div>

          <div class="hero-mascot-col">
            <div class="hero-mascot-card">
              <div class="hero-mascot-top">
                <div class="hero-mascot-stage">
                  <div class="hero-mascot-svg-box">
                    ${renderPatchCatSvg(activePose, { size: 54, label: `PatchCat ${activePose}` })}
                  </div>
                  <div>
                    <div class="hero-mascot-status-title">PatchCat: ${activePose.toUpperCase()}</div>
                    <div class="hero-mascot-status-sub">${sc.id} (${sc.pathsCount} exposed path)</div>
                  </div>
                </div>
                <span class="pill pill-lab">${t.poseStripLabel}</span>
              </div>
              <div class="pose-strip" aria-label="PatchCat five telemetry states">
                ${poseStripHtml}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="console" class="console-section" aria-label="ChainBreak Scenario Explorer">
        <div class="app-shell">
          <aside class="rail">
            <div class="rail-section">
              <div class="rail-heading">${t.postureHeading}</div>
              <div class="telemetry-row">
                <div id="mascot-3d-container"></div>
                <div class="telemetry-meta">
                  <span class="mascot-3d-label">TELEMETRY: ${mState.toUpperCase()}</span>
                  <span class="telemetry-sub">${t.postureSub}</span>
                </div>
              </div>
            </div>

            <div class="rail-section">
              <div class="rail-heading">${t.scenariosHeading}</div>
              <div class="scenario-list" role="tablist" aria-label="Payments Lab Scenario States">
                ${tabsHtml}
              </div>
            </div>

            <div class="rail-section">
              <div class="rail-heading">${t.mcpToolsHeading}</div>
              <p class="muted-note">${t.mcpToolsNote}</p>
              <ul class="mcp-tool-list">
                ${MCP_TOOLS_PREVIEW.map((name) => `<li class="mcp-tool-item"><span>${name}</span><span>LAB</span></li>`).join('')}
              </ul>
            </div>
          </aside>

          <div class="workspace">
            <div class="workspace-header">
              <div class="workspace-title-block">
                <h2>${t.consoleTitle}</h2>
                <p>${t.consoleDesc}</p>
              </div>
              <div class="workspace-actions">
                <button class="btn btn-primary" id="btn-pr-suggest" type="button">${t.btnDiff}</button>
                <a class="btn btn-secondary" id="btn-pr" href="#release-gate-simulation">${t.btnGate}</a>
              </div>
            </div>

            <section class="action-strip ${sc.pathsCount > 0 ? 'strip-alert' : 'strip-clear'}">
              <div class="action-strip-copy">
                <h3>${sc.label}</h3>
                <p>${isPt ? sc.summaryPt : sc.summaryEn}</p>
              </div>
              <span class="status-pill ${sc.pathsCount > 0 ? 'badge-high' : 'badge-low'}">
                ${sc.pathsCount > 0 ? 'PATH_VALIDATED (P1)' : '0 VIOLATIONS'}
              </span>
            </section>

            ${
              diffPreviewOpen
                ? `<section class="panel" id="panel-pr-suggestion">
                    <div class="panel-header">
                      <span class="panel-title">chore(policy): REMOVE_EDGE e-rollout-exporter-read-pii</span>
                      <span class="status-pill badge-medium">Review Required</span>
                    </div>
                    <p class="muted-note">Paths 1 -> 0 · Workflows 3/3 intact · requiresHumanApproval: true · autoApplyAllowed: false · mergeAllowed: false · deployAllowed: false</p>
                    <pre class="diff-pre"><span class="diff-line-hdr">--- a/policies/payments-lab/report-exporter-rollout.yaml#L24</span><span class="diff-line-hdr">+++ b/policies/payments-lab/report-exporter-rollout.yaml#L24</span><span class="diff-line-hdr">@@ -24,3 +24,0 @@</span><span class="diff-line-del">- edge: e-rollout-exporter-read-pii (REMOVE_EDGE: mcp_tool:report-exporter --[can_read; class=RESTRICTED]--&gt; data_asset:customer-payment-pii)</span><span class="diff-line-add">+ # REMOVED by PatchCat counterfactual spec; human sign-off mandatory</span></pre>
                  </section>`
                : ''
            }

            <section class="panel" id="panel-chainbreak">
              <div class="panel-header">
                <span class="panel-title">${t.graphTitle}</span>
                <span class="panel-meta">${sc.pathsCount} path(s) · ${workflowCount} workflows OK</span>
              </div>
              <div class="graph-canvas-wrap">
                ${renderScenarioGraphSvg(sc)}
              </div>
              ${renderSrTable(sc)}

              ${
                violatedEdges.length === 0
                  ? `<div class="empty-clean-banner">${t.clearBanner}</div>`
                  : `<div class="path-detail-block">
                      <div class="path-header-row">
                        <span class="status-pill badge-high">PATH_VALIDATED</span>
                        <span class="status-pill badge-medium">Severity P1</span>
                        <code class="mono-tag">NO_RESTRICTED_DATA_EXTERNAL_TRANSFER</code>
                      </div>
                      <div class="table-responsive">
                        <table class="data-table">
                          <thead><tr><th>Hop</th><th>Edge</th><th>Transition</th><th>Class</th><th>Source</th></tr></thead>
                          <tbody>
                            ${violatedEdges
                              .map(
                                (edge, idx) =>
                                  `<tr><td class="mono">${idx + 1}</td><td><code>${edge.edgeId}</code></td><td><code>${edge.from}</code> -> <code>${edge.to}</code></td><td>${edge.classification}</td><td><code>${edge.sourceRef}</code></td></tr>`
                              )
                              .join('')}
                          </tbody>
                        </table>
                      </div>
                    </div>`
              }

              <div class="sub-section-title">${t.workflowsTitle} (${workflowCount})</div>
              ${
                sc.operations.length === 0
                  ? `<p class="muted-note">${t.noWorkflows}</p>`
                  : `<div class="legit-ops-grid">
                      ${sc.operations.map((operation) => `
                        <div class="legit-op-item">
                          <span class="legit-op-head"><code>${operation.id}</code></span>
                          <span class="op-desc">${operation.preserved ? t.preservedWorkflow : t.brokenWorkflow} ·
                            ${isPt ? operation.descriptionPt : operation.descriptionEn}</span>
                        </div>
                      `).join('')}
                    </div>`
              }

              <details class="tech-receipt">
                <summary>${t.fixtureMetadata}</summary>
                <div class="tech-receipt-body">
                  <div>fixtureId: ${sc.id} · policyVersion: ${sc.policyVersion}</div>
                  <div>inputSha256: <code>${sc.inputSha256}</code></div>
                  <div>scope: PATH_VALIDATED proves deterministic graph reachability (NEVER EXPLOIT_CONFIRMED)</div>
                </div>
              </details>
            </section>

            <div class="dual-panels-grid">
              <section class="panel">
                <div class="panel-header">
                  <span class="panel-title">${t.reviewTitle}</span>
                  <span class="status-pill ${sc.reviewStatus === 'PENDING_REVIEW' ? 'badge-medium' : 'badge-low'}">${sc.reviewStatus}</span>
                </div>
                <div class="kv-list">
                  <div class="kv-row">
                    <span class="kv-label">Graph Verification</span>
                    <span class="kv-value mono">${sc.graphStatus}</span>
                  </div>
                  <div class="kv-row">
                    <span class="kv-label">Advisory Provider</span>
                    <span class="kv-value mono">${sc.advisoryProviderStatus}</span>
                  </div>
                  <div class="kv-row">
                    <span class="kv-label">Authority</span>
                    <span class="kv-value">Human sign-off required</span>
                  </div>
                  <div class="kv-row">
                    <span class="kv-label">Risk Severity</span>
                    <span class="kv-value mono">${sc.risk}</span>
                  </div>
                </div>
                <details class="tech-receipt">
                  <summary>Advisory Protocol Receipt</summary>
                  <div class="tech-receipt-body">
                    <div>mode: LAB_SIMULATION · externalApiConfigured: false · mergeAllowed: false · deployAllowed: false</div>
                  </div>
                </details>
              </section>

              <section class="panel" id="release-gate-simulation" tabindex="-1" aria-labelledby="release-gate-title">
                <div class="panel-header">
                  <h3 class="panel-title" id="release-gate-title">${t.gateTitle}</h3>
                  <span class="status-pill ${sodPass ? 'badge-low' : 'badge-high'}" id="txt-gate-verdict">${sodPass ? 'SoD: PASS' : 'SoD: REJECT'}</span>
                </div>
                <div class="gate-sub-header">
                  <span class="kv-label">Tri-Party Separation of Duties (Discoverer != Verifier != Authorizer)</span>
                  <button type="button" class="btn btn-secondary btn-xs" id="btn-toggle-self-cert">
                    ${simulateSelfCert ? t.restoreSod : t.testSelfCert}
                  </button>
                </div>
                <div class="sod-roles-row">
                  <div class="sod-role-chip">
                    <span class="sod-role-name">Discoverer</span>
                    <span class="sod-role-agent">${simulateSelfCert ? 'agent-omnipotent' : 'agent-discovery-chainbreak'}</span>
                  </div>
                  <div class="sod-role-chip">
                    <span class="sod-role-name">Verifier</span>
                    <span class="sod-role-agent">${simulateSelfCert ? 'agent-omnipotent' : 'agent-verifier-sandbox'}</span>
                  </div>
                  <div class="sod-role-chip">
                    <span class="sod-role-name">Authorizer</span>
                    <span class="sod-role-agent">agent-authorizer-gate</span>
                  </div>
                </div>
                <div class="delivery-readiness-note">
                  <p>${t.simulationNote}</p>
                  ${simulateSelfCert ? '<div class="fallback-note">Violation: <code>E_SOD_SELF_CERTIFICATION</code> (Discoverer cannot verify its own finding)</div>' : ''}
                  <div class="mono">mergeAllowed: false · deployAllowed: false · requiresHumanApproval: true</div>
                </div>
              </section>
            </div>
          </div>
        </div>
      </section>

      <section id="features" class="editorial-band">
        <div class="landing-section">
          <div class="section-header">
            <h2>${t.problemHeading}</h2>
            <p>${t.problemLead}</p>
          </div>
          <div class="outcomes-grid">
            <article class="outcome-block">
              <span class="outcome-meta">ChainBreak Policy Graph</span>
              <h3>${isPt ? 'Alcançabilidade Determinística' : 'Deterministic Reachability Proof'}</h3>
              <p>${isPt ? 'Rastreia saltos entre identidades, ferramentas MCP, ativos de dados e destinos externos com referência exata de arquivo e linha.' : 'Traces multi-hop reachability across identities, MCP tools, data assets, and external sinks anchored to exact sourceRef lines and SHA-256 hashes.'}</p>
            </article>
            <article class="outcome-block">
              <span class="outcome-meta">Verified Remediation</span>
              <h3>${isPt ? 'Correção Contrafactual Mínima' : 'Counterfactual Minimal Fix'}</h3>
              <p>${isPt ? 'Gera a menor remoção de aresta que zera a exposição (1 -> 0) enquanto preserva 3/3 operações de negócio legítimas.' : 'Synthesizes the smallest edge removal that breaks unauthorized exposure (1 -> 0) while proving 3/3 legitimate operations remain intact.'}</p>
            </article>
            <article class="outcome-block">
              <span class="outcome-meta">Agent &amp; MCP Security</span>
              <h3>${isPt ? 'Governança Tripartite Fail-Closed' : 'Fail-Closed Tri-Party Governance'}</h3>
              <p>${isPt ? 'Exige descoberta, verificação e autorização independentes, transporte MCP restrito a loopback e trava permanente contra auto-merge.' : 'Enforces independent discovery, verification, and authorization identities alongside loopback-only MCP controls and permanent human approval locks.'}</p>
            </article>
          </div>
        </div>
      </section>

      <section id="how" class="editorial-band-alt">
        <div class="landing-section">
          <div class="section-header">
            <h2>${t.howHeading}</h2>
            <p>${t.howLead}</p>
          </div>
          <div class="steps-grid">
            <div class="step-card">
              <span class="step-tag">Step 1</span>
              <h3>${isPt ? 'Modelar o Grafo' : 'Model Policy Graph'}</h3>
              <p>${isPt ? 'Normaliza identidades, ferramentas MCP, classificações PII e destinos com hash SHA-256 canônico.' : 'Normalize identities, MCP tools, data classifications, and trust zones with canonical SHA-256 integrity.'}</p>
            </div>
            <div class="step-card">
              <span class="step-tag">Step 2</span>
              <h3>${isPt ? 'Provar Alcançabilidade' : 'Prove Reachability'}</h3>
              <p>${isPt ? 'Executa travessia determinística e marca rotas reais como PATH_VALIDATED, nunca EXPLOIT_CONFIRMED.' : 'Run deterministic traversal and label verified exposure routes as PATH_VALIDATED, never EXPLOIT_CONFIRMED.'}</p>
            </div>
            <div class="step-card">
              <span class="step-tag">Step 3</span>
              <h3>${isPt ? 'Sintetizar Correção' : 'Synthesize Minimal Diff'}</h3>
              <p>${isPt ? 'Propõe remoção mínima de permissão e reavalia contrafactualmente os fluxos protegidos.' : 'Generate minimal edge-removal diffs and re-verify protected business workflows stay operational.'}</p>
            </div>
            <div class="step-card">
              <span class="step-tag">Step 4</span>
              <h3>${isPt ? 'Selo e Aprovação Humana' : 'Custody & Human Gate'}</h3>
              <p>${isPt ? 'Valida separação tripartite de deveres, cadeia Merkle RFC 8785 e revisão humana obrigatória.' : 'Validate Tri-Party Separation of Duties, RFC 8785 Merkle custody, and mandatory human sign-off.'}</p>
            </div>
          </div>
        </div>
      </section>

      <section id="trust" class="editorial-band">
        <div class="landing-section">
          <div class="section-header">
            <h2>${t.trustHeading}</h2>
            <p>${t.trustLead}</p>
          </div>
          <div class="trust-grid">
            <div class="panel">
              <div class="panel-header">
                <span class="panel-title">${isPt ? 'Invariantes Não-Negociáveis' : 'Non-Negotiable Safety Locks'}</span>
              </div>
              <div class="table-responsive">
                <table class="data-table">
                  <thead><tr><th>Invariant</th><th>Value</th></tr></thead>
                  <tbody>
                    <tr><td><code>mode</code></td><td class="mono">LAB (productionTested: false)</td></tr>
                    <tr><td><code>mergeAllowed / deployAllowed</code></td><td class="mono">false / false</td></tr>
                    <tr><td><code>autoApplyAllowed</code></td><td class="mono">false (requiresHumanApproval: true)</td></tr>
                    <tr><td><code>externalExecution</code></td><td class="mono">false (loopback 127.0.0.1 only)</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div class="panel">
              <div class="panel-header">
                <span class="panel-title">${t.statusHeading}</span>
              </div>
              <div class="table-responsive">
                <table class="data-table">
                  <thead><tr><th>Capability</th><th>Status</th></tr></thead>
                  <tbody>
                    <tr><td>ChainBreak Policy Reachability &amp; Counterfactual Fix</td><td><span class="status-pill badge-low">IMPLEMENTED</span></td></tr>
                    <tr><td>Loopback MCP Streamable HTTP &amp; Tenant Isolation</td><td><span class="status-pill badge-low">IMPLEMENTED</span></td></tr>
                    <tr><td>Hardened Container Sandbox Daemon</td><td><span class="status-pill badge-medium">PARTIAL (LAB_SIMULATION)</span></td></tr>
                    <tr><td>External Commercial Advisory &amp; Cloud Telemetry</td><td><span class="status-pill badge-high">PLANNED (NOT_CONFIGURED)</span></td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section class="editorial-band-alt">
        <div class="landing-section">
          <div class="section-header">
            <h2>${t.faqHeading}</h2>
          </div>
          <div class="faq-list">
            <details class="faq-item">
              <summary>${isPt ? 'Esta prévia na Vercel executa scans contra alvos reais?' : 'Does this Vercel preview scan live production targets?'}</summary>
              <p>${isPt ? 'Não. Esta prévia pública exibe exclusivamente dados sintéticos simulados de laboratório (SIMULATED LAB DATA). O servidor MCP ao vivo roda localmente em 127.0.0.1 via npm run demo:live.' : 'No. This public preview renders exclusively synthetic laboratory fixtures (SIMULATED LAB DATA). The live MCP Streamable HTTP server runs strictly on local loopback 127.0.0.1 via npm run demo:live.'}</p>
            </details>
            <details class="faq-item">
              <summary>${isPt ? 'Por que os achados são marcados como PATH_VALIDATED e não EXPLOIT_CONFIRMED?' : 'Why are paths labeled PATH_VALIDATED instead of EXPLOIT_CONFIRMED?'}</summary>
              <p>${isPt ? 'ChainBreak comprova alcançabilidade determinística em grafos de política modelados e referências de origem. Nunca exageramos alcançabilidade como exploração ativa em produção.' : 'ChainBreak proves deterministic reachability on modeled policy graphs anchored to sourceRef lines and SHA-256 hashes. We never overclaim graph reachability as live production exploitation.'}</p>
            </details>
            <details class="faq-item">
              <summary>${isPt ? 'O PatchCat aplica patches ou faz merge automaticamente?' : 'Can PatchCat auto-apply patches or merge pull requests?'}</summary>
              <p>${isPt ? 'Nunca. Todas as entregas travam autoApplyAllowed=false, mergeAllowed=false e deployAllowed=false, exigindo aprovação humana explícita.' : 'Never. Every remediation spec and release gate locks autoApplyAllowed=false, mergeAllowed=false, and deployAllowed=false, requiring explicit human sign-off.'}</p>
            </details>
          </div>
        </div>
      </section>
    </main>

    <footer class="site-footer">
      <div class="footer-inner">
        <span class="footer-meta">${t.footerText}</span>
        <div class="footer-links">
          <a href="${REPO_URL}" target="_blank" rel="noopener noreferrer">GitHub</a>
          <a href="#console">${t.navConsole}</a>
          <a href="#trust">${t.navTrust}</a>
        </div>
      </div>
    </footer>
  `;

  const mascotEl = document.getElementById('mascot-3d-container');
  if (mascotEl) {
    if (mascot) mascot.destroy();
    mascot = new MotionCatMascot3D('mascot-3d-container', mState);
  }

  document.getElementById('btn-toggle-theme')?.addEventListener('click', () => {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    writeSession('scriptkitty.vercel.theme', currentTheme);
    render();
  });

  document.getElementById('select-lang')?.addEventListener('change', (e) => {
    const val = (e.target as HTMLSelectElement).value === 'pt' ? 'pt' : 'en';
    currentLang = val;
    writeSession('scriptkitty.vercel.lang', currentLang);
    render();
  });

  document.getElementById('btn-pr-suggest')?.addEventListener('click', () => {
    activeScenarioId = 'payments-lab/remediated';
    diffPreviewOpen = true;
    render();
  });

  document.getElementById('btn-toggle-self-cert')?.addEventListener('click', () => {
    simulateSelfCert = !simulateSelfCert;
    render();
  });

  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-scenario]'));
  tabs.forEach((btn, index) => {
    btn.addEventListener('click', () => {
      selectScenario(btn);
    });
    btn.addEventListener('keydown', (ev) => {
      let nextIdx = -1;
      if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') nextIdx = (index + 1) % tabs.length;
      else if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') nextIdx = (index - 1 + tabs.length) % tabs.length;
      else if (ev.key === 'Home') nextIdx = 0;
      else if (ev.key === 'End') nextIdx = tabs.length - 1;
      if (nextIdx >= 0) {
        ev.preventDefault();
        selectScenario(tabs[nextIdx]);
      }
    });
  });

  if (focusId) document.getElementById(focusId)?.focus({ preventScroll: true });
}

function selectScenario(tab: HTMLButtonElement): void {
  const nextScenarioId = tab.dataset.scenario as ScenarioId;
  if (nextScenarioId !== activeScenarioId) diffPreviewOpen = false;
  activeScenarioId = nextScenarioId;
  render(tab.id);
}

render();
