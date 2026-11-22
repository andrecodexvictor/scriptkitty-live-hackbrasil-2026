/**
 * @file apps/ui/src/dashboard-view.ts
 * @description Product-grade bilingual (EN/PT/ES) landing + interactive verification
 * console renderer for ScriptKitty Live & PatchCat (`@script-kitty/ui`).
 */

import type {
  CanonicalFixtureId,
  PolicyGraphFixture,
} from './lab-fixtures.ts';
import type {
  DashboardState,
  PatchCatLiveController,
  SupportedLanguage,
} from './live-controller.ts';
import {
  MotionCatMascot3D,
  type MascotControllerHandle,
  type MascotState,
} from './mascot3d.ts';
import {
  escapeHtml as openUiEscapeHtml,
  renderOpenUiAdvisoryBrief,
} from './openui-catalog.ts';
import {
  mapMascotStateToPose,
  renderPatchCatSvg,
  type PatchCatPose,
} from './patchcat-mascot.ts';

type MotionChoreographyModule = typeof import('./motion-choreography.ts');
let motionModulePromise: Promise<MotionChoreographyModule | null> | null = null;

function isReducedMotionPreferred(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

function loadMotionChoreography(): Promise<MotionChoreographyModule | null> {
  if (
    typeof window === 'undefined' ||
    typeof document === 'undefined' ||
    isReducedMotionPreferred()
  ) {
    return Promise.resolve(null);
  }
  if (!motionModulePromise) {
    motionModulePromise = import('./motion-choreography.ts').catch(() => null);
  }
  return motionModulePromise;
}

export const escapeHtml = openUiEscapeHtml;

const REPO_URL =
  'https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026';

const CANONICAL_OFFLINE_TOOLS = [
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

const PATCHCAT_POSES: PatchCatPose[] = [
  'idle',
  'scanning',
  'alert',
  'verified',
  'needs_review',
];

export interface MountDashboardOptions {
  doc?: Document;
  mascotFactory?: (
    containerId: string,
    initialState: MascotState
  ) => MascotControllerHandle;
}

export interface MountedDashboard {
  unmount: () => void;
  getMascot: () => MascotControllerHandle | null;
}

export const UI_TRANSLATIONS: Record<
  SupportedLanguage,
  Record<string, string>
> = {
  en: {
    skipToContent: 'Skip to content',
    navHow: 'How It Works',
    navFeatures: 'Capabilities',
    navTrust: 'Boundaries',
    navConsole: 'Live Console',
    workspaceCrumb: 'payments-lab',
    sandboxPill: 'Isolated Sandbox',
    btnKeys: 'Model Providers',
    themeDark: 'Dark',
    themeLight: 'Light',
    heroEyebrow: 'AUTONOMOUS SECURITY ENGINEERING · LAB PREVIEW',
    landingH1: 'Security that sees the whole attack path.',
    landingLead:
      'ScriptKitty Live pairs deterministic policy-graph reachability (ChainBreak) with PatchCat counterfactual remediation and fail-closed MCP access controls before any rollout reaches review.',
    ctaConsole: 'Explore the live console',
    ctaGithub: 'View source on GitHub',
    disclosureSynthetic: 'Laboratory demonstration · Synthetic data · No live targets scanned',
    disclosureLocks: 'Human approval mandatory · Auto-merge locked',
    telemetryStripBadge: 'PatchCat 5-State Telemetry',
    postureHeading: 'Posture Monitor',
    postureSub: 'Deterministic Lab Engine',
    scenariosHeading: 'Verification Scenarios',
    connectionHeading: 'Runtime Connection',
    mcpToolsHeading: 'Registered MCP Tools',
    mcpToolsLiveLabel: 'Live MCP',
    mcpToolsOfflineLabel: 'Offline Preview',
    heroTitle: 'PatchCat Access Verification Console',
    heroDesc:
      'Verify least-privilege access paths across agent workflows, preview minimal permission diffs, and enforce independent release controls before merge.',
    btnScout: 'Run Verification',
    btnMemory: 'Audit History',
    btnPr: 'Validate Release Gate',
    learningTitle: 'Counterfactual 1-line permission fix verified',
    learningDesc:
      "Removing the excess permission link ('e-rollout-exporter-read-pii') blocks unauthorized payment data export while preserving 3/3 core business workflows.",
    btnPrSuggest: 'Preview Fix Diff',
    graphTitle: 'Access Reachability Graph',
    reviewTitle: 'Human Risk Review',
    gateTitle: 'Release Gate & Custody Proof',
    memoryTitle: 'Tenant Verification History',
    auditTitle: 'Tamper-Evident Audit Feed',
    problemHeading: 'Why probabilistic scanners miss chained agent risk',
    problemLead:
      'Point-in-time scanners flag isolated lines without proving whether an identity can actually chain an MCP tool to restricted payment data and an external sink.',
    howHeading: 'How deterministic verification works',
    howLead:
      'Every finding passes through explicit graph proof, minimal-diff synthesis, and independent separation of duties.',
    trustHeading: 'Trust and execution boundaries',
    trustLead:
      'ScriptKitty Live runs strictly in LAB mode with non-mutation locks and fail-closed defaults for all unconfigured external providers.',
    statusHeading: 'Honest implementation status',
    faqHeading: 'Frequently asked questions',
    footerCopy:
      'Hack Brasil 2026 · ScriptKitty Live & PatchCat · MIT License · Synthetic LAB Mode Only',
  },
  pt: {
    skipToContent: 'Ir para o conteúdo',
    navHow: 'Como Funciona',
    navFeatures: 'Capacidades',
    navTrust: 'Limites',
    navConsole: 'Console ao Vivo',
    workspaceCrumb: 'payments-lab',
    sandboxPill: 'Sandbox Isolado',
    btnKeys: 'Provedores IA',
    themeDark: 'Escuro',
    themeLight: 'Claro',
    heroEyebrow: 'ENGENHARIA DE SEGURANÇA AUTÔNOMA · PRÉVIA DE LAB',
    landingH1: 'Segurança que enxerga o caminho inteiro do ataque.',
    landingLead:
      'ScriptKitty Live combina alcançabilidade determinística em grafos de política (ChainBreak) com remediação contrafactual do PatchCat e controles MCP fail-closed antes de qualquer rollout.',
    ctaConsole: 'Explorar o console ao vivo',
    ctaGithub: 'Ver código no GitHub',
    disclosureSynthetic: 'Demonstração de laboratório · Dados sintéticos · Nenhum alvo real escaneado',
    disclosureLocks: 'Aprovação humana obrigatória · Auto-merge bloqueado',
    telemetryStripBadge: 'Telemetria PatchCat em 5 Estados',
    postureHeading: 'Monitor de Postura',
    postureSub: 'Motor Determinístico Lab',
    scenariosHeading: 'Cenários de Verificação',
    connectionHeading: 'Conexão em Tempo Real',
    mcpToolsHeading: 'Ferramentas MCP Registradas',
    mcpToolsLiveLabel: 'MCP ao Vivo',
    mcpToolsOfflineLabel: 'Prévia Offline',
    heroTitle: 'Explorador PatchCat — Verificação de Acesso',
    heroDesc:
      'Verifique rotas de privilégio mínimo entre fluxos de agentes, simule diffs mínimos de permissão e exija validação independente antes de qualquer merge.',
    btnScout: 'Executar Verificação',
    btnMemory: 'Histórico de Auditoria',
    btnPr: 'Validar Release Gate',
    learningTitle: 'Correção contrafactual mínima de 1 linha verificada',
    learningDesc:
      "Remover o vínculo excessivo ('e-rollout-exporter-read-pii') bloqueia a exportação indevida de dados de pagamento preservando 3/3 fluxos legítimos.",
    btnPrSuggest: 'Visualizar Diff da Correção',
    graphTitle: 'Grafo de Alcançabilidade de Acesso',
    reviewTitle: 'Revisão Humana de Risco',
    gateTitle: 'Release Gate e Prova de Custódia',
    memoryTitle: 'Histórico de Verificações do Tenant',
    auditTitle: 'Registro Imutável de Auditoria',
    problemHeading: 'Por que scanners probabilísticos perdem riscos encadeados em agentes',
    problemLead:
      'Scanners isolados geram alertas sem provar se uma identidade realmente consegue encadear uma ferramenta MCP até dados restritos e um destino externo.',
    howHeading: 'Como a verificação determinística funciona',
    howLead:
      'Cada achado passa por prova explícita em grafo, síntese de diff mínimo e separação independente de deveres.',
    trustHeading: 'Limites de confiança e execução',
    trustLead:
      'ScriptKitty Live opera estritamente em modo LAB com travas permanentes de não-mutação e falha fechada para provedores externos não configurados.',
    statusHeading: 'Status honesto de implementação',
    faqHeading: 'Perguntas frequentes',
    footerCopy:
      'Hack Brasil 2026 · ScriptKitty Live & PatchCat · Licença MIT · Apenas Modo LAB Sintético',
  },
  es: {
    skipToContent: 'Ir al contenido',
    navHow: 'Cómo Funciona',
    navFeatures: 'Capacidades',
    navTrust: 'Límites',
    navConsole: 'Consola en Vivo',
    workspaceCrumb: 'payments-lab',
    sandboxPill: 'Sandbox Aislado',
    btnKeys: 'Proveedores IA',
    themeDark: 'Oscuro',
    themeLight: 'Claro',
    heroEyebrow: 'INGENIERÍA DE SEGURIDAD AUTÓNOMA · VISTA DE LAB',
    landingH1: 'Seguridad que ve toda la ruta de ataque.',
    landingLead:
      'ScriptKitty Live combina alcanzabilidad determinística en grafos de políticas (ChainBreak) con remediación contrafactual de PatchCat y controles MCP fail-closed antes de cualquier despliegue.',
    ctaConsole: 'Explorar la consola en vivo',
    ctaGithub: 'Ver código en GitHub',
    disclosureSynthetic: 'Demostración de laboratorio · Datos sintéticos · Sin objetivos reales',
    disclosureLocks: 'Aprobación humana obligatoria · Auto-merge bloqueado',
    telemetryStripBadge: 'Telemetría PatchCat en 5 Estados',
    postureHeading: 'Monitor de Postura',
    postureSub: 'Motor Determinístico Lab',
    scenariosHeading: 'Escenarios de Verificación',
    connectionHeading: 'Conexión de Runtime',
    mcpToolsHeading: 'Herramientas MCP Registradas',
    mcpToolsLiveLabel: 'MCP en Vivo',
    mcpToolsOfflineLabel: 'Vista Offline',
    heroTitle: 'Explorador PatchCat — Verificación de Acceso',
    heroDesc:
      'Verifique rutas de privilegio mínimo en flujos de agentes, previsualice cambios mínimos de permisos y exija validación independiente antes del merge.',
    btnScout: 'Ejecutar Escaneo',
    btnMemory: 'Historial de Auditoría',
    btnPr: 'Validar Release Gate',
    learningTitle: 'Corrección contrafactual mínima verificada',
    learningDesc:
      "Eliminar el vínculo excesivo ('e-rollout-exporter-read-pii') bloquea la exportación indebida de datos preservando 3/3 flujos legítimos.",
    btnPrSuggest: 'Previsualizar Diff',
    graphTitle: 'Grafo de Alcanzabilidad de Acceso',
    reviewTitle: 'Revisión Humana de Riesgo',
    gateTitle: 'Compuerta de Release y Custodia',
    memoryTitle: 'Historial de Verificaciones',
    auditTitle: 'Registro Inmutable de Auditoría',
    problemHeading: 'Por qué los escáneres probabilísticos pierden riesgos encadenados',
    problemLead:
      'Los escáneres aislados marcan líneas sin demostrar si una identidad puede encadenar una herramienta MCP hacia datos restringidos y un destino externo.',
    howHeading: 'Cómo funciona la verificación determinística',
    howLead:
      'Cada hallazgo pasa por prueba explícita en grafo, síntesis de diff mínimo y separación independiente de deberes.',
    trustHeading: 'Límites de confianza y ejecución',
    trustLead:
      'ScriptKitty Live opera estrictamente en modo LAB con bloqueos permanentes de no mutación y falla cerrada para proveedores externos.',
    statusHeading: 'Estado honesto de implementación',
    faqHeading: 'Preguntas frecuentes',
    footerCopy:
      'Hack Brasil 2026 · ScriptKitty Live & PatchCat · Licencia MIT · Solo Modo LAB Sintético',
  },
};

const FIXTURE_TAB_META: Array<{
  id: CanonicalFixtureId;
  domId: string;
  label: string;
  subtitle: string;
  pill: string;
  pillTone: 'ok' | 'risk';
}> = [
  {
    id: 'payments-lab/baseline',
    domId: 'tab-baseline',
    label: 'Baseline',
    subtitle: 'payments-lab/baseline',
    pill: '0 paths',
    pillTone: 'ok',
  },
  {
    id: 'payments-lab/unsafe-rollout',
    domId: 'tab-unsafe-rollout',
    label: 'Unsafe Rollout',
    subtitle: 'payments-lab/unsafe-rollout',
    pill: 'P1 risk',
    pillTone: 'risk',
  },
  {
    id: 'payments-lab/remediated',
    domId: 'tab-remediated',
    label: 'Remediated',
    subtitle: 'payments-lab/remediated',
    pill: '0 paths',
    pillTone: 'ok',
  },
  {
    id: 'payments-lab/negative-control',
    domId: 'tab-negative-control',
    label: 'Negative Control',
    subtitle: 'payments-lab/negative-control',
    pill: 'Isolated',
    pillTone: 'ok',
  },
];

const GRAPH_NODE_W = 160;
const GRAPH_NODE_H = 42;

const GRAPH_COORDS: Record<string, { x: number; y: number }> = {
  'identity:support-agent': { x: 92, y: 84 },
  'identity:auditor-agent': { x: 92, y: 248 },
  'identity:finance-operator': { x: 92, y: 248 },
  'mcp_tool:report-exporter': { x: 340, y: 108 },
  'service:audit-exporter': { x: 340, y: 248 },
  'service:finance-processor': { x: 340, y: 248 },
  'data_asset:customer-profile-synthetic': { x: 626, y: 46 },
  'data_asset:non-sensitive-summary': { x: 626, y: 118 },
  'data_asset:customer-payment-pii': { x: 626, y: 200 },
  'data_asset:payment-ledger-internal': { x: 626, y: 280 },
  'destination:external-report-sink': { x: 888, y: 158 },
};

const EDGE_SHORT_LABELS: Record<string, string> = {
  'e-support-read-profile': 'read-profile',
  'e-support-invoke-exporter': 'invoke-exporter',
  'e-exporter-read-summary': 'read-summary',
  'e-rollout-exporter-read-pii': 'rollout-read-pii',
  'e-exporter-transfer-external': 'transfer-ext',
  'e-finance-assume-processor': 'assume-role',
  'e-finance-read-payment-pii': 'read-payment-pii',
  'e-finance-write-ledger': 'write-ledger',
};

function readSessionValue(key: string): string | null {
  try {
    return typeof sessionStorage !== 'undefined'
      ? sessionStorage.getItem(key)
      : null;
  } catch {
    return null;
  }
}

function writeSessionValue(key: string, value: string): void {
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(key, value);
    }
  } catch {
    // Non-fatal in headless tests
  }
}

function computeEdgeGeometry(
  edgeId: string,
  from: { x: number; y: number },
  to: { x: number; y: number }
): { pathD: string; labelX: number; labelY: number; arrowX: number; arrowY: number } {
  const startX = from.x + GRAPH_NODE_W / 2;
  const startY = from.y;
  const endX = to.x - GRAPH_NODE_W / 2 - 4;
  const endY = to.y;

  if (edgeId === 'e-support-read-profile') {
    const pathD = `M ${startX} ${startY - 8} C 290 18, 440 18, ${endX} ${endY}`;
    return { pathD, labelX: 340, labelY: 18, arrowX: endX, arrowY: endY };
  }

  if (edgeId === 'e-support-invoke-exporter') {
    const pathD = `M ${startX} ${startY + 6} C 210 ${startY + 6}, 220 ${endY}, ${endX} ${endY}`;
    return { pathD, labelX: 216, labelY: 54, arrowX: endX, arrowY: endY };
  }

  if (edgeId === 'e-exporter-read-summary') {
    const pathD = `M ${startX} ${startY} C 470 ${startY}, 500 ${endY}, ${endX} ${endY}`;
    return { pathD, labelX: 482, labelY: 96, arrowX: endX, arrowY: endY };
  }

  if (edgeId === 'e-exporter-transfer-external') {
    const pathD = `M ${startX} ${startY + 6} C 495 160, 710 158, ${endX} ${endY}`;
    return { pathD, labelX: 756, labelY: 145, arrowX: endX, arrowY: endY };
  }

  if (edgeId === 'e-rollout-exporter-read-pii') {
    const pathD = `M ${startX} ${startY + 10} C 475 135, 495 ${endY}, ${endX} ${endY - 4}`;
    return { pathD, labelX: 472, labelY: 174, arrowX: endX, arrowY: endY - 4 };
  }

  if (edgeId === 'e-finance-read-payment-pii') {
    const pathD = `M ${startX} ${startY - 4} C 470 ${startY - 12}, 495 ${endY + 6}, ${endX} ${endY + 6}`;
    return { pathD, labelX: 482, labelY: 232, arrowX: endX, arrowY: endY + 6 };
  }

  const dx = Math.max(40, Math.round((endX - startX) * 0.48));
  const pathD = `M ${startX} ${startY} C ${startX + dx} ${startY}, ${endX - dx} ${endY}, ${endX} ${endY}`;
  const labelX = Math.round((startX + endX) / 2);
  const labelY = Math.round((startY + endY) / 2) - 8;
  return { pathD, labelX, labelY, arrowX: endX, arrowY: endY };
}

function renderPolicyGraphSvg(
  fixture: PolicyGraphFixture,
  violatingEdgeIds: Set<string>
): string {
  const nodePosMap = new Map<string, { x: number; y: number }>();
  fixture.nodes.forEach((n, idx) => {
    const preset = GRAPH_COORDS[n.nodeId];
    nodePosMap.set(
      n.nodeId,
      preset ?? {
        x: 100 + (idx % 4) * 260,
        y: 52 + Math.floor(idx / 4) * 86,
      }
    );
  });

  const edgeSvg = fixture.edges
    .map((e) => {
      const from = nodePosMap.get(e.from);
      const to = nodePosMap.get(e.to);
      if (!from || !to) return '';

      const isViolation = violatingEdgeIds.has(e.edgeId);
      const isDeny = e.conditions?.effect === 'DENY' || e.conditions?.active === false;
      const stroke = isViolation
        ? 'var(--status-risk)'
        : isDeny
          ? 'var(--border-strong)'
          : 'var(--primary)';
      const strokeDasharray = isDeny ? '4 4' : 'none';
      const strokeWidth = isViolation ? '2.5' : '1.5';
      const opacity = isViolation ? '0.96' : isDeny ? '0.7' : '0.52';
      const geom = computeEdgeGeometry(e.edgeId, from, to);

      const labelText =
        EDGE_SHORT_LABELS[e.edgeId] ?? e.edgeId.replace(/^e-/, '');
      const showLabel = isViolation || e.kind === 'can_read' || e.kind === 'transfers_data_to';
      const badgeW = Math.max(58, labelText.length * 6.5 + 12);

      return `<g class="graph-edge ${isViolation ? 'graph-edge-violation' : ''}" data-edge-id="${escapeHtml(e.edgeId)}">
        <path d="${geom.pathD}" fill="none" stroke="${stroke}" stroke-width="${strokeWidth}" stroke-opacity="${opacity}" stroke-dasharray="${strokeDasharray}" stroke-linecap="round" />
        <polygon points="${geom.arrowX - 6},${geom.arrowY - 3.5} ${geom.arrowX + 1},${geom.arrowY} ${geom.arrowX - 6},${geom.arrowY + 3.5}" fill="${stroke}" fill-opacity="${opacity}" />
        ${
          showLabel
            ? `<rect x="${Math.round(geom.labelX - badgeW / 2)}" y="${geom.labelY - 11}" width="${Math.round(badgeW)}" height="16" rx="3" fill="var(--bg)" fill-opacity="0.96" /><text x="${geom.labelX}" y="${geom.labelY}" fill="${isViolation ? 'var(--status-risk)' : 'var(--ink-muted)'}" font-family="var(--font-mono)" font-size="9.5" font-weight="${isViolation ? '600' : '500'}" text-anchor="middle">${escapeHtml(labelText)}</text>`
            : ''
        }
      </g>`;
    })
    .join('');

  const nodeSvg = fixture.nodes
    .map((n) => {
      const pos = nodePosMap.get(n.nodeId)!;
      const isRestricted = n.dataClassification === 'RESTRICTED';
      const isExternal = n.trustZone === 'EXTERNAL';
      const fill = isExternal
        ? 'var(--status-warn-bg)'
        : isRestricted
          ? 'var(--status-risk-bg)'
          : 'var(--surface)';
      const stroke = isExternal
        ? 'var(--status-warn-border)'
        : isRestricted
          ? 'var(--status-risk-border)'
          : 'var(--border-strong)';
      const subText = `${n.kind} · ${n.dataClassification ?? n.trustZone}`;
      const shortLabel = n.nodeId.split(':')[1] ?? n.nodeId;
      const rx = pos.x - GRAPH_NODE_W / 2;
      const ry = pos.y - GRAPH_NODE_H / 2;

      return `<g class="graph-node" data-node-id="${escapeHtml(n.nodeId)}">
        <rect x="${rx}" y="${ry}" width="${GRAPH_NODE_W}" height="${GRAPH_NODE_H}" rx="6" fill="${fill}" stroke="${stroke}" stroke-width="1.25" />
        <text x="${pos.x}" y="${pos.y - 3}" fill="var(--ink)" font-family="var(--font-sans)" font-size="11" font-weight="600" text-anchor="middle">${escapeHtml(shortLabel)}</text>
        <text x="${pos.x}" y="${pos.y + 12}" fill="var(--ink-muted)" font-family="var(--font-mono)" font-size="9" text-anchor="middle">${escapeHtml(subText)}</text>
      </g>`;
    })
    .join('');

  return `<svg viewBox="0 0 980 330" class="policy-graph-svg" role="img" aria-label="Access Reachability Graph">
    ${edgeSvg}
    ${nodeSvg}
  </svg>`;
}

function renderGraphAccessibleTable(
  fixture: PolicyGraphFixture,
  violatingEdges: Set<string>
): string {
  return `
    <div class="sr-only">
      <table class="sr-table">
        <caption>ChainBreak policy graph edges for ${escapeHtml(fixture.fixtureId)}</caption>
      <thead>
        <tr>
          <th>Edge</th>
          <th>From</th>
          <th>Kind</th>
          <th>To</th>
          <th>Classification</th>
          <th>Violated</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        ${fixture.edges
          .map(
            (e) => `
          <tr>
            <td>${escapeHtml(e.edgeId)}</td>
            <td>${escapeHtml(e.from)}</td>
            <td>${escapeHtml(e.kind)}</td>
            <td>${escapeHtml(e.to)}</td>
            <td>${escapeHtml(e.dataClassification)}</td>
            <td>${violatingEdges.has(e.edgeId) ? 'YES' : 'NO'}</td>
            <td>${escapeHtml(e.sourceRef)}</td>
          </tr>`
          )
          .join('')}
      </tbody>
    </table>
    </div>
  `;
}

function formatUnifiedDiffHtml(diff: string): string {
  const lines = String(diff ?? '').split(/\r?\n/);
  return lines
    .map((line) => {
      const safe = escapeHtml(line);
      if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('@@')) {
        return `<span class="diff-line-hdr">${safe}</span>`;
      }
      if (line.startsWith('+')) {
        return `<span class="diff-line-add">${safe}</span>`;
      }
      if (line.startsWith('-')) {
        return `<span class="diff-line-del">${safe}</span>`;
      }
      return `<span class="diff-line-ctx">${safe}</span>`;
    })
    .join('');
}

function renderHeaderHtml(
  state: DashboardState,
  currentTheme: 'light' | 'dark',
  popoverOpen: boolean
): string {
  const t = UI_TRANSLATIONS[state.language] ?? UI_TRANSLATIONS.en;
  const isLive = state.connectionMode === 'LIVE_MCP_HTTP';
  const isAlert = state.mascotState === 'alert';
  const dotClass = isAlert ? 'dot-alert' : isLive ? '' : 'dot-lab';
  const activePose = mapMascotStateToPose(
    state.mascotState,
    state.adjudication.status === 'PENDING_REVIEW'
  );

  return `
    <a class="skip-link" href="#main-content">${escapeHtml(t.skipToContent)}</a>
    <header class="topbar">
      <div class="topbar-left">
        <a class="brand-mark" href="#main-content">
          <span class="brand-symbol-wrap">${renderPatchCatSvg(activePose, { size: 28, label: 'PatchCat logo' })}</span>
          <span class="brand-name">ScriptKitty Live</span>
          <span class="brand-agent-tag">/ PatchCat</span>
        </a>
        <span class="breadcrumb-sep">/</span>
        <span class="workspace-crumb">${escapeHtml(t.workspaceCrumb)}</span>
      </div>

      <nav class="topbar-nav" aria-label="Primary sections">
        <a class="nav-link" href="#how">${escapeHtml(t.navHow)}</a>
        <a class="nav-link" href="#features">${escapeHtml(t.navFeatures)}</a>
        <a class="nav-link" href="#trust">${escapeHtml(t.navTrust)}</a>
        <a class="nav-link" href="#console">${escapeHtml(t.navConsole)}</a>
      </nav>

      <div class="topbar-right">
        <span class="pill ${isLive ? 'pill-live' : 'pill-lab'}">
          <span class="status-dot ${dotClass}" aria-hidden="true"></span>
          <span id="badge-connection-mode">${escapeHtml(state.modeBadge)}</span>
        </span>

        <div class="boundary-wrap">
          <button type="button" class="pill" id="badge-lab-boundary" aria-expanded="${popoverOpen ? 'true' : 'false'}">
            ${escapeHtml(t.sandboxPill)}
          </button>
          <div class="boundary-popover" id="popover-sandbox" ${popoverOpen ? '' : 'hidden'}>
            <strong>Execution Boundary Guards</strong>
            <p>All verification runs inside an isolated deterministic lab graph. Auto-merge, deploy, and external target execution remain hard-locked off.</p>
            <div class="invariant-line">productionTested: false · mergeAllowed: false · deployAllowed: false · externalExecution: false</div>
          </div>
        </div>

        <button class="icon-btn" id="btn-toggle-theme" type="button">
          ${escapeHtml(currentTheme === 'light' ? t.themeDark : t.themeLight)}
        </button>

        <button class="icon-btn" id="btn-open-keys" type="button">
          ${escapeHtml(t.btnKeys)}
        </button>

        <select id="select-lang" class="topbar-select" aria-label="Interface Language">
          <option value="en" ${state.language === 'en' ? 'selected' : ''}>EN</option>
          <option value="pt" ${state.language === 'pt' ? 'selected' : ''}>PT</option>
          <option value="es" ${state.language === 'es' ? 'selected' : ''}>ES</option>
        </select>
      </div>
    </header>
  `;
}

function renderLandingHeroHtml(state: DashboardState): string {
  const t = UI_TRANSLATIONS[state.language] ?? UI_TRANSLATIONS.en;
  const activePose = mapMascotStateToPose(
    state.mascotState,
    state.adjudication.status === 'PENDING_REVIEW'
  );
  const pathCount = state.analysis.paths.length;

  const poseChipsHtml = PATCHCAT_POSES.map(
    (pose) => `
      <div class="pose-chip ${pose === activePose ? 'active' : ''}" data-pose="${pose}">
        ${renderPatchCatSvg(pose, { size: 36, label: `PatchCat ${pose}` })}
        <span class="pose-chip-label">${pose}</span>
      </div>`
  ).join('');

  return `
    <div class="hero-grid">
      <div class="hero-copy-col">
        <p class="hero-eyebrow">${escapeHtml(t.heroEyebrow)}</p>
        <h1 class="hero-display-title" id="txt-landing-h1">${escapeHtml(t.landingH1)}</h1>
        <p class="hero-lead">${escapeHtml(t.landingLead)}</p>
        <div class="hero-cta-row">
          <a class="btn btn-primary" href="#console">${escapeHtml(t.ctaConsole)}</a>
          <a class="btn btn-secondary" href="${REPO_URL}" target="_blank" rel="noopener noreferrer">${escapeHtml(t.ctaGithub)}</a>
        </div>
        <div class="hero-disclosure-row">
          <span class="disclosure-pill">${escapeHtml(t.disclosureSynthetic)}</span>
          <span class="disclosure-pill">${escapeHtml(t.disclosureLocks)}</span>
        </div>
      </div>

      <div class="hero-mascot-col">
        <div class="hero-mascot-card">
          <div class="hero-mascot-top">
            <div class="hero-mascot-stage">
              <div class="hero-mascot-svg-box" id="hero-patchcat-svg">
                ${renderPatchCatSvg(activePose, { size: 56, label: `PatchCat ${activePose}` })}
              </div>
              <div>
                <div class="hero-mascot-status-title">PatchCat: ${escapeHtml(activePose.toUpperCase())}</div>
                <div class="hero-mascot-status-sub">${escapeHtml(state.activeFixtureId)} (${pathCount} exposed path)</div>
              </div>
            </div>
            <span class="pill pill-static pill-telemetry">${escapeHtml(t.telemetryStripBadge)}</span>
          </div>
          <div class="pose-strip" id="patchcat-pose-strip" aria-label="PatchCat five telemetry states">
            ${poseChipsHtml}
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderSidebarHtml(
  state: DashboardState,
  openDetailsIds: Set<string>
): string {
  const t = UI_TRANSLATIONS[state.language] ?? UI_TRANSLATIONS.en;
  const srv = state.mcp.serverStatus;
  const isLive = state.connectionMode === 'LIVE_MCP_HTTP';
  const connOpen =
    openDetailsIds.has('details-runtime-conn') ||
    Boolean(state.mcp.lastFallbackReason);

  const tabsHtml = FIXTURE_TAB_META.map((tab) => {
    const active = state.activeFixtureId === tab.id;
    const pillClass = tab.pillTone === 'risk' ? 'tab-pill-risk' : 'tab-pill-ok';
    return `
      <button
        type="button"
        role="tab"
        id="${tab.domId}"
        data-fixture="${escapeHtml(tab.id)}"
        class="scenario-tab ${active ? 'active' : ''}"
        aria-selected="${active ? 'true' : 'false'}"
        tabindex="${active ? '0' : '-1'}"
      >
        <div class="scenario-tab-left">
          <span class="tab-title">${escapeHtml(tab.label)}</span>
          <span class="tab-sub">${escapeHtml(tab.subtitle)}</span>
        </div>
        <span class="tab-pill ${pillClass}">${escapeHtml(tab.pill)}</span>
      </button>
    `;
  }).join('');

  const toolsToShow =
    state.mcp.availableTools.length > 0
      ? state.mcp.availableTools
      : CANONICAL_OFFLINE_TOOLS;
  const toolsBadge =
    state.mcp.availableTools.length > 0
      ? `${t.mcpToolsLiveLabel} (${toolsToShow.length})`
      : `${t.mcpToolsOfflineLabel} (${toolsToShow.length})`;

  return `
    <div class="rail-section">
      <div class="rail-heading">${escapeHtml(t.scenariosHeading)}</div>
      <div class="scenario-list" role="tablist" aria-label="Payments Lab Scenario States">
        ${tabsHtml}
      </div>
    </div>

    <details class="rail-section rail-details" id="details-runtime-conn" ${connOpen ? 'open' : ''}>
      <summary>
        <span>${escapeHtml(t.connectionHeading)}</span>
        <span class="mono">${isLive ? 'MCP Live' : 'Deterministic'}</span>
      </summary>
      <div class="mcp-config-stack">
        <label class="field-label" for="input-mcp-url">Loopback Endpoint</label>
        <input type="text" id="input-mcp-url" class="form-control" value="${escapeHtml(state.mcp.url)}" placeholder="http://127.0.0.1:3847/mcp" />
        <label class="field-label" for="input-mcp-token">Bearer Token (Volatile Memory)</label>
        <input type="password" id="input-mcp-token" class="form-control" value="" placeholder="${state.mcp.hasBearerToken ? '•••••••• (loaded in memory)' : 'Optional Bearer token'}" />
        <div class="mcp-btn-row">
          <button type="button" class="btn btn-primary btn-xs" id="btn-mcp-connect">Connect MCP</button>
          <button type="button" class="btn btn-secondary btn-xs" id="btn-mcp-reset">Lab Mode</button>
        </div>
        <div class="mcp-meta-box">
          <div>Session: <span class="mono">${escapeHtml(state.mcp.sessionId ?? 'offline (deterministic)')}</span></div>
          <div>Advisory Provider: <span class="mono">${escapeHtml(srv?.jevProviderStatus ?? state.adjudication.providerStatus)}</span></div>
          <div>Verification Sandbox: <span class="mono">${escapeHtml(srv?.kaliMcpStatus ?? 'ISOLATED_STANDBY')}</span></div>
          <div>Active Model: <span class="mono">${escapeHtml(state.aiConfig.activeProvider.toUpperCase())}</span></div>
          ${
            state.mcp.lastFallbackReason
              ? `<div class="fallback-note" id="txt-mcp-fallback">Fallback: ${escapeHtml(state.mcp.lastFallbackReason)}</div>`
              : ''
          }
        </div>
      </div>
    </details>

    <section class="rail-section" id="panel-mcp-tools">
      <div class="panel-header">
        <span class="rail-heading">${escapeHtml(t.mcpToolsHeading)}</span>
        <span class="quiet-meta-pill">${escapeHtml(toolsBadge)}</span>
      </div>
      <ul class="mcp-tool-list">
        ${toolsToShow
          .map(
            (toolName) =>
              `<li class="mcp-tool-item"><span>${escapeHtml(toolName)}</span><span>${isLive ? 'LIVE' : 'LAB'}</span></li>`
          )
          .join('')}
      </ul>
    </section>
  `;
}

function renderHeroTextHtml(state: DashboardState): string {
  const t = UI_TRANSLATIONS[state.language] ?? UI_TRANSLATIONS.en;
  return `
    <div class="workspace-title-block">
      <h2 id="txt-hero-title">${escapeHtml(t.heroTitle)}</h2>
      <p id="txt-hero-desc">${escapeHtml(t.heroDesc)}</p>
    </div>
    <div class="workspace-actions">
      <button class="btn btn-primary" id="btn-scout" type="button" ${state.isBusy ? 'disabled' : ''}>${escapeHtml(t.btnScout)}</button>
      <button class="btn btn-secondary" id="btn-learn" type="button">${escapeHtml(t.btnMemory)}</button>
      <button class="btn btn-secondary" id="btn-pr" type="button">${escapeHtml(t.btnPr)}</button>
    </div>
  `;
}

function renderPanelsHtml(
  state: DashboardState,
  openDetailsIds: Set<string>
): string {
  const t = UI_TRANSLATIONS[state.language] ?? UI_TRANSLATIONS.en;
  const { analysis, adjudication, qualityGate, factoryDelivery } = state;
  const displaySpec = state.activeRemediationSpec ?? state.referenceRemediationSpec;
  const primaryAction = displaySpec.actions[0];
  const violatingEdges = new Set<string>(
    analysis.paths.flatMap((p) => p.edges.map((e) => e.edgeId))
  );
  const preservedCount = analysis.legitimateOperations.filter(
    (op) => op.preserved
  ).length;
  const totalLegit = analysis.legitimateOperations.length;
  const hasViolation = analysis.paths.length > 0;

  const pathsHtml = !hasViolation
    ? `<div class="empty-clean-banner">
        <strong>No unauthorized export paths detected.</strong> Policy <code>NO_RESTRICTED_DATA_EXTERNAL_TRANSFER</code> holds cleanly with ${preservedCount}/${totalLegit} core business workflows preserved.
      </div>`
    : analysis.paths
        .map(
          (p) => `
        <div class="path-detail-block">
          <div class="path-header-row">
            <span class="status-pill badge-high">${escapeHtml(p.status)}</span>
            <span class="status-pill badge-medium">Severity ${escapeHtml(p.riskRecommendation)}</span>
            <code class="mono-tag">${escapeHtml(p.violatedPolicyId)}</code>
          </div>
          <p class="path-summary">${escapeHtml(p.nonTechnicalSummary)}</p>
          <div class="table-responsive">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Hop</th>
                  <th>Link</th>
                  <th>Transition</th>
                  <th>Classification / Scope</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                ${p.edges
                  .map(
                    (edge, idx) => `
                  <tr>
                    <td class="mono">${idx + 1}</td>
                    <td><code>${escapeHtml(edge.edgeId)}</code></td>
                    <td><code>${escapeHtml(edge.from)}</code> → <code>${escapeHtml(edge.to)}</code></td>
                    <td>${escapeHtml(edge.dataClassification)} / ${escapeHtml(edge.scope)}</td>
                    <td><code>${escapeHtml(edge.sourceRef)}</code></td>
                  </tr>`
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </div>`
        )
        .join('');

  const legitOpsHtml =
    totalLegit === 0
      ? `<div class="muted-note">Negative-control scenario isolates transition semantics (0 business workflows registered; 0 exposed paths permitted).</div>`
      : analysis.legitimateOperations
          .map(
            (op) => `
          <div class="legit-op-item">
            <span class="legit-op-head">
              <span class="status-indicator ${op.preserved ? 'dot-ok' : 'dot-risk'}" aria-hidden="true"></span>
              <code>${escapeHtml(op.operationId)}</code>
            </span>
            <span class="op-desc">${escapeHtml(op.description)}</span>
          </div>`
          )
          .join('');

  const reviewBadgeClass =
    adjudication.status === 'PENDING_REVIEW'
      ? 'badge-medium'
      : adjudication.status === 'ACCEPTED_FOR_TRIAGE'
        ? 'badge-low'
        : 'badge-high';

  const triageChoice = adjudication.triage ?? 'N/A';
  const triageConf = adjudication.answers?.triage.confidence ?? 0;
  const isGatePass = qualityGate.verdict === 'PASS';
  const graphVerificationLabel = hasViolation ? 'CONFIRMED_BY_GRAPH' : 'CLEAR';
  const reviewGateLabel =
    adjudication.status === 'PENDING_REVIEW' ? 'REVIEW_REQUIRED' : adjudication.status;

  const chainReceiptOpen = openDetailsIds.has('details-receipt-chainbreak') ? 'open' : '';
  const reviewReceiptOpen = openDetailsIds.has('details-receipt-review') ? 'open' : '';
  const gateReceiptOpen = openDetailsIds.has('details-receipt-gate') ? 'open' : '';
  const deliveryReceiptOpen = openDetailsIds.has('details-receipt-delivery') ? 'open' : '';

  return `
    ${
      state.toastMessage
        ? `<div class="toast-banner" id="toast-banner" role="status">
            <span>${escapeHtml(state.toastMessage)}</span>
            <button type="button" id="btn-dismiss-toast" class="btn-close" aria-label="Dismiss notification">x</button>
          </div>`
        : ''
    }

    ${renderOpenUiAdvisoryBrief(state)}

    <section class="action-strip ${hasViolation ? 'strip-alert' : 'strip-clear'}">
      <div class="action-strip-copy">
        <h3 id="txt-learning-title">${escapeHtml(t.learningTitle)}</h3>
        <p id="txt-learning-desc">${escapeHtml(t.learningDesc)}</p>
      </div>
      <button class="btn btn-primary" id="btn-pr-suggest" type="button">
        ${escapeHtml(t.btnPrSuggest)}
      </button>
    </section>

    ${
      state.prSuggestionOpen && state.prSuggestion
        ? `<section class="panel" id="panel-pr-suggestion">
            <div class="panel-header">
              <span class="panel-title">${escapeHtml(state.prSuggestion.title)}</span>
              <span class="status-pill badge-medium">Review Required</span>
            </div>
            <div class="kv-list">
              <div class="kv-row">
                <span class="kv-label">Verification Delta</span>
                <span class="kv-value mono">Paths ${state.prSuggestion.pathsBefore} → ${state.prSuggestion.pathsAfter} · Workflows ${escapeHtml(state.prSuggestion.legitimatePreservedSummary)}</span>
              </div>
              <div class="kv-row">
                <span class="kv-label">Governance Locks</span>
                <span class="kv-value mono">requiresHumanApproval: true · autoApplyAllowed: false · mergeAllowed: false · deployAllowed: false</span>
              </div>
            </div>
            <pre class="diff-pre">${formatUnifiedDiffHtml(state.prSuggestion.unifiedDiff)}</pre>
          </section>`
        : ''
    }

    <section class="panel" id="panel-chainbreak">
      <div class="panel-header">
        <span class="panel-title">${escapeHtml(t.graphTitle)}</span>
        <span class="panel-meta">${hasViolation ? `${analysis.paths.length} unauthorized path` : '0 violations'} · ${preservedCount}/${totalLegit} workflows OK</span>
      </div>

      <div class="graph-canvas-wrap">
        ${renderPolicyGraphSvg(state.fixture, violatingEdges)}
      </div>
      ${renderGraphAccessibleTable(state.fixture, violatingEdges)}

      ${pathsHtml}

      <div class="sub-section-title">Protected Business Workflows (${preservedCount}/${totalLegit})</div>
      <div class="legit-ops-grid">
        ${legitOpsHtml}
      </div>

      <details class="tech-receipt" id="details-receipt-chainbreak" ${chainReceiptOpen}>
        <summary>Cryptographic &amp; Policy Receipt</summary>
        <div class="tech-receipt-body">
          <div>Scope guarantee: PATH_VALIDATED confirms deterministic graph reachability in the sandbox (NEVER EXPLOIT_CONFIRMED).</div>
          <div>analysisId: ${escapeHtml(analysis.analysisId)} · policyVersion: ${escapeHtml(analysis.policyVersion)} · status: ${escapeHtml(analysis.status)}</div>
          <div>inputSha256: <code id="txt-input-sha256">${escapeHtml(analysis.inputSha256)}</code></div>
          <div>legitimateOperationsPreserved: <code id="txt-legit-preserved">${String(analysis.legitimateOperationsPreserved)} (${preservedCount}/${totalLegit})</code></div>
        </div>
      </details>
    </section>

    <div class="dual-panels-grid">
      <section class="panel" id="panel-jev">
        <div class="panel-header">
          <span class="panel-title">${escapeHtml(t.reviewTitle)}</span>
          <span class="status-pill ${reviewBadgeClass}">${escapeHtml(reviewGateLabel)}</span>
        </div>

        <div class="kv-list">
          <div class="kv-row">
            <span class="kv-label">Graph Verification</span>
            <span class="kv-value mono">${escapeHtml(graphVerificationLabel)}</span>
          </div>
          <div class="kv-row">
            <span class="kv-label">Advisory Provider</span>
            <span class="kv-value mono">${escapeHtml(adjudication.providerStatus)}</span>
          </div>
          <div class="kv-row">
            <span class="kv-label">Triage Assessment</span>
            <span class="kv-value">${escapeHtml(triageChoice)} (${Math.round(triageConf * 100)}% confidence)</span>
          </div>
          <div class="kv-row">
            <span class="kv-label">Advisory Authority</span>
            <span class="kv-value">Advisory Only · Cannot override policy</span>
          </div>
        </div>

        <div class="invariant-line">
          <span>Risk Level: ${escapeHtml(adjudication.riskRecommendation)} · Human Sign-off: ${adjudication.requiresHumanReview ? 'Required' : 'Optional'} · Evidence: ${adjudication.probabilities.evidenceSufficient.toFixed(2)}</span>
        </div>

        <details class="tech-receipt" id="details-receipt-review" ${reviewReceiptOpen}>
          <summary>Advisory Protocol Details</summary>
          <div class="tech-receipt-body">
            <div>status: ${escapeHtml(adjudication.status)} · decisionSource: <code id="txt-jev-source">${escapeHtml(adjudication.decisionSource)}</code> · providerStatus: ${escapeHtml(adjudication.providerStatus)} · model: ${escapeHtml(adjudication.model)}</div>
            <div>p0DefinedByJevAlone: ${String(adjudication.p0DefinedByJevAlone)} · thresholdCalibrated: ${String(adjudication.confidenceOrUncertainty.thresholdCalibrated)} · mergeAllowed: false · deployAllowed: false</div>
            <div>evidenceSufficient: ${adjudication.probabilities.evidenceSufficient.toFixed(2)} · needsManualReview: ${adjudication.probabilities.needsManualReview.toFixed(2)}</div>
            <div>sanitizedStateDigest: ${escapeHtml(adjudication.sanitizedStateDigest)}</div>
            <div>preValidation: ${adjudication.preValidation.passed ? '5/5 CHECKS PASSED' : escapeHtml(adjudication.preValidation.blockingOutcome)}</div>
            ${
              adjudication.escalationReasons.length > 0
                ? `<ul class="reason-list">${adjudication.escalationReasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>`
                : '<div>No escalation blockers recorded.</div>'
            }
          </div>
        </details>
      </section>

      <section class="panel" id="panel-remediation-gate">
        <div class="panel-header">
          <span class="panel-title">${escapeHtml(t.gateTitle)}</span>
          <span class="status-pill ${isGatePass ? 'badge-low' : 'badge-high'}" id="txt-gate-verdict">${escapeHtml(qualityGate.verdict)}</span>
        </div>

        <div class="gate-sub-header">
          <span class="kv-label">Tri-Party Separation of Duties (Discoverer ≠ Verifier ≠ Authorizer)</span>
          <button type="button" class="btn btn-secondary btn-xs" id="btn-toggle-self-cert">
            ${state.simulateSelfCert ? 'Restore Independent Review' : 'Test Self-Cert Guard'}
          </button>
        </div>

        <div class="sod-roles-row">
          <div class="sod-role-chip">
            <span class="sod-role-name">Discoverer</span>
            <span class="sod-role-agent">${escapeHtml(qualityGate.sod_evaluation.discovering_agent_id)}</span>
          </div>
          <div class="sod-role-chip">
            <span class="sod-role-name">Verifier</span>
            <span class="sod-role-agent">${escapeHtml(qualityGate.sod_evaluation.verifying_agent_id)}</span>
          </div>
          <div class="sod-role-chip">
            <span class="sod-role-name">Authorizer</span>
            <span class="sod-role-agent">${escapeHtml(qualityGate.sod_evaluation.authorizing_agent_id)}</span>
          </div>
        </div>

        <div class="delivery-readiness-note" id="panel-factory-delivery">
          <div><strong>Release Readiness:</strong> ${factoryDelivery.eligible ? 'Eligible for Human PR Review' : 'Blocked by Release Policy'} · <strong>Target Action:</strong> <code>${escapeHtml(primaryAction.actionType)}</code> on <code>${escapeHtml(primaryAction.edgeId)}</code></div>
          ${
            !qualityGate.sod_evaluation.is_valid && qualityGate.sod_evaluation.violation_code
              ? `<div class="fallback-note">Violation: <code>${escapeHtml(qualityGate.sod_evaluation.violation_code)}</code> — ${escapeHtml(qualityGate.sod_evaluation.violation_details ?? 'Self-certification forbidden')}</div>`
              : ''
          }
          ${
            factoryDelivery.blockReason && qualityGate.sod_evaluation.is_valid
              ? `<div class="muted-note">Hold reason: ${escapeHtml(factoryDelivery.blockReason)}</div>`
              : ''
          }
          <details class="tech-receipt" id="details-receipt-delivery" ${deliveryReceiptOpen}>
            <summary>Delivery Contract Receipt</summary>
            <div class="tech-receipt-body">
              <div class="mono">contract: ${escapeHtml(factoryDelivery.contract)} · eligible: ${String(factoryDelivery.eligible)} · stage: ${escapeHtml(factoryDelivery.stage)} · mergeAllowed: false · deployAllowed: false</div>
            </div>
          </details>
        </div>

        <details class="tech-receipt" id="details-receipt-gate" ${gateReceiptOpen}>
          <summary>Custody Merkle &amp; Counterfactual Spec</summary>
          <div class="tech-receipt-body">
            <div>Custody Chain: ${qualityGate.custody_chain.total_nodes}/3 verified (valid: ${String(qualityGate.custody_valid)})</div>
            <div>merkle_root: <code id="txt-merkle-root" class="merkle-hash">${escapeHtml(qualityGate.merkle_root)}</code></div>
            <div>minimalChange: ${String(displaySpec.minimalChange)} · breaksUnauthorizedPath: ${String(displaySpec.breaksUnauthorizedPath)} · preservesLegitimateOperations: ${String(displaySpec.preservesLegitimateOperations)}</div>
            <div>requiresHumanApproval: true · autoApplyAllowed: false · sourceRef: ${escapeHtml(primaryAction.sourceRef)}</div>
          </div>
        </details>
      </section>
    </div>

    <section class="panel ${state.memoryDrawerOpen ? 'memory-open' : 'memory-collapsed'}" id="panel-memory">
      <div class="panel-header">
        <span class="panel-title">${escapeHtml(t.memoryTitle)}</span>
        <span class="panel-meta">${state.memorySnapshots.length} snapshot(s) · ${state.decisionHistory.length} decision(s)</span>
      </div>
      ${
        state.memoryDrawerOpen
          ? `<div class="table-responsive">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Scenario</th>
                    <th>Analysis ID</th>
                    <th>Paths</th>
                    <th>Review Status</th>
                    <th>Mode</th>
                    <th>Digest</th>
                  </tr>
                </thead>
                <tbody>
                  ${state.memorySnapshots
                    .map(
                      (s) => `
                    <tr>
                      <td><code>${escapeHtml(s.fixtureId)}</code></td>
                      <td><code>${escapeHtml(s.analysisId)}</code></td>
                      <td>${s.pathsCount}</td>
                      <td><code>${escapeHtml(s.jevStatus)}</code></td>
                      <td><code>${escapeHtml(s.mode)}</code></td>
                      <td><code>${escapeHtml(s.inputSha256.slice(0, 16))}...</code></td>
                    </tr>`
                    )
                    .join('')}
                </tbody>
              </table>
            </div>`
          : `<div class="muted-note">Select <strong>${escapeHtml(t.btnMemory)}</strong> in the workspace header to inspect recorded tenant runs.</div>`
      }
    </section>

    <section class="panel">
      <div class="panel-header">
        <span class="panel-title">${escapeHtml(t.auditTitle)}</span>
        <span class="panel-meta">${state.auditLog.length} event(s)</span>
      </div>
      <div class="audit-terminal" id="audit-terminal">
        ${state.auditLog
          .map(
            (entry) => `
          <div class="audit-entry">
            <span class="audit-hash">[${escapeHtml(entry.hash)}]</span>
            <span class="audit-cat">${escapeHtml(entry.category)}</span>
            <span>${escapeHtml(entry.message)}</span>
          </div>`
          )
          .join('')}
      </div>
    </section>
  `;
}

function renderEditorialSectionsHtml(state: DashboardState): string {
  const t = UI_TRANSLATIONS[state.language] ?? UI_TRANSLATIONS.en;
  const isPt = state.language === 'pt';
  const isEs = state.language === 'es';

  return `
    <section id="features" class="editorial-band">
      <div class="landing-section">
        <div class="section-header">
          <h2>${escapeHtml(t.problemHeading)}</h2>
          <p>${escapeHtml(t.problemLead)}</p>
        </div>
        <div class="outcomes-grid">
          <article class="outcome-block">
            <span class="outcome-meta">ChainBreak Policy Graph</span>
            <h3>${isPt ? 'Alcançabilidade Determinística' : isEs ? 'Alcanzabilidad Determinística' : 'Deterministic Reachability Proof'}</h3>
            <p>${isPt ? 'Rastreia saltos entre identidades, ferramentas MCP, ativos de dados e destinos externos com referência exata de arquivo e linha.' : isEs ? 'Rastrea saltos entre identidades, herramientas MCP, datos y destinos externos con referencia exacta.' : 'Traces multi-hop reachability across identities, MCP tools, data assets, and external sinks anchored to exact sourceRef lines and SHA-256 hashes.'}</p>
          </article>
          <article class="outcome-block">
            <span class="outcome-meta">Verified Remediation</span>
            <h3>${isPt ? 'Correção Contrafactual Mínima' : isEs ? 'Remediación Contrafactual Mínima' : 'Counterfactual Minimal Fix'}</h3>
            <p>${isPt ? 'Gera a menor remoção de aresta que zera a exposição (1 -> 0) enquanto preserva 3/3 operações de negócio legítimas.' : isEs ? 'Genera el retiro mínimo de arista que cierra la ruta (1 -> 0) preservando 3/3 flujos legítimos.' : 'Synthesizes the smallest edge removal that breaks unauthorized exposure (1 -> 0) while proving 3/3 legitimate operations remain intact.'}</p>
          </article>
          <article class="outcome-block">
            <span class="outcome-meta">Agent &amp; MCP Security</span>
            <h3>${isPt ? 'Governança Tripartite Fail-Closed' : isEs ? 'Gobernanza Tripartita Fail-Closed' : 'Fail-Closed Tri-Party Governance'}</h3>
            <p>${isPt ? 'Exige descoberta, verificação e autorização independentes, transporte MCP restrito a loopback e trava permanente contra auto-merge.' : isEs ? 'Exige descubrimiento, verificación y autorización independientes con bloqueo permanente contra auto-merge.' : 'Enforces independent discovery, verification, and authorization identities alongside loopback-only MCP controls and permanent human approval locks.'}</p>
          </article>
        </div>
      </div>
    </section>

    <section id="how" class="editorial-band-alt">
      <div class="landing-section">
        <div class="section-header">
          <h2>${escapeHtml(t.howHeading)}</h2>
          <p>${escapeHtml(t.howLead)}</p>
        </div>
        <div class="steps-grid">
          <div class="step-card">
            <span class="step-tag">Step 1</span>
            <h3>${isPt ? 'Modelar o Grafo' : isEs ? 'Modelar el Grafo' : 'Model Policy Graph'}</h3>
            <p>${isPt ? 'Normaliza identidades, ferramentas MCP, classificações PII e destinos com hash SHA-256 canônico.' : isEs ? 'Normaliza identidades, herramientas MCP, clasificaciones y destinos con hash SHA-256.' : 'Normalize identities, MCP tools, data classifications, and trust zones with canonical SHA-256 integrity.'}</p>
          </div>
          <div class="step-card">
            <span class="step-tag">Step 2</span>
            <h3>${isPt ? 'Provar Alcançabilidade' : isEs ? 'Probar Alcanzabilidad' : 'Prove Reachability'}</h3>
            <p>${isPt ? 'Executa travessia determinística e marca rotas reais como PATH_VALIDATED, nunca EXPLOIT_CONFIRMED.' : isEs ? 'Ejecuta recorrido determinístico marcando rutas como PATH_VALIDATED, nunca EXPLOIT_CONFIRMED.' : 'Run deterministic traversal and label verified exposure routes as PATH_VALIDATED, never EXPLOIT_CONFIRMED.'}</p>
          </div>
          <div class="step-card">
            <span class="step-tag">Step 3</span>
            <h3>${isPt ? 'Sintetizar Correção' : isEs ? 'Sintetizar Corrección' : 'Synthesize Minimal Diff'}</h3>
            <p>${isPt ? 'Propõe remoção mínima de permissão e reavalia contrafactualmente os fluxos protegidos.' : isEs ? 'Propone retiro mínimo de permiso y reevalúa contrafactualmente los flujos protegidos.' : 'Generate minimal edge-removal diffs and re-verify protected business workflows stay operational.'}</p>
          </div>
          <div class="step-card">
            <span class="step-tag">Step 4</span>
            <h3>${isPt ? 'Selo e Aprovação Humana' : isEs ? 'Custodia y Aprobación Humana' : 'Custody & Human Gate'}</h3>
            <p>${isPt ? 'Valida separação tripartite de deveres, cadeia Merkle RFC 8785 e revisão humana obrigatória.' : isEs ? 'Valida separación tripartita de deberes, cadena Merkle RFC 8785 y revisión humana obligatoria.' : 'Validate Tri-Party Separation of Duties, RFC 8785 Merkle custody, and mandatory human sign-off.'}</p>
          </div>
        </div>
      </div>
    </section>

    <section id="trust" class="editorial-band">
      <div class="landing-section">
        <div class="section-header">
          <h2>${escapeHtml(t.trustHeading)}</h2>
          <p>${escapeHtml(t.trustLead)}</p>
        </div>
        <div class="trust-grid">
          <div class="panel">
            <div class="panel-header">
              <span class="panel-title">${isPt ? 'Invariantes Não-Negociáveis' : isEs ? 'Invariantes No Negociables' : 'Non-Negotiable Safety Locks'}</span>
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
              <span class="panel-title">${escapeHtml(t.statusHeading)}</span>
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
          <h2>${escapeHtml(t.faqHeading)}</h2>
        </div>
        <div class="faq-list">
          <details class="faq-item">
            <summary>${isPt ? 'Quais dados alimentam este laboratório?' : isEs ? '¿Qué datos alimentan este laboratorio?' : 'What data feeds this security console?'}</summary>
            <p>${isPt ? 'Todas as execuções usam fixtures sintéticas de payments-lab e um alvo loopback isolado. Nenhum alvo real de produção é escaneado.' : isEs ? 'Todas las ejecuciones usan fixtures sintéticas de payments-lab y un objetivo loopback aislado.' : 'Every verification run uses synthetic payments-lab policy fixtures and an isolated loopback lab target. No live production targets are scanned.'}</p>
          </details>
          <details class="faq-item">
            <summary>${isPt ? 'Por que os achados são marcados como PATH_VALIDATED e não EXPLOIT_CONFIRMED?' : isEs ? '¿Por qué las rutas son PATH_VALIDATED y no EXPLOIT_CONFIRMED?' : 'Why are findings marked PATH_VALIDATED instead of EXPLOIT_CONFIRMED?'}</summary>
            <p>${isPt ? 'ChainBreak comprova alcançabilidade determinística em grafos de política modelados e referências de origem. Nunca exageramos alcançabilidade como exploração ativa em produção.' : isEs ? 'ChainBreak demuestra alcanzabilidad determinística en grafos de política con referencias exactas de origen.' : 'ChainBreak proves deterministic reachability on modeled policy graphs anchored to sourceRef lines and SHA-256 hashes. We never claim graph reachability equals live production exploitation.'}</p>
          </details>
          <details class="faq-item">
            <summary>${isPt ? 'O PatchCat aplica patches ou faz merge automaticamente?' : isEs ? '¿PatchCat aplica parches o hace merge automáticamente?' : 'Can PatchCat auto-apply patches or merge pull requests?'}</summary>
            <p>${isPt ? 'Nunca. Todas as entregas travam autoApplyAllowed=false, mergeAllowed=false e deployAllowed=false, exigindo aprovação humana explícita.' : isEs ? 'Nunca. Todas las entregas mantienen autoApplyAllowed=false, mergeAllowed=false y deployAllowed=false.' : 'Never. Every remediation spec and release gate locks autoApplyAllowed=false, mergeAllowed=false, and deployAllowed=false, requiring explicit human sign-off.'}</p>
          </details>
        </div>
      </div>
    </section>

    <footer class="site-footer">
      <div class="footer-inner">
        <span class="footer-meta">${escapeHtml(t.footerCopy)}</span>
        <div class="footer-links">
          <a href="${REPO_URL}" target="_blank" rel="noopener noreferrer">GitHub</a>
          <a href="#console">${escapeHtml(t.navConsole)}</a>
          <a href="#trust">${escapeHtml(t.navTrust)}</a>
        </div>
      </div>
    </footer>
  `;
}

function renderModalHtml(state: DashboardState): string {
  if (!state.showKeyModal) return '';
  return `
    <div class="modal-overlay" id="modal-overlay">
      <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="modal-keys-title">
        <div class="modal-header">
          <h3 id="modal-keys-title">Model Provider Credentials</h3>
          <button class="btn-close" id="btn-close-keys" type="button" aria-label="Close">x</button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label for="key-provider">Active Reasoning Engine</label>
            <select id="key-provider" class="form-control">
              <option value="openai" ${state.aiConfig.activeProvider === 'openai' ? 'selected' : ''}>OpenAI (GPT-4o / Codex)</option>
              <option value="google" ${state.aiConfig.activeProvider === 'google' ? 'selected' : ''}>Google Gemini (2.5 Flash / Pro)</option>
              <option value="nvidia" ${state.aiConfig.activeProvider === 'nvidia' ? 'selected' : ''}>NVIDIA NIM Security AI</option>
              <option value="openrouter" ${state.aiConfig.activeProvider === 'openrouter' ? 'selected' : ''}>OpenRouter (Multi-Model)</option>
              <option value="claude" ${state.aiConfig.activeProvider === 'claude' ? 'selected' : ''}>Anthropic Claude</option>
              <option value="grok" ${state.aiConfig.activeProvider === 'grok' ? 'selected' : ''}>xAI Grok</option>
              <option value="codex" ${state.aiConfig.activeProvider === 'codex' ? 'selected' : ''}>ChatGPT Codex Subscription</option>
            </select>
          </div>
          <div class="form-group">
            <label for="input-openai">OpenAI API Key</label>
            <input type="password" id="input-openai" class="form-control" placeholder="${state.aiConfig.hasOpenaiKey ? '•••••••• (stored in memory)' : 'sk-...'}" value="" />
          </div>
          <div class="form-group">
            <label for="input-google">Google Gemini API Key</label>
            <input type="password" id="input-google" class="form-control" placeholder="${state.aiConfig.hasGoogleKey ? '•••••••• (stored in memory)' : 'AIzaSy...'}" value="" />
          </div>
          <div class="form-group">
            <label for="input-nvidia">NVIDIA NIM API Key</label>
            <input type="password" id="input-nvidia" class="form-control" placeholder="${state.aiConfig.hasNvidiaKey ? '•••••••• (stored in memory)' : 'nvapi-...'}" value="" />
          </div>
          <div class="form-group">
            <label for="input-openrouter">OpenRouter API Key</label>
            <input type="password" id="input-openrouter" class="form-control" placeholder="${state.aiConfig.hasOpenrouterKey ? '•••••••• (stored in memory)' : 'sk-or-v1-...'}" value="" />
          </div>
          <div class="form-group">
            <label for="input-claude">Anthropic Claude API Key</label>
            <input type="password" id="input-claude" class="form-control" placeholder="${state.aiConfig.hasAnthropicKey ? '•••••••• (stored in memory)' : 'sk-ant-...'}" value="" />
          </div>
          <div class="form-group">
            <label for="input-grok">xAI Grok API Key</label>
            <input type="password" id="input-grok" class="form-control" placeholder="${state.aiConfig.hasGrokKey ? '•••••••• (stored in memory)' : 'xai-...'}" value="" />
          </div>
          <div class="form-group">
            <label for="input-codex">ChatGPT Codex Subscription Token</label>
            <input type="password" id="input-codex" class="form-control" placeholder="${state.aiConfig.hasCodexToken ? '•••••••• (stored in memory)' : 'Paste Codex subscription token...'}" value="" />
            <span class="muted-note">Credentials stay strictly in volatile runtime memory and never serialize into DOM or advisory logs.</span>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-primary" id="btn-save-keys" type="button">Save Configuration</button>
        </div>
      </div>
    </div>
  `;
}

/**
 * Mounts `PatchCatLiveController` + `MotionCatMascot3D` onto a root container and binds
 * workflow controls, keyboard-accessible scenario tabs, theme toggle, language persistence,
 * sandbox popover, and Motion.dev cues.
 */
export function mountPatchCatDashboard(
  root: Element,
  controller: PatchCatLiveController,
  options: MountDashboardOptions = {}
): MountedDashboard {
  const savedLang = readSessionValue('scriptkitty.lang');
  if (
    (savedLang === 'en' || savedLang === 'pt' || savedLang === 'es') &&
    controller.getState().language !== savedLang
  ) {
    controller.setLanguage(savedLang);
  }

  const initial = controller.getState();
  const initialT = UI_TRANSLATIONS[initial.language] ?? UI_TRANSLATIONS.en;

  let currentTheme: 'light' | 'dark' = 'dark';
  const savedTheme = readSessionValue('scriptkitty.theme');
  if (savedTheme === 'light' || savedTheme === 'dark') {
    currentTheme = savedTheme;
  }

  let sandboxPopoverOpen = false;
  const openDetailsIds = new Set<string>();
  let prevFixtureId: string | null = null;
  let prevModalOpen = initial.showKeyModal;
  let prevAuditCount = initial.auditLog.length;

  const doc =
    options.doc ??
    (typeof document !== 'undefined' ? document : undefined);

  if (doc?.documentElement && typeof doc.documentElement.setAttribute === 'function') {
    const existingTheme =
      typeof doc.documentElement.getAttribute === 'function'
        ? doc.documentElement.getAttribute('data-theme')
        : null;
    if (existingTheme === 'dark' || existingTheme === 'light') {
      currentTheme = existingTheme;
    } else {
      doc.documentElement.setAttribute('data-theme', currentTheme);
    }
  }

  root.innerHTML = `
    <div id="mount-header"></div>
    <main id="main-content" class="page-shell">
      <section class="hero-section" id="mount-hero-landing"></section>
      <section id="console" class="console-section" aria-label="PatchCat Interactive Console">
        <div class="app-shell">
          <aside class="rail">
            <div class="rail-section">
              <div class="rail-heading" id="txt-posture-heading">${escapeHtml(initialT.postureHeading)}</div>
              <div class="telemetry-row">
                <div id="mascot-3d-container"></div>
                <div class="telemetry-meta">
                  <span class="mascot-3d-label" id="mascot-state-label">PATCHCAT TELEMETRY: ${escapeHtml(initial.mascotState.toUpperCase())}</span>
                  <span class="telemetry-sub" id="txt-posture-sub">${escapeHtml(initialT.postureSub)}</span>
                </div>
              </div>
            </div>
            <div id="mount-sidebar" class="rail-stack"></div>
          </aside>
          <div class="workspace">
            <section class="workspace-header" id="mount-hero-text"></section>
            <div id="mount-panels" class="workspace-stack"></div>
          </div>
        </div>
      </section>
      <div id="mount-editorial"></div>
    </main>
    <div id="mount-modal"></div>
  `;

  const mascotFactory =
    options.mascotFactory ??
    ((containerId: string, state: MascotState) =>
      new MotionCatMascot3D(containerId, state));

  let mascot: MascotControllerHandle | null = null;
  try {
    mascot = mascotFactory('mascot-3d-container', initial.mascotState);
  } catch {
    mascot = null;
  }

  const getEl = (selector: string): Element | null =>
    root.querySelector(selector);

  const trackDetailsToggles = (): void => {
    const detailIds = [
      'details-runtime-conn',
      'details-receipt-chainbreak',
      'details-receipt-review',
      'details-receipt-gate',
      'details-receipt-delivery',
    ];
    for (const id of detailIds) {
      const el = getEl(`#${id}`);
      if (!el) continue;
      el.addEventListener('toggle', () => {
        const isOpen =
          typeof (el as { open?: boolean }).open === 'boolean'
            ? Boolean((el as { open?: boolean }).open)
            : typeof el.getAttribute === 'function' && el.getAttribute('open') !== null;
        if (isOpen) {
          openDetailsIds.add(id);
        } else {
          openDetailsIds.delete(id);
        }
      });
    }
  };

  let latestState = initial;

  const renderState = (state: DashboardState): void => {
    latestState = state;
    const t = UI_TRANSLATIONS[state.language] ?? UI_TRANSLATIONS.en;

    const headerMount = getEl('#mount-header');
    const landingHeroMount = getEl('#mount-hero-landing');
    const sidebarMount = getEl('#mount-sidebar');
    const heroMount = getEl('#mount-hero-text');
    const panelsMount = getEl('#mount-panels');
    const editorialMount = getEl('#mount-editorial');
    const modalMount = getEl('#mount-modal');
    const mascotLabel = getEl('#mascot-state-label');
    const postureHeading = getEl('#txt-posture-heading');
    const postureSub = getEl('#txt-posture-sub');

    if (doc?.documentElement && typeof doc.documentElement.setAttribute === 'function') {
      doc.documentElement.setAttribute(
        'lang',
        state.language === 'pt' ? 'pt-BR' : state.language
      );
    }

    if (headerMount) {
      headerMount.innerHTML = renderHeaderHtml(state, currentTheme, sandboxPopoverOpen);
    }
    if (landingHeroMount) {
      landingHeroMount.innerHTML = renderLandingHeroHtml(state);
    }
    if (sidebarMount) {
      sidebarMount.innerHTML = renderSidebarHtml(state, openDetailsIds);
    }
    if (heroMount) {
      heroMount.innerHTML = renderHeroTextHtml(state);
    }
    if (panelsMount) {
      panelsMount.innerHTML = renderPanelsHtml(state, openDetailsIds);
    }
    if (editorialMount) {
      editorialMount.innerHTML = renderEditorialSectionsHtml(state);
    }
    if (modalMount) {
      modalMount.innerHTML = renderModalHtml(state);
    }
    if (mascotLabel) {
      mascotLabel.textContent = `PATCHCAT TELEMETRY: ${state.mascotState.toUpperCase()}`;
    }
    if (postureHeading) {
      postureHeading.textContent = t.postureHeading;
    }
    if (postureSub) {
      postureSub.textContent = t.postureSub;
    }
    if (mascot) {
      mascot.setState(state.mascotState);
    }

    bindEvents();
    trackDetailsToggles();

    const runScenarioAnim =
      prevFixtureId !== null && prevFixtureId !== state.activeFixtureId;
    const runDrawAnim = runScenarioAnim && state.analysis.paths.length > 0;
    const runModalAnim = !prevModalOpen && state.showKeyModal;
    const runAuditAnim = state.auditLog.length > prevAuditCount;

    if (
      (runScenarioAnim || runModalAnim || runAuditAnim) &&
      !isReducedMotionPreferred()
    ) {
      void loadMotionChoreography().then((mod) => {
        if (!mod) return;
        if (runScenarioAnim) mod.animateScenarioTransition(root);
        if (runDrawAnim) mod.animateAttackPathDraw(root);
        if (runModalAnim) mod.animateOverlayEnter(root, '.modal-box');
        if (runAuditAnim) {
          mod.animateStaggeredRows(root, '#audit-terminal .audit-entry');
        }
      });
    }

    prevFixtureId = state.activeFixtureId;
    prevModalOpen = state.showKeyModal;
    prevAuditCount = state.auditLog.length;
  };

  const bindEvents = (): void => {
    getEl('#select-lang')?.addEventListener('change', (e) => {
      const target = e.target as { value?: string } | null;
      const val = (target?.value ?? 'en') as SupportedLanguage;
      writeSessionValue('scriptkitty.lang', val);
      controller.setLanguage(val);
    });

    getEl('#btn-toggle-theme')?.addEventListener('click', () => {
      currentTheme = currentTheme === 'light' ? 'dark' : 'light';
      writeSessionValue('scriptkitty.theme', currentTheme);
      if (doc?.documentElement && typeof doc.documentElement.setAttribute === 'function') {
        doc.documentElement.setAttribute('data-theme', currentTheme);
      }
      renderState(latestState);
    });

    getEl('#badge-lab-boundary')?.addEventListener('click', () => {
      sandboxPopoverOpen = !sandboxPopoverOpen;
      renderState(latestState);
    });

    getEl('#btn-open-keys')?.addEventListener('click', () => {
      controller.setKeyModalOpen(true);
    });

    getEl('#btn-close-keys')?.addEventListener('click', () => {
      controller.setKeyModalOpen(false);
    });

    getEl('#btn-save-keys')?.addEventListener('click', () => {
      const providerEl = getEl('#key-provider') as HTMLSelectElement | null;
      const getVal = (id: string) =>
        (getEl(id) as HTMLInputElement | null)?.value ?? '';
      controller.saveAiConfig({
        activeProvider: providerEl?.value ?? 'openai',
        openaiApiKey: getVal('#input-openai') || undefined,
        googleApiKey: getVal('#input-google') || undefined,
        nvidiaApiKey: getVal('#input-nvidia') || undefined,
        openrouterApiKey: getVal('#input-openrouter') || undefined,
        anthropicApiKey: getVal('#input-claude') || undefined,
        grokApiKey: getVal('#input-grok') || undefined,
        codexSubscriptionToken: getVal('#input-codex') || undefined,
      });
    });

    getEl('#btn-dismiss-toast')?.addEventListener('click', () => {
      controller.dismissToast();
    });

    getEl('#btn-mcp-connect')?.addEventListener('click', () => {
      const urlInput = getEl('#input-mcp-url') as HTMLInputElement | null;
      const tokenInput = getEl('#input-mcp-token') as HTMLInputElement | null;
      controller.setMcpConnectionConfig({
        url: urlInput?.value,
        token: tokenInput?.value ? tokenInput.value : undefined,
        autoProbe: true,
      });
      void controller.connectAndSyncMcp();
    });

    getEl('#btn-mcp-reset')?.addEventListener('click', () => {
      controller.disconnectToLabDeterministic();
    });

    getEl('#btn-scout')?.addEventListener('click', () => {
      void controller.runFullScout();
    });

    getEl('#btn-learn')?.addEventListener('click', () => {
      void controller.viewMemory();
    });

    getEl('#btn-pr')?.addEventListener('click', () => {
      void controller.submitPrReviewGate();
    });

    getEl('#btn-pr-suggest')?.addEventListener('click', () => {
      void controller.createPrSuggestion();
    });

    getEl('#btn-toggle-self-cert')?.addEventListener('click', () => {
      controller.toggleSelfCertSimulation();
    });

    FIXTURE_TAB_META.forEach((tab, index) => {
      const tabEl = getEl(`#${tab.domId}`);
      if (!tabEl) return;
      tabEl.addEventListener('click', () => {
        void controller.selectFixture(tab.id);
      });
      tabEl.addEventListener('keydown', (e: unknown) => {
        const keyEvent = e as { key?: string; preventDefault?: () => void };
        const key = keyEvent?.key;
        let nextIndex = -1;
        if (key === 'ArrowRight' || key === 'ArrowDown') {
          nextIndex = (index + 1) % FIXTURE_TAB_META.length;
        } else if (key === 'ArrowLeft' || key === 'ArrowUp') {
          nextIndex = (index - 1 + FIXTURE_TAB_META.length) % FIXTURE_TAB_META.length;
        } else if (key === 'Home') {
          nextIndex = 0;
        } else if (key === 'End') {
          nextIndex = FIXTURE_TAB_META.length - 1;
        }
        if (nextIndex >= 0) {
          keyEvent.preventDefault?.();
          const nextTab = FIXTURE_TAB_META[nextIndex];
          void controller.selectFixture(nextTab.id);
          const nextEl = getEl(`#${nextTab.domId}`) as { focus?: () => void } | null;
          nextEl?.focus?.();
        }
      });
    });
  };

  renderState(initial);
  const unsubscribe = controller.subscribe((nextState) => {
    renderState(nextState);
  });

  return {
    unmount: () => {
      unsubscribe();
      if (mascot) {
        mascot.destroy();
        mascot = null;
      }
      root.innerHTML = '';
    },
    getMascot: () => mascot,
  };
}
