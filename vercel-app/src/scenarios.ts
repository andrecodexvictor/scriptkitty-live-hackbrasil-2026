export type ScenarioId =
  | 'payments-lab/baseline'
  | 'payments-lab/unsafe-rollout'
  | 'payments-lab/remediated'
  | 'payments-lab/negative-control';

export interface ScenarioNode {
  nodeId: string;
  kind: 'identity' | 'mcp_tool' | 'service' | 'data_asset' | 'destination';
  classification?: string;
  trustZone: 'INTERNAL' | 'EXTERNAL';
}

export interface ScenarioEdge {
  edgeId: string;
  from: string;
  to: string;
  kind: 'can_read' | 'can_invoke' | 'transfers_data_to' | 'assumes_role' | 'can_write';
  classification: string;
  sourceRef: string;
  effect: 'ALLOW' | 'DENY';
  violated?: boolean;
}

interface ScenarioOperation {
  id: string;
  descriptionEn: string;
  descriptionPt: string;
  preserved: boolean;
}

export interface ScenarioDataset {
  id: ScenarioId;
  domId: string;
  label: string;
  pill: string;
  pillTone: 'ok' | 'risk';
  inputSha256: string;
  policyVersion: string;
  pathsCount: number;
  risk: 'NONE' | 'P1';
  reviewStatus: 'ACCEPTED_FOR_TRIAGE' | 'PENDING_REVIEW';
  graphStatus: 'CLEAR' | 'CONFIRMED_BY_GRAPH';
  advisoryProviderStatus: 'NOT_CONFIGURED';
  nodes: ScenarioNode[];
  edges: ScenarioEdge[];
  operations: readonly ScenarioOperation[];
  summaryEn: string;
  summaryPt: string;
}

const BASE_OPERATIONS: readonly ScenarioOperation[] = [
  {
    id: 'op-support-read-profile',
    descriptionEn: 'Support reads the synthetic profile within its assigned scope.',
    descriptionPt: 'O suporte lê o perfil sintético dentro do escopo atribuído.',
    preserved: true,
  },
  {
    id: 'op-non-sensitive-export',
    descriptionEn: 'Support exports a public report summary.',
    descriptionPt: 'O suporte exporta um resumo público do relatório.',
    preserved: true,
  },
  {
    id: 'op-finance-process-payments',
    descriptionEn: 'Finance reads payment PII and writes to the internal ledger.',
    descriptionPt: 'Finanças lê dados pessoais de pagamentos e grava no registro interno.',
    preserved: true,
  },
];

const BASE_NODES: ScenarioNode[] = [
  { nodeId: 'identity:support-agent', kind: 'identity', trustZone: 'INTERNAL' },
  { nodeId: 'identity:finance-operator', kind: 'identity', trustZone: 'INTERNAL' },
  { nodeId: 'mcp_tool:report-exporter', kind: 'mcp_tool', trustZone: 'INTERNAL' },
  { nodeId: 'service:finance-processor', kind: 'service', trustZone: 'INTERNAL' },
  { nodeId: 'data_asset:customer-profile-synthetic', kind: 'data_asset', classification: 'INTERNAL', trustZone: 'INTERNAL' },
  { nodeId: 'data_asset:non-sensitive-summary', kind: 'data_asset', classification: 'PUBLIC', trustZone: 'INTERNAL' },
  { nodeId: 'data_asset:customer-payment-pii', kind: 'data_asset', classification: 'RESTRICTED', trustZone: 'INTERNAL' },
  { nodeId: 'data_asset:payment-ledger-internal', kind: 'data_asset', classification: 'RESTRICTED', trustZone: 'INTERNAL' },
  { nodeId: 'destination:external-report-sink', kind: 'destination', classification: 'PUBLIC', trustZone: 'EXTERNAL' },
];

const BASE_EDGES: ScenarioEdge[] = [
  {
    edgeId: 'e-support-read-profile',
    from: 'identity:support-agent',
    to: 'data_asset:customer-profile-synthetic',
    kind: 'can_read',
    classification: 'INTERNAL',
    sourceRef: 'policies/payments-lab/baseline.policy.yaml#edges.support_read_profile',
    effect: 'ALLOW',
  },
  {
    edgeId: 'e-support-invoke-exporter',
    from: 'identity:support-agent',
    to: 'mcp_tool:report-exporter',
    kind: 'can_invoke',
    classification: 'PUBLIC',
    sourceRef: 'policies/payments-lab/baseline.policy.yaml#edges.support_invoke_exporter',
    effect: 'ALLOW',
  },
  {
    edgeId: 'e-exporter-read-summary',
    from: 'mcp_tool:report-exporter',
    to: 'data_asset:non-sensitive-summary',
    kind: 'can_read',
    classification: 'PUBLIC',
    sourceRef: 'policies/payments-lab/baseline.policy.yaml#edges.exporter_read_summary',
    effect: 'ALLOW',
  },
  {
    edgeId: 'e-exporter-transfer-external',
    from: 'mcp_tool:report-exporter',
    to: 'destination:external-report-sink',
    kind: 'transfers_data_to',
    classification: 'PUBLIC',
    sourceRef: 'policies/payments-lab/baseline.policy.yaml#edges.exporter_transfer_external',
    effect: 'ALLOW',
  },
  {
    edgeId: 'e-finance-assume-processor',
    from: 'identity:finance-operator',
    to: 'service:finance-processor',
    kind: 'assumes_role',
    classification: 'RESTRICTED',
    sourceRef: 'policies/payments-lab/baseline.policy.yaml#edges.finance_assume_processor',
    effect: 'ALLOW',
  },
  {
    edgeId: 'e-finance-read-payment-pii',
    from: 'service:finance-processor',
    to: 'data_asset:customer-payment-pii',
    kind: 'can_read',
    classification: 'RESTRICTED',
    sourceRef: 'policies/payments-lab/baseline.policy.yaml#edges.finance_read_payment_pii',
    effect: 'ALLOW',
  },
  {
    edgeId: 'e-finance-write-ledger',
    from: 'service:finance-processor',
    to: 'data_asset:payment-ledger-internal',
    kind: 'can_write',
    classification: 'RESTRICTED',
    sourceRef: 'policies/payments-lab/baseline.policy.yaml#edges.finance_write_ledger',
    effect: 'ALLOW',
  },
];

export const VERCEL_SCENARIOS: Record<ScenarioId, ScenarioDataset> = {
  'payments-lab/baseline': {
    id: 'payments-lab/baseline',
    domId: 'tab-baseline',
    label: 'Baseline',
    pill: '0 paths',
    pillTone: 'ok',
    inputSha256: '76c07c4340acfc748443a496435867c819354f99241cd361cd585d2dc85a8bbc',
    policyVersion: '2026.11.09-baseline',
    pathsCount: 0,
    risk: 'NONE',
    reviewStatus: 'ACCEPTED_FOR_TRIAGE',
    graphStatus: 'CLEAR',
    advisoryProviderStatus: 'NOT_CONFIGURED',
    nodes: BASE_NODES,
    edges: BASE_EDGES,
    operations: BASE_OPERATIONS,
    summaryEn: 'Baseline architecture: support exports only PUBLIC summary reports; finance retains isolated internal ledger scope.',
    summaryPt: 'Arquitetura baseline: o suporte exporta apenas resumos PUBLIC; finanças mantém escopo interno isolado.',
  },
  'payments-lab/unsafe-rollout': {
    id: 'payments-lab/unsafe-rollout',
    domId: 'tab-unsafe-rollout',
    label: 'Unsafe Rollout',
    pill: 'P1 risk',
    pillTone: 'risk',
    inputSha256: '142cdbbd10b23de6967672f56587b29a5ef028dc727213810a85cc8bcf5b3da0',
    policyVersion: '2026.11.09-unsafe-rollout',
    pathsCount: 1,
    risk: 'P1',
    reviewStatus: 'PENDING_REVIEW',
    graphStatus: 'CONFIRMED_BY_GRAPH',
    advisoryProviderStatus: 'NOT_CONFIGURED',
    nodes: BASE_NODES,
    edges: [
      ...BASE_EDGES.map((e) =>
        e.edgeId === 'e-support-invoke-exporter'
          ? {
              ...e,
              sourceRef: 'policies/payments-lab/unsafe-rollout.policy.yaml#edges.support_invoke_exporter',
              violated: true,
            }
          : e.edgeId === 'e-exporter-transfer-external'
            ? {
                ...e,
                classification: 'RESTRICTED',
                sourceRef: 'policies/payments-lab/report-exporter-rollout.yaml#L38',
                violated: true,
              }
            : e
      ),
      {
        edgeId: 'e-rollout-exporter-read-pii',
        from: 'mcp_tool:report-exporter',
        to: 'data_asset:customer-payment-pii',
        kind: 'can_read',
        classification: 'RESTRICTED',
        sourceRef: 'policies/payments-lab/report-exporter-rollout.yaml#L24',
        effect: 'ALLOW',
        violated: true,
      },
    ],
    operations: BASE_OPERATIONS,
    summaryEn: 'Unsafe rollout adds edge e-rollout-exporter-read-pii, exposing RESTRICTED payment PII to an EXTERNAL sink (PATH_VALIDATED, P1).',
    summaryPt: 'Rollout inseguro adiciona a aresta e-rollout-exporter-read-pii, expondo PII de pagamento RESTRICTED a destino EXTERNAL (PATH_VALIDATED, P1).',
  },
  'payments-lab/remediated': {
    id: 'payments-lab/remediated',
    domId: 'tab-remediated',
    label: 'Remediated',
    pill: '0 paths',
    pillTone: 'ok',
    inputSha256: '49dfd23089baf48d8d86e323f5604cbba6d33d81dbac42cebbb071ecc932b5d1',
    policyVersion: '2026.11.09-remediated',
    pathsCount: 0,
    risk: 'NONE',
    reviewStatus: 'ACCEPTED_FOR_TRIAGE',
    graphStatus: 'CLEAR',
    advisoryProviderStatus: 'NOT_CONFIGURED',
    nodes: BASE_NODES,
    edges: BASE_EDGES,
    operations: BASE_OPERATIONS,
    summaryEn: 'Counterfactual fix removes e-rollout-exporter-read-pii and restores PUBLIC export ceiling: forbidden paths drop 1 -> 0 while 3/3 workflows remain intact.',
    summaryPt: 'Correção contrafactual remove e-rollout-exporter-read-pii e restaura teto PUBLIC: rotas proibidas caem 1 -> 0 com 3/3 fluxos intactos.',
  },
  'payments-lab/negative-control': {
    id: 'payments-lab/negative-control',
    domId: 'tab-negative-control',
    label: 'Negative Control',
    pill: 'Isolated',
    pillTone: 'ok',
    inputSha256: '156320fa4255cd72eb812ed0186833c2c06d915ceeb33da34717291ee40bc2e1',
    policyVersion: '2026.11.09-negative-control',
    pathsCount: 0,
    risk: 'NONE',
    reviewStatus: 'ACCEPTED_FOR_TRIAGE',
    graphStatus: 'CLEAR',
    advisoryProviderStatus: 'NOT_CONFIGURED',
    nodes: [
      { nodeId: 'identity:auditor-agent', kind: 'identity', trustZone: 'INTERNAL' },
      { nodeId: 'service:audit-exporter', kind: 'service', trustZone: 'INTERNAL' },
      { nodeId: 'data_asset:customer-payment-pii', kind: 'data_asset', classification: 'RESTRICTED', trustZone: 'INTERNAL' },
      { nodeId: 'destination:external-report-sink', kind: 'destination', classification: 'PUBLIC', trustZone: 'EXTERNAL' },
    ],
    edges: [
      {
        edgeId: 'e-auditor-deny-pii',
        from: 'service:audit-exporter',
        to: 'data_asset:customer-payment-pii',
        kind: 'can_read',
        classification: 'PUBLIC',
        sourceRef: 'policies/payments-lab/negative-control.yaml#L14',
        effect: 'DENY',
      },
    ],
    operations: [],
    summaryEn: 'Negative control verifies DENY semantics and missing source/sink authorization fail closed with 0 exposed paths.',
    summaryPt: 'Controle negativo verifica que semântica DENY e ausência de autorização falham fechado com 0 rotas expostas.',
  },
};

const NODE_W = 160;
const NODE_H = 42;

const COORDS: Record<string, { x: number; y: number }> = {
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

const SHORT_EDGE: Record<string, string> = {
  'e-support-read-profile': 'read-profile',
  'e-support-invoke-exporter': 'invoke-exporter',
  'e-exporter-read-summary': 'read-summary',
  'e-rollout-exporter-read-pii': 'rollout-read-pii',
  'e-exporter-transfer-external': 'transfer-ext',
  'e-finance-assume-processor': 'assume-role',
  'e-finance-read-payment-pii': 'read-payment-pii',
  'e-finance-write-ledger': 'write-ledger',
  'e-auditor-deny-pii': 'deny-pii',
};

function esc(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function edgeGeom(edgeId: string, from: { x: number; y: number }, to: { x: number; y: number }) {
  const sx = from.x + NODE_W / 2;
  const sy = from.y;
  const ex = to.x - NODE_W / 2 - 4;
  const ey = to.y;

  if (edgeId === 'e-support-read-profile') {
    return { d: `M ${sx} ${sy - 8} C 290 18, 440 18, ${ex} ${ey}`, lx: 340, ly: 20, ax: ex, ay: ey };
  }
  if (edgeId === 'e-support-invoke-exporter') {
    return { d: `M ${sx} ${sy + 6} C 210 ${sy + 6}, 220 ${ey}, ${ex} ${ey}`, lx: 216, ly: 54, ax: ex, ay: ey };
  }
  if (edgeId === 'e-exporter-read-summary') {
    return { d: `M ${sx} ${sy} C 470 ${sy}, 500 ${ey}, ${ex} ${ey}`, lx: 482, ly: 96, ax: ex, ay: ey };
  }
  if (edgeId === 'e-exporter-transfer-external') {
    return { d: `M ${sx} ${sy + 6} C 495 160, 710 158, ${ex} ${ey}`, lx: 756, ly: 145, ax: ex, ay: ey };
  }
  if (edgeId === 'e-rollout-exporter-read-pii') {
    return { d: `M ${sx} ${sy + 10} C 475 135, 495 ${ey}, ${ex} ${ey - 4}`, lx: 472, ly: 174, ax: ex, ay: ey - 4 };
  }
  if (edgeId === 'e-finance-read-payment-pii') {
    return { d: `M ${sx} ${sy - 4} C 470 ${sy - 12}, 495 ${ey + 6}, ${ex} ${ey + 6}`, lx: 482, ly: 232, ax: ex, ay: ey + 6 };
  }
  const dx = Math.max(40, Math.round((ex - sx) * 0.48));
  return {
    d: `M ${sx} ${sy} C ${sx + dx} ${sy}, ${ex - dx} ${ey}, ${ex} ${ey}`,
    lx: Math.round((sx + ex) / 2),
    ly: Math.round((sy + ey) / 2) - 10,
    ax: ex,
    ay: ey,
  };
}

export function renderScenarioGraphSvg(scenario: ScenarioDataset): string {
  const posMap = new Map<string, { x: number; y: number }>();
  scenario.nodes.forEach((n, idx) => {
    posMap.set(n.nodeId, COORDS[n.nodeId] ?? { x: 100 + (idx % 4) * 260, y: 52 + Math.floor(idx / 4) * 86 });
  });

  const edgeSvg = scenario.edges
    .map((e) => {
      const from = posMap.get(e.from);
      const to = posMap.get(e.to);
      if (!from || !to) return '';
      const isViolation = Boolean(e.violated);
      const isDeny = e.effect === 'DENY';
      const stroke = isViolation ? 'var(--status-risk)' : isDeny ? 'var(--border-strong)' : 'var(--primary)';
      const dash = isDeny ? '4 4' : 'none';
      const sw = isViolation ? '2.5' : '1.5';
      const op = isViolation ? '0.96' : isDeny ? '0.7' : '0.55';
      const g = edgeGeom(e.edgeId, from, to);
      const label = SHORT_EDGE[e.edgeId] ?? e.edgeId.replace(/^e-/, '');
      const showLabel = isViolation || e.kind === 'can_read' || e.kind === 'transfers_data_to';
      const badgeW = Math.max(58, label.length * 6.5 + 12);

      return `<g data-edge-id="${esc(e.edgeId)}">
        <path d="${g.d}" fill="none" stroke="${stroke}" stroke-width="${sw}" stroke-opacity="${op}" stroke-dasharray="${dash}" stroke-linecap="round" />
        <polygon points="${g.ax - 6},${g.ay - 3.5} ${g.ax + 1},${g.ay} ${g.ax - 6},${g.ay + 3.5}" fill="${stroke}" fill-opacity="${op}" />
        ${
          showLabel
            ? `<rect x="${Math.round(g.lx - badgeW / 2)}" y="${g.ly - 11}" width="${Math.round(badgeW)}" height="16" rx="3" fill="var(--bg)" fill-opacity="0.96" /><text x="${g.lx}" y="${g.ly}" fill="${isViolation ? 'var(--status-risk)' : 'var(--ink-muted)'}" font-family="var(--font-mono)" font-size="9.5" font-weight="${isViolation ? '600' : '500'}" text-anchor="middle">${esc(label)}</text>`
            : ''
        }
      </g>`;
    })
    .join('');

  const nodeSvg = scenario.nodes
    .map((n) => {
      const pos = posMap.get(n.nodeId)!;
      const isRestricted = n.classification === 'RESTRICTED';
      const isExternal = n.trustZone === 'EXTERNAL';
      const fill = isExternal ? 'var(--status-warn-bg)' : isRestricted ? 'var(--status-risk-bg)' : 'var(--surface)';
      const stroke = isExternal ? 'var(--status-warn-border)' : isRestricted ? 'var(--status-risk-border)' : 'var(--border-strong)';
      const subText = `${n.kind} · ${n.classification ?? n.trustZone}`;
      const shortLabel = n.nodeId.split(':')[1] ?? n.nodeId;
      return `<g data-node-id="${esc(n.nodeId)}">
        <rect x="${pos.x - NODE_W / 2}" y="${pos.y - NODE_H / 2}" width="${NODE_W}" height="${NODE_H}" rx="6" fill="${fill}" stroke="${stroke}" stroke-width="1.25" />
        <text x="${pos.x}" y="${pos.y - 3}" fill="var(--ink)" font-family="var(--font-sans)" font-size="11" font-weight="600" text-anchor="middle">${esc(shortLabel)}</text>
        <text x="${pos.x}" y="${pos.y + 12}" fill="var(--ink-muted)" font-family="var(--font-mono)" font-size="9" text-anchor="middle">${esc(subText)}</text>
      </g>`;
    })
    .join('');

  return `<svg viewBox="0 0 980 330" class="policy-graph-svg" role="img" aria-label="ChainBreak Access Reachability Graph">${edgeSvg}${nodeSvg}</svg>`;
}
