/**
 * @file apps/ui/src/openui-catalog.ts
 * @description Declarative OpenUI Lang component catalog (`@openuidev/lang-core`)
 * compiling PatchCat Live's current verification state into a schema-validated,
 * strictly escaped product advisory brief (`#panel-openui-brief`).
 */

import {
  createLibrary,
  createParser,
  defineComponent,
  type ElementNode,
  type Library,
} from '@openuidev/lang-core';
import { z } from 'zod/v4';
import type { DashboardState, SupportedLanguage } from './live-controller.ts';

export function escapeHtml(raw: unknown): string {
  const str = String(raw ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const identityRenderer = (props: unknown) => props;

export const GateCheckItemComponent = defineComponent({
  name: 'GateCheckItem',
  description: 'Single deterministic verification check with human-readable outcome',
  props: z.object({
    label: z.string(),
    status: z.enum(['CLEAR', 'REVIEW', 'BLOCKED']),
    detail: z.string(),
  }),
  component: identityRenderer,
});

export const RemediationActionRowComponent = defineComponent({
  name: 'RemediationActionRow',
  description: 'Minimum counterfactual change proposal requiring human sign-off',
  props: z.object({
    target: z.string(),
    changeSummary: z.string(),
    impactDelta: z.string(),
    approvalRequired: z.boolean(),
  }),
  component: identityRenderer,
});

export const RiskVerdictBannerComponent = defineComponent({
  name: 'RiskVerdictBanner',
  description: 'Primary product verdict banner for security posture',
  props: z.object({
    severity: z.enum(['CLEAR', 'ACTION_REQUIRED', 'BLOCKED']),
    headline: z.string(),
    summary: z.string(),
  }),
  component: identityRenderer,
});

export const PolicySummaryComponent = defineComponent({
  name: 'PolicySummary',
  description: 'Root declarative verification brief rendered by PatchCat Live',
  props: z.object({
    scenarioLabel: z.string(),
    verdict: RiskVerdictBannerComponent.ref,
    remediation: RemediationActionRowComponent.ref,
    checks: z.array(GateCheckItemComponent.ref),
  }),
  component: identityRenderer,
});

export const PATCHCAT_OPENUI_LIBRARY: Library = createLibrary({
  id: 'patchcat-live-v2',
  root: 'PolicySummary',
  components: [
    PolicySummaryComponent,
    RiskVerdictBannerComponent,
    RemediationActionRowComponent,
    GateCheckItemComponent,
  ],
  componentGroups: [
    {
      name: 'Verification Advisory',
      components: [
        'PolicySummary',
        'RiskVerdictBanner',
        'RemediationActionRow',
        'GateCheckItem',
      ],
    },
  ],
});

const patchCatOpenUiParser = createParser(
  PATCHCAT_OPENUI_LIBRARY.toJSONSchema(),
  'PolicySummary'
);

function quoteOpenUiString(value: string): string {
  return JSON.stringify(String(value ?? '').replace(/[\r\n]+/g, ' '));
}

const BRIEF_COPY: Record<
  SupportedLanguage,
  {
    sectionTitle: string;
    specBadge: string;
    clearHeadline: string;
    clearSummary: string;
    riskHeadline: string;
    riskSummary: string;
    gateRejectHeadline: string;
    gateRejectSummary: string;
    checkPathLabel: string;
    checkWorkflowsLabel: string;
    checkApprovalLabel: string;
    humanSignOffText: string;
    pathViolatedFmt: (count: number, risk: string) => string;
    pathClearText: string;
    workflowsIsolatedText: string;
    workflowsIntactFmt: (preserved: number, total: number) => string;
    remediationProposedText: string;
    remediationVerifiedText: string;
    remediationLabel: string;
    scenarios: Record<string, string>;
  }
> = {
  en: {
    sectionTitle: 'Verification Summary',
    specBadge: 'OpenUI Schema Validated',
    clearHeadline: 'All monitored access boundaries verified clear',
    clearSummary:
      'Deterministic reachability confirms no unauthorized export routes while preserving business operations.',
    riskHeadline: 'Unauthorized data-export path detected in rollout',
    riskSummary:
      'A permission change allows restricted customer payment records to reach an external destination. Human review is required before rollout.',
    gateRejectHeadline: 'Release gate blocked: independent review violated',
    gateRejectSummary:
      'Discovery and verification cannot share the same reviewer identity. Restore separation of duties to proceed.',
    checkPathLabel: 'Access Boundary',
    checkWorkflowsLabel: 'Protected Workflows',
    checkApprovalLabel: 'Release Controls',
    humanSignOffText: 'Human approval mandatory · Auto-merge locked',
    pathViolatedFmt: (count, risk) => `${count} unauthorized chain (${risk})`,
    pathClearText: '0 unauthorized paths',
    workflowsIsolatedText: 'Semantic isolation verified (0 routes)',
    workflowsIntactFmt: (preserved, total) => `${preserved}/${total} core operations intact`,
    remediationProposedText: 'Proposed 1-edge removal resolves path (1 -> 0)',
    remediationVerifiedText: 'Verified edge removal keeps workflows operational (0 paths)',
    remediationLabel: 'Counterfactual Fix',
    scenarios: {
      'payments-lab/baseline': 'Baseline Architecture',
      'payments-lab/unsafe-rollout': 'Unsafe Rollout Candidate',
      'payments-lab/remediated': 'Remediated Configuration',
      'payments-lab/negative-control': 'Incompatible Edge Control',
    },
  },
  pt: {
    sectionTitle: 'Resumo da Verificação',
    specBadge: 'Esquema OpenUI Validado',
    clearHeadline: 'Todas as fronteiras de acesso verificadas sem exposição',
    clearSummary:
      'A alcançabilidade determinística confirma zero rotas indevidas de exportação com operações legítimas preservadas.',
    riskHeadline: 'Rota não autorizada de exportação detectada no rollout',
    riskSummary:
      'Uma alteração de permissão permite que registros restritos de pagamento alcancem um destino externo. Revisão humana obrigatória.',
    gateRejectHeadline: 'Gate bloqueado: revisão independente violada',
    gateRejectSummary:
      'A descoberta e a verificação não podem usar a mesma identidade. Restaure a separação tripartite para prosseguir.',
    checkPathLabel: 'Fronteira de Acesso',
    checkWorkflowsLabel: 'Fluxos Protegidos',
    checkApprovalLabel: 'Controles de Release',
    humanSignOffText: 'Aprovação humana obrigatória · Auto-merge bloqueado',
    pathViolatedFmt: (count, risk) => `${count} cadeia indevida (${risk})`,
    pathClearText: '0 caminhos não autorizados',
    workflowsIsolatedText: 'Isolamento semântico verificado (0 rotas)',
    workflowsIntactFmt: (preserved, total) => `${preserved}/${total} operações centrais intactas`,
    remediationProposedText: 'Remoção de 1 aresta resolve o caminho (1 -> 0)',
    remediationVerifiedText: 'Remoção verificada mantém fluxos operando (0 caminhos)',
    remediationLabel: 'Correção Contrafactual',
    scenarios: {
      'payments-lab/baseline': 'Arquitetura Baseline',
      'payments-lab/unsafe-rollout': 'Candidato de Rollout Inseguro',
      'payments-lab/remediated': 'Configuração Remediada',
      'payments-lab/negative-control': 'Controle Negativo de Aresta',
    },
  },
  es: {
    sectionTitle: 'Resumen de Verificación',
    specBadge: 'Validado vía OpenUI',
    clearHeadline: 'Límites de acceso verificados sin rutas prohibidas',
    clearSummary:
      'El análisis determinístico confirma cero rutas indebidas preservando los flujos legítimos.',
    riskHeadline: 'Ruta no autorizada de exportación detectada en rollout',
    riskSummary:
      'Un cambio de permisos expone datos restringidos de pago a un destino externo. Requiere aprobación humana.',
    gateRejectHeadline: 'Compuerta bloqueada: revisión independiente violada',
    gateRejectSummary:
      'Descubrimiento y verificación no pueden compartir identidad. Restaure la separación de deberes.',
    checkPathLabel: 'Límite de Acceso',
    checkWorkflowsLabel: 'Flujos Protegidos',
    checkApprovalLabel: 'Controles de Release',
    humanSignOffText: 'Aprobación humana obligatoria · Auto-merge bloqueado',
    pathViolatedFmt: (count, risk) => `${count} cadena indebida (${risk})`,
    pathClearText: '0 rutas no autorizadas',
    workflowsIsolatedText: 'Aislamiento semántico verificado (0 rutas)',
    workflowsIntactFmt: (preserved, total) => `${preserved}/${total} operaciones intactas`,
    remediationProposedText: 'Retirar 1 arista resuelve la ruta (1 -> 0)',
    remediationVerifiedText: 'Corrección verificada mantiene flujos activos (0 rutas)',
    remediationLabel: 'Corrección Contrafactual',
    scenarios: {
      'payments-lab/baseline': 'Arquitectura Baseline',
      'payments-lab/unsafe-rollout': 'Rollout Inseguro',
      'payments-lab/remediated': 'Configuración Remediada',
      'payments-lab/negative-control': 'Control Negativo de Arista',
    },
  },
};

/**
 * Generates a declarative OpenUI Lang program describing the current security
 * state and parses/validates it through `@openuidev/lang-core`.
 */
export function buildPatchCatOpenUiProgram(state: DashboardState): string {
  const copy = BRIEF_COPY[state.language] ?? BRIEF_COPY.en;
  const hasViolation = state.analysis.paths.length > 0;
  const isGateBlocked = state.qualityGate.verdict !== 'PASS';

  const preservedCount = state.analysis.legitimateOperations.filter(
    (op) => op.preserved
  ).length;
  const totalLegit = state.analysis.legitimateOperations.length;

  const severity: 'CLEAR' | 'ACTION_REQUIRED' | 'BLOCKED' = isGateBlocked
    ? 'BLOCKED'
    : hasViolation
      ? 'ACTION_REQUIRED'
      : 'CLEAR';

  const headline = isGateBlocked
    ? copy.gateRejectHeadline
    : hasViolation
      ? copy.riskHeadline
      : copy.clearHeadline;

  const summary = isGateBlocked
    ? copy.gateRejectSummary
    : hasViolation
      ? copy.riskSummary
      : copy.clearSummary;

  const displaySpec =
    state.activeRemediationSpec ?? state.referenceRemediationSpec;
  const primaryAct = displaySpec.actions[0];
  const scenarioLabel =
    copy.scenarios[state.activeFixtureId] ?? state.activeFixtureId;

  const pathStatus: 'CLEAR' | 'REVIEW' | 'BLOCKED' = hasViolation
    ? 'BLOCKED'
    : 'CLEAR';
  const workflowStatus: 'CLEAR' | 'REVIEW' | 'BLOCKED' =
    totalLegit === 0 || preservedCount === totalLegit ? 'CLEAR' : 'BLOCKED';
  const approvalStatus: 'CLEAR' | 'REVIEW' | 'BLOCKED' = isGateBlocked
    ? 'BLOCKED'
    : state.adjudication.status === 'PENDING_REVIEW'
      ? 'REVIEW'
      : 'CLEAR';

  const pathDetail = hasViolation
    ? copy.pathViolatedFmt(
        state.analysis.paths.length,
        state.analysis.paths[0].riskRecommendation
      )
    : copy.pathClearText;
  const workflowDetail =
    totalLegit === 0
      ? copy.workflowsIsolatedText
      : copy.workflowsIntactFmt(preservedCount, totalLegit);
  const remediationTarget = primaryAct?.edgeId ?? 'none';
  const remediationDelta = hasViolation
    ? copy.remediationProposedText
    : copy.remediationVerifiedText;

  return [
    `root = PolicySummary(${quoteOpenUiString(scenarioLabel)}, verdict, remediation, [chkPath, chkWorkflows, chkApproval])`,
    `verdict = RiskVerdictBanner(${quoteOpenUiString(severity)}, ${quoteOpenUiString(headline)}, ${quoteOpenUiString(summary)})`,
    `remediation = RemediationActionRow(${quoteOpenUiString(remediationTarget)}, ${quoteOpenUiString(primaryAct?.actionType ?? 'NONE')}, ${quoteOpenUiString(remediationDelta)}, true)`,
    `chkPath = GateCheckItem(${quoteOpenUiString(copy.checkPathLabel)}, ${quoteOpenUiString(pathStatus)}, ${quoteOpenUiString(pathDetail)})`,
    `chkWorkflows = GateCheckItem(${quoteOpenUiString(copy.checkWorkflowsLabel)}, ${quoteOpenUiString(workflowStatus)}, ${quoteOpenUiString(workflowDetail)})`,
    `chkApproval = GateCheckItem(${quoteOpenUiString(copy.checkApprovalLabel)}, ${quoteOpenUiString(approvalStatus)}, ${quoteOpenUiString(copy.humanSignOffText)})`,
  ].join('\n');
}

export interface CompiledOpenUiBrief {
  program: string;
  root: ElementNode | null;
  errorCount: number;
  componentNames: string[];
}

export function compilePatchCatOpenUiBrief(
  state: DashboardState
): CompiledOpenUiBrief {
  const program = buildPatchCatOpenUiProgram(state);
  const parsed = patchCatOpenUiParser.parse(program);
  return {
    program,
    root: parsed.root,
    errorCount: parsed.meta.errors.length,
    componentNames: Object.keys(PATCHCAT_OPENUI_LIBRARY.components),
  };
}

/**
 * Renders the parsed & validated OpenUI Lang program as restrained HTML inside `#panel-openui-brief`.
 */
export function renderOpenUiAdvisoryBrief(state: DashboardState): string {
  const copy = BRIEF_COPY[state.language] ?? BRIEF_COPY.en;
  const compiled = compilePatchCatOpenUiBrief(state);
  const rootProps = (compiled.root?.props ?? {}) as {
    scenarioLabel?: string;
    verdict?: ElementNode;
    remediation?: ElementNode;
    checks?: ElementNode[];
  };

  const verdictProps = (rootProps.verdict?.props ?? {}) as {
    severity?: string;
    headline?: string;
    summary?: string;
  };
  const remediationProps = (rootProps.remediation?.props ?? {}) as {
    target?: string;
    changeSummary?: string;
    impactDelta?: string;
    approvalRequired?: boolean;
  };
  const checks = Array.isArray(rootProps.checks) ? rootProps.checks : [];

  const toneClass =
    verdictProps.severity === 'BLOCKED'
      ? 'brief-risk'
      : verdictProps.severity === 'ACTION_REQUIRED'
        ? 'brief-warn'
        : 'brief-clear';

  const checksHtml = checks
    .map((node) => {
      const p = (node?.props ?? {}) as {
        label?: string;
        status?: string;
        detail?: string;
      };
      const dotClass =
        p.status === 'BLOCKED'
          ? 'dot-risk'
          : p.status === 'REVIEW'
            ? 'dot-warn'
            : 'dot-ok';
      return `
        <div class="brief-check-item">
          <span class="brief-check-label">
            <span class="status-indicator ${dotClass}" aria-hidden="true"></span>
            ${escapeHtml(p.label ?? '')}
          </span>
          <span class="brief-check-detail">${escapeHtml(p.detail ?? '')}</span>
        </div>`;
    })
    .join('');

  return `
    <section class="panel openui-brief ${toneClass}" id="panel-openui-brief" data-openui-root="${escapeHtml(compiled.root?.typeName ?? 'PolicySummary')}" data-openui-errors="${compiled.errorCount}">
      <div class="brief-header">
        <div class="brief-headline-wrap">
          <span class="brief-title">${escapeHtml(verdictProps.headline ?? copy.clearHeadline)}</span>
          <p class="brief-summary">${escapeHtml(verdictProps.summary ?? copy.clearSummary)}</p>
        </div>
        <span class="quiet-meta-pill">${escapeHtml(copy.specBadge)}</span>
      </div>
      <div class="brief-checks-row">
        ${checksHtml}
      </div>
      <div class="brief-remediation-meta">
        <span class="brief-rem-label">${escapeHtml(copy.remediationLabel)}:</span>
        <code>${escapeHtml(remediationProps.target ?? 'none')}</code>
        <span class="brief-rem-delta">${escapeHtml(remediationProps.impactDelta ?? '')}</span>
      </div>
    </section>
  `;
}
