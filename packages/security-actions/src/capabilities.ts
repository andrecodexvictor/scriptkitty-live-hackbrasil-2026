/**
 * @file packages/security-actions/src/capabilities.ts
 * @description Registers the 14 Security Action Engine capabilities over ChainBreak,
 * JEV-as-a-Judge, CompanyBrainStore, and Hardened Kali LAB_SYNTHETIC Verification:
 * - Core 5: `security.chainbreak.analyze`, `security.chainbreak.get`,
 *   `security.judge.evaluate`, `security.remediation.spec`, `security.status`
 * - Audit & Evidence 3: `security.audit.start`, `security.audit.get`, `security.evidence.get`
 * - Kali LAB_SYNTHETIC 6: `security.kali.lab_run`, `security.kali.service_inventory`,
 *   `security.kali.tls_review`, `security.kali.web_passive_baseline`,
 *   `security.kali.local_code_scan`, `security.kali.get_run`
 */

import { z } from 'zod';
import {
  analyzeFixture,
  ChainBreakError,
  isAllowedFixtureId,
  loadFixtureGraph,
  resolveFixturePath,
  verifyGraphIntegrity,
} from '../../chainbreak/dist/index.js';
import {
  CompanyBrainStore,
  CompanyContextError,
  TenantIsolationError,
} from '../../company-context/dist/index.js';
import {
  AdjudicationResultSchema,
  evaluateWithJevJudge,
  resolveJevProviderStatus,
  type JevEscalationPolicyConfig,
  type JevProvider,
  type TypeSafeClientLike,
} from '../../jev-judge/dist/index.js';
import {
  KALI_LAB_ACTION_IDS,
  KALI_LAB_SYNTHETIC_PROFILE,
  type KaliLabActionId,
  KaliSecurityError,
  KaliGetRunInputSchema,
  KaliLabRunInputSchema,
  KaliLocalCodeScanInputSchema,
  KaliServiceInventoryInputSchema,
  KaliTlsReviewInputSchema,
  KaliWebPassiveBaselineInputSchema,
} from '../../kali-mcp-assessment/dist/schemas.js';
import {
  executeKaliLabSyntheticAction,
  KaliLabRunStore,
  redactKaliLabValue,
} from '../../kali-mcp-assessment/dist/lab-runner.js';
import {
  ActionEngineError,
  createEngine,
  defineCapability,
  type AuditLogEntry,
  type CapabilityRunContext,
  type SecurityActionEngine,
} from './engine.js';

export const SECURITY_CAPABILITY_IDS = [
  'security.chainbreak.analyze',
  'security.chainbreak.get',
  'security.judge.evaluate',
  'security.remediation.spec',
  'security.status',
  'security.audit.start',
  'security.audit.get',
  'security.evidence.get',
  'security.kali.lab_run',
  'security.kali.service_inventory',
  'security.kali.tls_review',
  'security.kali.web_passive_baseline',
  'security.kali.local_code_scan',
  'security.kali.get_run',
] as const;

export type SecurityCapabilityId = (typeof SECURITY_CAPABILITY_IDS)[number];

export interface ExternalAdapterStatus {
  status: string;
  mode: string;
  enabled: boolean;
  externalExecution: false;
  detail?: string;
}

export interface CreateSecurityActionEngineOptions {
  name?: string;
  version?: string;
  store?: CompanyBrainStore;
  dbPath?: string;
  fixturesDir?: string;
  workspaceRoot?: string;
  kaliRunStore?: KaliLabRunStore;
  jevProvider?: JevProvider;
  typesafeClient?: TypeSafeClientLike;
  escalationPolicy?: Partial<JevEscalationPolicyConfig>;
  externalAdaptersStatus?: () => Record<string, ExternalAdapterStatus>;
  defaultTimeoutMs?: number;
  defaultMaxCostUnits?: number;
  onAuditEvent?: (entry: AuditLogEntry) => void;
  now?: () => string;
}

function mapDomainError(
  err: unknown,
  ctx: CapabilityRunContext
): ActionEngineError {
  if (err instanceof ActionEngineError) {
    return err;
  }
  if (err instanceof TenantIsolationError) {
    return new ActionEngineError(
      'FORBIDDEN',
      err.message,
      {
        publicMessage: 'Cross-tenant resource access denied',
        correlationId: ctx.correlationId,
      }
    );
  }
  if (err instanceof CompanyContextError) {
    if (err.code === 'NOT_FOUND') {
      return new ActionEngineError('NOT_FOUND', err.message, {
        correlationId: ctx.correlationId,
      });
    }
    if (err.code === 'VALIDATION_ERROR') {
      return new ActionEngineError('INPUT_INVALID', err.message, {
        correlationId: ctx.correlationId,
      });
    }
    return new ActionEngineError('EXECUTION_FAILED', err.message, {
      correlationId: ctx.correlationId,
    });
  }
  if (err instanceof ChainBreakError) {
    if (err.code === 'DISALLOWED_FIXTURE') {
      return new ActionEngineError('INPUT_INVALID', err.message, {
        correlationId: ctx.correlationId,
      });
    }
    if (err.code === 'FIXTURE_NOT_FOUND') {
      return new ActionEngineError('NOT_FOUND', err.message, {
        correlationId: ctx.correlationId,
      });
    }
  }
  if (err instanceof KaliSecurityError) {
    return mapKaliSecurityError(err, ctx.correlationId);
  }
  return new ActionEngineError(
    'EXECUTION_FAILED',
    err instanceof Error ? err.message : 'Security action execution failed',
    { correlationId: ctx.correlationId }
  );
}

function mapKaliSecurityError(err: KaliSecurityError, correlationId: string): ActionEngineError {
  if (
    err.code === 'KALI_TENANT_ISOLATION_VIOLATION' ||
    err.code.startsWith('E_SOD') ||
    err.code.startsWith('E_SCOPE') ||
    err.code === 'KALI_BLOCKED_IMDS_TARGET' ||
    err.code === 'KALI_BLOCKED_RFC1918_TARGET' ||
    err.code === 'KALI_BLOCKED_PUBLIC_OR_NONLAB_TARGET'
  ) {
    return new ActionEngineError('FORBIDDEN', err.message, { correlationId });
  }
  if (err.code === 'KALI_RUN_NOT_FOUND') {
    return new ActionEngineError('NOT_FOUND', err.message, { correlationId });
  }
  if (err.code === 'KALI_BUDGET_EXCEEDED') {
    return new ActionEngineError('BUDGET_EXCEEDED', err.message, { correlationId });
  }
  if (err.code === 'KALI_SANDBOX_UNAVAILABLE') {
    return new ActionEngineError('EXECUTION_FAILED', err.message, { correlationId });
  }
  return new ActionEngineError('INPUT_INVALID', err.message, { correlationId });
}

const AnalyzeInputSchema = z
  .object({
    fixtureId: z.string().trim().min(1, 'fixtureId is required'),
    policyVersion: z.string().trim().min(1).optional(),
  })
  .strict();

const AnalyzeOutputSchema = z.object({
  analysisId: z.string().min(1),
  status: z.string().min(1),
  idempotentReplay: z.boolean(),
  stored: z.literal(true),
  analysis: z.record(z.unknown()),
  evidence: z.array(z.record(z.unknown())),
  mode: z.literal('LAB'),
  productionTested: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
});

const GetAnalysisInputSchema = z
  .object({
    analysisId: z.string().trim().min(1, 'analysisId is required'),
  })
  .strict();

const GetAnalysisOutputSchema = z.object({
  analysis: z.record(z.unknown()),
  evidence: z.array(z.record(z.unknown())),
  adjudications: z.array(z.record(z.unknown())),
  remediationSpecs: z.array(z.record(z.unknown())),
  decisionHistory: z.array(z.record(z.unknown())),
  mode: z.literal('LAB'),
  productionTested: z.literal(false),
});

const JudgeEvaluateInputSchema = z
  .object({
    analysisId: z.string().trim().min(1, 'analysisId is required'),
    expectedInputSha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/i, 'expectedInputSha256 must be 64-char hex')
      .optional(),
    model: z.string().trim().min(1).optional(),
  })
  .strict();

const JudgeEvaluateOutputSchema = z.object({
  analysisId: z.string().min(1),
  adjudication: AdjudicationResultSchema,
  mode: z.literal('LAB'),
  productionTested: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
});

const RemediationSpecInputSchema = z
  .object({
    analysisId: z.string().trim().min(1, 'analysisId is required'),
    pathId: z.string().trim().min(1, 'pathId is required'),
  })
  .strict();

const RemediationSpecOutputSchema = z.object({
  analysisId: z.string().min(1),
  pathId: z.string().min(1),
  remediationSpec: z.record(z.unknown()),
  requiresHumanApproval: z.literal(true),
  autoApplyAllowed: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
});

const StatusInputSchema = z.object({}).strict();

const StatusOutputSchema = z.object({
  service: z.string().min(1),
  version: z.string().min(1),
  mode: z.literal('LAB'),
  productionTested: z.literal(false),
  HARNESS2_EXPERIMENTS_ENABLED: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
  jevProviderStatus: z.enum(['LIVE', 'NOT_CONFIGURED']),
  components: z.record(z.record(z.unknown())),
  adapters: z.record(z.unknown()),
  timestamp: z.string().datetime(),
});

const AuditStartInputSchema = z
  .object({
    fixtureId: z.string().trim().min(1).optional(),
    targetRef: z.string().trim().min(1).optional(),
    policyVersion: z.string().trim().min(1).optional(),
    includeJudge: z.boolean().optional(),
  })
  .strict();

const AuditStartOutputSchema = z.object({
  auditId: z.string().min(1),
  runId: z.string().min(1),
  analysisId: z.string().min(1),
  tenantId: z.string().min(1),
  fixtureId: z.string().min(1),
  status: z.string().min(1),
  idempotentReplay: z.boolean(),
  stored: z.literal(true),
  redacted: z.literal(true),
  findingCount: z.number().int().nonnegative(),
  evidenceIds: z.array(z.string()),
  analysis: z.record(z.unknown()),
  evidence: z.array(z.record(z.unknown())),
  adjudication: z.record(z.unknown()).nullable(),
  remediationSpecs: z.array(z.record(z.unknown())),
  mode: z.literal('LAB'),
  productionTested: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
  externalExecution: z.literal(false),
});

const AuditGetInputSchema = z
  .object({
    auditId: z.string().trim().min(1).optional(),
    analysisId: z.string().trim().min(1).optional(),
  })
  .strict()
  .superRefine((data, zCtx) => {
    if (!data.auditId && !data.analysisId) {
      zCtx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['auditId'],
        message: 'Either auditId or analysisId is required',
      });
    }
  });

const AuditGetOutputSchema = z.object({
  auditId: z.string().min(1),
  analysisId: z.string().min(1),
  tenantId: z.string().min(1),
  status: z.string().min(1),
  redacted: z.literal(true),
  analysis: z.record(z.unknown()),
  evidence: z.array(z.record(z.unknown())),
  adjudications: z.array(z.record(z.unknown())),
  remediationSpecs: z.array(z.record(z.unknown())),
  decisionHistory: z.array(z.record(z.unknown())),
  mode: z.literal('LAB'),
  productionTested: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
  externalExecution: z.literal(false),
});

const EvidenceGetInputSchema = z
  .object({
    evidenceId: z.string().trim().min(1).optional(),
    analysisId: z.string().trim().min(1).optional(),
  })
  .strict()
  .superRefine((data, zCtx) => {
    if (!data.evidenceId && !data.analysisId) {
      zCtx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['evidenceId'],
        message: 'Either evidenceId or analysisId is required',
      });
    }
  });

const EvidenceGetOutputSchema = z.object({
  tenantId: z.string().min(1),
  analysisId: z.string().min(1).nullable(),
  evidenceId: z.string().min(1).nullable(),
  redacted: z.literal(true),
  verified: z.boolean(),
  evidence: z.array(z.record(z.unknown())),
  mode: z.literal('LAB'),
  productionTested: z.literal(false),
  mergeAllowed: z.literal(false),
  deployAllowed: z.literal(false),
  externalExecution: z.literal(false),
});

export interface SecurityActionRuntime {
  engine: SecurityActionEngine;
  store: CompanyBrainStore;
  kaliRunStore: KaliLabRunStore;
  close: () => void;
}

/**
 * Creates the canonical SecurityActionEngine wired to ChainBreak, JEV-as-a-Judge,
 * and a tenant-isolated CompanyBrainStore. Both direct callers and MCP Streamable HTTP
 * invoke this exact engine instance via `engine.invoke(...)`.
 */
export function createSecurityActionRuntime(
  options: CreateSecurityActionEngineOptions = {}
): SecurityActionRuntime {
  const ownsStore = options.store === undefined;
  const store =
    options.store ??
    new CompanyBrainStore({
      dbPath: options.dbPath ?? ':memory:',
      now: options.now,
    });
  const nowFn = options.now ?? (() => new Date().toISOString());
  const engineName = options.name ?? '@script-kitty/security-actions';
  const engineVersion = options.version ?? '0.1.0';

  const analyzeCapability = defineCapability({
    id: 'security.chainbreak.analyze',
    title: 'ChainBreak Policy Graph Analyze',
    description:
      'Runs deterministic ChainBreak LAB reachability analysis on an allowlisted fixture and persists tenant-isolated evidence in CompanyBrainStore.',
    inputSchema: AnalyzeInputSchema,
    outputSchema: AnalyzeOutputSchema,
    access: {
      requiredScopes: ['security:analyze'],
      costUnits: 10,
      timeoutMs: 10_000,
    },
    annotations: {
      readOnly: false,
      destructive: false,
      idempotent: true,
      openWorld: false,
    },
    async run(input, ctx) {
      try {
        if (!isAllowedFixtureId(input.fixtureId)) {
          throw new ActionEngineError(
            'INPUT_INVALID',
            `Fixture '${input.fixtureId}' is not in the authorized ChainBreak LAB allowlist`,
            { correlationId: ctx.correlationId }
          );
        }

        const { canonicalId } = resolveFixturePath(
          input.fixtureId,
          options.fixturesDir
        );
        const rawGraph = loadFixtureGraph(input.fixtureId, options.fixturesDir);
        const integrity = verifyGraphIntegrity(rawGraph);
        const fixturePolicyVersion =
          typeof rawGraph.policyVersion === 'string' &&
          rawGraph.policyVersion.trim().length > 0
            ? rawGraph.policyVersion.trim()
            : 'unknown';

        if (
          input.policyVersion &&
          input.policyVersion !== fixturePolicyVersion
        ) {
          throw new ActionEngineError(
            'INPUT_INVALID',
            `Requested policyVersion '${input.policyVersion}' does not match fixture policyVersion '${fixturePolicyVersion}'`,
            { correlationId: ctx.correlationId }
          );
        }

        const effectivePolicyVersion =
          input.policyVersion ?? fixturePolicyVersion;

        if (integrity.valid) {
          const existing = store.findAnalysisByIdempotency(ctx.tenantId, {
            fixtureId: canonicalId,
            policyVersion: effectivePolicyVersion,
            inputSha256: integrity.computedInputSha256,
          });
          if (existing) {
            return {
              analysisId: existing.analysisId,
              status: existing.status,
              idempotentReplay: true,
              stored: true as const,
              analysis: existing as unknown as Record<string, unknown>,
              evidence: existing.evidence as unknown as Array<
                Record<string, unknown>
              >,
              mode: 'LAB' as const,
              productionTested: false as const,
              mergeAllowed: false as const,
              deployAllowed: false as const,
            };
          }
        }

        const analysis = analyzeFixture(input.fixtureId, {
          fixturesDir: options.fixturesDir,
          policyVersion: input.policyVersion,
          executionScope: {
            tenantId: ctx.tenantId,
            principalId: ctx.principal.principalId,
            mode: 'LAB',
            allowedFixtures: [canonicalId, input.fixtureId],
            allowedPolicyVersions: [effectivePolicyVersion],
            maxNodes: 500,
            maxDepth: 12,
            maxPaths: 50,
            maxDurationMs: Math.min(5_000, ctx.budgetRemainingMs),
            allowProductionExecution: false,
            allowAutoMergeOrDeploy: false,
          },
          bindToAuthenticatedTenant: true,
          now: nowFn(),
        });

        const persisted = store.saveAnalysis(ctx.tenantId, analysis, {
          actorPrincipalId: ctx.principal.principalId,
          correlationId: ctx.correlationId,
          sourceRef: analysis.fixtureId,
        });

        return {
          analysisId: persisted.analysisId,
          status: persisted.status,
          idempotentReplay: false,
          stored: true as const,
          analysis: persisted as unknown as Record<string, unknown>,
          evidence: persisted.evidence as unknown as Array<
            Record<string, unknown>
          >,
          mode: 'LAB' as const,
          productionTested: false as const,
          mergeAllowed: false as const,
          deployAllowed: false as const,
        };
      } catch (err) {
        throw mapDomainError(err, ctx);
      }
    },
  });

  const getCapability = defineCapability({
    id: 'security.chainbreak.get',
    title: 'ChainBreak Analysis Get',
    description:
      'Retrieves persisted SecurityAnalysis, ChainBreakEvidence, AdjudicationResult, RemediationSpec, and DecisionHistory scoped strictly to the caller tenantId.',
    inputSchema: GetAnalysisInputSchema,
    outputSchema: GetAnalysisOutputSchema,
    access: {
      requiredScopes: ['security:read'],
      costUnits: 1,
      timeoutMs: 5_000,
    },
    annotations: {
      readOnly: true,
      destructive: false,
      idempotent: true,
      openWorld: false,
    },
    async run(input, ctx) {
      try {
        const context = store.getAnalysisWithContext(
          ctx.tenantId,
          input.analysisId
        );
        if (!context) {
          throw new ActionEngineError(
            'NOT_FOUND',
            `Analysis '${input.analysisId}' not found`,
            { correlationId: ctx.correlationId }
          );
        }
        return {
          analysis: context.analysis as unknown as Record<string, unknown>,
          evidence: context.evidence as unknown as Array<
            Record<string, unknown>
          >,
          adjudications: context.adjudications as unknown as Array<
            Record<string, unknown>
          >,
          remediationSpecs: context.remediationSpecs as unknown as Array<
            Record<string, unknown>
          >,
          decisionHistory: context.decisionHistory as unknown as Array<
            Record<string, unknown>
          >,
          mode: 'LAB' as const,
          productionTested: false as const,
        };
      } catch (err) {
        throw mapDomainError(err, ctx);
      }
    },
  });

  const judgeEvaluateCapability = defineCapability({
    id: 'security.judge.evaluate',
    title: 'JEV-as-a-Judge Advisory Evaluate',
    description:
      'Evaluates a persisted LAB analysis via deterministic pre-validations, sanitized TypeSafe JEV inference (or explicit offline mock), escalation policy, and deterministic risk checks.',
    inputSchema: JudgeEvaluateInputSchema,
    outputSchema: JudgeEvaluateOutputSchema,
    access: {
      requiredScopes: ['security:judge'],
      costUnits: 15,
      timeoutMs: 15_000,
    },
    annotations: {
      readOnly: false,
      destructive: false,
      idempotent: false,
      openWorld: false,
    },
    async run(input, ctx) {
      try {
        const ctxData = store.getAnalysisWithContext(
          ctx.tenantId,
          input.analysisId
        );
        if (!ctxData) {
          throw new ActionEngineError(
            'NOT_FOUND',
            `Analysis '${input.analysisId}' not found`,
            { correlationId: ctx.correlationId }
          );
        }

        const adjudication = await evaluateWithJevJudge({
          analysis: ctxData.analysis as any,
          evidence: ctxData.evidence as any,
          authContext: {
            principalId: ctx.principal.principalId,
            tenantId: ctx.tenantId,
            correlationId: ctx.correlationId,
          },
          expectedInputSha256: input.expectedInputSha256,
          escalationPolicy: options.escalationPolicy,
          provider: options.jevProvider,
          client: options.typesafeClient,
          model: input.model,
          signal: ctx.signal,
          timeoutMs: ctx.budgetRemainingMs,
          now: nowFn(),
        });

        store.saveAdjudication(ctx.tenantId, adjudication, {
          actorPrincipalId: ctx.principal.principalId,
          correlationId: ctx.correlationId,
          sourceRef:
            adjudication.sourceRefs[0] ?? ctxData.analysis.fixtureId,
        });

        return {
          analysisId: input.analysisId,
          adjudication,
          mode: 'LAB' as const,
          productionTested: false as const,
          mergeAllowed: false as const,
          deployAllowed: false as const,
        };
      } catch (err) {
        throw mapDomainError(err, ctx);
      }
    },
  });

  const remediationSpecCapability = defineCapability({
    id: 'security.remediation.spec',
    title: 'Defensive Remediation Spec',
    description:
      'Returns the minimal reviewable defensive RemediationSpec for an analyzed path with requiresHumanApproval=true and autoApplyAllowed=false.',
    inputSchema: RemediationSpecInputSchema,
    outputSchema: RemediationSpecOutputSchema,
    access: {
      requiredScopes: ['security:remediate'],
      costUnits: 5,
      timeoutMs: 5_000,
    },
    annotations: {
      readOnly: true,
      destructive: false,
      idempotent: true,
      openWorld: false,
    },
    async run(input, ctx) {
      try {
        const analysis = store.getAnalysisOrThrow(
          ctx.tenantId,
          input.analysisId
        );

        const pathExists = analysis.paths.some(
          (p) => (p as { pathId?: string }).pathId === input.pathId
        );
        if (!pathExists) {
          throw new ActionEngineError(
            'NOT_FOUND',
            `AttackPath '${input.pathId}' not found in analysis '${input.analysisId}'`,
            { correlationId: ctx.correlationId }
          );
        }

        let spec = store.getRemediationSpecForPath(
          ctx.tenantId,
          input.analysisId,
          input.pathId
        );
        if (!spec) {
          const fromAnalysis = analysis.remediationSpecs.find(
            (s) => s.pathId === input.pathId
          );
          if (!fromAnalysis) {
            throw new ActionEngineError(
              'NOT_FOUND',
              `RemediationSpec for path '${input.pathId}' not available`,
              { correlationId: ctx.correlationId }
            );
          }
          spec = store.saveRemediationSpec(ctx.tenantId, fromAnalysis, {
            actorPrincipalId: ctx.principal.principalId,
            correlationId: ctx.correlationId,
          });
        }

        return {
          analysisId: input.analysisId,
          pathId: input.pathId,
          remediationSpec: spec as unknown as Record<string, unknown>,
          requiresHumanApproval: true as const,
          autoApplyAllowed: false as const,
          mergeAllowed: false as const,
          deployAllowed: false as const,
        };
      } catch (err) {
        throw mapDomainError(err, ctx);
      }
    },
  });

  const statusCapability = defineCapability({
    id: 'security.status',
    title: 'Security Action Engine Status',
    description:
      'Reports component readiness, LAB-only boundary, JEV provider configuration status, and Harness2 feature flag status.',
    inputSchema: StatusInputSchema,
    outputSchema: StatusOutputSchema,
    access: {
      requiredScopes: ['security:status'],
      costUnits: 0,
      timeoutMs: 2_000,
    },
    annotations: {
      readOnly: true,
      destructive: false,
      idempotent: true,
      openWorld: false,
    },
    async run() {
      const jevStatus: 'LIVE' | 'NOT_CONFIGURED' =
        options.jevProvider?.mode === 'LIVE' || options.typesafeClient
          ? 'LIVE'
          : options.jevProvider?.mode === 'MOCK'
            ? 'NOT_CONFIGURED'
            : resolveJevProviderStatus();

      const externalAdapters = options.externalAdaptersStatus?.() ?? {
        patchcat: {
          status: 'ISOLATED_LAB_ONLY',
          mode: 'LAB',
          enabled: false,
          externalExecution: false,
        },
        typesafeJev: {
          status: jevStatus,
          mode: jevStatus === 'LIVE' ? 'LIVE' : 'MOCK_OFFLINE',
          enabled: jevStatus === 'LIVE',
          externalExecution: false,
        },
        factoryDeliveryGate: {
          status: 'READY',
          mode: 'LAB',
          enabled: true,
          externalExecution: false,
        },
      };

      return {
        service: engineName,
        version: engineVersion,
        mode: 'LAB' as const,
        productionTested: false as const,
        HARNESS2_EXPERIMENTS_ENABLED: false as const,
        mergeAllowed: false as const,
        deployAllowed: false as const,
        jevProviderStatus: jevStatus,
        components: {
          chainbreak: {
            status: 'READY',
            mode: 'LAB',
            allowlistFixtures: 4,
          },
          jevJudge: {
            status: jevStatus === 'LIVE' ? 'LIVE' : 'MOCK_FALLBACK_ONLY',
            providerStatus: jevStatus,
          },
          companyContext: {
            status: 'READY',
            tenantIsolated: true,
            storage: 'node:sqlite',
          },
          kaliLabSynthetic: {
            status: 'READY',
            profile: KALI_LAB_SYNTHETIC_PROFILE,
            mode: 'LAB_SANDBOX_ONLY',
            actions: [...KALI_LAB_ACTION_IDS],
            externalExecution: false,
          },
          actionEngine: {
            status: 'READY',
            capabilities: [...SECURITY_CAPABILITY_IDS],
          },
        },
        adapters: {
          externalExecution: false,
          ...externalAdapters,
        },
        timestamp: nowFn(),
      };
    },
  });

  const auditRunIndex = new Map<
    string,
    { auditId: string; analysisId: string; tenantId: string }
  >();
  const MAX_AUDIT_RUN_INDEX_ENTRIES = 2000;
  const setAuditRunIndex = (
    key: string,
    entry: { auditId: string; analysisId: string; tenantId: string }
  ): void => {
    if (!auditRunIndex.has(key)) {
      while (auditRunIndex.size >= MAX_AUDIT_RUN_INDEX_ENTRIES) {
        const oldestKey = auditRunIndex.keys().next().value;
        if (oldestKey === undefined) break;
        auditRunIndex.delete(oldestKey);
      }
    }
    auditRunIndex.delete(key);
    auditRunIndex.set(key, entry);
  };

  const auditStartCapability = defineCapability({
    id: 'security.audit.start',
    title: 'Continuous Security Audit Start (LAB)',
    description:
      'Runs deterministic ChainBreak LAB audit on an allowlisted fixture, persists tenant-isolated analysis/evidence/remediation/adjudication in CompanyBrainStore, and returns redacted audit results.',
    inputSchema: AuditStartInputSchema,
    outputSchema: AuditStartOutputSchema,
    access: {
      requiredScopes: ['security:analyze'],
      costUnits: 15,
      timeoutMs: 15_000,
    },
    annotations: {
      readOnly: false,
      destructive: false,
      idempotent: true,
      openWorld: false,
    },
    async run(input, ctx) {
      try {
        const requestedFixture = (
          input.fixtureId ??
          input.targetRef ??
          'payments-lab/unsafe-rollout'
        ).trim();

        if (!isAllowedFixtureId(requestedFixture)) {
          throw new ActionEngineError(
            'INPUT_INVALID',
            `Fixture '${requestedFixture}' is not in the authorized ChainBreak LAB allowlist`,
            { correlationId: ctx.correlationId }
          );
        }

        const { canonicalId } = resolveFixturePath(
          requestedFixture,
          options.fixturesDir
        );
        const rawGraph = loadFixtureGraph(
          requestedFixture,
          options.fixturesDir
        );
        const integrity = verifyGraphIntegrity(rawGraph);
        const fixturePolicyVersion =
          typeof rawGraph.policyVersion === 'string' &&
          rawGraph.policyVersion.trim().length > 0
            ? rawGraph.policyVersion.trim()
            : 'unknown';

        if (
          input.policyVersion &&
          input.policyVersion !== fixturePolicyVersion
        ) {
          throw new ActionEngineError(
            'INPUT_INVALID',
            `Requested policyVersion '${input.policyVersion}' does not match fixture policyVersion '${fixturePolicyVersion}'`,
            { correlationId: ctx.correlationId }
          );
        }

        const effectivePolicyVersion =
          input.policyVersion ?? fixturePolicyVersion;

        let persisted = integrity.valid
          ? store.findAnalysisByIdempotency(ctx.tenantId, {
              fixtureId: canonicalId,
              policyVersion: effectivePolicyVersion,
              inputSha256: integrity.computedInputSha256,
            })
          : null;
        const idempotentReplay = persisted !== null;

        if (!persisted) {
          const analysis = analyzeFixture(requestedFixture, {
            fixturesDir: options.fixturesDir,
            policyVersion: input.policyVersion,
            executionScope: {
              tenantId: ctx.tenantId,
              principalId: ctx.principal.principalId,
              mode: 'LAB',
              allowedFixtures: [canonicalId, requestedFixture],
              allowedPolicyVersions: [effectivePolicyVersion],
              maxNodes: 500,
              maxDepth: 12,
              maxPaths: 50,
              maxDurationMs: Math.min(5_000, ctx.budgetRemainingMs),
              allowProductionExecution: false,
              allowAutoMergeOrDeploy: false,
            },
            bindToAuthenticatedTenant: true,
            now: nowFn(),
          });

          persisted = store.saveAnalysis(ctx.tenantId, analysis, {
            actorPrincipalId: ctx.principal.principalId,
            correlationId: ctx.correlationId,
            sourceRef: analysis.fixtureId,
          });
        }

        let adjudicationRecord: Record<string, unknown> | null = null;
        if (input.includeJudge !== false) {
          const adjudication = await evaluateWithJevJudge({
            analysis: persisted as any,
            evidence: persisted.evidence as any,
            authContext: {
              principalId: ctx.principal.principalId,
              tenantId: ctx.tenantId,
              correlationId: ctx.correlationId,
            },
            escalationPolicy: options.escalationPolicy,
            provider: options.jevProvider,
            client: options.typesafeClient,
            signal: ctx.signal,
            timeoutMs: ctx.budgetRemainingMs,
            now: nowFn(),
          });

          store.saveAdjudication(ctx.tenantId, adjudication, {
            actorPrincipalId: ctx.principal.principalId,
            correlationId: ctx.correlationId,
            sourceRef: adjudication.sourceRefs[0] ?? persisted.fixtureId,
          });
          adjudicationRecord = redactKaliLabValue(
            adjudication as unknown as Record<string, unknown>
          );
        }

        const auditId = `audit-${persisted.analysisId}`;
        setAuditRunIndex(auditId, {
          auditId,
          analysisId: persisted.analysisId,
          tenantId: ctx.tenantId,
        });
        setAuditRunIndex(persisted.analysisId, {
          auditId,
          analysisId: persisted.analysisId,
          tenantId: ctx.tenantId,
        });

        const redactedAnalysis = redactKaliLabValue(
          persisted as unknown as Record<string, unknown>
        );
        const redactedEvidence = redactKaliLabValue(
          persisted.evidence as unknown as Array<Record<string, unknown>>
        );
        const redactedSpecs = redactKaliLabValue(
          (persisted.remediationSpecs ?? []) as unknown as Array<
            Record<string, unknown>
          >
        );

        return {
          auditId,
          runId: auditId,
          analysisId: persisted.analysisId,
          tenantId: ctx.tenantId,
          fixtureId: persisted.fixtureId,
          status: persisted.status,
          idempotentReplay,
          stored: true as const,
          redacted: true as const,
          findingCount: Array.isArray(persisted.paths)
            ? persisted.paths.length
            : 0,
          evidenceIds: [...persisted.evidenceIds],
          analysis: redactedAnalysis,
          evidence: redactedEvidence,
          adjudication: adjudicationRecord,
          remediationSpecs: redactedSpecs,
          mode: 'LAB' as const,
          productionTested: false as const,
          mergeAllowed: false as const,
          deployAllowed: false as const,
          externalExecution: false as const,
        };
      } catch (err) {
        throw mapDomainError(err, ctx);
      }
    },
  });

  const auditGetCapability = defineCapability({
    id: 'security.audit.get',
    title: 'Continuous Security Audit Get (Tenant-Isolated)',
    description:
      'Retrieves a persisted, redacted security audit run (analysis, evidence, adjudications, remediationSpecs, decisionHistory) strictly scoped to the caller tenantId.',
    inputSchema: AuditGetInputSchema,
    outputSchema: AuditGetOutputSchema,
    access: {
      requiredScopes: ['security:read'],
      costUnits: 1,
      timeoutMs: 5_000,
    },
    annotations: {
      readOnly: true,
      destructive: false,
      idempotent: true,
      openWorld: false,
    },
    async run(input, ctx) {
      try {
        const rawId = (input.auditId ?? input.analysisId ?? '').trim();
        const indexed = auditRunIndex.get(rawId);
        if (indexed && indexed.tenantId !== ctx.tenantId) {
          throw new TenantIsolationError(
            `Cross-tenant access denied for auditId '${rawId}'`
          );
        }

        const targetAnalysisId =
          indexed?.analysisId ??
          (rawId.startsWith('audit-') ? rawId.slice('audit-'.length) : rawId);

        const context = store.getAnalysisWithContext(
          ctx.tenantId,
          targetAnalysisId
        );
        if (!context) {
          throw new ActionEngineError(
            'NOT_FOUND',
            `Audit '${rawId}' not found`,
            { correlationId: ctx.correlationId }
          );
        }

        const resolvedAuditId =
          indexed?.auditId ?? `audit-${context.analysis.analysisId}`;

        return {
          auditId: resolvedAuditId,
          analysisId: context.analysis.analysisId,
          tenantId: ctx.tenantId,
          status: context.analysis.status,
          redacted: true as const,
          analysis: redactKaliLabValue(
            context.analysis as unknown as Record<string, unknown>
          ),
          evidence: redactKaliLabValue(
            context.evidence as unknown as Array<Record<string, unknown>>
          ),
          adjudications: redactKaliLabValue(
            context.adjudications as unknown as Array<Record<string, unknown>>
          ),
          remediationSpecs: redactKaliLabValue(
            context.remediationSpecs as unknown as Array<
              Record<string, unknown>
            >
          ),
          decisionHistory: redactKaliLabValue(
            context.decisionHistory as unknown as Array<Record<string, unknown>>
          ),
          mode: 'LAB' as const,
          productionTested: false as const,
          mergeAllowed: false as const,
          deployAllowed: false as const,
          externalExecution: false as const,
        };
      } catch (err) {
        throw mapDomainError(err, ctx);
      }
    },
  });

  const evidenceGetCapability = defineCapability({
    id: 'security.evidence.get',
    title: 'Security Evidence Get (Tenant-Isolated & Redacted)',
    description:
      'Retrieves persisted, redacted ChainBreakEvidence records by evidenceId and/or analysisId strictly scoped to the caller tenantId.',
    inputSchema: EvidenceGetInputSchema,
    outputSchema: EvidenceGetOutputSchema,
    access: {
      requiredScopes: ['security:read'],
      costUnits: 1,
      timeoutMs: 5_000,
    },
    annotations: {
      readOnly: true,
      destructive: false,
      idempotent: true,
      openWorld: false,
    },
    async run(input, ctx) {
      try {
        const requestedEvId = input.evidenceId?.trim() || null;
        const requestedAnalysisId = input.analysisId?.trim() || null;

        // 1. Check direct evidenceId ownership via typed CompanyBrainStore helper
        if (requestedEvId) {
          const directEv = store.getEvidenceById(ctx.tenantId, requestedEvId);
          if (directEv) {
            if (
              requestedAnalysisId &&
              requestedAnalysisId !== directEv.analysisId
            ) {
              // Ensure requestedAnalysisId also belongs to caller tenant or fail closed
              store.getEvidenceForAnalysis(ctx.tenantId, requestedAnalysisId);
              throw new ActionEngineError(
                'NOT_FOUND',
                `Evidence '${requestedEvId}' does not belong to analysis '${requestedAnalysisId}'`,
                { correlationId: ctx.correlationId }
              );
            }

            const redactedEv = redactKaliLabValue(
              directEv as unknown as Record<string, unknown>
            );
            return {
              tenantId: ctx.tenantId,
              analysisId: directEv.analysisId,
              evidenceId: requestedEvId,
              redacted: true as const,
              verified: Boolean(redactedEv.verified),
              evidence: [redactedEv],
              mode: 'LAB' as const,
              productionTested: false as const,
              mergeAllowed: false as const,
              deployAllowed: false as const,
              externalExecution: false as const,
            };
          }
        }

        // 2. Lookup by analysisId (enforces row ownership in CompanyBrainStore)
        if (requestedAnalysisId) {
          const analysis = store.getAnalysis(ctx.tenantId, requestedAnalysisId);
          if (!analysis) {
            throw new ActionEngineError(
              'NOT_FOUND',
              `Analysis '${requestedAnalysisId}' not found`,
              { correlationId: ctx.correlationId }
            );
          }
          const evList = store.getEvidenceForAnalysis(
            ctx.tenantId,
            requestedAnalysisId
          );
          const filtered = requestedEvId
            ? evList.filter((e) => e.evidenceId === requestedEvId)
            : evList;

          if (filtered.length === 0) {
            throw new ActionEngineError(
              'NOT_FOUND',
              `Evidence '${requestedEvId ?? requestedAnalysisId}' not found`,
              { correlationId: ctx.correlationId }
            );
          }

          const redactedList = redactKaliLabValue(
            filtered as unknown as Array<Record<string, unknown>>
          );
          return {
            tenantId: ctx.tenantId,
            analysisId: requestedAnalysisId,
            evidenceId:
              requestedEvId ??
              (redactedList.length === 1
                ? String(redactedList[0].evidenceId ?? '')
                : null),
            redacted: true as const,
            verified: redactedList.every((e) => Boolean(e.verified)),
            evidence: redactedList,
            mode: 'LAB' as const,
            productionTested: false as const,
            mergeAllowed: false as const,
            deployAllowed: false as const,
            externalExecution: false as const,
          };
        }

        throw new ActionEngineError(
          'NOT_FOUND',
          `Evidence '${requestedEvId ?? 'unknown'}' not found`,
          { correlationId: ctx.correlationId }
        );
      } catch (err) {
        throw mapDomainError(err, ctx);
      }
    },
  });

  const kaliRunStore = options.kaliRunStore ?? new KaliLabRunStore();
  const GenericKaliOutputSchema = z.record(z.unknown());
  const runKaliLabActionForCtx = async (
    actionId: KaliLabActionId | string,
    input: Record<string, unknown>,
    ctx: {
      tenantId: string;
      principal: { principalId: string };
      correlationId: string;
      budgetRemainingMs: number;
    }
  ): Promise<Record<string, unknown>> => {
    try {
      return (await executeKaliLabSyntheticAction(actionId, input, {
        workspaceRoot: options.workspaceRoot,
        now: options.now,
        tenantId: ctx.tenantId,
        principalId: ctx.principal.principalId,
        correlationId: ctx.correlationId,
        budgetRemainingMs: ctx.budgetRemainingMs,
        runStore: kaliRunStore,
      })) as unknown as Record<string, unknown>;
    } catch (err) {
      if (err instanceof KaliSecurityError) {
        throw mapKaliSecurityError(err, ctx.correlationId);
      }
      throw new ActionEngineError(
        'EXECUTION_FAILED',
        err instanceof Error ? err.message : 'Kali security action failed',
        { correlationId: ctx.correlationId }
      );
    }
  };

  const kaliLabCapabilities = [
    defineCapability({
      id: 'security.kali.lab_run',
      title: 'Kali LAB_SYNTHETIC Enumerated Verification Run',
      description:
        'Executes an enumerated Kali LAB_SYNTHETIC verification action (service_inventory, tls_review, web_passive_baseline, local_code_scan) with strict scopeRef, targetRef, budgetRef, zero raw shell, static `--` argv, and secret redaction.',
      inputSchema: KaliLabRunInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:analyze'],
        costUnits: 15,
        timeoutMs: 30_000,
      },
      annotations: {
        readOnly: false,
        destructive: false,
        idempotent: true,
        openWorld: false,
      },
      async run(input, ctx) {
        return runKaliLabActionForCtx(
          input.actionId,
          input as unknown as Record<string, unknown>,
          ctx
        );
      },
    }),
    defineCapability({
      id: 'security.kali.service_inventory',
      title: 'Kali LAB_SYNTHETIC Service Inventory',
      description:
        'Runs bounded LAB_SYNTHETIC TCP connect service inventory on allowlisted loopback/localnet targets using static `--` argv and redacts all banners/findings.',
      inputSchema: KaliServiceInventoryInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:analyze'],
        costUnits: 10,
        timeoutMs: 30_000,
      },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: true,
        openWorld: false,
      },
      async run(input, ctx) {
        return runKaliLabActionForCtx(
          'service_inventory',
          input as unknown as Record<string, unknown>,
          ctx
        );
      },
    }),
    defineCapability({
      id: 'security.kali.tls_review',
      title: 'Kali LAB_SYNTHETIC TLS Posture Review',
      description:
        'Runs non-destructive LAB_SYNTHETIC TLS cipher and protocol posture review on allowlisted loopback/localnet targets.',
      inputSchema: KaliTlsReviewInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:analyze'],
        costUnits: 10,
        timeoutMs: 30_000,
      },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: true,
        openWorld: false,
      },
      async run(input, ctx) {
        return runKaliLabActionForCtx(
          'tls_review',
          input as unknown as Record<string, unknown>,
          ctx
        );
      },
    }),
    defineCapability({
      id: 'security.kali.web_passive_baseline',
      title: 'Kali LAB_SYNTHETIC Web Passive Baseline',
      description:
        'Runs passive HTTP security header and CORS hygiene baseline assessment on allowlisted loopback/localnet targets.',
      inputSchema: KaliWebPassiveBaselineInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:analyze'],
        costUnits: 10,
        timeoutMs: 30_000,
      },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: true,
        openWorld: false,
      },
      async run(input, ctx) {
        return runKaliLabActionForCtx(
          'web_passive_baseline',
          input as unknown as Record<string, unknown>,
          ctx
        );
      },
    }),
    defineCapability({
      id: 'security.kali.local_code_scan',
      title: 'Kali LAB_SYNTHETIC Airgapped Local Code & Dependency Scan',
      description:
        'Runs airgapped (--net=none) local workspace manifest and configuration scan with strict path containment and secret redaction.',
      inputSchema: KaliLocalCodeScanInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:analyze'],
        costUnits: 15,
        timeoutMs: 45_000,
      },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: true,
        openWorld: false,
      },
      async run(input, ctx) {
        return runKaliLabActionForCtx(
          'local_code_scan',
          input as unknown as Record<string, unknown>,
          ctx
        );
      },
    }),
    defineCapability({
      id: 'security.kali.get_run',
      title: 'Kali LAB_SYNTHETIC Tenant-Isolated Run Lookup',
      description:
        'Retrieves a persisted, redacted Kali LAB_SYNTHETIC verification run strictly scoped to the authenticated caller tenantId.',
      inputSchema: KaliGetRunInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:read'],
        costUnits: 1,
        timeoutMs: 5_000,
      },
      annotations: {
        readOnly: true,
        destructive: false,
        idempotent: true,
        openWorld: false,
      },
      async run(input, ctx) {
        try {
          const run = kaliRunStore.getRun(ctx.tenantId, input.runId);
          return {
            runId: run.runId,
            tenantId: run.tenantId,
            actionId: run.actionId,
            profile: run.profile,
            mode: 'LAB' as const,
            executionMode: run.executionMode,
            redacted: true as const,
            productionTested: false as const,
            mergeAllowed: false as const,
            deployAllowed: false as const,
            externalExecution: false as const,
            run: run as unknown as Record<string, unknown>,
          };
        } catch (err) {
          throw mapDomainError(err, ctx);
        }
      },
    }),
  ];

  const engine = createEngine({
    name: engineName,
    version: engineVersion,
    capabilities: [
      analyzeCapability,
      getCapability,
      judgeEvaluateCapability,
      remediationSpecCapability,
      statusCapability,
      auditStartCapability,
      auditGetCapability,
      evidenceGetCapability,
      ...kaliLabCapabilities,
    ],
    defaultTimeoutMs: options.defaultTimeoutMs,
    defaultMaxCostUnits: options.defaultMaxCostUnits,
    onAuditEvent: options.onAuditEvent,
  });

  return {
    engine,
    store,
    kaliRunStore,
    close: () => {
      if (ownsStore) {
        store.close();
      }
    },
  };
}

export function createSecurityActionEngine(
  options: CreateSecurityActionEngineOptions = {}
): SecurityActionEngine {
  return createSecurityActionRuntime(options).engine;
}
