/**
 * @file packages/kali-mcp-assessment/src/capabilities.ts
 * @description Wraps `@script-kitty/kali-mcp-assessment/lab-runner` into
 * `@script-kitty/security-actions` `CapabilityDefinition` / `SecurityActionEngine` tools.
 */

import { z } from 'zod';
import {
  ActionEngineError,
  createEngine,
  defineCapability,
  type CapabilityDefinition,
  type SecurityActionEngine,
} from '@script-kitty/security-actions/engine';
import {
  KALI_CAPABILITY_NAMES,
  KALI_LAB_ACTION_IDS,
  KALI_LAB_SYNTHETIC_CAPABILITY_NAMES,
  KALI_LAB_SYNTHETIC_PROFILE,
  type KaliCapabilityName,
  type KaliLabActionId,
  KaliSecurityError as KaliSecurityErrorClass,
  KaliConfigAuditInputSchema,
  KaliGetRunInputSchema,
  KaliLabRunInputSchema,
  KaliLocalCodeScanInputSchema,
  KaliReconSurfaceInputSchema,
  KaliSbomCveCheckInputSchema,
  KaliServiceInventoryInputSchema,
  KaliTlsReviewInputSchema,
  KaliVerifyReproducerInputSchema,
  KaliWebPassiveBaselineInputSchema,
  verifyEngagementScope,
} from './schemas.js';
import {
  executeKaliCapability,
  executeKaliLabSyntheticAction,
  KaliLabRunStore,
  type KaliRunnerOptions,
} from './lab-runner.js';

export * from './lab-runner.js';

export function mapKaliErrorToEngine(err: unknown, correlationId: string): ActionEngineError {
  if (err instanceof ActionEngineError) return err;
  if (err instanceof KaliSecurityErrorClass) {
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
  return new ActionEngineError(
    'EXECUTION_FAILED',
    err instanceof Error ? err.message : String(err),
    { correlationId }
  );
}

const GenericKaliOutputSchema = z.record(z.unknown());

/**
 * Registers the 4 allowlisted Kali assessment capabilities as Invokta `@script-kitty/security-actions`
 * `CapabilityDefinition` objects.
 */
export function createKaliCapabilities(
  options: KaliRunnerOptions = {}
): CapabilityDefinition<any, any>[] {
  return [
    defineCapability({
      id: 'security.kali.recon_surface',
      title: 'Kali Lab Recon Surface Verification',
      description:
        'Lab-only bounded TCP connect / HTTP metadata probe emitting canonical SecurityFinding contracts.',
      inputSchema: KaliReconSurfaceInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:kali:recon'],
        costUnits: 15,
        timeoutMs: 45_000,
      },
      annotations: { readOnly: true, destructive: false, idempotent: true, openWorld: false },
      async run(input, ctx) {
        try {
          return (await executeKaliCapability(
            'security.kali.recon_surface',
            input as unknown as Record<string, unknown>,
            options
          )) as unknown as Record<string, unknown>;
        } catch (err) {
          throw mapKaliErrorToEngine(err, ctx.correlationId);
        }
      },
    }),
    defineCapability({
      id: 'security.kali.config_audit',
      title: 'Kali Lab Configuration & TLS/Header Audit',
      description:
        'Non-destructive TLS posture, HTTP security header hygiene, and static config tree audit.',
      inputSchema: KaliConfigAuditInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:kali:audit'],
        costUnits: 15,
        timeoutMs: 60_000,
      },
      annotations: { readOnly: true, destructive: false, idempotent: true, openWorld: false },
      async run(input, ctx) {
        try {
          return (await executeKaliCapability(
            'security.kali.config_audit',
            input as unknown as Record<string, unknown>,
            options
          )) as unknown as Record<string, unknown>;
        } catch (err) {
          throw mapKaliErrorToEngine(err, ctx.correlationId);
        }
      },
    }),
    defineCapability({
      id: 'security.kali.verify_reproducer',
      title: 'Kali Lab Deterministic Reproducer Verification',
      description:
        'Executes SHA-256 pinned reproducer verification with Tri-Party Separation of Duties and canonical Evidence minting.',
      inputSchema: KaliVerifyReproducerInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:kali:verify'],
        costUnits: 25,
        timeoutMs: 30_000,
      },
      annotations: { readOnly: false, destructive: false, idempotent: false, openWorld: false },
      async run(input, ctx) {
        try {
          return (await executeKaliCapability(
            'security.kali.verify_reproducer',
            input as unknown as Record<string, unknown>,
            options
          )) as unknown as Record<string, unknown>;
        } catch (err) {
          throw mapKaliErrorToEngine(err, ctx.correlationId);
        }
      },
    }),
    defineCapability({
      id: 'security.kali.sbom_cve_check',
      title: 'Kali Lab Offline Airgapped SBOM & CVE Audit',
      description:
        'Performs offline airgapped (--net=none) CycloneDX SBOM hashing and CVE inventory matching.',
      inputSchema: KaliSbomCveCheckInputSchema,
      outputSchema: GenericKaliOutputSchema,
      access: {
        requiredScopes: ['security:kali:sbom'],
        costUnits: 20,
        timeoutMs: 90_000,
      },
      annotations: { readOnly: true, destructive: false, idempotent: true, openWorld: false },
      async run(input, ctx) {
        try {
          return (await executeKaliCapability(
            'security.kali.sbom_cve_check',
            input as unknown as Record<string, unknown>,
            options
          )) as unknown as Record<string, unknown>;
        } catch (err) {
          throw mapKaliErrorToEngine(err, ctx.correlationId);
        }
      },
    }),
  ];
}

export function createKaliActionEngine(options: KaliRunnerOptions = {}): SecurityActionEngine {
  return createEngine({
    name: '@script-kitty/kali-mcp-assessment',
    version: '0.1.0',
    capabilities: createKaliCapabilities(options),
    defaultTimeoutMs: 60_000,
  });
}


/**
 * Creates the 6 enumerated Kali LAB_SYNTHETIC capabilities (`security.kali.lab_run`,
 * `security.kali.service_inventory`, `security.kali.tls_review`,
 * `security.kali.web_passive_baseline`, `security.kali.local_code_scan`,
 * `security.kali.get_run`) backed by a tenant-isolated `KaliLabRunStore`.
 */
export function createKaliLabSyntheticCapabilities(
  options: KaliRunnerOptions & { runStore?: KaliLabRunStore } = {}
): {
  capabilities: CapabilityDefinition<any, any>[];
  runStore: KaliLabRunStore;
} {
  const runStore = options.runStore ?? new KaliLabRunStore();

  const runActionForCtx = async (
    actionId: KaliLabActionId | string,
    input: Record<string, unknown>,
    ctx: {
      tenantId: string;
      principal: { principalId: string };
      correlationId: string;
      budgetRemainingMs: number;
    }
  ) => {
    try {
      return (await executeKaliLabSyntheticAction(actionId, input, {
        ...options,
        tenantId: ctx.tenantId,
        principalId: ctx.principal.principalId,
        correlationId: ctx.correlationId,
        budgetRemainingMs: ctx.budgetRemainingMs,
        runStore,
      })) as unknown as Record<string, unknown>;
    } catch (err) {
      throw mapKaliErrorToEngine(err, ctx.correlationId);
    }
  };

  const capabilities: CapabilityDefinition<any, any>[] = [
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
        return runActionForCtx(
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
        return runActionForCtx(
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
        return runActionForCtx(
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
        return runActionForCtx(
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
        return runActionForCtx(
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
          const run = runStore.getRun(ctx.tenantId, input.runId);
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
          throw mapKaliErrorToEngine(err, ctx.correlationId);
        }
      },
    }),
  ];

  return { capabilities, runStore };
}

