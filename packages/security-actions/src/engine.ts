/**
 * @file packages/security-actions/src/engine.ts
 * @description Single domain execution path (`createEngine`, `defineCapability`, `engine.invoke`)
 * enforcing Zod schema validation, capability authorization, principal-derived tenant isolation,
 * cost/time budget enforcement, AbortSignal cancellation, and sanitized correlationId audit logging.
 */

import * as crypto from 'node:crypto';
import { z } from 'zod';

export type ActionEngineErrorCode =
  | 'CAPABILITY_NOT_FOUND'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'INPUT_INVALID'
  | 'OUTPUT_INVALID'
  | 'CANCELLED'
  | 'TIMEOUT'
  | 'BUDGET_EXCEEDED'
  | 'NOT_FOUND'
  | 'EXECUTION_FAILED';

export class ActionEngineError extends Error {
  readonly code: ActionEngineErrorCode;
  readonly publicMessage: string;
  readonly correlationId?: string;

  constructor(
    code: ActionEngineErrorCode,
    message: string,
    options: { publicMessage?: string; correlationId?: string } = {}
  ) {
    super(`${code}: ${message}`);
    this.name = 'ActionEngineError';
    this.code = code;
    this.publicMessage = options.publicMessage ?? message;
    this.correlationId = options.correlationId;
  }
}

export const AuthPrincipalSchema = z.object({
  principalId: z.string().trim().min(1, 'principalId is required'),
  tenantId: z.string().trim().min(1, 'tenantId is required'),
  roles: z.array(z.string().min(1)).default([]),
  scopes: z.array(z.string().min(1)).default([]),
  tokenId: z.string().min(1).optional(),
});
export type AuthPrincipal = z.infer<typeof AuthPrincipalSchema>;

export interface InvocationBudget {
  timeoutMs?: number;
  maxCostUnits?: number;
}

export interface AuthContext {
  principal: AuthPrincipal;
  correlationId?: string;
  source?: 'direct' | 'mcp-http' | 'cli' | string;
  signal?: AbortSignal;
  budget?: InvocationBudget;
}

export interface CapabilityAnnotations {
  readOnly?: boolean;
  destructive?: boolean;
  idempotent?: boolean;
  openWorld?: boolean;
}

export interface CapabilityAccessPolicy {
  requiredScopes?: string[];
  requiredRoles?: string[];
  costUnits?: number;
  timeoutMs?: number;
}

export interface CapabilityRunContext {
  principal: AuthPrincipal;
  tenantId: string;
  correlationId: string;
  source: string;
  signal: AbortSignal;
  budgetRemainingMs: number;
}

export interface CapabilityDefinition<
  TInputSchema extends z.ZodTypeAny = z.ZodTypeAny,
  TOutputSchema extends z.ZodTypeAny = z.ZodTypeAny,
> {
  id: string;
  title: string;
  description: string;
  inputSchema: TInputSchema;
  outputSchema: TOutputSchema;
  access: CapabilityAccessPolicy;
  annotations?: CapabilityAnnotations;
  run: (
    input: z.infer<TInputSchema>,
    ctx: CapabilityRunContext
  ) => Promise<z.infer<TOutputSchema>> | z.infer<TOutputSchema>;
}

export interface AuditLogEntry {
  timestamp: string;
  correlationId: string;
  capabilityId: string;
  principalId: string;
  tenantId: string;
  source: string;
  status: 'SUCCESS' | 'ERROR';
  errorCode?: ActionEngineErrorCode;
  durationMs: number;
  costUnits: number;
}

export interface EngineOptions {
  name: string;
  version: string;
  capabilities: ReadonlyArray<CapabilityDefinition<any, any>>;
  defaultTimeoutMs?: number;
  defaultMaxCostUnits?: number;
  maxAuditEntries?: number;
  onAuditEvent?: (entry: AuditLogEntry) => void;
}

export interface CapabilitySummary {
  id: string;
  title: string;
  description: string;
  access: CapabilityAccessPolicy;
  annotations?: CapabilityAnnotations;
  inputSchema: z.ZodTypeAny;
  outputSchema: z.ZodTypeAny;
}

export function defineCapability<
  TInputSchema extends z.ZodTypeAny,
  TOutputSchema extends z.ZodTypeAny,
>(
  def: CapabilityDefinition<TInputSchema, TOutputSchema>
): CapabilityDefinition<TInputSchema, TOutputSchema> {
  if (!def.id || !/^[a-z0-9][a-z0-9._-]{1,126}$/i.test(def.id)) {
    throw new Error(`Invalid capability id '${def.id}'`);
  }
  return Object.freeze({
    ...def,
    access: Object.freeze({ ...def.access }),
    ...(def.annotations ? { annotations: Object.freeze({ ...def.annotations }) } : {}),
  });
}

function hasAuthorization(
  principal: AuthPrincipal,
  access: CapabilityAccessPolicy
): { allowed: boolean; reason?: string } {
  if (access.requiredRoles && access.requiredRoles.length > 0) {
    const roleSet = new Set(principal.roles);
    const matchesRole = access.requiredRoles.some((r) => roleSet.has(r));
    if (!matchesRole) {
      return {
        allowed: false,
        reason: `Principal lacks any required role: [${access.requiredRoles.join(', ')}]`,
      };
    }
  }

  if (access.requiredScopes && access.requiredScopes.length > 0) {
    const scopeSet = new Set(principal.scopes);
    const hasWildcard =
      scopeSet.has('*') || scopeSet.has('security:*');
    if (!hasWildcard) {
      const missing = access.requiredScopes.filter((s) => !scopeSet.has(s));
      if (missing.length > 0) {
        return {
          allowed: false,
          reason: `Principal lacks required scope(s): [${missing.join(', ')}]`,
        };
      }
    }
  }

  return { allowed: true };
}

function combineSignals(
  callerSignal: AbortSignal | undefined,
  timeoutMs: number
): { signal: AbortSignal; didTimeout: () => boolean; cleanup: () => void } {
  const controller = new AbortController();
  let timedOut = false;

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new Error(`Capability timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  const onCallerAbort = () => {
    controller.abort(callerSignal?.reason ?? new Error('Caller aborted request'));
  };

  if (callerSignal) {
    if (callerSignal.aborted) {
      clearTimeout(timer);
      controller.abort(callerSignal.reason ?? new Error('Caller aborted request'));
    } else {
      callerSignal.addEventListener('abort', onCallerAbort, { once: true });
    }
  }

  return {
    signal: controller.signal,
    didTimeout: () => timedOut,
    cleanup: () => {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', onCallerAbort);
    },
  };
}

export interface SecurityActionEngine {
  readonly name: string;
  readonly version: string;
  list(): CapabilitySummary[];
  getCapability(capabilityId: string): CapabilitySummary | undefined;
  invoke<TResult = unknown>(
    capabilityId: string,
    input: unknown,
    authContext: AuthContext
  ): Promise<TResult>;
  getAuditLog(tenantId?: string): AuditLogEntry[];
}

export function createEngine(options: EngineOptions): SecurityActionEngine {
  const defaultTimeoutMs = options.defaultTimeoutMs ?? 15_000;
  const defaultMaxCostUnits = options.defaultMaxCostUnits ?? 100;
  const maxAuditEntries = options.maxAuditEntries ?? 1_000;

  const registry = new Map<string, CapabilityDefinition<any, any>>();
  for (const cap of options.capabilities) {
    if (registry.has(cap.id)) {
      throw new Error(`Duplicate capability registration: '${cap.id}'`);
    }
    registry.set(cap.id, cap);
  }

  const auditEntries: AuditLogEntry[] = [];

  const recordAudit = (entry: AuditLogEntry) => {
    auditEntries.push(entry);
    if (auditEntries.length > maxAuditEntries) {
      auditEntries.shift();
    }
    options.onAuditEvent?.(entry);
  };

  return {
    name: options.name,
    version: options.version,

    list(): CapabilitySummary[] {
      return Array.from(registry.values()).map((cap) => ({
        id: cap.id,
        title: cap.title,
        description: cap.description,
        access: cap.access,
        annotations: cap.annotations,
        inputSchema: cap.inputSchema,
        outputSchema: cap.outputSchema,
      }));
    },

    getCapability(capabilityId: string): CapabilitySummary | undefined {
      const cap = registry.get(capabilityId);
      if (!cap) return undefined;
      return {
        id: cap.id,
        title: cap.title,
        description: cap.description,
        access: cap.access,
        annotations: cap.annotations,
        inputSchema: cap.inputSchema,
        outputSchema: cap.outputSchema,
      };
    },

    async invoke<TResult = unknown>(
      capabilityId: string,
      rawInput: unknown,
      authContext: AuthContext
    ): Promise<TResult> {
      const startedMs = Date.now();
      const correlationId =
        authContext?.correlationId && authContext.correlationId.trim().length > 0
          ? authContext.correlationId.trim()
          : crypto.randomUUID();
      const source = authContext?.source ?? 'direct';

      const cap = registry.get(capabilityId);
      const costUnits = cap?.access.costUnits ?? 0;

      // Authenticate caller principal first (never trust tenantId inside payload)
      const principalParse = AuthPrincipalSchema.safeParse(authContext?.principal);
      if (!principalParse.success) {
        const err = new ActionEngineError(
          'UNAUTHENTICATED',
          'Valid authenticated principal with principalId and tenantId is required',
          { correlationId }
        );
        recordAudit({
          timestamp: new Date().toISOString(),
          correlationId,
          capabilityId,
          principalId: 'anonymous',
          tenantId: 'unknown',
          source,
          status: 'ERROR',
          errorCode: err.code,
          durationMs: Date.now() - startedMs,
          costUnits: 0,
        });
        throw err;
      }

      const principal = principalParse.data;
      const emitError = (err: ActionEngineError): never => {
        recordAudit({
          timestamp: new Date().toISOString(),
          correlationId,
          capabilityId,
          principalId: principal.principalId,
          tenantId: principal.tenantId,
          source,
          status: 'ERROR',
          errorCode: err.code,
          durationMs: Date.now() - startedMs,
          costUnits,
        });
        throw err;
      };

      if (!cap) {
        return emitError(
          new ActionEngineError(
            'CAPABILITY_NOT_FOUND',
            `Capability '${capabilityId}' is not registered`,
            { correlationId }
          )
        );
      }

      if (authContext.signal?.aborted) {
        return emitError(
          new ActionEngineError(
            'CANCELLED',
            'Invocation cancelled before execution started',
            { correlationId }
          )
        );
      }

      // Authorize capability scopes/roles
      const authz = hasAuthorization(principal, cap.access);
      if (!authz.allowed) {
        return emitError(
          new ActionEngineError('FORBIDDEN', authz.reason ?? 'Forbidden', {
            correlationId,
          })
        );
      }

      // Enforce cost budget
      const maxCost = authContext.budget?.maxCostUnits ?? defaultMaxCostUnits;
      if (!Number.isFinite(maxCost) || maxCost < 0 || costUnits > maxCost) {
        return emitError(
          new ActionEngineError(
            'BUDGET_EXCEEDED',
            `Capability cost (${costUnits}) exceeds invocation cost budget (${maxCost})`,
            { correlationId }
          )
        );
      }

      // Reject any payload attempting to inject/override tenantId
      if (
        rawInput !== null &&
        typeof rawInput === 'object' &&
        !Array.isArray(rawInput) &&
        Object.prototype.hasOwnProperty.call(rawInput, 'tenantId')
      ) {
        return emitError(
          new ActionEngineError(
            'FORBIDDEN',
            'Request payload must not specify tenantId; tenant scope is derived exclusively from authenticated principal',
            { correlationId }
          )
        );
      }

      // Validate input against Zod schema
      const parsedInput = cap.inputSchema.safeParse(rawInput ?? {});
      if (!parsedInput.success) {
        const details = parsedInput.error.errors
          .map((e: z.ZodIssue) => `${e.path.join('.') || 'input'}: ${e.message}`)
          .join('; ');
        return emitError(
          new ActionEngineError(
            'INPUT_INVALID',
            `Input validation failed for '${capabilityId}': ${details}`,
            { correlationId }
          )
        );
      }

      const rawTimeout =
        authContext.budget?.timeoutMs ?? cap.access.timeoutMs ?? defaultTimeoutMs;
      const effectiveTimeoutMs = Math.max(
        1,
        Math.min(
          rawTimeout,
          cap.access.timeoutMs ?? rawTimeout,
          defaultTimeoutMs
        )
      );

      const { signal, didTimeout, cleanup } = combineSignals(
        authContext.signal,
        effectiveTimeoutMs
      );

      let abortRejectHandler: (() => void) | undefined;
      try {
        const abortPromise = new Promise<never>((_resolve, reject) => {
          if (signal.aborted) {
            reject(
              new ActionEngineError(
                didTimeout() ? 'TIMEOUT' : 'CANCELLED',
                didTimeout()
                  ? `Capability '${capabilityId}' exceeded ${effectiveTimeoutMs}ms budget`
                  : `Capability '${capabilityId}' was cancelled`,
                { correlationId }
              )
            );
            return;
          }
          abortRejectHandler = () => {
            reject(
              new ActionEngineError(
                didTimeout() ? 'TIMEOUT' : 'CANCELLED',
                didTimeout()
                  ? `Capability '${capabilityId}' exceeded ${effectiveTimeoutMs}ms budget`
                  : `Capability '${capabilityId}' was cancelled`,
                { correlationId }
              )
            );
          };
          signal.addEventListener('abort', abortRejectHandler, { once: true });
        });

        const execPromise = Promise.resolve(
          cap.run(parsedInput.data, {
            principal,
            tenantId: principal.tenantId,
            correlationId,
            source,
            signal,
            budgetRemainingMs: effectiveTimeoutMs,
          })
        );
        execPromise.catch(() => {});
        abortPromise.catch(() => {});

        const rawOutput = await Promise.race([execPromise, abortPromise]);

        if (signal.aborted) {
          return emitError(
            new ActionEngineError(
              didTimeout() ? 'TIMEOUT' : 'CANCELLED',
              didTimeout()
                ? `Capability '${capabilityId}' exceeded ${effectiveTimeoutMs}ms budget`
                : `Capability '${capabilityId}' was cancelled`,
              { correlationId }
            )
          );
        }

        const parsedOutput = cap.outputSchema.safeParse(rawOutput);
        if (!parsedOutput.success) {
          return emitError(
            new ActionEngineError(
              'OUTPUT_INVALID',
              `Capability '${capabilityId}' returned invalid output schema`,
              { correlationId }
            )
          );
        }

        recordAudit({
          timestamp: new Date().toISOString(),
          correlationId,
          capabilityId,
          principalId: principal.principalId,
          tenantId: principal.tenantId,
          source,
          status: 'SUCCESS',
          durationMs: Date.now() - startedMs,
          costUnits,
        });

        return parsedOutput.data as TResult;
      } catch (err) {
        if (err instanceof ActionEngineError) {
          return emitError(err);
        }
        return emitError(
          new ActionEngineError(
            'EXECUTION_FAILED',
            err instanceof Error ? err.message : 'Capability execution failed',
            {
              publicMessage:
                err instanceof Error
                  ? err.message
                  : 'Capability execution failed',
              correlationId,
            }
          )
        );
      } finally {
        if (abortRejectHandler) {
          signal.removeEventListener('abort', abortRejectHandler);
        }
        cleanup();
      }
    },

    getAuditLog(tenantId?: string): AuditLogEntry[] {
      if (!tenantId) {
        return [...auditEntries];
      }
      return auditEntries.filter((e) => e.tenantId === tenantId);
    },
  };
}
