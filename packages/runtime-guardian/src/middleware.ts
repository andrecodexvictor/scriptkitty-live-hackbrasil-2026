/**
 * @file packages/runtime-guardian/src/middleware.ts
 * @description In-process MCP Server Wrapper and Client Interceptor Middleware
 * for AI Agent Runtime Protection.
 */

import { randomUUID } from 'node:crypto';
import {
  type GuardianConfig,
  type SecurityPolicy,
  type InterceptionContext,
  type InterceptionDecision,
  type ToolDefinition,
  GuardianSecurityError,
} from './types.js';
import { ToolPoisoningGuard } from './tool-poisoning.js';
import { PromptInjectionDetector, sanitizeString } from './prompt-injection.js';
import { ScopeBoundaryGuard } from './scope-guard.js';
import { ConfusedDeputyGuard } from './confused-deputy.js';
import {
  type IAuditLogger,
  InMemoryAuditLogger,
  FileAuditLogger,
  canonicalStringify,
  sha256,
} from './audit-logger.js';

export class RuntimeGuardian {
  private config: GuardianConfig;
  private toolPoisoning: ToolPoisoningGuard;
  private promptInjection: PromptInjectionDetector;
  private scopeGuard: ScopeBoundaryGuard;
  private confusedDeputy: ConfusedDeputyGuard;
  private auditLogger: IAuditLogger;

  constructor(config?: GuardianConfig) {
    this.config = {
      guardian_id: config?.guardian_id ?? `guardian-${randomUUID().slice(0, 8)}`,
      environment: config?.environment ?? 'development',
      failClosed: config?.failClosed !== false, // default true
      errorMode: config?.errorMode ?? 'tool_result', // default tool_result
      policy: config?.policy ?? {},
    };

    const policy = this.config.policy ?? {};

    this.toolPoisoning = new ToolPoisoningGuard(policy.toolPoisoning);
    this.promptInjection = new PromptInjectionDetector(policy.promptInjection);
    this.scopeGuard = new ScopeBoundaryGuard(policy.scopeGuard);
    this.confusedDeputy = new ConfusedDeputyGuard(policy.confusedDeputy);

    if (policy.auditLogger?.logFilePath) {
      this.auditLogger = new FileAuditLogger(policy.auditLogger.logFilePath);
    } else {
      this.auditLogger = new InMemoryAuditLogger();
    }
  }

  public getConfig(): GuardianConfig {
    return this.config;
  }

  public getPolicy(): SecurityPolicy {
    return this.config.policy ?? {};
  }

  public getAuditLogger(): IAuditLogger {
    return this.auditLogger;
  }

  public getToolPoisoningGuard(): ToolPoisoningGuard {
    return this.toolPoisoning;
  }

  public getPromptInjectionDetector(): PromptInjectionDetector {
    return this.promptInjection;
  }

  public getScopeBoundaryGuard(): ScopeBoundaryGuard {
    return this.scopeGuard;
  }

  public getConfusedDeputyGuard(): ConfusedDeputyGuard {
    return this.confusedDeputy;
  }

  /**
   * Hook 1: onListTools
   * Intercepts tools/list response, verifies hashes against manifest,
   * blocks shadow tools, detects schema drift, and records audit node.
   */
  public async onListTools(
    candidateTools: ToolDefinition[],
    context?: Partial<InterceptionContext>
  ): Promise<ToolDefinition[]> {
    const ctx: InterceptionContext = {
      session_id: context?.session_id ?? `sess-${randomUUID().slice(0, 8)}`,
      caller_agent_id: context?.caller_agent_id,
      timestamp: context?.timestamp ?? new Date().toISOString(),
      ...context,
    };

    const result = this.toolPoisoning.verifyToolList(candidateTools, ctx);

    // Record audit event
    const hasViolations = result.violations.length > 0;
    const verdict = hasViolations ? 'BLOCK' : 'ALLOW';
    const decision = verdict;

    await this.auditLogger.log({
      event_type: 'TOOL_LIST',
      stage: 'ON_LIST_TOOLS',
      agent_id: ctx.caller_agent_id,
      session_id: ctx.session_id,
      tool_name: 'system:tools/list',
      decision,
      policy_id: 'tool_poisoning_manifest',
      detector: 'tool_poisoning',
      rule_id: hasViolations ? result.violations[0].violation_code : 'tools_verified',
      details: {
        total_advertised: candidateTools.length,
        allowed_count: result.allowedTools.length,
        violations: result.violations,
      },
    });

    if (hasViolations && this.config.failClosed && result.allowedTools.length === 0) {
      const topV = result.violations[0];
      throw new GuardianSecurityError(
        `Tool listing blocked by Guardian fail-closed policy: ${topV.violation_code} - ${topV.details}`,
        topV.violation_code,
        'tool_poisoning',
        'tool_listing_verification',
        { violations: result.violations }
      );
    }

    return result.allowedTools;
  }

  /**
   * Hook 2: onCallTool
   * Intercepts tools/call request before execution across 4 defense phases:
   * 1. Tool Identity & Registration
   * 2. Confused Deputy & Tri-Party Separation of Duties
   * 3. Scope Guard & Resource Boundary Containment
   * 4. Indirect Prompt Injection Inspection & Sanitization
   */
  public async onCallTool(
    toolName: string,
    toolArgs: Record<string, unknown> = {},
    context?: Partial<InterceptionContext>
  ): Promise<InterceptionDecision> {
    const ctx: InterceptionContext = {
      session_id: context?.session_id ?? `sess-${randomUUID().slice(0, 8)}`,
      caller_agent_id: context?.caller_agent_id,
      target_agent_id: context?.target_agent_id,
      discovering_agent_id: context?.discovering_agent_id,
      delegation_token: context?.delegation_token,
      tool_name: toolName,
      timestamp: context?.timestamp ?? new Date().toISOString(),
      trace_id: context?.trace_id,
      taint_tags: context?.taint_tags,
      taint_context: context?.taint_context,
      is_tainted: context?.is_tainted,
      ...context,
    };

    // Phase 1: Tool Poisoning / Identity Verification
    const toolCheck = this.toolPoisoning.verifyToolCall(toolName, ctx);
    if (toolCheck.verdict === 'BLOCK') {
      await this.auditLogger.log({
        event_type: 'TOOL_POISONING_DETECTED',
        stage: 'ON_CALL_TOOL',
        agent_id: ctx.caller_agent_id,
        session_id: ctx.session_id,
        tool_name: toolName,
        decision: 'BLOCK',
        policy_id: 'tool_poisoning_policy',
        detector: 'tool_poisoning',
        rule_id: toolCheck.rule_id,
        details: { reason: toolCheck.reason, metadata: toolCheck.metadata },
      });
      return toolCheck;
    }

    // Phase 2: Confused Deputy & Separation of Duties
    const deputyCheck = this.confusedDeputy.inspect(toolName, toolArgs, ctx);
    if (deputyCheck.verdict === 'BLOCK') {
      await this.auditLogger.log({
        event_type: 'CONFUSED_DEPUTY_DETECTED',
        stage: 'ON_CALL_TOOL',
        agent_id: ctx.caller_agent_id,
        session_id: ctx.session_id,
        tool_name: toolName,
        decision: 'BLOCK',
        policy_id: 'confused_deputy_policy',
        detector: 'confused_deputy',
        rule_id: deputyCheck.rule_id,
        details: { reason: deputyCheck.reason, metadata: deputyCheck.metadata },
      });
      return deputyCheck;
    }

    // Phase 3: Scope Guard & Path Boundary
    const scopeCheck = this.scopeGuard.inspect(toolArgs, ctx);
    if (scopeCheck.verdict === 'BLOCK') {
      await this.auditLogger.log({
        event_type: 'SCOPE_VIOLATION_DETECTED',
        stage: 'ON_CALL_TOOL',
        agent_id: ctx.caller_agent_id,
        session_id: ctx.session_id,
        tool_name: toolName,
        decision: 'BLOCK',
        policy_id: 'scope_guard_policy',
        detector: 'scope_guard',
        rule_id: scopeCheck.rule_id,
        details: { reason: scopeCheck.reason, metadata: scopeCheck.metadata },
      });
      return scopeCheck;
    }

    // Phase 4: Indirect Prompt Injection Inspection
    const injectionCheck = this.promptInjection.inspect(toolArgs, ctx);
    if (injectionCheck.verdict === 'BLOCK') {
      await this.auditLogger.log({
        event_type: 'PROMPT_INJECTION_DETECTED',
        stage: 'ON_CALL_TOOL',
        agent_id: ctx.caller_agent_id,
        session_id: ctx.session_id,
        tool_name: toolName,
        decision: 'BLOCK',
        policy_id: 'prompt_injection_policy',
        detector: 'prompt_injection',
        rule_id: injectionCheck.rule_id,
        details: { reason: injectionCheck.reason, metadata: injectionCheck.metadata },
      });
      return injectionCheck;
    }

    if (injectionCheck.verdict === 'SANITIZE') {
      await this.auditLogger.log({
        event_type: 'TOOL_CALL',
        stage: 'ON_CALL_TOOL',
        agent_id: ctx.caller_agent_id,
        session_id: ctx.session_id,
        tool_name: toolName,
        decision: 'SANITIZE',
        policy_id: 'prompt_injection_policy',
        detector: 'prompt_injection',
        rule_id: injectionCheck.rule_id,
        details: { reason: injectionCheck.reason, metadata: injectionCheck.metadata },
      });
      return injectionCheck;
    }

    // Phase 5: Clean tool call ALLOW
    await this.auditLogger.log({
      event_type: 'TOOL_CALL',
      stage: 'ON_CALL_TOOL',
      agent_id: ctx.caller_agent_id,
      session_id: ctx.session_id,
      tool_name: toolName,
      decision: 'ALLOW',
      policy_id: 'default_authorization',
      detector: 'policy',
      rule_id: 'tool_call_authorized',
      details: {
        arguments_digest: sha256(canonicalStringify(toolArgs)),
      },
    });

    return {
      verdict: 'ALLOW',
      detector: 'policy',
      rule_id: 'tool_call_authorized',
    };
  }

  /**
   * Hook 3: onToolResult
   * Intercepts tool execution outputs before they re-enter agent/LLM context:
   * - Redacts leaked credentials (AWS, GitHub, private keys).
   * - Neutralizes second-order prompt injection payloads.
   * - Records SHA-256 result digest to custody chain.
   */
  public async onToolResult(
    result: unknown,
    context?: Partial<InterceptionContext>
  ): Promise<unknown> {
    const ctx: InterceptionContext = {
      session_id: context?.session_id ?? `sess-${randomUUID().slice(0, 8)}`,
      caller_agent_id: context?.caller_agent_id,
      tool_name: context?.tool_name ?? 'unknown',
      timestamp: context?.timestamp ?? new Date().toISOString(),
      ...context,
    };

    // Deep sanitize outputs: credential redaction & second-order injection
    const sanitizedResult = this.promptInjection.sanitize(result);

    const resultDigest = sha256(canonicalStringify(sanitizedResult));

    await this.auditLogger.log({
      event_type: 'TOOL_RESULT',
      stage: 'ON_TOOL_RESULT',
      agent_id: ctx.caller_agent_id,
      session_id: ctx.session_id,
      tool_name: ctx.tool_name ?? 'unknown',
      decision: 'ALLOW',
      policy_id: 'output_custody_policy',
      detector: 'policy',
      rule_id: 'tool_result_custody_sealed',
      details: {
        result_digest: resultDigest,
      },
    });

    return sanitizedResult;
  }
}

export function createGuardianMiddleware(config?: GuardianConfig): RuntimeGuardian {
  return new RuntimeGuardian(config);
}

/**
 * Wraps an MCP Server instance with RuntimeGuardian middleware.
 * Supports both pre-existing handlers and future setRequestHandler invocations.
 */
export function wrapMcpServer(server: any, guardian: RuntimeGuardian): any {
  if (!server) return server;

  const originalSetRequestHandler = server.setRequestHandler.bind(server);

  // Helper to wrap a tools/list handler
  const wrapListHandler = (originalHandler: Function) => {
    return async (request: any, extra: any) => {
      const originalResult = await originalHandler(request, extra);
      const tools = originalResult?.tools ?? [];
      const verifiedTools = await guardian.onListTools(tools, {
        session_id: extra?.sessionId,
        caller_agent_id: extra?.callerId,
      });
      return {
        ...originalResult,
        tools: verifiedTools,
      };
    };
  };

  // Helper to wrap a tools/call handler
  const wrapCallHandler = (originalHandler: Function) => {
    return async (request: any, extra: any) => {
      const { name, arguments: args, _meta } = request?.params ?? {};

      const context: Partial<InterceptionContext> = {
        session_id: _meta?.session_id ?? extra?.sessionId,
        caller_agent_id: _meta?.caller_agent_id ?? _meta?.agent_id ?? extra?.callerId,
        target_agent_id: _meta?.target_agent_id,
        discovering_agent_id: _meta?.discovering_agent_id,
        delegation_token: _meta?.delegation_token,
        trace_id: _meta?.trace_id,
        taint_tags: _meta?.taint_tags,
        taint_context: _meta?.taint_context,
        is_tainted: _meta?.is_tainted,
      };

      const decision = await guardian.onCallTool(name, args ?? {}, context);

      if (decision.verdict === 'BLOCK') {
        if (guardian.getConfig().errorMode === 'throw') {
          throw new GuardianSecurityError(
            decision.reason ?? `Execution of tool '${name}' was blocked by Runtime Guardian`,
            decision.rule_id,
            decision.detector,
            decision.rule_id,
            decision.metadata
          );
        }

        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `[GUARDIAN_SECURITY_BLOCK] ${decision.rule_id}: ${decision.reason}`,
            },
          ],
        };
      }

      // If sanitized, pass sanitized payload
      const effectiveArgs =
        decision.verdict === 'SANITIZE' && decision.sanitized_payload
          ? (decision.sanitized_payload as Record<string, unknown>)
          : args;

      const patchedRequest = {
        ...request,
        params: {
          ...request.params,
          arguments: effectiveArgs,
        },
      };

      const rawResult = await originalHandler(patchedRequest, extra);
      const safeResult = await guardian.onToolResult(rawResult, {
        ...context,
        tool_name: name,
      });

      return safeResult;
    };
  };

  // Wrap any already registered handlers in _requestHandlers map
  if (server._requestHandlers && server._requestHandlers instanceof Map) {
    if (server._requestHandlers.has('tools/list')) {
      const existing = server._requestHandlers.get('tools/list');
      server._requestHandlers.set('tools/list', wrapListHandler(existing));
    }
    if (server._requestHandlers.has('tools/call')) {
      const existing = server._requestHandlers.get('tools/call');
      server._requestHandlers.set('tools/call', wrapCallHandler(existing));
    }
  }

  // Intercept future setRequestHandler calls
  server.setRequestHandler = (schema: any, handler: Function) => {
    // Determine method name across Zod v3/v4 schemas (schema.shape.method literal) and mock objects
    const shape =
      typeof schema?.shape === 'function'
        ? schema.shape()
        : (schema?.shape ?? schema?._def?.shape?.());
    const methodField = shape?.method;
    const schemaMethod =
      schema?.method ??
      methodField?.value ??
      methodField?._def?.value ??
      methodField?.def?.value ??
      (Array.isArray(methodField?.def?.values) ? methodField.def.values[0] : undefined) ??
      (Array.isArray(methodField?._def?.values) ? methodField._def.values[0] : undefined);

    const paramsShape =
      schema?.params?.shape ??
      shape?.params?.shape ??
      shape?.params?._def?.shape?.();

    const isListTools =
      schemaMethod !== undefined
        ? schemaMethod === 'tools/list'
        : schema?.title === 'ListToolsRequest' ||
          Boolean(paramsShape && !paramsShape?.name);

    const isCallTool =
      schemaMethod !== undefined
        ? schemaMethod === 'tools/call'
        : schema?.title === 'CallToolRequest' ||
          Boolean(paramsShape?.name);

    if (isListTools) {
      return originalSetRequestHandler(schema, wrapListHandler(handler));
    }

    if (isCallTool) {
      return originalSetRequestHandler(schema, wrapCallHandler(handler));
    }

    return originalSetRequestHandler(schema, handler);
  };

  return server;
}

/**
 * Creates a standalone client-side guardian interceptor for direct agent tool calling runtimes.
 */
export function createGuardianClientInterceptor(guardian: RuntimeGuardian) {
  return {
    executeProtectedTool: async <T = unknown>(
      toolName: string,
      toolArgs: Record<string, unknown>,
      executor: (sanitizedArgs: Record<string, unknown>) => Promise<T>,
      context?: Partial<InterceptionContext>
    ): Promise<T> => {
      const decision = await guardian.onCallTool(toolName, toolArgs, context);

      if (decision.verdict === 'BLOCK') {
        throw new GuardianSecurityError(
          decision.reason ?? `Execution of tool '${toolName}' was blocked by Runtime Guardian`,
          decision.rule_id,
          decision.detector,
          decision.rule_id,
          decision.metadata
        );
      }

      const effectiveArgs =
        decision.verdict === 'SANITIZE' && decision.sanitized_payload
          ? (decision.sanitized_payload as Record<string, unknown>)
          : toolArgs;

      const rawResult = await executor(effectiveArgs);
      const safeResult = (await guardian.onToolResult(rawResult, {
        ...context,
        tool_name: toolName,
      })) as T;

      return safeResult;
    },
  };
}
