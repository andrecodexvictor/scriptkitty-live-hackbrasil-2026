/**
 * @file packages/kali-mcp-assessment/src/server.ts
 * @description Hardened MCP Server exposing the 4 allowlisted `security.kali.*`
 * verification capabilities, wrapped with `@script-kitty/runtime-guardian`
 * (`wrapMcpServer`, `ToolPoisoningGuard` RFC 8785 pin manifest, `ConfusedDeputyGuard`
 * HMAC-SHA256 delegation + Tri-Party SoD + taint barrier, `ScopeBoundaryGuard`,
 * `PromptInjectionDetector` ingress + `onToolResult` egress redaction/sanitization,
 * and SHA-256 Merkle custody audit logging).
 */

import * as path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { canonicalStringify, sha256 } from '@script-kitty/contracts';
import { validateSeparationOfDuties } from '@script-kitty/quality-gate';
import { sanitizeOutput } from '../../adapters/dist/index.js';
import {
  DEFAULT_PATH_ARGUMENT_NAMES,
  RuntimeGuardian,
  computeToolDefinitionHash,
  createDelegationClaims,
  signDelegationToken,
  wrapMcpServer,
  type InterceptionContext,
  type SignedDelegationToken,
  type ToolDefinition,
  type ToolPinManifest,
} from '../../runtime-guardian/dist/index.js';
import {
  type KaliRunnerOptions,
  executeKaliCapability,
} from './capabilities.js';
import {
  KALI_CAPABILITY_NAMES,
  KALI_MODE,
  type KaliCapabilityName,
  KaliSecurityError,
  scanKaliPayloadSafety,
} from './schemas.js';

/**
 * Canonical MCP tool definitions for the 4 allowlisted verification capabilities.
 */
export const KALI_MCP_TOOL_DEFINITIONS: readonly ToolDefinition[] = Object.freeze([
  {
    name: 'security.kali.recon_surface',
    description:
      'Authorized lab-only attack-surface discovery on 127.0.0.1, localhost, or *.localnet using safe TCP connect / HTTP metadata probes.',
    is_state_changing: true,
    capabilities: ['lab_network_probe'],
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['scope', 'target_host', 'discovering_agent_id'],
      properties: {
        scope: {
          type: 'object',
          description: 'Signed LAB EngagementScopeRef with future expires_at',
        },
        target_host: {
          type: 'string',
          description: 'Permitted lab host only (127.0.0.1, localhost, or *.localnet)',
        },
        ports: {
          type: 'array',
          items: { type: 'integer', minimum: 1, maximum: 65535 },
          description: 'Unique lab TCP ports (max 32)',
        },
        probe_profile: {
          type: 'string',
          enum: ['tcp_connect_ports', 'http_headers_metadata'],
        },
        discovering_agent_id: { type: 'string' },
        timeout_ms: { type: 'integer', minimum: 1000, maximum: 45000 },
      },
    },
  },
  {
    name: 'security.kali.config_audit',
    description:
      'Non-destructive TLS posture, HTTP security header hygiene, and static config tree baseline auditing inside lab boundaries.',
    is_state_changing: false,
    capabilities: ['lab_config_audit'],
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['scope', 'audit_mode', 'discovering_agent_id'],
      properties: {
        scope: { type: 'object' },
        audit_mode: {
          type: 'string',
          enum: ['tls_posture', 'http_security_headers', 'static_config_tree'],
        },
        target_host: { type: 'string' },
        target_port: { type: 'integer', minimum: 1, maximum: 65535 },
        config_rel_path: { type: 'string' },
        discovering_agent_id: { type: 'string' },
        timeout_ms: { type: 'integer', minimum: 1000, maximum: 60000 },
      },
    },
  },
  {
    name: 'security.kali.verify_reproducer',
    description:
      'Deterministic SHA-256 pinned reproducer verification minting canonical Evidence with Tri-Party Separation of Duties enforcement.',
    is_state_changing: true,
    capabilities: ['lab_reproducer_verify'],
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: [
        'scope',
        'finding_id',
        'discovering_agent_id',
        'verifier_agent_id',
        'reproducer_rel_path',
        'expected_reproducer_sha256',
        'reproducer_runtime',
      ],
      properties: {
        scope: { type: 'object' },
        finding_id: { type: 'string' },
        discovering_agent_id: { type: 'string' },
        verifier_agent_id: { type: 'string' },
        authorizing_agent_id: { type: 'string' },
        reproducer_rel_path: { type: 'string' },
        expected_reproducer_sha256: { type: 'string' },
        reproducer_runtime: {
          type: 'string',
          enum: ['node', 'python3', 'http_replay_har'],
        },
        target_host: { type: 'string' },
        target_port: { type: 'integer', minimum: 1, maximum: 65535 },
        expected_invariant: { type: 'string' },
        dry_run: { type: 'boolean' },
        timeout_ms: { type: 'integer', minimum: 1000, maximum: 30000 },
      },
    },
  },
  {
    name: 'security.kali.sbom_cve_check',
    description:
      'Offline airgapped (--net=none) CycloneDX SBOM digest extraction and local vulnerability matching.',
    is_state_changing: false,
    capabilities: ['lab_offline_sbom'],
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['scope', 'manifest_rel_path', 'discovering_agent_id'],
      properties: {
        scope: { type: 'object' },
        manifest_rel_path: { type: 'string' },
        scanner_engine: {
          type: 'string',
          enum: ['trivy_offline', 'syft_grype_offline'],
        },
        severity_filter: {
          type: 'array',
          items: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
        },
        discovering_agent_id: { type: 'string' },
        timeout_ms: { type: 'integer', minimum: 1000, maximum: 90000 },
      },
    },
  },
]);

/**
 * Generates an RFC 8785 + SHA-256 `ToolPinManifest` over the 4 allowlisted Kali MCP tools.
 */
export function createKaliToolPinManifest(
  tools: readonly ToolDefinition[] = KALI_MCP_TOOL_DEFINITIONS,
  registeredAt: string = '2026-01-01T00:00:00.000Z'
): ToolPinManifest {
  const pinned_tools: ToolPinManifest['pinned_tools'] = {};
  for (const tool of tools) {
    pinned_tools[tool.name] = {
      tool_hash: computeToolDefinitionHash(tool),
      canonical_definition: tool,
      registered_at: registeredAt,
      registered_by: 'kali-mcp-assessment',
      is_state_changing: Boolean(tool.is_state_changing),
    };
  }

  return {
    manifest_version: 'kali-mcp-assessment/1.0.0',
    manifest_sha256: sha256(canonicalStringify(pinned_tools)),
    pinned_tools,
  };
}

/**
 * Mints a signed HMAC-SHA256 delegation token bound to a specific caller and Kali MCP tool.
 */
export function mintKaliDelegationToken(params: {
  issuer: string;
  subject: string;
  toolName: KaliCapabilityName;
  hmacSecret: string;
  keyId?: string;
  ttlMs?: number;
  discoveringAgentId?: string;
  findingId?: string;
  isTainted?: boolean;
  taintSource?: string;
}): SignedDelegationToken {
  const claims = createDelegationClaims({
    issuer: params.issuer,
    subject: params.subject,
    audience: params.toolName,
    allowed_scopes: [`tools:call:${params.toolName}`],
    ttlMs: params.ttlMs ?? 60_000,
    discovering_agent_id: params.discoveringAgentId,
    finding_id: params.findingId,
    is_tainted: params.isTainted,
    taint_source: params.taintSource,
  });
  return signDelegationToken(claims, params.hmacSecret, params.keyId ?? 'kali-hmac-key-1');
}

export interface CreateKaliGuardianOptions {
  workspaceRoot?: string;
  hmacSecret?: string;
  requireDelegationToken?: boolean;
  auditLogFilePath?: string;
  errorMode?: 'tool_result' | 'throw';
  manifest?: ToolPinManifest;
}

/**
 * Builds the pre-configured `RuntimeGuardian` enforcing all 4 MCP security phases
 * for `@script-kitty/kali-mcp-assessment`.
 */
export function createKaliGuardian(options: CreateKaliGuardianOptions = {}): RuntimeGuardian {
  const workspaceRoot = path.resolve(options.workspaceRoot ?? process.cwd());
  const manifest = options.manifest ?? createKaliToolPinManifest();

  return new RuntimeGuardian({
    guardian_id: 'guardian-kali-mcp-assessment',
    environment: 'production',
    failClosed: true,
    errorMode: options.errorMode ?? 'tool_result',
    policy: {
      toolPoisoning: {
        enabled: true,
        manifest,
        allowedTools: [...KALI_CAPABILITY_NAMES],
        enforceSchemaHash: true,
        allowUnregistered: false,
        allowShadowTools: false,
      },
      confusedDeputy: {
        enabled: true,
        enforceSeparationOfDuties: true,
        requireDelegationToken: options.requireDelegationToken ?? true,
        hmacSecret: options.hmacSecret,
        keyId: 'kali-hmac-key-1',
        verificationToolNames: ['security.kali.verify_reproducer'],
        stateChangingToolNames: [
          'security.kali.verify_reproducer',
          'security.kali.recon_surface',
        ],
        maxTtlMs: 300_000,
      },
      scopeGuard: {
        enabled: true,
        allowedRoots: [workspaceRoot],
        allowSensitiveFiles: false,
        allowSymlinks: false,
        pathArgumentNames: [
          ...DEFAULT_PATH_ARGUMENT_NAMES,
          'config_rel_path',
          'reproducer_rel_path',
          'manifest_rel_path',
          'config_path',
          'reproducer_path',
          'manifest_path',
        ],
      },
      promptInjection: {
        enabled: true,
        action: 'BLOCK',
        blockExfiltration: true,
        detectCredentials: true,
      },
      auditLogger: {
        enabled: true,
        requireCustodyChain: true,
        logFilePath: options.auditLogFilePath,
      },
    },
  });
}

export interface CreateKaliMcpServerOptions extends KaliRunnerOptions, CreateKaliGuardianOptions {
  serverName?: string;
  serverVersion?: string;
  /**
   * Optional extra unpinned tools injected ONLY in unit tests to verify
   * RuntimeGuardian's `onListTools` tool-poisoning filter drops them.
   */
  advertisedToolsOverride?: ToolDefinition[];
}

export interface KaliMcpServerHandle {
  server: Server;
  guardian: RuntimeGuardian;
  manifest: ToolPinManifest;
  tools: readonly ToolDefinition[];
  listTools: (context?: Partial<InterceptionContext>) => Promise<{ tools: ToolDefinition[] }>;
  callTool: (
    params: {
      name: string;
      arguments?: Record<string, unknown>;
      _meta?: Record<string, unknown>;
    },
    extra?: { sessionId?: string; callerId?: string }
  ) => Promise<Record<string, unknown>>;
}

/**
 * Instantiates the hardened MCP `Server` wrapped by `@script-kitty/runtime-guardian`
 * (`wrapMcpServer`) and backed by the 4 `security.kali.*` verification capabilities.
 */
export function createKaliMcpServer(options: CreateKaliMcpServerOptions = {}): KaliMcpServerHandle {
  const workspaceRoot = path.resolve(options.workspaceRoot ?? process.cwd());
  const manifest = options.manifest ?? createKaliToolPinManifest();
  const guardian = createKaliGuardian({
    workspaceRoot,
    hmacSecret: options.hmacSecret,
    requireDelegationToken: options.requireDelegationToken,
    auditLogFilePath: options.auditLogFilePath,
    errorMode: options.errorMode,
    manifest,
  });

  const server = new Server(
    {
      name: options.serverName ?? 'script-kitty-kali-mcp-assessment',
      version: options.serverVersion ?? '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Wrap MCP Server with RuntimeGuardian BEFORE registering handlers so `setRequestHandler`
  // wraps `tools/list` and `tools/call` across both stdio/InMemoryTransport and direct dispatch.
  wrapMcpServer(server, guardian);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: (options.advertisedToolsOverride ?? [...KALI_MCP_TOOL_DEFINITIONS]) as unknown[],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const params = request.params as {
      name: string;
      arguments?: Record<string, unknown>;
      _meta?: Record<string, unknown>;
    };
    const toolName = String(params?.name ?? '').trim();
    const args = (params?.arguments ?? {}) as Record<string, unknown>;
    const meta = (params?._meta ?? {}) as Record<string, unknown>;

    const failResponse = (code: string, message: string) => {
      const safeMsg = sanitizeOutput(message);
      const body = {
        ok: false,
        mode: KALI_MODE,
        capability: toolName,
        error_code: code,
        error_message: safeMsg,
      };
      return {
        isError: true,
        content: [{ type: 'text' as const, text: `[KALI_SECURITY_BLOCK] ${code}: ${safeMsg}` }],
        structuredContent: body,
      };
    };

    if (!KALI_CAPABILITY_NAMES.includes(toolName as KaliCapabilityName)) {
      return failResponse(
        'KALI_DISALLOWED_CAPABILITY',
        `Capability '${toolName}' is not in the allowlisted security.kali.* surface`
      );
    }

    const safety = scanKaliPayloadSafety(args);
    if (!safety.safe) {
      return failResponse(
        safety.ruleId ?? 'KALI_UNSAFE_PAYLOAD',
        safety.reason ?? 'Unsafe argument payload rejected'
      );
    }

    // Defense-in-depth SoD check cross-validating `_meta` identity + payload identity.
    if (toolName === 'security.kali.verify_reproducer') {
      const callerMeta =
        typeof meta.caller_agent_id === 'string' ? meta.caller_agent_id.trim() : undefined;
      const payloadVerifier =
        typeof args.verifier_agent_id === 'string' ? args.verifier_agent_id.trim() : undefined;
      const payloadDiscoverer =
        typeof args.discovering_agent_id === 'string'
          ? args.discovering_agent_id.trim()
          : undefined;
      const scopeAuth =
        typeof (args.scope as { authorized_by?: unknown } | undefined)?.authorized_by === 'string'
          ? String((args.scope as { authorized_by: string }).authorized_by).trim()
          : undefined;
      const payloadAuth =
        typeof args.authorizing_agent_id === 'string'
          ? args.authorizing_agent_id.trim()
          : typeof meta.authorizing_agent_id === 'string'
            ? meta.authorizing_agent_id.trim()
            : scopeAuth;

      if (callerMeta && payloadVerifier && callerMeta.toLowerCase() !== payloadVerifier.toLowerCase()) {
        return failResponse(
          'E_SOD_CALLER_MISMATCH',
          `Authenticated caller '${callerMeta}' does not match verifier_agent_id '${payloadVerifier}'`
        );
      }

      const sodEval = validateSeparationOfDuties(
        payloadDiscoverer,
        payloadVerifier ?? callerMeta,
        payloadAuth,
        { hasIndependentEvidence: true, evidenceVerifierId: payloadVerifier ?? callerMeta }
      );
      if (!sodEval.is_valid) {
        return failResponse(
          sodEval.violation_code ?? 'E_SOD_SELF_CERTIFICATION',
          sodEval.violation_details ?? 'Tri-Party Separation of Duties violation'
        );
      }
    }

    try {
      const executionResult = await executeKaliCapability(
        toolName as KaliCapabilityName,
        args,
        {
          ...options,
          workspaceRoot,
        }
      );

      return {
        isError: !executionResult.ok,
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(executionResult),
          },
        ],
        structuredContent: executionResult as unknown as Record<string, unknown>,
      };
    } catch (err: unknown) {
      if (err instanceof KaliSecurityError) {
        return failResponse(err.code, err.message);
      }
      return failResponse(
        'KALI_EXECUTION_ERROR',
        err instanceof Error ? err.message : String(err)
      );
    }
  });

  const requestHandlers = (server as unknown as {
    _requestHandlers?: Map<string, (req: unknown, extra?: unknown) => Promise<unknown>>;
  })._requestHandlers;

  return {
    server,
    guardian,
    manifest,
    tools: KALI_MCP_TOOL_DEFINITIONS,
    async listTools(context?: Partial<InterceptionContext>) {
      const handler = requestHandlers?.get('tools/list');
      if (!handler) {
        throw new Error('tools/list handler not registered');
      }
      return (await handler(
        { method: 'tools/list', params: {} },
        {
          sessionId: context?.session_id,
          callerId: context?.caller_agent_id,
        }
      )) as { tools: ToolDefinition[] };
    },
    async callTool(params, extra) {
      const handler = requestHandlers?.get('tools/call');
      if (!handler) {
        throw new Error('tools/call handler not registered');
      }
      return (await handler(
        {
          method: 'tools/call',
          params,
        },
        extra ?? {}
      )) as Record<string, unknown>;
    },
  };
}
