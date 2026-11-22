/**
 * @file packages/security-actions/src/mcp-http.ts
 * @description Fail-closed MCP Streamable HTTP Server (`127.0.0.1` loopback binding)
 * routing `initialize`, `tools/list`, and `tools/call` strictly through `engine.invoke(...)`.
 */

import * as crypto from 'node:crypto';
import * as http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  isInitializeRequest,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import {
  ActionEngineError,
  AuthPrincipalSchema,
  type AuthPrincipal,
  type SecurityActionEngine,
} from './engine.js';

export interface McpToolDefinition {
  name: string;
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

export interface McpHttpServerOptions {
  host?: string;
  port?: number;
  path?: string;
  allowNonLoopback?: boolean;
  allowedHosts?: string[];
  allowedOrigins?: string[];
  requireOriginHeader?: boolean;
  maxRequestBodyBytes?: number;
  rateLimit?: RateLimitConfig;
  authRateLimit?: RateLimitConfig;
  maxRateLimitBuckets?: number;
  sessionTtlMs?: number;
  cleanupIntervalMs?: number;
  tokens?: Record<string, AuthPrincipal>;
  authenticateToken?: (
    token: string,
    req: http.IncomingMessage
  ) => Promise<AuthPrincipal | null> | AuthPrincipal | null;
  allowStatelessRequests?: boolean;
  maxSessions?: number;
  maxConcurrentRequests?: number;
}

export interface McpHttpServerStats {
  activeSessions: number;
  rateLimitBuckets: number;
  authRateLimitBuckets: number;
  inFlightRequests: number;
}

export interface McpHttpServerHandle {
  server: http.Server;
  host: string;
  port: number;
  path: string;
  url: string;
  getStats: () => McpHttpServerStats;
  close: () => Promise<void>;
}

function sha256Buffer(value: string): Buffer {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

function timingSafeStringMatch(a: string, b: string): boolean {
  const bufA = sha256Buffer(a);
  const bufB = sha256Buffer(b);
  return crypto.timingSafeEqual(bufA, bufB);
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return (
    normalized === '127.0.0.1' ||
    normalized === 'localhost' ||
    normalized === '::1' ||
    normalized === '[::1]'
  );
}

/**
 * Minimal deterministic Zod-to-JSON-Schema Draft-07 converter for registered capabilities.
 */
export function zodToJsonSchemaSimple(schema: z.ZodTypeAny): Record<string, unknown> {
  const def = schema._def as Record<string, any>;
  const typeName = def.typeName as string | undefined;

  if (typeName === 'ZodOptional' || typeName === 'ZodDefault') {
    return zodToJsonSchemaSimple(def.innerType);
  }
  if (typeName === 'ZodNullable') {
    const inner = zodToJsonSchemaSimple(def.innerType);
    return { anyOf: [inner, { type: 'null' }] };
  }
  if (typeName === 'ZodEffects') {
    return zodToJsonSchemaSimple(def.schema);
  }
  if (typeName === 'ZodUnion') {
    const options = Array.isArray(def.options)
      ? (def.options as z.ZodTypeAny[]).map((opt) => zodToJsonSchemaSimple(opt))
      : [{ type: 'string' }, { type: 'object' }];
    return { anyOf: options };
  }
  if (typeName === 'ZodString') {
    const out: Record<string, unknown> = { type: 'string' };
    if (Array.isArray(def.checks)) {
      for (const check of def.checks) {
        if (check.kind === 'min') out.minLength = check.value;
        if (check.kind === 'max') out.maxLength = check.value;
        if (check.kind === 'regex' && check.regex instanceof RegExp) {
          out.pattern = check.regex.source;
        }
      }
    }
    return out;
  }
  if (typeName === 'ZodNumber') {
    const out: Record<string, unknown> = { type: 'number' };
    if (Array.isArray(def.checks)) {
      for (const check of def.checks) {
        if (check.kind === 'int') out.type = 'integer';
        if (check.kind === 'min') out.minimum = check.value;
        if (check.kind === 'max') out.maximum = check.value;
      }
    }
    return out;
  }
  if (typeName === 'ZodBoolean') {
    return { type: 'boolean' };
  }
  if (typeName === 'ZodLiteral') {
    return { const: def.value };
  }
  if (typeName === 'ZodEnum') {
    return { type: 'string', enum: def.values };
  }
  if (typeName === 'ZodArray') {
    return {
      type: 'array',
      items: zodToJsonSchemaSimple(def.type),
    };
  }
  if (typeName === 'ZodRecord') {
    return {
      type: 'object',
      additionalProperties: def.valueType
        ? zodToJsonSchemaSimple(def.valueType)
        : true,
    };
  }
  if (typeName === 'ZodObject') {
    const shape =
      typeof def.shape === 'function'
        ? (def.shape() as Record<string, z.ZodTypeAny>)
        : (def.shape as Record<string, z.ZodTypeAny>);
    const properties: Record<string, unknown> = {};
    const required: string[] = [];

    for (const [key, propSchema] of Object.entries(shape)) {
      properties[key] = zodToJsonSchemaSimple(propSchema);
      if (!propSchema.isOptional()) {
        required.push(key);
      }
    }

    const result: Record<string, unknown> = {
      type: 'object',
      properties,
      additionalProperties: def.unknownKeys === 'strict' ? false : true,
    };
    if (required.length > 0) {
      result.required = required;
    }
    return result;
  }

  return { type: 'object' };
}

function serializeToolError(
  error: unknown,
  correlationId?: string
): { isError: true; content: Array<{ type: 'text'; text: string }> } {
  if (error instanceof ActionEngineError) {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            code: error.code,
            message: error.publicMessage,
            correlationId: error.correlationId ?? correlationId,
          }),
        },
      ],
    };
  }
  return {
    isError: true,
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          code: 'EXECUTION_FAILED',
          message: 'Capability execution failed',
          correlationId,
        }),
      },
    ],
  };
}

function sendJsonRpcHttpError(
  res: http.ServerResponse,
  statusCode: number,
  rpcCode: number,
  message: string,
  extraHeaders: Record<string, string> = {}
): void {
  if (res.headersSent) return;
  const body = JSON.stringify({
    jsonrpc: '2.0',
    error: {
      code: rpcCode,
      message,
    },
    id: null,
  });
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

export class SlidingWindowRateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly maxBuckets: number;
  private readonly buckets = new Map<string, number[]>();

  constructor(maxRequests: number, windowMs: number, maxBuckets = 10_000) {
    this.maxRequests =
      Number.isFinite(maxRequests) && maxRequests > 0
        ? Math.floor(maxRequests)
        : 1;
    this.windowMs =
      Number.isFinite(windowMs) && windowMs > 0 ? Math.floor(windowMs) : 60_000;
    this.maxBuckets =
      Number.isInteger(maxBuckets) && maxBuckets > 0 ? maxBuckets : 10_000;
  }

  get bucketCount(): number {
    return this.buckets.size;
  }

  peek(
    key: string,
    now = Date.now()
  ): { allowed: boolean; retryAfterSec: number } {
    const cutoff = now - this.windowMs;
    const prev = this.buckets.get(key);
    if (!prev || prev.length === 0) {
      if (prev) this.buckets.delete(key);
      return { allowed: true, retryAfterSec: 0 };
    }
    const active = prev.filter((ts) => ts > cutoff);
    if (active.length === 0) {
      this.buckets.delete(key);
      return { allowed: true, retryAfterSec: 0 };
    }
    if (active.length >= this.maxRequests) {
      this.buckets.set(key, active);
      const oldest = active[0] ?? now;
      const retryAfterMs = Math.max(1_000, oldest + this.windowMs - now);
      return {
        allowed: false,
        retryAfterSec: Math.ceil(retryAfterMs / 1_000),
      };
    }
    if (active.length !== prev.length) {
      this.buckets.set(key, active);
    }
    return { allowed: true, retryAfterSec: 0 };
  }

  isAllowed(key: string, now = Date.now()): boolean {
    return this.peek(key, now).allowed;
  }

  prune(now = Date.now()): number {
    const cutoff = now - this.windowMs;
    let removed = 0;
    for (const [key, timestamps] of this.buckets.entries()) {
      const active = timestamps.filter((ts) => ts > cutoff);
      if (active.length === 0) {
        this.buckets.delete(key);
        removed += 1;
      } else if (active.length !== timestamps.length) {
        this.buckets.set(key, active);
      }
    }
    return removed;
  }

  checkAndConsume(
    key: string,
    now = Date.now()
  ): { allowed: boolean; retryAfterSec: number } {
    const cutoff = now - this.windowMs;
    const prev = this.buckets.get(key) ?? [];
    const active = prev.filter((ts) => ts > cutoff);

    if (active.length >= this.maxRequests) {
      this.buckets.delete(key);
      this.buckets.set(key, active);
      const oldest = active[0] ?? now;
      const retryAfterMs = Math.max(1_000, oldest + this.windowMs - now);
      return {
        allowed: false,
        retryAfterSec: Math.ceil(retryAfterMs / 1_000),
      };
    }

    if (!this.buckets.has(key) && this.buckets.size >= this.maxBuckets) {
      this.prune(now);
      while (this.buckets.size >= this.maxBuckets) {
        const oldestKey = this.buckets.keys().next().value;
        if (oldestKey === undefined) break;
        this.buckets.delete(oldestKey);
      }
    }

    active.push(now);
    this.buckets.delete(key);
    this.buckets.set(key, active);
    return { allowed: true, retryAfterSec: 0 };
  }
}

async function readBoundedBody(
  req: http.IncomingMessage,
  maxBytes: number
): Promise<Buffer> {
  const contentLengthHeader = req.headers['content-length'];
  if (contentLengthHeader !== undefined) {
    const declared = Number(contentLengthHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new HttpPayloadTooLargeError(
        `Content-Length ${declared} exceeds maxRequestBodyBytes ${maxBytes}`
      );
    }
  }

  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;

    const cleanup = () => {
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
    };

    const onData = (chunk: Buffer | string) => {
      if (settled) return;
      const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
      totalBytes += buf.length;
      if (totalBytes > maxBytes) {
        settled = true;
        cleanup();
        req.destroy();
        reject(
          new HttpPayloadTooLargeError(
            `Request body exceeded limit of ${maxBytes} bytes`
          )
        );
        return;
      }
      chunks.push(buf);
    };

    const onEnd = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks));
    };

    const onError = (err: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(err);
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
  });
}

class HttpPayloadTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HttpPayloadTooLargeError';
  }
}

interface ActiveMcpSession {
  sessionId: string;
  principalId: string;
  tenantId: string;
  server: Server;
  transport: StreamableHTTPServerTransport;
  createdAtMs: number;
  lastSeenAtMs: number;
}

export async function startMcpHttpServer(
  engine: SecurityActionEngine,
  options: McpHttpServerOptions = {}
): Promise<McpHttpServerHandle> {
  const host = options.host ?? '127.0.0.1';
  if (!options.allowNonLoopback && !isLoopbackHost(host)) {
    throw new Error(
      `MCP Streamable HTTP server must bind to a loopback host (127.0.0.1/localhost/::1); received '${host}'`
    );
  }

  const requestedPort = options.port ?? 0;
  const endpointPath = options.path ?? '/mcp';
  const maxRequestBodyBytes = options.maxRequestBodyBytes ?? 1_048_576;
  const maxSessions = options.maxSessions ?? 128;
  const maxConcurrentRequests =
    options.maxConcurrentRequests !== undefined &&
    Number.isInteger(options.maxConcurrentRequests) &&
    options.maxConcurrentRequests > 0
      ? options.maxConcurrentRequests
      : 64;
  let inFlightRequests = 0;
  const sessionTtlMs =
    options.sessionTtlMs !== undefined && options.sessionTtlMs > 0
      ? options.sessionTtlMs
      : 900_000;
  const maxRateLimitBuckets = options.maxRateLimitBuckets ?? 10_000;
  const requireOriginHeader = options.requireOriginHeader ?? false;
  const allowStatelessRequests = options.allowStatelessRequests ?? true;
  const rateLimitWindowMs = options.rateLimit?.windowMs ?? 60_000;
  const authRateLimitWindowMs = options.authRateLimit?.windowMs ?? 60_000;
  const rateLimiter = new SlidingWindowRateLimiter(
    options.rateLimit?.maxRequests ?? 120,
    rateLimitWindowMs,
    maxRateLimitBuckets
  );
  const authRateLimiter = new SlidingWindowRateLimiter(
    options.authRateLimit?.maxRequests ?? 20,
    authRateLimitWindowMs,
    maxRateLimitBuckets
  );
  const cleanupIntervalMs =
    options.cleanupIntervalMs !== undefined && options.cleanupIntervalMs > 0
      ? options.cleanupIntervalMs
      : Math.min(
          Math.max(
            50,
            Math.floor(
              Math.min(sessionTtlMs, rateLimitWindowMs, authRateLimitWindowMs) / 2
            )
          ),
          60_000
        );

  // Pre-build tool catalog and dot/underscore name resolution from the ActionEngine
  const capabilityLookup = new Map<string, string>();
  const catalogTools: McpToolDefinition[] = engine.list().map((cap) => {
    capabilityLookup.set(cap.id, cap.id);
    capabilityLookup.set(cap.id.replace(/[^a-zA-Z0-9_-]/g, '_'), cap.id);
    return {
      name: cap.id,
      title: cap.title,
      description: cap.description,
      inputSchema: zodToJsonSchemaSimple(cap.inputSchema),
      ...(cap.annotations
        ? {
            annotations: {
              ...(cap.annotations.readOnly !== undefined
                ? { readOnlyHint: cap.annotations.readOnly }
                : {}),
              ...(cap.annotations.destructive !== undefined
                ? { destructiveHint: cap.annotations.destructive }
                : {}),
              ...(cap.annotations.idempotent !== undefined
                ? { idempotentHint: cap.annotations.idempotent }
                : {}),
              ...(cap.annotations.openWorld !== undefined
                ? { openWorldHint: cap.annotations.openWorld }
                : {}),
            },
          }
        : {}),
    };
  });

  const authenticate = async (
    req: http.IncomingMessage
  ): Promise<AuthPrincipal | null> => {
    const authHeader = req.headers.authorization;
    if (typeof authHeader !== 'string') {
      return null;
    }
    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match) {
      return null;
    }
    const presentedToken = match[1].trim();
    if (!presentedToken) {
      return null;
    }

    let principal: AuthPrincipal | null = null;
    if (options.authenticateToken) {
      principal = await options.authenticateToken(presentedToken, req);
    } else if (options.tokens) {
      let matchedPrincipal: AuthPrincipal | null = null;
      for (const [configuredToken, candidatePrincipal] of Object.entries(
        options.tokens
      )) {
        const isMatch = timingSafeStringMatch(presentedToken, configuredToken);
        if (isMatch && matchedPrincipal === null) {
          matchedPrincipal = candidatePrincipal;
        }
      }
      principal = matchedPrincipal;
    }

    if (!principal) {
      return null;
    }
    const parsed = AuthPrincipalSchema.safeParse(principal);
    return parsed.success ? parsed.data : null;
  };

  const createBoundServer = (principal: AuthPrincipal): Server => {
    const mcpServer = new Server(
      { name: engine.name, version: engine.version },
      { capabilities: { tools: {} } }
    );

    mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: catalogTools,
    }));

    mcpServer.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const capabilityId = capabilityLookup.get(request.params.name);
      if (!capabilityId) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Unknown tool '${request.params.name}'`
        );
      }

      const authExtra = (
        extra as {
          authInfo?: { extra?: { principal?: AuthPrincipal; correlationId?: string } };
          signal?: AbortSignal;
        }
      )?.authInfo?.extra;
      const effectivePrincipal = authExtra?.principal ?? principal;
      const correlationId = authExtra?.correlationId ?? crypto.randomUUID();

      try {
        const result = await engine.invoke<Record<string, unknown>>(
          capabilityId,
          request.params.arguments ?? {},
          {
            principal: effectivePrincipal,
            correlationId,
            source: 'mcp-http',
            signal: extra.signal,
          }
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result),
            },
          ],
          structuredContent: result,
        };
      } catch (err) {
        return serializeToolError(err, correlationId);
      }
    });

    return mcpServer;
  };

  const sessions = new Map<string, ActiveMcpSession>();

  const closeSessionResources = async (session: ActiveMcpSession): Promise<void> => {
    await session.transport.close().catch(() => {});
    await session.server.close().catch(() => {});
  };

  const reapExpiredSessions = async (now = Date.now()): Promise<number> => {
    rateLimiter.prune(now);
    authRateLimiter.prune(now);
    const expired: ActiveMcpSession[] = [];
    for (const [id, session] of sessions.entries()) {
      if (now - session.lastSeenAtMs >= sessionTtlMs) {
        sessions.delete(id);
        expired.push(session);
      }
    }
    for (const session of expired) {
      await closeSessionResources(session);
    }
    return expired.length;
  };

  const reaperTimer = setInterval(() => {
    void reapExpiredSessions();
  }, cleanupIntervalMs);
  reaperTimer.unref();

  let actualPort = requestedPort;
  let allowedHostsSet = new Set<string>(options.allowedHosts ?? []);
  let allowedOriginsSet = new Set<string>(options.allowedOrigins ?? []);

  const refreshAllowlists = (boundPort: number) => {
    if (!options.allowedHosts || options.allowedHosts.length === 0) {
      allowedHostsSet = new Set([
        `127.0.0.1:${boundPort}`,
        `localhost:${boundPort}`,
        `[::1]:${boundPort}`,
        '127.0.0.1',
        'localhost',
        '[::1]',
      ]);
    } else {
      allowedHostsSet = new Set(options.allowedHosts);
    }

    if (!options.allowedOrigins || options.allowedOrigins.length === 0) {
      allowedOriginsSet = new Set([
        `http://127.0.0.1:${boundPort}`,
        `http://localhost:${boundPort}`,
        `http://[::1]:${boundPort}`,
        'http://127.0.0.1:5173',
        'http://localhost:5173',
        'http://127.0.0.1',
        'http://localhost',
        'https://127.0.0.1',
        'https://localhost',
      ]);
    } else {
      allowedOriginsSet = new Set(
        options.allowedOrigins.map((origin) => origin.trim().replace(/\/+$/, ''))
      );
    }
  };

  const applyCorsHeaders = (
    res: http.ServerResponse,
    validatedOrigin: string | undefined
  ): void => {
    if (!validatedOrigin) {
      return;
    }
    res.setHeader('Access-Control-Allow-Origin', validatedOrigin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Mcp-Session-Id, Accept, X-Correlation-Id'
    );
    res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
  };

  const httpServer = http.createServer(async (req, res) => {
    if (inFlightRequests >= maxConcurrentRequests) {
      sendJsonRpcHttpError(
        res,
        503,
        -32000,
        'Server busy: maximum concurrent requests reached',
        { 'Retry-After': '1' }
      );
      return;
    }
    inFlightRequests += 1;
    try {
      const rawUrl = req.url ?? '/';
      const pathname = new URL(rawUrl, 'http://127.0.0.1').pathname;

      // 1. Validate Host header (DNS rebinding guard)
      const hostHeader = req.headers.host;
      if (
        typeof hostHeader !== 'string' ||
        !allowedHostsSet.has(hostHeader.toLowerCase())
      ) {
        sendJsonRpcHttpError(res, 403, -32000, 'Forbidden: invalid Host header');
        return;
      }

      // 2. Validate Origin header against fail-closed loopback allowlist
      const originHeader = req.headers.origin;
      let validatedOrigin: string | undefined;
      if (originHeader !== undefined) {
        const normalizedOrigin = Array.isArray(originHeader)
          ? originHeader[0]
          : originHeader;
        if (!normalizedOrigin || !allowedOriginsSet.has(normalizedOrigin)) {
          sendJsonRpcHttpError(
            res,
            403,
            -32000,
            'Forbidden: Origin header not in allowlist'
          );
          return;
        }
        validatedOrigin = normalizedOrigin;
      } else if (requireOriginHeader) {
        sendJsonRpcHttpError(
          res,
          403,
          -32000,
          'Forbidden: Origin header is required'
        );
        return;
      }

      // 3. Enforce single MCP endpoint path
      if (pathname !== endpointPath) {
        applyCorsHeaders(res, validatedOrigin);
        sendJsonRpcHttpError(res, 404, -32000, 'Not Found');
        return;
      }

      // 3.5. Fail-closed CORS preflight (OPTIONS) for allowlisted loopback origins
      // Preflight requests do not carry Bearer tokens per Fetch/CORS spec;
      // Host, Origin allowlist, and endpoint path are already enforced above.
      if (req.method === 'OPTIONS') {
        if (!validatedOrigin) {
          sendJsonRpcHttpError(
            res,
            403,
            -32000,
            'Forbidden: Origin header is required for CORS preflight'
          );
          return;
        }
        applyCorsHeaders(res, validatedOrigin);
        res.writeHead(204, {
          'Access-Control-Max-Age': '600',
          'Cache-Control': 'no-store',
        });
        res.end();
        return;
      }

      // Attach fail-closed CORS headers ONLY for allowlisted Origin on actual requests
      applyCorsHeaders(res, validatedOrigin);

      // 4. Pre-auth per-IP sliding-window guard (fail-closed 429 before invoking token checks)
      const authIpKey = req.socket.remoteAddress ?? 'local';
      const preAuthCheck = authRateLimiter.peek(authIpKey);
      if (!preAuthCheck.allowed) {
        sendJsonRpcHttpError(
          res,
          429,
          -32002,
          'Authentication rate limit exceeded',
          {
            'Retry-After': String(preAuthCheck.retryAfterSec),
          }
        );
        return;
      }

      // 5. Authenticate Bearer token strictly (fail-closed 401 before touching sessions or engine)
      const principal = await authenticate(req);
      if (!principal) {
        const failedAuthCheck = authRateLimiter.checkAndConsume(authIpKey);
        if (!failedAuthCheck.allowed) {
          sendJsonRpcHttpError(
            res,
            429,
            -32002,
            'Authentication rate limit exceeded',
            {
              'Retry-After': String(failedAuthCheck.retryAfterSec),
            }
          );
          return;
        }
        sendJsonRpcHttpError(res, 401, -32001, 'Unauthorized', {
          'WWW-Authenticate': 'Bearer',
        });
        return;
      }

      // 6. Sliding-window rate limiting keyed by principal + remote IP
      const rateKey = `${principal.principalId}:${authIpKey}`;
      const rateCheck = rateLimiter.checkAndConsume(rateKey);
      if (!rateCheck.allowed) {
        sendJsonRpcHttpError(res, 429, -32002, 'Rate limit exceeded', {
          'Retry-After': String(rateCheck.retryAfterSec),
        });
        return;
      }

      const correlationId =
        typeof req.headers['x-correlation-id'] === 'string' &&
        req.headers['x-correlation-id'].trim().length > 0
          ? req.headers['x-correlation-id'].trim()
          : crypto.randomUUID();

      const authReq = req as http.IncomingMessage & {
        auth?: {
          token: string;
          clientId: string;
          scopes: string[];
          extra?: Record<string, unknown>;
        };
      };
      authReq.auth = {
        token: '[REDACTED]',
        clientId: principal.principalId,
        scopes: principal.scopes,
        extra: {
          principal,
          correlationId,
        },
      };

      const sessionHeader = req.headers['mcp-session-id'];
      const sessionId =
        typeof sessionHeader === 'string' && sessionHeader.trim().length > 0
          ? sessionHeader.trim()
          : undefined;

      if (req.method === 'GET' || req.method === 'DELETE') {
        if (!sessionId) {
          sendJsonRpcHttpError(
            res,
            400,
            -32000,
            'Bad Request: Mcp-Session-Id header is required'
          );
          return;
        }
        const existingSession = sessions.get(sessionId);
        const nowMs = Date.now();
        if (!existingSession || nowMs - existingSession.lastSeenAtMs >= sessionTtlMs) {
          if (existingSession) {
            sessions.delete(sessionId);
            await closeSessionResources(existingSession);
          }
          sendJsonRpcHttpError(res, 404, -32000, 'Session not found');
          return;
        }
        existingSession.lastSeenAtMs = nowMs;
        if (
          existingSession.principalId !== principal.principalId ||
          existingSession.tenantId !== principal.tenantId
        ) {
          sendJsonRpcHttpError(
            res,
            403,
            -32000,
            'Forbidden: session belongs to a different authenticated principal'
          );
          return;
        }
        await existingSession.transport.handleRequest(authReq, res);
        return;
      }

      if (req.method !== 'POST') {
        sendJsonRpcHttpError(res, 405, -32000, 'Method Not Allowed', {
          Allow: 'POST, GET, DELETE, OPTIONS',
        });
        return;
      }

      // Enforce request body size limit before JSON parsing
      let bodyBuf: Buffer;
      try {
        bodyBuf = await readBoundedBody(req, maxRequestBodyBytes);
      } catch (err) {
        if (err instanceof HttpPayloadTooLargeError) {
          sendJsonRpcHttpError(res, 413, -32000, err.message);
          return;
        }
        throw err;
      }

      let parsedBody: unknown;
      try {
        parsedBody = JSON.parse(bodyBuf.toString('utf8'));
      } catch {
        sendJsonRpcHttpError(res, 400, -32700, 'Parse error: invalid JSON');
        return;
      }

      // Stateful session routing
      if (sessionId) {
        const existingSession = sessions.get(sessionId);
        const nowMs = Date.now();
        if (!existingSession || nowMs - existingSession.lastSeenAtMs >= sessionTtlMs) {
          if (existingSession) {
            sessions.delete(sessionId);
            await closeSessionResources(existingSession);
          }
          sendJsonRpcHttpError(res, 404, -32000, 'Session not found');
          return;
        }
        existingSession.lastSeenAtMs = nowMs;
        if (
          existingSession.principalId !== principal.principalId ||
          existingSession.tenantId !== principal.tenantId
        ) {
          sendJsonRpcHttpError(
            res,
            403,
            -32000,
            'Forbidden: session belongs to a different authenticated principal'
          );
          return;
        }
        await existingSession.transport.handleRequest(
          authReq,
          res,
          parsedBody
        );
        return;
      }

      if (isInitializeRequest(parsedBody)) {
        await reapExpiredSessions();
        if (sessions.size >= maxSessions) {
          sendJsonRpcHttpError(
            res,
            503,
            -32000,
            'Server at maximum concurrent MCP session capacity'
          );
          return;
        }

        const newSessionId = crypto.randomUUID();
        const server = createBoundServer(principal);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => newSessionId,
          enableJsonResponse: true,
          onsessionclosed: async (closedId) => {
            const s = sessions.get(closedId);
            sessions.delete(closedId);
            await s?.server.close().catch(() => {});
          },
        });

        const initNowMs = Date.now();
        sessions.set(newSessionId, {
          sessionId: newSessionId,
          principalId: principal.principalId,
          tenantId: principal.tenantId,
          server,
          transport,
          createdAtMs: initNowMs,
          lastSeenAtMs: initNowMs,
        });

        await server.connect(transport);
        await transport.handleRequest(authReq, res, parsedBody);
        return;
      }

      if (allowStatelessRequests) {
        const server = createBoundServer(principal);
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        await server.connect(transport);
        try {
          await transport.handleRequest(authReq, res, parsedBody);
        } finally {
          await transport.close().catch(() => {});
          await server.close().catch(() => {});
        }
        return;
      }

      sendJsonRpcHttpError(
        res,
        400,
        -32000,
        'Bad Request: Mcp-Session-Id required for non-initialize requests'
      );
    } catch {
      sendJsonRpcHttpError(res, 500, -32603, 'Internal server error');
    } finally {
      inFlightRequests -= 1;
    }
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => {
      httpServer.removeListener('listening', onListening);
      reject(err);
    };
    const onListening = () => {
      httpServer.removeListener('error', onError);
      const addr = httpServer.address();
      if (addr && typeof addr !== 'string') {
        actualPort = addr.port;
      }
      refreshAllowlists(actualPort);
      resolve();
    };
    httpServer.headersTimeout = 10_000;
    httpServer.requestTimeout = 30_000;
    httpServer.once('error', onError);
    httpServer.once('listening', onListening);
    httpServer.listen(requestedPort, host);
  });

  const urlHost = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const baseUrl = `http://${urlHost}:${actualPort}${endpointPath}`;

  return {
    server: httpServer,
    host,
    port: actualPort,
    path: endpointPath,
    url: baseUrl,
    getStats: () => ({
      activeSessions: sessions.size,
      rateLimitBuckets: rateLimiter.bucketCount,
      authRateLimitBuckets: authRateLimiter.bucketCount,
      inFlightRequests,
    }),
    close: async () => {
      clearInterval(reaperTimer);
      for (const s of sessions.values()) {
        await s.transport.close().catch(() => {});
        await s.server.close().catch(() => {});
      }
      sessions.clear();
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
        if (typeof httpServer.closeAllConnections === 'function') {
          httpServer.closeAllConnections();
        }
      });
    },
  };
}
