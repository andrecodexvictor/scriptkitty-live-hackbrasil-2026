/**
 * @file apps/ui/src/mcp-browser-client.ts
 * @description Browser-pure MCP Streamable HTTP JSON-RPC 2.0 client compatible with
 * `@script-kitty/security-actions` (`startMcpHttpServer`). Enforces loopback SSRF
 * restrictions and Bearer token redaction.
 */

export type McpClientErrorCode =
  | 'SSRF_BLOCKED'
  | 'INVALID_URL'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'RATE_LIMITED'
  | 'TIMEOUT'
  | 'NETWORK_ERROR'
  | 'PROTOCOL_ERROR'
  | 'TOOL_ERROR';

export class McpClientError extends Error {
  readonly code: McpClientErrorCode;
  readonly httpStatus?: number;
  readonly toolErrorCode?: string;

  constructor(
    code: McpClientErrorCode,
    message: string,
    options: { httpStatus?: number; toolErrorCode?: string } = {}
  ) {
    super(message);
    this.name = 'McpClientError';
    this.code = code;
    this.httpStatus = options.httpStatus;
    this.toolErrorCode = options.toolErrorCode;
  }
}

export interface McpBrowserClientOptions {
  url: string;
  token?: string;
  origin?: string;
  correlationId?: string;
  timeoutMs?: number;
  fetchImpl?: typeof globalThis.fetch;
}

export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpToolCallResult<T = Record<string, unknown>> {
  isError: boolean;
  parsed: T;
  rawText: string;
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

/**
 * Validates that an MCP endpoint URL targets strictly local loopback interfaces
 * with no embedded credentials (fail-closed SSRF guard).
 */
export function validateLoopbackMcpUrl(rawUrl: string): URL {
  const trimmed = (rawUrl ?? '').trim();
  if (!trimmed) {
    throw new McpClientError('INVALID_URL', 'MCP endpoint URL is required');
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new McpClientError('INVALID_URL', 'Malformed MCP endpoint URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new McpClientError(
      'SSRF_BLOCKED',
      `Disallowed MCP URL protocol '${parsed.protocol}' (only http/https loopback permitted)`
    );
  }

  if (parsed.username || parsed.password) {
    throw new McpClientError(
      'SSRF_BLOCKED',
      'Embedded credentials in MCP URL are forbidden'
    );
  }

  const host = parsed.hostname.toLowerCase();
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new McpClientError(
      'SSRF_BLOCKED',
      `SSRF fail-closed: MCP endpoint host '${host}' is not loopback (127.0.0.1 / localhost / ::1)`
    );
  }

  return parsed;
}

/**
 * Scrubs any Bearer token or credential substrings from diagnostic/error messages.
 */
export function redactTokenFromMessage(message: string, token?: string): string {
  let out = message.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{4,}/gi, 'Bearer [REDACTED]');
  const cleanToken = (token ?? '').trim();
  if (cleanToken.length >= 4) {
    out = out.split(cleanToken).join('[REDACTED]');
  }
  return out;
}

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: string | number | null;
  result?: Record<string, unknown>;
  error?: {
    code?: number;
    message?: string;
    data?: unknown;
  };
}

function parseSseOrJson(contentType: string, rawBody: string): JsonRpcResponse {
  const ct = contentType.toLowerCase();
  if (ct.includes('text/event-stream')) {
    const dataLines: string[] = [];
    let currentData: string[] = [];
    for (const line of rawBody.split(/\r?\n/)) {
      if (line.startsWith('data:')) {
        currentData.push(line.slice(5).trimStart());
      } else if (line.trim() === '' && currentData.length > 0) {
        dataLines.push(currentData.join('\n'));
        currentData = [];
      }
    }
    if (currentData.length > 0) {
      dataLines.push(currentData.join('\n'));
    }
    for (let i = dataLines.length - 1; i >= 0; i--) {
      try {
        return JSON.parse(dataLines[i]) as JsonRpcResponse;
      } catch {
        // continue trying previous SSE frame
      }
    }
    throw new McpClientError(
      'PROTOCOL_ERROR',
      'Unable to parse SSE JSON-RPC frame from MCP server'
    );
  }

  try {
    return JSON.parse(rawBody) as JsonRpcResponse;
  } catch {
    throw new McpClientError(
      'PROTOCOL_ERROR',
      'Invalid JSON-RPC payload returned by MCP server'
    );
  }
}

export class McpBrowserClient {
  readonly url: string;
  private readonly token?: string;
  private readonly origin?: string;
  private readonly correlationId: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof globalThis.fetch;
  private sessionId: string | null = null;
  private requestCounter = 0;
  private connected = false;

  constructor(options: McpBrowserClientOptions) {
    const validated = validateLoopbackMcpUrl(options.url);
    this.url = validated.toString();
    this.token = options.token?.trim() || undefined;
    this.origin = options.origin?.trim() || undefined;
    this.correlationId =
      options.correlationId ?? `ui-mcp-${Date.now().toString(36)}`;
    this.timeoutMs = options.timeoutMs ?? 4_000;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new McpClientError(
        'NETWORK_ERROR',
        'No fetch implementation available for MCP HTTP client'
      );
    }
  }

  public getSessionId(): string | null {
    return this.sessionId;
  }

  public isConnected(): boolean {
    return this.connected;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      'X-Correlation-Id': this.correlationId,
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (this.sessionId) {
      headers['Mcp-Session-Id'] = this.sessionId;
    }
    // Browsers manage the Origin header automatically on fetch; only attach explicitly in headless/Node callers
    if (this.origin && typeof window === 'undefined') {
      headers['Origin'] = this.origin;
    }
    return headers;
  }

  private async postJsonRpc(
    payload: Record<string, unknown>,
    expectResponse: boolean
  ): Promise<JsonRpcResponse | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(this.url, {
        method: 'POST',
        headers: this.buildHeaders(),
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      const returnedSession = response.headers.get('mcp-session-id');
      if (returnedSession) {
        this.sessionId = returnedSession;
      }

      if (response.status === 401) {
        throw new McpClientError(
          'UNAUTHORIZED',
          'MCP server rejected authentication (HTTP 401)',
          { httpStatus: 401 }
        );
      }
      if (response.status === 403) {
        throw new McpClientError(
          'FORBIDDEN',
          'MCP server denied origin or permissions (HTTP 403)',
          { httpStatus: 403 }
        );
      }
      if (response.status === 429) {
        throw new McpClientError(
          'RATE_LIMITED',
          'MCP server rate-limited request (HTTP 429)',
          { httpStatus: 429 }
        );
      }
      if (response.status === 404) {
        this.sessionId = null;
        this.connected = false;
      }
      if (!response.ok) {
        const snippet = redactTokenFromMessage(
          await response.text().catch(() => ''),
          this.token
        ).slice(0, 160);
        throw new McpClientError(
          'PROTOCOL_ERROR',
          `MCP HTTP ${response.status}${snippet ? `: ${snippet}` : ''}`,
          { httpStatus: response.status }
        );
      }

      if (!expectResponse || response.status === 202) {
        return null;
      }

      const rawText = await response.text();
      if (!rawText.trim()) {
        return null;
      }

      const rpc = parseSseOrJson(
        response.headers.get('content-type') ?? 'application/json',
        rawText
      );
      if (rpc.error) {
        throw new McpClientError(
          'PROTOCOL_ERROR',
          redactTokenFromMessage(
            rpc.error.message ?? 'MCP JSON-RPC error',
            this.token
          )
        );
      }
      return rpc;
    } catch (err) {
      if (err instanceof McpClientError) {
        throw err;
      }
      const rawMsg = err instanceof Error ? err.message : String(err);
      const safeMsg = redactTokenFromMessage(rawMsg, this.token);
      if (
        (err instanceof Error && err.name === 'AbortError') ||
        safeMsg.toLowerCase().includes('abort')
      ) {
        throw new McpClientError(
          'TIMEOUT',
          `MCP HTTP request timed out after ${this.timeoutMs}ms`
        );
      }
      throw new McpClientError(
        'NETWORK_ERROR',
        `MCP HTTP endpoint unreachable: ${safeMsg}`
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Executes Streamable HTTP MCP initialization (`initialize` -> `notifications/initialized`).
   */
  public async connect(): Promise<{ sessionId: string | null }> {
    this.requestCounter += 1;
    await this.postJsonRpc(
      {
        jsonrpc: '2.0',
        id: this.requestCounter,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: {
            name: '@script-kitty/ui',
            version: '0.1.0',
          },
        },
      },
      true
    );

    await this.postJsonRpc(
      {
        jsonrpc: '2.0',
        method: 'notifications/initialized',
        params: {},
      },
      false
    );

    this.connected = true;
    return { sessionId: this.sessionId };
  }

  /**
   * Terminates the active MCP Streamable HTTP session via `DELETE /mcp`
   * and resets local connection/session state even if cleanup fails.
   */
  public async close(): Promise<void> {
    const sessionToClose = this.sessionId;
    this.sessionId = null;
    this.connected = false;

    if (!sessionToClose) {
      return;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const headers: Record<string, string> = {
      Accept: 'application/json, text/event-stream',
      'X-Correlation-Id': this.correlationId,
      'Mcp-Session-Id': sessionToClose,
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (this.origin && typeof window === 'undefined') {
      headers['Origin'] = this.origin;
    }

    try {
      await this.fetchImpl(this.url, {
        method: 'DELETE',
        headers,
        signal: controller.signal,
      });
    } catch {
      // Best-effort remote session cleanup
    } finally {
      clearTimeout(timer);
    }
  }

  public async listTools(): Promise<McpToolDescriptor[]> {
    if (!this.connected) {
      await this.connect();
    }
    this.requestCounter += 1;
    const rpc = await this.postJsonRpc(
      {
        jsonrpc: '2.0',
        id: this.requestCounter,
        method: 'tools/list',
        params: {},
      },
      true
    );
    const tools = rpc?.result?.tools;
    return Array.isArray(tools) ? (tools as McpToolDescriptor[]) : [];
  }

  public async callToolJson<T = Record<string, unknown>>(
    name: string,
    args: Record<string, unknown> = {}
  ): Promise<McpToolCallResult<T>> {
    if (!this.connected) {
      await this.connect();
    }
    this.requestCounter += 1;
    const rpc = await this.postJsonRpc(
      {
        jsonrpc: '2.0',
        id: this.requestCounter,
        method: 'tools/call',
        params: {
          name,
          arguments: args,
        },
      },
      true
    );

    const result = rpc?.result ?? {};
    const isError = Boolean(result.isError);
    const content = Array.isArray(result.content)
      ? (result.content as Array<{ type?: string; text?: string }>)
      : [];
    const firstText =
      content.find((c) => c.type === 'text' && typeof c.text === 'string')?.text ??
      '';

    let parsed: Record<string, unknown> = {};
    if (
      result.structuredContent &&
      typeof result.structuredContent === 'object'
    ) {
      parsed = result.structuredContent as Record<string, unknown>;
    } else if (firstText.trim()) {
      try {
        parsed = JSON.parse(firstText) as Record<string, unknown>;
      } catch {
        parsed = { text: firstText };
      }
    }

    if (isError) {
      const codeStr =
        typeof parsed.code === 'string' ? parsed.code : 'TOOL_ERROR';
      const msg =
        typeof parsed.message === 'string'
          ? parsed.message
          : firstText || `Tool '${name}' failed`;
      throw new McpClientError('TOOL_ERROR', redactTokenFromMessage(msg, this.token), {
        toolErrorCode: codeStr,
      });
    }

    return {
      isError,
      parsed: parsed as T,
      rawText: firstText,
    };
  }
}
