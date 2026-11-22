/**
 * @file packages/security-actions/src/mcp-client.ts
 * @description Official `@modelcontextprotocol/sdk` Streamable HTTP client helper
 * for invoking ScriptKitty Security Actions over `/mcp`.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

export interface SecurityMcpClientOptions {
  url: string;
  token: string;
  origin?: string;
  correlationId?: string;
  clientName?: string;
  clientVersion?: string;
  extraHeaders?: Record<string, string>;
}

export interface ConnectedSecurityMcpClient {
  client: Client;
  transport: StreamableHTTPClientTransport;
  sessionId: string | undefined;
  listTools: () => ReturnType<Client['listTools']>;
  callToolJson: <T = unknown>(
    name: string,
    args?: Record<string, unknown>
  ) => Promise<{ raw: Awaited<ReturnType<Client['callTool']>>; parsed: T; isError: boolean }>;
  close: () => Promise<void>;
}

export function extractMcpToolPayload<T = unknown>(
  result: Awaited<ReturnType<Client['callTool']>>
): { parsed: T; isError: boolean } {
  const isError = Boolean((result as { isError?: boolean }).isError);
  const structured = (result as { structuredContent?: unknown })
    .structuredContent;
  if (!isError && structured !== undefined) {
    return { parsed: structured as T, isError: false };
  }

  const content = (
    result as { content?: Array<{ type: string; text?: string }> }
  ).content;
  const textBlock = content?.find((c) => c.type === 'text')?.text ?? '{}';
  try {
    return { parsed: JSON.parse(textBlock) as T, isError };
  } catch {
    return { parsed: { rawText: textBlock } as unknown as T, isError };
  }
}

export async function connectSecurityMcpClient(
  options: SecurityMcpClientOptions
): Promise<ConnectedSecurityMcpClient> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${options.token}`,
    ...(options.origin ? { Origin: options.origin } : {}),
    ...(options.correlationId
      ? { 'x-correlation-id': options.correlationId }
      : {}),
    ...(options.extraHeaders ?? {}),
  };

  const client = new Client({
    name: options.clientName ?? '@script-kitty/security-actions-client',
    version: options.clientVersion ?? '0.1.0',
  });

  const transport = new StreamableHTTPClientTransport(new URL(options.url), {
    requestInit: { headers },
  });

  await client.connect(transport);

  return {
    client,
    transport,
    get sessionId() {
      return transport.sessionId;
    },
    listTools: () => client.listTools(),
    callToolJson: async <T = unknown>(
      name: string,
      args: Record<string, unknown> = {}
    ) => {
      const raw = await client.callTool({ name, arguments: args });
      const { parsed, isError } = extractMcpToolPayload<T>(raw);
      return { raw, parsed, isError };
    },
    close: async () => {
      await transport.terminateSession().catch(() => {});
      await client.close().catch(() => {});
    },
  };
}
