#!/usr/bin/env node
/**
 * @file apps/mcp-server/src/index.ts
 * @description Stdio entrypoint and public exports for @script-kitty/mcp-server v0.2.0.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  MCP_SERVER_NAME,
  MCP_SERVER_VERSION,
  createScriptKittyMcpServer,
} from './server.js';

export * from './server.js';
export * from './scanner.js';

function isDirectEntrypoint(): boolean {
  try {
    if (!process.argv[1]) return false;
    const entryPath = fs.realpathSync(path.resolve(process.argv[1]));
    const modulePath = fs.realpathSync(fileURLToPath(import.meta.url));
    return entryPath === modulePath;
  } catch {
    return false;
  }
}

export async function startStdioMcpServer(): Promise<void> {
  const envRoots = process.env.SCRIPT_KITTY_ALLOWED_ROOTS
    ? process.env.SCRIPT_KITTY_ALLOWED_ROOTS.split(path.delimiter)
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;

  const bundle = createScriptKittyMcpServer({
    allowedRoots: envRoots,
    dbPath: process.env.SCRIPT_KITTY_DB_PATH || ':memory:',
    auditLogPath: process.env.SCRIPT_KITTY_AUDIT_LOG_PATH || undefined,
  });

  const transport = new StdioServerTransport();

  const shutdown = async () => {
    await bundle.close();
  };

  process.once('SIGINT', () => {
    void shutdown().finally(() => process.exit(0));
  });
  process.once('SIGTERM', () => {
    void shutdown().finally(() => process.exit(0));
  });

  await bundle.server.connect(transport);
  console.error(
    `${MCP_SERVER_NAME} v${MCP_SERVER_VERSION} running on stdio (RuntimeGuardian + SecurityActionEngine active)`
  );
}

if (isDirectEntrypoint()) {
  startStdioMcpServer().catch((err) => {
    console.error('Fatal error in MCP Server:', err);
    process.exit(1);
  });
}
