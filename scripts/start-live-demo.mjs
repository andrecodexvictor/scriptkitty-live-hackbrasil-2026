#!/usr/bin/env node
/**
 * @file scripts/start-live-demo.mjs
 * @description One-command live Proof-of-Concept launcher for ScriptKitty 2.0 / PatchCat Live.
 *
 * Boots two strictly loopback (`127.0.0.1`) servers with zero extra runtime dependencies:
 *  1. Real Invokta MCP Streamable HTTP Server (`@script-kitty/security-actions`) on `127.0.0.1:${MCP_PORT}` (default `3847`)
 *     backed by `:memory:` SQLite Company Brain, deterministic ChainBreak LAB fixtures,
 *     JEV-as-a-Judge (explicit `MOCK` / `NOT_CONFIGURED` offline fallback), and fail-closed loopback CORS.
 *  2. Built `apps/ui/dist/` static bundle server on `127.0.0.1:${UI_PORT}` (default `5173`)
 *     with strict path-traversal containment and loopback-only `/api/demo-config`.
 *
 * CLI flags:
 *  --check              Self-test mode: boots both servers, verifies UI `200`, CORS `OPTIONS` preflight,
 *                       disallowed Origin `403`, missing/invalid Bearer `401`, and live MCP
 *                       `initialize` -> `tools/list` -> `tools/call (security.status)` with
 *                       `Origin: http://127.0.0.1:5173`, prints JSON result, and exits `0`.
 *  --mcp-port=<port>    Override MCP Streamable HTTP port (default: `process.env.MCP_PORT || 3847`)
 *  --ui-port=<port>     Override UI static server port (default: `process.env.UI_PORT || 5173`)
 *  --token=<token>      Override Bearer session token (default: `process.env.DEMO_TOKEN || 'sk-live-demo-token-2026'`)
 *  --help, -h           Show usage information and exit `0`.
 */

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createSecurityActionRuntime,
  SECURITY_CAPABILITY_IDS,
  startMcpHttpServer,
} from '@script-kitty/security-actions';
import {
  Harness2Adapter,
  KaliMcpAdapter,
} from '../packages/adapters/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const UI_DIST_DIR = path.join(REPO_ROOT, 'apps', 'ui', 'dist');
const FIXTURES_DIR = path.join(REPO_ROOT, 'fixtures', 'payments-lab');

const DEFAULT_MCP_PORT = 3847;
const DEFAULT_UI_PORT = 5173;
const DEFAULT_DEMO_TOKEN = 'sk-live-demo-token-2026';
const LOOPBACK_HOST = '127.0.0.1';

const MIME_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'application/javascript; charset=utf-8'],
  ['.mjs', 'application/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.svg', 'image/svg+xml'],
  ['.ico', 'image/x-icon'],
  ['.woff', 'font/woff'],
  ['.woff2', 'font/woff2'],
  ['.map', 'application/json; charset=utf-8'],
  ['.txt', 'text/plain; charset=utf-8'],
]);

function printUsage() {
  console.log(`
ScriptKitty 2.0 / PatchCat Live — One-Command Live PoC Launcher (LAB Mode Only)

Usage:
  node scripts/start-live-demo.mjs [options]

Options:
  --check              Run automated self-test (UI 200, CORS preflight, 403/401 guards,
                       MCP initialize + tools/list + security.status) and exit 0
  --mcp-port=<port>    Loopback MCP Streamable HTTP port (env: MCP_PORT, default: ${DEFAULT_MCP_PORT})
  --ui-port=<port>     Loopback PatchCat UI static port  (env: UI_PORT,  default: ${DEFAULT_UI_PORT})
  --token=<token>      Session Bearer token              (env: DEMO_TOKEN, default: ${DEFAULT_DEMO_TOKEN})
  --help, -h           Show this help text

Environment Variables:
  MCP_PORT             MCP HTTP port (default: ${DEFAULT_MCP_PORT})
  UI_PORT              UI static port (default: ${DEFAULT_UI_PORT})
  DEMO_TOKEN           Bearer token for /mcp (default: ${DEFAULT_DEMO_TOKEN})
  TYPESAFE_API_KEY     Optional live TypeSafe JEV API key (offline MOCK when unset)
`.trim());
}

function parsePort(raw, label) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`Invalid ${label} port '${raw}': expected integer 0..65535`);
  }
  return n;
}

function parseCliArgs(argv) {
  let checkMode = false;
  let showHelp = false;
  let mcpPortExplicit = process.env.MCP_PORT !== undefined;
  let uiPortExplicit = process.env.UI_PORT !== undefined;
  let mcpPort = mcpPortExplicit
    ? parsePort(process.env.MCP_PORT, 'MCP_PORT')
    : DEFAULT_MCP_PORT;
  let uiPort = uiPortExplicit
    ? parsePort(process.env.UI_PORT, 'UI_PORT')
    : DEFAULT_UI_PORT;
  let demoToken = (process.env.DEMO_TOKEN ?? DEFAULT_DEMO_TOKEN).trim();

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--check' || arg === '--self-test') {
      checkMode = true;
    } else if (arg === '--help' || arg === '-h') {
      showHelp = true;
    } else if (arg.startsWith('--mcp-port=')) {
      mcpPort = parsePort(arg.slice('--mcp-port='.length), '--mcp-port');
      mcpPortExplicit = true;
    } else if (arg === '--mcp-port' && argv[i + 1]) {
      mcpPort = parsePort(argv[++i], '--mcp-port');
      mcpPortExplicit = true;
    } else if (arg.startsWith('--ui-port=')) {
      uiPort = parsePort(arg.slice('--ui-port='.length), '--ui-port');
      uiPortExplicit = true;
    } else if (arg === '--ui-port' && argv[i + 1]) {
      uiPort = parsePort(argv[++i], '--ui-port');
      uiPortExplicit = true;
    } else if (arg.startsWith('--token=')) {
      demoToken = arg.slice('--token='.length).trim();
    } else if (arg === '--token' && argv[i + 1]) {
      demoToken = argv[++i].trim();
    } else {
      throw new Error(`Unknown CLI argument: ${arg} (use --help for usage)`);
    }
  }

  if (!demoToken) {
    throw new Error('DEMO_TOKEN / --token must be a non-empty string');
  }

  return {
    checkMode,
    showHelp,
    mcpPort,
    mcpPortExplicit,
    uiPort,
    uiPortExplicit,
    demoToken,
  };
}

function isAllowedLoopbackHostHeader(hostHeader, boundPort) {
  if (typeof hostHeader !== 'string') return false;
  const normalized = hostHeader.trim().toLowerCase();
  const allowed = new Set([
    `127.0.0.1:${boundPort}`,
    `localhost:${boundPort}`,
    `[::1]:${boundPort}`,
    '127.0.0.1',
    'localhost',
    '[::1]',
  ]);
  return allowed.has(normalized);
}

/**
 * Resolves a request pathname strictly inside `realRootDir`, blocking traversal,
 * null bytes, backslashes, and symlink escapes.
 */
function resolveContainedStaticFile(realRootDir, rawPathname) {
  if (rawPathname.includes('\0') || rawPathname.includes('\\')) {
    return { status: 400, filePath: null };
  }

  let decoded;
  try {
    decoded = decodeURIComponent(rawPathname);
  } catch {
    return { status: 400, filePath: null };
  }

  if (decoded.includes('\0') || decoded.includes('\\')) {
    return { status: 400, filePath: null };
  }

  const segments = decoded.split('/').filter(Boolean);
  if (segments.some((seg) => seg === '..' || seg === '.')) {
    return { status: 403, filePath: null };
  }

  const relativeTarget = segments.length === 0 ? 'index.html' : segments.join('/');
  const resolvedCandidate = path.resolve(realRootDir, relativeTarget);
  const relCheck = path.relative(realRootDir, resolvedCandidate);
  if (relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
    return { status: 403, filePath: null };
  }

  if (!fs.existsSync(resolvedCandidate)) {
    return { status: 404, filePath: null };
  }

  const stat = fs.statSync(resolvedCandidate);
  const finalCandidate = stat.isDirectory()
    ? path.join(resolvedCandidate, 'index.html')
    : resolvedCandidate;

  if (!fs.existsSync(finalCandidate)) {
    return { status: 404, filePath: null };
  }

  const realTarget = fs.realpathSync(finalCandidate);
  const realRel = path.relative(realRootDir, realTarget);
  if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
    return { status: 403, filePath: null };
  }

  return { status: 200, filePath: realTarget };
}

async function startStaticUiServer({
  distDir,
  requestedPort,
  allowEphemeralFallback,
  getDemoConfig,
}) {
  if (!fs.existsSync(distDir) || !fs.existsSync(path.join(distDir, 'index.html'))) {
    throw new Error(
      `Built UI bundle not found at '${distDir}'. Run 'npm run build --workspace=@script-kitty/ui' (or 'npm run build') first.`
    );
  }

  const realRootDir = fs.realpathSync(distDir);
  let boundPort = requestedPort;

  const server = http.createServer((req, res) => {
    try {
      if (!isAllowedLoopbackHostHeader(req.headers.host, boundPort)) {
        res.writeHead(403, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(JSON.stringify({ error: 'Forbidden: non-loopback Host header' }));
        return;
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, {
          'Content-Type': 'application/json; charset=utf-8',
          Allow: 'GET, HEAD',
          'Cache-Control': 'no-store',
        });
        res.end(JSON.stringify({ error: 'Method Not Allowed' }));
        return;
      }

      const rawUrl = req.url ?? '/';
      const rawPathname = rawUrl.split('?')[0] || '/';
      const parsedUrl = new URL(rawUrl, `http://${LOOPBACK_HOST}:${boundPort}`);

      if (parsedUrl.pathname === '/api/demo-config') {
        const payload = JSON.stringify(getDemoConfig(), null, 2);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
        });
        if (req.method === 'HEAD') {
          res.end();
        } else {
          res.end(payload);
        }
        return;
      }

      const resolved = resolveContainedStaticFile(realRootDir, rawPathname);
      if (resolved.status !== 200 || !resolved.filePath) {
        const message =
          resolved.status === 400
            ? 'Bad Request'
            : resolved.status === 403
              ? 'Forbidden: path traversal blocked'
              : 'Not Found';
        res.writeHead(resolved.status, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        });
        res.end(message);
        return;
      }

      const ext = path.extname(resolved.filePath).toLowerCase();
      const contentType = MIME_TYPES.get(ext) ?? 'application/octet-stream';
      const content = fs.readFileSync(resolved.filePath);

      res.writeHead(200, {
        'Content-Type': contentType,
        'Content-Length': String(content.length),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'Referrer-Policy': 'no-referrer',
      });
      if (req.method === 'HEAD') {
        res.end();
      } else {
        res.end(content);
      }
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end('Internal Server Error');
      }
    }
  });

  const listenOnPort = (portToTry) =>
    new Promise((resolve, reject) => {
      const onError = (err) => {
        server.removeListener('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        server.removeListener('error', onError);
        const addr = server.address();
        boundPort = addr && typeof addr !== 'string' ? addr.port : portToTry;
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(portToTry, LOOPBACK_HOST);
    });

  try {
    await listenOnPort(requestedPort);
  } catch (err) {
    if (allowEphemeralFallback && err && err.code === 'EADDRINUSE' && requestedPort !== 0) {
      await listenOnPort(0);
    } else {
      throw err;
    }
  }

  return {
    server,
    host: LOOPBACK_HOST,
    port: boundPort,
    url: `http://${LOOPBACK_HOST}:${boundPort}`,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        if (typeof server.closeAllConnections === 'function') {
          server.closeAllConnections();
        }
      });
    },
  };
}

function buildAllowedOrigins(uiPort, mcpPort) {
  return Array.from(
    new Set([
      `http://127.0.0.1:${DEFAULT_UI_PORT}`,
      `http://localhost:${DEFAULT_UI_PORT}`,
      `http://127.0.0.1:${uiPort}`,
      `http://localhost:${uiPort}`,
      `http://127.0.0.1:${mcpPort}`,
      `http://localhost:${mcpPort}`,
    ])
  );
}

async function runSelfCheck({ uiHandle, mcpHandle, demoToken, allowedOrigins }) {
  const testOrigin = `http://127.0.0.1:${DEFAULT_UI_PORT}`;

  // 1. UI root returns 200 HTML
  const uiRes = await fetch(`${uiHandle.url}/`, { method: 'GET' });
  assert.equal(uiRes.status, 200, `Expected UI GET / -> 200, got ${uiRes.status}`);
  const uiHtml = await uiRes.text();
  assert.ok(
    uiHtml.includes('<div id="app">') &&
      (uiHtml.includes('PatchCat Live') || uiHtml.includes('ScriptKitty Live')),
    'Expected built PatchCat UI index.html payload'
  );

  // 2. UI path-traversal attempt fails closed (403/404)
  const traversalRes = await fetch(`${uiHandle.url}/%2e%2e/%2e%2e/package.json`);
  assert.ok(
    traversalRes.status === 403 || traversalRes.status === 404,
    `Expected traversal block (403/404), got ${traversalRes.status}`
  );

  // 3. Loopback /api/demo-config returns LAB metadata without leaking token
  const configRes = await fetch(`${uiHandle.url}/api/demo-config`);
  assert.equal(configRes.status, 200);
  const configJson = await configRes.json();
  assert.equal(configJson.mode, 'LAB');
  assert.equal(configJson.mcpUrl, mcpHandle.url);
  assert.equal(JSON.stringify(configJson).includes(demoToken), false);

  // 4. CORS preflight OPTIONS for allowlisted loopback Origin -> 204
  const corsPreflightOk = await fetch(mcpHandle.url, {
    method: 'OPTIONS',
    headers: {
      Origin: testOrigin,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers':
        'authorization, content-type, mcp-session-id, x-correlation-id',
    },
  });
  assert.equal(corsPreflightOk.status, 204);
  assert.equal(
    corsPreflightOk.headers.get('access-control-allow-origin'),
    testOrigin
  );
  assert.equal(
    corsPreflightOk.headers.get('access-control-expose-headers'),
    'Mcp-Session-Id'
  );

  // 5. Fail-closed checks: disallowed Origin -> 403, missing/invalid Bearer -> 401
  const evilOriginPreflight = await fetch(mcpHandle.url, {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://evil.attacker.example',
      'Access-Control-Request-Method': 'POST',
    },
  });
  assert.equal(evilOriginPreflight.status, 403);
  assert.equal(
    evilOriginPreflight.headers.get('access-control-allow-origin'),
    null
  );

  const evilOriginPost = await fetch(mcpHandle.url, {
    method: 'POST',
    headers: {
      Origin: 'https://evil.attacker.example',
      Authorization: `Bearer ${demoToken}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 901,
      method: 'tools/list',
      params: {},
    }),
  });
  assert.equal(evilOriginPost.status, 403);
  assert.equal(evilOriginPost.headers.get('access-control-allow-origin'), null);

  const invalidTokenRes = await fetch(mcpHandle.url, {
    method: 'POST',
    headers: {
      Origin: testOrigin,
      Authorization: 'Bearer invalid-demo-token',
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 902,
      method: 'tools/list',
      params: {},
    }),
  });
  assert.equal(invalidTokenRes.status, 401);

  // 6. Real MCP initialize -> notifications/initialized -> tools/list -> tools/call (security.status)
  const commonHeaders = {
    Origin: testOrigin,
    Authorization: `Bearer ${demoToken}`,
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    'X-Correlation-Id': 'live-demo-self-check-001',
  };

  const initRes = await fetch(mcpHandle.url, {
    method: 'POST',
    headers: commonHeaders,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: {
          name: 'scriptkitty-live-demo-check',
          version: '0.1.0',
        },
      },
    }),
  });
  assert.equal(initRes.status, 200);
  assert.equal(initRes.headers.get('access-control-allow-origin'), testOrigin);
  const sessionId = initRes.headers.get('mcp-session-id');
  assert.ok(sessionId && sessionId.length > 0, 'Expected Mcp-Session-Id header');
  const initJson = await initRes.json();
  assert.ok(initJson.result?.serverInfo?.name, 'Expected MCP initialize serverInfo');

  const sessionHeaders = {
    ...commonHeaders,
    'Mcp-Session-Id': sessionId,
  };

  const notifRes = await fetch(mcpHandle.url, {
    method: 'POST',
    headers: sessionHeaders,
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: {},
    }),
  });
  assert.ok(
    notifRes.status === 200 || notifRes.status === 202,
    `Expected notifications/initialized 200/202, got ${notifRes.status}`
  );

  const listRes = await fetch(mcpHandle.url, {
    method: 'POST',
    headers: sessionHeaders,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {},
    }),
  });
  assert.equal(listRes.status, 200);
  const listJson = await listRes.json();
  const toolNames = (listJson.result?.tools ?? []).map((t) => t.name).sort();
  assert.deepEqual(toolNames, [...SECURITY_CAPABILITY_IDS].sort());

  const statusCallRes = await fetch(mcpHandle.url, {
    method: 'POST',
    headers: sessionHeaders,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'security.status',
        arguments: {},
      },
    }),
  });
  assert.equal(statusCallRes.status, 200);
  assert.equal(
    statusCallRes.headers.get('access-control-allow-origin'),
    testOrigin
  );
  const statusCallJson = await statusCallRes.json();
  const statusPayload = statusCallJson.result?.structuredContent;
  assert.equal(statusPayload?.mode, 'LAB');
  assert.equal(statusPayload?.productionTested, false);
  assert.equal(statusPayload?.mergeAllowed, false);
  assert.equal(statusPayload?.deployAllowed, false);
  assert.equal(statusPayload?.HARNESS2_EXPERIMENTS_ENABLED, false);

  return {
    check: 'PASS',
    ui: {
      url: uiHandle.url,
      indexStatus: uiRes.status,
      traversalBlockedStatus: traversalRes.status,
      demoConfigStatus: configRes.status,
    },
    mcp: {
      url: mcpHandle.url,
      sessionId,
      testedOrigin: testOrigin,
      allowedOrigins,
      corsPreflightStatus: corsPreflightOk.status,
      disallowedOriginPreflightStatus: evilOriginPreflight.status,
      disallowedOriginPostStatus: evilOriginPost.status,
      invalidBearerStatus: invalidTokenRes.status,
      tools: toolNames,
      securityStatus: statusPayload,
    },
  };
}

async function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  if (opts.showHelp) {
    printUsage();
    return;
  }

  const kaliAdapter = new KaliMcpAdapter();
  const harness2Adapter = new Harness2Adapter();
  const kaliStatus = kaliAdapter.getStatus();
  const harness2Status = harness2Adapter.getStatus();

  const runtime = createSecurityActionRuntime({
    dbPath: ':memory:',
    fixturesDir: FIXTURES_DIR,
    externalAdaptersStatus: () => ({
      patchcat: {
        status: 'ISOLATED_LAB_ONLY',
        mode: 'LAB',
        enabled: true,
        externalExecution: false,
      },
      typesafeJev: {
        status: process.env.TYPESAFE_API_KEY?.trim() ? 'LIVE' : 'NOT_CONFIGURED',
        mode: process.env.TYPESAFE_API_KEY?.trim() ? 'LIVE' : 'MOCK_OFFLINE',
        enabled: Boolean(process.env.TYPESAFE_API_KEY?.trim()),
        externalExecution: false,
      },
      kaliMcp: {
        status: kaliStatus.configuration_status,
        mode: kaliStatus.mode,
        enabled: kaliStatus.enabled,
        externalExecution: false,
      },
      harness2: {
        status: harness2Status.configuration_status,
        mode: harness2Status.mode,
        enabled: harness2Status.enabled,
        externalExecution: false,
      },
      factoryDeliveryGate: {
        status: 'READY',
        mode: 'LAB',
        enabled: true,
        externalExecution: false,
      },
    }),
  });

  const demoPrincipal = {
    principalId: 'operator-patchcat-live',
    tenantId: 'payments-lab',
    roles: ['security-operator'],
    scopes: [
      'security:status',
      'security:analyze',
      'security:read',
      'security:judge',
      'security:remediate',
    ],
  };

  let uiHandle = null;
  let mcpHandle = null;
  let allowedOrigins = [];
  let shuttingDown = false;

  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    await Promise.allSettled([
      uiHandle ? uiHandle.close() : Promise.resolve(),
      mcpHandle ? mcpHandle.close() : Promise.resolve(),
    ]);
    runtime.close();
  };

  try {
    // Start UI static server first so we know its exact bound port for MCP allowedOrigins
    uiHandle = await startStaticUiServer({
      distDir: UI_DIST_DIR,
      requestedPort: opts.uiPort,
      allowEphemeralFallback: opts.checkMode && !opts.uiPortExplicit,
      getDemoConfig: () => ({
        mode: 'LAB',
        productionTested: false,
        mergeAllowed: false,
        deployAllowed: false,
        uiUrl: uiHandle?.url ?? `http://${LOOPBACK_HOST}:${opts.uiPort}`,
        mcpUrl: mcpHandle?.url ?? `http://${LOOPBACK_HOST}:${opts.mcpPort}/mcp`,
        allowedOrigins,
        defaultFixture: 'payments-lab/baseline',
        authRequired: true,
        authHeaderFormat: 'Authorization: Bearer <DEMO_TOKEN>',
      }),
    });

    const startMcpWithPort = async (portToBind) => {
      const candidateOrigins = buildAllowedOrigins(
        uiHandle.port,
        portToBind > 0 ? portToBind : opts.mcpPort
      );
      const handle = await startMcpHttpServer(runtime.engine, {
        host: LOOPBACK_HOST,
        port: portToBind,
        path: '/mcp',
        allowedOrigins: candidateOrigins,
        rateLimit: { maxRequests: 240, windowMs: 60_000 },
        tokens: {
          [opts.demoToken]: demoPrincipal,
        },
      });
      allowedOrigins = candidateOrigins;
      return handle;
    };

    try {
      mcpHandle = await startMcpWithPort(opts.mcpPort);
    } catch (err) {
      if (
        opts.checkMode &&
        !opts.mcpPortExplicit &&
        err &&
        err.code === 'EADDRINUSE' &&
        opts.mcpPort !== 0
      ) {
        mcpHandle = await startMcpWithPort(0);
      } else {
        throw err;
      }
    }

    if (opts.checkMode) {
      const report = await runSelfCheck({
        uiHandle,
        mcpHandle,
        demoToken: opts.demoToken,
        allowedOrigins,
      });
      console.log(JSON.stringify(report, null, 2));
      await shutdown();
      return;
    }

    const autoConnectUrl = `${uiHandle.url}/?mcpUrl=${encodeURIComponent(mcpHandle.url)}&token=${encodeURIComponent(opts.demoToken)}&autoConnect=1`;

    console.log('='.repeat(84));
    console.log(' ScriptKitty 2.0 / PatchCat Live — Local PoC Stack Ready (LAB Mode Only)');
    console.log('='.repeat(84));
    console.log(` PatchCat UI (Static):   ${uiHandle.url}`);
    console.log(` Invokta MCP HTTP:       ${mcpHandle.url}`);
    console.log(` Loopback Demo Config:   ${uiHandle.url}/api/demo-config`);
    console.log(` Session Bearer Token:   ${opts.demoToken}`);
    console.log(` Tenant / Principal:     ${demoPrincipal.tenantId} / ${demoPrincipal.principalId}`);
    console.log(` Allowed CORS Origins:   ${allowedOrigins.join(', ')}`);
    console.log(` Quick-Connect UI URL:   ${autoConnectUrl}`);
    console.log(' Boundaries:             mode=LAB | productionTested=false | mergeAllowed=false | deployAllowed=false');
    console.log('='.repeat(84));
    console.log('Press Ctrl+C (SIGINT / SIGTERM) to stop both loopback servers cleanly.');

    const handleSignal = async (signal) => {
      console.log(`\n[start-live-demo] Received ${signal}; shutting down loopback servers cleanly...`);
      await shutdown();
      process.exit(0);
    };

    process.once('SIGINT', () => {
      void handleSignal('SIGINT');
    });
    process.once('SIGTERM', () => {
      void handleSignal('SIGTERM');
    });
  } catch (err) {
    await shutdown();
    throw err;
  }
}

main().catch((err) => {
  console.error('[start-live-demo] Fatal error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
