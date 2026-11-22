import http from 'node:http';
import { fileURLToPath } from 'node:url';
import type { DatabaseSync } from 'node:sqlite';
import { createDatabase } from './db.js';
import { searchIncidents } from './routes/search.js';
import { runHostPing } from './routes/diagnostics.js';
import { getReportById } from './routes/reports.js';
import './types.js';

export interface LabAppOptions {
  db?: DatabaseSync;
  port?: number;
}

export interface LabAppInstance {
  server: http.Server;
  db: DatabaseSync;
  port: number;
  start: (port?: number) => Promise<number>;
  stop: () => Promise<void>;
  getPort: () => number;
}

/**
 * Creates a synthetic vulnerable lab application HTTP server.
 * Uses native node:http and node:sqlite with zero external dependencies.
 */
export function createLabApp(options: LabAppOptions = {}): LabAppInstance {
  const db = options.db ?? createDatabase(':memory:');
  let currentPort = options.port ?? 0;

  const server = http.createServer(async (req, res) => {
    // Enable CORS for testing flexibility
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-user-id, authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const host = req.headers.host || 'localhost';
    const parsedUrl = new URL(req.url || '/', `http://${host}`);
    const pathname = parsedUrl.pathname;

    try {
      // 1. Health check
      if (req.method === 'GET' && (pathname === '/health' || pathname === '/api/health')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', app: 'lab-app', timestamp: new Date().toISOString() }));
        return;
      }

      // 2. Incident Search (SQL Injection CWE-89)
      if (req.method === 'GET' && (pathname === '/api/incidents/search' || pathname === '/api/search')) {
        const query = parsedUrl.searchParams.get('q') ?? parsedUrl.searchParams.get('query') ?? '';
        const results = searchIncidents(db, query);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(results));
        return;
      }

      // 3. Network Diagnostics (Command Injection CWE-78)
      if (req.method === 'POST' && (pathname === '/api/diagnostics/ping' || pathname === '/api/ping')) {
        let bodyRaw = '';
        for await (const chunk of req) {
          bodyRaw += chunk;
        }

        let targetHost = '';
        if (bodyRaw) {
          try {
            const parsed = JSON.parse(bodyRaw);
            targetHost = parsed.host || '';
          } catch {
            targetHost = bodyRaw.trim();
          }
        }

        if (!targetHost) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing host parameter' }));
          return;
        }

        const result = runHostPing(targetHost, db);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }

      // 4. Incident Reports by ID (Broken Access Control / IDOR CWE-639)
      const reportMatch = pathname.match(/^\/api\/(?:reports|incidents)\/(\d+)$/);
      if (req.method === 'GET' && reportMatch) {
        const reportId = parseInt(reportMatch[1], 10);
        const userIdHeader = (req.headers['x-user-id'] as string) || null;

        const response = getReportById(db, reportId, userIdHeader);
        res.writeHead(response.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response.body));
        return;
      }

      // Route Not Found
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not Found', path: pathname }));
    } catch (err: any) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Server Error', message: err.message }));
    }
  });

  const instance: LabAppInstance = {
    server,
    db,
    get port() {
      return currentPort;
    },
    getPort: () => currentPort,
    start: (portToUse?: number) => {
      return new Promise((resolve, reject) => {
        const port = portToUse ?? currentPort;
        server.listen(port, '127.0.0.1', () => {
          const addr = server.address();
          if (addr && typeof addr === 'object') {
            currentPort = addr.port;
          }
          resolve(currentPort);
        });
        server.on('error', reject);
      });
    },
    stop: () => {
      return new Promise((resolve, reject) => {
        server.close((err) => {
          try {
            db.close();
          } catch {
            // Already closed or ignored
          }
          if (err) reject(err);
          else resolve();
        });
      });
    }
  };

  return instance;
}

// Auto-start server when executed directly as CLI
const isDirectExecution = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isDirectExecution) {
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const app = createLabApp({ port });
  app.start().then((listeningPort) => {
    console.log(`[lab-app] Synthetic Lab Application running at http://127.0.0.1:${listeningPort}`);
  }).catch((err) => {
    console.error('[lab-app] Failed to start server:', err);
    process.exit(1);
  });
}
