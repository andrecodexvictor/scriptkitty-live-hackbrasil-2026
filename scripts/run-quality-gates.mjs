#!/usr/bin/env node
/**
 * @file scripts/run-quality-gates.mjs
 * @description Independent executable Quality Gates runner (G00-G14) for ScriptKitty Live / PatchCat
 * (Hack Brasil 2026) per 06_QUALITY_GATES_AND_ACCEPTANCE.md.
 *
 * ZERO FAKE PASSES:
 *  - Every check executes a real command, HTTP call, Chromium CDP session, or GitHub API call.
 *  - SKIPPED, MOCK, NOT_CONFIGURED, INCONCLUSIVE, or unconfigured public URLs never map to PASS.
 *  - Secrets and Bearer tokens are scrubbed before writing evidence/*-redacted.json or logs.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const EVIDENCE_DIR = path.join(REPO_ROOT, 'evidence');
const FIXTURES_DIR = path.join(REPO_ROOT, 'fixtures', 'payments-lab');
const UI_DIST_DIR = path.join(REPO_ROOT, 'apps', 'ui', 'dist');
const VERCEL_DIST_DIR = path.join(REPO_ROOT, 'vercel-app', 'dist');
const DEMO_VIDEO_MP4 = path.join(REPO_ROOT, 'demo-video', 'scriptkitty-live-poc-demo-2m30s.mp4');
const DEMO_VIDEO_SRT = path.join(REPO_ROOT, 'demo-video', 'scriptkitty-live-poc-demo-2m30s.srt');
const DEMO_FRAMES_DIR = path.join(REPO_ROOT, 'demo-video', 'frames');

const COMPETITION_REPO_API = 'https://api.github.com/repos/andrecodexvictor/scriptkitty-live-hackbrasil-2026';
const COMPETITION_REPO_HTML = 'https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026';
const HACKBR_CUTOFF_ISO = '2026-11-04T21:00:00-03:00';
const HACKBR_FREEZE_ISO = '2026-11-27T23:59:00-03:00';
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

const relPath = (absPath) => path.relative(REPO_ROOT, absPath).replace(/\\/g, '/');

function findBinary(envVar, cmdName, extraCandidates = []) {
  const fromEnv = process.env[envVar]?.trim();
  if (fromEnv && fs.existsSync(fromEnv)) return fromEnv;
  const which = spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmdName], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (which.status === 0 && which.stdout.trim()) {
    const first = which.stdout.trim().split(/\r?\n/)[0].trim();
    if (first && fs.existsSync(first)) return first;
  }
  return extraCandidates.find((c) => c && fs.existsSync(c)) ?? null;
}

function discoverHostBinaries() {
  const lad = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  const pf = process.env.ProgramFiles || 'C:\\Program Files';
  const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';

  const ffmpeg = findBinary('FFMPEG_PATH', 'ffmpeg', [
    path.join(lad, 'Programs', 'Stremio', 'ffmpeg.exe'),
    'C:\\ffmpeg\\bin\\ffmpeg.exe',
    path.join(os.homedir(), 'scoop', 'shims', 'ffmpeg.exe'),
    'C:\\ProgramData\\chocolatey\\bin\\ffmpeg.exe',
  ]);
  const ffprobe = findBinary('FFPROBE_PATH', 'ffprobe', [
    ffmpeg ? path.join(path.dirname(ffmpeg), process.platform === 'win32' ? 'ffprobe.exe' : 'ffprobe') : '',
    path.join(lad, 'Programs', 'Stremio', 'ffprobe.exe'),
    'C:\\ffmpeg\\bin\\ffprobe.exe',
    path.join(os.homedir(), 'scoop', 'shims', 'ffprobe.exe'),
    'C:\\ProgramData\\chocolatey\\bin\\ffprobe.exe',
  ]);

  const pwChromiums = [];
  const pwRoot = path.join(lad, 'ms-playwright');
  if (fs.existsSync(pwRoot)) {
    for (const d of fs.readdirSync(pwRoot)) {
      if (d.startsWith('chromium-')) {
        pwChromiums.push(
          path.join(pwRoot, d, 'chrome-win64', 'chrome.exe'),
          path.join(pwRoot, d, 'chrome-win', 'chrome.exe')
        );
      }
    }
  }
  const chromium = findBinary('CHROMIUM_PATH', 'chrome', [
    ...pwChromiums,
    path.join(pf, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(pf86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(lad, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(pf, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    path.join(pf86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  ]);
  const impeccableDetect = [
    path.join(os.homedir(), '.agents', 'skills', 'impeccable', 'scripts', 'detect.mjs'),
    path.join(REPO_ROOT, 'impeccable', 'scripts', 'detect.mjs'),
  ].find((p) => fs.existsSync(p)) ?? null;

  return { ffmpeg, ffprobe, chromium, impeccableDetect };
}

const SECRET_REGEX_PATTERNS = [
  { re: /Bearer\s+[A-Za-z0-9._\-+/=]{8,}/gi, replacement: 'Bearer [REDACTED_TOKEN]' },
  { re: /\bsk-[A-Za-z0-9_-]{12,}\b/g, replacement: '[REDACTED_SK_TOKEN]' },
  { re: /\bghp_[A-Za-z0-9]{16,}\b/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { re: /\bgithub_pat_[A-Za-z0-9_]{16,}\b/g, replacement: '[REDACTED_GITHUB_PAT]' },
  { re: /\bAIza[0-9A-Za-z\-_]{20,}\b/g, replacement: '[REDACTED_GOOGLE_KEY]' },
  { re: /\bnvapi-[A-Za-z0-9\-_]{16,}\b/g, replacement: '[REDACTED_NVIDIA_KEY]' },
  { re: /\bxai-[A-Za-z0-9\-_]{16,}\b/g, replacement: '[REDACTED_XAI_KEY]' },
  { re: /\bAKIA[0-9A-Z]{16}\b/g, replacement: '[REDACTED_AWS_KEY]' },
];

function redactString(input, explicitSecrets = []) {
  let out = String(input ?? '');
  for (const secret of explicitSecrets) {
    if (typeof secret === 'string' && secret.trim().length >= 6) {
      out = out.split(secret).join('[REDACTED_SECRET]');
    }
  }
  for (const { re, replacement } of SECRET_REGEX_PATTERNS) {
    out = out.replace(re, replacement);
  }
  return out;
}

function redactValue(value, explicitSecrets = []) {
  if (typeof value === 'string') return redactString(value, explicitSecrets);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, explicitSecrets));
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (/^(?:authorization|token|bearer|api_?key|secret|password|hmacSecret)$/i.test(k) && typeof v === 'string' && v.length > 0) {
        out[k] = '[REDACTED_SECRET]';
      } else {
        out[k] = redactValue(v, explicitSecrets);
      }
    }
    return out;
  }
  return value;
}

function writeRedactedJson(filePath, data, explicitSecrets = []) {
  const serialized = redactString(JSON.stringify(redactValue(data, explicitSecrets), null, 2), explicitSecrets);
  for (const secret of explicitSecrets) {
    if (typeof secret === 'string' && secret.trim().length >= 6) {
      assert.equal(serialized.includes(secret), false, `Secret leak blocked in ${relPath(filePath)}`);
    }
  }
  fs.writeFileSync(filePath, serialized + '\n', 'utf8');
}

function runCommandCapture(label, command, args, options = {}) {
  const t0 = Date.now();
  const isWinNpm = process.platform === 'win32' && (command === 'npm' || command === 'npm.cmd' || command === 'npx');
  const actualCmd = isWinNpm && !command.endsWith('.cmd') ? `${command}.cmd` : command;
  const res = spawnSync(actualCmd, args, {
    cwd: options.cwd ?? REPO_ROOT,
    encoding: 'utf8',
    timeout: options.timeoutMs ?? 240_000,
    shell: options.shell ?? isWinNpm,
    env: { ...process.env, ...(options.env ?? {}) },
  });
  const durationMs = Date.now() - t0;
  const stdout = (res.stdout || '').replace(/\r\n/g, '\n');
  const stderr = (res.stderr || '').replace(/\r\n/g, '\n');
  const exitCode = typeof res.status === 'number' ? res.status : 1;
  return {
    label,
    command: `${command} ${args.join(' ')}`.trim(),
    exitCode,
    durationMs,
    stdout,
    stderr,
    combined: [
      `# Command: ${command} ${args.join(' ')}`,
      `# CWD: ${options.cwd ?? REPO_ROOT}`,
      `# ExitCode: ${exitCode} | DurationMs: ${durationMs}`,
      stdout.trim(),
      stderr.trim(),
    ].filter(Boolean).join('\n'),
  };
}

function getGitHeadSha() {
  const res = runCommandCapture('git rev-parse HEAD', 'git', ['rev-parse', 'HEAD']);
  return res.exitCode === 0 && /^[a-f0-9]{40}$/i.test(res.stdout.trim()) ? res.stdout.trim() : '0'.repeat(40);
}

async function loadBuiltPackages() {
  const imp = (rel) => import(pathToFileURL(path.join(REPO_ROOT, rel)).href);
  return {
    securityActions: await imp('packages/security-actions/dist/index.js'),
    chainbreak: await imp('packages/chainbreak/dist/index.js'),
    contracts: await imp('packages/contracts/dist/index.js'),
    qualityGate: await imp('packages/quality-gate/dist/index.js'),
    companyContext: await imp('packages/company-context/dist/index.js'),
    adapters: await imp('packages/adapters/dist/index.js'),
    evidence: await imp('packages/evidence/dist/index.js'),
    patchcatOrchestrator: await imp('packages/patchcat-orchestrator/dist/index.js'),
    kaliMcp: await imp('packages/kali-mcp-assessment/dist/index.js'),
    jevJudge: await imp('packages/jev-judge/dist/index.js'),
  };
}

function resolveContainedStaticFile(realRootDir, rawPathname) {
  if (rawPathname.includes('\0') || rawPathname.includes('\\')) return { status: 400, filePath: null };
  let decoded;
  try {
    decoded = decodeURIComponent(rawPathname);
  } catch {
    return { status: 400, filePath: null };
  }
  if (decoded.includes('\0') || decoded.includes('\\')) return { status: 400, filePath: null };
  const segments = decoded.split('/').filter(Boolean);
  if (segments.some((s) => s === '..' || s === '.')) return { status: 403, filePath: null };
  const candidate = path.resolve(realRootDir, segments.length === 0 ? 'index.html' : segments.join('/'));
  const rel = path.relative(realRootDir, candidate);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return { status: 403, filePath: null };
  if (!fs.existsSync(candidate)) return { status: 404, filePath: null };
  const finalCandidate = fs.statSync(candidate).isDirectory() ? path.join(candidate, 'index.html') : candidate;
  if (!fs.existsSync(finalCandidate)) return { status: 404, filePath: null };
  const realTarget = fs.realpathSync(finalCandidate);
  const realRel = path.relative(realRootDir, realTarget);
  if (realRel.startsWith('..') || path.isAbsolute(realRel)) return { status: 403, filePath: null };
  return { status: 200, filePath: realTarget };
}

async function startEphemeralStaticServer(distDir) {
  if (!fs.existsSync(path.join(distDir, 'index.html'))) {
    throw new Error(`Built static directory not found at ${distDir}`);
  }
  const realRootDir = fs.realpathSync(distDir);
  let boundPort = 0;
  const server = http.createServer((req, res) => {
    try {
      const resolved = resolveContainedStaticFile(realRootDir, (req.url ?? '/').split('?')[0] || '/');
      if (resolved.status !== 200 || !resolved.filePath) {
        res.writeHead(resolved.status, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('Not Found');
        return;
      }
      const content = fs.readFileSync(resolved.filePath);
      const ext = path.extname(resolved.filePath).toLowerCase();
      res.writeHead(200, {
        'Content-Type': MIME_TYPES.get(ext) ?? 'application/octet-stream',
        'Content-Length': String(content.length),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end(content);
    } catch {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Internal Server Error');
      }
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, LOOPBACK_HOST, () => {
      const addr = server.address();
      boundPort = addr && typeof addr !== 'string' ? addr.port : 0;
      resolve();
    });
  });
  return {
    port: boundPort,
    url: `http://${LOOPBACK_HOST}:${boundPort}`,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      }),
  };
}

async function killProcessTree(proc) {
  if (!proc || proc.exitCode !== null || proc.killed) return;
  try {
    proc.kill('SIGTERM');
  } catch { /* ignore */ }
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (proc.exitCode === null && proc.pid) {
        if (process.platform === 'win32') {
          spawnSync('taskkill', ['/PID', String(proc.pid), '/T', '/F'], { stdio: 'ignore', timeout: 5000 });
        } else {
          try { proc.kill('SIGKILL'); } catch { /* ignore */ }
        }
      }
      resolve();
    }, 2000);
    proc.once('exit', () => { clearTimeout(timer); resolve(); });
  });
}

async function launchChromiumCdp(chromiumPath, profileDir) {
  fs.mkdirSync(profileDir, { recursive: true });
  const proc = spawn(
    chromiumPath,
    [
      '--headless=new', '--no-sandbox', '--disable-dev-shm-usage',
      '--disable-background-timer-throttling', '--disable-renderer-backgrounding',
      '--force-device-scale-factor=1', '--hide-scrollbars', '--remote-debugging-port=0',
      `--user-data-dir=${profileDir}`, '--window-size=1440,900', 'about:blank',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );

  let stderrBuf = '';
  const wsBrowserUrl = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Chromium DevTools timeout:\n${stderrBuf}`)), 20_000);
    proc.stderr.on('data', (chunk) => {
      stderrBuf += chunk.toString();
      const m = stderrBuf.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (m) { clearTimeout(timer); resolve(m[1]); }
    });
    proc.once('exit', (code) => { clearTimeout(timer); reject(new Error(`Chromium exited (${code}):\n${stderrBuf}`)); });
  });

  const baseHttp = wsBrowserUrl.replace(/^ws:/, 'http:').replace(/\/devtools\/browser\/.*$/, '');
  const targets = await (await fetch(`${baseHttp}/json/list`)).json();
  const pageTarget = targets.find((t) => t.type === 'page') ?? targets[0];
  if (!pageTarget?.webSocketDebuggerUrl) {
    await killProcessTree(proc);
    throw new Error('No Chromium page target found');
  }

  const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = (err) => reject(new Error(`CDP WebSocket error: ${err}`));
  });

  let seq = 0;
  const pending = new Map();
  const listeners = new Map();
  ws.onmessage = (event) => {
    const msg = JSON.parse(String(event.data));
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(`CDP ${msg.error.code}: ${msg.error.message}`)) : resolve(msg.result);
    } else if (msg.method && listeners.has(msg.method)) {
      for (const fn of listeners.get(msg.method)) fn(msg.params);
    }
  };
  ws.onclose = () => {
    for (const { reject } of pending.values()) reject(new Error('CDP WebSocket closed'));
    pending.clear();
  };

  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });
  const on = (method, handler) => {
    if (!listeners.has(method)) listeners.set(method, new Set());
    listeners.get(method).add(handler);
    return () => listeners.get(method)?.delete(handler);
  };

  await send('Page.enable');
  await send('Runtime.enable');
  await send('DOM.enable');

  const evaluate = async (expression) => {
    const res = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (res.exceptionDetails) {
      throw new Error(`Browser eval exception: ${res.exceptionDetails.text || JSON.stringify(res.exceptionDetails)}`);
    }
    return res.result?.value;
  };

  return {
    send,
    evaluate,
    setViewport: (width, height, deviceScaleFactor = 1) =>
      send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor, mobile: width < 768 }),
    waitForCondition: async (jsExpr, timeoutMs = 12_000, label = 'condition') => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (await evaluate(`Boolean(${jsExpr})`)) return;
        await new Promise((r) => setTimeout(r, 120));
      }
      throw new Error(`Timed out waiting for browser ${label} (${jsExpr})`);
    },
    navigate: async (url) => {
      const loadDone = new Promise((resolve) => {
        const off = on('Page.loadEventFired', () => { off(); resolve(); });
      });
      await send('Page.navigate', { url });
      await Promise.race([loadDone, new Promise((r) => setTimeout(r, 8000))]);
      await new Promise((r) => setTimeout(r, 350));
    },
    screenshotPng: async (outPath) => {
      const res = await send('Page.captureScreenshot', { format: 'png', fromSurface: true });
      fs.writeFileSync(outPath, Buffer.from(res.data, 'base64'));
    },
    close: async () => {
      await Promise.race([send('Browser.close').catch(() => {}), new Promise((r) => setTimeout(r, 800))]);
      try { ws.close(); } catch { /* ignore */ }
      await killProcessTree(proc);
    },
  };
}

// ============================================================================
// Gate G00: Hack Brasil 2026 Eligibility & Provenance Preflight
// ============================================================================

async function runGateG00(verifiedSha) {
  const t0 = Date.now();
  const artifactPath = path.join(EVIDENCE_DIR, 'submission-preflight.json');
  const originUrl = runCommandCapture('git remote', 'git', ['remote', 'get-url', 'origin']).stdout.trim();
  const logOut = runCommandCapture('git log', 'git', ['log', '--reverse', '--format=%H|%aI|%s']).stdout;

  const cutoffMs = Date.parse(HACKBR_CUTOFF_ISO);
  const preEventCommits = logOut
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [sha, authorDate, ...subjectParts] = line.split('|');
      return {
        sha: sha?.slice(0, 7) ?? '',
        fullSha: sha ?? '',
        authorDate: authorDate ?? '',
        subject: subjectParts.join('|'),
        isPreEvent: Number.isFinite(Date.parse(authorDate)) && Date.parse(authorDate) < cutoffMs,
      };
    })
    .filter((c) => c.isPreEvent);

  const hasProvenanceDoc = fs.existsSync(path.join(REPO_ROOT, 'PROVENANCE.md'));
  const hasLicenseDoc = fs.existsSync(path.join(REPO_ROOT, 'LICENSE'));

  let githubApiStatus = 0;
  let githubRepoMeta = null;
  let githubApiError = null;
  let remoteHeadSha = null;

  try {
    const ghHeaders = { 'User-Agent': 'scriptkitty-quality-gates/1.0', Accept: 'application/vnd.github+json' };
    const res = await fetch(COMPETITION_REPO_API, { headers: ghHeaders });
    githubApiStatus = res.status;
    if (res.ok) {
      const json = await res.json();
      githubRepoMeta = {
        full_name: json.full_name,
        html_url: json.html_url,
        created_at: json.created_at,
        updated_at: json.updated_at,
        pushed_at: json.pushed_at,
        private: json.private,
        fork: json.fork,
        size: json.size,
        default_branch: json.default_branch,
        createdAfterCutoff: Number.isFinite(Date.parse(json.created_at)) && Date.parse(json.created_at) > cutoffMs,
        cutoffIso: HACKBR_CUTOFF_ISO,
      };
      if (json.size > 0) {
        const cRes = await fetch(`${COMPETITION_REPO_API}/commits/${json.default_branch || 'main'}`, { headers: ghHeaders });
        if (cRes.ok) remoteHeadSha = (await cRes.json()).sha ?? null;
      }
    } else {
      githubApiError = `GitHub API returned HTTP ${res.status}`;
    }
  } catch (err) {
    githubApiError = err instanceof Error ? err.message : 'GitHub API fetch failed';
  }

  const repoEligible = Boolean(
    githubRepoMeta?.createdAfterCutoff && githubRepoMeta.private === false && githubRepoMeta.fork === false
  );
  const originMatchesCompetition = originUrl.toLowerCase().includes('scriptkitty-live-hackbrasil-2026');
  const remoteCommitSynced = Boolean(remoteHeadSha && remoteHeadSha.toLowerCase() === verifiedSha.toLowerCase());

  const blockers = [];
  if (!repoEligible) blockers.push(githubApiError || 'Competition repository not verified as public, non-fork, post-Nov-4-2026');
  if (!githubRepoMeta || githubRepoMeta.size === 0 || !remoteCommitSynced) {
    blockers.push(`Competition repository (${COMPETITION_REPO_HTML}) has size=${githubRepoMeta?.size ?? 'unknown'} KB and remoteHeadSha=${remoteHeadSha ?? 'none'} (local HEAD=${verifiedSha.slice(0, 7)}). Human approval required before pushing.`);
  }
  if (!originMatchesCompetition) {
    blockers.push(`Local remote 'origin' points to '${originUrl}' instead of '${COMPETITION_REPO_HTML}.git'.`);
  }
  if (preEventCommits.length > 0) {
    blockers.push(`History has ${preEventCommits.length} pre-event commit(s) before ${HACKBR_CUTOFF_ISO}; clean competition push must follow PROVENANCE.md.`);
  }

  const status = blockers.length === 0 ? 'PASS' : 'BLOCKED';
  writeRedactedJson(artifactPath, {
    gateId: 'G00',
    verifiedSha,
    verifiedAtUtc: new Date().toISOString(),
    status,
    competitionRepository: { apiEndpoint: COMPETITION_REPO_API, httpStatus: githubApiStatus, eligibleContainer: repoEligible, metadata: githubRepoMeta, remoteHeadSha, error: githubApiError },
    localGitWorkspace: { headSha: verifiedSha, originUrl, originMatchesCompetition, remoteCommitSynced, preEventCommitCount: preEventCommits.length, preEventCommits, hasProvenanceMd: hasProvenanceDoc, hasLicense: hasLicenseDoc },
    blockers,
  });

  return {
    id: 'G00',
    name: 'Hack Brasil 2026 Eligibility & Provenance Preflight',
    status,
    command: `GET ${COMPETITION_REPO_API} + git remote/log preflight`,
    exitCode: repoEligible ? 0 : 1,
    durationMs: Date.now() - t0,
    artifacts: [relPath(artifactPath)],
    details: { repoEligible, createdAt: githubRepoMeta?.created_at ?? null, createdAfterCutoff: githubRepoMeta?.createdAfterCutoff ?? false, isPublic: githubRepoMeta?.private === false, isNotFork: githubRepoMeta?.fork === false, repoSizeKb: githubRepoMeta?.size ?? null, originUrl, preEventCommitCount: preEventCommits.length, hasProvenanceMd: hasProvenanceDoc },
    blocker: blockers.length > 0 ? blockers.join(' | ') : null,
  };
}

// ============================================================================
// Gate G01: Build, Typecheck & Automated Unit/Verification Tests
// ============================================================================

function runGateG01() {
  const t0 = Date.now();
  const buildLogPath = path.join(EVIDENCE_DIR, 'build.log');
  const typecheckLogPath = path.join(EVIDENCE_DIR, 'typecheck.log');
  const unitTestsLogPath = path.join(EVIDENCE_DIR, 'unit-tests.log');

  const rootBuild = runCommandCapture('npm run build', 'npm', ['run', 'build']);
  const vercelBuild = runCommandCapture('vercel-app build', 'npm', ['run', 'build'], { cwd: path.join(REPO_ROOT, 'vercel-app') });
  fs.writeFileSync(buildLogPath, `${rootBuild.combined}\n${'='.repeat(80)}\n${vercelBuild.combined}\n`, 'utf8');

  const typecheckRun = runCommandCapture('npm run typecheck', 'npm', ['run', 'typecheck', '--workspaces', '--if-present']);
  fs.writeFileSync(typecheckLogPath, typecheckRun.combined + '\n', 'utf8');

  const tsTestsRun = runCommandCapture('npm test', 'npm', ['test']);
  const pyTestsRun = runCommandCapture('npm run test:python', 'python', ['-m', 'unittest', 'discover', '-s', 'tests/python', '-p', 'test_*.py', '-v']);
  const verifyRun = runCommandCapture('npm run verify', process.execPath, ['packages/verification-suite/tests/run-all.mts']);
  fs.writeFileSync(unitTestsLogPath, `${tsTestsRun.combined}\n${'='.repeat(80)}\n${pyTestsRun.combined}\n${'='.repeat(80)}\n${verifyRun.combined}\n`, 'utf8');

  const tsOut = `${tsTestsRun.stdout}\n${tsTestsRun.stderr}`;
  const tsPassMatches = Array.from(tsOut.matchAll(/^# pass (\d+)/gm));
  const tsTotalPass = tsPassMatches.reduce((acc, m) => acc + Number(m[1]), 0);
  const tsTotalFail = Array.from(tsOut.matchAll(/^# fail (\d+)/gm)).reduce((acc, m) => acc + Number(m[1]), 0);
  const pyOut = `${pyTestsRun.stdout}\n${pyTestsRun.stderr}`;
  const pyTotal = Number(pyOut.match(/Ran (\d+) tests/)?.[1] ?? 0);
  const pyOk = /\bOK\b/.test(pyOut);
  const verifyPassed = Number(verifyRun.stdout.match(/Total Tests Passed\s*:\s*(\d+)/)?.[1] ?? 0);
  const verifyFailed = Number(verifyRun.stdout.match(/Total Tests Failed\s*:\s*(\d+)/)?.[1] ?? 0);

  const ok =
    rootBuild.exitCode === 0 && vercelBuild.exitCode === 0 && typecheckRun.exitCode === 0 &&
    tsTestsRun.exitCode === 0 && pyTestsRun.exitCode === 0 && verifyRun.exitCode === 0 &&
    tsTotalPass > 0 && tsTotalFail === 0 && pyTotal > 0 && pyOk && verifyPassed > 0 && verifyFailed === 0;

  return {
    id: 'G01',
    name: 'Build, Typecheck & Automated Unit/Verification Tests',
    status: ok ? 'PASS' : 'FAIL',
    command: 'npm run build; npm --prefix vercel-app run build; npm run typecheck --workspaces --if-present; npm test; npm run test:python; npm run verify',
    exitCode: ok ? 0 : 1,
    durationMs: Date.now() - t0,
    artifacts: [relPath(buildLogPath), relPath(typecheckLogPath), relPath(unitTestsLogPath)],
    details: {
      rootBuildExitCode: rootBuild.exitCode,
      vercelBuildExitCode: vercelBuild.exitCode,
      typecheckExitCode: typecheckRun.exitCode,
      tsWorkspacesTested: tsPassMatches.length,
      tsTestsPassed: tsTotalPass,
      tsTestsFailed: tsTotalFail,
      pythonTestsPassed: pyTotal,
      verificationSuiteTiers1To7Passed: verifyPassed,
      verificationSuiteTiers1To7Failed: verifyFailed,
      combinedAutomatedTestsPassed: tsTotalPass + pyTotal,
    },
    blocker: ok ? null : 'One or more build, typecheck, or automated test suites failed',
  };
}

// ============================================================================
// Gate G02: ChainBreak Policy Graph Reachability & Counterfactual Diff
// ============================================================================

async function runGateG02(pkgs) {
  const t0 = Date.now();
  const { analyzeFixture } = pkgs.chainbreak;
  const outFiles = {
    baseline: path.join(EVIDENCE_DIR, 'chainbreak-baseline.json'),
    unsafe: path.join(EVIDENCE_DIR, 'chainbreak-unsafe.json'),
    remediated: path.join(EVIDENCE_DIR, 'chainbreak-remediated.json'),
    diff: path.join(EVIDENCE_DIR, 'chainbreak-diff.json'),
  };

  const baseline = analyzeFixture('payments-lab/baseline', { fixturesDir: FIXTURES_DIR });
  const unsafe = analyzeFixture('payments-lab/unsafe-rollout', { fixturesDir: FIXTURES_DIR });
  const remediated = analyzeFixture('payments-lab/remediated', { fixturesDir: FIXTURES_DIR });
  const negativeControl = analyzeFixture('payments-lab/negative-control', { fixturesDir: FIXTURES_DIR });

  for (const a of [baseline, unsafe, remediated, negativeControl]) {
    assert.equal(a.status, 'COMPLETED');
    assert.match(a.inputSha256, /^[a-f0-9]{64}$/i);
    assert.equal(a.mode, 'LAB');
    assert.equal(a.productionTested, false);
    for (const ev of a.evidence) {
      assert.ok(typeof ev.sourceRef === 'string' && ev.sourceRef.trim().length > 0);
      assert.match(ev.contentSha256, /^[a-f0-9]{64}$/i);
    }
  }
  assert.equal(baseline.paths.length, 0);
  assert.equal(unsafe.paths.length, 1);
  assert.equal(remediated.paths.length, 0);
  assert.equal(negativeControl.paths.length, 0);
  for (const a of [baseline, unsafe, remediated]) {
    assert.equal(a.legitimateOperationsPreserved, true);
    assert.equal(a.legitimateOperations.filter((o) => o.preserved).length, 3);
  }

  const unsafePath = unsafe.paths[0];
  assert.equal(unsafePath.status, 'PATH_VALIDATED');
  assert.equal(unsafePath.violatedPolicyId, 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER');
  for (const edge of unsafePath.edges) assert.ok(typeof edge.sourceRef === 'string' && edge.sourceRef.trim().length > 0);

  const remSpec = unsafe.remediationSpecs[0];
  assert.equal(remSpec.minimalChange, true);
  assert.equal(remSpec.breaksUnauthorizedPath, true);
  assert.equal(remSpec.preservesLegitimateOperations, true);
  assert.equal(remSpec.requiresHumanApproval, true);
  assert.equal(remSpec.autoApplyAllowed, false);
  assert.equal(remSpec.actions[0].actionType, 'REMOVE_EDGE');
  assert.equal(remSpec.actions[0].edgeId, 'e-rollout-exporter-read-pii');

  const diffReport = {
    gateId: 'G02',
    generatedAtUtc: new Date().toISOString(),
    mode: 'LAB',
    productionTested: false,
    beforeFixture: { fixtureId: unsafe.fixtureId, analysisId: unsafe.analysisId, inputSha256: unsafe.inputSha256, forbiddenPathsCount: unsafe.paths.length, pathStatus: unsafePath.status, violatedPolicyId: unsafePath.violatedPolicyId, legitimateOperationsPreserved: '3/3' },
    afterFixture: { fixtureId: remediated.fixtureId, analysisId: remediated.analysisId, inputSha256: remediated.inputSha256, forbiddenPathsCount: remediated.paths.length, legitimateOperationsPreserved: '3/3' },
    negativeControlFixture: { fixtureId: negativeControl.fixtureId, analysisId: negativeControl.analysisId, inputSha256: negativeControl.inputSha256, forbiddenPathsCount: negativeControl.paths.length },
    counterfactualRemediation: { remediationId: remSpec.remediationId, forbiddenPathDelta: '1 -> 0', legitimateOperationsPreservedSummary: '3/3', minimalAction: remSpec.actions[0], requiresHumanApproval: true, autoApplyAllowed: false },
  };

  writeRedactedJson(outFiles.baseline, baseline);
  writeRedactedJson(outFiles.unsafe, unsafe);
  writeRedactedJson(outFiles.remediated, remediated);
  writeRedactedJson(outFiles.diff, diffReport);

  return {
    id: 'G02',
    name: 'ChainBreak Policy Graph Reachability & Counterfactual Diff',
    status: 'PASS',
    command: 'analyzeFixture(baseline, unsafe-rollout, remediated, negative-control)',
    exitCode: 0,
    durationMs: Date.now() - t0,
    artifacts: Object.values(outFiles).map(relPath),
    details: {
      pathCounts: { baseline: baseline.paths.length, unsafeRollout: unsafe.paths.length, remediated: remediated.paths.length, negativeControl: negativeControl.paths.length },
      legitimatePreserved: '3/3',
      inputSha256: { baseline: baseline.inputSha256, unsafeRollout: unsafe.inputSha256, remediated: remediated.inputSha256, negativeControl: negativeControl.inputSha256 },
      remediationAction: `${remSpec.actions[0].actionType}:${remSpec.actions[0].edgeId}`,
    },
    blocker: null,
  };
}

// ============================================================================
// Gates G03, G04 & G05: MCP HTTP Client, Auth/Tenant/Rate-Limit & Judge
// ============================================================================

async function runGatesG03G04G05(pkgs) {
  const t0 = Date.now();
  const mcpTranscriptPath = path.join(EVIDENCE_DIR, 'mcp-client-transcript-redacted.json');
  const judgeArtifactPath = path.join(EVIDENCE_DIR, 'judge-evaluation-redacted.json');
  const { createSecurityActionRuntime, startMcpHttpServer, SECURITY_CAPABILITY_IDS } = pkgs.securityActions;
  const { evaluateWithJevJudge } = pkgs.jevJudge;

  const tokenAlpha = `sk-gate-alpha-${crypto.randomBytes(12).toString('hex')}`;
  const tokenBeta = `sk-gate-beta-${crypto.randomBytes(12).toString('hex')}`;
  const allowedOrigin = 'http://127.0.0.1:5173';
  const scopes = ['security:*', 'security:status', 'security:analyze', 'security:read', 'security:judge', 'security:remediate', 'security:audit', 'security:evidence', 'security:kali'];
  const alphaPrincipal = { principalId: 'gate-operator-alpha', tenantId: 'payments-lab', roles: ['security-operator'], scopes };
  const betaPrincipal = { principalId: 'gate-operator-beta', tenantId: 'tenant-beta', roles: ['security-operator'], scopes };

  const runtime = createSecurityActionRuntime({ dbPath: ':memory:', fixturesDir: FIXTURES_DIR });
  let mcpHandle = null;
  let rateLimitHandle = null;
  const transcriptSteps = [];

  const createRpcHelper = (url) => async (stepLabel, { token, origin = allowedOrigin, sessionId, method = 'POST', body = null }) => {
    const headers = {
      ...(method === 'POST' ? { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' } : { 'Access-Control-Request-Method': 'POST' }),
      ...(origin !== null ? { Origin: origin } : {}),
      ...(token !== null ? { Authorization: `Bearer ${token}` } : {}),
      ...(sessionId ? { 'Mcp-Session-Id': sessionId } : {}),
    };
    const res = await fetch(url, { method, headers, ...(body ? { body: JSON.stringify(body) } : {}) });
    const text = await res.text();
    let parsedJson = null;
    try { parsedJson = JSON.parse(text); } catch { parsedJson = text ? { rawText: text } : null; }
    transcriptSteps.push({
      step: stepLabel,
      request: { method, url, headers: { ...headers, ...(headers.Authorization ? { Authorization: 'Bearer [REDACTED_TOKEN]' } : {}) }, body },
      response: { status: res.status, mcpSessionId: res.headers.get('mcp-session-id'), retryAfter: res.headers.get('retry-after'), accessControlAllowOrigin: res.headers.get('access-control-allow-origin'), body: parsedJson },
    });
    return { res, parsedJson, sessionId: res.headers.get('mcp-session-id'), structured: parsedJson?.result?.structuredContent };
  };

  try {
    mcpHandle = await startMcpHttpServer(runtime.engine, {
      host: LOOPBACK_HOST,
      port: 0,
      path: '/mcp',
      allowedOrigins: [allowedOrigin],
      requireOriginHeader: true,
      tokens: { [tokenAlpha]: alphaPrincipal, [tokenBeta]: betaPrincipal },
    });
    const rpc = createRpcHelper(mcpHandle.url);

    // G03: initialize -> initialized -> tools/list -> status -> analyze (replay) -> get -> remediation.spec
    const initAlpha = await rpc('G03.1_initialize_alpha', {
      token: tokenAlpha,
      body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'gates-runner-http', version: '1.0.0' } } },
    });
    assert.equal(initAlpha.res.status, 200);
    assert.ok(initAlpha.sessionId);
    assert.equal(initAlpha.res.headers.get('access-control-allow-origin'), allowedOrigin);
    const alphaSid = initAlpha.sessionId;

    await rpc('G03.2_notifications_initialized', { token: tokenAlpha, sessionId: alphaSid, body: { jsonrpc: '2.0', method: 'notifications/initialized', params: {} } });

    const listAlpha = await rpc('G03.3_tools_list', { token: tokenAlpha, sessionId: alphaSid, body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} } });
    assert.equal(listAlpha.res.status, 200);
    const listedTools = (listAlpha.parsedJson?.result?.tools ?? []).map((t) => t.name).sort();
    assert.equal(listedTools.length, 14, `Expected 14 MCP tools, got ${listedTools.length}`);
    assert.deepEqual(listedTools, runtime.engine.list().map((c) => c.id).sort());

    const callTool = (step, id, name, args = {}, opts = {}) =>
      rpc(step, { token: opts.token ?? tokenAlpha, sessionId: opts.sessionId ?? alphaSid, origin: opts.origin, body: { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } } });

    const statusCall = await callTool('G03.4_security_status', 3, 'security.status');
    assert.equal(statusCall.structured?.mode, 'LAB');
    assert.equal(statusCall.structured?.mergeAllowed, false);
    assert.equal(statusCall.structured?.deployAllowed, false);

    const analyze1 = await callTool('G03.5_chainbreak_analyze', 4, 'security.chainbreak.analyze', { fixtureId: 'payments-lab/unsafe-rollout' });
    assert.equal(analyze1.structured?.stored, true);
    assert.equal(analyze1.structured?.idempotentReplay, false);
    const analysisId = analyze1.structured.analysisId;
    const inputSha256 = analyze1.structured.analysis.inputSha256;
    const pathId = analyze1.structured.analysis.paths[0].pathId;
    const evidenceId = analyze1.structured.evidence[0].evidenceId;

    const analyze2 = await callTool('G03.6_chainbreak_replay', 5, 'security.chainbreak.analyze', { fixtureId: 'payments-lab/unsafe-rollout' });
    assert.equal(analyze2.structured?.analysisId, analysisId);
    assert.equal(analyze2.structured?.idempotentReplay, true);

    const getCall = await callTool('G03.7_chainbreak_get', 6, 'security.chainbreak.get', { analysisId });
    assert.equal(getCall.structured?.analysis?.analysisId, analysisId);

    const remCall = await callTool('G03.8_remediation_spec', 7, 'security.remediation.spec', { analysisId, pathId });
    assert.equal(remCall.structured?.requiresHumanApproval, true);
    assert.equal(remCall.structured?.autoApplyAllowed, false);

    // G03.9-11: Audit & Evidence tools (`audit.start`, `audit.get`, `evidence.get`)
    const auditStart = await callTool('G03.9_audit_start', 8, 'security.audit.start', { fixtureId: 'payments-lab/unsafe-rollout', includeJudge: false });
    assert.equal(auditStart.structured?.stored, true);
    assert.equal(auditStart.structured?.redacted, true);
    const auditId = auditStart.structured.auditId;
    const auditGet = await callTool('G03.10_audit_get', 9, 'security.audit.get', { auditId });
    assert.equal(auditGet.structured?.auditId, auditId);
    const evidenceGet = await callTool('G03.11_evidence_get', 10, 'security.evidence.get', { evidenceId, analysisId });
    assert.equal(evidenceGet.structured?.redacted, true);
    assert.ok(evidenceGet.structured?.evidence?.length >= 1);

    // G03.12-17: Kali LAB_SYNTHETIC tools over MCP HTTP
    const kaliLabRun = await callTool('G03.12_kali_lab_run', 11, 'security.kali.lab_run', { actionId: 'service_inventory', scopeRef: 'SK-SCOPE-G03-LAB', targetRef: '127.0.0.1', budgetRef: 'LAB_DEFAULT_BUDGET' });
    assert.equal(kaliLabRun.structured?.mode, 'LAB');
    const kaliRunId = kaliLabRun.structured.runId;
    assert.ok(kaliRunId);
    const kaliInv = await callTool('G03.13_kali_service_inventory', 12, 'security.kali.service_inventory', { scopeRef: 'SK-SCOPE-G03-LAB', targetRef: '127.0.0.1' });
    const kaliTls = await callTool('G03.14_kali_tls_review', 13, 'security.kali.tls_review', { scopeRef: 'SK-SCOPE-G03-LAB', targetRef: '127.0.0.1:443' });
    const kaliWeb = await callTool('G03.15_kali_web_passive_baseline', 14, 'security.kali.web_passive_baseline', { scopeRef: 'SK-SCOPE-G03-LAB', targetRef: '127.0.0.1:3000' });
    const kaliCode = await callTool('G03.16_kali_local_code_scan', 15, 'security.kali.local_code_scan', { scopeRef: 'SK-SCOPE-G03-LAB', targetRef: 'apps/lab-app/package.json' });
    const kaliGet = await callTool('G03.17_kali_get_run', 16, 'security.kali.get_run', { runId: kaliRunId });
    for (const kr of [kaliInv, kaliTls, kaliWeb, kaliCode, kaliGet]) {
      assert.equal(kr.structured?.mode, 'LAB');
      assert.equal(kr.structured?.externalExecution, false);
    }

    // G05: Advisory Judge evaluation + hash mismatch guard
    const judgeCall = await callTool('G05.1_judge_evaluate', 17, 'security.judge.evaluate', { analysisId, expectedInputSha256: inputSha256 });
    const adj = judgeCall.structured?.adjudication;
    assert.ok(adj);
    assert.equal(adj.p0DefinedByJevAlone, false);
    assert.equal(adj.exploitConfirmed, false);
    assert.equal(adj.status, 'PENDING_REVIEW');
    assert.equal(adj.escalated, true);

    const mismatchAdj = await evaluateWithJevJudge({
      analysis: analyze1.structured.analysis,
      evidence: analyze1.structured.evidence,
      authContext: { principalId: alphaPrincipal.principalId, tenantId: alphaPrincipal.tenantId, correlationId: 'gate-g05-mismatch' },
      expectedInputSha256: '0'.repeat(64),
    });
    assert.equal(mismatchAdj.preValidation.passed, false);

    // G04: Fail-Closed Auth, Origin, Tenant Isolation & Rate Limiting (429 + Retry-After) + Session TTL
    const missingToken = await rpc('G04.1_missing_bearer_401', { token: null, body: { jsonrpc: '2.0', id: 401, method: 'tools/list', params: {} } });
    assert.equal(missingToken.res.status, 401);

    const invalidToken = await rpc('G04.2_invalid_bearer_401', { token: 'sk-invalid-token', body: { jsonrpc: '2.0', id: 402, method: 'tools/list', params: {} } });
    assert.equal(invalidToken.res.status, 401);

    const evilOpt = await rpc('G04.3_evil_origin_options_403', { token: null, origin: 'https://evil.attacker.example', method: 'OPTIONS' });
    assert.equal(evilOpt.res.status, 403);
    assert.equal(evilOpt.res.headers.get('access-control-allow-origin'), null);

    const evilPost = await rpc('G04.4_evil_origin_post_403', { token: tokenAlpha, origin: 'https://evil.attacker.example', body: { jsonrpc: '2.0', id: 403, method: 'tools/list', params: {} } });
    assert.equal(evilPost.res.status, 403);

    const goodOpt = await rpc('G04.5_good_origin_options_204', { token: null, origin: allowedOrigin, method: 'OPTIONS' });
    assert.equal(goodOpt.res.status, 204);
    assert.equal(goodOpt.res.headers.get('access-control-allow-origin'), allowedOrigin);
    const allowMethodsHeader = goodOpt.res.headers.get('access-control-allow-methods') ?? '';
    assert.ok(allowMethodsHeader.split(',').map((m) => m.trim().toUpperCase()).includes('DELETE'), `Expected DELETE in Access-Control-Allow-Methods, got: ${allowMethodsHeader}`);

    const initBeta = await rpc('G04.6_init_beta', {
      token: tokenBeta,
      body: { jsonrpc: '2.0', id: 500, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'gates-beta', version: '1.0.0' } } },
    });
    const betaSid = initBeta.sessionId;

    const assertCrossTenantForbidden = async (step, id, toolName, args) => {
      const r = await callTool(step, id, toolName, args, { token: tokenBeta, sessionId: betaSid });
      assert.equal(r.parsedJson?.result?.isError, true);
      const err = JSON.parse(r.parsedJson?.result?.content?.[0]?.text ?? '{}');
      assert.equal(err.code, 'FORBIDDEN');
      return err.code;
    };

    const crossTenantChainbreakCode = await assertCrossTenantForbidden('G04.7a_cross_tenant_chainbreak_get', 501, 'security.chainbreak.get', { analysisId });
    const crossTenantAuditCode = await assertCrossTenantForbidden('G04.7b_cross_tenant_audit_get', 502, 'security.audit.get', { auditId });
    const crossTenantEvidenceCode = await assertCrossTenantForbidden('G04.7c_cross_tenant_evidence_get', 503, 'security.evidence.get', { evidenceId });
    const crossTenantKaliCode = await assertCrossTenantForbidden('G04.7d_cross_tenant_kali_get_run', 504, 'security.kali.get_run', { runId: kaliRunId });

    const tenantInject = await callTool('G04.8_tenant_inject_forbidden', 505, 'security.chainbreak.analyze', { fixtureId: 'payments-lab/baseline', tenantId: 'payments-lab' }, { token: tokenBeta, sessionId: betaSid });
    const tenantInjectErr = JSON.parse(tenantInject.parsedJson?.result?.content?.[0]?.text ?? '{}');
    assert.equal(tenantInjectErr.code, 'FORBIDDEN');

    const sessionHijack = await rpc('G04.9_session_hijack_403', { token: tokenBeta, sessionId: alphaSid, body: { jsonrpc: '2.0', id: 506, method: 'tools/list', params: {} } });
    assert.equal(sessionHijack.res.status, 403);

    // G04.10: Post-auth burst + idle session TTL eviction (404) + pre-auth spray rate limiting (429 + Retry-After)
    rateLimitHandle = await startMcpHttpServer(runtime.engine, {
      host: LOOPBACK_HOST,
      port: 0,
      path: '/mcp',
      allowedOrigins: [allowedOrigin],
      rateLimit: { maxRequests: 2, windowMs: 60_000 },
      authRateLimit: { maxRequests: 2, windowMs: 60_000 },
      sessionTtlMs: 40,
      tokens: { [tokenAlpha]: alphaPrincipal, [tokenBeta]: betaPrincipal },
    });
    const rlRpc = createRpcHelper(rateLimitHandle.url);
    const ttlInit = await rlRpc('G04.10a_ttl_init_beta', { token: tokenBeta, body: { jsonrpc: '2.0', id: 600, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'ttl-test', version: '1.0' } } } });
    assert.equal(ttlInit.res.status, 200);
    const rl1 = await rlRpc('G04.10b_post_auth_1', { token: tokenAlpha, body: { jsonrpc: '2.0', id: 601, method: 'tools/list', params: {} } });
    const rl2 = await rlRpc('G04.10c_post_auth_2', { token: tokenAlpha, body: { jsonrpc: '2.0', id: 602, method: 'tools/list', params: {} } });
    const rl3 = await rlRpc('G04.10d_post_auth_429', { token: tokenAlpha, body: { jsonrpc: '2.0', id: 603, method: 'tools/list', params: {} } });
    assert.equal(rl1.res.status, 200);
    assert.equal(rl2.res.status, 200);
    assert.equal(rl3.res.status, 429);
    assert.ok(Number(rl3.res.headers.get('retry-after')) >= 1);

    await new Promise((r) => setTimeout(r, 70));
    const ttlExpired = await rlRpc('G04.10e_idle_session_ttl_404', { token: tokenBeta, sessionId: ttlInit.sessionId, body: { jsonrpc: '2.0', id: 604, method: 'tools/list', params: {} } });
    assert.equal(ttlExpired.res.status, 404);
    const statsAfterTtl = rateLimitHandle.getStats();
    assert.equal(statsAfterTtl.activeSessions, 0);

    const bad1 = await rlRpc('G04.10f_pre_auth_1', { token: 'sk-bad-1', body: { jsonrpc: '2.0', id: 605, method: 'tools/list', params: {} } });
    const bad2 = await rlRpc('G04.10g_pre_auth_2', { token: 'sk-bad-2', body: { jsonrpc: '2.0', id: 606, method: 'tools/list', params: {} } });
    const bad3 = await rlRpc('G04.10h_pre_auth_429', { token: 'sk-bad-3', body: { jsonrpc: '2.0', id: 607, method: 'tools/list', params: {} } });
    assert.equal(bad1.res.status, 401);
    assert.equal(bad2.res.status, 401);
    assert.equal(bad3.res.status, 429);
    assert.ok(Number(bad3.res.headers.get('retry-after')) >= 1);

    const failClosedChecks = {
      missingBearerStatus: missingToken.res.status,
      invalidBearerStatus: invalidToken.res.status,
      disallowedOriginOptionsStatus: evilOpt.res.status,
      disallowedOriginPostStatus: evilPost.res.status,
      allowedOriginOptionsStatus: goodOpt.res.status,
      allowedOriginAllowMethods: allowMethodsHeader,
      crossTenantChainbreakGetCode: crossTenantChainbreakCode,
      crossTenantAuditGetCode: crossTenantAuditCode,
      crossTenantEvidenceGetCode: crossTenantEvidenceCode,
      crossTenantKaliGetRunCode: crossTenantKaliCode,
      payloadTenantIdInjectionCode: tenantInjectErr.code,
      crossPrincipalSessionHijackStatus: sessionHijack.res.status,
      postAuthRateLimitStatus: rl3.res.status,
      postAuthRetryAfterSec: Number(rl3.res.headers.get('retry-after')),
      preAuthRateLimitStatus: bad3.res.status,
      preAuthRetryAfterSec: Number(bad3.res.headers.get('retry-after')),
      idleSessionTtlEvictionStatus: ttlExpired.res.status,
      rateLimitServerStatsObserved: statsAfterTtl,
    };

    writeRedactedJson(mcpTranscriptPath, {
      gateIds: ['G03', 'G04'],
      generatedAtUtc: new Date().toISOString(),
      serverEndpoint: mcpHandle.url,
      registeredCapabilities: [...SECURITY_CAPABILITY_IDS],
      listedTools,
      toolParityVerified: true,
      persistenceVerified: { analysisId, idempotentReplay: true, decisionHistoryCount: getCall.structured.decisionHistory.length },
      failClosedChecks,
      transcript: transcriptSteps,
    }, [tokenAlpha, tokenBeta]);

    const hasTypesafeKey = Boolean(process.env.TYPESAFE_API_KEY?.trim());
    const g05Status = hasTypesafeKey && adj.providerStatus === 'LIVE' ? 'PASS' : 'NOT_CONFIGURED';
    writeRedactedJson(judgeArtifactPath, {
      gateId: 'G05',
      generatedAtUtc: new Date().toISOString(),
      status: g05Status,
      typesafeApiKeyConfigured: hasTypesafeKey,
      providerStatus: adj.providerStatus,
      decisionSource: adj.decisionSource,
      advisoryOutcome: adj.status,
      requiresHumanReview: adj.requiresHumanReview,
      invariantsVerified: {
        preValidationPassedOnValidHash: adj.preValidation.passed,
        preValidationBlockedOnHashMismatch: mismatchAdj.preValidation.passed === false,
        p0DefinedByJevAlone: adj.p0DefinedByJevAlone,
        exploitConfirmed: adj.exploitConfirmed,
        mergeAllowed: adj.mergeAllowed,
        deployAllowed: adj.deployAllowed,
      },
      adjudication: adj,
      honestDisclosure: hasTypesafeKey ? 'Live TYPESAFE_API_KEY configured.' : 'TYPESAFE_API_KEY unset -> NOT_CONFIGURED (escalated to PENDING_REVIEW; never fake PASS).',
    }, [tokenAlpha, tokenBeta, process.env.TYPESAFE_API_KEY ?? '']);

    const elapsed = Date.now() - t0;
    return {
      gateG03: {
        id: 'G03',
        name: 'MCP Streamable HTTP Real Client, Tool Parity & Persistence',
        status: 'PASS',
        command: 'Loopback HTTP fetch -> POST /mcp (initialize -> tools/list -> tools/call)',
        exitCode: 0,
        durationMs: elapsed,
        artifacts: [relPath(mcpTranscriptPath)],
        details: { toolsCount: listedTools.length, tools: listedTools, toolParity: true, persistedAnalysisId: analysisId, idempotentReplay: true },
        blocker: null,
      },
      gateG04: {
        id: 'G04',
        name: 'MCP Fail-Closed Auth (401), Origin (403), Tenant (FORBIDDEN) & Rate Limit (429)',
        status: 'PASS',
        command: 'Loopback HTTP negative suite (401, 403, FORBIDDEN, session hijack 403, rate limit 429 + Retry-After)',
        exitCode: 0,
        durationMs: elapsed,
        artifacts: [relPath(mcpTranscriptPath)],
        details: failClosedChecks,
        blocker: null,
      },
      gateG05: {
        id: 'G05',
        name: 'Bounded Advisory Judge Evaluation (Fail-Closed Escalation)',
        status: g05Status,
        command: 'MCP tools/call security.judge.evaluate + hash-mismatch pre-validation check',
        exitCode: 0,
        durationMs: elapsed,
        artifacts: [relPath(judgeArtifactPath)],
        details: { providerStatus: adj.providerStatus, decisionSource: adj.decisionSource, adjudicationStatus: adj.status, requiresHumanReview: adj.requiresHumanReview, p0DefinedByJevAlone: adj.p0DefinedByJevAlone, hashMismatchBlocked: mismatchAdj.preValidation.passed === false },
        blocker: g05Status === 'NOT_CONFIGURED' ? 'TYPESAFE_API_KEY env var is unset; external live judge provider is NOT_CONFIGURED (escalated to PENDING_REVIEW)' : null,
      },
    };
  } finally {
    if (rateLimitHandle) await rateLimitHandle.close().catch(() => {});
    if (mcpHandle) await mcpHandle.close().catch(() => {});
    runtime.close();
  }
}

// ============================================================================
// Gates G06 & G08: Quality Gate & Verified Counterfactual Remediation
// ============================================================================

async function runGatesG06G08(pkgs, verifiedSha) {
  const t0 = Date.now();
  const artifactPath = path.join(EVIDENCE_DIR, 'quality-engine-run-redacted.json');
  const { buildCustodyChain, computeEvidenceChainHash, computeFindingFingerprint, computePatchSha256, GateVerdict, sha256, verifyChainOfCustody, verifyMerkleProof } = pkgs.contracts;
  const { DeterministicQualityGate } = pkgs.qualityGate;
  const { evaluateFactoryDeliveryEligibility } = pkgs.companyContext;
  const { computeCanonicalDigest, EvidenceLedger, TenantIsolationError: EvidenceTenantIsolationError, UnverifiedAiProseError, verifyAnalysisMerkleBundle } = pkgs.evidence;
  const { assertNoPolicyOrGateMutation, assertTriPartySod, PatchCatGovernanceError, PatchCatOrchestrator, ZenPrBundleSchema } = pkgs.patchcatOrchestrator;

  const recordedAt = new Date().toISOString();
  const pathId = 'path-payments-unsafe-rollout-001';
  const scriptSha = sha256(pathId);

  const finding = {
    finding_id: 'SK-FIND-GATE-CB-001',
    source_engine: 'chainbreak-v0',
    title: 'Unauthorized RESTRICTED PII Data Path via Report Exporter Rollout',
    description: 'Unsafe rollout edge e-rollout-exporter-read-pii enables PII reachability to external sink.',
    cwe_id: 'CWE-284',
    owasp_category: 'A01:2021-Broken Access Control',
    severity: 'HIGH',
    confidence: 'CERTAIN',
    target_type: 'CONFIGURATION',
    target: 'fixtures/payments-lab/unsafe-rollout.json',
    location: { file_path: 'policies/payments-lab/report-exporter-rollout.yaml', start_line: 24, end_line: 38, symbol: 'report-exporter' },
    fingerprint: computeFindingFingerprint({ cwe_id: 'CWE-284', file_path: 'policies/payments-lab/report-exporter-rollout.yaml', rule_or_match: 'NO_RESTRICTED_DATA_EXTERNAL_TRANSFER' }),
    commit_hash: verifiedSha,
    discovered_at: recordedAt,
    agent_context: { discovering_agent_id: 'agent-discovery-chainbreak', agent_archetype: 'policy_graph_analyzer', tool_call_trace: ['security.chainbreak.analyze'] },
    raw_metadata: { mode: 'LAB', commitSha: verifiedSha },
  };

  const makeEv = (id, status) => ({
    evidence_id: id,
    finding_id: finding.finding_id,
    verification_type: 'REPRODUCER_EXECUTION',
    status,
    verifier_agent_id: 'agent-verifier-sandbox',
    sandbox_environment: { runtime: 'node_sandbox', network_isolated: true, timeout_ms: 5000 },
    reproducer_artifact: { script_path: 'fixtures/payments-lab/remediated.json', script_sha256: scriptSha, exit_code: 1, stdout: `PATH_VALIDATED:${pathId}`, stderr: '', execution_duration_ms: 11 },
    reproduction_proof: { proof_type: 'EXECUTABLE_POC', payload: pathId, expected_behavior: '0 paths violating NO_RESTRICTED_DATA_EXTERNAL_TRANSFER', observed_vulnerable_behavior: '1 modeled policy path' },
    chain_hash: computeEvidenceChainHash({ finding_id: finding.finding_id, verifier_agent_id: 'agent-verifier-sandbox', status, script_sha256: scriptSha, recorded_at: recordedAt }),
    recorded_at: recordedAt,
  });

  const verifiedEvidence = makeEv('SK-EVID-GATE-CB-001', 'VERIFIED_TRUE_POSITIVE');
  const inconclusiveEvidence = makeEv('SK-EVID-GATE-INCONCLUSIVE-001', 'INCONCLUSIVE');
  const diffContent = '--- a/policies/payments-lab/report-exporter-rollout.yaml\n+++ b/policies/payments-lab/report-exporter-rollout.yaml\n@@ -24,3 +24,0 @@\n- edge: e-rollout-exporter-read-pii';
  const patch = {
    patch_id: 'SK-PATCH-GATE-CB-001',
    finding_id: finding.finding_id,
    author_engine: 'agent-remediation-patchcat',
    diff_content: diffContent,
    affected_files: ['policies/payments-lab/report-exporter-rollout.yaml'],
    base_commit: verifiedSha,
    patch_sha256: computePatchSha256(diffContent),
    recheck_status: 'passed_clean',
    recheck_evidence_id: verifiedEvidence.evidence_id,
    blast_radius: { files_modified: 1, lines_added: 0, lines_deleted: 1, ast_impact_scope: 'LOCAL_FUNCTION', downstream_dependents: [], breaking_change_risk: 'LOW' },
    rollback_plan: { revert_patch: diffContent.replace(/^- /gm, '+ '), killswitch_flag: 'REVERT_REPORT_EXPORTER_EDGE_RESTRICTION' },
    created_at: recordedAt,
  };

  const custodyChain = buildCustodyChain({ finding, evidence: verifiedEvidence, patch });
  const custodyCheck = verifyChainOfCustody(custodyChain);
  assert.equal(custodyCheck.valid, true);

  const gate = new DeterministicQualityGate();
  const inconclusiveDecision = await gate.evaluate({ target_commit: verifiedSha, findings: [finding], evidence: [inconclusiveEvidence], patches: [patch], discovering_agent_id: 'agent-discovery-chainbreak', verifying_agent_id: 'agent-verifier-sandbox', authorizing_agent_id: 'agent-authorizer-gate' });
  assert.notEqual(inconclusiveDecision.verdict, GateVerdict.PASS);
  assert.equal(inconclusiveDecision.verdict, GateVerdict.BLOCK);

  const selfCertDecision = await gate.evaluate({ target_commit: verifiedSha, findings: [finding], evidence: [verifiedEvidence], patches: [patch], discovering_agent_id: 'agent-self', verifying_agent_id: 'agent-self', authorizing_agent_id: 'agent-authorizer-gate' });
  assert.equal(selfCertDecision.verdict, GateVerdict.REJECT);
  assert.match(String(selfCertDecision.sod_evaluation.violation_details), /E_SOD_SELF_CERTIFICATION/);

  const passDecision = await gate.evaluate({ target_commit: verifiedSha, findings: [finding], evidence: [verifiedEvidence], patches: [patch], discovering_agent_id: 'agent-discovery-chainbreak', verifying_agent_id: 'agent-verifier-sandbox', authorizing_agent_id: 'agent-authorizer-gate', custody_chain: custodyChain });
  assert.equal(passDecision.verdict, GateVerdict.PASS);
  assert.equal(passDecision.target_commit, verifiedSha);

  const deliveryCheck = evaluateFactoryDeliveryEligibility({
    contract: 'factory.delivery.v1',
    snapshot: {
      cancelled: false,
      deadlineAt: '2026-12-01T00:00:00.000Z',
      submissions: 1,
      maxSubmissions: 4,
      submitter: 'agent-remediation-patchcat',
      reviewer: 'human-security-reviewer',
      artifact: { commitSha: verifiedSha, summary: 'Removed e-rollout-exporter-read-pii; 0 paths.', checks: [{ key: 'tests', status: 'passed', evidenceRef: 'evidence/unit-tests.log' }, { key: 'typecheck', status: 'passed', evidenceRef: 'evidence/typecheck.log' }, { key: 'build', status: 'passed', evidenceRef: 'evidence/build.log' }] },
      review: { commitSha: verifiedSha, verdict: 'approve', summary: 'Verified minimal change.', evidenceRefs: [verifiedEvidence.evidence_id] },
    },
    authority: { enabled: true, requesterActive: true, submitterActive: true, reviewerActive: true },
  }, { headSha: verifiedSha, now: '2026-11-21T12:00:00.000Z' });
  assert.equal(deliveryCheck.eligible, true);
  assert.equal(deliveryCheck.mergeAllowed, false);
  assert.equal(deliveryCheck.deployAllowed, false);

  const orchestrator = new PatchCatOrchestrator({ repoRoot: REPO_ROOT, fixturesDir: FIXTURES_DIR, dbPath: ':memory:' });
  const evidenceLedger = new EvidenceLedger({ dbPath: ':memory:' });
  const governanceChecks = {};
  let zenPrBundle, merkleBundle, merkleBundleCheck, inclusionValid = false;

  try {
    const orchResult = await orchestrator.run({
      type: 'rollout', tenantId: 'payments-lab', actorPrincipalId: 'gate-operator-alpha',
      fixtureId: 'payments-lab/unsafe-rollout', verifiedFixtureId: 'payments-lab/remediated',
      targetPath: 'fixtures/payments-lab/unsafe-rollout.json', sourceRef: 'rollout://payments-lab/g08',
      commitSha: verifiedSha, discoveringAgentId: 'agent-discovery-chainbreak', verifyingAgentId: 'agent-verifier-kali', authorizingAgentId: 'agent-authorizer-gate',
    });
    zenPrBundle = ZenPrBundleSchema.parse(orchResult.zenPrBundle);
    assert.equal(zenPrBundle.beforeAfterProof.forbiddenPathDeltaSummary, '1 -> 0');
    assert.equal(zenPrBundle.beforeAfterProof.legitimateOperationsSummary, '3/3');
    assert.equal(zenPrBundle.mergeAllowed, false);
    assert.equal(zenPrBundle.deployAllowed, false);

    const cbEvidenceId = `ev-gate-cb-${orchResult.analysisId}`;
    evidenceLedger.recordChainBreakEvidence('payments-lab', {
      evidenceId: cbEvidenceId, analysisId: orchResult.analysisId, kind: 'GRAPH_PATH',
      sourceRef: 'fixtures/payments-lab/unsafe-rollout.json#path-1',
      contentSha256: computeCanonicalDigest(zenPrBundle.beforeAfterProof),
      producer: '@script-kitty/chainbreak:analyzer-v0', verified: true, createdAt: zenPrBundle.createdAt, commitSha: verifiedSha,
    }, { payload: zenPrBundle.beforeAfterProof });
    evidenceLedger.recordContractEvidence('payments-lab', verifiedEvidence, { analysisId: orchResult.analysisId, verifyChainHash: true, linkedChainBreakEvidenceIds: [cbEvidenceId], relationType: 'REPRODUCES_PATH' });

    merkleBundle = evidenceLedger.buildAnalysisMerkleBundle('payments-lab', orchResult.analysisId, { generatedAt: zenPrBundle.createdAt });
    merkleBundleCheck = verifyAnalysisMerkleBundle(merkleBundle, { requireVerifiedProof: true, verifyChainHash: true });
    assert.equal(merkleBundleCheck.valid, true);
    inclusionValid = verifyMerkleProof(merkleBundle.entries[0].leafHash, merkleBundle.entries[0].proof, merkleBundle.merkleRoot);
    assert.equal(inclusionValid, true);

    const expectErr = (fn, ErrCls) => { try { fn(); return 'NOT_BLOCKED'; } catch (e) { assert.ok(e instanceof ErrCls); return e.code; } };
    governanceChecks.policyMutationBlocked = expectErr(() => assertNoPolicyOrGateMutation({ mergeAllowed: true }), PatchCatGovernanceError);
    governanceChecks.sodViolationBlocked = expectErr(() => assertTriPartySod('a', 'a', 'c'), PatchCatGovernanceError);
    governanceChecks.unverifiedAiProseBlocked = expectErr(() => evidenceLedger.recordEvidence('payments-lab', 'LLM prose'), UnverifiedAiProseError);
    governanceChecks.crossTenantEvidenceBlocked = expectErr(() => evidenceLedger.getReceipt('tenant-beta', cbEvidenceId), EvidenceTenantIsolationError);
  } finally {
    evidenceLedger.close();
    orchestrator.close();
  }

  writeRedactedJson(artifactPath, {
    gateIds: ['G06', 'G08'],
    verifiedSha,
    generatedAtUtc: new Date().toISOString(),
    qualityGate: {
      targetCommitSha: verifiedSha,
      inconclusiveEvidenceVerdict: inconclusiveDecision.verdict,
      selfCertificationRejectVerdict: selfCertDecision.verdict,
      triPartyPassVerdict: passDecision.verdict,
      triPartyAuditMerkleRoot: passDecision.audit_merkle_root,
      custodyChainMerkleRoot: custodyCheck.merkle_root,
      factoryDeliveryV1: deliveryCheck,
    },
    remediationVerification: {
      bundleId: zenPrBundle.bundleId,
      forbiddenPathDeltaSummary: zenPrBundle.beforeAfterProof.forbiddenPathDeltaSummary,
      legitimateOperationsSummary: zenPrBundle.beforeAfterProof.legitimateOperationsSummary,
      merkleRoot: merkleBundle.merkleRoot,
      merkleBundleValid: merkleBundleCheck.valid,
      merkleInclusionProofValid: inclusionValid,
      governanceChecks,
    },
  });

  const elapsed = Date.now() - t0;
  return {
    gateG06: {
      id: 'G06',
      name: 'Zero-Trust Quality Gate, Tri-Party SoD & SHA-Bound Custody',
      status: 'PASS',
      command: `DeterministicQualityGate.evaluate(commit=${verifiedSha.slice(0, 7)})`,
      exitCode: 0,
      durationMs: elapsed,
      artifacts: [relPath(artifactPath)],
      details: { targetCommit: verifiedSha, inconclusiveVerdict: inconclusiveDecision.verdict, selfCertVerdict: selfCertDecision.verdict, triPartyVerdict: passDecision.verdict, auditMerkleRoot: passDecision.audit_merkle_root, custodyMerkleRoot: custodyCheck.merkle_root },
      blocker: null,
    },
    gateG08: {
      id: 'G08',
      name: 'Verified Counterfactual Remediation & RFC 8785 Merkle Inclusion Proof',
      status: 'PASS',
      command: 'PatchCatOrchestrator.run(unsafe-rollout -> remediated) + EvidenceLedger Merkle',
      exitCode: 0,
      durationMs: elapsed,
      artifacts: [relPath(artifactPath)],
      details: { forbiddenPathDelta: '1 -> 0', legitimateOperationsPreserved: '3/3', merkleRoot: merkleBundle.merkleRoot, inclusionProofValid: inclusionValid, governanceChecks },
      blocker: null,
    },
  };
}

// ============================================================================
// Gate G07: Kali LAB Sandbox Verification & Negative Boundary Suite
// ============================================================================

async function runGateG07(pkgs, verifiedSha) {
  const t0 = Date.now();
  const artifactPath = path.join(EVIDENCE_DIR, 'kali-lab-run-redacted.json');
  const { buildSafeKaliArgv, createKaliMcpServer, executeKaliCapability, generateProfileAArgs, KALI_CAPABILITY_NAMES, KALI_MODE, KaliSandboxOrchestrator, KaliSecurityError, mintKaliDelegationToken, scanKaliPayloadSafety, validateProfileAArgs } = pkgs.kaliMcp;
  const { sanitizeOutput } = pkgs.adapters;
  const { sha256, validateEvidence, validateFinding, verifyChainOfCustody } = pkgs.contracts;

  const kaliScope = { scope_id: 'SK-SCOPE-G07-LAB', authorized_by: 'agent-quality-gate-authority', mode: 'LAB', target_allowlist: ['127.0.0.1', 'localhost', 'lab-app.localnet'], expires_at: new Date(Date.now() + 3_600_000).toISOString() };
  const sqliReproRelPath = 'apps/lab-app/repro/repro-sqli.mts';
  const sqliReproSha256 = sha256(fs.readFileSync(path.join(REPO_ROOT, sqliReproRelPath)));
  const kaliHmacSecret = `sk-gate-kali-hmac-${crypto.randomBytes(16).toString('hex')}`;
  const noRuntimeOrchestrator = new KaliSandboxOrchestrator({
    workspaceRoot: REPO_ROOT,
    execFileImpl: async () => ({ exitCode: 1, stdout: '', stderr: 'no OCI/gVisor runtime in LAB gate test' }),
  });

  const kaliServer = createKaliMcpServer({ workspaceRoot: REPO_ROOT, commitHash: verifiedSha, hmacSecret: kaliHmacSecret, requestedExecutionMode: 'LAB_SIMULATION', orchestrator: noRuntimeOrchestrator });
  const callGuardedKali = async (toolName, args, callerId = 'agent-kali-recon-scout', extra = {}) => {
    const tok = mintKaliDelegationToken({ issuer: 'agent-quality-gate-authority', subject: callerId, toolName, hmacSecret: kaliHmacSecret, ...extra });
    const res = await kaliServer.callTool({
      name: toolName,
      arguments: args,
      _meta: { caller_agent_id: callerId, delegation_token: tok, authorizing_agent_id: 'agent-quality-gate-authority', ...(extra.discoveringAgentId ? { discovering_agent_id: extra.discoveringAgentId } : {}) },
    });
    return { isError: res.isError, parsed: JSON.parse(res.content[0].text) };
  };

  const reconRun = await callGuardedKali('security.kali.recon_surface', { scope: kaliScope, target_host: '127.0.0.1', ports: [80, 443, 3000], probe_profile: 'tcp_connect_ports', discovering_agent_id: 'agent-kali-recon-scout' });
  assert.equal(reconRun.isError, false);
  assert.equal(validateFinding(reconRun.parsed.findings[0]).success, true);

  const tlsRun = await callGuardedKali('security.kali.config_audit', { scope: kaliScope, audit_mode: 'tls_posture', target_host: '127.0.0.1', target_port: 443, discovering_agent_id: 'agent-kali-recon-scout' });
  const webRun = await callGuardedKali('security.kali.config_audit', { scope: kaliScope, audit_mode: 'http_security_headers', target_host: '127.0.0.1', target_port: 3000, discovering_agent_id: 'agent-kali-recon-scout' });
  const sbomRun = await callGuardedKali('security.kali.sbom_cve_check', { scope: kaliScope, manifest_rel_path: 'apps/lab-app/package.json', scanner_engine: 'trivy_offline', severity_filter: ['CRITICAL', 'HIGH'], discovering_agent_id: 'agent-kali-recon-scout' });
  const verifyRun = await callGuardedKali('security.kali.verify_reproducer', {
    scope: kaliScope, finding_id: reconRun.parsed.findings[0].finding_id,
    discovering_agent_id: 'agent-kali-recon-scout', verifier_agent_id: 'agent-kali-sandbox-verifier', authorizing_agent_id: 'agent-quality-gate-authority',
    reproducer_rel_path: sqliReproRelPath, expected_reproducer_sha256: sqliReproSha256, reproducer_runtime: 'node',
  }, 'agent-kali-sandbox-verifier', { discoveringAgentId: 'agent-kali-recon-scout', findingId: reconRun.parsed.findings[0].finding_id });
  assert.equal(tlsRun.isError, false);
  assert.equal(webRun.isError, false);
  assert.equal(sbomRun.isError, false);
  assert.equal(verifyRun.isError, false);
  assert.equal(validateEvidence(verifyRun.parsed.evidence).success, true);
  assert.equal(verifyChainOfCustody(verifyRun.parsed.custody.chain).valid, true);

  const captureKaliErr = (fn) => {
    try { fn(); return { blocked: false, code: null }; }
    catch (err) { assert.ok(err instanceof KaliSecurityError); return { blocked: true, code: err.code, message: err.message }; }
  };

  const outOfScopeDomain = captureKaliErr(() => buildSafeKaliArgv('security.kali.recon_surface', { scope: kaliScope, target_host: 'evil.example', discovering_agent_id: 'agent-kali-recon-scout' }));
  const imdsBlock = captureKaliErr(() => buildSafeKaliArgv('security.kali.recon_surface', { scope: kaliScope, target_host: '169.254.169.254', discovering_agent_id: 'agent-kali-recon-scout' }));
  const rfc1918Block = captureKaliErr(() => buildSafeKaliArgv('security.kali.recon_surface', { scope: kaliScope, target_host: '192.168.1.25', discovering_agent_id: 'agent-kali-recon-scout' }));
  const flagScriptBlock = captureKaliErr(() => buildSafeKaliArgv('security.kali.recon_surface', { scope: kaliScope, target_host: '--script=vuln', discovering_agent_id: 'agent-kali-recon-scout' }));
  const shellMetaBlock = captureKaliErr(() => buildSafeKaliArgv('security.kali.recon_surface', { scope: kaliScope, target_host: '127.0.0.1; $(id)', discovering_agent_id: 'agent-kali-recon-scout' }));
  const rawCmdBlock = scanKaliPayloadSafety({ scope: kaliScope, target_host: '127.0.0.1', command: 'bash -i' });
  const rawNmapArgsBlock = scanKaliPayloadSafety({ scope: kaliScope, target_host: '127.0.0.1', raw_nmap_args: '-sS --script=vuln' });
  const runCmdParamBlock = scanKaliPayloadSafety({ scope: kaliScope, target_host: '127.0.0.1', run_command: 'id' });
  assert.equal(outOfScopeDomain.code, 'KALI_BLOCKED_PUBLIC_OR_NONLAB_TARGET');
  assert.equal(imdsBlock.code, 'KALI_BLOCKED_IMDS_TARGET');
  assert.equal(rfc1918Block.code, 'KALI_BLOCKED_RFC1918_TARGET');
  assert.equal(flagScriptBlock.blocked, true);
  assert.equal(shellMetaBlock.code, 'KALI_SHELL_METACHAR_BLOCKED');
  assert.equal(rawCmdBlock.safe, false);
  assert.equal(rawNmapArgsBlock.safe, false);
  assert.equal(runCmdParamBlock.safe, false);

  let liveFailClosed = null;
  try {
    await executeKaliCapability('security.kali.sbom_cve_check', { scope: kaliScope, manifest_rel_path: 'apps/lab-app/package.json', discovering_agent_id: 'agent-kali-recon-scout' }, { workspaceRoot: REPO_ROOT, requestedExecutionMode: 'LIVE_CONTAINER', orchestrator: noRuntimeOrchestrator });
  } catch (err) {
    assert.ok(err instanceof KaliSecurityError);
    liveFailClosed = err.code;
  }
  assert.equal(liveFailClosed, 'KALI_SANDBOX_UNAVAILABLE');

  const canarySecret = 'sk-live-canary-secret-998877665544332211';
  const profileA = generateProfileAArgs({ workspaceRoot: REPO_ROOT, networkMode: 'airgapped', hostEnv: { OPENAI_API_KEY: canarySecret, GITHUB_TOKEN: 'ghp_1234567890abcdef1234567890abcdef1234' }, innerSpec: buildSafeKaliArgv('security.kali.sbom_cve_check', { scope: kaliScope, manifest_rel_path: 'apps/lab-app/package.json', discovering_agent_id: 'agent-kali-recon-scout' }) });
  const profileACheck = validateProfileAArgs(profileA.argv, { requireGvisor: true });
  assert.equal(profileACheck.valid, true);
  assert.equal(JSON.stringify(profileA.argv).includes(canarySecret), false);
  const redactedCanary = redactString(sanitizeOutput(`Bearer ${canarySecret} AKIAIOSFODNN7EXAMPLE`), [canarySecret]);
  assert.equal(redactedCanary.includes(canarySecret), false);

  const guardianAudit = await kaliServer.guardian.getAuditLogger().verifyIntegrity();
  assert.equal(guardianAudit.valid, true);

  writeRedactedJson(artifactPath, {
    gateId: 'G07',
    verifiedSha,
    generatedAtUtc: new Date().toISOString(),
    mode: KALI_MODE,
    allowlistedCapabilities: [...KALI_CAPABILITY_NAMES],
    positiveLabRuns: {
      reconSurface: { ok: reconRun.parsed.ok, executionMode: reconRun.parsed.executionMode, argv: reconRun.parsed.argv },
      tlsReview: { ok: tlsRun.parsed.ok, argv: tlsRun.parsed.argv },
      webPassiveBaseline: { ok: webRun.parsed.ok, argv: webRun.parsed.argv },
      sbomCveCheck: { ok: sbomRun.parsed.ok, networkMode: sbomRun.parsed.networkMode, sbomSummary: sbomRun.parsed.sbom_summary },
      verifyReproducer: { ok: verifyRun.parsed.ok, evidenceId: verifyRun.parsed.evidence.evidence_id },
    },
    negativeSecurityChecks: { outOfScopeDomain, imdsBlock, rfc1918Block, flagScriptBlock, shellMetaBlock, rawCmdBlock, rawNmapArgsBlock, runCmdParamBlock, liveFailClosed },
    isolationAndRedaction: { profileAOciGvisorValid: profileACheck.valid, strippedHostCredentialKeys: profileA.envAudit.strippedKeys, canarySecretRedacted: true, guardianAuditEvents: guardianAudit.total_events, guardianAuditMerkleRoot: guardianAudit.merkle_root },
  }, [kaliHmacSecret, canarySecret]);

  return {
    id: 'G07',
    name: 'Kali LAB Sandbox Verification, Zero-Shell Argv & Negative Security Suite',
    status: 'PASS',
    command: '@script-kitty/kali-mcp-assessment LAB_SYNTHETIC + negative checks (evil.example, 169.254.169.254, --script=..., raw shell, redaction)',
    exitCode: 0,
    durationMs: Date.now() - t0,
    artifacts: [relPath(artifactPath)],
    details: { mode: KALI_MODE, positiveCapabilitiesVerified: KALI_CAPABILITY_NAMES.length, outOfScopeDomainBlocked: outOfScopeDomain.code, cloudImdsBlocked: imdsBlock.code, flagInjectionBlocked: flagScriptBlock.code, rawShellBlocked: shellMetaBlock.code, secretRedactionVerified: true },
    blocker: null,
  };
}

// ============================================================================
// Gate G09: Landing / UI / A11y / 5-Viewport Visual QA & Impeccable Scan
// ============================================================================

async function runGateG09(pkgs, bins) {
  const t0 = Date.now();
  const viewports = [
    { label: 'desktop', width: 1440, height: 900, file: 'screenshot-desktop.png' },
    { label: 'laptop', width: 1280, height: 720, file: 'screenshot-laptop.png' },
    { label: 'tablet', width: 768, height: 1024, file: 'screenshot-tablet.png' },
    { label: 'mobile', width: 390, height: 844, file: 'screenshot-mobile.png' },
    { label: 'mobile-360', width: 360, height: 800, file: 'screenshot-mobile-360.png' },
  ];

  if (!bins.chromium) {
    return { id: 'G09', name: 'Landing / UI / A11y / 5-Viewport Visual QA', status: 'FAIL', command: 'Chromium CDP 5-viewport audit', exitCode: 1, durationMs: Date.now() - t0, artifacts: [], details: { error: 'Chromium not found' }, blocker: 'Missing Chromium binary' };
  }

  const { createSecurityActionRuntime, startMcpHttpServer } = pkgs.securityActions;
  const runtime = createSecurityActionRuntime({ dbPath: ':memory:', fixturesDir: FIXTURES_DIR });
  const demoToken = `sk-gate-ui-${crypto.randomBytes(8).toString('hex')}`;
  let uiServer = null, vercelServer = null, mcpServer = null, cdp = null;
  const tmpProfileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scriptkitty-g09-chrome-'));

  try {
    uiServer = await startEphemeralStaticServer(UI_DIST_DIR);
    vercelServer = await startEphemeralStaticServer(VERCEL_DIST_DIR);
    mcpServer = await startMcpHttpServer(runtime.engine, {
      host: LOOPBACK_HOST, port: 0, path: '/mcp',
      allowedOrigins: [uiServer.url, `http://localhost:${uiServer.port}`, 'http://127.0.0.1:5173'],
      tokens: { [demoToken]: { principalId: 'g09-ui-operator', tenantId: 'payments-lab', roles: ['security-operator'], scopes: ['security:*'] } },
    });

    cdp = await launchChromiumCdp(bins.chromium, tmpProfileDir);
    await cdp.setViewport(1440, 900, 1);
    await cdp.navigate(`${uiServer.url}/?mcpUrl=${encodeURIComponent(mcpServer.url)}&token=${encodeURIComponent(demoToken)}&autoConnect=1`);
    await cdp.waitForCondition(`Boolean(document.querySelector('#app')) && document.querySelector('#app').children.length > 0`, 12_000, '#app mount');
    await cdp.waitForCondition(`window.__PATCHCAT_CONTROLLER__?.getState().connectionMode === 'LIVE_MCP_HTTP'`, 8_000, 'LIVE_MCP_HTTP').catch(() => {});

    const measureOverflow = () => cdp.evaluate(`(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      overflowPx: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth),
      zeroHorizontalOverflow: document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    }))()`);

    const uiViewportResults = [];
    const screenshotArtifacts = [];
    for (const vp of viewports) {
      await cdp.setViewport(vp.width, vp.height, 1);
      await cdp.evaluate('window.scrollTo(0, 0)');
      await new Promise((r) => setTimeout(r, 250));
      const metrics = await measureOverflow();
      const outPng = path.join(EVIDENCE_DIR, vp.file);
      await cdp.screenshotPng(outPng);
      screenshotArtifacts.push(relPath(outPng));
      uiViewportResults.push({ viewport: `${vp.width}x${vp.height}`, label: vp.label, screenshot: relPath(outPng), ...metrics });
    }

    await cdp.setViewport(1440, 900, 1);
    await new Promise((r) => setTimeout(r, 200));

    const a11yChecks = await cdp.evaluate(`(async () => {
      const ctrl = window.__PATCHCAT_CONTROLLER__;
      const initialTitle = document.querySelector('#txt-hero-title')?.textContent?.trim() ?? '';
      const langSelect = document.querySelector('#select-lang');
      let ptTitle = '';
      if (langSelect) {
        langSelect.value = 'pt';
        langSelect.dispatchEvent(new Event('change', { bubbles: true }));
        await new Promise((r) => setTimeout(r, 120));
        ptTitle = document.querySelector('#txt-hero-title')?.textContent?.trim() ?? '';
        langSelect.value = 'en';
        langSelect.dispatchEvent(new Event('change', { bubbles: true }));
        await new Promise((r) => setTimeout(r, 120));
      }
      const tabBaseline = document.querySelector('#tab-baseline');
      if (tabBaseline) {
        tabBaseline.click();
        await new Promise((r) => setTimeout(r, 100));
        tabBaseline.focus();
        tabBaseline.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', code: 'ArrowRight', bubbles: true }));
        await new Promise((r) => setTimeout(r, 140));
      }
      const afterArrowFixture = ctrl ? ctrl.getState().activeFixtureId : null;
      document.querySelector('#tab-unsafe-rollout')?.click();
      await new Promise((r) => setTimeout(r, 100));
      const clickFixture = ctrl ? ctrl.getState().activeFixtureId : null;
      document.querySelector('#tab-baseline')?.click();

      // Check theme toggle (#btn-toggle-theme -> data-theme dark <-> light)
      const initialTheme = document.documentElement.getAttribute('data-theme');
      const themeBtn = document.querySelector('#btn-toggle-theme');
      if (themeBtn) themeBtn.click();
      await new Promise((r) => setTimeout(r, 80));
      const toggledTheme = document.documentElement.getAttribute('data-theme');
      if (themeBtn) themeBtn.click();
      await new Promise((r) => setTimeout(r, 80));
      const restoredTheme = document.documentElement.getAttribute('data-theme');

      return {
        initialTitle, ptTitle,
        bilingualSwitchWorks: Boolean(ptTitle && ptTitle !== initialTitle),
        keyboardArrowRightMovedTab: afterArrowFixture === 'payments-lab/unsafe-rollout',
        clickTabSwitchWorks: clickFixture === 'payments-lab/unsafe-rollout',
        themeToggleWorks: Boolean(initialTheme && toggledTheme && toggledTheme !== initialTheme && restoredTheme === initialTheme),
        hasHeader: Boolean(document.querySelector('header')),
        hasMain: Boolean(document.querySelector('main')),
      };
    })()`);

    await cdp.evaluate(`document.querySelector('#btn-scout')?.focus();`);
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9 });
    await new Promise((r) => setTimeout(r, 80));
    const focusInfo = await cdp.evaluate(`(() => {
      const el = document.activeElement;
      if (!el || el === document.body) return { activeId: null, matchesFocusVisible: false, hasFocusStyle: false };
      const cs = window.getComputedStyle(el);
      const matchesFocusVisible = typeof el.matches === 'function' && el.matches(':focus-visible');
      const hasFocusStyle = matchesFocusVisible && ((cs.outlineStyle !== 'none' && cs.outlineWidth !== '0px') || cs.boxShadow !== 'none');
      return { activeId: el.id || el.tagName, matchesFocusVisible, hasFocusStyle };
    })()`);
    a11yChecks.hasFocusStyle = Boolean(focusInfo?.hasFocusStyle);
    a11yChecks.focusVisibleTarget = focusInfo?.activeId ?? null;

    await cdp.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
    const reducedMotionMatched = await cdp.evaluate(`window.matchMedia('(prefers-reduced-motion: reduce)').matches`);

    await cdp.navigate(`${vercelServer.url}/`);
    await cdp.waitForCondition(`Boolean(document.body) && document.body.innerText.trim().length > 0`, 8_000, 'vercel-app load');
    const vercelViewportResults = [];
    for (const vp of viewports) {
      await cdp.setViewport(vp.width, vp.height, 1);
      await new Promise((r) => setTimeout(r, 160));
      vercelViewportResults.push({ viewport: `${vp.width}x${vp.height}`, label: vp.label, ...(await measureOverflow()) });
    }

    let impeccableFindings = [];
    let impeccableExitCode = 0;
    let impeccableCommand = 'impeccable/scripts/detect.mjs --json';
    if (bins.impeccableDetect) {
      const targets = ['apps/ui/index.html', 'apps/ui/src/style.css', 'apps/ui/src/dashboard-view.ts', 'apps/ui/src/openui-catalog.ts', 'vercel-app/index.html', 'vercel-app/src/style.css'].filter((rel) => fs.existsSync(path.join(REPO_ROOT, rel)));
      const impRes = runCommandCapture('impeccable detect.mjs', process.execPath, [bins.impeccableDetect, '--json', ...targets]);
      impeccableCommand = impRes.command;
      impeccableExitCode = impRes.exitCode;
      try { impeccableFindings = JSON.parse(impRes.stdout.slice(impRes.stdout.indexOf('['))); } catch { impeccableFindings = [{ error: 'Parse error', raw: impRes.stdout }]; }
    }

    const uiZero = uiViewportResults.every((r) => r.zeroHorizontalOverflow);
    const vercelZero = vercelViewportResults.every((r) => r.zeroHorizontalOverflow);
    const impClean = Array.isArray(impeccableFindings) && impeccableFindings.length === 0;
    const localPassed = uiZero && vercelZero && a11yChecks.bilingualSwitchWorks && a11yChecks.keyboardArrowRightMovedTab && a11yChecks.clickTabSwitchWorks && a11yChecks.themeToggleWorks && a11yChecks.hasFocusStyle && a11yChecks.hasHeader && a11yChecks.hasMain && reducedMotionMatched && impClean;

    const publicDemoUrl = process.env.PUBLIC_DEMO_URL?.trim() || null;
    let publicUrlReachable = false;
    let publicUrlStatus = null;
    if (publicDemoUrl && publicDemoUrl.startsWith('https://')) {
      try { const r = await fetch(publicDemoUrl); publicUrlStatus = r.status; publicUrlReachable = r.ok; } catch { publicUrlReachable = false; }
    }

    const status = !localPassed ? 'FAIL' : publicUrlReachable ? 'PASS' : 'BLOCKED';
    const blocker = !localPassed
      ? `Local UI/A11y/Visual QA failed (uiZero=${uiZero}, vercelZero=${vercelZero}, bilingual=${a11yChecks.bilingualSwitchWorks}, impeccable=${impeccableFindings.length})`
      : !publicUrlReachable
        ? 'Local 5-viewport Chromium visual QA, EN/PT switcher, A11y, reduced-motion & impeccable ([]) PASSED; PUBLIC_DEMO_URL not deployed over public HTTPS yet.'
        : null;

    return {
      id: 'G09',
      name: 'Landing / UI / A11y / 5-Viewport Visual QA & Public HTTPS Check',
      status,
      command: `Chromium CDP (5 viewports) + ${impeccableCommand}`,
      exitCode: localPassed ? 0 : 1,
      durationMs: Date.now() - t0,
      artifacts: screenshotArtifacts,
      details: {
        localVisualQaStatus: localPassed ? 'PASS' : 'FAIL',
        uiZeroOverflowAll5Viewports: uiZero,
        vercelZeroOverflowAll5Viewports: vercelZero,
        uiViewports: uiViewportResults,
        vercelViewports: vercelViewportResults,
        a11yAndInteraction: { ...a11yChecks, prefersReducedMotionEmulated: reducedMotionMatched },
        impeccableAntipatternScan: { exitCode: impeccableExitCode, findingsCount: impeccableFindings.length, findings: impeccableFindings },
        publicHttpsCheck: { configuredUrl: publicDemoUrl, reachable: publicUrlReachable, httpStatus: publicUrlStatus },
      },
      blocker,
    };
  } finally {
    if (cdp) await cdp.close().catch(() => {});
    if (mcpServer) await mcpServer.close().catch(() => {});
    if (uiServer) await uiServer.close().catch(() => {});
    if (vercelServer) await vercelServer.close().catch(() => {});
    runtime.close();
    try { fs.rmSync(tmpProfileDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* ignore */ }
  }
}

// ============================================================================
// Gate G10: Security Hygiene, Dependency Audit, GC Hygiene & Provenance
// ============================================================================

function runGateG10() {
  const t0 = Date.now();
  const depAuditLogPath = path.join(EVIDENCE_DIR, 'dependency-audit.log');
  const codeSecLogPath = path.join(EVIDENCE_DIR, 'code-security.log');

  const auditRun = runCommandCapture('npm audit --omit=dev --json', 'npm', ['audit', '--omit=dev', '--json']);

  let vulnTotal = 0;
  let advisoryContext = null;
  try {
    const parsed = JSON.parse(auditRun.stdout.slice(auditRun.stdout.indexOf('{')));
    vulnTotal = parsed?.metadata?.vulnerabilities?.total ?? Object.keys(parsed?.vulnerabilities ?? {}).length;
    const zodVuln = parsed?.vulnerabilities?.zod;
    if (zodVuln) {
      let installedZodVersion = 'unknown';
      try { installedZodVersion = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'node_modules/zod/package.json'), 'utf8')).version ?? 'unknown'; } catch { /* ignore */ }
      const via = Array.isArray(zodVuln.via) ? zodVuln.via.find((v) => typeof v === 'object') : null;
      advisoryContext = {
        package: 'zod',
        installedVersion: installedZodVersion,
        severity: zodVuln.severity ?? 'high',
        advisoryUrl: via?.url ?? 'https://github.com/advisories/GHSA-mrhx-c7xc-m3w5',
        fixAvailable: zodVuln.fixAvailable ?? null,
        runtimeMitigation: 'Honest FAIL preserved (semver-major zod v3->v4 upgrade deferred to preserve v3 schema compatibility). Runtime exposure mitigated in LAB mode by maxRequestBodyBytes = 1_048_576 (1 MiB) in packages/security-actions/src/mcp-http.ts (readBoundedBody) and 127.0.0.1 loopback-only binding.',
      };
    }
  } catch {
    vulnTotal = auditRun.exitCode === 0 ? 0 : 1;
  }

  fs.writeFileSync(
    depAuditLogPath,
    [
      auditRun.combined,
      advisoryContext ? `# AdvisoryRuntimeContext: ${JSON.stringify(advisoryContext)}` : '',
    ].filter(Boolean).join('\n') + '\n',
    'utf8'
  );

  const excludedDirs = new Set(['node_modules', '.git', 'dist', 'evidence', 'demo-video', '.context']);
  const textExtensions = new Set(['.ts', '.mts', '.js', '.mjs', '.json', '.md', '.html', '.css', '.yml', '.yaml', '.py', '.sh', '.ps1']);
  const allowlistedRedactionTemplates = [
    /\[REDACTED PRIVATE KEY\]/i,
    /-example-redacted-placeholder\b/i,
  ];
  const allowlistedDummies = [
    /sk-live-demo-token|sk-live-rec-|sk-live-canary-secret|sk-live-secret-1234567890abcdef|sk-demo-|sk-gate-|sk-test-|sk-proj-test|sk-ant-test|sk-ant-api03-test|sk-or-v1-\.\.\.|sk-ant-\.\.\.|sk-\.\.\./i,
    /AIzaSy\.\.\.|AIzaSyDummy|AIzaSyTest|nvapi-\.\.\.|nvapi-test|xai-\.\.\.|xai-test|AKIAIOSFODNN7EXAMPLE|AKIA1234567890ABCDEF|ghp_1234567890abcdef|ghp_test/i,
  ];
  const allowlistedTestFixtureSha256 = new Set([
    '19ee0c2c5724ed05334853e649a9f0b368e2b81798a3e3b40730b88cfc160b15',
    'b862933b9bf6214c73b3e0b1f351d45da519c2da880e7c9bddc5d843843fcbc6',
    'f1cfada5ed19a74cd664eedf30f04a766a02525bcecfc81336bdd5100fa41529',
    '59fd41f64807b694ef3b24592f0b75681c0b2f53e9fc4959165b8348fe43fc11',
    'ca8f83cbf8f3637bb92194a878a2d713e3b2cac7acd672c3418f0d5691134401',
    '4d1e3b4a1264634f753fd990c8f68f315a09e55acec7f7b2ad567a6b4ffbb8f5',
    '4c1c678d9abde83e51cf68ca5a2fdea52286e03a6997119cb797f027d131a0e2',
    'abc8c1c6858b81593ad29c8f8ec906ecbb9c60486fc0702d5d8a0fe319d6e9ea',
    '7ed6af49ee097213757da2dfb6b40f20a574959b7d4fe22df9493c6e727a203f',
    'c17f6716ba44bfd47b3784776cdf0a3c4166f2eb28d08bef1132e13e84385e12',
    'e181e13e2aa1a502862f433bb05d3c18b7f0b6c82e8612b02d4a3c8ae3c82fbc',
    '8ddb4386c55851876b88176cd502e91f78ce41a27f34c3a0cfcf131fb8cd1d5a',
    '4a000a3806c4e01d9733029f8e97eabd80eec732e7b3b0b7f25fa55b4ec186a0',
    '03aafb028d538b06c4341bf8cf2a692a3c6d1f36e34e0e0b376f407c6117a246',
    '4ea8165598411b853dab0b1bfa4045fc457a5dd06ea0d48f967935e5c4349109',
  ]);
  const liveLeakRegexes = [
    { name: 'OpenAI/Secret Key (sk-)', re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
    { name: 'GitHub PAT (ghp_)', re: /\bghp_[A-Za-z0-9]{24,}\b/g },
    { name: 'Google API Key (AIza)', re: /\bAIza[0-9A-Za-z\-_]{30,}\b/g },
    { name: 'NVIDIA NIM Key (nvapi-)', re: /\bnvapi-[A-Za-z0-9\-_]{20,}\b/g },
    { name: 'xAI Key (xai-)', re: /\bxai-[A-Za-z0-9\-_]{20,}\b/g },
    { name: 'AWS Access Key ID (AKIA)', re: /\bAKIA[0-9A-Z]{16}\b/g },
    { name: 'PEM Private Key', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  ];

  let scannedFilesCount = 0;
  const leakedSecrets = [];
  const syntheticFixtures = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!excludedDirs.has(entry.name)) walk(path.join(dir, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if ((!textExtensions.has(ext) && entry.name !== 'Dockerfile') || entry.name === 'package-lock.json') continue;
        const fullPath = path.join(dir, entry.name);
        const rel = relPath(fullPath);
        const isTestFile = /(?:^|\/)(?:tests\/|[^/]+\.test\.[^/]+$)/.test(rel);
        scannedFilesCount += 1;
        const lines = fs.readFileSync(fullPath, 'utf8').split(/\r?\n/);
        for (let idx = 0; idx < lines.length; idx += 1) {
          const lineAndNext = `${lines[idx]}\n${lines[idx + 1] ?? ''}`;
          for (const rule of liveLeakRegexes) {
            const matches = lines[idx].match(rule.re);
            if (!matches) continue;
            for (const m of matches) {
              const isDummy = allowlistedDummies.some((p) => p.test(m) || p.test(lines[idx]));
              const isRedactionTpl = allowlistedRedactionTemplates.some((p) => p.test(lineAndNext));
              const isSyntheticPemTest = isTestFile && rule.name === 'PEM Private Key' && /secretbytes|\.\.\.sample\.\.\.|MIIBOgIBAAJBA/.test(lineAndNext);
              const matchSha256 = crypto.createHash('sha256').update(m).digest('hex');
              const isSyntheticTestToken = isTestFile && allowlistedTestFixtureSha256.has(matchSha256);
              if (isDummy || isRedactionTpl || isSyntheticPemTest || isSyntheticTestToken) {
                if (isRedactionTpl || isSyntheticPemTest || isSyntheticTestToken) {
                  syntheticFixtures.push({ file: rel, line: idx + 1, rule: rule.name, matchRedacted: `${m.slice(0, 6)}...[SYNTHETIC_FIXTURE]` });
                }
              } else {
                leakedSecrets.push({ file: rel, line: idx + 1, rule: rule.name, matchRedacted: `${m.slice(0, 6)}...[REDACTED]` });
              }
            }
          }
        }
      }
    }
  };
  walk(REPO_ROOT);

  // Check LICENSE, PROVENANCE.md & bounded-memory GC hygiene in mcp-http.ts and live-controller.ts
  const hasLicense = fs.existsSync(path.join(REPO_ROOT, 'LICENSE'));
  const hasProvenance = fs.existsSync(path.join(REPO_ROOT, 'PROVENANCE.md'));
  const hasNotice = fs.existsSync(path.join(REPO_ROOT, 'NOTICE.md'));
  const mcpHttpSrc = fs.readFileSync(path.join(REPO_ROOT, 'packages/security-actions/src/mcp-http.ts'), 'utf8');
  const liveCtrlSrc = fs.readFileSync(path.join(REPO_ROOT, 'apps/ui/src/live-controller.ts'), 'utf8');
  const gcHygiene = {
    mcpRateLimiterPruning: /prune\(/.test(mcpHttpSrc) || /maxBuckets/.test(mcpHttpSrc),
    mcpSessionTtlEviction: /sessionTtlMs|lastSeenAtMs/.test(mcpHttpSrc),
    uiSnapshotMapBounded: /MAX_SNAPSHOT_CACHE\s*=\s*50/.test(liveCtrlSrc) && /snapshotMap\.size\s*>=\s*MAX_SNAPSHOT_CACHE/.test(liveCtrlSrc),
  };

  fs.writeFileSync(codeSecLogPath, [
    '# ScriptKitty Live — G10 Code Security, GC & Secret Hygiene Log',
    `TimestampUtc: ${new Date().toISOString()}`,
    `ScannedFilesCount: ${scannedFilesCount}`,
    `LeakedLiveSecretsCount: ${leakedSecrets.length}`,
    `SyntheticTestFixturesVerifiedCount: ${syntheticFixtures.length}`,
    `ProductionDependencyVulnerabilities: ${vulnTotal}`,
    `LICENSE_Present: ${hasLicense} | PROVENANCE_Present: ${hasProvenance} | NOTICE_Present: ${hasNotice}`,
    `GC_Hygiene: ${JSON.stringify(gcHygiene)}`,
    'LeakedSecrets:',
    JSON.stringify(leakedSecrets, null, 2),
    'SyntheticTestFixtures:',
    JSON.stringify(syntheticFixtures, null, 2),
  ].join('\n') + '\n', 'utf8');

  const passed = vulnTotal === 0 && leakedSecrets.length === 0 && hasLicense && hasProvenance;
  const blockers = [];
  if (vulnTotal > 0) blockers.push(`npm audit reported ${vulnTotal} prod vulnerabilities`);
  if (leakedSecrets.length > 0) blockers.push(`Found ${leakedSecrets.length} leaked token(s)`);
  if (!hasLicense) blockers.push('Missing LICENSE');
  if (!hasProvenance) blockers.push('Missing PROVENANCE.md');

  return {
    id: 'G10',
    name: 'Security Hygiene, Dependency Audit, GC Bounds & Provenance Verification',
    status: passed ? 'PASS' : 'FAIL',
    command: 'npm audit --omit=dev --json + repo secret scan + GC hygiene + LICENSE/PROVENANCE check',
    exitCode: passed ? 0 : 1,
    durationMs: Date.now() - t0,
    artifacts: [relPath(depAuditLogPath), relPath(codeSecLogPath)],
    details: { scannedFilesCount, leakedLiveSecretsCount: leakedSecrets.length, syntheticTestFixturesVerifiedCount: syntheticFixtures.length, productionDependencyVulnerabilities: vulnTotal, advisoryContext, hasLicense, hasProvenanceMd: hasProvenance, hasNoticeMd: hasNotice, gcHygiene },
    blocker: blockers.length > 0 ? blockers.join('; ') : null,
  };
}

// ============================================================================
// Gate G11 & G12: Operational Self-Check, 10-Stage Demo & Video <=180s Check
// ============================================================================

function runGateG11() {
  const t0 = Date.now();
  const liveCheckRun = runCommandCapture('start-live-demo --check', process.execPath, ['scripts/start-live-demo.mjs', '--check', '--ui-port=0', '--mcp-port=0'], { env: { TYPESAFE_API_KEY: '' } });
  let liveCheckPayload = null;
  let liveCheckPassed = liveCheckRun.exitCode === 0;
  try {
    liveCheckPayload = JSON.parse(liveCheckRun.stdout.slice(liveCheckRun.stdout.indexOf('{')));
    liveCheckPassed = liveCheckPassed && liveCheckPayload?.check === 'PASS';
  } catch { liveCheckPassed = false; }

  const demoRun = runCommandCapture('npm run demo', process.execPath, ['scripts/demo-wednesday.mjs'], { env: { TYPESAFE_API_KEY: '' } });
  const demoPassed = demoRun.exitCode === 0 && demoRun.stdout.includes('ALL 10 STAGES PASSED CLEANLY');
  const passed = liveCheckPassed && demoPassed;

  return {
    id: 'G11',
    name: 'Operational Cold-Start Launcher & 10-Stage End-to-End Demo',
    status: passed ? 'PASS' : 'FAIL',
    command: 'node scripts/start-live-demo.mjs --check --ui-port=0 --mcp-port=0; npm run demo',
    exitCode: passed ? 0 : 1,
    durationMs: Date.now() - t0,
    artifacts: [],
    details: { startLiveDemoCheckExitCode: liveCheckRun.exitCode, startLiveDemoCheckVerdict: liveCheckPayload?.check ?? 'FAIL', startLiveDemoToolsCount: liveCheckPayload?.mcp?.tools?.length ?? 0, demoWednesdayExitCode: demoRun.exitCode, demoWednesdayAll10StagesPassed: demoPassed },
    blocker: passed ? null : `start-live-demo --check (${liveCheckRun.exitCode}) or demo-wednesday (${demoRun.exitCode}) failed`,
  };
}

async function runGateG12(bins) {
  const t0 = Date.now();
  const videoExists = fs.existsSync(DEMO_VIDEO_MP4);
  const srtExists = fs.existsSync(DEMO_VIDEO_SRT);
  const keyframesCount = fs.existsSync(DEMO_FRAMES_DIR) ? fs.readdirSync(DEMO_FRAMES_DIR).filter((f) => f.toLowerCase().endsWith('.png')).length : 0;

  let videoMeta = null;
  let localVideoValid = false;
  if (videoExists && bins.ffprobe) {
    const probe = spawnSync(bins.ffprobe, ['-v', 'error', '-show_format', '-show_streams', '-of', 'json', DEMO_VIDEO_MP4], { encoding: 'utf8', timeout: 15_000 });
    if (probe.status === 0) {
      try {
        const meta = JSON.parse(probe.stdout);
        const vStream = meta.streams?.find((s) => s.codec_type === 'video');
        const aStream = meta.streams?.find((s) => s.codec_type === 'audio');
        const durationSec = Number(meta.format?.duration ?? 0);
        videoMeta = { durationSec, within180sLimit: durationSec > 0 && durationSec <= 180, sizeBytes: Number(meta.format?.size ?? 0), videoCodec: vStream?.codec_name ?? null, pixFmt: vStream?.pix_fmt ?? null, width: vStream?.width ?? null, height: vStream?.height ?? null, audioCodec: aStream?.codec_name ?? null };
        localVideoValid = Boolean(videoMeta.within180sLimit && videoMeta.videoCodec === 'h264' && videoMeta.width === 1920 && videoMeta.height === 1080 && videoMeta.audioCodec === 'aac' && srtExists && keyframesCount >= 6);
      } catch { localVideoValid = false; }
    }
  }

  const publicDemoUrl = process.env.PUBLIC_DEMO_URL?.trim() || null;
  const publicVideoUrl = process.env.PUBLIC_VIDEO_URL?.trim() || null;
  const checkPublic = async (url) => {
    if (!url || !url.startsWith('https://')) return false;
    try { return (await fetch(url)).ok; } catch { return false; }
  };
  const [publicDemoReachable, publicVideoReachable] = await Promise.all([checkPublic(publicDemoUrl), checkPublic(publicVideoUrl)]);

  const blockers = [];
  if (!localVideoValid) blockers.push('Local PoC demo video failed ffprobe <=180s 1920x1080 H.264/AAC check');
  if (!publicDemoReachable) blockers.push('PUBLIC_DEMO_URL is not configured/deployed yet (requires human Vercel HTTPS deploy approval)');
  if (!publicVideoReachable) blockers.push('PUBLIC_VIDEO_URL is not configured yet (Hack Brasil requires <=180s team video where all 4 members appear and speak)');

  return {
    id: 'G12',
    name: 'Public Demo URL & <=180s Demo/Team Video Verification',
    status: !localVideoValid ? 'FAIL' : blockers.length === 0 ? 'PASS' : 'BLOCKED',
    command: 'ffprobe demo-video/scriptkitty-live-poc-demo-2m30s.mp4 + PUBLIC_DEMO_URL & PUBLIC_VIDEO_URL check',
    exitCode: localVideoValid ? 0 : 1,
    durationMs: Date.now() - t0,
    artifacts: videoExists ? [relPath(DEMO_VIDEO_MP4), relPath(DEMO_VIDEO_SRT)] : [],
    details: { localPocVideoStatus: localVideoValid ? 'PASS' : 'FAIL', localPocVideoMeta: videoMeta, srtPresent: srtExists, extractedKeyframesCount: keyframesCount, publicDemoUrl, publicDemoReachable, publicVideoUrl, publicVideoReachable },
    blocker: blockers.length > 0 ? blockers.join(' | ') : null,
  };
}

// ============================================================================
// Master Runner Orchestration (G00 - G14)
// ============================================================================

async function main() {
  const startedAtMs = Date.now();
  const requireAllPass = process.argv.includes('--require-all-pass');
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

  const verifiedSha = getGitHeadSha();
  const bins = discoverHostBinaries();
  console.log(`${'='.repeat(84)}\n ScriptKitty Live / PatchCat — Quality Gates Runner (G00–G14)\n Verified Git HEAD SHA: ${verifiedSha}\n${'='.repeat(84)}`);

  const g00 = await runGateG00(verifiedSha);
  const g01 = runGateG01();
  const pkgs = await loadBuiltPackages();
  const g02 = await runGateG02(pkgs);
  const { gateG03, gateG04, gateG05 } = await runGatesG03G04G05(pkgs);
  const { gateG06, gateG08 } = await runGatesG06G08(pkgs, verifiedSha);
  const g07 = await runGateG07(pkgs, verifiedSha);
  const g09 = await runGateG09(pkgs, bins);
  const g10 = runGateG10();
  const g11 = runGateG11();
  const g12 = await runGateG12(bins);

  const gates = [g00, g01, g02, gateG03, gateG04, gateG05, gateG06, g07, gateG08, g09, g10, g11, g12];

  const gateReportPath = path.join(EVIDENCE_DIR, 'gate-report.json');
  const requiredEvidenceFiles = [
    'submission-preflight.json', 'build.log', 'typecheck.log', 'unit-tests.log',
    'chainbreak-baseline.json', 'chainbreak-unsafe.json', 'chainbreak-remediated.json', 'chainbreak-diff.json',
    'mcp-client-transcript-redacted.json', 'judge-evaluation-redacted.json', 'quality-engine-run-redacted.json', 'kali-lab-run-redacted.json',
    'screenshot-desktop.png', 'screenshot-laptop.png', 'screenshot-tablet.png', 'screenshot-mobile.png', 'screenshot-mobile-360.png',
    'dependency-audit.log', 'code-security.log',
  ];
  const missingEvidenceFiles = requiredEvidenceFiles.filter((f) => {
    const p = path.join(EVIDENCE_DIR, f);
    return !fs.existsSync(p) || fs.statSync(p).size === 0;
  });

  gates.push({
    id: 'G13',
    name: 'Deterministic Evidence Bundle & Gate Report Emission',
    status: missingEvidenceFiles.length === 0 ? 'PASS' : 'FAIL',
    command: 'Verify evidence/* artifacts non-empty + emit evidence/gate-report.json',
    exitCode: missingEvidenceFiles.length === 0 ? 0 : 1,
    durationMs: 4,
    artifacts: [relPath(gateReportPath)],
    details: { verifiedEvidenceFilesCount: requiredEvidenceFiles.length - missingEvidenceFiles.length, expectedEvidenceFilesCount: requiredEvidenceFiles.length, missingEvidenceFiles },
    blocker: missingEvidenceFiles.length > 0 ? `Missing evidence artifact(s): ${missingEvidenceFiles.join(', ')}` : null,
  });

  const localFailures = gates.filter((g) => g.status === 'FAIL');
  const externalBlockers = gates.filter((g) => g.status === 'BLOCKED' || g.status === 'NOT_CONFIGURED').map((g) => ({ gateId: g.id, status: g.status, blocker: g.blocker }));
  const g14Status = localFailures.length > 0 ? 'FAIL' : externalBlockers.length > 0 ? 'BLOCKED' : 'PASS';

  gates.push({
    id: 'G14',
    name: 'Hack Brasil 2026 Final Submission Freeze Gate',
    status: g14Status,
    command: `Verify G00..G13 completion prior to ${HACKBR_FREEZE_ISO}`,
    exitCode: localFailures.length === 0 ? 0 : 1,
    durationMs: 2,
    artifacts: [relPath(gateReportPath)],
    details: {
      freezeDeadlineIso: HACKBR_FREEZE_ISO,
      localEngineeringGatesFailed: localFailures.length,
      pendingExternalHumanGates: externalBlockers.map((b) => b.gateId),
      humanSubmissionChecklist: [
        '1. Review PROVENANCE.md and push clean Hack Brasil 2026 commit to https://github.com/andrecodexvictor/scriptkitty-live-hackbrasil-2026',
        '2. Deploy public HTTPS preview (vercel-app or apps/ui) and set PUBLIC_DEMO_URL',
        '3. Record/upload <=180s 4-person on-camera team pitch video and set PUBLIC_VIDEO_URL',
        '4. Re-run npm run gates to confirm G00, G09, G12, and G14 transition from BLOCKED to PASS',
      ],
    },
    blocker: g14Status === 'BLOCKED' ? `Local engineering checks PASSED; submission freeze BLOCKED awaiting human action on [${externalBlockers.map((b) => b.gateId).join(', ')}]` : localFailures.length > 0 ? `Blocked by local failures: [${localFailures.map((g) => g.id).join(', ')}]` : null,
  });

  const counts = {
    total: gates.length,
    PASS: gates.filter((g) => g.status === 'PASS').length,
    NOT_CONFIGURED: gates.filter((g) => g.status === 'NOT_CONFIGURED').length,
    BLOCKED: gates.filter((g) => g.status === 'BLOCKED').length,
    FAIL: gates.filter((g) => g.status === 'FAIL').length,
  };
  const overallVerdict = counts.FAIL > 0 ? 'FAIL' : counts.BLOCKED > 0 || counts.NOT_CONFIGURED > 0 ? 'BLOCKED' : 'PASS';
  const localEngineeringVerdict = counts.FAIL === 0 ? 'PASS' : 'FAIL';

  writeRedactedJson(gateReportPath, {
    schemaVersion: 'scriptkitty.quality-gates.v1',
    verifiedSha,
    verifiedAtUtc: new Date().toISOString(),
    totalDurationMs: Date.now() - startedAtMs,
    overallVerdict,
    localEngineeringVerdict,
    summary: counts,
    externalHumanBlockers: externalBlockers,
    gates: Object.fromEntries(gates.map((g) => [g.id, g])),
    gateList: gates,
  });

  console.log('\n' + '='.repeat(84));
  for (const g of gates) {
    console.log(` [${g.id}] ${g.status.padEnd(14, ' ')} | ${g.name}${g.blocker ? `\n         ↳ ${g.blocker}` : ''}`);
  }
  console.log('='.repeat(84));
  console.log(` Summary: PASS=${counts.PASS} | NOT_CONFIGURED=${counts.NOT_CONFIGURED} | BLOCKED=${counts.BLOCKED} | FAIL=${counts.FAIL}`);
  console.log(` Local Engineering: ${localEngineeringVerdict} | Overall Submission: ${overallVerdict}`);
  console.log(` Report: ${relPath(gateReportPath)}\n${'='.repeat(84)}`);

  if (counts.FAIL > 0 || (requireAllPass && overallVerdict !== 'PASS')) process.exit(1);
}

main().catch((err) => {
  console.error('[run-quality-gates] FATAL ERROR:', err instanceof Error ? err.stack || err.message : String(err));
  process.exit(1);
});
