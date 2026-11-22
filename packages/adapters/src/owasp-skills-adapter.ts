/**
 * @file packages/adapters/src/owasp-skills-adapter.ts
 * @description OWASP Security Skills Pack Adapter for ScriptKitty 2.0.
 * Aligned with the local OWASP Security Pack (v1.1.0, 29 skills across 24 domains)
 * and Cloudflare / Edge security auditing policies. Evaluates deterministic checks
 * across AppSec, AgentSec & MCP, Supply Chain, and Cloud/Cloudflare Infrastructure,
 * enforcing .security-pack.json v1 bounded limits and SHA-256 fingerprint exceptions.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { z } from 'zod';

import {
  type SecurityFinding,
  type Evidence,
  type PatchProposal,
  type TargetType,
  type RecheckStatus,
  validateFinding,
  validateEvidence,
  computeFindingFingerprint,
  computeEvidenceChainHash,
  sha256,
} from '../../contracts/dist/index.js';

import type {
  ISecurityEngineAdapter,
  AdapterStatusReport,
  ScanTarget,
  ScanOptions,
  AdapterScanResult,
  ReproduceOptions,
  AdapterReproduceResult,
  RecheckOptions,
  AdapterRecheckResult,
} from './adapter-interface.js';

import {
  withTimeout,
  sanitizeOutput,
  sanitizeObject,
  safeExecute,
  TimeoutError,
} from './execution-boundary.js';

import {
  parseSecurityPackPolicy,
  type SecurityPackPolicy,
} from './quality-engine-adapter.js';

export type OwaspSkillDomain =
  | 'APPSEC'
  | 'AGENTSEC_MCP'
  | 'SUPPLY_CHAIN'
  | 'CLOUD_CLOUDFLARE';

export interface OwaspSkillEntry {
  name: string;
  title: string;
  description: string;
  kind: 'domain' | 'workflow' | 'router';
  category?: OwaspSkillDomain;
}

export interface OwaspSkillsCatalog {
  version: string;
  domainCount: number;
  skills: OwaspSkillEntry[];
  source: 'embedded' | 'filesystem';
}

const CatalogSchema = z.object({
  version: z.string().min(1),
  domainCount: z.number().int().positive(),
  skills: z.array(
    z.object({
      name: z.string().min(1),
      title: z.string().min(1),
      description: z.string().min(1),
      kind: z.enum(['domain', 'workflow', 'router']),
    })
  ),
});

/**
 * Canonical embedded catalog mirroring security-pack/data/pack-catalog.json v1.1.0 (29 skills).
 */
export const EMBEDDED_OWASP_SKILLS_CATALOG: OwaspSkillsCatalog = {
  version: '1.1.0',
  domainCount: 24,
  source: 'embedded',
  skills: [
    { name: 'security-architecture', title: 'Architecture & Threat Modeling', description: 'Trust boundaries, abuse cases, Zero Trust design.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-identity', title: 'Authentication, Tokens & Sessions', description: 'Login, MFA, passkeys, OAuth/OIDC, SAML, JWT, workload identity.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-authorization', title: 'Authorization & Tenant Isolation', description: 'RBAC, object/field permissions, IDOR/BOLA, tenant boundaries.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-web', title: 'Browser, DOM & Web Boundaries', description: 'XSS, CSRF, cookies, CSP, CORS, headers, web cache.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-api', title: 'APIs, Protocols & Messaging', description: 'REST, GraphQL, gRPC, WebSockets, webhooks, service APIs.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-input', title: 'Inputs, Parsers & Injections', description: 'SQL/NoSQL/LDAP, SSRF, uploads, XXE, deserialization, OS command injection.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-crypto-secrets', title: 'Cryptography, Secrets & Transport', description: 'Passwords, keys, secret storage, TLS, certificates, rotation.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-data-privacy', title: 'Data, Databases & Privacy', description: 'DB access, PII exposure, retention, export/deletion, backups.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-supply-chain', title: 'Dependencies & Supply Chain', description: 'Lockfiles, CI/CD, GitHub Actions, build images, SBOM, provenance.', kind: 'domain', category: 'SUPPLY_CHAIN' },
    { name: 'security-cloud-infrastructure', title: 'Cloud, Containers & Infrastructure', description: 'Docker, Kubernetes, IaC, DNS, serverless, IAM, Cloudflare edge.', kind: 'domain', category: 'CLOUD_CLOUDFLARE' },
    { name: 'security-language-frameworks', title: 'Languages & Frameworks', description: 'Java, .NET, JS/TS, Node, Python, PHP, Rails, Next.js.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-ai-agents', title: 'AI, Agents, RAG & MCP', description: 'LLM, RAG, prompt injection, MCP tool security, agent memory and execution.', kind: 'domain', category: 'AGENTSEC_MCP' },
    { name: 'security-mobile', title: 'Mobile Applications', description: 'Android/iOS storage, WebView, deep links, mobile transport.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-embedded', title: 'Embedded & Physical Devices', description: 'Firmware, automotive, drones, embedded admin interfaces.', kind: 'domain', category: 'CLOUD_CLOUDFLARE' },
    { name: 'security-operations', title: 'Review, Observability & Response', description: 'Secure code review, safe logging, incident response.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-abuse-business', title: 'Abuse, Business Logic & Availability', description: 'Bots, workflow abuse, concurrency, rate limits, DoS.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-payments', title: 'Payments & Financial Integrations', description: 'Checkout, callbacks, transaction authorization, agent payments.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-verification', title: 'ASVS / WSTG Verification', description: 'ASVS/WSTG/MASVS test plans and control evidence.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-ci-cd', title: 'CI/CD & Build Boundaries', description: 'Workflows, runners, fork PR isolation, OIDC deploy, caches.', kind: 'domain', category: 'SUPPLY_CHAIN' },
    { name: 'security-containers-kubernetes', title: 'Containers & Kubernetes', description: 'Dockerfiles, pods, service accounts, RBAC, NetworkPolicy.', kind: 'domain', category: 'CLOUD_CLOUDFLARE' },
    { name: 'security-infrastructure-as-code', title: 'Infrastructure as Code & State', description: 'Terraform, OpenTofu, CloudFormation, Pulumi, state security.', kind: 'domain', category: 'CLOUD_CLOUDFLARE' },
    { name: 'security-detection-response', title: 'Detection, Response & Recovery', description: 'Detections, containment, recovery validation, tabletop.', kind: 'domain', category: 'CLOUD_CLOUDFLARE' },
    { name: 'security-desktop', title: 'Desktop Security (Electron/Tauri)', description: 'IPC, native bridges, custom protocols, auto-updates.', kind: 'domain', category: 'APPSEC' },
    { name: 'security-vulnerability-management', title: 'Vulnerability Triage & Remediation', description: 'CVE/advisory triage, SBOM/VEX, reachability, exceptions.', kind: 'domain', category: 'SUPPLY_CHAIN' },
    { name: 'security-audit', title: 'Full Pack Security Audit', description: 'Cross-domain audit coverage and gap tracking.', kind: 'workflow', category: 'APPSEC' },
    { name: 'security-hardening', title: 'Verifiable Hardening', description: 'Implement verifiable controls with regression proof.', kind: 'workflow', category: 'APPSEC' },
    { name: 'security-telemetry', title: 'Security Telemetry Instrumentation', description: 'Local pack usage telemetry and security event design.', kind: 'workflow', category: 'CLOUD_CLOUDFLARE' },
    { name: 'security-evaluate', title: 'Pack Evidence Evaluation', description: 'Evaluate security skill quality and routing accuracy.', kind: 'workflow', category: 'AGENTSEC_MCP' },
    { name: 'security-router', title: 'Multi-Domain Security Router', description: 'Route cross-cutting audits to relevant OWASP modules.', kind: 'router', category: 'APPSEC' },
  ],
};

/**
 * Safely loads the OWASP Security Pack catalog from a local directory (rejecting symlinks & path escapes),
 * or returns the embedded canonical catalog when no directory is supplied.
 */
export async function loadOwaspSkillsCatalog(packRootDir?: string): Promise<OwaspSkillsCatalog> {
  if (!packRootDir || !packRootDir.trim()) {
    return EMBEDDED_OWASP_SKILLS_CATALOG;
  }

  const rootAbs = path.resolve(packRootDir);
  const catalogPath = path.resolve(rootAbs, 'data', 'pack-catalog.json');
  const rel = path.relative(rootAbs, catalogPath);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error('Unsafe catalog path escaping security-pack root');
  }

  const rootReal = await fs.realpath(rootAbs);
  const stat = await fs.lstat(catalogPath);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 1024 * 1024) {
    throw new Error('Security-pack catalog must be a bounded regular file (no symlinks)');
  }
  const catReal = await fs.realpath(catalogPath);
  const realRel = path.relative(rootReal, catReal);
  if (realRel.startsWith('..') || path.isAbsolute(realRel)) {
    throw new Error('Security-pack catalog resolves outside pack boundary');
  }

  const raw = JSON.parse(await fs.readFile(catReal, 'utf8'));
  const parsed = CatalogSchema.parse(raw);

  const categoryLookup = new Map<string, OwaspSkillDomain>(
    EMBEDDED_OWASP_SKILLS_CATALOG.skills.map((s) => [s.name, s.category ?? 'APPSEC'])
  );

  return {
    version: parsed.version,
    domainCount: parsed.domainCount,
    source: 'filesystem',
    skills: parsed.skills.map((s) => ({
      ...s,
      category: categoryLookup.get(s.name) ?? 'APPSEC',
    })),
  };
}

export interface OwaspFileInput {
  path: string;
  content: string;
}

export interface OwaspMcpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  requiresApproval?: boolean;
  stateChanging?: boolean;
}

export interface OwaspRuleMatch {
  ruleId: string;
  domain: OwaspSkillDomain;
  skillName: string;
  title: string;
  description: string;
  cwe_id: string;
  owasp_category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'CERTAIN' | 'FIRM' | 'TENTATIVE';
  target_type: TargetType;
  file_path: string;
  start_line: number;
  end_line: number;
  matched_token: string;
}

interface PatternRule {
  ruleId: string;
  domain: OwaspSkillDomain;
  skillName: string;
  title: string;
  description: string;
  cwe_id: string;
  owasp_category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: 'CERTAIN' | 'FIRM';
  target_type: TargetType;
  filePattern?: RegExp;
  regex: RegExp;
  skipCommentLines?: boolean;
}

const DETERMINISTIC_OWASP_RULES: PatternRule[] = [
  // --- APPSEC (Secrets, TLS, CORS, Injection) ---
  {
    ruleId: 'builtin.github-token',
    domain: 'APPSEC',
    skillName: 'security-crypto-secrets',
    title: 'Hardcoded GitHub Personal Access Token',
    description: 'High-specificity GitHub credential signature detected in repository artifact.',
    cwe_id: 'CWE-798',
    owasp_category: 'A07:2021-Identification and Authentication Failures',
    severity: 'CRITICAL',
    confidence: 'CERTAIN',
    target_type: 'SOURCE_CODE',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{70,255})\b/,
  },
  {
    ruleId: 'builtin.stripe-live-key',
    domain: 'APPSEC',
    skillName: 'security-payments',
    title: 'Hardcoded Stripe Live API Secret',
    description: 'High-specificity live payment gateway secret detected.',
    cwe_id: 'CWE-798',
    owasp_category: 'A07:2021-Identification and Authentication Failures',
    severity: 'CRITICAL',
    confidence: 'CERTAIN',
    target_type: 'SOURCE_CODE',
    regex: /\bsk_live_[A-Za-z0-9]{24,255}\b/,
  },
  {
    ruleId: 'builtin.private-key',
    domain: 'APPSEC',
    skillName: 'security-crypto-secrets',
    title: 'Embedded Private Key Block',
    description: 'PEM-encoded cryptographic private key detected inside workspace file.',
    cwe_id: 'CWE-798',
    owasp_category: 'A02:2021-Cryptographic Failures',
    severity: 'CRITICAL',
    confidence: 'CERTAIN',
    target_type: 'SOURCE_CODE',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
  },
  {
    ruleId: 'heuristic.tls-verification-disabled',
    domain: 'APPSEC',
    skillName: 'security-crypto-secrets',
    title: 'TLS Certificate Verification Disabled',
    description: 'Disabling TLS verification exposes transport channels to MitM attacks.',
    cwe_id: 'CWE-295',
    owasp_category: 'A02:2021-Cryptographic Failures',
    severity: 'HIGH',
    confidence: 'FIRM',
    target_type: 'SOURCE_CODE',
    skipCommentLines: true,
    regex: /(?:\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?)/,
  },
  {
    ruleId: 'heuristic.cors-wildcard',
    domain: 'APPSEC',
    skillName: 'security-web',
    title: 'Wildcard CORS Origin Policy',
    description: 'Wildcard CORS origin grants cross-origin read capabilities across untrusted sites.',
    cwe_id: 'CWE-942',
    owasp_category: 'A05:2021-Security Misconfiguration',
    severity: 'MEDIUM',
    confidence: 'FIRM',
    target_type: 'SOURCE_CODE',
    skipCommentLines: true,
    regex: /(?:\bcors\s*\(\s*\{[^}\n]*\borigin\s*:\s*['"]\*['"]|['"]Access-Control-Allow-Origin['"]\s*[,:=]\s*['"]\*['"])/,
  },
  {
    ruleId: 'appsec.sql-template-interpolation',
    domain: 'APPSEC',
    skillName: 'security-input',
    title: 'Raw SQL Template Interpolation',
    description: 'User-controlled expressions interpolated directly into SQL string without parameterization.',
    cwe_id: 'CWE-89',
    owasp_category: 'A03:2021-Injection',
    severity: 'CRITICAL',
    confidence: 'FIRM',
    target_type: 'SOURCE_CODE',
    filePattern: /\.(?:[cm]?[jt]sx?|py|rb|php|go|java)$/i,
    skipCommentLines: true,
    regex: /(?:SELECT\b|INSERT\b|UPDATE\b|DELETE\b)[^`\n]*\$\{[^}]+\}/i,
  },
  {
    ruleId: 'appsec.os-command-interpolation',
    domain: 'APPSEC',
    skillName: 'security-input',
    title: 'Dynamic OS Shell Execution Interpolation',
    description: 'Interpolating variables into child_process.exec / shell invocations permits command injection.',
    cwe_id: 'CWE-78',
    owasp_category: 'A03:2021-Injection',
    severity: 'CRITICAL',
    confidence: 'FIRM',
    target_type: 'SOURCE_CODE',
    filePattern: /\.(?:[cm]?[jt]sx?|py|sh)$/i,
    skipCommentLines: true,
    regex: /\b(?:exec|execSync|os\.system)\s*\(\s*`[^`\n]*\$\{[^}]+\}/,
  },

  // --- AGENTSEC & MCP ---
  {
    ruleId: 'agentsec.prompt-override-delimiter',
    domain: 'AGENTSEC_MCP',
    skillName: 'security-ai-agents',
    title: 'Untrusted Prompt Override or Delimiter Marker',
    description: 'Instruction override or system prompt delimiter found inside prompt/tool/document artifact.',
    cwe_id: 'CWE-74',
    owasp_category: 'LLM01:2025-Prompt Injection',
    severity: 'HIGH',
    confidence: 'FIRM',
    target_type: 'LLM_PROMPT',
    regex: /(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|<\|(?:im_start|system|im_end)\|>|<\/?system>|\[\/?INST\])/i,
  },
  {
    ruleId: 'agentsec.exfiltration-webhook',
    domain: 'AGENTSEC_MCP',
    skillName: 'security-ai-agents',
    title: 'Suspicious External Exfiltration Endpoint in Agent Artifact',
    description: 'Untrusted webhook/tunnel sink detected inside agent instructions or tool metadata.',
    cwe_id: 'CWE-918',
    owasp_category: 'LLM02:2025-Sensitive Information Disclosure',
    severity: 'HIGH',
    confidence: 'CERTAIN',
    target_type: 'MCP_TOOL',
    regex: /https?:\/\/(?:[a-zA-Z0-9-]+\.)*(?:webhook\.site|burpcollaborator\.net|oastify\.com|requestbin\.net|ngrok\.io|interact\.sh)/i,
  },

  // --- SUPPLY CHAIN & CI/CD ---
  {
    ruleId: 'supplychain.unpinned-github-action',
    domain: 'SUPPLY_CHAIN',
    skillName: 'security-supply-chain',
    title: 'Unpinned GitHub Action Reference (Mutable Tag/Branch)',
    description: 'GitHub Actions workflow references an external action by mutable tag/branch instead of a 40-hex commit SHA.',
    cwe_id: 'CWE-829',
    owasp_category: 'A08:2021-Software and Data Integrity Failures',
    severity: 'HIGH',
    confidence: 'CERTAIN',
    target_type: 'CONFIGURATION',
    filePattern: /\.ya?ml$/i,
    skipCommentLines: true,
    regex: /\buses:\s*[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_./-]+@(?!([a-fA-F0-9]{40}\b))[\w.-]+/,
  },
  {
    ruleId: 'supplychain.curl-pipe-shell',
    domain: 'SUPPLY_CHAIN',
    skillName: 'security-ci-cd',
    title: 'Unverified Remote Script Piped to Shell',
    description: 'Downloading and directly piping remote content into sh/bash bypasses checksum verification.',
    cwe_id: 'CWE-829',
    owasp_category: 'A08:2021-Software and Data Integrity Failures',
    severity: 'HIGH',
    confidence: 'CERTAIN',
    target_type: 'CONFIGURATION',
    skipCommentLines: true,
    regex: /\b(?:curl|wget)\b[^\n|]{1,200}\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b/i,
  },
  {
    ruleId: 'supplychain.wildcard-dependency',
    domain: 'SUPPLY_CHAIN',
    skillName: 'security-supply-chain',
    title: 'Unpinned Wildcard or Latest Package Dependency',
    description: 'Package manifest pins dependency to "*", "latest", or unencrypted git+http source.',
    cwe_id: 'CWE-1104',
    owasp_category: 'LLM03:2025-Supply Chain Risks',
    severity: 'MEDIUM',
    confidence: 'CERTAIN',
    target_type: 'DEPENDENCY',
    filePattern: /package\.json$/i,
    regex: /"[^"\s]+"\s*:\s*"(?:\*|latest|git\+http:\/\/[^"]+)"/,
  },

  // --- CLOUD & CLOUDFLARE EDGE ---
  {
    ruleId: 'cloudflare.cloud-metadata-ssrf',
    domain: 'CLOUD_CLOUDFLARE',
    skillName: 'security-cloud-infrastructure',
    title: 'Cloud Instance Metadata SSRF Target',
    description: 'Reference to link-local cloud metadata IP (169.254.169.254 / metadata.google.internal) risks IAM credential theft.',
    cwe_id: 'CWE-918',
    owasp_category: 'A10:2021-Server-Side Request Forgery',
    severity: 'CRITICAL',
    confidence: 'CERTAIN',
    target_type: 'CLOUD_RESOURCE',
    regex: /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)/,
  },
  {
    ruleId: 'cloudflare.workers-plaintext-var-secret',
    domain: 'CLOUD_CLOUDFLARE',
    skillName: 'security-cloud-infrastructure',
    title: 'Plaintext Secret in Cloudflare Workers Wrangler [vars]',
    description: 'Sensitive API keys/secrets should use `wrangler secret put` bindings rather than plaintext config variables.',
    cwe_id: 'CWE-798',
    owasp_category: 'A05:2021-Security Misconfiguration',
    severity: 'HIGH',
    confidence: 'FIRM',
    target_type: 'CLOUD_RESOURCE',
    filePattern: /wrangler\.(?:toml|jsonc?)$/i,
    skipCommentLines: true,
    regex: /\b[A-Z0-9_]*(?:SECRET|API_KEY|PRIVATE_KEY|TOKEN|PASSWORD)[A-Z0-9_]*\s*[:=]\s*["'][^"']{6,}["']/,
  },
  {
    ruleId: 'cloudflare.deprecated-tls-version',
    domain: 'CLOUD_CLOUDFLARE',
    skillName: 'security-cloud-infrastructure',
    title: 'Deprecated TLS 1.0 / 1.1 Minimum Version Configured',
    description: 'Edge or server configuration permits legacy TLS 1.0/1.1 protocols vulnerable to downgrade attacks.',
    cwe_id: 'CWE-326',
    owasp_category: 'A02:2021-Cryptographic Failures',
    severity: 'HIGH',
    confidence: 'CERTAIN',
    target_type: 'CLOUD_RESOURCE',
    skipCommentLines: true,
    regex: /(?:min_tls_version|TLSVersion|ssl_protocols)[^\n]*(?:1\.0|1\.1|TLSv1(?!\.[23]))/i,
  },
];

export interface OwaspEvaluationInput {
  files?: OwaspFileInput[];
  mcpTools?: OwaspMcpToolDefinition[];
  policy?: SecurityPackPolicy | unknown;
  todayUtc?: string;
  commitHash?: string;
  discoveringAgentId?: string;
  domainFilter?: OwaspSkillDomain[];
}

export interface OwaspEvaluationOutput {
  status: 'pass' | 'finding' | 'error';
  findings: SecurityFinding[];
  suppressedFindingIds: string[];
  domainSummary: Record<OwaspSkillDomain, number>;
  errors: string[];
  warnings: string[];
}

/**
 * Evaluates deterministic OWASP Security Pack + Cloudflare edge security checks across
 * provided files and MCP tool manifests, enforcing .security-pack.json v1 policy limits & exceptions.
 */
export function evaluateOwaspPolicyChecks(input: OwaspEvaluationInput): OwaspEvaluationOutput {
  const errors: string[] = [];
  const warnings: string[] = [];
  const suppressedFindingIds: string[] = [];
  const findings: SecurityFinding[] = [];
  const domainSummary: Record<OwaspSkillDomain, number> = {
    APPSEC: 0,
    AGENTSEC_MCP: 0,
    SUPPLY_CHAIN: 0,
    CLOUD_CLOUDFLARE: 0,
  };

  let parsedPolicy: SecurityPackPolicy = { version: 1 };
  if (input.policy !== undefined) {
    try {
      parsedPolicy = parseSecurityPackPolicy(input.policy, input.todayUtc);
    } catch (err: unknown) {
      return {
        status: 'error',
        findings: [],
        suppressedFindingIds: [],
        domainSummary,
        errors: [sanitizeOutput(err instanceof Error ? err.message : String(err))],
        warnings: [],
      };
    }
  }

  const maxFiles = parsedPolicy.limits?.maxFiles ?? 5000;
  const maxFileBytes = parsedPolicy.limits?.maxFileBytes ?? 2 * 1024 * 1024;
  const maxTotalBytes = parsedPolicy.limits?.maxTotalBytes ?? 32 * 1024 * 1024;

  const files = input.files ?? [];
  if (files.length > maxFiles) {
    return {
      status: 'error',
      findings: [],
      suppressedFindingIds: [],
      domainSummary,
      errors: [`File count limit exceeded: ${files.length} exceeds maxFiles limit ${maxFiles}`],
      warnings: [],
    };
  }

  const domainAllow = input.domainFilter && input.domainFilter.length > 0
    ? new Set(input.domainFilter)
    : undefined;
  const commitHash = input.commitHash || 'e5f6a7b8c9d01234567890123456789012345678';
  const discoveringAgentId = input.discoveringAgentId || 'owasp-skills-pack-scanner';

  const exceptionSet = new Set(
    (parsedPolicy.exceptions ?? []).map((e) => e.fingerprint.toLowerCase())
  );

  const rawMatches: OwaspRuleMatch[] = [];
  let totalBytes = 0;

  for (const file of files) {
    const filePath = (file.path ?? '').trim();
    if (!filePath || filePath.includes('..') || filePath.includes('\0')) {
      errors.push(`Rejected unsafe file path '${sanitizeOutput(file.path)}'`);
      continue;
    }

    const byteSize = Buffer.byteLength(file.content ?? '', 'utf8');
    if (byteSize > maxFileBytes) {
      errors.push(`File '${filePath}' size ${byteSize} exceeds maxFileBytes ${maxFileBytes}`);
      continue;
    }
    totalBytes += byteSize;
    if (totalBytes > maxTotalBytes) {
      errors.push(`Total scanned byte size exceeds maxTotalBytes ${maxTotalBytes}`);
      break;
    }

    const lines = (file.content ?? '').split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx++) {
      const line = lines[idx];
      const trimmedLine = line.trim();
      const isComment = /^\s*(?:\/\/|#|\*|\/\*|<!--)/.test(line);

      for (const rule of DETERMINISTIC_OWASP_RULES) {
        if (domainAllow && !domainAllow.has(rule.domain)) continue;
        if (rule.filePattern && !rule.filePattern.test(filePath)) continue;
        if (rule.skipCommentLines && isComment) continue;

        const match = rule.regex.exec(line);
        if (match) {
          rawMatches.push({
            ruleId: rule.ruleId,
            domain: rule.domain,
            skillName: rule.skillName,
            title: rule.title,
            description: rule.description,
            cwe_id: rule.cwe_id,
            owasp_category: rule.owasp_category,
            severity: rule.severity,
            confidence: rule.confidence,
            target_type: rule.target_type,
            file_path: filePath,
            start_line: idx + 1,
            end_line: idx + 1,
            matched_token: `${rule.ruleId}:${idx + 1}:${sha256(trimmedLine).slice(0, 12)}`,
          });
        }
      }
    }
  }

  // Evaluate MCP Tool definitions for schema & agency posture
  const mcpTools = input.mcpTools ?? [];
  if (!domainAllow || domainAllow.has('AGENTSEC_MCP')) {
    for (const tool of mcpTools) {
      const schema = tool.inputSchema;
      if (schema && schema.type === 'object' && schema.additionalProperties !== false) {
        rawMatches.push({
          ruleId: 'agentsec.mcp-schema-permissive',
          domain: 'AGENTSEC_MCP',
          skillName: 'security-ai-agents',
          title: `Permissive MCP Tool Schema on '${sanitizeOutput(tool.name)}'`,
          description: 'MCP tool object inputSchema permits arbitrary additionalProperties, weakening input validation.',
          cwe_id: 'CWE-20',
          owasp_category: 'LLM07:2025-Insecure Tool Design',
          severity: 'MEDIUM',
          confidence: 'CERTAIN',
          target_type: 'MCP_TOOL',
          file_path: `mcp/tools/${tool.name}.json`,
          start_line: 1,
          end_line: 1,
          matched_token: `mcp.schema.additionalProperties:${tool.name}`,
        });
      }

      if (tool.stateChanging === true && tool.requiresApproval !== true) {
        rawMatches.push({
          ruleId: 'agentsec.mcp-state-change-unapproved',
          domain: 'AGENTSEC_MCP',
          skillName: 'security-ai-agents',
          title: `State-Changing MCP Tool '${sanitizeOutput(tool.name)}' Lacks Explicit Approval Guard`,
          description: 'State-changing MCP tool does not enforce explicit approval or Separation of Duties verification.',
          cwe_id: 'CWE-862',
          owasp_category: 'LLM06:2025-Excessive Agency',
          severity: 'HIGH',
          confidence: 'CERTAIN',
          target_type: 'MCP_TOOL',
          file_path: `mcp/tools/${tool.name}.json`,
          start_line: 1,
          end_line: 1,
          matched_token: `mcp.agency.unapproved:${tool.name}`,
        });
      }
    }
  }

  // Convert matches to validated canonical SecurityFinding contracts
  for (let i = 0; i < rawMatches.length; i++) {
    const m = rawMatches[i];
    const fingerprint = computeFindingFingerprint({
      cwe_id: m.cwe_id,
      file_path: m.file_path,
      rule_or_match: m.ruleId,
    });

    const findingId = `SK-OWASP-${sha256(`${m.ruleId}\0${m.file_path}\0${m.start_line}\0${i}`).substring(0, 16)}`;

    if (exceptionSet.has(fingerprint.toLowerCase())) {
      suppressedFindingIds.push(findingId);
      continue;
    }

    const candidate: SecurityFinding = {
      finding_id: findingId,
      source_engine: 'owasp_skills_pack',
      title: sanitizeOutput(m.title),
      description: sanitizeOutput(m.description),
      cwe_id: m.cwe_id,
      owasp_category: m.owasp_category,
      severity: m.severity,
      confidence: m.confidence,
      target_type: m.target_type,
      target: m.file_path,
      location: {
        file_path: m.file_path,
        start_line: m.start_line,
        end_line: m.end_line,
        symbol: m.skillName,
      },
      fingerprint,
      commit_hash: commitHash,
      discovered_at: new Date().toISOString(),
      agent_context: {
        discovering_agent_id: discoveringAgentId,
        agent_archetype: 'owasp_policy_evaluator',
        tool_call_trace: [`owasp-skills-pack:${m.skillName}:${m.ruleId}`],
        reasoning_hash: sha256(m.matched_token),
      },
      raw_metadata: sanitizeObject({
        rule_id: m.ruleId,
        owasp_domain: m.domain,
        skill_name: m.skillName,
        match_digest: sha256(m.matched_token),
      }),
    };

    const validated = validateFinding(candidate);
    if (validated.success) {
      findings.push(validated.data);
      domainSummary[m.domain]++;
    } else {
      warnings.push(`Discarded non-compliant OWASP finding ${findingId}: ${validated.errors?.map(e => e.message).join('; ')}`);
    }
  }

  return {
    status: errors.length > 0 ? 'error' : findings.length > 0 ? 'finding' : 'pass',
    findings,
    suppressedFindingIds,
    domainSummary,
    errors,
    warnings,
  };
}

export interface OwaspSkillsPackAdapterConfig {
  packDir?: string;
}

/**
 * OWASP Security Skills Pack & Cloudflare Policy Adapter.
 */
export class OwaspSkillsPackAdapter implements ISecurityEngineAdapter {
  public readonly engine_name = 'owasp_skills_pack';
  public readonly supported_target_types: (TargetType | string)[] = [
    'SOURCE_CODE',
    'CONFIGURATION',
    'MCP_TOOL',
    'CLOUD_RESOURCE',
    'DEPENDENCY',
  ];

  private readonly config: OwaspSkillsPackAdapterConfig;
  private loadedCatalog: OwaspSkillsCatalog = EMBEDDED_OWASP_SKILLS_CATALOG;

  constructor(config: OwaspSkillsPackAdapterConfig = {}) {
    this.config = config;
  }

  public getCatalog(): OwaspSkillsCatalog {
    return this.loadedCatalog;
  }

  public getStatus(): AdapterStatusReport {
    return {
      engine_name: this.engine_name,
      mode: 'PASSIVE',
      configuration_status: 'CONFIGURED',
      configured: true,
      enabled: true,
      reason: `OWASP Security Skills Pack v${this.loadedCatalog.version} (${this.loadedCatalog.skills.length} skills / ${this.loadedCatalog.domainCount} domains) loaded in deterministic passive mode.`,
      capabilities: [
        'appsec_static_policy',
        'agentsec_mcp_posture',
        'supply_chain_pinning',
        'cloudflare_edge_audit',
        'security_pack_v1_exceptions',
      ],
      details: {
        catalog_version: this.loadedCatalog.version,
        domain_count: this.loadedCatalog.domainCount,
        skill_count: this.loadedCatalog.skills.length,
        source: this.loadedCatalog.source,
      },
    };
  }

  public async initialize(): Promise<boolean> {
    if (this.config.packDir) {
      try {
        this.loadedCatalog = await loadOwaspSkillsCatalog(this.config.packDir);
      } catch {
        return false;
      }
    }
    return true;
  }

  public async scan(target: ScanTarget, options?: ScanOptions): Promise<AdapterScanResult> {
    const startTime = Date.now();
    const timeoutMs = options?.timeout_ms ?? 20_000;

    return safeExecute(async () => {
      return await withTimeout(
        this.performScanInternal(target, options, startTime),
        timeoutMs,
        'OwaspSkillsPackAdapter.scan'
      );
    }, (error: Error) => ({
      engine_name: this.engine_name,
      status: 'error',
      configuration_status: 'CONFIGURED',
      findings: [],
      duration_ms: Date.now() - startTime,
      is_partial: error instanceof TimeoutError,
      errors: [sanitizeOutput(error.message)],
    }));
  }

  private async performScanInternal(
    target: ScanTarget,
    options: ScanOptions | undefined,
    startTime: number
  ): Promise<AdapterScanResult> {
    if (typeof target.metadata?.pack_dir === 'string' && target.metadata.pack_dir.trim()) {
      this.loadedCatalog = await loadOwaspSkillsCatalog(target.metadata.pack_dir);
    }

    const filesInput: OwaspFileInput[] = [];
    if (Array.isArray(target.metadata?.files)) {
      for (const f of target.metadata.files as OwaspFileInput[]) {
        filesInput.push(f);
      }
    } else if (typeof target.metadata?.content === 'string') {
      filesInput.push({
        path: target.target_url_or_path || 'target.txt',
        content: target.metadata.content,
      });
    }

    const mcpTools = Array.isArray(target.metadata?.mcp_tools)
      ? (target.metadata.mcp_tools as OwaspMcpToolDefinition[])
      : [];

    const evaluation = evaluateOwaspPolicyChecks({
      files: filesInput,
      mcpTools,
      policy: target.metadata?.policy,
      todayUtc: target.metadata?.today_utc as string | undefined,
      commitHash: target.commit_hash,
      discoveringAgentId: target.metadata?.discovering_agent_id as string | undefined,
      domainFilter: target.metadata?.domain_filter as OwaspSkillDomain[] | undefined,
    });

    if (evaluation.status === 'error') {
      return {
        engine_name: this.engine_name,
        status: 'error',
        configuration_status: 'CONFIGURED',
        findings: [],
        duration_ms: Date.now() - startTime,
        errors: evaluation.errors,
        warnings: evaluation.warnings.length > 0 ? evaluation.warnings : undefined,
      };
    }

    let findings = evaluation.findings;
    if (options?.severity_filter && options.severity_filter.length > 0) {
      findings = findings.filter((f) => options.severity_filter!.includes(f.severity));
    }
    if (options?.max_findings && findings.length > options.max_findings) {
      findings = findings.slice(0, options.max_findings);
      evaluation.warnings.push(`Truncated findings to configured max_findings=${options.max_findings}.`);
    }

    return {
      engine_name: this.engine_name,
      status: 'success',
      configuration_status: 'CONFIGURED',
      findings,
      duration_ms: Date.now() - startTime,
      warnings: evaluation.warnings.length > 0 ? evaluation.warnings : undefined,
      raw_metadata: {
        catalog_version: this.loadedCatalog.version,
        skill_count: this.loadedCatalog.skills.length,
        suppressed_count: evaluation.suppressedFindingIds.length,
        domain_summary: evaluation.domainSummary,
      },
    };
  }

  public async reproduce(finding: SecurityFinding, options?: ReproduceOptions): Promise<AdapterReproduceResult> {
    const startTime = Date.now();
    const timeoutMs = options?.timeout_ms ?? 15_000;

    return safeExecute(async () => {
      return await withTimeout(
        this.performReproduceInternal(finding, options, startTime),
        timeoutMs,
        'OwaspSkillsPackAdapter.reproduce'
      );
    }, (error: Error) => ({
      engine_name: this.engine_name,
      finding_id: finding.finding_id,
      status: 'error',
      reproduction_verified: false,
      duration_ms: Date.now() - startTime,
      error: sanitizeOutput(error.message),
    }));
  }

  private async performReproduceInternal(
    finding: SecurityFinding,
    options: ReproduceOptions | undefined,
    startTime: number
  ): Promise<AdapterReproduceResult> {
    const customConfig = options?.custom_config || {};
    const verifierAgentId = options?.verifier_agent_id ?? 'owasp-policy-verifier';
    let confirmed = customConfig.confirmed !== false;

    // If source content or MCP tool manifest is provided, re-evaluate deterministically
    if (typeof customConfig.content === 'string') {
      const check = evaluateOwaspPolicyChecks({
        files: [{ path: finding.location.file_path, content: customConfig.content }],
        commitHash: finding.commit_hash,
      });
      confirmed = check.findings.some((f) => f.fingerprint === finding.fingerprint || f.cwe_id === finding.cwe_id);
    }

    const status = confirmed ? 'VERIFIED_TRUE_POSITIVE' : 'REFUTED_FALSE_POSITIVE';
    const recordedAt = new Date().toISOString();
    const ruleId = String(finding.raw_metadata?.rule_id || finding.cwe_id);
    const proofPayload = `owasp-skills-pack check --rule ${ruleId} --file ${finding.location.file_path}:${finding.location.start_line}`;

    const evidence: Evidence = {
      evidence_id: `SK-EVID-OWASP-${sha256(finding.finding_id + recordedAt).substring(0, 16)}`,
      finding_id: finding.finding_id,
      verification_type: 'DETERMINISTIC_AST',
      status,
      verifier_agent_id: verifierAgentId,
      sandbox_environment: {
        runtime: 'dry_run',
        network_isolated: true,
        timeout_ms: options?.timeout_ms ?? 15_000,
      },
      reproduction_proof: {
        proof_type: 'CLI_COMMAND',
        payload: proofPayload,
        expected_behavior: 'Policy rule should not trigger once control is properly implemented.',
        observed_vulnerable_behavior: confirmed
          ? `Deterministic OWASP policy rule '${ruleId}' matched target artifact '${finding.location.file_path}'.`
          : `Deterministic OWASP policy rule '${ruleId}' did not match target artifact.`,
      },
      chain_hash: computeEvidenceChainHash({
        finding_id: finding.finding_id,
        verifier_agent_id: verifierAgentId,
        status,
        script_sha256: sha256(proofPayload),
        recorded_at: recordedAt,
      }),
      recorded_at: recordedAt,
    };

    const validated = validateEvidence(evidence);
    if (!validated.success) {
      return {
        engine_name: this.engine_name,
        finding_id: finding.finding_id,
        status: 'error',
        reproduction_verified: false,
        duration_ms: Date.now() - startTime,
        error: `Evidence validation failed: ${validated.errors?.map(e => e.message).join('; ')}`,
      };
    }

    return {
      engine_name: this.engine_name,
      finding_id: finding.finding_id,
      status: 'success',
      evidence: validated.data,
      reproduction_verified: confirmed,
      duration_ms: Date.now() - startTime,
    };
  }

  public async recheck(patch: PatchProposal, options?: RecheckOptions): Promise<AdapterRecheckResult> {
    const startTime = Date.now();
    return safeExecute<AdapterRecheckResult>(async () => {
      const customConfig = options?.custom_config || {};
      const verifierAgentId = options?.verifier_agent_id ?? 'owasp-policy-recheck';

      // Extract added lines from patch diff_content to verify patch didn't introduce new OWASP violations
      const addedLines = patch.diff_content
        .split('\n')
        .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
        .map((l) => l.substring(1))
        .join('\n');

      let violationPresent = customConfig.reproducer_still_fails === true;
      if (addedLines.trim().length > 0 && patch.affected_files.length > 0) {
        const evalAdded = evaluateOwaspPolicyChecks({
          files: [{ path: patch.affected_files[0], content: addedLines }],
          commitHash: patch.base_commit,
        });
        if (evalAdded.findings.length > 0) {
          violationPresent = true;
        }
      }

      const recheckStatus: RecheckStatus = violationPresent ? 'reproducer_still_fails' : 'passed_clean';
      const recordedAt = new Date().toISOString();
      const evStatus = violationPresent ? 'VERIFIED_TRUE_POSITIVE' : 'REFUTED_FALSE_POSITIVE';

      const evidence: Evidence = {
        evidence_id: `SK-EVID-OWASP-RECHECK-${sha256(patch.patch_id + recordedAt).substring(0, 16)}`,
        finding_id: patch.finding_id,
        verification_type: 'DETERMINISTIC_AST',
        status: evStatus,
        verifier_agent_id: verifierAgentId,
        sandbox_environment: {
          runtime: 'dry_run',
          network_isolated: true,
          timeout_ms: options?.timeout_ms ?? 15_000,
        },
        reproduction_proof: {
          proof_type: 'CLI_COMMAND',
          payload: `owasp-skills-pack recheck ${patch.affected_files.join(',')}`,
          expected_behavior: 'Patched additions satisfy OWASP AppSec, AgentSec, Supply Chain, and Edge policies.',
          observed_vulnerable_behavior: violationPresent
            ? 'OWASP deterministic policy rule still triggered on patched lines.'
            : 'Zero OWASP policy violations detected in added patch lines.',
        },
        chain_hash: computeEvidenceChainHash({
          finding_id: patch.finding_id,
          verifier_agent_id: verifierAgentId,
          status: evStatus,
          script_sha256: patch.patch_sha256,
          recorded_at: recordedAt,
        }),
        recorded_at: recordedAt,
      };

      const evValid = validateEvidence(evidence);

      return {
        engine_name: this.engine_name,
        patch_id: patch.patch_id,
        finding_id: patch.finding_id,
        status: 'success',
        recheck_status: recheckStatus,
        evidence: evValid.success ? evValid.data : undefined,
        duration_ms: Date.now() - startTime,
        tests_passed: !violationPresent,
        reproducer_passed: !violationPresent,
      };
    }, (error: Error): AdapterRecheckResult => ({
      engine_name: this.engine_name,
      patch_id: patch.patch_id,
      finding_id: patch.finding_id,
      status: 'error',
      recheck_status: 'untested',
      duration_ms: Date.now() - startTime,
      error: sanitizeOutput(error.message),
      tests_passed: false,
      reproducer_passed: false,
    }));
  }
}
