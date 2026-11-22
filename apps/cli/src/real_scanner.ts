/**
 * @file apps/cli/src/real_scanner.ts
 * @description Real local SAST, secret leak (with secret redaction), and HTTP security header scanner.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as http from "node:http";
import * as https from "node:https";
import { maskSecret } from "./credentials.js";

export interface RealFinding {
  finding_id: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  file_path?: string;
  line_number?: number;
  snippet?: string;
  description: string;
  remediation: string;
}

export interface RealAuditReport {
  status: "COMPLETED";
  scanned_path: string;
  total_files_scanned: number;
  total_findings: number;
  findings: RealFinding[];
}

export interface RealHttpHeaderReport {
  status: "COMPLETED" | "UNREACHABLE" | "BLOCKED";
  target: string;
  reachable: boolean;
  status_code?: number;
  present_headers: string[];
  missing_headers: string[];
  findings: RealFinding[];
  error?: string;
}

const SECRET_PATTERNS: ReadonlyArray<{
  name: string;
  regex: RegExp;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}> = [
  { name: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/, severity: "CRITICAL" },
  {
    name: "AWS Secret Access Key",
    regex: /(?:aws_secret_access_key|aws_access_key)\s*=\s*['"][A-Za-z0-9/+=]{40}['"]/i,
    severity: "CRITICAL",
  },
  {
    name: "GitHub Personal Access Token",
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
    severity: "CRITICAL",
  },
  {
    name: "OpenAI / Generic API Key",
    regex: /\bsk-[a-zA-Z0-9]{20,}\b/,
    severity: "CRITICAL",
  },
  {
    name: "Slack Bot Token",
    regex: /xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}/,
    severity: "HIGH",
  },
  {
    name: "Generic Private Key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: "CRITICAL",
  },
  {
    name: "Hardcoded JWT Token",
    regex: /eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.?[A-Za-z0-9\-_.+/=]*/,
    severity: "MEDIUM",
  },
];

const SAST_PATTERNS: ReadonlyArray<{
  name: string;
  regex: RegExp;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  remediation: string;
}> = [
  {
    name: "Command Injection Risk",
    regex: /(?:os\.system\(|child_process\.exec\(|execSync\(|eval\()/,
    severity: "CRITICAL",
    remediation: "Avoid passing unsanitized user inputs to shell execution functions; use execFile with shell: false.",
  },
  {
    name: "Insecure Hash (MD5 / SHA1)",
    regex: /(?:crypto\.createHash\(['"](?:md5|sha1)['"]\)|hashlib\.(?:md5|sha1)\()/,
    severity: "HIGH",
    remediation: "Upgrade hash function to SHA-256 or bcrypt/argon2 for password hashing.",
  },
  {
    name: "SQL Injection Risk",
    regex: /(?:SELECT\s+.+\s+FROM\s+.+WHERE\s+.+=\s*['"]\s*\+\s*|query\(\s*`[^`]*\$\{)/i,
    severity: "HIGH",
    remediation: "Use parameterized queries or prepared statements.",
  },
  {
    name: "Path Traversal Risk",
    regex: /(?:res\.sendFile\(.*req\.(?:query|params|body)|fs\.readFileSync\(.*req\.(?:query|params|body))/,
    severity: "HIGH",
    remediation: "Sanitize and resolve user-provided file paths against allowed roots using realpath containment.",
  },
  {
    name: "Wildcard CORS Permissive Header",
    regex: /Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/i,
    severity: "MEDIUM",
    remediation: "Restrict Access-Control-Allow-Origin to specific trusted domains.",
  },
];

const BLOCKED_IMDS_HOSTS = new Set([
  "169.254.169.254",
  "metadata.google.internal",
  "100.100.100.200",
]);

function shouldSkipFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return (
    normalized.includes("/node_modules/") ||
    normalized.includes("/.git/") ||
    normalized.includes("/dist/") ||
    normalized.includes("/build/") ||
    normalized.includes("/.context/") ||
    /\.(?:png|jpg|jpeg|gif|zip|exe|sqlite|db)$/i.test(normalized)
  );
}

function redactMatchedSecret(line: string, regex: RegExp): string {
  const flags = regex.flags.includes("i") ? "gi" : "g";
  return line.replace(new RegExp(regex.source, flags), (match) => {
    return maskSecret(match) ?? "[REDACTED]";
  });
}

export function scanWorkspaceReal(targetPath: string): RealAuditReport {
  const absPath = path.resolve(targetPath);
  const findings: RealFinding[] = [];
  let fileCount = 0;

  if (!fs.existsSync(absPath)) {
    return {
      status: "COMPLETED",
      scanned_path: absPath,
      total_files_scanned: 0,
      total_findings: 0,
      findings: [],
    };
  }

  const baseRoot = fs.statSync(absPath).isDirectory()
    ? absPath
    : path.dirname(absPath);

  function analyzeFile(filePath: string) {
    try {
      const stat = fs.statSync(filePath);
      if (!stat.isFile() || stat.size > 2 * 1024 * 1024) return;
      const content = fs.readFileSync(filePath, "utf-8");
      if (content.includes("\u0000")) return;

      fileCount++;
      const lines = content.split(/\r?\n/);
      const relPath = path.relative(baseRoot, filePath) || path.basename(filePath);

      for (let idx = 0; idx < lines.length; idx++) {
        const line = lines[idx];

        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(line)) {
            findings.push({
              finding_id: `SK-SEC-${findings.length + 1}`,
              category: "Hardcoded Credential / Secret Leak",
              severity: pattern.severity,
              file_path: relPath,
              line_number: idx + 1,
              snippet: redactMatchedSecret(line.trim(), pattern.regex),
              description: `Exposed ${pattern.name} detected in source file.`,
              remediation:
                "Move sensitive credentials to environment variables (.env) or a secure key vault.",
            });
          }
        }

        for (const pattern of SAST_PATTERNS) {
          if (pattern.regex.test(line)) {
            findings.push({
              finding_id: `SK-SAST-${findings.length + 1}`,
              category: "Static Code Vulnerability (SAST)",
              severity: pattern.severity,
              file_path: relPath,
              line_number: idx + 1,
              snippet: line.trim(),
              description: `Potential ${pattern.name} vulnerability pattern detected.`,
              remediation: pattern.remediation,
            });
          }
        }
      }
    } catch {
      // Ignore unreadable files
    }
  }

  function traverseDir(current: string) {
    if (!fs.existsSync(current)) return;
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) return;
    if (stat.isFile()) {
      analyzeFile(current);
      return;
    }
    if (!stat.isDirectory()) return;

    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (shouldSkipFile(fullPath) || entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        traverseDir(fullPath);
      } else if (entry.isFile()) {
        analyzeFile(fullPath);
      }
    }
  }

  traverseDir(absPath);

  return {
    status: "COMPLETED",
    scanned_path: absPath,
    total_files_scanned: fileCount,
    total_findings: findings.length,
    findings,
  };
}

export async function evaluateHttpHeadersDetailed(
  targetUrl: string
): Promise<RealHttpHeaderReport> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return {
        status: "BLOCKED",
        target: targetUrl,
        reachable: false,
        present_headers: [],
        missing_headers: [],
        findings: [],
        error: `Unsupported URL scheme '${parsed.protocol}'`,
      };
    }
    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (BLOCKED_IMDS_HOSTS.has(host)) {
      return {
        status: "BLOCKED",
        target: targetUrl,
        reachable: false,
        present_headers: [],
        missing_headers: [],
        findings: [],
        error: `Target host '${host}' blocked by IMDS SSRF guard`,
      };
    }
  } catch (err) {
    return {
      status: "BLOCKED",
      target: targetUrl,
      reachable: false,
      present_headers: [],
      missing_headers: [],
      findings: [],
      error: err instanceof Error ? err.message : "Invalid target URL",
    };
  }

  return new Promise((resolve) => {
    const client = parsed.protocol === "https:" ? https : http;
    const req = client.get(parsed, { timeout: 3000 }, (res) => {
      res.resume();
      const headers = res.headers;
      const present_headers: string[] = [];
      const missing_headers: string[] = [];
      const findings: RealFinding[] = [];

      const checks: Array<{
        key: string;
        label: string;
        id: string;
        severity: RealFinding["severity"];
        remediation: string;
      }> = [
        {
          key: "strict-transport-security",
          label: "Strict-Transport-Security",
          id: "SK-HDR-01",
          severity: "HIGH",
          remediation:
            "Enforce HTTPS with HSTS header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        },
        {
          key: "content-security-policy",
          label: "Content-Security-Policy",
          id: "SK-HDR-02",
          severity: "MEDIUM",
          remediation: "Add a CSP header to prevent cross-site scripting (XSS) attacks.",
        },
        {
          key: "x-frame-options",
          label: "X-Frame-Options",
          id: "SK-HDR-03",
          severity: "LOW",
          remediation: "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to mitigate clickjacking.",
        },
        {
          key: "x-content-type-options",
          label: "X-Content-Type-Options",
          id: "SK-HDR-04",
          severity: "LOW",
          remediation: "Set 'X-Content-Type-Options: nosniff'.",
        },
      ];

      for (const c of checks) {
        if (headers[c.key]) {
          present_headers.push(c.label);
        } else {
          missing_headers.push(c.label);
          findings.push({
            finding_id: c.id,
            category: "Insecure HTTP Headers",
            severity: c.severity,
            description: `Missing ${c.label} header.`,
            remediation: c.remediation,
          });
        }
      }

      resolve({
        status: "COMPLETED",
        target: targetUrl,
        reachable: true,
        status_code: res.statusCode,
        present_headers,
        missing_headers,
        findings,
      });
    });

    req.on("timeout", () => {
      req.destroy(new Error("HTTP request timed out"));
    });

    req.on("error", (err) => {
      resolve({
        status: "UNREACHABLE",
        target: targetUrl,
        reachable: false,
        present_headers: [],
        missing_headers: [],
        findings: [],
        error: err.message,
      });
    });
  });
}

export async function evaluateHttpHeadersReal(targetUrl: string): Promise<RealFinding[]> {
  const report = await evaluateHttpHeadersDetailed(targetUrl);
  return report.findings;
}
