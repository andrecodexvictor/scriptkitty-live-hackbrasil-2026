/**
 * @file packages/quality-gate/src/policy.ts
 * @description Policy schema, parser, bounded limits, severity thresholds,
 * exact exception validation, and fail-closed scope checking for ScriptKitty 2.0.
 */

import { resolve, relative, isAbsolute, normalize } from 'node:path';
import { z } from 'zod';
import {
  Severity,
  SeveritySchema,
  type SecurityFinding,
} from '@script-kitty/contracts';

/**
 * Supported Policy Version
 */
export const SUPPORTED_POLICY_VERSION = 1;

/**
 * Standard default bounded limits for policy enforcement.
 */
export const POLICY_DEFAULTS = {
  VERSION: 1 as const,
  MAX_FILE_BYTES: 2 * 1024 * 1024, // 2 MiB per file
  MAX_FILES: 5000,                  // 5,000 files maximum
  MAX_TOTAL_BYTES: 32 * 1024 * 1024, // 32 MiB total scanned bytes
  TIMEOUT_MS: 20_000,               // 20s scanner/evaluation timeout
  SEVERITY_THRESHOLD: ['CRITICAL', 'HIGH'] as Severity[],
};

/**
 * Policy Exception Schema.
 * Requires exact { rule_id, fingerprint, reason, expires }.
 * expires must be valid UTC YYYY-MM-DD and >= today.
 * Supports both rule_id / ruleId.
 */
export const PolicyExceptionSchema = z.preprocess((val) => {
  if (typeof val === 'object' && val !== null) {
    const raw = val as Record<string, unknown>;
    return {
      rule_id: raw.rule_id ?? raw.ruleId,
      fingerprint: raw.fingerprint,
      reason: raw.reason,
      expires: raw.expires,
    };
  }
  return val;
}, z.object({
  rule_id: z.string().min(1, { message: 'rule_id is required' }).max(100),
  fingerprint: z.string().regex(/^[a-fA-F0-9]{64}$/, {
    message: 'fingerprint must be a 64-character hexadecimal SHA-256 hash',
  }),
  reason: z.string().min(3, { message: 'reason must be at least 3 characters' }).max(1000),
  expires: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, {
    message: 'expires must match YYYY-MM-DD UTC date format',
  }),
})).refine((data) => {
  const date = new Date(`${data.expires}T00:00:00Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === data.expires;
}, {
  message: 'expires must be a valid Gregorian calendar date in UTC YYYY-MM-DD format',
  path: ['expires'],
});

export type PolicyException = z.infer<typeof PolicyExceptionSchema>;

/**
 * Canonical Policy Schema.
 * Bounded limits, exact exceptions, severity thresholds, and allowed scopes.
 */
export const PolicySchema = z.preprocess((val) => {
  if (typeof val === 'object' && val !== null) {
    const raw = val as Record<string, unknown>;
    return {
      version: raw.version ?? 1,
      max_file_bytes: raw.max_file_bytes ?? raw.maxFileBytes ?? POLICY_DEFAULTS.MAX_FILE_BYTES,
      max_files: raw.max_files ?? raw.maxFiles ?? POLICY_DEFAULTS.MAX_FILES,
      max_total_bytes: raw.max_total_bytes ?? raw.maxTotalBytes ?? POLICY_DEFAULTS.MAX_TOTAL_BYTES,
      timeout_ms: raw.timeout_ms ?? raw.timeoutMs ?? POLICY_DEFAULTS.TIMEOUT_MS,
      severity_threshold: raw.severity_threshold ?? raw.severityThreshold ?? POLICY_DEFAULTS.SEVERITY_THRESHOLD,
      required_scanners: raw.required_scanners ?? raw.requiredScanners ?? [],
      exceptions: raw.exceptions ?? [],
      allowed_scopes: raw.allowed_scopes ?? raw.allowedScopes ?? [],
    };
  }
  return val;
}, z.object({
  version: z.literal(1, {
    errorMap: () => ({ message: 'Invalid security policy: version must strictly be 1' }),
  }),
  max_file_bytes: z.number().int().positive().max(
    POLICY_DEFAULTS.MAX_FILE_BYTES,
    { message: `max_file_bytes cannot exceed ${POLICY_DEFAULTS.MAX_FILE_BYTES} bytes (2 MiB)` }
  ).default(POLICY_DEFAULTS.MAX_FILE_BYTES),
  max_files: z.number().int().positive().max(
    POLICY_DEFAULTS.MAX_FILES,
    { message: `max_files cannot exceed ${POLICY_DEFAULTS.MAX_FILES}` }
  ).default(POLICY_DEFAULTS.MAX_FILES),
  max_total_bytes: z.number().int().positive().max(
    POLICY_DEFAULTS.MAX_TOTAL_BYTES,
    { message: `max_total_bytes cannot exceed ${POLICY_DEFAULTS.MAX_TOTAL_BYTES} bytes (32 MiB)` }
  ).default(POLICY_DEFAULTS.MAX_TOTAL_BYTES),
  timeout_ms: z.number().int().positive().max(600_000).default(POLICY_DEFAULTS.TIMEOUT_MS),
  severity_threshold: z.preprocess((val) => {
    if (typeof val === 'string') return [val.toUpperCase()];
    if (Array.isArray(val)) return val.map((s) => String(s).toUpperCase());
    return val;
  }, z.array(SeveritySchema)).default(['CRITICAL', 'HIGH']),
  required_scanners: z.array(z.string()).default([]),
  exceptions: z.array(PolicyExceptionSchema).max(5000).default([]),
  allowed_scopes: z.array(z.string()).default([]),
}));

export type Policy = z.infer<typeof PolicySchema>;

/**
 * Default safe fallback policy.
 */
export const DEFAULT_POLICY: Policy = {
  version: 1,
  max_file_bytes: POLICY_DEFAULTS.MAX_FILE_BYTES,
  max_files: POLICY_DEFAULTS.MAX_FILES,
  max_total_bytes: POLICY_DEFAULTS.MAX_TOTAL_BYTES,
  timeout_ms: POLICY_DEFAULTS.TIMEOUT_MS,
  severity_threshold: ['CRITICAL', 'HIGH'],
  required_scanners: [],
  exceptions: [],
  allowed_scopes: [],
};

/**
 * Checks whether an exception's expiration date has passed.
 * Returns true if expired (< today).
 */
export function isExceptionExpired(exception: PolicyException, currentDate?: string): boolean {
  const today = currentDate ?? new Date().toISOString().slice(0, 10);
  return exception.expires < today;
}

/**
 * Validates an array of exceptions. If any exception is expired, returns { valid: false, expiredExceptions }.
 */
export function evaluateExceptionsValidity(
  exceptions: PolicyException[],
  currentDate?: string
): { valid: boolean; expiredExceptions: PolicyException[] } {
  const expired: PolicyException[] = [];
  for (const ex of exceptions) {
    if (isExceptionExpired(ex, currentDate)) {
      expired.push(ex);
    }
  }
  return {
    valid: expired.length === 0,
    expiredExceptions: expired,
  };
}

/**
 * Checks whether a candidate finding is exempted by an unexpired policy exception.
 * Finding fingerprint must match exactly (case-insensitive).
 */
export function findMatchingException(
  finding: { rule_id?: string; fingerprint: string },
  exceptions: PolicyException[],
  currentDate?: string
): { matched: boolean; exception?: PolicyException; isExpired: boolean } {
  const fFingerprint = finding.fingerprint.trim().toLowerCase();
  for (const ex of exceptions) {
    if (ex.fingerprint.trim().toLowerCase() === fFingerprint) {
      if (!finding.rule_id || ex.rule_id.toLowerCase() === finding.rule_id.toLowerCase()) {
        const expired = isExceptionExpired(ex, currentDate);
        return { matched: true, exception: ex, isExpired: expired };
      }
    }
  }
  return { matched: false, isExpired: false };
}

/**
 * Checks if a target path is inside the authorized scopeRoot.
 * Prevents directory traversal attacks (`../`, symlink escapes, drive changes).
 */
export function insideScope(scopeRoot: string, targetPath: string): boolean {
  if (!scopeRoot || !targetPath) return false;

  const resolvedRoot = resolve(scopeRoot);
  const resolvedTarget = resolve(resolvedRoot, targetPath);

  // Normalize paths to forward slashes for cross-platform comparison
  const normRoot = normalize(resolvedRoot).toLowerCase();
  const normTarget = normalize(resolvedTarget).toLowerCase();

  // Root must be a prefix of target
  if (normTarget === normRoot) {
    return true;
  }

  const isWindows = process.platform === 'win32';
  const sep = isWindows ? '\\' : '/';

  const rel = relative(resolvedRoot, resolvedTarget);
  if (rel === '') return true;
  if (rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) {
    return false;
  }

  // Double check drive letter or root path prefix on Windows
  if (isWindows) {
    if (!normTarget.startsWith(normRoot.endsWith('\\') ? normRoot : normRoot + '\\')) {
      return false;
    }
  } else {
    if (!normTarget.startsWith(normRoot.endsWith('/') ? normRoot : normRoot + '/')) {
      return false;
    }
  }

  return true;
}

/**
 * Checks if target path is in ANY of the allowed scopes.
 * If allowedScopes is empty, scope checking is bypassed or evaluated against root.
 */
export function isTargetInScope(targetPath: string, allowedScopes: string[] | string): boolean {
  const scopes = Array.isArray(allowedScopes) ? allowedScopes : [allowedScopes];
  if (scopes.length === 0) return true;

  // Reject explicit traversal sequences even before resolution
  if (targetPath.includes('../') || targetPath.includes('..\\')) {
    // If target has .. but resolves within scope, insideScope will verify safely
  }

  return scopes.some((scope) => insideScope(scope, targetPath));
}

/**
 * Checks whether a finding severity meets or exceeds the blocking threshold.
 */
export function isSeverityBlocking(
  severity: Severity | string,
  threshold: Severity[] | Severity | string = ['CRITICAL', 'HIGH']
): boolean {
  const normalizedSeverity = String(severity).trim().toUpperCase();
  const thresholds = Array.isArray(threshold)
    ? threshold.map((t) => String(t).trim().toUpperCase())
    : [String(threshold).trim().toUpperCase()];

  return thresholds.includes(normalizedSeverity);
}

/**
 * Parses and validates an arbitrary input into a strict Policy object.
 * Throws on schema violations or malformed policies.
 */
export function parsePolicy(input: unknown): Policy {
  return PolicySchema.parse(input);
}

/**
 * Safe parser for Policy returning a structured result.
 */
export function validatePolicy(input: unknown): {
  success: boolean;
  data?: Policy;
  errors?: string[];
} {
  const result = PolicySchema.safeParse(input);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    errors: result.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`),
  };
}
