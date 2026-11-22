/**
 * @file packages/runtime-guardian/src/scope-guard.ts
 * @description Resource Scope & Path Boundary Guard: Root Containment,
 * Path Traversal Prevention, Null Byte Filtering, NTFS ADS Defense,
 * Symlink Resolution, and Sensitive File Access Protection.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  type ScopeGuardPolicy,
  type InterceptionDecision,
  type InterceptionContext,
  GuardianSecurityError,
} from './types.js';

export const DEFAULT_BLOCKED_PATTERNS: RegExp[] = [
  /^\.git(?:[\\\/]|$)/i,
  /(?:^|[\\\/])\.git(?:[\\\/]|$)/i,
  /^\.env(?:\.[a-zA-Z0-9_-]+)?$/i,
  /(?:^|[\\\/])\.env(?:\.[a-zA-Z0-9_-]+)?$/i,
  /(?:^|[\\\/])id_(?:rsa|ed25519|ecdsa)(?:\.pub)?$/i,
  /(?:^|[\\\/])\.aws[\\\/]credentials$/i,
  /\.(?:pem|key|pfx|p12)$/i,
  /(?:^|[\\\/])etc[\\\/](?:passwd|shadow)$/i,
];

export const DEFAULT_PATH_ARGUMENT_NAMES: string[] = [
  'path',
  'filePath',
  'file_path',
  'targetPath',
  'target_path',
  'dir',
  'directory',
  'file',
  'source',
  'destination',
  'output_path',
  'outputPath',
];

/**
 * Validates, normalizes, and verifies boundary containment for a candidate file or resource path.
 */
export function validateAndResolvePath(
  inputPath: string,
  policy: ScopeGuardPolicy
): string {
  if (!inputPath || typeof inputPath !== 'string') {
    throw new GuardianSecurityError(
      'Path must be a non-empty string',
      'E_PATH_INVALID',
      'scope_guard',
      'path_validation'
    );
  }

  // 1. Reject Null Bytes and ASCII control characters
  if (/[\x00-\x1F\x7F]/.test(inputPath) || inputPath.includes('%00')) {
    throw new GuardianSecurityError(
      `Path contains null bytes or illegal control characters: ${inputPath}`,
      'E_PATH_NULL_BYTE',
      'scope_guard',
      'null_byte_filter'
    );
  }

  // 2. Detect Double / Multi-layer URL Encoding
  let decoded = inputPath;
  try {
    const once = decodeURIComponent(inputPath);
    const twice = decodeURIComponent(once);
    if (once !== twice) {
      throw new GuardianSecurityError(
        `Multi-layer URL encoding detected in path: ${inputPath}`,
        'E_PATH_DOUBLE_ENCODING',
        'scope_guard',
        'encoding_check'
      );
    }
    decoded = once;
  } catch (err: unknown) {
    if (err instanceof GuardianSecurityError) throw err;
    throw new GuardianSecurityError(
      `Invalid URL encoding in path: ${inputPath}`,
      'E_PATH_MALFORMED_ENCODING',
      'scope_guard',
      'encoding_check'
    );
  }

  // 3. Unicode NFKC Normalization (e.g., fullwidth dot \uff0e\uff0e\uff0f -> ../)
  decoded = decoded.normalize('NFKC');

  // 4. Handle Resource URI Schemes if present
  let cleanPath = decoded;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(decoded)) {
    try {
      const url = new URL(decoded);
      const allowedSchemes = policy.allowedUriSchemes ?? ['file', 'sqlite'];
      const scheme = url.protocol.replace(':', '');
      if (!allowedSchemes.includes(scheme)) {
        throw new GuardianSecurityError(
          `URI Scheme '${scheme}' is not permitted. Allowed: ${allowedSchemes.join(', ')}`,
          'E_INVALID_URI_SCHEME',
          'scope_guard',
          'scheme_check'
        );
      }
      if (scheme === 'file') {
        cleanPath = fileURLToPath(url);
      } else if (scheme === 'sqlite') {
        cleanPath = url.pathname;
      }
    } catch (e: unknown) {
      if (e instanceof GuardianSecurityError) throw e;
      throw new GuardianSecurityError(
        `Malformed URI in path: ${decoded}`,
        'E_INVALID_URI_SCHEME',
        'scope_guard',
        'scheme_check'
      );
    }
  }

  // 5. Windows Specific Namespace Protections
  if (cleanPath.startsWith('\\\\') || cleanPath.startsWith('//')) {
    throw new GuardianSecurityError(
      `UNC network paths are strictly prohibited: ${inputPath}`,
      'E_PATH_UNC_FORBIDDEN',
      'scope_guard',
      'unc_protection'
    );
  }
  // NTFS Alternate Data Streams (e.g. file.txt::$DATA or file.txt:stream)
  // Ensure we don't accidentally match Windows drive letters like C:\
  const withoutDrive = cleanPath.replace(/^[a-zA-Z]:[\\\/]/, '');
  if (/:/.test(withoutDrive)) {
    throw new GuardianSecurityError(
      `NTFS Alternate Data Streams are prohibited: ${inputPath}`,
      'E_PATH_NTFS_ADS',
      'scope_guard',
      'ntfs_ads_protection'
    );
  }

  // 6. Lexical Resolution
  const allowedRoots = policy.allowedRoots && policy.allowedRoots.length > 0
    ? policy.allowedRoots
    : [process.cwd()];

  const primaryRoot = path.resolve(allowedRoots[0]);
  const resolvedPath = path.isAbsolute(cleanPath)
    ? path.resolve(cleanPath)
    : path.resolve(primaryRoot, cleanPath);

  // 7. Symlink Resolution (realpath)
  let realTargetPath = resolvedPath;
  try {
    if (fs.existsSync(resolvedPath)) {
      realTargetPath = fs.realpathSync.native ? fs.realpathSync.native(resolvedPath) : fs.realpathSync(resolvedPath);
    } else {
      // Resolve nearest existing ancestor directory
      let parentDir = path.dirname(resolvedPath);
      while (parentDir && !fs.existsSync(parentDir) && parentDir !== path.dirname(parentDir)) {
        parentDir = path.dirname(parentDir);
      }
      if (fs.existsSync(parentDir)) {
        const realParent = fs.realpathSync.native ? fs.realpathSync.native(parentDir) : fs.realpathSync(parentDir);
        const relativeLeaf = path.relative(parentDir, resolvedPath);
        realTargetPath = path.resolve(realParent, relativeLeaf);
      }
    }
  } catch {
    // If realpath resolution fails, retain lexically resolved path
    realTargetPath = resolvedPath;
  }

  // 8. Root Containment Invariance Check
  const isWindows = process.platform === 'win32';
  let contained = false;

  for (const root of allowedRoots) {
    let canonicalRoot = path.resolve(root);
    try {
      if (fs.existsSync(canonicalRoot)) {
        canonicalRoot = fs.realpathSync.native ? fs.realpathSync.native(canonicalRoot) : fs.realpathSync(canonicalRoot);
      }
    } catch {
      canonicalRoot = path.resolve(root);
    }

    const targetToCheck = isWindows ? realTargetPath.toLowerCase() : realTargetPath;
    const rootToCheck = isWindows ? canonicalRoot.toLowerCase() : canonicalRoot;

    const rel = path.relative(rootToCheck, targetToCheck);
    if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
      contained = true;
      break;
    }
  }

  if (!contained) {
    throw new GuardianSecurityError(
      `Resolved path '${realTargetPath}' escapes allowed roots: [${allowedRoots.join(', ')}]`,
      'E_PATH_OUT_OF_BOUNDS',
      'scope_guard',
      'root_containment',
      { resolvedPath: realTargetPath, allowedRoots }
    );
  }

  // 9. Blocked Files & Sensitive Resources Check
  if (!policy.allowSensitiveFiles) {
    const blockedPatterns = policy.blockedPathPatterns ?? DEFAULT_BLOCKED_PATTERNS;
    const fileName = path.basename(realTargetPath);

    for (const pat of blockedPatterns) {
      const regex = typeof pat === 'string' ? new RegExp(pat, 'i') : pat;
      if (regex.test(fileName) || regex.test(realTargetPath)) {
        throw new GuardianSecurityError(
          `Access to sensitive file or directory is blocked: '${fileName}'`,
          'E_SENSITIVE_RESOURCE_BLOCKED',
          'scope_guard',
          'sensitive_file_blacklist',
          { targetPath: realTargetPath }
        );
      }
    }
  }

  return realTargetPath;
}

/**
 * ScopeBoundaryGuard intercepts tool call arguments and verifies path containment.
 */
export class ScopeBoundaryGuard {
  private policy: ScopeGuardPolicy;

  constructor(policy?: ScopeGuardPolicy) {
    this.policy = policy ?? {
      enabled: true,
      allowedRoots: [process.cwd()],
    };
  }

  public validatePath(inputPath: string): string {
    return validateAndResolvePath(inputPath, this.policy);
  }

  public inspect(
    args: Record<string, unknown>,
    context?: InterceptionContext
  ): InterceptionDecision {
    if (!this.policy.enabled) {
      return {
        verdict: 'ALLOW',
        detector: 'scope_guard',
        rule_id: 'scope_guard_disabled',
      };
    }

    const pathArgNames = this.policy.pathArgumentNames ?? DEFAULT_PATH_ARGUMENT_NAMES;
    const ancestors = new WeakSet<object>();
    let visitedNodes = 0;
    const MAX_VISITED_NODES = 10_000;

    const inspectNode = (
      node: unknown,
      keyName: string,
      argPath: string,
      depth: number
    ): InterceptionDecision | null => {
      if (depth > 20 || node === null || node === undefined) {
        return null;
      }
      if (++visitedNodes > MAX_VISITED_NODES) {
        return {
          verdict: 'BLOCK',
          detector: 'scope_guard',
          rule_id: 'E_SCOPE_PAYLOAD_TOO_COMPLEX',
          reason: `Tool arguments exceeded scope traversal node limit (${MAX_VISITED_NODES})`,
          metadata: { argument: argPath, depth },
        };
      }

      if (typeof node === 'string') {
        const value = node;
        const isCandidateName = pathArgNames.includes(keyName);

        // Do not treat standard web URLs (http/https) as local filesystem paths unless explicitly named as a path argument
        const isHttpUrl = /^https?:\/\//i.test(value);
        if (isHttpUrl && !isCandidateName) {
          return null;
        }

        const isPathLike =
          isCandidateName ||
          value.includes('..') ||
          value.includes('\\') ||
          value.includes('\0') ||
          value.includes('%00') ||
          /^(?:file|sqlite|gopher|dict|php|expect):\/\//i.test(value);

        if (isPathLike) {
          try {
            validateAndResolvePath(value, this.policy);
          } catch (err: unknown) {
            if (err instanceof GuardianSecurityError) {
              return {
                verdict: 'BLOCK',
                detector: 'scope_guard',
                rule_id: err.code,
                reason: err.message,
                metadata: { argument: argPath, value, details: err.details },
              };
            }
            return {
              verdict: 'BLOCK',
              detector: 'scope_guard',
              rule_id: 'E_PATH_TRAVERSAL',
              reason: (err as Error).message,
              metadata: { argument: argPath, value },
            };
          }
        }
        return null;
      }

      if (typeof node === 'object') {
        if (ancestors.has(node)) {
          return null;
        }
        ancestors.add(node);
        try {
          if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i++) {
              const decision = inspectNode(node[i], keyName, `${argPath}[${i}]`, depth + 1);
              if (decision) return decision;
            }
          } else {
            for (const [k, v] of Object.entries(node)) {
              const nextPath = argPath ? `${argPath}.${k}` : k;
              const decision = inspectNode(v, k, nextPath, depth + 1);
              if (decision) return decision;
            }
          }
        } finally {
          ancestors.delete(node);
        }
      }

      return null;
    };

    // Recursively search all arguments (top-level keys, nested objects, and arrays) for path parameters
    const violation = inspectNode(args, '', '', 0);
    if (violation) {
      return violation;
    }

    return {
      verdict: 'ALLOW',
      detector: 'scope_guard',
      rule_id: 'scope_verified',
      reason: 'All path arguments resolved within allowed boundaries',
    };
  }
}
