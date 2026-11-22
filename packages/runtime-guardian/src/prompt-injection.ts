/**
 * @file packages/runtime-guardian/src/prompt-injection.ts
 * @description Multi-tier Prompt Injection Detector and Sanitizer:
 * Behavioral Overrides, Delimiter Breaks, Obfuscation Characters,
 * Exfiltration Targets, and Credential Leak Redaction.
 */

import {
  type PromptInjectionPolicy,
  type InterceptionDecision,
  type InterceptionContext,
  GuardianSecurityError,
} from './types.js';

// ============================================================================
// Detection Patterns
// ============================================================================

export const BEHAVIORAL_OVERRIDE_PATTERNS: RegExp[] = [
  /(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|former)\s+(?:instructions|rules|directives|prompts|commands|constraints)/i,
  /(?:new|updated|revised|replacement)\s+(?:directive|instruction|system\s+prompt|role)\s*:/i,
  /(?:system\s+prompt\s+override|system\s+override|developer\s+override)/i,
  /(?:you\s+are\s+now\s+in|enter|switch\s+to|activate)\s+(?:maintenance|debug|admin|god|unrestricted|developer|sudo)\s+mode/i,
  /(?:from\s+now\s+on\s*,\s*(?:you\s+(?:are|must|will)|act\s+as|pretend\s+to\s+be))/i,
  /(?:do\s+anything\s+now|DAN\s+mode|jailbreak)/i,
  /(?:disregard\s+all\s+(?:safety|ethical)\s+guidelines)/i,
  /(?:stop\s+following\s+(?:your|the)\s+system\s+prompt)/i,
  /(?:you\s+must\s+obey\s+the\s+following\s+override)/i,
];

export const DELIMITER_PATTERNS: RegExp[] = [
  /`{3,}[a-zA-Z]*\n?(?:system|instruction|prompt|override)/i,
  /<\/?(?:system|instruction|instructions|override|admin|developer|context_end|tool_output|prompt)[\s>]/i,
  /\[\/?(?:INST|SYS)\]/i,
  /<\|(?:im_start|im_end|system|user|assistant)\|>/i,
  /<<\/?SYS>>/i,
  /<\/?s>/i,
  /<!--\s*#?\s*(?:system|admin|override).*?-->/i,
];

export const OBFUSCATION_CHARS_REGEX = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g;

export const EXFILTRATION_PATTERNS: RegExp[] = [
  /https?:\/\/(?:[a-zA-Z0-9-]+\.)*(?:webhook\.site|burpcollaborator\.net|oastify\.com|requestbin\.net|pipedream\.net|ngrok\.io|serveo\.net|localhost\.run|interact\.sh)[^\s"'>]*/i,
  /https?:\/\/(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)[^\s"'>]*/i,
  /!\[[^\]]*\]\((https?:\/\/[^\)]+)\)/i, // Markdown image leak
];

export const CREDENTIAL_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/, // AWS Access Key
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/, // GitHub PAT
  /\bsk-[a-zA-Z0-9]{20,}\b/, // OpenAI key
  /\bBearer\s+[a-zA-Z0-9\-._~+/]+=*\b/, // Bearer token
  /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, // PEM Private Key
];

// Helper to normalize basic leetspeak for obfuscation resistance
export function normalizeLeetSpeak(input: string): string {
  return input
    .replace(/1/g, 'i')
    .replace(/0/g, 'o')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/@/g, 'a')
    .replace(/\$/g, 's');
}

export interface ScanFinding {
  type: 'BEHAVIORAL' | 'DELIMITER' | 'EXFILTRATION' | 'CREDENTIAL' | 'OBFUSCATION';
  rule_id: string;
  matched: string;
  path?: string;
}

export interface ScanResult {
  is_safe: boolean;
  findings: ScanFinding[];
  sanitizedText?: string;
}

/**
 * Scans a single string for prompt injection vectors.
 */
export function scanStringForInjection(
  text: string,
  policy?: PromptInjectionPolicy
): ScanResult {
  const findings: ScanFinding[] = [];

  // 1. Check for zero-width / obfuscation characters
  if (OBFUSCATION_CHARS_REGEX.test(text)) {
    findings.push({
      type: 'OBFUSCATION',
      rule_id: 'E_OBFUSCATION_CHARS',
      matched: 'Unicode zero-width or directional characters',
    });
  }

  // Pre-normalize text (NFKC + remove zero-width chars)
  const normalized = text.normalize('NFKC').replace(OBFUSCATION_CHARS_REGEX, '');
  const leetNormalized = normalizeLeetSpeak(normalized);

  // 2. Behavioral overrides check (CRITICAL)
  for (const pattern of BEHAVIORAL_OVERRIDE_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(leetNormalized)) {
      findings.push({
        type: 'BEHAVIORAL',
        rule_id: 'E_BEHAVIORAL_OVERRIDE',
        matched: pattern.source,
      });
      break;
    }
  }

  // 3. Exfiltration hosts check (CRITICAL)
  const blockExfil = policy?.blockExfiltration !== false;
  if (blockExfil) {
    for (const pattern of EXFILTRATION_PATTERNS) {
      const match = normalized.match(pattern);
      if (match) {
        findings.push({
          type: 'EXFILTRATION',
          rule_id: 'E_EXFILTRATION_PAYLOAD',
          matched: match[0],
        });
        break;
      }
    }
  }

  // 4. Delimiters check
  for (const pattern of DELIMITER_PATTERNS) {
    const match = normalized.match(pattern);
    if (match) {
      findings.push({
        type: 'DELIMITER',
        rule_id: 'E_DELIMITER_INJECTION',
        matched: match[0],
      });
      break;
    }
  }

  // 5. Credential leak check
  const detectCreds = policy?.detectCredentials !== false;
  if (detectCreds) {
    for (const pattern of CREDENTIAL_PATTERNS) {
      const match = normalized.match(pattern);
      if (match) {
        findings.push({
          type: 'CREDENTIAL',
          rule_id: 'E_SECRET_ARGUMENT_LEAK',
          matched: match[0],
        });
        break;
      }
    }
  }

  // 6. Custom patterns if provided
  if (policy?.customPatterns) {
    for (const pat of policy.customPatterns) {
      const regex = typeof pat === 'string' ? new RegExp(pat, 'i') : pat;
      if (regex.test(normalized)) {
        findings.push({
          type: 'BEHAVIORAL',
          rule_id: 'E_CUSTOM_INJECTION_PATTERN',
          matched: regex.source,
        });
      }
    }
  }

  return {
    is_safe: findings.length === 0,
    findings,
  };
}

/**
 * Sanitizes a string by stripping obfuscation characters, neutralizing delimiters,
 * redacting credentials, and replacing injection markers.
 */
export function sanitizeString(text: string): string {
  // 1. Strip zero-width chars and normalize NFKC
  let result = text.normalize('NFKC').replace(OBFUSCATION_CHARS_REGEX, '');

  // 2. Redact credentials
  for (const pattern of CREDENTIAL_PATTERNS) {
    result = result.replace(new RegExp(pattern, 'g'), '[REDACTED_SECRET]');
  }

  // 3. Replace behavioral overrides
  for (const pattern of BEHAVIORAL_OVERRIDE_PATTERNS) {
    result = result.replace(new RegExp(pattern, 'g'), '[SANITIZED_INJECTION]');
  }

  // 4. Replace delimiters
  for (const pattern of DELIMITER_PATTERNS) {
    result = result.replace(new RegExp(pattern, 'g'), (matched) => {
      // Escape HTML tags or replace tokens
      return matched.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    });
  }

  return result;
}

/**
 * PromptInjectionDetector recursively scans payloads and enforces BLOCK/SANITIZE policies.
 */
export class PromptInjectionDetector {
  private policy: PromptInjectionPolicy;

  constructor(policy?: PromptInjectionPolicy) {
    this.policy = policy ?? { enabled: true, action: 'BLOCK' };
  }

  /**
   * Recursively inspects unknown payload (string, object, array).
   */
  public inspect(
    payload: unknown,
    context?: InterceptionContext
  ): InterceptionDecision {
    if (!this.policy.enabled) {
      return {
        verdict: 'ALLOW',
        detector: 'prompt_injection',
        rule_id: 'prompt_injection_disabled',
      };
    }

    const allFindings: ScanFinding[] = [];
    const seen = new WeakSet<object>();

    const traverse = (node: unknown, currentPath: string, depth: number) => {
      if (depth > 20) return;
      if (node === null || node === undefined) return;

      if (typeof node === 'string') {
        const scan = scanStringForInjection(node, this.policy);
        for (const f of scan.findings) {
          allFindings.push({ ...f, path: currentPath });
        }
        return;
      }

      if (typeof node === 'object') {
        if (seen.has(node)) return;
        seen.add(node);

        if (Array.isArray(node)) {
          for (let i = 0; i < node.length; i++) {
            traverse(node[i], `${currentPath}[${i}]`, depth + 1);
          }
        } else {
          for (const [key, val] of Object.entries(node)) {
            // Also check key for injection
            const keyScan = scanStringForInjection(key, this.policy);
            for (const f of keyScan.findings) {
              allFindings.push({ ...f, path: `${currentPath}.KEY(${key})` });
            }
            traverse(val, currentPath ? `${currentPath}.${key}` : key, depth + 1);
          }
        }
      }
    };

    traverse(payload, '', 0);

    if (allFindings.length === 0) {
      return {
        verdict: 'ALLOW',
        detector: 'prompt_injection',
        rule_id: 'payload_clean',
      };
    }

    // Determine verdict based on policy action and findings
    // Critical findings (Behavioral overrides, exfiltration) trigger BLOCK regardless
    const hasCritical = allFindings.some(
      (f) => f.type === 'BEHAVIORAL' || f.type === 'EXFILTRATION'
    );

    const configuredAction = this.policy.action ?? 'BLOCK';

    if (configuredAction === 'BLOCK' || hasCritical) {
      const topViolation = allFindings[0];
      return {
        verdict: 'BLOCK',
        detector: 'prompt_injection',
        rule_id: topViolation.rule_id,
        reason: `Prompt injection detected: ${topViolation.rule_id} (${topViolation.matched}) at '${topViolation.path}'`,
        metadata: {
          findings: allFindings,
        },
      };
    }

    // SANITIZE mode
    const sanitized = this.sanitize(payload);
    return {
      verdict: 'SANITIZE',
      detector: 'prompt_injection',
      rule_id: 'payload_sanitized',
      reason: `Sanitized ${allFindings.length} injection markers from payload`,
      sanitized_payload: sanitized,
      metadata: {
        findings: allFindings,
      },
    };
  }

  /**
   * Deeply sanitizes payload.
   */
  public sanitize(payload: unknown): unknown {
    const seen = new WeakSet<object>();

    const traverse = (node: unknown, depth: number): unknown => {
      if (depth > 20) return node;
      if (node === null || node === undefined) return node;

      if (typeof node === 'string') {
        return sanitizeString(node);
      }

      if (typeof node === 'object') {
        if (seen.has(node)) return node;
        seen.add(node);

        if (Array.isArray(node)) {
          return node.map((item) => traverse(item, depth + 1));
        }

        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(node)) {
          out[k] = traverse(v, depth + 1);
        }
        return out;
      }

      return node;
    };

    return traverse(payload, 0);
  }
}
