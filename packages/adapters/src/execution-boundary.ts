/**
 * @file packages/adapters/src/execution-boundary.ts
 * @description Hardened execution boundary wrappers for ScriptKitty 2.0 adapters.
 * Enforces wall-clock timeouts, size budgets, secret redaction, and total error isolation
 * to guarantee that external security engines never throw unhandled exceptions.
 */

/**
 * Custom error thrown when an operation exceeds its configured wall-clock timeout.
 */
export class TimeoutError extends Error {
  public readonly timeoutMs: number;
  public readonly operation: string;

  constructor(message: string, timeoutMs: number, operation = 'Operation') {
    super(message);
    this.name = 'TimeoutError';
    this.timeoutMs = timeoutMs;
    this.operation = operation;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Custom error thrown when a payload or artifact exceeds its size budget.
 */
export class SizeBudgetExceededError extends Error {
  public readonly currentBytes: number;
  public readonly maxBytes: number;
  public readonly label: string;

  constructor(label: string, currentBytes: number, maxBytes: number) {
    super(`${label} size ${currentBytes} bytes exceeds maximum allowed budget of ${maxBytes} bytes`);
    this.name = 'SizeBudgetExceededError';
    this.currentBytes = currentBytes;
    this.maxBytes = maxBytes;
    this.label = label;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Enforces a strict wall-clock timeout on any asynchronous Promise.
 * Cleans up timer handles promptly and rejects with TimeoutError if the deadline expires.
 *
 * @param promise The asynchronous promise to execute.
 * @param timeoutMs Maximum allowed execution duration in milliseconds.
 * @param operation Descriptive name of the operation for logging.
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation = 'Operation'
): Promise<T> {
  if (timeoutMs <= 0 || !Number.isFinite(timeoutMs)) {
    return promise;
  }

  let timer: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new TimeoutError(`${operation} timed out after ${timeoutMs}ms`, timeoutMs, operation));
    }, timeoutMs);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}

/**
 * Standard security credential patterns to redact.
 */
const DEFAULT_SECRET_PATTERNS: RegExp[] = [
  // HTTP Authorization Bearer tokens
  /bearer\s+[a-zA-Z0-9_\-\.]{15,}/gi,
  // Key / Secret key-value assignments
  /(?:api[_-]?key|auth[_-]?token|client[_-]?secret|access[_-]?token|secret[_-]?token|secret|password|token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{8,})["']?/gi,
  // AWS Access Key ID
  /AKIA[0-9A-Z]{16}/g,
  // GitHub Personal Access Tokens
  /gh[pousr]_[A-Za-z0-9_]{36,}/g,
  // Cloudflare API Tokens & Keys
  /(?:CF_TOKEN|CLOUDFLARE_API_KEY|CF_API_KEY)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{30,})["']?/gi,
  // Slack Tokens
  /xox[baprs]-[0-9A-Za-z\-]{20,}/g,
  // Private Key Blocks (RSA, EC, OpenSSH, etc.)
  /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
  // Generic JSON Web Tokens (JWT)
  /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g,
  // Passwords embedded in URLs (e.g. postgres://user:pass@host)
  /(https?|postgres|mysql|redis|mongodb):\/\/([^:\s]+):([^@\s]+)@/gi,
];

/**
 * Redacts credentials, tokens, passwords, and private keys from strings, replacing them with [REDACTED].
 *
 * @param raw Input string containing potential secrets.
 * @param additionalPatterns Optional user-provided regex patterns to redact.
 */
export function sanitizeOutput(raw: string, additionalPatterns: RegExp[] = []): string {
  if (typeof raw !== 'string' || raw.length === 0) {
    return raw;
  }

  let sanitized = raw;

  // 1. Redact Private Key blocks completely
  sanitized = sanitized.replace(
    /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
    '-----BEGIN PRIVATE KEY-----\n[REDACTED PRIVATE KEY]\n-----END PRIVATE KEY-----'
  );

  // 2. Redact Bearer tokens
  sanitized = sanitized.replace(/bearer\s+[a-zA-Z0-9_\-\.]{15,}/gi, 'Bearer [REDACTED]');

  // 3. Redact URL passwords
  sanitized = sanitized.replace(
    /(https?|postgres|mysql|redis|mongodb):\/\/([^:\s]+):([^@\s]+)@/gi,
    '$1://$2:[REDACTED]@'
  );

  // 4. Redact Key-Value assignments
  sanitized = sanitized.replace(
    /((?:api[_-]?key|auth[_-]?token|client[_-]?secret|access[_-]?token|secret[_-]?token|secret|password|token)\s*[:=]\s*["']?)([a-zA-Z0-9_\-\.]{8,})(["']?)/gi,
    '$1[REDACTED]$3'
  );

  // 5. Redact Cloudflare token assignments
  sanitized = sanitized.replace(
    /((?:CF_TOKEN|CLOUDFLARE_API_KEY|CF_API_KEY)\s*[:=]\s*["']?)([a-zA-Z0-9_\-]{30,})(["']?)/gi,
    '$1[REDACTED]$3'
  );

  // 6. Redact AWS Keys
  sanitized = sanitized.replace(/AKIA[0-9A-Z]{16}/g, 'AKIA[REDACTED]');

  // 7. Redact GitHub PATs
  sanitized = sanitized.replace(/gh[pousr]_[A-Za-z0-9_]{36,}/g, 'ghp_[REDACTED]');

  // 8. Redact Slack tokens
  sanitized = sanitized.replace(/xox[baprs]-[0-9A-Za-z\-]{20,}/g, 'xox-[REDACTED]');

  // 9. Redact JWTs
  sanitized = sanitized.replace(
    /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g,
    'eyJ[REDACTED].eyJ[REDACTED].[REDACTED]'
  );

  // 10. Apply any additional patterns
  for (const pattern of additionalPatterns) {
    sanitized = sanitized.replace(pattern, '[REDACTED]');
  }

  return sanitized;
}

/**
 * Recursively traverses an arbitrary object or array, sanitizing all nested string values.
 */
export function sanitizeObject<T>(input: T, additionalPatterns: RegExp[] = []): T {
  if (input === null || typeof input !== 'object') {
    if (typeof input === 'string') {
      return sanitizeOutput(input, additionalPatterns) as unknown as T;
    }
    return input;
  }

  if (Array.isArray(input)) {
    return input.map((item) => sanitizeObject(item, additionalPatterns)) as unknown as T;
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    // If the key itself indicates a secret, redact entirely if string
    const lowerKey = key.toLowerCase();
    if (
      typeof value === 'string' &&
      (lowerKey.includes('token') ||
        lowerKey.includes('secret') ||
        lowerKey.includes('password') ||
        lowerKey.includes('api_key') ||
        lowerKey.includes('apikey') ||
        lowerKey.includes('auth'))
    ) {
      result[key] = '[REDACTED]';
    } else {
      result[key] = sanitizeObject(value, additionalPatterns);
    }
  }

  return result as T;
}

/**
 * Computes byte length of a string or Buffer.
 */
export function getByteLength(content: string | Buffer): number {
  if (Buffer.isBuffer(content)) {
    return content.length;
  }
  return Buffer.byteLength(content, 'utf8');
}

/**
 * Checks if a string or Buffer is within an allocated byte budget.
 */
export function checkSizeBudget(
  content: string | Buffer,
  maxBytes: number,
  label = 'Payload'
): { ok: boolean; size: number; limit: number; error?: string } {
  const size = getByteLength(content);
  if (size > maxBytes) {
    return {
      ok: false,
      size,
      limit: maxBytes,
      error: `${label} size ${size} bytes exceeds maximum allowed budget of ${maxBytes} bytes`,
    };
  }
  return { ok: true, size, limit: maxBytes };
}

/**
 * Asserts that a string or Buffer is within the allocated byte budget, throwing SizeBudgetExceededError otherwise.
 */
export function assertWithinBudget(
  content: string | Buffer,
  maxBytes: number,
  label = 'Payload'
): void {
  const check = checkSizeBudget(content, maxBytes, label);
  if (!check.ok) {
    throw new SizeBudgetExceededError(label, check.size, check.limit);
  }
}

/**
 * Safely truncates a string to fit within an allocated byte budget, appending a truncation indicator.
 */
export function truncateToBudget(
  content: string,
  maxBytes: number,
  suffix = '...[TRUNCATED]'
): { content: string; truncated: boolean; originalSize: number } {
  const originalSize = Buffer.byteLength(content, 'utf8');
  if (originalSize <= maxBytes) {
    return { content, truncated: false, originalSize };
  }

  const suffixBytes = Buffer.byteLength(suffix, 'utf8');
  const targetBytes = Math.max(0, maxBytes - suffixBytes);
  const buf = Buffer.from(content, 'utf8');
  const truncatedStr = buf.subarray(0, targetBytes).toString('utf8');

  return {
    content: truncatedStr + suffix,
    truncated: true,
    originalSize,
  };
}

/**
 * Wraps an async function to guarantee that it never throws unhandled exceptions.
 * Any caught error is passed to the fallback mapper.
 */
export async function safeExecute<T>(
  fn: () => Promise<T> | T,
  fallback: (err: Error) => T
): Promise<T> {
  try {
    return await fn();
  } catch (err: unknown) {
    const errorObj = err instanceof Error ? err : new Error(String(err));
    return fallback(errorObj);
  }
}

/**
 * Options for executeInBoundary.
 */
export interface BoundaryOptions {
  timeoutMs?: number;
  operationName?: string;
  sanitize?: boolean;
}

/**
 * Outcome of an execution within a boundary.
 */
export interface BoundaryExecutionResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  durationMs: number;
  timedOut?: boolean;
}

/**
 * Executes an operation inside a full isolation boundary, capturing timeouts and errors.
 */
export async function executeInBoundary<T>(
  fn: () => Promise<T>,
  options: BoundaryOptions = {}
): Promise<BoundaryExecutionResult<T>> {
  const start = Date.now();
  const timeoutMs = options.timeoutMs ?? 30_000;
  const operationName = options.operationName ?? 'AdapterOperation';

  try {
    const result = await withTimeout(fn(), timeoutMs, operationName);
    return {
      success: true,
      data: result,
      durationMs: Date.now() - start,
    };
  } catch (err: unknown) {
    const isTimeout = err instanceof TimeoutError;
    const rawMessage = err instanceof Error ? err.message : String(err);
    const sanitizedMsg = options.sanitize !== false ? sanitizeOutput(rawMessage) : rawMessage;

    return {
      success: false,
      error: sanitizedMsg,
      durationMs: Date.now() - start,
      timedOut: isTimeout,
    };
  }
}
