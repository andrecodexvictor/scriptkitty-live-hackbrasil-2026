/**
 * @file packages/runtime-guardian/src/confused-deputy.ts
 * @description Confused Deputy Defense: HMAC-SHA256 Delegation Tokens,
 * Replay Nonce Cache, Tri-Party Separation of Duties (A_disc != A_veri != A_auth),
 * and Tainted Context Escalation Barrier.
 */

import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import { canonicalStringify } from './audit-logger.js';
import {
  type DelegationTokenClaims,
  DelegationTokenClaimsSchema,
  type SignedDelegationToken,
  SignedDelegationTokenSchema,
  type DelegationValidationContext,
  type ConfusedDeputyPolicy,
  type InterceptionDecision,
  type InterceptionContext,
  GuardianSecurityError,
} from './types.js';

export const DEFAULT_VERIFICATION_TOOLS = ['verify_finding', 'run_recheck'];
export const DEFAULT_STATE_CHANGING_TOOLS = [
  'verify_finding',
  'generate_patch',
  'apply_patch',
  'execute_command',
  'run_recheck',
];

/**
 * Creates and cryptographically signs a delegation token using HMAC-SHA256.
 */
export function signDelegationToken(
  claims: DelegationTokenClaims,
  secretKey: string,
  keyId: string = 'key-primary'
): SignedDelegationToken {
  const validatedClaims = DelegationTokenClaimsSchema.parse(claims);
  const canonicalClaims = canonicalStringify(validatedClaims);
  const signature = createHmac('sha256', secretKey).update(canonicalClaims).digest('hex');

  return {
    claims: validatedClaims,
    signature,
    key_id: keyId,
  };
}

/**
 * Helper to build standard token claims with defaults.
 */
export function createDelegationClaims(params: {
  issuer: string;
  subject: string;
  audience: string;
  allowed_scopes: string[];
  ttlMs?: number; // max 300,000 ms (5 mins)
  nonce?: string;
  is_tainted?: boolean;
  taint_source?: string;
  discovering_agent_id?: string;
  finding_id?: string;
}): DelegationTokenClaims {
  const now = Date.now();
  const ttl = Math.min(params.ttlMs ?? 60_000, 300_000);
  const issued_at = new Date(now).toISOString();
  const expires_at = new Date(now + ttl).toISOString();
  const nonce = params.nonce ?? randomUUID().replace(/-/g, '');

  return {
    token_id: randomUUID(),
    issuer: params.issuer,
    subject: params.subject,
    audience: params.audience,
    allowed_scopes: params.allowed_scopes,
    issued_at,
    expires_at,
    nonce,
    taint_context: {
      is_tainted: params.is_tainted ?? false,
      taint_source: params.taint_source,
    },
    sod_lineage: {
      discovering_agent_id: params.discovering_agent_id,
      finding_id: params.finding_id,
    },
  };
}

/**
 * Cryptographically verifies a signed delegation token.
 */
export function verifyDelegationToken(
  token: SignedDelegationToken | string,
  secretKey: string,
  context: DelegationValidationContext
): { is_valid: boolean; violation_code?: string; error?: string } {
  let parsedToken: SignedDelegationToken;

  if (typeof token === 'string') {
    try {
      parsedToken = JSON.parse(token);
    } catch {
      return {
        is_valid: false,
        violation_code: 'E_INVALID_TOKEN_FORMAT',
        error: 'Delegation token string is not valid JSON',
      };
    }
  } else {
    parsedToken = token;
  }

  const parseResult = SignedDelegationTokenSchema.safeParse(parsedToken);
  if (!parseResult.success) {
    return {
      is_valid: false,
      violation_code: 'E_MALFORMED_TOKEN_SCHEMA',
      error: `Token schema validation failed: ${parseResult.error.message}`,
    };
  }

  const { claims, signature } = parseResult.data;

  // 1. Signature Verification (timing-safe)
  const canonicalClaims = canonicalStringify(claims);
  const expectedSig = createHmac('sha256', secretKey).update(canonicalClaims).digest('hex');

  if (
    signature.length !== expectedSig.length ||
    !timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSig, 'hex'))
  ) {
    return {
      is_valid: false,
      violation_code: 'E_INVALID_TOKEN_SIGNATURE',
      error: 'Cryptographic HMAC signature mismatch on delegation token',
    };
  }

  const now = (context.current_timestamp ?? new Date()).getTime();
  const issuedAt = new Date(claims.issued_at).getTime();
  const expiresAt = new Date(claims.expires_at).getTime();

  // 2. Maximum TTL Invariant (max 300s = 300,000ms)
  if (expiresAt - issuedAt > 300_000) {
    return {
      is_valid: false,
      violation_code: 'E_TOKEN_TTL_EXCEEDED',
      error: `Delegation token lifetime (${expiresAt - issuedAt}ms) exceeds max 300s`,
    };
  }

  // 3. Expiration Check with 2-second clock-skew tolerance
  if (now > expiresAt + 2000) {
    return {
      is_valid: false,
      violation_code: 'E_TOKEN_EXPIRED',
      error: `Delegation token expired at ${claims.expires_at} (current time: ${new Date(now).toISOString()})`,
    };
  }
  if (now < issuedAt - 2000) {
    return {
      is_valid: false,
      violation_code: 'E_TOKEN_FUTURE',
      error: `Delegation token issued in the future: ${claims.issued_at}`,
    };
  }

  // 4. Nonce Replay Check
  if (context.active_nonce_cache) {
    const cacheObj = context.active_nonce_cache as unknown as {
      has: (nonce: string) => boolean;
      add: (nonce: string) => unknown;
      recordNonce?: (nonce: string, expiresAtMs: number, nowMs: number) => void;
    };
    if (cacheObj.has(claims.nonce)) {
      return {
        is_valid: false,
        violation_code: 'E_TOKEN_REPLAYED',
        error: `Delegation token nonce '${claims.nonce}' has already been consumed (replay attack detected)`,
      };
    }
    if (typeof cacheObj.recordNonce === 'function') {
      cacheObj.recordNonce(claims.nonce, expiresAt + 2000, now);
    } else {
      cacheObj.add(claims.nonce);
    }
  }

  // 5. Subject Identity Match (caller must be delegate)
  if (claims.subject.toLowerCase() !== context.calling_agent_id.toLowerCase()) {
    return {
      is_valid: false,
      violation_code: 'E_SUBJECT_MISMATCH',
      error: `Token subject '${claims.subject}' does not match caller agent ID '${context.calling_agent_id}'`,
    };
  }

  // 6. Audience Match
  if (
    claims.audience !== '*' &&
    claims.audience.toLowerCase() !== context.target_tool_name.toLowerCase()
  ) {
    return {
      is_valid: false,
      violation_code: 'E_AUDIENCE_MISMATCH',
      error: `Token audience '${claims.audience}' does not match target tool '${context.target_tool_name}'`,
    };
  }

  // 7. Scope Coverage Check
  const requiredScope = context.required_scope ?? `tools:call:${context.target_tool_name}`;
  const hasScope =
    claims.allowed_scopes.includes('*') ||
    claims.allowed_scopes.includes(requiredScope) ||
    claims.allowed_scopes.includes(`tools:call:${context.target_tool_name}`) ||
    claims.allowed_scopes.includes('tools:call');

  if (!hasScope) {
    return {
      is_valid: false,
      violation_code: 'E_UNAUTHORIZED_SCOPE',
      error: `Required scope '${requiredScope}' not granted in token allowed_scopes: [${claims.allowed_scopes.join(', ')}]`,
    };
  }

  // 8. Tainted Context Escalation Barrier
  if (claims.taint_context?.is_tainted && context.is_state_changing) {
    return {
      is_valid: false,
      violation_code: 'E_TAINTED_STATE_CHANGE_BLOCKED',
      error: `Caller has tainted context (${claims.taint_context.taint_source ?? 'unknown'}); state-changing action '${context.target_tool_name}' is forbidden`,
    };
  }

  // 9. Separation of Duties (Tri-Party SoD Invariance)
  if (claims.sod_lineage?.discovering_agent_id) {
    const disc = claims.sod_lineage.discovering_agent_id.toLowerCase();
    const caller = context.calling_agent_id.toLowerCase();
    if (disc === caller && (context.target_tool_name === 'verify_finding' || context.target_tool_name === 'run_recheck')) {
      return {
        is_valid: false,
        violation_code: 'E_SOD_SELF_CERTIFICATION',
        error: `Discovering agent '${disc}' cannot verify its own finding via delegation`,
      };
    }
  }

  return { is_valid: true };
}

/**
 * ConfusedDeputyGuard intercepts tool calls and validates delegation proofs & SoD.
 */
export class ConfusedDeputyGuard {
  private policy: ConfusedDeputyPolicy;
  private nonceCache: Map<string, number> = new Map<string, number>();
  private readonly maxNonceCacheSize: number;

  constructor(policy?: ConfusedDeputyPolicy, maxNonceCacheSize = 10_000) {
    this.policy = policy ?? {
      enabled: true,
      enforceSeparationOfDuties: true,
    };
    this.maxNonceCacheSize =
      Number.isInteger(maxNonceCacheSize) && maxNonceCacheSize > 0
        ? maxNonceCacheSize
        : 10_000;
  }

  public getNonceCache(): Map<string, number> {
    return this.nonceCache;
  }

  public clearNonceCache(): void {
    this.nonceCache.clear();
  }

  private pruneExpiredNonces(nowMs: number): void {
    for (const [nonce, expiresAtMs] of this.nonceCache.entries()) {
      if (expiresAtMs <= nowMs) {
        this.nonceCache.delete(nonce);
      }
    }
  }

  private recordNonce(nonce: string, expiresAtMs: number, nowMs: number): void {
    this.pruneExpiredNonces(nowMs);
    if (!this.nonceCache.has(nonce)) {
      while (this.nonceCache.size >= this.maxNonceCacheSize) {
        const oldestNonce = this.nonceCache.keys().next().value;
        if (oldestNonce === undefined) break;
        this.nonceCache.delete(oldestNonce);
      }
    }
    this.nonceCache.delete(nonce);
    this.nonceCache.set(nonce, expiresAtMs);
  }

  public inspect(
    toolName: string,
    toolArgs: Record<string, unknown>,
    context: InterceptionContext
  ): InterceptionDecision {
    if (!this.policy.enabled) {
      return {
        verdict: 'ALLOW',
        detector: 'confused_deputy',
        rule_id: 'confused_deputy_disabled',
      };
    }

    const verificationTools = this.policy.verificationToolNames ?? DEFAULT_VERIFICATION_TOOLS;
    const stateChangingTools = this.policy.stateChangingToolNames ?? DEFAULT_STATE_CHANGING_TOOLS;

    // Check if dry_run flag is set to true on tool arguments (e.g. verify_finding { dry_run: true })
    const isExplicitDryRun = toolArgs?.dry_run === true;
    const isStateChanging = stateChangingTools.includes(toolName) && !isExplicitDryRun;
    const isVerification = verificationTools.includes(toolName);

    const callerId = context.caller_agent_id ?? 'anonymous';
    const discoveringId = context.discovering_agent_id;

    // 1. Enforce Tri-Party Separation of Duties (A_disc != A_veri)
    if (this.policy.enforceSeparationOfDuties && isVerification && discoveringId) {
      if (callerId.toLowerCase() === discoveringId.toLowerCase()) {
        return {
          verdict: 'BLOCK',
          detector: 'confused_deputy',
          rule_id: 'E_SOD_SELF_CERTIFICATION',
          reason: `Separation of Duties violation: Discovering agent '${discoveringId}' attempted to verify its own finding via '${toolName}'`,
          metadata: { callerId, discoveringId, toolName },
        };
      }
    }

    // 2. Tainted context barrier: untrusted / tainted contexts are prohibited from state-changing tools
    const isTainted =
      context.is_tainted === true ||
      context.taint_context?.is_tainted === true ||
      (context.taint_tags && context.taint_tags.length > 0);

    if (isTainted && isStateChanging) {
      const source = context.taint_context?.taint_source ?? context.taint_tags?.[0]?.source ?? 'untrusted_input';
      return {
        verdict: 'BLOCK',
        detector: 'confused_deputy',
        rule_id: 'E_TAINTED_CALLER_PRIVILEGE_VIOLATION',
        reason: `Tainted context barrier triggered: Caller has tainted context (${source}); execution of state-changing tool '${toolName}' is forbidden`,
        metadata: { callerId, isTainted, source, toolName },
      };
    }

    // 3. Cryptographic delegation token check
    const requireToken = this.policy.requireDelegationToken === true;
    const providedToken = context.delegation_token;

    if (requireToken && !providedToken) {
      return {
        verdict: 'BLOCK',
        detector: 'confused_deputy',
        rule_id: 'E_MISSING_DELEGATION_TOKEN',
        reason: `Policy requires valid cryptographic delegation token for tool '${toolName}'`,
        metadata: { toolName, callerId },
      };
    }

    if (providedToken) {
      const secret = this.policy.hmacSecret;
      if (!secret) {
        return {
          verdict: 'BLOCK',
          detector: 'confused_deputy',
          rule_id: 'E_MISSING_HMAC_SECRET',
          reason: 'HMAC secret is not configured in Guardian policy for token verification',
        };
      }

      const nonceCacheAdapter = {
        has: (nonce: string): boolean => {
          const expiresAtMs = this.nonceCache.get(nonce);
          if (expiresAtMs === undefined) {
            return false;
          }
          if (expiresAtMs <= Date.now()) {
            this.nonceCache.delete(nonce);
            return false;
          }
          return true;
        },
        add: (nonce: string) => {
          const nowMs = Date.now();
          this.recordNonce(nonce, nowMs + 300_000, nowMs);
          return nonceCacheAdapter;
        },
        recordNonce: (nonce: string, expiresAtMs: number, nowMs: number): void => {
          this.recordNonce(nonce, expiresAtMs, nowMs);
        },
      } as unknown as Set<string>;

      const valContext: DelegationValidationContext = {
        calling_agent_id: callerId,
        target_tool_name: toolName,
        is_state_changing: isStateChanging,
        active_nonce_cache: nonceCacheAdapter,
        discovering_agent_id: discoveringId,
      };

      const verification = verifyDelegationToken(providedToken, secret, valContext);
      if (!verification.is_valid) {
        return {
          verdict: 'BLOCK',
          detector: 'confused_deputy',
          rule_id: verification.violation_code ?? 'E_INVALID_DELEGATION_TOKEN',
          reason: verification.error ?? 'Delegation token verification failed',
          metadata: { toolName, callerId },
        };
      }
    }

    return {
      verdict: 'ALLOW',
      detector: 'confused_deputy',
      rule_id: 'confused_deputy_verified',
      reason: 'Caller identity, delegation authorization, and SoD invariants verified',
    };
  }
}
