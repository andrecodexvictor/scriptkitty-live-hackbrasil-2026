/**
 * @file packages/runtime-guardian/tests/deputy.test.mts
 * @description Comprehensive Test Suite for Confused Deputy Defense:
 * HMAC-SHA256 Delegation Tokens, Nonce Replay Protection, TTL Invariants,
 * Tri-Party Separation of Duties (A_disc != A_veri), and Tainted Context Barrier.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  signDelegationToken,
  createDelegationClaims,
  verifyDelegationToken,
  ConfusedDeputyGuard,
  type DelegationValidationContext,
} from '../dist/index.js';

describe('Suite 1: Delegation Token Signing & Verification', () => {
  const secretKey = 'super-secret-hmac-key-for-test-32bytes!';

  it('TEST_TOKEN_1: valid signed token verifies cleanly', () => {
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
      ttlMs: 60_000,
    });

    const signedToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, true);
  });

  it('TEST_TOKEN_2: tampered signature is rejected (E_INVALID_TOKEN_SIGNATURE)', () => {
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
    });

    const signedToken = signDelegationToken(claims, secretKey);
    // Tamper signature
    signedToken.signature = (signedToken.signature.startsWith('0') ? '1' : '0') + signedToken.signature.slice(1);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_INVALID_TOKEN_SIGNATURE');
  });

  it('TEST_TOKEN_3: tampered payload claims invalidate signature', () => {
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
    });

    const signedToken = signDelegationToken(claims, secretKey);
    // Attacker modifies subject to attacker-agent
    signedToken.claims.subject = 'attacker-agent';

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'attacker-agent',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_INVALID_TOKEN_SIGNATURE');
  });
});

describe('Suite 2: Token TTL & Expiration Invariants', () => {
  const secretKey = 'test-secret-key-32-bytes-secure!';

  it('TEST_TTL_1: rejects tokens with lifetime exceeding 300 seconds (E_TOKEN_TTL_EXCEEDED)', () => {
    const now = Date.now();
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call'],
    });
    // Manually set 10 minutes TTL
    claims.issued_at = new Date(now).toISOString();
    claims.expires_at = new Date(now + 600_000).toISOString();

    const signedToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_TOKEN_TTL_EXCEEDED');
  });

  it('TEST_TTL_2: rejects expired tokens (E_TOKEN_EXPIRED)', () => {
    const now = Date.now();
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call'],
    });
    // Expired 5 seconds ago
    claims.issued_at = new Date(now - 60_000).toISOString();
    claims.expires_at = new Date(now - 5_000).toISOString();

    const signedToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_TOKEN_EXPIRED');
  });

  it('TEST_TTL_3: rejects tokens issued in the future (E_TOKEN_FUTURE)', () => {
    const now = Date.now();
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call'],
    });
    // Issued 10 seconds in the future
    claims.issued_at = new Date(now + 10_000).toISOString();
    claims.expires_at = new Date(now + 60_000).toISOString();

    const signedToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_TOKEN_FUTURE');
  });
});

describe('Suite 3: Replay Protection & Nonce Caching', () => {
  const secretKey = 'test-secret-key-32-bytes-secure!';

  it('TEST_REPLAY_1: prevents replay attacks using identical nonce (E_TOKEN_REPLAYED)', () => {
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
    });

    const signedToken = signDelegationToken(claims, secretKey);
    const nonceCache = new Set<string>();

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: nonceCache,
    };

    // First presentation succeeds
    const firstResult = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(firstResult.is_valid, true);
    assert.ok(nonceCache.has(claims.nonce));

    // Second presentation with same nonce fails
    const secondResult = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(secondResult.is_valid, false);
    assert.equal(secondResult.violation_code, 'E_TOKEN_REPLAYED');
  });
});

describe('Suite 4: Identity, Audience & Scope Matches', () => {
  const secretKey = 'test-secret-key-32-bytes-secure!';

  it('TEST_MATCH_1: rejects token presentation by mismatched agent (E_SUBJECT_MISMATCH)', () => {
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call'],
    });

    const signedToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-impostor-9',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_SUBJECT_MISMATCH');
  });

  it('TEST_MATCH_2: rejects token presented to wrong audience tool (E_AUDIENCE_MISMATCH)', () => {
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'scout_target',
      allowed_scopes: ['tools:call'],
    });

    const signedToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_AUDIENCE_MISMATCH');
  });

  it('TEST_MATCH_3: rejects token lacking requested scope (E_UNAUTHORIZED_SCOPE)', () => {
    const claims = createDelegationClaims({
      issuer: 'agent-orchestrator',
      subject: 'agent-worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:read'],
    });

    const signedToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'agent-worker-1',
      target_tool_name: 'verify_finding',
      required_scope: 'tools:write',
      is_state_changing: true,
      active_nonce_cache: new Set<string>(),
    };

    const result = verifyDelegationToken(signedToken, secretKey, valContext);
    assert.equal(result.is_valid, false);
    assert.equal(result.violation_code, 'E_UNAUTHORIZED_SCOPE');
  });
});

describe('Suite 5: Tri-Party Separation of Duties (A_disc != A_veri)', () => {
  const secretKey = 'test-secret-key-32-bytes-secure!';

  it('TEST_SOD_1: blocks discovering agent from self-certifying verification (E_SOD_SELF_CERTIFICATION)', () => {
    const guard = new ConfusedDeputyGuard({
      enabled: true,
      enforceSeparationOfDuties: true,
    });

    // Discoverer attempts to call verify_finding
    const decision = guard.inspect(
      'verify_finding',
      { finding_id: 'SK-FIND-001', dry_run: false },
      {
        session_id: 'sess-1',
        caller_agent_id: 'agent-scanner-01',
        discovering_agent_id: 'agent-scanner-01',
        timestamp: new Date().toISOString(),
      }
    );

    assert.equal(decision.verdict, 'BLOCK');
    assert.equal(decision.rule_id, 'E_SOD_SELF_CERTIFICATION');
  });

  it('TEST_SOD_2: allows independent verifier agent to verify finding', () => {
    const guard = new ConfusedDeputyGuard({
      enabled: true,
      enforceSeparationOfDuties: true,
    });

    const decision = guard.inspect(
      'verify_finding',
      { finding_id: 'SK-FIND-001', dry_run: false },
      {
        session_id: 'sess-1',
        caller_agent_id: 'agent-verifier-02',
        discovering_agent_id: 'agent-scanner-01',
        timestamp: new Date().toISOString(),
      }
    );

    assert.equal(decision.verdict, 'ALLOW');
  });
});

describe('Suite 6: Tainted Context Escalation Barrier', () => {
  it('TEST_TAINT_1: blocks tainted agent from executing state-changing tools', () => {
    const guard = new ConfusedDeputyGuard({
      enabled: true,
      enforceSeparationOfDuties: true,
    });

    const decision = guard.inspect(
      'generate_patch',
      { finding_id: 'SK-FIND-001' },
      {
        session_id: 'sess-taint-1',
        caller_agent_id: 'agent-remediation',
        is_tainted: true,
        taint_context: { is_tainted: true, taint_source: 'untrusted_rag_chunk' },
        timestamp: new Date().toISOString(),
      }
    );

    assert.equal(decision.verdict, 'BLOCK');
    assert.equal(decision.rule_id, 'E_TAINTED_CALLER_PRIVILEGE_VIOLATION');
  });

  it('TEST_TAINT_2: allows tainted agent to call read-only / dry_run tools', () => {
    const guard = new ConfusedDeputyGuard({
      enabled: true,
      enforceSeparationOfDuties: true,
    });

    const decision = guard.inspect(
      'verify_finding',
      { finding_id: 'SK-FIND-001', dry_run: true },
      {
        session_id: 'sess-taint-2',
        caller_agent_id: 'agent-verifier',
        discovering_agent_id: 'agent-other',
        is_tainted: true,
        taint_context: { is_tainted: true, taint_source: 'untrusted_rag_chunk' },
        timestamp: new Date().toISOString(),
      }
    );

    assert.equal(decision.verdict, 'ALLOW');
  });

  it('TEST_TAINT_3: bounds nonceCache Map with TTL pruning and maxNonceCacheSize eviction', () => {
    const secretKey = 'test-secret-key-32-bytes-secure!';
    const guard = new ConfusedDeputyGuard(
      {
        enabled: true,
        enforceSeparationOfDuties: true,
        requireDelegationToken: true,
        hmacSecret: secretKey,
      },
      2
    );

    const cache = guard.getNonceCache();
    assert.ok(cache instanceof Map);
    cache.set('stale-nonce-entry', Date.now() - 10_000);

    const makeDecision = (nonce: string) => {
      const claims = createDelegationClaims({
        issuer: 'agent-orchestrator',
        subject: 'agent-verifier',
        audience: 'verify_finding',
        allowed_scopes: ['tools:call:verify_finding'],
        nonce,
        discovering_agent_id: 'agent-scanner',
      });
      const signed = signDelegationToken(claims, secretKey);
      return guard.inspect(
        'verify_finding',
        { finding_id: 'SK-FIND-TTL-1' },
        {
          session_id: 'sess-nonce-ttl',
          caller_agent_id: 'agent-verifier',
          discovering_agent_id: 'agent-scanner',
          delegation_token: signed,
          timestamp: new Date().toISOString(),
        }
      );
    };

    const nonce1 = '1'.repeat(32);
    const nonce2 = '2'.repeat(32);
    const nonce3 = '3'.repeat(32);

    assert.equal(makeDecision(nonce1).verdict, 'ALLOW');
    assert.equal(cache.has('stale-nonce-entry'), false);
    assert.equal(makeDecision(nonce1).rule_id, 'E_TOKEN_REPLAYED');
    assert.equal(makeDecision(nonce2).verdict, 'ALLOW');
    assert.equal(cache.size, 2);

    assert.equal(makeDecision(nonce3).verdict, 'ALLOW');
    assert.equal(cache.size, 2);
    assert.equal(cache.has(nonce1), false);
    assert.equal(cache.has(nonce2), true);
    assert.equal(cache.has(nonce3), true);
  });
});
