/**
 * @file packages/runtime-guardian/tests/adversarial-scope-deputy-audit.test.mts
 * @description Empirical Challenger Test Suite: Adversarial stress testing for
 * Scope Boundary Guard, Confused Deputy Protection, and Merkle Audit Custody.
 * Authored by p2_m3_challenger_2.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as os from 'node:os';
import * as fsPromises from 'node:fs/promises';
import {
  // Scope Guard
  validateAndResolvePath,
  ScopeBoundaryGuard,
  // Confused Deputy
  signDelegationToken,
  createDelegationClaims,
  verifyDelegationToken,
  ConfusedDeputyGuard,
  // Audit Custody
  GENESIS_HASH,
  EMPTY_MERKLE_ROOT,
  sha256,
  canonicalStringify,
  computeGuardianEventHash,
  computeMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  verifyGuardianAuditChain,
  InMemoryAuditLogger,
  FileAuditLogger,
  // Types & Errors
  GuardianSecurityError,
  type ScopeGuardPolicy,
  type DelegationValidationContext,
  type GuardianAuditEvent,
} from '../dist/index.js';

describe('Adversarial Challenge 1: Scope Boundary Guard & Path Traversal Permutations', () => {
  let tempRoot: string;
  let policy: ScopeGuardPolicy;
  let guard: ScopeBoundaryGuard;

  beforeEach(async () => {
    tempRoot = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'adv-scope-'));
    policy = {
      enabled: true,
      allowedRoots: [tempRoot],
      allowSensitiveFiles: false,
    };
    guard = new ScopeBoundaryGuard(policy);
  });

  afterEach(async () => {
    try {
      await fsPromises.rm(tempRoot, { recursive: true, force: true });
    } catch {}
  });

  it('ADV_PATH_1: blocks standard and mixed directory traversal sequences (../, ..\\, ..\\/)', () => {
    const attackPayloads = [
      '../../etc/passwd',
      '..\\..\\windows\\win.ini',
      '..\\/..\\/sensitive.key',
      'sub/nested/../../../../out.txt',
      'foo/bar/../../../outside.txt',
      '.\\..\\..\\escaped.dat',
    ];

    for (const payload of attackPayloads) {
      assert.throws(
        () => validateAndResolvePath(payload, policy),
        (err: GuardianSecurityError) => {
          assert.equal(err.code, 'E_PATH_OUT_OF_BOUNDS');
          return true;
        },
        `Failed to block traversal payload: ${payload}`
      );
    }
  });

  it('ADV_PATH_2: blocks double and multi-layer URL encoded traversal (%252e%252e%252f)', () => {
    const encodedPayloads = [
      '%252e%252e%252fetc%252fpasswd',
      '%252e%252e%255cwindows%255cwin.ini',
      'subdir/%252e%252e/%252e%252e/target',
      '%25252e%25252e%25252fsecret',
    ];

    for (const payload of encodedPayloads) {
      assert.throws(
        () => validateAndResolvePath(payload, policy),
        (err: GuardianSecurityError) => {
          assert.equal(err.code, 'E_PATH_DOUBLE_ENCODING');
          return true;
        },
        `Failed to block double URL encoding payload: ${payload}`
      );
    }
  });

  it('ADV_PATH_3: blocks literal and URL-encoded null bytes (\\0, %00, \\x00)', () => {
    const nullPayloads = [
      'legit.txt\0/../../../etc/passwd',
      'innocent.png%00.exe',
      'test\x00file',
      '\0/escaped',
      'data/item\x1Ftest', // ASCII control character
    ];

    for (const payload of nullPayloads) {
      assert.throws(
        () => validateAndResolvePath(payload, policy),
        (err: GuardianSecurityError) => {
          assert.equal(err.code, 'E_PATH_NULL_BYTE');
          return true;
        },
        `Failed to block null byte payload: ${payload}`
      );
    }
  });

  it('ADV_PATH_4: blocks Windows UNC network paths (\\\\127.0.0.1\\share, //attacker/share)', () => {
    const uncPayloads = [
      '\\\\127.0.0.1\\c$\\secret.txt',
      '\\\\localhost\\admin$\\cmd.exe',
      '\\\\remote-attacker.com\\data\\exfil',
      '//evil.com/share/drop',
    ];

    for (const payload of uncPayloads) {
      assert.throws(
        () => validateAndResolvePath(payload, policy),
        (err: GuardianSecurityError) => {
          assert.equal(err.code, 'E_PATH_UNC_FORBIDDEN');
          return true;
        },
        `Failed to block UNC payload: ${payload}`
      );
    }
  });

  it('ADV_PATH_5: blocks NTFS Alternate Data Streams (::$DATA, :hidden, :stream)', () => {
    const adsPayloads = [
      'sample.txt::$DATA',
      'document.pdf:hidden_stream',
      'data.csv:secret:$DATA',
      'folder:$INDEX_ALLOCATION',
    ];

    for (const payload of adsPayloads) {
      assert.throws(
        () => validateAndResolvePath(payload, policy),
        (err: GuardianSecurityError) => {
          assert.equal(err.code, 'E_PATH_NTFS_ADS');
          return true;
        },
        `Failed to block NTFS ADS payload: ${payload}`
      );
    }
  });

  it('ADV_PATH_6: blocks sensitive file blacklist (.git, .env, SSH keys, certificates, unix shadow)', () => {
    const sensitiveFiles = [
      '.git',
      '.git/config',
      '.git/HEAD',
      'subdir/.git/index',
      '.env',
      '.env.production',
      '.env.local',
      '.env.secrets',
      'id_rsa',
      'id_rsa.pub',
      'id_ed25519',
      'id_ecdsa',
      '.aws/credentials',
      'server.key',
      'cert.pem',
      'identity.pfx',
      'bundle.p12',
      'etc/passwd',
      'etc/shadow',
    ];

    for (const item of sensitiveFiles) {
      assert.throws(
        () => validateAndResolvePath(item, policy),
        (err: GuardianSecurityError) => {
          assert.ok(
            err.code === 'E_SENSITIVE_RESOURCE_BLOCKED' || err.code === 'E_PATH_OUT_OF_BOUNDS',
            `Expected E_SENSITIVE_RESOURCE_BLOCKED or E_PATH_OUT_OF_BOUNDS for ${item}, got ${err.code}`
          );
          return true;
        },
        `Failed to block sensitive resource: ${item}`
      );
    }
  });

  it('ADV_PATH_7: blocks prohibited URI schemes (gopher://, http://, dict://) while allowing valid file:// within root', () => {
    const forbiddenUris = [
      'gopher://evil.com/traversal',
      'http://127.0.0.1:8080/internal',
      'ftp://ftp.example.com/file',
      'dict://dict.org/d:search',
    ];

    for (const uri of forbiddenUris) {
      assert.throws(
        () => validateAndResolvePath(uri, policy),
        (err: GuardianSecurityError) => {
          assert.equal(err.code, 'E_INVALID_URI_SCHEME');
          return true;
        },
        `Failed to block forbidden URI scheme: ${uri}`
      );
    }

    // Permitted file:// inside root
    const validLocalFile = path.join(tempRoot, 'safe.txt');
    const validFileUri = `file://${validLocalFile.replace(/\\/g, '/')}`;
    const resolved = validateAndResolvePath(validFileUri, policy);
    assert.ok(resolved.length > 0);
  });

  it('ADV_PATH_8: ScopeBoundaryGuard.inspect blocks tool call with path traversal disguised in parameters', () => {
    const decision1 = guard.inspect({
      target_path: '../../etc/shadow',
      mode: 'read',
    });
    assert.equal(decision1.verdict, 'BLOCK');
    assert.equal(decision1.rule_id, 'E_PATH_OUT_OF_BOUNDS');

    const decision2 = guard.inspect({
      custom_arg: 'safe_name',
      sneak: 'innocent.txt\0.bat',
    });
    assert.equal(decision2.verdict, 'BLOCK');
    assert.equal(decision2.rule_id, 'E_PATH_NULL_BYTE');

    const decision3 = guard.inspect({
      filePath: 'safe_document.txt',
    });
    assert.equal(decision3.verdict, 'ALLOW');
  });
});

describe('Adversarial Challenge 2: Confused Deputy & Privilege Escalation Attacks', () => {
  const secretKey = 'test-master-hmac-key-adversarial-32b!';
  let deputyGuard: ConfusedDeputyGuard;

  beforeEach(() => {
    deputyGuard = new ConfusedDeputyGuard({
      enabled: true,
      enforceSeparationOfDuties: true,
      requireDelegationToken: true,
      hmacSecret: secretKey,
    });
  });

  it('ADV_DEPUTY_1: rejects tokens with forged or tampered HMAC signature', () => {
    const claims = createDelegationClaims({
      issuer: 'orchestrator',
      subject: 'worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
    });

    const validToken = signDelegationToken(claims, secretKey);

    // Attack 1: Alter last byte of HMAC hex
    const forgedToken1 = {
      ...validToken,
      signature: validToken.signature.slice(0, -2) + (validToken.signature.endsWith('00') ? 'ff' : '00'),
    };

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
    };

    const res1 = verifyDelegationToken(forgedToken1, secretKey, valContext);
    assert.equal(res1.is_valid, false);
    assert.equal(res1.violation_code, 'E_INVALID_TOKEN_SIGNATURE');

    // Attack 2: Signed with rogue secret key
    const rogueSigned = signDelegationToken(claims, 'rogue-adversary-key-32-bytes!!!');
    const res2 = verifyDelegationToken(rogueSigned, secretKey, valContext);
    assert.equal(res2.is_valid, false);
    assert.equal(res2.violation_code, 'E_INVALID_TOKEN_SIGNATURE');

    // Attack 3: Modify claim field after signing
    const tamperedPayloadToken = {
      ...validToken,
      claims: {
        ...validToken.claims,
        allowed_scopes: ['*'], // Attacker escalates privileges
      },
    };
    const res3 = verifyDelegationToken(tamperedPayloadToken, secretKey, valContext);
    assert.equal(res3.is_valid, false);
    assert.equal(res3.violation_code, 'E_INVALID_TOKEN_SIGNATURE');
  });

  it('ADV_DEPUTY_2: rejects expired tokens and enforces max 300s TTL invariant', () => {
    const now = Date.now();
    const claims = createDelegationClaims({
      issuer: 'orchestrator',
      subject: 'worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
    });

    // 1. Expired token (issued 10m ago, expired 5m ago)
    claims.issued_at = new Date(now - 600_000).toISOString();
    claims.expires_at = new Date(now - 300_000).toISOString();
    const expiredToken = signDelegationToken(claims, secretKey);

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: new Set<string>(),
      current_timestamp: new Date(now),
    };

    const expRes = verifyDelegationToken(expiredToken, secretKey, valContext);
    assert.equal(expRes.is_valid, false);
    assert.equal(expRes.violation_code, 'E_TOKEN_EXPIRED');

    // 2. Future token (issued in future beyond 2s clock skew)
    claims.issued_at = new Date(now + 10_000).toISOString();
    claims.expires_at = new Date(now + 70_000).toISOString();
    const futureToken = signDelegationToken(claims, secretKey);
    const futRes = verifyDelegationToken(futureToken, secretKey, valContext);
    assert.equal(futRes.is_valid, false);
    assert.equal(futRes.violation_code, 'E_TOKEN_FUTURE');

    // 3. Lifetime exceeding 300s (e.g. 301 seconds)
    claims.issued_at = new Date(now).toISOString();
    claims.expires_at = new Date(now + 301_000).toISOString();
    const longToken = signDelegationToken(claims, secretKey);
    const longRes = verifyDelegationToken(longToken, secretKey, valContext);
    assert.equal(longRes.is_valid, false);
    assert.equal(longRes.violation_code, 'E_TOKEN_TTL_EXCEEDED');
  });

  it('ADV_DEPUTY_3: catches and blocks nonce reuse replay attacks', () => {
    const claims = createDelegationClaims({
      issuer: 'orchestrator',
      subject: 'worker-1',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
      ttlMs: 60_000,
    });

    const token = signDelegationToken(claims, secretKey);
    const nonceCache = new Set<string>();

    const valContext: DelegationValidationContext = {
      calling_agent_id: 'worker-1',
      target_tool_name: 'verify_finding',
      is_state_changing: false,
      active_nonce_cache: nonceCache,
    };

    // First presentation: Valid
    const firstAttempt = verifyDelegationToken(token, secretKey, valContext);
    assert.equal(firstAttempt.is_valid, true);
    assert.ok(nonceCache.has(claims.nonce));

    // Second presentation (Replay): Blocked!
    const replayAttempt = verifyDelegationToken(token, secretKey, valContext);
    assert.equal(replayAttempt.is_valid, false);
    assert.equal(replayAttempt.violation_code, 'E_TOKEN_REPLAYED');
    assert.match(replayAttempt.error ?? '', /replay attack detected/);
  });

  it('ADV_DEPUTY_4: strictly enforces Tri-Party Separation of Duties (A_disc != A_veri)', () => {
    const discoveringAgent = 'agent-scout-01';
    const findingId = 'VULN-SQLI-2026-001';

    // 1. Discoverer attempts to self-verify finding -> BLOCKED
    const selfCertClaims = createDelegationClaims({
      issuer: 'orchestrator',
      subject: discoveringAgent,
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
      discovering_agent_id: discoveringAgent,
      finding_id: findingId,
    });
    const selfToken = signDelegationToken(selfCertClaims, secretKey);

    const decision1 = deputyGuard.inspect(
      'verify_finding',
      { finding_id: findingId },
      {
        caller_agent_id: discoveringAgent,
        discovering_agent_id: discoveringAgent,
        delegation_token: selfToken,
      }
    );
    assert.equal(decision1.verdict, 'BLOCK');
    assert.equal(decision1.rule_id, 'E_SOD_SELF_CERTIFICATION');
    assert.match(decision1.reason ?? '', /Separation of Duties violation/);

    // 2. Discoverer attempts to self-verify with run_recheck tool -> BLOCKED
    const decision2 = deputyGuard.inspect(
      'run_recheck',
      { finding_id: findingId },
      {
        caller_agent_id: discoveringAgent,
        discovering_agent_id: discoveringAgent,
        delegation_token: selfToken,
      }
    );
    assert.equal(decision2.verdict, 'BLOCK');
    assert.equal(decision2.rule_id, 'E_SOD_SELF_CERTIFICATION');

    // 3. Independent verifier agent verifies finding -> ALLOWED
    const independentVerifier = 'agent-verifier-02';
    const validClaims = createDelegationClaims({
      issuer: 'orchestrator',
      subject: independentVerifier,
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
      discovering_agent_id: discoveringAgent,
      finding_id: findingId,
    });
    const validToken = signDelegationToken(validClaims, secretKey);

    const decision3 = deputyGuard.inspect(
      'verify_finding',
      { finding_id: findingId },
      {
        caller_agent_id: independentVerifier,
        discovering_agent_id: discoveringAgent,
        delegation_token: validToken,
      }
    );
    assert.equal(decision3.verdict, 'ALLOW');
  });

  it('ADV_DEPUTY_5: blocks tainted context from executing state-changing tools', () => {
    const taintedClaims = createDelegationClaims({
      issuer: 'orchestrator',
      subject: 'worker-tainted',
      audience: 'apply_patch',
      allowed_scopes: ['tools:call:apply_patch'],
      is_tainted: true,
      taint_source: 'prompt_injection_advisory',
    });
    const token = signDelegationToken(taintedClaims, secretKey);

    // 1. Tainted agent attempting state-changing tool 'apply_patch' -> BLOCKED
    const stateChangingDecision = deputyGuard.inspect(
      'apply_patch',
      { patch_file: 'fix.patch' },
      {
        caller_agent_id: 'worker-tainted',
        is_tainted: true,
        taint_context: { is_tainted: true, taint_source: 'prompt_injection_advisory' },
        delegation_token: token,
      }
    );
    assert.equal(stateChangingDecision.verdict, 'BLOCK');
    assert.equal(stateChangingDecision.rule_id, 'E_TAINTED_CALLER_PRIVILEGE_VIOLATION');

    // 2. Tainted agent executing verify_finding with dry_run: true -> ALLOWED
    const readOnlyClaims = createDelegationClaims({
      issuer: 'orchestrator',
      subject: 'worker-tainted',
      audience: 'verify_finding',
      allowed_scopes: ['tools:call:verify_finding'],
      is_tainted: true,
    });
    const readToken = signDelegationToken(readOnlyClaims, secretKey);

    const dryRunDecision = deputyGuard.inspect(
      'verify_finding',
      { finding_id: '123', dry_run: true },
      {
        caller_agent_id: 'worker-tainted',
        is_tainted: true,
        delegation_token: readToken,
      }
    );
    assert.equal(dryRunDecision.verdict, 'ALLOW');
  });
});

describe('Adversarial Challenge 3: Merkle Audit Custody & Tamper Detection Invariants', () => {
  let logger: InMemoryAuditLogger;
  let fileLogger: FileAuditLogger;
  let tempAuditFile: string;

  beforeEach(async () => {
    logger = new InMemoryAuditLogger();
    tempAuditFile = path.join(
      await fsPromises.mkdtemp(path.join(os.tmpdir(), 'adv-audit-')),
      'guardian-audit.ndjson'
    );
    fileLogger = new FileAuditLogger(tempAuditFile);
  });

  afterEach(async () => {
    try {
      await fileLogger.close();
      await fsPromises.rm(path.dirname(tempAuditFile), { recursive: true, force: true });
    } catch {}
  });

  it('ADV_AUDIT_1: detects single event payload alteration and identifies exact broken_index', async () => {
    // Generate a sequence of 5 audit events
    const events: GuardianAuditEvent[] = [];
    for (let i = 0; i < 5; i++) {
      events.push(
        logger.logSync({
          event_type: 'TOOL_CALL',
          tool_name: `tool_${i}`,
          decision: i === 2 ? 'BLOCK' : 'ALLOW',
          policy_id: 'prod_policy',
          details: { count: i },
        })
      );
    }

    // Clean verification passes
    const cleanCheck = verifyGuardianAuditChain(events);
    assert.equal(cleanCheck.valid, true);
    assert.equal(cleanCheck.total_events, 5);

    // Adversarial Tampering: Modify decision of event 2 from BLOCK to ALLOW
    const tampered = JSON.parse(JSON.stringify(events)) as GuardianAuditEvent[];
    tampered[2].decision = 'ALLOW';

    const tamperedCheck = verifyGuardianAuditChain(tampered);
    assert.equal(tamperedCheck.valid, false);
    assert.equal(tamperedCheck.broken_index, 2);
    assert.match(tamperedCheck.error ?? '', /Current hash mismatch at index 2/);
  });

  it('ADV_AUDIT_2: detects prev_hash alteration (broken parent custody link)', async () => {
    const events: GuardianAuditEvent[] = [];
    for (let i = 0; i < 4; i++) {
      events.push(
        logger.logSync({
          event_type: 'SCOPE_CHECK',
          tool_name: 'read_file',
          decision: 'ALLOW',
          policy_id: 'default',
        })
      );
    }

    const tampered = JSON.parse(JSON.stringify(events)) as GuardianAuditEvent[];
    // Attacker modifies parent hash of event 3
    tampered[3].prev_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const check = verifyGuardianAuditChain(tampered);
    assert.equal(check.valid, false);
    assert.equal(check.broken_index, 3);
    assert.match(check.error ?? '', /Parent hash mismatch at index 3/);
  });

  it('ADV_AUDIT_3: detects chain truncation against expected Merkle root', async () => {
    const events: GuardianAuditEvent[] = [];
    for (let i = 0; i < 6; i++) {
      events.push(
        logger.logSync({
          event_type: 'TOOL_CALL',
          tool_name: `worker_step_${i}`,
          decision: 'ALLOW',
          policy_id: 'policy_m3',
        })
      );
    }

    const expectedRoot = await logger.getMerkleRoot();

    // Adversary truncates the last event from the chain
    const truncatedEvents = events.slice(0, 5);

    // Internally truncated chain passes internal linking, but MUST fail expected Merkle root check
    const check = verifyGuardianAuditChain(truncatedEvents, expectedRoot);
    assert.equal(check.valid, false);
    assert.equal(check.broken_index, -1);
    assert.match(check.error ?? '', /Merkle root mismatch/);
  });

  it('ADV_AUDIT_4: detects event deletion and reordering in custody chain', async () => {
    const events: GuardianAuditEvent[] = [];
    for (let i = 0; i < 5; i++) {
      events.push(
        logger.logSync({
          event_type: 'TOOL_CALL',
          tool_name: `step_${i}`,
          decision: 'ALLOW',
          policy_id: 'policy',
        })
      );
    }

    // 1. Deletion attack: remove middle event index 2
    const deletedEvents = [events[0], events[1], events[3], events[4]];
    const delCheck = verifyGuardianAuditChain(deletedEvents);
    assert.equal(delCheck.valid, false);
    assert.equal(delCheck.broken_index, 2); // event 3 now at index 2 has mismatched prev_hash

    // 2. Reordering attack: swap index 1 and 2
    const swappedEvents = [events[0], events[2], events[1], events[3], events[4]];
    const swapCheck = verifyGuardianAuditChain(swappedEvents);
    assert.equal(swapCheck.valid, false);
    assert.equal(swapCheck.broken_index, 1);
  });

  it('ADV_AUDIT_5: detects tampered leaves and proof nodes in logarithmic Merkle proofs', async () => {
    const leaves = [
      sha256('leaf-0'),
      sha256('leaf-1'),
      sha256('leaf-2'),
      sha256('leaf-3'),
      sha256('leaf-4'),
    ];
    const root = computeMerkleRoot(leaves);

    // Valid inclusion proof for leaf 2
    const proof = generateMerkleProof(leaves, 2);
    assert.equal(verifyMerkleProof(leaves[2], proof, root), true);

    // Attack 1: Alter leaf payload
    const fakeLeaf = sha256('forged-leaf-content');
    assert.equal(verifyMerkleProof(fakeLeaf, proof, root), false);

    // Attack 2: Tamper one sibling hash in the proof path
    const tamperedProof = JSON.parse(JSON.stringify(proof));
    tamperedProof[0].hash = sha256('tampered-sibling');
    assert.equal(verifyMerkleProof(leaves[2], tamperedProof, root), false);

    // Attack 3: Tamper root
    assert.equal(verifyMerkleProof(leaves[2], proof, sha256('bogus-root')), false);
  });

  it('ADV_AUDIT_6: FileAuditLogger startup integrity check rejects modified disk records', async () => {
    await fileLogger.init();

    await fileLogger.log({
      event_type: 'POLICY_VIOLATION',
      tool_name: 'secret_dump',
      decision: 'BLOCK',
      policy_id: 'prod_policy',
    });
    await fileLogger.log({
      event_type: 'TOOL_CALL',
      tool_name: 'read_config',
      decision: 'ALLOW',
      policy_id: 'prod_policy',
    });
    await fileLogger.close();

    // Attacker modifies first record on disk
    const diskContent = await fsPromises.readFile(tempAuditFile, 'utf-8');
    const lines = diskContent.trim().split('\n');
    const firstEvent = JSON.parse(lines[0]) as GuardianAuditEvent;
    firstEvent.decision = 'ALLOW'; // Adversary flips BLOCK to ALLOW
    lines[0] = canonicalStringify(firstEvent);
    await fsPromises.writeFile(tempAuditFile, lines.join('\n') + '\n', 'utf-8');

    // New FileAuditLogger instance boots up on tampered file -> MUST throw E_AUDIT_LOG_TAMPERED
    const recoveryLogger = new FileAuditLogger(tempAuditFile);
    await assert.rejects(
      async () => recoveryLogger.init(),
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_AUDIT_LOG_TAMPERED');
        assert.match(err.message, /Startup audit chain verification failed at index 0/);
        return true;
      }
    );
  });

  it('ADV_AUDIT_7: stress-tests 100-event custody chain and verifies Merkle inclusion proofs for all leaves', async () => {
    const scaleLogger = new InMemoryAuditLogger();
    const eventCount = 100;
    const events: GuardianAuditEvent[] = [];

    for (let i = 0; i < eventCount; i++) {
      events.push(
        scaleLogger.logSync({
          event_type: 'TOOL_CALL',
          tool_name: `worker_action_${i}`,
          decision: i % 7 === 0 ? 'BLOCK' : 'ALLOW',
          policy_id: 'enterprise_policy',
          details: { index: i, nonce: Math.random().toString(36) },
        })
      );
    }

    // 1. Verify unbroken chain
    const chainVerification = await scaleLogger.verifyIntegrity();
    assert.equal(chainVerification.valid, true);
    assert.equal(chainVerification.total_events, eventCount);

    const root = await scaleLogger.getMerkleRoot();
    assert.match(root, /^[a-f0-9]{64}$/);

    // 2. Generate and verify inclusion proof for every single leaf
    for (let i = 0; i < eventCount; i++) {
      const proof = await scaleLogger.generateProof(i);
      const isValid = verifyMerkleProof(events[i].current_hash, proof, root);
      assert.equal(isValid, true, `Inclusion proof failed for leaf ${i}`);
    }
  });
});

