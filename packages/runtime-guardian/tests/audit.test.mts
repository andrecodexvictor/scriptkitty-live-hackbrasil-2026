/**
 * @file packages/runtime-guardian/tests/audit.test.mts
 * @description Test Suite for RFC 8785 Canonical JSON Serialization,
 * Merkle Tree Root Computation, Inclusion Proofs, Custody Chaining,
 * In-Memory & File-Based Loggers, and Tamper Detection Invariants.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import {
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
  type GuardianAuditEvent,
  GuardianSecurityError,
} from '../dist/index.js';

describe('Suite 1: RFC 8785 Canonical JSON Serialization & Deterministic Hashing', () => {
  it('TEST_CANON_1: sorts object keys strictly using Unicode code point order regardless of insertion order', () => {
    const objA = { z: 1, a: 2, m: 3 };
    const objB = { m: 3, a: 2, z: 1 };
    const strA = canonicalStringify(objA);
    const strB = canonicalStringify(objB);

    assert.equal(strA, '{"a":2,"m":3,"z":1}');
    assert.equal(strA, strB);
    assert.equal(sha256(strA), sha256(strB));
  });

  it('TEST_CANON_2: recursively sorts nested object properties and strips undefined', () => {
    const nestedA = {
      level1: { beta: 'two', alpha: 'one', omitted: undefined },
      top: true,
    };
    const nestedB = {
      top: true,
      level1: { alpha: 'one', beta: 'two' },
    };

    assert.equal(canonicalStringify(nestedA), canonicalStringify(nestedB));
    assert.equal(
      canonicalStringify(nestedA),
      '{"level1":{"alpha":"one","beta":"two"},"top":true}'
    );
  });

  it('TEST_CANON_3: serializes arrays deterministically and converts undefined to null', () => {
    const arr = [1, undefined, 'test', false, null];
    assert.equal(canonicalStringify(arr), '[1,null,"test",false,null]');
  });

  it('TEST_CANON_4: formats Date instances as ISO 8601 UTC strings', () => {
    const date = new Date('2026-11-10T19:00:00.000Z');
    assert.equal(canonicalStringify(date), '"2026-11-10T19:00:00.000Z"');
  });

  it('TEST_CANON_5: stress tests 100 permutations of random keys producing identical digest', () => {
    const baseKeys = Array.from({ length: 25 }, (_, i) => `prop_${String.fromCharCode(97 + i)}`);
    const canonicalExpected = canonicalStringify(
      Object.fromEntries(baseKeys.map((k, i) => [k, i]))
    );
    const expectedHash = sha256(canonicalExpected);

    for (let run = 0; run < 100; run++) {
      const shuffledKeys = [...baseKeys].sort(() => Math.random() - 0.5);
      const permutedObj = Object.fromEntries(shuffledKeys.map((k) => [k, baseKeys.indexOf(k)]));
      const serialized = canonicalStringify(permutedObj);
      assert.equal(sha256(serialized), expectedHash);
    }
  });
});

describe('Suite 2: SHA-256 Custody Chaining & Genesis Anchorage', () => {
  it('TEST_CHAIN_1: first operational event anchors to GENESIS_HASH', () => {
    const logger = new InMemoryAuditLogger();
    const event = logger.logSync({
      event_type: 'GENESIS',
      tool_name: 'system',
      decision: 'ALLOW',
      policy_id: 'genesis_policy',
      details: { init: true },
    });

    assert.equal(event.prev_hash, GENESIS_HASH);
    assert.equal(event.index, 0);
    assert.match(event.current_hash, /^[a-f0-9]{64}$/);
  });

  it('TEST_CHAIN_2: sequential logging creates mathematically unbroken parent links', () => {
    const logger = new InMemoryAuditLogger();
    const count = 10;
    const events: GuardianAuditEvent[] = [];

    for (let i = 0; i < count; i++) {
      events.push(
        logger.logSync({
          event_type: 'TOOL_CALL',
          tool_name: `tool_${i}`,
          decision: 'ALLOW',
          policy_id: 'default_policy',
          details: { iteration: i },
        })
      );
    }

    assert.equal(events.length, count);
    assert.equal(events[0].prev_hash, GENESIS_HASH);

    for (let i = 1; i < count; i++) {
      assert.equal(events[i].prev_hash, events[i - 1].current_hash);
      assert.equal(events[i].index, i);
    }

    assert.equal(logger.getLatestHash(), events[count - 1].current_hash);
  });

  it('TEST_CHAIN_3: verifyGuardianAuditChain validates clean sequence of events', () => {
    const logger = new InMemoryAuditLogger();
    for (let i = 0; i < 7; i++) {
      logger.logSync({
        event_type: 'TOOL_CALL',
        tool_name: 'scout_target',
        decision: 'ALLOW',
        policy_id: 'policy-1',
        details: { target: `https://example-${i}.com` },
      });
    }

    const verification = logger.verifyIntegritySync();
    assert.equal(verification.valid, true);
    assert.equal(verification.total_events, 7);
    assert.equal(verification.broken_index, undefined);
    assert.match(verification.merkle_root, /^[a-f0-9]{64}$/);
  });
});

describe('Suite 3: Binary Merkle Tree & Logarithmic Inclusion Proofs', () => {
  it('TEST_MERKLE_1: empty array returns EMPTY_MERKLE_ROOT', () => {
    assert.equal(computeMerkleRoot([]), EMPTY_MERKLE_ROOT);
  });

  it('TEST_MERKLE_2: single leaf returns leaf hash itself', () => {
    const leaf = sha256('single-leaf-data');
    assert.equal(computeMerkleRoot([leaf]), leaf);
  });

  it('TEST_MERKLE_3: odd leaf count duplicates the last leaf for pairwise hashing', () => {
    const l0 = sha256('leaf-0');
    const l1 = sha256('leaf-1');
    const l2 = sha256('leaf-2');

    // 3 leaves: Level 0: [l0, l1, l2, l2 (duplicated)]
    // Level 1: [sha256(l0 + l1), sha256(l2 + l2)]
    // Root: sha256(Level1[0] + Level1[1])
    const expectedParent0 = sha256(l0 + l1);
    const expectedParent1 = sha256(l2 + l2);
    const expectedRoot = sha256(expectedParent0 + expectedParent1);

    const actualRoot = computeMerkleRoot([l0, l1, l2]);
    assert.equal(actualRoot, expectedRoot);
  });

  it('TEST_MERKLE_4: generates and verifies Merkle inclusion proofs for all leaves in a 7-leaf tree', () => {
    const leaves = Array.from({ length: 7 }, (_, i) => sha256(`leaf-node-${i}`));
    const root = computeMerkleRoot(leaves);

    for (let i = 0; i < leaves.length; i++) {
      const proof = generateMerkleProof(leaves, i);
      const isValid = verifyMerkleProof(leaves[i], proof, root);
      assert.equal(isValid, true, `Proof failed for leaf index ${i}`);
    }
  });

  it('TEST_MERKLE_5: tampered sibling in proof fails verification', () => {
    const leaves = Array.from({ length: 4 }, (_, i) => sha256(`node-${i}`));
    const root = computeMerkleRoot(leaves);

    const proof = generateMerkleProof(leaves, 1);
    // Tamper one sibling hash
    proof[0].hash = sha256('tampered-sibling');

    const isValid = verifyMerkleProof(leaves[1], proof, root);
    assert.equal(isValid, false);
  });
});

describe('Suite 4: Adversarial Tamper Detection across Attack Vectors (T1-T8)', () => {
  function generateValidChain(count: number): GuardianAuditEvent[] {
    const logger = new InMemoryAuditLogger();
    for (let i = 0; i < count; i++) {
      logger.logSync({
        event_type: 'TOOL_CALL',
        tool_name: 'verify_finding',
        decision: i % 2 === 0 ? 'ALLOW' : 'BLOCK',
        policy_id: 'policy_sod',
        details: { finding_id: `SK-FIND-${i}` },
      });
    }
    return [...logger.getEventsSync()];
  }

  it('TEST_TAMPER_1: detects payload alteration (decision BLOCK -> ALLOW) at broken index', () => {
    const chain = generateValidChain(5);
    // Tamper event at index 2 (was ALLOW, flip to BLOCK)
    chain[2].decision = 'BLOCK';

    const result = verifyGuardianAuditChain(chain);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, 2);
    assert.match(result.error!, /Current hash mismatch at index 2/);
  });

  it('TEST_TAMPER_2: detects nested details tampering', () => {
    const chain = generateValidChain(5);
    chain[3].details = { finding_id: 'SK-FIND-TAMPERED' };

    const result = verifyGuardianAuditChain(chain);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, 3);
  });

  it('TEST_TAMPER_3: detects timestamp tampering', () => {
    const chain = generateValidChain(4);
    chain[1].timestamp = '2020-01-01T00:00:00.000Z';

    const result = verifyGuardianAuditChain(chain);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, 1);
  });

  it('TEST_TAMPER_4: detects parent link tampering', () => {
    const chain = generateValidChain(4);
    chain[2].prev_hash = sha256('fake-parent-hash');

    const result = verifyGuardianAuditChain(chain);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, 2);
    assert.match(result.error!, /Parent hash mismatch at index 2/);
  });

  it('TEST_TAMPER_5: detects event reordering / swapping', () => {
    const chain = generateValidChain(4);
    const temp = chain[1];
    chain[1] = chain[2];
    chain[2] = temp;

    const result = verifyGuardianAuditChain(chain);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, 1);
  });

  it('TEST_TAMPER_6: detects event deletion from middle of chain', () => {
    const chain = generateValidChain(5);
    // Delete event at index 1
    chain.splice(1, 1);

    const result = verifyGuardianAuditChain(chain);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, 1);
  });

  it('TEST_TAMPER_7: detects Genesis hash modification at index 0', () => {
    const chain = generateValidChain(3);
    chain[0].prev_hash = 'GENESIS_TAMPERED';

    const result = verifyGuardianAuditChain(chain);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, 0);
  });

  it('TEST_TAMPER_8: detects fraudulent expected Merkle root discrepancy', () => {
    const chain = generateValidChain(5);
    const fraudulentRoot = sha256('attacker-fabricated-root');

    const result = verifyGuardianAuditChain(chain, fraudulentRoot);
    assert.equal(result.valid, false);
    assert.equal(result.broken_index, -1);
    assert.match(result.error!, /Merkle root mismatch/);
  });
});

describe('Suite 5: InMemoryAuditLogger Concurrency & Operations', () => {
  it('TEST_INMEM_1: async log, getEvents, and getMerkleRoot', async () => {
    const logger = new InMemoryAuditLogger();
    await logger.log({
      event_type: 'TOOL_LIST',
      tool_name: 'system',
      decision: 'ALLOW',
      policy_id: 'tool_policy',
    });
    await logger.log({
      event_type: 'TOOL_CALL',
      tool_name: 'scan_secrets',
      decision: 'ALLOW',
      policy_id: 'tool_policy',
    });

    const events = await logger.getEvents();
    assert.equal(events.length, 2);
    const root = await logger.getMerkleRoot();
    assert.match(root, /^[a-f0-9]{64}$/);

    const check = await logger.verifyIntegrity(root);
    assert.equal(check.valid, true);
  });

  it('TEST_INMEM_2: concurrent asynchronous appends maintain unbroken chain', async () => {
    const logger = new InMemoryAuditLogger();
    const promises = Array.from({ length: 25 }, (_, i) =>
      logger.log({
        event_type: 'TOOL_CALL',
        tool_name: `tool_async_${i}`,
        decision: 'ALLOW',
        policy_id: 'concurrency_test',
        details: { index: i },
      })
    );

    await Promise.all(promises);
    const events = await logger.getEvents();
    assert.equal(events.length, 25);

    const check = await logger.verifyIntegrity();
    assert.equal(check.valid, true);
    assert.equal(check.total_events, 25);
  });

  it('TEST_INMEM_3: clear resets state to GENESIS_HASH', () => {
    const logger = new InMemoryAuditLogger();
    logger.logSync({
      event_type: 'TOOL_CALL',
      tool_name: 'scout_target',
      decision: 'ALLOW',
      policy_id: 'p1',
    });

    assert.equal(logger.getEventsSync().length, 1);
    logger.clear();
    assert.equal(logger.getEventsSync().length, 0);
    assert.equal(logger.getLatestHash(), GENESIS_HASH);

    const nextEvent = logger.logSync({
      event_type: 'GENESIS',
      tool_name: 'system',
      decision: 'ALLOW',
      policy_id: 'p1',
    });
    assert.equal(nextEvent.prev_hash, GENESIS_HASH);
  });
});

describe('Suite 6: FileAuditLogger Persistence, Recovery & Tamper Resistance', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(async () => {
    tmpDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'guardian-audit-test-'));
    logFile = path.join(tmpDir, 'audit.jsonl');
  });

  afterEach(async () => {
    try {
      await fsPromises.rm(tmpDir, { recursive: true, force: true });
    } catch {}
  });

  it('TEST_FILE_1: logs events to disk in NDJSON format and verifies integrity', async () => {
    const logger = new FileAuditLogger(logFile);
    for (let i = 0; i < 5; i++) {
      await logger.log({
        event_type: 'TOOL_CALL',
        tool_name: `file_tool_${i}`,
        decision: 'ALLOW',
        policy_id: 'file_policy',
        details: { idx: i },
      });
    }

    const events = await logger.getEvents();
    assert.equal(events.length, 5);

    const rawContent = await fsPromises.readFile(logFile, 'utf-8');
    const lines = rawContent.split('\n').filter((l) => l.trim().length > 0);
    assert.equal(lines.length, 5);

    const check = await logger.verifyIntegrity();
    assert.equal(check.valid, true);
    assert.equal(check.total_events, 5);
  });

  it('TEST_FILE_2: crash and restart recovery resumes hash chain seamlessly', async () => {
    // Session 1: write 3 events
    const logger1 = new FileAuditLogger(logFile);
    await logger1.log({
      event_type: 'TOOL_LIST',
      tool_name: 'system',
      decision: 'ALLOW',
      policy_id: 'p1',
    });
    await logger1.log({
      event_type: 'TOOL_CALL',
      tool_name: 'scout_target',
      decision: 'ALLOW',
      policy_id: 'p1',
    });
    await logger1.log({
      event_type: 'TOOL_RESULT',
      tool_name: 'scout_target',
      decision: 'ALLOW',
      policy_id: 'p1',
    });
    const lastHashSession1 = logger1.getLatestHash();
    await logger1.close();

    // Session 2: instantiate new logger on same file
    const logger2 = new FileAuditLogger(logFile);
    await logger2.init();
    assert.equal(logger2.getLatestHash(), lastHashSession1);

    await logger2.log({
      event_type: 'TOOL_CALL',
      tool_name: 'verify_finding',
      decision: 'BLOCK',
      policy_id: 'sod_policy',
    });

    const allEvents = await logger2.getEvents();
    assert.equal(allEvents.length, 4);
    assert.equal(allEvents[3].prev_hash, lastHashSession1);

    const integrity = await logger2.verifyIntegrity();
    assert.equal(integrity.valid, true);
    assert.equal(integrity.total_events, 4);
  });

  it('TEST_FILE_3: startup integrity check throws GuardianSecurityError if disk log was modified', async () => {
    const logger1 = new FileAuditLogger(logFile);
    await logger1.log({
      event_type: 'TOOL_CALL',
      tool_name: 'scout_target',
      decision: 'ALLOW',
      policy_id: 'p1',
    });
    await logger1.log({
      event_type: 'TOOL_CALL',
      tool_name: 'verify_finding',
      decision: 'BLOCK',
      policy_id: 'p1',
    });

    // Tamper disk file directly: replace BLOCK with ALLOW
    const content = await fsPromises.readFile(logFile, 'utf-8');
    const tampered = content.replace('"BLOCK"', '"ALLOW"');
    await fsPromises.writeFile(logFile, tampered, 'utf-8');

    const logger2 = new FileAuditLogger(logFile);
    await assert.rejects(
      async () => {
        await logger2.init();
      },
      (err: GuardianSecurityError) => {
        assert.equal(err.code, 'E_AUDIT_LOG_TAMPERED');
        return true;
      }
    );
  });

  it('TEST_FILE_4: caps in-memory events[] via maxInMemoryEvents FIFO and recovers writeQueue after error', async () => {
    const inMem = new InMemoryAuditLogger({ maxInMemoryEvents: 3 });
    await assert.rejects(
      async () =>
        inMem.log({
          event_type: 'TOOL_CALL',
          tool_name: 'scout_target',
          decision: 'ALLOW',
          policy_id: 'p1',
          details: { bad: 1n as unknown as number },
        })
    );
    for (let i = 0; i < 5; i++) {
      await inMem.log({
        event_type: 'TOOL_CALL',
        tool_name: `tool-${i}`,
        decision: 'ALLOW',
        policy_id: 'p1',
      });
    }
    const memEvents = await inMem.getEvents();
    assert.equal(memEvents.length, 3);
    assert.deepEqual(
      memEvents.map((e) => e.tool_name),
      ['tool-2', 'tool-3', 'tool-4']
    );

    const boundedFileLogger = new FileAuditLogger(logFile, { maxInMemoryEvents: 3 });
    await assert.rejects(
      async () =>
        boundedFileLogger.log({
          event_type: 'TOOL_CALL',
          tool_name: 'scout_target',
          decision: 'ALLOW',
          policy_id: 'p1',
          details: { bad: 1n as unknown as number },
        })
    );
    for (let i = 0; i < 5; i++) {
      await boundedFileLogger.log({
        event_type: 'TOOL_CALL',
        tool_name: `file-tool-${i}`,
        decision: 'ALLOW',
        policy_id: 'p1',
      });
    }
    const fileEvents = await boundedFileLogger.getEvents();
    assert.equal(fileEvents.length, 3);
    assert.deepEqual(
      fileEvents.map((e) => e.tool_name),
      ['file-tool-2', 'file-tool-3', 'file-tool-4']
    );
    await boundedFileLogger.close();
  });
});
