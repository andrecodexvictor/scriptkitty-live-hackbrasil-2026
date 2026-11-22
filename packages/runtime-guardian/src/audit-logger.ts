/**
 * @file packages/runtime-guardian/src/audit-logger.ts
 * @description RFC 8785 Canonical JSON Serialization, GuardianAuditEvent Schema,
 * SHA-256 Merkle Custody Chaining, and In-Memory & File-Based Audit Loggers.
 */

import { createHash, randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import * as path from 'node:path';
import {
  type GuardianAuditEvent,
  type GuardianAuditEventType,
  type GuardianDecision,
  type DetectorType,
  type MerkleProof,
  type AuditVerificationResult,
  GuardianSecurityError,
} from './types.js';

export const GENESIS_HASH =
  'GENESIS_0000000000000000000000000000000000000000000000000000000000000000';

export const EMPTY_MERKLE_ROOT =
  '0000000000000000000000000000000000000000000000000000000000000000';

export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * RFC 8785 aligned canonical JSON serialization.
 * - Keys sorted strictly by Unicode code point order.
 * - Whitespace completely eliminated.
 * - Dates serialized to ISO 8601 UTC.
 * - Arrays preserve index order; undefined becomes null.
 * - Undefined object values are omitted.
 * - Numbers serialized deterministically (-0 normalized to 0).
 */
export function canonicalStringify(val: unknown): string {
  if (val === null || typeof val !== 'object') {
    if (typeof val === 'number') {
      if (!Number.isFinite(val)) return 'null';
      return Object.is(val, -0) ? '0' : JSON.stringify(val);
    }
    return JSON.stringify(val);
  }
  if (typeof (val as { toISOString?: unknown }).toISOString === 'function') {
    return JSON.stringify((val as { toISOString: () => string }).toISOString());
  }
  if (Array.isArray(val)) {
    return '[' + val.map((item) => (item === undefined ? 'null' : canonicalStringify(item))).join(',') + ']';
  }
  const obj = val as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const entries: string[] = [];
  for (const key of sortedKeys) {
    const v = obj[key];
    if (v !== undefined) {
      entries.push(JSON.stringify(key) + ':' + canonicalStringify(v));
    }
  }
  return '{' + entries.join(',') + '}';
}

/**
 * Computes deterministic SHA-256 hash sealing a GuardianAuditEvent into the custody chain.
 * current_hash = sha256(canonicalStringify(eventWithoutCurrentHash) + prevHash)
 */
export function computeGuardianEventHash(
  eventWithoutCurrentHash: Omit<GuardianAuditEvent, 'current_hash'>,
  prevHash: string
): string {
  const canonical = canonicalStringify(eventWithoutCurrentHash);
  return sha256(canonical + prevHash);
}

/**
 * Computes binary Merkle tree root over leaf hashes with odd-leaf duplication.
 */
export function computeMerkleRoot(leaves: readonly string[]): string {
  if (leaves.length === 0) return EMPTY_MERKLE_ROOT;
  let currentLevel = [...leaves];
  while (currentLevel.length > 1) {
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      nextLevel.push(sha256(currentLevel[i] + currentLevel[i + 1]));
    }
    currentLevel = nextLevel;
  }
  return currentLevel[0];
}

/**
 * Generates logarithmic Merkle inclusion proof for target leaf index.
 */
export function generateMerkleProof(leaves: readonly string[], targetIndex: number): MerkleProof {
  if (targetIndex < 0 || targetIndex >= leaves.length) {
    throw new Error(`Target index ${targetIndex} out of bounds for leaf array of length ${leaves.length}`);
  }
  const proof: MerkleProof = [];
  let currentLevel = [...leaves];
  let idx = targetIndex;

  while (currentLevel.length > 1) {
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }
    const isRightSibling = idx % 2 === 0;
    const siblingIndex = isRightSibling ? idx + 1 : idx - 1;

    proof.push({
      position: isRightSibling ? 'right' : 'left',
      hash: currentLevel[siblingIndex],
    });

    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      nextLevel.push(sha256(currentLevel[i] + currentLevel[i + 1]));
    }
    currentLevel = nextLevel;
    idx = Math.floor(idx / 2);
  }

  return proof;
}

/**
 * Verifies Merkle inclusion proof against expected Merkle root.
 */
export function verifyMerkleProof(leafHash: string, proof: MerkleProof, expectedRoot: string): boolean {
  let current = leafHash;
  for (const step of proof) {
    if (step.position === 'right') {
      current = sha256(current + step.hash);
    } else {
      current = sha256(step.hash + current);
    }
  }
  return current === expectedRoot;
}

/**
 * Validates cryptographic chain integrity across an array of GuardianAuditEvents.
 */
export function verifyGuardianAuditChain(
  events: readonly GuardianAuditEvent[],
  expectedMerkleRoot?: string
): AuditVerificationResult {
  if (events.length === 0) {
    return {
      valid: true,
      total_events: 0,
      merkle_root: EMPTY_MERKLE_ROOT,
      latest_hash: GENESIS_HASH,
    };
  }

  let expectedParent = GENESIS_HASH;
  const leafHashes: string[] = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i];

    // Check parent link
    if (event.prev_hash !== expectedParent) {
      return {
        valid: false,
        total_events: events.length,
        merkle_root: '',
        latest_hash: expectedParent,
        broken_index: i,
        error: `Parent hash mismatch at index ${i}: expected ${expectedParent}, got ${event.prev_hash}`,
      };
    }

    // Recompute current hash
    const copy = { ...event } as Record<string, unknown>;
    delete copy.current_hash;

    const expectedCurrentHash = computeGuardianEventHash(
      copy as unknown as Omit<GuardianAuditEvent, 'current_hash'>,
      event.prev_hash
    );

    if (event.current_hash !== expectedCurrentHash) {
      return {
        valid: false,
        total_events: events.length,
        merkle_root: '',
        latest_hash: expectedParent,
        broken_index: i,
        error: `Current hash mismatch at index ${i}: stored ${event.current_hash}, computed ${expectedCurrentHash}`,
      };
    }

    leafHashes.push(event.current_hash);
    expectedParent = event.current_hash;
  }

  const computedRoot = computeMerkleRoot(leafHashes);

  if (expectedMerkleRoot !== undefined && expectedMerkleRoot !== computedRoot) {
    return {
      valid: false,
      total_events: events.length,
      merkle_root: computedRoot,
      latest_hash: expectedParent,
      broken_index: -1,
      error: `Merkle root mismatch: expected ${expectedMerkleRoot}, computed ${computedRoot}`,
    };
  }

  return {
    valid: true,
    total_events: events.length,
    merkle_root: computedRoot,
    latest_hash: expectedParent,
  };
}

export interface LogEventParams {
  event_type: GuardianAuditEventType;
  stage?: 'ON_LIST_TOOLS' | 'ON_CALL_TOOL' | 'ON_TOOL_RESULT' | 'INFRASTRUCTURE';
  agent_id?: string;
  session_id?: string;
  tool_name?: string;
  decision: GuardianDecision;
  policy_id: string;
  detector?: DetectorType;
  rule_id?: string;
  details?: Record<string, unknown>;
  event_id?: string;
  timestamp?: string;
}

export interface IAuditLogger {
  log(params: LogEventParams): Promise<GuardianAuditEvent>;
  getEvents(): Promise<readonly GuardianAuditEvent[]>;
  getLatestHash(): string;
  getMerkleRoot(): Promise<string>;
  verifyIntegrity(expectedMerkleRoot?: string): Promise<AuditVerificationResult>;
  generateProof(targetIndex: number): Promise<MerkleProof>;
  close(): Promise<void>;
}

export interface AuditLoggerOptions {
  maxInMemoryEvents?: number;
}

function resolveMaxInMemoryEvents(
  options?: number | AuditLoggerOptions
): number {
  const raw = typeof options === 'number' ? options : options?.maxInMemoryEvents;
  return Number.isInteger(raw) && (raw as number) > 0 ? (raw as number) : 5_000;
}

/**
 * In-memory high-performance implementation of IAuditLogger.
 */
export class InMemoryAuditLogger implements IAuditLogger {
  private events: GuardianAuditEvent[] = [];
  private latestHash: string = GENESIS_HASH;
  private writeQueue: Promise<void> = Promise.resolve();
  private totalLogged = 0;
  private readonly maxInMemoryEvents: number;

  constructor(options?: number | AuditLoggerOptions) {
    this.maxInMemoryEvents = resolveMaxInMemoryEvents(options);
  }

  public logSync(params: LogEventParams): GuardianAuditEvent {
    const event_id = params.event_id ?? `GAE-${Date.now()}-${randomUUID().slice(0, 8)}`;
    const timestamp = params.timestamp ?? new Date().toISOString();
    const index = this.totalLogged;
    const prev_hash = this.latestHash;

    const partialEvent: Omit<GuardianAuditEvent, 'current_hash'> = {
      event_id,
      index,
      timestamp,
      event_type: params.event_type,
      stage: params.stage ?? 'INFRASTRUCTURE',
      agent_id: params.agent_id,
      session_id: params.session_id,
      tool_name: params.tool_name ?? 'system',
      decision: params.decision,
      policy_id: params.policy_id,
      detector: params.detector,
      rule_id: params.rule_id,
      details: params.details ?? {},
      prev_hash,
    };

    const current_hash = computeGuardianEventHash(partialEvent, prev_hash);
    const fullEvent: GuardianAuditEvent = {
      ...partialEvent,
      current_hash,
    };

    this.events.push(fullEvent);
    while (this.events.length > this.maxInMemoryEvents) {
      this.events.shift();
    }
    this.totalLogged += 1;
    this.latestHash = current_hash;
    return fullEvent;
  }

  public async log(params: LogEventParams): Promise<GuardianAuditEvent> {
    const next = this.writeQueue
      .catch(() => undefined)
      .then(() => this.logSync(params));
    this.writeQueue = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  public getEventsSync(): readonly GuardianAuditEvent[] {
    return [...this.events];
  }

  public async getEvents(): Promise<readonly GuardianAuditEvent[]> {
    return this.getEventsSync();
  }

  public getLatestHash(): string {
    return this.latestHash;
  }

  public getMerkleRootSync(): string {
    return computeMerkleRoot(this.events.map((e) => e.current_hash));
  }

  public async getMerkleRoot(): Promise<string> {
    return this.getMerkleRootSync();
  }

  public verifyIntegritySync(expectedMerkleRoot?: string): AuditVerificationResult {
    return verifyGuardianAuditChain(this.events, expectedMerkleRoot);
  }

  public async verifyIntegrity(expectedMerkleRoot?: string): Promise<AuditVerificationResult> {
    return this.verifyIntegritySync(expectedMerkleRoot);
  }

  public async generateProof(targetIndex: number): Promise<MerkleProof> {
    return generateMerkleProof(
      this.events.map((e) => e.current_hash),
      targetIndex
    );
  }

  public clear(): void {
    this.events = [];
    this.totalLogged = 0;
    this.latestHash = GENESIS_HASH;
  }

  public async close(): Promise<void> {
    await this.writeQueue.catch(() => undefined);
  }
}

/**
 * Persistent NDJSON file-based audit logger with startup verification.
 */
export class FileAuditLogger implements IAuditLogger {
  private filePath: string;
  private events: GuardianAuditEvent[] = [];
  private latestHash: string = GENESIS_HASH;
  private writeQueue: Promise<void> = Promise.resolve();
  private initialized: boolean = false;
  private totalLogged = 0;
  private readonly maxInMemoryEvents: number;

  constructor(filePath: string, options?: number | AuditLoggerOptions) {
    this.filePath = path.resolve(filePath);
    this.maxInMemoryEvents = resolveMaxInMemoryEvents(options);
  }

  public async init(): Promise<void> {
    if (this.initialized) return;

    // Ensure directory exists
    const dir = path.dirname(this.filePath);
    await fsPromises.mkdir(dir, { recursive: true });

    if (fs.existsSync(this.filePath)) {
      const content = await fsPromises.readFile(this.filePath, 'utf-8');
      const lines = content.split('\n').filter((l) => l.trim().length > 0);
      const parsedEvents: GuardianAuditEvent[] = [];

      for (let i = 0; i < lines.length; i++) {
        try {
          const parsed = JSON.parse(lines[i]) as GuardianAuditEvent;
          parsedEvents.push(parsed);
        } catch (err: unknown) {
          throw new GuardianSecurityError(
            `Corrupted line at index ${i} in audit log: ${(err as Error).message}`,
            'E_AUDIT_LOG_PARSE_CORRUPTED',
            'policy',
            'audit_file_integrity'
          );
        }
      }

      const verification = verifyGuardianAuditChain(parsedEvents);
      if (!verification.valid) {
        throw new GuardianSecurityError(
          `Startup audit chain verification failed at index ${verification.broken_index}: ${verification.error}`,
          'E_AUDIT_LOG_TAMPERED',
          'policy',
          'audit_file_integrity',
          verification
        );
      }

      this.totalLogged = parsedEvents.length;
      this.events =
        parsedEvents.length > this.maxInMemoryEvents
          ? parsedEvents.slice(-this.maxInMemoryEvents)
          : parsedEvents;
      this.latestHash = verification.latest_hash;
    }

    this.initialized = true;
  }

  public async log(params: LogEventParams): Promise<GuardianAuditEvent> {
    await this.init();

    const next = this.writeQueue
      .catch(() => undefined)
      .then(async () => {
        const event_id = params.event_id ?? `GAE-${Date.now()}-${randomUUID().slice(0, 8)}`;
        const timestamp = params.timestamp ?? new Date().toISOString();
        const index = this.totalLogged;
        const prev_hash = this.latestHash;

        const partialEvent: Omit<GuardianAuditEvent, 'current_hash'> = {
          event_id,
          index,
          timestamp,
          event_type: params.event_type,
          stage: params.stage ?? 'INFRASTRUCTURE',
          agent_id: params.agent_id,
          session_id: params.session_id,
          tool_name: params.tool_name ?? 'system',
          decision: params.decision,
          policy_id: params.policy_id,
          detector: params.detector,
          rule_id: params.rule_id,
          details: params.details ?? {},
          prev_hash,
        };

        const current_hash = computeGuardianEventHash(partialEvent, prev_hash);
        const fullEvent: GuardianAuditEvent = {
          ...partialEvent,
          current_hash,
        };

        const serializedLine = canonicalStringify(fullEvent) + '\n';
        await fsPromises.appendFile(this.filePath, serializedLine, 'utf-8');

        this.events.push(fullEvent);
        while (this.events.length > this.maxInMemoryEvents) {
          this.events.shift();
        }
        this.totalLogged += 1;
        this.latestHash = current_hash;
        return fullEvent;
      });
    this.writeQueue = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  public async getEvents(): Promise<readonly GuardianAuditEvent[]> {
    await this.init();
    return [...this.events];
  }

  public getLatestHash(): string {
    return this.latestHash;
  }

  public async getMerkleRoot(): Promise<string> {
    await this.init();
    return computeMerkleRoot(this.events.map((e) => e.current_hash));
  }

  public async verifyIntegrity(expectedMerkleRoot?: string): Promise<AuditVerificationResult> {
    await this.init();
    return verifyGuardianAuditChain(this.events, expectedMerkleRoot);
  }

  public async generateProof(targetIndex: number): Promise<MerkleProof> {
    await this.init();
    return generateMerkleProof(
      this.events.map((e) => e.current_hash),
      targetIndex
    );
  }

  public async close(): Promise<void> {
    await this.writeQueue.catch(() => undefined);
  }
}
