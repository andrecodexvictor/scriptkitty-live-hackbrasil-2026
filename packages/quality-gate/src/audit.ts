/**
 * @file packages/quality-gate/src/audit.ts
 * @description Tamper-evident evaluation logging and SHA-256 Merkle root computation
 * over all rule evaluations, SoD checks, and gate decisions in ScriptKitty 2.0.
 */

import {
  sha256,
  canonicalStringify,
  computeMerkleRoot,
  EMPTY_MERKLE_ROOT,
  type RuleEvaluation,
  type SeparationOfDutiesEvaluation,
} from '@script-kitty/contracts';
import type { SeparationOfDutiesResult } from './separation-of-duties.js';

/**
 * Types of logged audit events.
 */
export type AuditEventType =
  | 'RULE_EVALUATION'
  | 'SOD_EVALUATION'
  | 'POLICY_EVALUATION'
  | 'CHAIN_VERIFICATION'
  | 'GATE_DECISION';

/**
 * Single immutable audit event.
 */
export interface AuditEvent {
  event_id: string;
  event_type: AuditEventType;
  timestamp: string;
  details: Record<string, unknown>;
  event_hash: string;
}

/**
 * Audit log integrity verification result.
 */
export interface AuditIntegrityResult {
  valid: boolean;
  total_events: number;
  merkle_root: string;
  broken_index?: number;
  error?: string;
}

/**
 * Computes canonical SHA-256 leaf hash for an audit event.
 * Strips self-referential hash field (`event_hash`).
 */
export function hashAuditEvent(event: Omit<AuditEvent, 'event_hash'> | AuditEvent): string {
  const copy = { ...event } as Record<string, unknown>;
  delete copy.event_hash;
  return sha256(canonicalStringify(copy));
}

/**
 * Computes the SHA-256 binary Merkle root over an array of audit events or event hashes.
 */
export function computeAuditMerkleRoot(
  items: Array<AuditEvent | string | RuleEvaluation>
): string {
  if (!items || items.length === 0) {
    return EMPTY_MERKLE_ROOT;
  }

  const leafHashes: string[] = items.map((item) => {
    if (typeof item === 'string') {
      return item;
    }
    if ('event_hash' in item && typeof (item as AuditEvent).event_hash === 'string') {
      return (item as AuditEvent).event_hash;
    }
    // Object without event_hash (e.g. RuleEvaluation)
    return sha256(canonicalStringify(item));
  });

  return computeMerkleRoot(leafHashes);
}

/**
 * Tamper-Evident Evaluation Audit Logger.
 * Records all gate decisions, rule checks, and SoD evaluations into an immutable,
 * verifiable audit log backed by a binary Merkle tree root.
 */
export class TamperEvidentAuditLogger {
  private events: AuditEvent[] = [];
  private eventCounter = 0;

  /**
   * Appends an audit event to the log and computes its canonical hash.
   */
  public logEvent(
    eventType: AuditEventType,
    details: Record<string, unknown>,
    timestamp?: string
  ): AuditEvent {
    this.eventCounter++;
    const eventId = `EVT-${Date.now()}-${this.eventCounter.toString().padStart(4, '0')}`;
    const ts = timestamp ?? new Date().toISOString();

    const candidate: Omit<AuditEvent, 'event_hash'> = {
      event_id: eventId,
      event_type: eventType,
      timestamp: ts,
      details,
    };

    const eventHash = hashAuditEvent(candidate);

    const fullEvent: AuditEvent = {
      ...candidate,
      event_hash: eventHash,
    };

    this.events.push(fullEvent);
    return fullEvent;
  }

  /**
   * Logs a single rule evaluation result.
   */
  public logRuleEvaluation(rule: RuleEvaluation): AuditEvent {
    return this.logEvent('RULE_EVALUATION', {
      rule_id: rule.rule_id,
      status: rule.status,
      reason: rule.reason,
      finding_id: rule.finding_id,
    });
  }

  /**
   * Logs a Separation of Duties check result.
   */
  public logSoDEvaluation(
    sod: SeparationOfDutiesEvaluation | SeparationOfDutiesResult
  ): AuditEvent {
    return this.logEvent('SOD_EVALUATION', {
      discovering_agent_id: sod.discovering_agent_id,
      verifying_agent_id: sod.verifying_agent_id,
      authorizing_agent_id: sod.authorizing_agent_id,
      is_valid: sod.is_valid,
      violation_details: sod.violation_details,
    });
  }

  /**
   * Logs a policy check result.
   */
  public logPolicyEvaluation(
    policyId: string,
    details: Record<string, unknown>
  ): AuditEvent {
    return this.logEvent('POLICY_EVALUATION', {
      policy_id: policyId,
      ...details,
    });
  }

  /**
   * Logs the final GateDecision payload.
   */
  public logGateDecision(decisionPayload: Record<string, unknown>): AuditEvent {
    return this.logEvent('GATE_DECISION', decisionPayload);
  }

  /**
   * Returns all recorded audit events.
   */
  public getEvents(): AuditEvent[] {
    return [...this.events];
  }

  /**
   * Returns an array of leaf hashes for all recorded events.
   */
  public getEventHashes(): string[] {
    return this.events.map((e) => e.event_hash);
  }

  /**
   * Computes the binary Merkle root over all recorded events.
   */
  public getMerkleRoot(): string {
    return computeAuditMerkleRoot(this.events);
  }

  /**
   * Verifies the cryptographic integrity of the audit log.
   * Confirms every event hash matches canonical recomputed hash.
   */
  public verifyIntegrity(): AuditIntegrityResult {
    if (this.events.length === 0) {
      return {
        valid: true,
        total_events: 0,
        merkle_root: EMPTY_MERKLE_ROOT,
      };
    }

    for (let i = 0; i < this.events.length; i++) {
      const event = this.events[i];
      const expectedHash = hashAuditEvent(event);
      if (event.event_hash !== expectedHash) {
        return {
          valid: false,
          total_events: this.events.length,
          merkle_root: '',
          broken_index: i,
          error: `Audit event hash mismatch at index ${i}: expected ${expectedHash}, found ${event.event_hash}`,
        };
      }
    }

    const root = this.getMerkleRoot();
    return {
      valid: true,
      total_events: this.events.length,
      merkle_root: root,
    };
  }

  /**
   * Resets the logger.
   */
  public clear(): void {
    this.events = [];
    this.eventCounter = 0;
  }
}
