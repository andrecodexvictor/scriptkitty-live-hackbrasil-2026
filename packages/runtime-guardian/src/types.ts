/**
 * @file packages/runtime-guardian/src/types.ts
 * @description Canonical type definitions, schemas, contexts, decisions, and policies
 * for the AgentSec Runtime Guardian.
 */

import { z } from 'zod';
import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';

// ============================================================================
// Interception Verdicts & Decisions
// ============================================================================

export type InterceptionVerdict = 'ALLOW' | 'BLOCK' | 'SANITIZE' | 'ESCALATE' | 'REQUIRE_APPROVAL';

export type DetectorType =
  | 'prompt_injection'
  | 'tool_poisoning'
  | 'scope_guard'
  | 'confused_deputy'
  | 'policy'
  | 'custom';

export interface InterceptionDecision {
  verdict: InterceptionVerdict;
  detector: DetectorType;
  rule_id: string;
  reason?: string;
  sanitized_payload?: unknown;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// Context & Telemetry
// ============================================================================

export interface TaintTag {
  source: string;
  taint_id: string;
  vector: string;
}

export interface TaintContext {
  is_tainted: boolean;
  taint_source?: string;
  taint_id?: string;
}

export interface InterceptionContext {
  session_id: string;
  caller_agent_id?: string;
  target_agent_id?: string;
  discovering_agent_id?: string;
  delegation_token?: string | SignedDelegationToken;
  tool_name?: string;
  timestamp: string;
  trace_id?: string;
  client_metadata?: Record<string, unknown>;
  taint_tags?: TaintTag[];
  taint_context?: TaintContext;
  is_tainted?: boolean;
}

// ============================================================================
// Tool Definitions & Pinning
// ============================================================================

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties?: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
    [key: string]: unknown;
  };
  capabilities?: string[];
  is_state_changing?: boolean;
  allowed_roles?: string[];
  timeout_ms?: number;
  [key: string]: unknown;
}

export interface PinnedToolEntry {
  tool_hash: string;
  canonical_definition?: ToolDefinition;
  registered_at?: string;
  registered_by?: string;
  allowed_roles?: string[];
  is_state_changing?: boolean;
}

export interface ToolPinManifest {
  manifest_version?: string;
  manifest_sha256?: string;
  pinned_tools: Record<string, PinnedToolEntry>;
}

export interface ToolViolation {
  tool_name: string;
  violation_code:
    | 'E_UNREGISTERED_TOOL'
    | 'E_TOOL_HASH_DRIFT'
    | 'E_DUPLICATE_TOOL'
    | 'E_DESCRIPTION_POISONING'
    | 'E_INVALID_SCHEMA'
    | 'E_TOOL_SHADOWING';
  details: string;
}

export interface ToolListingValidationResult {
  is_valid: boolean;
  filtered_tools: ToolDefinition[];
  violations: ToolViolation[];
}

// ============================================================================
// Cryptographic Delegation Tokens
// ============================================================================

export const DelegationTokenClaimsSchema = z.object({
  token_id: z.string().uuid('token_id must be a valid UUIDv4'),
  issuer: z.string().min(1, 'issuer agent ID is required'),
  subject: z.string().min(1, 'subject (delegate) agent ID is required'),
  audience: z.string().min(1, 'audience (target tool or server) is required'),
  allowed_scopes: z.array(z.string().min(1)).min(1, 'at least one allowed scope is required'),
  issued_at: z.string().datetime({ message: 'issued_at must be an ISO 8601 UTC timestamp' }),
  expires_at: z.string().datetime({ message: 'expires_at must be an ISO 8601 UTC timestamp' }),
  nonce: z.string().regex(/^[a-f0-9]{16,64}$/i, 'nonce must be a 16-64 hex character string'),
  taint_context: z
    .object({
      is_tainted: z.boolean(),
      taint_source: z.string().optional(),
      taint_id: z.string().optional(),
    })
    .default({ is_tainted: false }),
  sod_lineage: z
    .object({
      discovering_agent_id: z.string().optional(),
      finding_id: z.string().optional(),
    })
    .optional(),
});

export type DelegationTokenClaims = z.infer<typeof DelegationTokenClaimsSchema>;

export const SignedDelegationTokenSchema = z.object({
  claims: DelegationTokenClaimsSchema,
  signature: z.string().regex(/^[a-f0-9]{64}$/i, 'signature must be a 64-char SHA-256 HMAC hex string'),
  key_id: z.string().min(1, 'key_id is required'),
});

export type SignedDelegationToken = z.infer<typeof SignedDelegationTokenSchema>;

export interface DelegationValidationContext {
  calling_agent_id: string;
  target_tool_name: string;
  is_state_changing: boolean;
  required_scope?: string;
  current_timestamp?: Date;
  active_nonce_cache?: Set<string>;
  discovering_agent_id?: string;
}

// ============================================================================
// Security Policies & Configuration
// ============================================================================

export interface PromptInjectionPolicy {
  enabled: boolean;
  action?: 'BLOCK' | 'SANITIZE';
  customPatterns?: (string | RegExp)[];
  stripDelimiters?: boolean;
  maxStringLength?: number;
  blockExfiltration?: boolean;
  detectCredentials?: boolean;
}

export interface ToolPoisoningPolicy {
  enabled: boolean;
  allowedTools?: string[];
  enforceSchemaHash?: boolean;
  manifest?: ToolPinManifest;
  knownToolHashes?: Record<string, string>; // tool_name -> sha256 hex
  allowShadowTools?: boolean;
  allowUnregistered?: boolean;
}

export interface ScopeGuardPolicy {
  enabled: boolean;
  allowedRoots: string[];
  blockedPathPatterns?: (string | RegExp)[];
  pathArgumentNames?: string[];
  allowSensitiveFiles?: boolean;
  allowSymlinks?: boolean;
  allowedUriSchemes?: string[];
}

export interface ConfusedDeputyPolicy {
  enabled: boolean;
  enforceSeparationOfDuties: boolean;
  requireDelegationToken?: boolean;
  hmacSecret?: string;
  keyId?: string;
  verificationToolNames?: string[];
  stateChangingToolNames?: string[];
  maxTtlMs?: number;
}

export interface AuditLoggerPolicy {
  enabled: boolean;
  requireCustodyChain?: boolean;
  logFilePath?: string;
}

export interface SecurityPolicy {
  promptInjection?: PromptInjectionPolicy;
  toolPoisoning?: ToolPoisoningPolicy;
  scopeGuard?: ScopeGuardPolicy;
  confusedDeputy?: ConfusedDeputyPolicy;
  auditLogger?: AuditLoggerPolicy;
}

export interface GuardianConfig {
  guardian_id?: string;
  environment?: 'development' | 'testing' | 'production';
  policy?: SecurityPolicy;
  failClosed?: boolean; // Default: true
  errorMode?: 'tool_result' | 'throw'; // Default: 'tool_result'
}

// ============================================================================
// Audit Logging Contracts
// ============================================================================

export type GuardianAuditEventType =
  | 'TOOL_LIST'
  | 'TOOL_CALL'
  | 'TOOL_RESULT'
  | 'PROMPT_INJECTION_DETECTED'
  | 'TOOL_POISONING_DETECTED'
  | 'SCOPE_VIOLATION_DETECTED'
  | 'CONFUSED_DEPUTY_DETECTED'
  | 'POLICY_VIOLATION'
  | 'SECURITY_VIOLATION'
  | 'GENESIS';

export type GuardianDecision = InterceptionVerdict;

export interface GuardianAuditEvent {
  event_id: string;
  index: number;
  timestamp: string;
  event_type: GuardianAuditEventType;
  stage: 'ON_LIST_TOOLS' | 'ON_CALL_TOOL' | 'ON_TOOL_RESULT' | 'INFRASTRUCTURE';
  agent_id?: string;
  session_id?: string;
  tool_name: string;
  decision: GuardianDecision;
  policy_id: string;
  detector?: DetectorType;
  rule_id?: string;
  details: Record<string, unknown>;
  prev_hash: string;
  current_hash: string;
}

export interface MerkleProofStep {
  position: 'left' | 'right';
  hash: string;
}

export type MerkleProof = MerkleProofStep[];

export interface AuditVerificationResult {
  valid: boolean;
  total_events: number;
  merkle_root: string;
  latest_hash: string;
  broken_index?: number;
  error?: string;
}

// ============================================================================
// Security Error
// ============================================================================

export class GuardianSecurityError extends Error {
  public readonly code: string;
  public readonly detector: DetectorType;
  public readonly ruleId: string;
  public readonly details?: unknown;

  constructor(message: string, code: string, detector: DetectorType, ruleId: string, details?: unknown) {
    super(`[GuardianSecurityError] ${code}: ${message}`);
    this.name = 'GuardianSecurityError';
    this.code = code;
    this.detector = detector;
    this.ruleId = ruleId;
    this.details = details;
    Object.setPrototypeOf(this, GuardianSecurityError.prototype);
  }
}
