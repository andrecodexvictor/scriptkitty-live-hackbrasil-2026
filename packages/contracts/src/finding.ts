import { z } from 'zod';
import * as crypto from 'node:crypto';
import {
  SeveritySchema,
  ConfidenceSchema,
  TargetTypeSchema,
  CweIdSchema,
  OwaspCategorySchema,
  SourceEngineSchema,
  Severity,
  Confidence,
  TargetType,
} from './common.js';

/**
 * Source code location within the target repository
 */
export const SourceLocationSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      file_path: val.file_path ?? val.filePath,
      start_line: val.start_line ?? val.startLine,
      end_line: val.end_line ?? val.endLine,
      start_column: val.start_column ?? val.startColumn,
      end_column: val.end_column ?? val.endColumn,
      symbol: val.symbol ?? val.astSymbol,
    };
  }
  return val;
}, z.object({
  file_path: z.string().min(1, 'file_path cannot be empty'),
  start_line: z.number().int().positive('start_line must be a positive 1-indexed integer'),
  end_line: z.number().int().positive('end_line must be a positive 1-indexed integer'),
  start_column: z.number().int().positive().optional(),
  end_column: z.number().int().positive().optional(),
  symbol: z.string().optional(),
})).refine((data) => data.end_line >= data.start_line, {
  message: 'end_line must be greater than or equal to start_line',
  path: ['end_line'],
});

export type SourceLocation = z.infer<typeof SourceLocationSchema>;

/**
 * Agent context trace documenting discovery lineage
 */
export const AgentContextTraceSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      discovering_agent_id: val.discovering_agent_id ?? val.discoveringAgentId,
      agent_archetype: val.agent_archetype ?? val.agentArchetype,
      session_id: val.session_id ?? val.sessionId,
      tool_call_trace: val.tool_call_trace ?? val.toolCallTrace ?? [],
      reasoning_hash: val.reasoning_hash ?? val.reasoningHash,
    };
  }
  return val;
}, z.object({
  discovering_agent_id: z.string().min(1, 'discovering_agent_id is required'),
  agent_archetype: z.string().optional(),
  session_id: z.string().optional(),
  tool_call_trace: z.array(z.string()).default([]),
  reasoning_hash: z.string().regex(/^[a-f0-9]{64}$/i, 'reasoning_hash must be a 64-character SHA-256 hex string').optional(),
}));

export type AgentContextTrace = z.infer<typeof AgentContextTraceSchema>;

/**
 * AgentSec Runtime Defense Metadata (MCP tools, prompt injection, tainted memory)
 */
export const AgentSecMetadataSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      mcp_tool_name: val.mcp_tool_name ?? val.mcpToolName,
      mcp_server_id: val.mcp_server_id ?? val.mcpServerId,
      taint_source: val.taint_source ?? val.taintSource,
      taint_id: val.taint_id ?? val.taintId,
      injection_vector: val.injection_vector ?? val.injectionVector,
      affected_parameter: val.affected_parameter ?? val.affectedParameter,
      blocked_by_guardrail: val.blocked_by_guardrail ?? val.blockedByGuardrail,
    };
  }
  return val;
}, z.object({
  mcp_tool_name: z.string().optional(),
  mcp_server_id: z.string().optional(),
  taint_source: z.string().optional(), // e.g. "rag_document", "user_prompt", "mcp_tool_response"
  taint_id: z.string().optional(),     // e.g. "T-992"
  injection_vector: z.string().optional(), // e.g. "indirect_prompt_injection", "confused_deputy"
  affected_parameter: z.string().optional(), // e.g. "arguments.command"
  blocked_by_guardrail: z.boolean().optional(),
}));

export type AgentSecMetadata = z.infer<typeof AgentSecMetadataSchema>;

/**
 * Canonical SecurityFinding Schema
 */
export const SecurityFindingSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      finding_id: val.finding_id ?? val.findingId ?? val.id,
      source_engine: val.source_engine ?? val.sourceEngine ?? 'builtin',
      title: val.title,
      description: val.description ?? '',
      cwe_id: val.cwe_id ?? val.cweId,
      owasp_category: val.owasp_category ?? val.owaspCategory,
      severity: val.severity,
      confidence: val.confidence,
      target_type: val.target_type ?? val.targetType ?? 'SOURCE_CODE',
      target: val.target,
      location: val.location ?? val.sourceLocation,
      fingerprint: val.fingerprint ?? val.findingHash,
      commit_hash: val.commit_hash ?? val.commitHash,
      discovered_at: val.discovered_at ?? val.createdAt ?? val.discoveredAt,
      agent_context: val.agent_context ?? val.agentContext,
      agent_sec: val.agent_sec ?? val.agentSec,
      raw_metadata: val.raw_metadata ?? val.rawMetadata ?? {},
    };
  }
  return val;
}, z.object({
  finding_id: z.string().min(1, 'finding_id is required').regex(/^[a-zA-Z0-9_\-\.:]+$/, 'Invalid finding_id format'),
  source_engine: SourceEngineSchema,
  title: z.string().min(1, 'title is required').max(500),
  description: z.string().default(''),
  cwe_id: CweIdSchema,
  owasp_category: OwaspCategorySchema,
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  target_type: TargetTypeSchema.default(TargetType.SOURCE_CODE),
  target: z.string().min(1, 'target is required'),
  location: SourceLocationSchema,
  fingerprint: z.string().regex(/^[a-f0-9]{64}$/i, 'fingerprint must be a 64-character SHA-256 hex string'),
  commit_hash: z.string().regex(/^[a-f0-9]{7,64}$/i, 'commit_hash must be a valid git commit SHA (7 to 64 hex characters)'),
  discovered_at: z.string().datetime({ message: 'discovered_at must be an ISO 8601 UTC timestamp' }),
  agent_context: AgentContextTraceSchema.optional(),
  agent_sec: AgentSecMetadataSchema.optional(),
  raw_metadata: z.record(z.unknown()).default({}),
}));

export type SecurityFinding = z.infer<typeof SecurityFindingSchema>;

/**
 * Canonical SHA-256 Fingerprint Generator
 * Used for Quality Engine exception suppression matching (.security-pack.json v1)
 */
export function computeFindingFingerprint(params: {
  cwe_id: string;
  file_path: string;
  rule_or_match: string;
}): string {
  const normalizedCwe = params.cwe_id.trim().toUpperCase();
  const normalizedPath = params.file_path.trim().replace(/\\/g, '/');
  const payload = `${normalizedCwe}\0${normalizedPath}\0${params.rule_or_match.trim()}`;
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}
