/**
 * @file packages/runtime-guardian/src/tool-poisoning.ts
 * @description Tool Poisoning Defense: RFC 8785 Canonical Tool Hashing,
 * Manifest Hash Pinning, Shadow Tool Detection, and Schema Drift Prevention.
 */

import { canonicalStringify, sha256 } from './audit-logger.js';
import {
  type ToolDefinition,
  type ToolPinManifest,
  type ToolPoisoningPolicy,
  type ToolViolation,
  type ToolListingValidationResult,
  type InterceptionDecision,
  type InterceptionContext,
  GuardianSecurityError,
} from './types.js';

/**
 * Normalizes tool definition to only canonical hashable fields
 * with trimmed strings to guarantee hash stability.
 */
export function normalizeToolForHash(tool: ToolDefinition): Record<string, unknown> {
  return {
    name: (tool.name || '').trim(),
    description: (tool.description || '').trim(),
    inputSchema: tool.inputSchema ?? { type: 'object' },
  };
}

/**
 * Computes deterministic RFC 8785 + SHA-256 digest of a tool definition.
 */
export function computeToolDefinitionHash(tool: ToolDefinition): string {
  const normalized = normalizeToolForHash(tool);
  const canonicalJson = canonicalStringify(normalized);
  return sha256(canonicalJson);
}

// Alias for convenience
export const computeToolHash = computeToolDefinitionHash;

/**
 * Regex patterns for checking prompt injection in tool descriptions during registration.
 */
const DESCRIPTION_INJECTION_PATTERNS = [
  /(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|rules|directives|prompts)/i,
  /(?:system\s+prompt\s+override|system\s+override)/i,
  /<\|(?:im_start|im_end|system)\|>/i,
  /\[\/?(?:INST|SYS)\]/i,
  /<\/?(?:system|instruction|override)[\s>]/i,
];

export function scanDescriptionForPoisoning(description: string): { is_safe: boolean; reason?: string } {
  if (!description) return { is_safe: true };
  for (const pattern of DESCRIPTION_INJECTION_PATTERNS) {
    if (pattern.test(description)) {
      return {
        is_safe: false,
        reason: `Description matches injection pattern: ${pattern.source}`,
      };
    }
  }
  return { is_safe: true };
}

/**
 * Validates a list of advertised tools against a manifest and security policy.
 */
export function validateAndFilterTools(
  advertisedTools: ToolDefinition[],
  manifest?: ToolPinManifest,
  policy?: ToolPoisoningPolicy
): ToolListingValidationResult {
  const seenNames = new Set<string>();
  const filteredTools: ToolDefinition[] = [];
  const violations: ToolViolation[] = [];

  const allowUnregistered = policy?.allowUnregistered ?? false;
  const allowShadowTools = policy?.allowShadowTools ?? false;
  const knownHashes = policy?.knownToolHashes ?? {};
  const allowedToolsList = policy?.allowedTools;

  for (const tool of advertisedTools) {
    // 1. Schema structure check
    if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string' || tool.name.trim() === '') {
      violations.push({
        tool_name: tool?.name || 'unknown',
        violation_code: 'E_INVALID_SCHEMA',
        details: 'Tool definition must be an object with a non-empty name string',
      });
      continue;
    }

    // 2. Duplicate / shadow tool detection
    if (seenNames.has(tool.name)) {
      violations.push({
        tool_name: tool.name,
        violation_code: 'E_DUPLICATE_TOOL',
        details: `Duplicate tool name detected: '${tool.name}' attempted shadowing`,
      });
      if (!allowShadowTools) {
        continue;
      }
    }
    seenNames.add(tool.name);

    // 3. Allowed tools whitelist check
    if (allowedToolsList && !allowedToolsList.includes(tool.name)) {
      violations.push({
        tool_name: tool.name,
        violation_code: 'E_UNREGISTERED_TOOL',
        details: `Tool '${tool.name}' is not in allowedTools list`,
      });
      continue;
    }

    // 4. Manifest / Known Hashes check
    // 4. Description injection check
    const descCheck = scanDescriptionForPoisoning(tool.description);
    if (!descCheck.is_safe) {
      violations.push({
        tool_name: tool.name,
        violation_code: 'E_DESCRIPTION_POISONING',
        details: `Prompt injection vector detected in description of '${tool.name}': ${descCheck.reason}`,
      });
      continue;
    }

    // 5. Manifest / Known Hashes check
    const pinnedEntry = manifest?.pinned_tools?.[tool.name];
    const expectedHash = pinnedEntry?.tool_hash ?? knownHashes[tool.name];

    if (expectedHash) {
      const computed = computeToolDefinitionHash(tool);
      if (computed !== expectedHash) {
        violations.push({
          tool_name: tool.name,
          violation_code: 'E_TOOL_HASH_DRIFT',
          details: `Tool '${tool.name}' hash drift detected. Expected: ${expectedHash}, computed: ${computed}`,
        });
        continue;
      }
    } else if (manifest && !allowUnregistered) {
      violations.push({
        tool_name: tool.name,
        violation_code: 'E_UNREGISTERED_TOOL',
        details: `Tool '${tool.name}' is not in pinned tool registry manifest`,
      });
      continue;
    }

    filteredTools.push(tool);
  }

  return {
    is_valid: violations.length === 0,
    filtered_tools: filteredTools,
    violations,
  };
}

/**
 * ToolPoisoningGuard manages tool hash pinning and listing interception.
 */
export class ToolPoisoningGuard {
  private policy: ToolPoisoningPolicy;

  constructor(policy?: ToolPoisoningPolicy) {
    this.policy = policy ?? { enabled: true };
  }

  public computeToolHash(tool: ToolDefinition): string {
    return computeToolDefinitionHash(tool);
  }

  public verifyToolList(
    tools: ToolDefinition[],
    context?: InterceptionContext
  ): {
    allowedTools: ToolDefinition[];
    decisions: InterceptionDecision[];
    violations: ToolViolation[];
  } {
    if (!this.policy.enabled) {
      return {
        allowedTools: tools,
        decisions: [
          {
            verdict: 'ALLOW',
            detector: 'tool_poisoning',
            rule_id: 'tool_poisoning_disabled',
            reason: 'Tool poisoning guard is disabled in policy',
          },
        ],
        violations: [],
      };
    }

    const result = validateAndFilterTools(tools, this.policy.manifest, this.policy);

    const decisions: InterceptionDecision[] = [];

    if (result.violations.length === 0) {
      decisions.push({
        verdict: 'ALLOW',
        detector: 'tool_poisoning',
        rule_id: 'tools_verified',
        reason: `All ${result.filtered_tools.length} advertised tools verified against manifest`,
      });
    } else {
      for (const v of result.violations) {
        decisions.push({
          verdict: 'BLOCK',
          detector: 'tool_poisoning',
          rule_id: v.violation_code,
          reason: v.details,
          metadata: { tool_name: v.tool_name },
        });
      }
    }

    return {
      allowedTools: result.filtered_tools,
      decisions,
      violations: result.violations,
    };
  }

  public verifyToolCall(name: string, context?: InterceptionContext): InterceptionDecision {
    if (!this.policy.enabled) {
      return {
        verdict: 'ALLOW',
        detector: 'tool_poisoning',
        rule_id: 'tool_poisoning_disabled',
      };
    }

    // Check whitelist if configured
    if (this.policy.allowedTools && !this.policy.allowedTools.includes(name)) {
      return {
        verdict: 'BLOCK',
        detector: 'tool_poisoning',
        rule_id: 'E_UNREGISTERED_TOOL',
        reason: `Tool '${name}' is not in allowedTools list`,
        metadata: { tool_name: name },
      };
    }

    // Check manifest if configured
    if (this.policy.manifest && !this.policy.allowUnregistered) {
      if (!this.policy.manifest.pinned_tools[name]) {
        return {
          verdict: 'BLOCK',
          detector: 'tool_poisoning',
          rule_id: 'E_UNREGISTERED_TOOL',
          reason: `Tool '${name}' is not registered in pinned tool manifest`,
          metadata: { tool_name: name },
        };
      }
    }

    return {
      verdict: 'ALLOW',
      detector: 'tool_poisoning',
      rule_id: 'tool_call_verified',
      reason: `Tool '${name}' is authorized`,
    };
  }
}
