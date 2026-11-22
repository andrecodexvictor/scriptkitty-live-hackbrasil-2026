/**
 * @file packages/quality-gate/src/separation-of-duties.ts
 * @description Strict Tri-Party Separation of Duties (SoD) Validator for ScriptKitty 2.0.
 * Enforces mathematical invariance: A_disc != A_veri && A_veri != A_auth && A_disc != A_auth.
 */

import {
  evaluateSeparationOfDuties as contractsEvaluateSoD,
  type SeparationOfDutiesEvaluation,
} from '@script-kitty/contracts';

/**
 * Standard SoD Violation Codes
 */
export const SoDViolationCode = {
  E_SOD_OMNIPOTENT_AGENT: 'E_SOD_OMNIPOTENT_AGENT',
  E_SOD_SELF_CERTIFICATION: 'E_SOD_SELF_CERTIFICATION',
  E_SOD_SELF_AUTHORIZATION: 'E_SOD_SELF_AUTHORIZATION',
  E_SOD_DISCOVERER_AUTHORIZATION: 'E_SOD_DISCOVERER_AUTHORIZATION',
  E_SOD_MISSING_AGENT: 'E_SOD_MISSING_AGENT',
  E_SOD_SELF_ASSERTED_EVIDENCE: 'E_SOD_SELF_ASSERTED_EVIDENCE',
} as const;

export type SoDViolationCode = (typeof SoDViolationCode)[keyof typeof SoDViolationCode];

/**
 * Separation of Duties Validation Result
 */
export interface SeparationOfDutiesResult {
  discovering_agent_id: string;
  verifying_agent_id: string;
  authorizing_agent_id: string;
  is_valid: boolean;
  violation_code?: SoDViolationCode;
  violation_details?: string;
}

/**
 * Agent role assignment mapping.
 */
export interface AgentRoleMapping {
  [agentId: string]: 'discovery' | 'verification' | 'authorization' | string;
}

/**
 * Options for extended SoD verification.
 */
export interface SoDValidationOptions {
  hasIndependentEvidence?: boolean;
  evidenceVerifierId?: string | null;
}

/**
 * Validates strict Tri-Party Separation of Duties across agent identities.
 * Mathematical invariance:
 *   A_disc != A_veri && A_veri != A_auth && A_disc != A_auth.
 *
 * Case-insensitive comparison with whitespace trimming.
 * Self-asserted or missing verification evidence strictly results in is_valid: false.
 */
export function validateSeparationOfDuties(
  discoveringAgentId?: string | null,
  verifyingAgentId?: string | null,
  authorizingAgentId?: string | null,
  options?: SoDValidationOptions
): SeparationOfDutiesResult {
  const dTrimmed = (discoveringAgentId ?? '').trim();
  const vTrimmed = (verifyingAgentId ?? '').trim();
  const aTrimmed = (authorizingAgentId ?? '').trim();

  // 1. Check for missing identities
  if (!dTrimmed || !vTrimmed || !aTrimmed) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_code: SoDViolationCode.E_SOD_MISSING_AGENT,
      violation_details:
        'E_SOD_MISSING_AGENT: Discovering, verifying, and authorizing agent identities must all be provided',
    };
  }

  // 2. Normalize case
  const d = dTrimmed.toLowerCase();
  const v = vTrimmed.toLowerCase();
  const a = aTrimmed.toLowerCase();

  // 3. Omnipotent Agent (d == v == a)
  if (d === v && v === a) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_code: SoDViolationCode.E_SOD_OMNIPOTENT_AGENT,
      violation_details:
        'E_SOD_OMNIPOTENT_AGENT: Single agent attempted discovery, verification, and authorization',
    };
  }

  // 4. Self-Certification (d == v)
  if (d === v) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_code: SoDViolationCode.E_SOD_SELF_CERTIFICATION,
      violation_details:
        'E_SOD_SELF_CERTIFICATION: Discovering agent cannot verify its own finding',
    };
  }

  // 5. Self-Authorization (v == a)
  if (v === a) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_code: SoDViolationCode.E_SOD_SELF_AUTHORIZATION,
      violation_details:
        'E_SOD_SELF_AUTHORIZATION: Verifying agent cannot authorize the gate release',
    };
  }

  // 6. Discoverer-Authorization (d == a)
  if (d === a) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_code: SoDViolationCode.E_SOD_OMNIPOTENT_AGENT,
      violation_details:
        'E_SOD_OMNIPOTENT_AGENT: Discovering agent cannot authorize the gate release (E_SOD_DISCOVERER_AUTHORIZATION)',
    };
  }

  // 7. Check evidence independence & self-assertion
  if (options?.hasIndependentEvidence === false) {
    return {
      discovering_agent_id: dTrimmed,
      verifying_agent_id: vTrimmed,
      authorizing_agent_id: aTrimmed,
      is_valid: false,
      violation_code: SoDViolationCode.E_SOD_SELF_ASSERTED_EVIDENCE,
      violation_details:
        'E_SOD_SELF_ASSERTED_EVIDENCE: Self-asserted finding lacks independent empirical verification evidence',
    };
  }

  if (options?.evidenceVerifierId) {
    const evVerifier = options.evidenceVerifierId.trim().toLowerCase();
    if (evVerifier === d) {
      return {
        discovering_agent_id: dTrimmed,
        verifying_agent_id: vTrimmed,
        authorizing_agent_id: aTrimmed,
        is_valid: false,
        violation_code: SoDViolationCode.E_SOD_SELF_CERTIFICATION,
        violation_details:
          'E_SOD_SELF_CERTIFICATION: Evidence was self-asserted by the discovering agent',
      };
    }
  }

  return {
    discovering_agent_id: dTrimmed,
    verifying_agent_id: vTrimmed,
    authorizing_agent_id: aTrimmed,
    is_valid: true,
  };
}

/**
 * Validates Separation of Duties from an AgentRoleMapping object.
 * Identifies whether distinct agents are assigned to 'discovery', 'verification', and 'authorization'.
 */
export function validateAgentRoleMapping(roleMapping: AgentRoleMapping): SeparationOfDutiesResult {
  const discoveryAgents: string[] = [];
  const verificationAgents: string[] = [];
  const authorizationAgents: string[] = [];

  for (const [agentId, role] of Object.entries(roleMapping)) {
    const r = role.toLowerCase().trim();
    if (r === 'discovery') discoveryAgents.push(agentId);
    if (r === 'verification') verificationAgents.push(agentId);
    if (r === 'authorization') authorizationAgents.push(agentId);
  }

  const disc = discoveryAgents[0] ?? '';
  const veri = verificationAgents[0] ?? '';
  const auth = authorizationAgents[0] ?? '';

  return validateSeparationOfDuties(disc, veri, auth);
}

/**
 * Re-exports the contracts canonical evaluateSeparationOfDuties function.
 */
export { contractsEvaluateSoD as evaluateSeparationOfDuties };
export type { SeparationOfDutiesEvaluation };
