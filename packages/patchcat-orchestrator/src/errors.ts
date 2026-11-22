/**
 * @file packages/patchcat-orchestrator/src/errors.ts
 * @description Fail-closed governance, SoD, Guardian, and orchestration errors for PatchCat.
 */

export type PatchCatGovernanceErrorCode =
  | 'E_POLICY_MUTATION_FORBIDDEN'
  | 'E_SOD_VIOLATION'
  | 'E_GUARDIAN_BLOCKED'
  | 'E_DELIVERY_GATE_FAILED'
  | 'E_TENANT_ISOLATION'
  | 'E_INVALID_INPUT'
  | 'E_ORCHESTRATION_FAILED';

export interface PatchCatGovernanceErrorOptions {
  stage?: string;
  correlationId?: string;
  details?: Record<string, unknown>;
  cause?: unknown;
}

/**
 * Fail-closed governance error raised whenever an event or caller requests a forbidden
 * policy mutation, Quality Gate bypass, auto-merge/auto-deploy override, Tri-Party SoD
 * violation, or RuntimeGuardian security block.
 */
export class PatchCatGovernanceError extends Error {
  public readonly code: PatchCatGovernanceErrorCode;
  public readonly stage?: string;
  public readonly correlationId?: string;
  public readonly details?: Record<string, unknown>;

  constructor(
    code: PatchCatGovernanceErrorCode,
    message: string,
    options: PatchCatGovernanceErrorOptions = {}
  ) {
    super(`[${code}] ${message}`, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'PatchCatGovernanceError';
    this.code = code;
    this.stage = options.stage;
    this.correlationId = options.correlationId;
    this.details = options.details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
