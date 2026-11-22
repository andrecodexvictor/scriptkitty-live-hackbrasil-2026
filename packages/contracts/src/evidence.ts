import { z } from 'zod';
import * as crypto from 'node:crypto';
import {
  VerificationStatusSchema,
  VerificationTypeSchema,
  VerificationStatus,
  VerificationType,
} from './common.js';
import { canonicalStringify } from './custody.js';

/**
 * Sandbox containment specification for safe reproduction
 */
export const SandboxEnvironmentSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      runtime: val.runtime ?? 'docker_isolated',
      network_isolated: val.network_isolated ?? val.networkIsolated ?? true,
      timeout_ms: val.timeout_ms ?? val.timeoutMs,
      container_image_digest: val.container_image_digest ?? val.containerImageDigest,
      os_platform: val.os_platform ?? val.osPlatform,
      lockfile_sha256: val.lockfile_sha256 ?? val.lockfileSha256,
    };
  }
  return val;
}, z.object({
  runtime: z.enum([
    'gvisor',
    'docker_isolated',
    'node_sandbox',
    'mock_fixture',
    'dry_run',
    'container_isolated',
  ]),
  network_isolated: z.boolean({ required_error: 'network_isolated boolean flag is mandatory' }),
  timeout_ms: z.number().int().positive('timeout_ms must be a positive integer'),
  container_image_digest: z.string().optional(),
  os_platform: z.string().optional(),
  lockfile_sha256: z.string().regex(/^[a-f0-9]{64}$/i).optional(),
}));

export type SandboxEnvironment = z.infer<typeof SandboxEnvironmentSchema>;

/**
 * Reproducer execution artifacts and execution logs
 */
export const ReproducerArtifactSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      script_path: val.script_path ?? val.scriptPath,
      script_sha256: val.script_sha256 ?? val.scriptSha256,
      exit_code: val.exit_code ?? val.exitCode,
      stdout: val.stdout ?? '',
      stderr: val.stderr ?? '',
      execution_duration_ms: val.execution_duration_ms ?? val.durationMs ?? val.executionDurationMs,
    };
  }
  return val;
}, z.object({
  script_path: z.string().min(1, 'script_path is required'),
  script_sha256: z.string().regex(/^[a-f0-9]{64}$/i, 'script_sha256 must be a 64-character hex string'),
  exit_code: z.number().int(),
  stdout: z.string().default(''),
  stderr: z.string().default(''),
  execution_duration_ms: z.number().int().nonnegative('execution_duration_ms must be non-negative'),
}));

export type ReproducerArtifact = z.infer<typeof ReproducerArtifactSchema>;

/**
 * Proof payload and behavior comparison
 */
export const ProofType = {
  EXECUTABLE_POC: 'EXECUTABLE_POC',
  HTTP_HAR: 'HTTP_HAR',
  MOCK_PAYLOAD: 'MOCK_PAYLOAD',
  CLI_COMMAND: 'CLI_COMMAND',
  MCP_PAYLOAD: 'MCP_PAYLOAD',
} as const;

export type ProofType = (typeof ProofType)[keyof typeof ProofType];

export const ReproductionProofSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      proof_type: (val.proof_type ?? val.proofType ?? 'EXECUTABLE_POC').toUpperCase(),
      payload: val.payload,
      expected_behavior: val.expected_behavior ?? val.expectedBehavior,
      observed_vulnerable_behavior: val.observed_vulnerable_behavior ?? val.observedVulnerableBehavior,
    };
  }
  return val;
}, z.object({
  proof_type: z.enum(['EXECUTABLE_POC', 'HTTP_HAR', 'MOCK_PAYLOAD', 'CLI_COMMAND', 'MCP_PAYLOAD']),
  payload: z.string().min(1, 'proof payload is required'),
  expected_behavior: z.string().min(1, 'expected_behavior is required'),
  observed_vulnerable_behavior: z.string().min(1, 'observed_vulnerable_behavior is required'),
}));

export type ReproductionProof = z.infer<typeof ReproductionProofSchema>;

/**
 * Low-level system trace (syscalls, network egress, filesystem changes)
 */
export const SystemTraceSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      syscall_trace: val.syscall_trace ?? val.syscallTrace,
      network_egress: val.network_egress ?? val.networkEgress,
      filesystem_modifications: val.filesystem_modifications ?? val.filesystemModifications,
    };
  }
  return val;
}, z.object({
  syscall_trace: z.array(z.string()).optional(),
  network_egress: z.array(z.string()).optional(),
  filesystem_modifications: z.array(z.string()).optional(),
}));

export type SystemTrace = z.infer<typeof SystemTraceSchema>;

/**
 * Cryptographic Ed25519 signature of the verifying agent
 */
export const VerifierSignatureSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      verifying_agent_id: val.verifying_agent_id ?? val.verifyingAgentId,
      public_key: val.public_key ?? val.publicKey,
      signature: val.signature,
      signed_at: val.signed_at ?? val.verifiedAt ?? val.signedAt,
    };
  }
  return val;
}, z.object({
  verifying_agent_id: z.string().min(1, 'verifying_agent_id is required'),
  public_key: z.string().min(1, 'public_key is required'),
  signature: z.string().min(1, 'signature is required'),
  signed_at: z.string().datetime({ message: 'signed_at must be an ISO 8601 UTC timestamp' }),
}));

export type VerifierSignature = z.infer<typeof VerifierSignatureSchema>;

/**
 * Canonical Evidence Contract Schema
 */
export const EvidenceSchema = z.preprocess((val: any) => {
  if (val && typeof val === 'object') {
    return {
      evidence_id: val.evidence_id ?? val.evidenceId ?? val.id,
      finding_id: val.finding_id ?? val.findingId,
      verification_type: val.verification_type ?? val.verificationType ?? 'REPRODUCER_EXECUTION',
      status: val.status,
      verifier_agent_id: val.verifier_agent_id ?? val.verifierAgentId ?? val.verifierIdentity?.verifyingAgentId,
      sandbox_environment: val.sandbox_environment ?? val.sandboxEnvironment ?? {
        runtime: val.testExecutionLogs?.runner === 'SANDBOX_RUNNER' ? 'docker_isolated' : 'node_sandbox',
        network_isolated: true,
        timeout_ms: val.testExecutionLogs?.durationMs ? Math.max(30000, val.testExecutionLogs.durationMs * 2) : 30000,
        container_image_digest: val.environmentHash?.containerImageDigest,
        os_platform: val.environmentHash?.osPlatform,
        lockfile_sha256: val.environmentHash?.lockfileSha256,
      },
      reproducer_artifact: val.reproducer_artifact ?? (val.testExecutionLogs ? {
        script_path: 'workspace/poc_reproduce.ts',
        script_sha256: val.environmentHash?.lockfileSha256 ?? '0'.repeat(64),
        exit_code: val.testExecutionLogs.exitCode,
        stdout: val.testExecutionLogs.stdout ?? '',
        stderr: val.testExecutionLogs.stderr ?? '',
        execution_duration_ms: val.testExecutionLogs.durationMs ?? 0,
      } : undefined),
      reproduction_proof: val.reproduction_proof ?? val.reproductionProof,
      system_trace: val.system_trace ?? val.systemTrace,
      chain_hash: val.chain_hash ?? val.evidenceHash,
      signature: val.signature ?? (val.verifierIdentity ? {
        verifying_agent_id: val.verifierIdentity.verifyingAgentId,
        public_key: val.verifierIdentity.publicKey,
        signature: val.verifierIdentity.signature,
        signed_at: val.verifierIdentity.verifiedAt,
      } : undefined),
      recorded_at: val.recorded_at ?? val.recordedAt ?? val.verifierIdentity?.verifiedAt ?? new Date().toISOString(),
    };
  }
  return val;
}, z.object({
  evidence_id: z.string().min(3).regex(/^[a-zA-Z0-9_\-\.:]+$/, 'Invalid evidence_id format'),
  finding_id: z.string().min(3).regex(/^[a-zA-Z0-9_\-\.:]+$/, 'Invalid finding_id format'),
  verification_type: VerificationTypeSchema,
  status: VerificationStatusSchema,
  verifier_agent_id: z.string().min(1, 'verifier_agent_id is required'),
  sandbox_environment: SandboxEnvironmentSchema,
  reproducer_artifact: ReproducerArtifactSchema.optional(),
  reproduction_proof: ReproductionProofSchema.optional(),
  system_trace: SystemTraceSchema.optional(),
  chain_hash: z.string().regex(/^[a-f0-9]{64}$/i, 'chain_hash must be a 64-character SHA-256 hex string'),
  signature: VerifierSignatureSchema.optional(),
  recorded_at: z.string().datetime({ message: 'recorded_at must be an ISO 8601 UTC timestamp' }),
}));

export type Evidence = z.infer<typeof EvidenceSchema>;

/**
 * Computes canonical evidence chain hash linking finding and verifier identity
 * Uses structured canonical JSON hashing (RFC 8785) to eliminate second-preimage delimiter collisions.
 */
export function computeEvidenceChainHash(params: {
  finding_id: string;
  verifier_agent_id: string;
  status: string;
  script_sha256?: string;
  recorded_at: string;
}): string {
  const scriptHash = params.script_sha256 || '0'.repeat(64);
  const normalizedStatus = params.status.trim().toUpperCase();
  const payload = canonicalStringify({
    finding_id: params.finding_id,
    verifier_agent_id: params.verifier_agent_id,
    status: normalizedStatus,
    script_sha256: scriptHash,
    recorded_at: params.recorded_at,
  });
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}
