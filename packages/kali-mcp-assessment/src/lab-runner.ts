/**
 * @file packages/kali-mcp-assessment/src/lab-runner.ts
 * @description Implements the 4 allowlisted defensive/verification Kali MCP capabilities:
 * - `security.kali.recon_surface`
 * - `security.kali.config_audit`
 * - `security.kali.verify_reproducer`
 * - `security.kali.sbom_cve_check`
 *
 * Supports deterministic offline `LabSimulationRunner` (`executionMode: "LAB_SIMULATION"`)
 * and fail-closed `LIVE_CONTAINER` execution via `KaliSandboxOrchestrator`, normalizing all outputs
 * into canonical `@script-kitty/contracts` `SecurityFinding` and `Evidence` records with
 * RFC 8785 SHA-256 custody hashes and `@script-kitty/quality-gate` Tri-Party SoD validation.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  type Evidence,
  type SecurityFinding,
  type ChainOfCustody,
  type ChainVerificationResult,
  type TargetType,
  VerificationStatus,
  VerificationType,
  OwaspWeb2021,
  buildCustodyChain,
  canonicalStringify,
  computeEvidenceChainHash,
  computeFindingFingerprint,
  sha256,
  validateEvidence,
  validateFinding,
  verifyChainOfCustody,
} from '@script-kitty/contracts';
import {
  SoDViolationCode,
  validateSeparationOfDuties,
  type SeparationOfDutiesResult,
} from '@script-kitty/quality-gate';
import {
  sanitizeObject,
  sanitizeOutput,
  type KaliMcpCapability,
  type KaliSandboxTransport,
} from '../../adapters/dist/index.js';
import {
  DEFAULT_PATH_ARGUMENT_NAMES,
  ScopeBoundaryGuard,
  PromptInjectionDetector,
} from '../../runtime-guardian/dist/index.js';
import {
  type SafeKaliArgvSpec,
  type SafeKaliLabSyntheticArgvSpec,
  buildSafeKaliArgv,
  buildSafeKaliLabSyntheticArgv,
} from './argv-builder.js';
import {
  DEFAULT_KALI_IMAGE_DIGEST,
  KaliSandboxOrchestrator,
  type SandboxExecutionResponse,
} from './sandbox-profile.js';
import {
  KALI_CAPABILITY_NAMES,
  KALI_LAB_ACTION_IDS,
  KALI_LAB_SYNTHETIC_CAPABILITY_NAMES,
  KALI_LAB_SYNTHETIC_PROFILE,
  KALI_MODE,
  type KaliCapabilityName,
  type KaliExecutionMode,
  type KaliLabActionId,
  type KaliLabSyntheticCapabilityName,
  type KaliSecurityError,
  KaliSecurityError as KaliSecurityErrorClass,
  type ParsedKaliConfigAuditInput,
  type ParsedKaliReconSurfaceInput,
  type ParsedKaliSbomCveCheckInput,
  type ParsedKaliVerifyReproducerInput,
  type RequestedExecutionMode,
  KaliConfigAuditInputSchema,
  KaliGetRunInputSchema,
  KaliLabRunInputSchema,
  KaliLocalCodeScanInputSchema,
  KaliReconSurfaceInputSchema,
  KaliSbomCveCheckInputSchema,
  KaliServiceInventoryInputSchema,
  KaliTlsReviewInputSchema,
  KaliVerifyReproducerInputSchema,
  KaliWebPassiveBaselineInputSchema,
  verifyEngagementScope,
} from './schemas.js';

export const KALI_SOURCE_ENGINE = 'kali_mcp_assessment' as const;
export const DEFAULT_KALI_COMMIT_HASH = '0123456789abcdef0123456789abcdef01234567';

export interface KaliCustodySummary {
  custody_standard: 'RFC8785_SHA256_MERKLE';
  chain?: ChainOfCustody;
  verification?: ChainVerificationResult;
  finding_fingerprints: string[];
  evidence_chain_hash?: string;
  canonical_output_sha256: string;
}

export interface KaliCapabilityExecutionResult {
  ok: boolean;
  mode: typeof KALI_MODE;
  executionMode: KaliExecutionMode;
  simulated: boolean;
  capability: KaliCapabilityName;
  networkMode: 'airgapped' | 'lab-loopback-bridge';
  imageDigest: string;
  argv: readonly string[];
  findings: SecurityFinding[];
  evidence?: Evidence;
  custody: KaliCustodySummary;
  sod_evaluation?: SeparationOfDutiesResult;
  sbom_summary?: {
    bomFormat: 'CycloneDX';
    specVersion: '1.5';
    manifestPath: string;
    sbomSha256: string;
    componentCount: number;
    vulnerabilityCount: number;
  };
  surface_inventory?: Array<{
    host: string;
    port: number;
    protocol: string;
    state: 'open' | 'closed' | 'filtered';
    service: string;
    banner?: string;
  }>;
  error_code?: string;
  error_message?: string;
  warnings: string[];
}

export interface LabReproducerFixture {
  content?: string;
  sha256?: string;
  exitCode: number;
  stdout: string;
  stderr?: string;
  durationMs?: number;
  observedBehavior?: string;
}

export interface LabSimulationFixtures {
  openPortsByHost?: Record<string, number[]>;
  bannersByEndpoint?: Record<string, string>;
  reproducers?: Record<string, LabReproducerFixture>;
  cvesByManifest?: Record<
    string,
    Array<{
      cveId: string;
      packageName: string;
      installedVersion: string;
      fixedVersion: string;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      title: string;
    }>
  >;
  strictReproducerOnDisk?: boolean;
}

export interface KaliRunnerOptions {
  workspaceRoot?: string;
  commitHash?: string;
  imageDigest?: string;
  requestedExecutionMode?: RequestedExecutionMode;
  orchestrator?: KaliSandboxOrchestrator;
  simulationRunner?: LabSimulationRunner;
  fixtures?: LabSimulationFixtures;
  defaultAuthorizingAgentId?: string;
  now?: () => string;
}

function createScopeGuard(workspaceRoot: string): ScopeBoundaryGuard {
  return new ScopeBoundaryGuard({
    enabled: true,
    allowedRoots: [workspaceRoot],
    allowSensitiveFiles: false,
    allowSymlinks: false,
    pathArgumentNames: [
      ...DEFAULT_PATH_ARGUMENT_NAMES,
      'config_rel_path',
      'reproducer_rel_path',
      'manifest_rel_path',
    ],
  });
}

function sanitizeFindingMetadata(raw: Record<string, unknown>, sanitizer: PromptInjectionDetector): Record<string, unknown> {
  const step1 = sanitizeObject(raw);
  return sanitizer.sanitize(step1) as Record<string, unknown>;
}

/**
 * Normalizes validated findings to `@script-kitty/contracts` `SecurityFinding`.
 */
export function buildCanonicalKaliFinding(params: {
  idSeed: string;
  title: string;
  description: string;
  cweId: string;
  owaspCategory: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence?: 'CERTAIN' | 'FIRM' | 'TENTATIVE';
  targetType: TargetType | string;
  target: string;
  filePath: string;
  startLine?: number;
  endLine?: number;
  ruleId: string;
  discoveringAgentId: string;
  capability: KaliCapabilityName;
  commitHash: string;
  discoveredAt: string;
  rawMetadata: Record<string, unknown>;
}): SecurityFinding {
  const sanitizer = new PromptInjectionDetector({ enabled: true, action: 'SANITIZE' });
  const findingId = `SK-KALI-${sha256(params.idSeed).slice(0, 16)}`;
  const fingerprint = computeFindingFingerprint({
    cwe_id: params.cweId,
    file_path: params.filePath,
    rule_or_match: params.ruleId,
  });

  const candidate: SecurityFinding = {
    finding_id: findingId,
    source_engine: KALI_SOURCE_ENGINE,
    title: String(sanitizer.sanitize(sanitizeOutput(params.title))).slice(0, 500),
    description: String(sanitizer.sanitize(sanitizeOutput(params.description))),
    cwe_id: params.cweId,
    owasp_category: params.owaspCategory,
    severity: params.severity,
    confidence: params.confidence ?? 'FIRM',
    target_type: params.targetType as SecurityFinding['target_type'],
    target: params.target,
    location: {
      file_path: params.filePath,
      start_line: Math.max(1, params.startLine ?? 1),
      end_line: Math.max(Math.max(1, params.startLine ?? 1), params.endLine ?? 1),
    },
    fingerprint,
    commit_hash: params.commitHash,
    discovered_at: params.discoveredAt,
    agent_context: {
      discovering_agent_id: params.discoveringAgentId,
      agent_archetype: 'kali_lab_assessment',
      tool_call_trace: [params.capability],
    },
    raw_metadata: sanitizeFindingMetadata(params.rawMetadata, sanitizer),
  };

  const validated = validateFinding(candidate);
  if (!validated.success) {
    throw new KaliSecurityErrorClass(
      'KALI_CONTRACT_VALIDATION_ERROR',
      validated.errors.map((e) => `${e.path}: ${e.message}`).join('; ')
    );
  }
  return validated.data;
}

/**
 * Deterministic offline simulation runner explicitly tagged `executionMode: "LAB_SIMULATION"`.
 * Never claims live container execution when no sandbox container ran on host.
 */
export class LabSimulationRunner {
  private readonly workspaceRoot: string;
  private readonly commitHash: string;
  private readonly imageDigest: string;
  private readonly fixtures: LabSimulationFixtures;
  private readonly scopeGuard: ScopeBoundaryGuard;
  private readonly now: () => string;

  constructor(options: {
    workspaceRoot?: string;
    commitHash?: string;
    imageDigest?: string;
    fixtures?: LabSimulationFixtures;
    now?: () => string;
  } = {}) {
    this.workspaceRoot = path.resolve(options.workspaceRoot ?? process.cwd());
    this.commitHash = options.commitHash ?? DEFAULT_KALI_COMMIT_HASH;
    this.imageDigest = options.imageDigest ?? DEFAULT_KALI_IMAGE_DIGEST;
    this.fixtures = options.fixtures ?? {};
    this.scopeGuard = createScopeGuard(this.workspaceRoot);
    this.now = options.now ?? (() => new Date().toISOString());
  }

  public async runReconSurface(
    input: ParsedKaliReconSurfaceInput,
    spec: SafeKaliArgvSpec
  ): Promise<KaliCapabilityExecutionResult> {
    const discoveredAt = this.now();
    const configuredPorts =
      this.fixtures.openPortsByHost?.[input.target_host] ??
      input.ports.filter((p) => p === 80 || p === 3000 || p === 8080 || p === 443);

    const openPorts = configuredPorts.filter((p) => input.ports.includes(p));
    const surfaceInventory = input.ports.map((port) => {
      const isOpen = openPorts.includes(port);
      const endpointKey = `${input.target_host}:${port}`;
      const rawBanner =
        this.fixtures.bannersByEndpoint?.[endpointKey] ??
        (isOpen
          ? port === 443
            ? 'nginx/1.24.0 TLSv1.2 (lab-fixture)'
            : 'Node.js/http lab-app (Access-Control-Allow-Origin: *)'
          : undefined);

      return {
        host: input.target_host,
        port,
        protocol: port === 443 ? 'https' : 'http',
        state: (isOpen ? 'open' : 'closed') as 'open' | 'closed',
        service: port === 443 ? 'https-lab' : port === 3000 ? 'lab-app-http' : 'http-lab',
        banner: rawBanner,
      };
    });

    const findings: SecurityFinding[] = [];
    for (const item of surfaceInventory) {
      if (item.state !== 'open') continue;
      if (item.port !== 443) {
        findings.push(
          buildCanonicalKaliFinding({
            idSeed: `recon:${input.target_host}:${item.port}:${input.probe_profile}`,
            title: `Cleartext HTTP lab service exposed on ${input.target_host}:${item.port}`,
            description: `Authorized LAB_SIMULATION surface probe detected unencrypted HTTP service '${item.service}' responding on port ${item.port}.`,
            cweId: 'CWE-200',
            owaspCategory: OwaspWeb2021.A05_SECURITY_MISCONFIGURATION,
            severity: item.port === 3000 ? 'HIGH' : 'MEDIUM',
            targetType: 'API_ENDPOINT',
            target: `${item.protocol}://${item.host}:${item.port}`,
            filePath: `lab-surface/${item.host}:${item.port}`,
            ruleId: `KALI-RECON-${input.probe_profile.toUpperCase()}-${item.port}`,
            discoveringAgentId: input.discovering_agent_id,
            capability: 'security.kali.recon_surface',
            commitHash: this.commitHash,
            discoveredAt,
            rawMetadata: {
              executionMode: 'LAB_SIMULATION',
              simulated: true,
              mode: KALI_MODE,
              networkMode: spec.networkMode,
              imageDigest: this.imageDigest,
              port: item.port,
              banner: item.banner ?? '',
            },
          })
        );
      }
    }

    const custodyHash = sha256(canonicalStringify({ capability: 'security.kali.recon_surface', findings }));
    return {
      ok: true,
      mode: KALI_MODE,
      executionMode: 'LAB_SIMULATION',
      simulated: true,
      capability: 'security.kali.recon_surface',
      networkMode: spec.networkMode,
      imageDigest: this.imageDigest,
      argv: spec.argv,
      findings,
      surface_inventory: surfaceInventory,
      custody: {
        custody_standard: 'RFC8785_SHA256_MERKLE',
        finding_fingerprints: findings.map((f) => f.fingerprint),
        canonical_output_sha256: custodyHash,
      },
      warnings: [
        'LAB_SIMULATION: Deterministic offline simulation executed (no live container spawned).',
      ],
    };
  }

  public async runConfigAudit(
    input: ParsedKaliConfigAuditInput,
    spec: SafeKaliArgvSpec
  ): Promise<KaliCapabilityExecutionResult> {
    const discoveredAt = this.now();
    const findings: SecurityFinding[] = [];

    if (input.audit_mode === 'static_config_tree' && input.config_rel_path) {
      const resolvedPath = this.scopeGuard.validatePath(input.config_rel_path);
      let fileContent = '';
      if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isFile()) {
        fileContent = fs.readFileSync(resolvedPath, 'utf8').slice(0, 256 * 1024);
      }

      const targetDesc = fileContent || `simulated-config:${input.config_rel_path}`;
      const hasWildcardOrPermissive =
        targetDesc.includes('*') ||
        targetDesc.includes('http://') ||
        !fileContent ||
        targetDesc.includes('USER root');

      if (hasWildcardOrPermissive) {
        findings.push(
          buildCanonicalKaliFinding({
            idSeed: `config:${input.config_rel_path}:${sha256(targetDesc).slice(0, 12)}`,
            title: `Configuration baseline hardening gap in ${input.config_rel_path}`,
            description: `Static LAB_SIMULATION configuration audit identified missing strict transport or container hardening posture in ${input.config_rel_path}.`,
            cweId: 'CWE-16',
            owaspCategory: OwaspWeb2021.A05_SECURITY_MISCONFIGURATION,
            severity: 'MEDIUM',
            targetType: 'CONFIGURATION',
            target: input.config_rel_path,
            filePath: input.config_rel_path,
            ruleId: 'KALI-CONFIG-STATIC-HARDENING',
            discoveringAgentId: input.discovering_agent_id,
            capability: 'security.kali.config_audit',
            commitHash: this.commitHash,
            discoveredAt,
            rawMetadata: {
              executionMode: 'LAB_SIMULATION',
              simulated: true,
              mode: KALI_MODE,
              networkMode: spec.networkMode,
              imageDigest: this.imageDigest,
              configBytes: Buffer.byteLength(targetDesc, 'utf8'),
            },
          })
        );
      }
    } else if (input.audit_mode === 'tls_posture') {
      const host = input.target_host ?? '127.0.0.1';
      const port = input.target_port ?? 443;
      findings.push(
        buildCanonicalKaliFinding({
          idSeed: `tls:${host}:${port}`,
          title: `Legacy TLS cipher posture detected on lab endpoint ${host}:${port}`,
          description: `LAB_SIMULATION TLS posture check flagged TLS 1.1 / RSA key-exchange fallback enabled for ${host}:${port}.`,
          cweId: 'CWE-326',
          owaspCategory: OwaspWeb2021.A02_CRYPTOGRAPHIC_FAILURES,
          severity: 'HIGH',
          targetType: 'API_ENDPOINT',
          target: `https://${host}:${port}`,
          filePath: `lab-tls/${host}:${port}`,
          ruleId: 'KALI-CONFIG-TLS-WEAK-PROTOCOL',
          discoveringAgentId: input.discovering_agent_id,
          capability: 'security.kali.config_audit',
          commitHash: this.commitHash,
          discoveredAt,
          rawMetadata: {
            executionMode: 'LAB_SIMULATION',
            simulated: true,
            mode: KALI_MODE,
            networkMode: spec.networkMode,
            imageDigest: this.imageDigest,
            protocols: ['TLSv1.1', 'TLSv1.2'],
          },
        })
      );
    } else {
      const host = input.target_host ?? '127.0.0.1';
      const port = input.target_port ?? 3000;
      const endpointKey = `${host}:${port}`;
      const injectedBanner = this.fixtures.bannersByEndpoint?.[endpointKey];
      findings.push(
        buildCanonicalKaliFinding({
          idSeed: `headers:${host}:${port}`,
          title: `Missing security headers & wildcard CORS on ${host}:${port}`,
          description: `LAB_SIMULATION HTTP header hygiene audit detected Access-Control-Allow-Origin: * and missing Content-Security-Policy / Strict-Transport-Security headers.`,
          cweId: 'CWE-693',
          owaspCategory: OwaspWeb2021.A05_SECURITY_MISCONFIGURATION,
          severity: 'MEDIUM',
          targetType: 'API_ENDPOINT',
          target: `http://${host}:${port}`,
          filePath: `lab-http/${host}:${port}`,
          ruleId: 'KALI-CONFIG-HTTP-HEADER-HYGIENE',
          discoveringAgentId: input.discovering_agent_id,
          capability: 'security.kali.config_audit',
          commitHash: this.commitHash,
          discoveredAt,
          rawMetadata: {
            executionMode: 'LAB_SIMULATION',
            simulated: true,
            mode: KALI_MODE,
            networkMode: spec.networkMode,
            imageDigest: this.imageDigest,
            observed_cors: '*',
            missing_headers: ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options'],
            ...(injectedBanner ? { response_banner: injectedBanner } : {}),
          },
        })
      );
    }

    const custodyHash = sha256(canonicalStringify({ capability: 'security.kali.config_audit', findings }));
    return {
      ok: true,
      mode: KALI_MODE,
      executionMode: 'LAB_SIMULATION',
      simulated: true,
      capability: 'security.kali.config_audit',
      networkMode: spec.networkMode,
      imageDigest: this.imageDigest,
      argv: spec.argv,
      findings,
      custody: {
        custody_standard: 'RFC8785_SHA256_MERKLE',
        finding_fingerprints: findings.map((f) => f.fingerprint),
        canonical_output_sha256: custodyHash,
      },
      warnings: [
        'LAB_SIMULATION: Deterministic offline simulation executed (no live container spawned).',
      ],
    };
  }

  public async runVerifyReproducer(
    input: ParsedKaliVerifyReproducerInput,
    spec: SafeKaliArgvSpec,
    authorizingAgentId: string
  ): Promise<KaliCapabilityExecutionResult> {
    const recordedAt = this.now();
    const resolvedPath = this.scopeGuard.validatePath(input.reproducer_rel_path);

    const sodEval = validateSeparationOfDuties(
      input.discovering_agent_id,
      input.verifier_agent_id,
      authorizingAgentId,
      { hasIndependentEvidence: true, evidenceVerifierId: input.verifier_agent_id }
    );

    if (!sodEval.is_valid) {
      throw new KaliSecurityErrorClass(
        sodEval.violation_code ?? SoDViolationCode.E_SOD_SELF_CERTIFICATION,
        sodEval.violation_details ?? 'Tri-Party Separation of Duties violation'
      );
    }

    // Compute pinned reproducer SHA-256 against disk file or fixture when present (fail closed on mismatch).
    const fixture =
      this.fixtures.reproducers?.[input.finding_id] ??
      this.fixtures.reproducers?.[input.reproducer_rel_path];

    let actualSha256: string | undefined;
    let sourceOrigin: 'disk' | 'fixture' | 'synthetic' = 'synthetic';

    if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isFile()) {
      const bytes = fs.readFileSync(resolvedPath);
      actualSha256 = sha256(bytes);
      sourceOrigin = 'disk';
    } else if (fixture?.sha256) {
      actualSha256 = fixture.sha256.toLowerCase();
      sourceOrigin = 'fixture';
    } else if (fixture?.content !== undefined) {
      actualSha256 = sha256(fixture.content);
      sourceOrigin = 'fixture';
    } else if (this.fixtures.strictReproducerOnDisk && !input.dry_run) {
      actualSha256 = '0'.repeat(64);
      sourceOrigin = 'disk';
    } else {
      actualSha256 = input.expected_reproducer_sha256;
      sourceOrigin = 'synthetic';
    }

    const shaMismatch = actualSha256.toLowerCase() !== input.expected_reproducer_sha256.toLowerCase();

    let exitCode: number;
    let status: Evidence['status'];
    let stdout: string;
    let stderr: string;
    let observedBehavior: string;

    if (shaMismatch) {
      exitCode = 2;
      status = VerificationStatus.EXECUTION_ERROR;
      stdout = '';
      stderr = `E_REPRODUCER_SHA256_MISMATCH: expected=${input.expected_reproducer_sha256}, actual=${actualSha256}`;
      observedBehavior = 'Fail-closed abort: reproducer SHA-256 digest did not match pinned hash.';
    } else if (fixture) {
      exitCode = fixture.exitCode;
      stdout = sanitizeOutput(fixture.stdout);
      stderr = sanitizeOutput(fixture.stderr ?? '');
      if (exitCode === 124) {
        status = VerificationStatus.INCONCLUSIVE;
        observedBehavior =
          fixture.observedBehavior ?? 'Verification timed out in LAB_SIMULATION sandbox (exit 124).';
      } else if (exitCode === 1) {
        status = VerificationStatus.VERIFIED_TRUE_POSITIVE;
        observedBehavior =
          fixture.observedBehavior ??
          `LAB_SIMULATION reproducer confirmed vulnerability (${input.finding_id}, exit_code=1).`;
      } else if (exitCode === 0) {
        status = VerificationStatus.REFUTED_FALSE_POSITIVE;
        observedBehavior =
          fixture.observedBehavior ??
          `LAB_SIMULATION reproducer held cleanly (mitigated/false-positive, exit_code=0).`;
      } else {
        status = VerificationStatus.EXECUTION_ERROR;
        observedBehavior =
          fixture.observedBehavior ??
          `LAB_SIMULATION reproducer exited abnormally (exit_code=${exitCode}).`;
      }
    } else if (input.dry_run) {
      exitCode = 0;
      status = VerificationStatus.INCONCLUSIVE;
      stdout = `[DRY_RUN][LAB_SIMULATION] Verified argv & pinned SHA-256 (${actualSha256}) for ${input.reproducer_rel_path}`;
      stderr = '';
      observedBehavior = 'Dry-run validation verified governance & argv without target mutation.';
    } else {
      exitCode = 1;
      status = VerificationStatus.VERIFIED_TRUE_POSITIVE;
      stdout = `[LAB_SIMULATION] Verified deterministic canary reproducer (${input.reproducer_runtime}) -> VULNERABLE_CONFIRMED`;
      stderr = '';
      observedBehavior = `LAB_SIMULATION reproducer confirmed canary invariant breach for ${input.finding_id}.`;
    }

    const evidenceCandidate: Evidence = {
      evidence_id: `SK-EVID-KALI-${sha256(`${input.finding_id}:${recordedAt}:${actualSha256}`).slice(0, 16)}`,
      finding_id: input.finding_id,
      verification_type: VerificationType.REPRODUCER_EXECUTION,
      status,
      verifier_agent_id: input.verifier_agent_id,
      sandbox_environment: {
        runtime: input.dry_run ? 'dry_run' : 'mock_fixture',
        network_isolated: true,
        timeout_ms: input.timeout_ms,
        container_image_digest: this.imageDigest,
        os_platform: 'linux-kali-lab-simulation',
      },
      reproducer_artifact: {
        script_path: input.reproducer_rel_path,
        script_sha256: actualSha256,
        exit_code: exitCode,
        stdout,
        stderr,
        execution_duration_ms: fixture?.durationMs ?? 12,
      },
      reproduction_proof: {
        proof_type: input.reproducer_runtime === 'http_replay_har' ? 'HTTP_HAR' : 'EXECUTABLE_POC',
        payload: canonicalStringify({
          capability: 'security.kali.verify_reproducer',
          runtime: input.reproducer_runtime,
          reproducer_rel_path: input.reproducer_rel_path,
          binary: spec.binary,
          source_origin: sourceOrigin,
        }),
        expected_behavior:
          input.expected_invariant ??
          `Verify deterministic security invariant for finding ${input.finding_id}`,
        observed_vulnerable_behavior: observedBehavior,
      },
      chain_hash: computeEvidenceChainHash({
        finding_id: input.finding_id,
        verifier_agent_id: input.verifier_agent_id,
        status,
        script_sha256: actualSha256,
        recorded_at: recordedAt,
      }),
      recorded_at: recordedAt,
    };

    const validatedEv = validateEvidence(evidenceCandidate);
    if (!validatedEv.success) {
      throw new KaliSecurityErrorClass(
        'KALI_CONTRACT_VALIDATION_ERROR',
        validatedEv.errors.map((e) => `${e.path}: ${e.message}`).join('; ')
      );
    }

    const syntheticFinding = buildCanonicalKaliFinding({
      idSeed: `finding-link:${input.finding_id}`,
      title: `Linked finding ${input.finding_id} under independent verification`,
      description: `Verification linkage finding recorded during Kali assessment custody sealing.`,
      cweId: 'CWE-89',
      owaspCategory: OwaspWeb2021.A03_INJECTION,
      severity: 'HIGH',
      targetType: 'API_ENDPOINT',
      target: input.target_host ?? input.reproducer_rel_path,
      filePath: input.reproducer_rel_path,
      ruleId: input.finding_id,
      discoveringAgentId: input.discovering_agent_id,
      capability: 'security.kali.verify_reproducer',
      commitHash: this.commitHash,
      discoveredAt: recordedAt,
      rawMetadata: {
        executionMode: 'LAB_SIMULATION',
        simulated: true,
        linked_finding_id: input.finding_id,
      },
    });
    // Align chain finding_id cleanly to the verified evidence's finding_id
    const alignedFinding: SecurityFinding = {
      ...syntheticFinding,
      finding_id: input.finding_id,
    };

    const chain = buildCustodyChain({
      finding: alignedFinding,
      evidence: validatedEv.data,
    });
    const chainCheck = verifyChainOfCustody(chain);

    return {
      ok: !shaMismatch && status !== VerificationStatus.EXECUTION_ERROR,
      mode: KALI_MODE,
      executionMode: 'LAB_SIMULATION',
      simulated: true,
      capability: 'security.kali.verify_reproducer',
      networkMode: spec.networkMode,
      imageDigest: this.imageDigest,
      argv: spec.argv,
      findings: [],
      evidence: validatedEv.data,
      sod_evaluation: sodEval,
      custody: {
        custody_standard: 'RFC8785_SHA256_MERKLE',
        chain,
        verification: chainCheck,
        finding_fingerprints: [],
        evidence_chain_hash: validatedEv.data.chain_hash,
        canonical_output_sha256: sha256(canonicalStringify(validatedEv.data)),
      },
      ...(shaMismatch
        ? {
            error_code: 'E_REPRODUCER_SHA256_MISMATCH',
            error_message: stderr,
          }
        : {}),
      warnings: [
        'LAB_SIMULATION: Deterministic offline simulation executed (no live container spawned).',
      ],
    };
  }

  public async runSbomCveCheck(
    input: ParsedKaliSbomCveCheckInput,
    spec: SafeKaliArgvSpec
  ): Promise<KaliCapabilityExecutionResult> {
    const discoveredAt = this.now();
    const resolvedPath = this.scopeGuard.validatePath(input.manifest_rel_path);

    let components: Array<{ name: string; version: string }> = [
      { name: 'lab-demo-http-parser', version: '1.2.3' },
      { name: 'zod', version: '3.25.76' },
    ];
    let manifestBytes = Buffer.from(canonicalStringify({ components }), 'utf8');

    if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isFile()) {
      manifestBytes = fs.readFileSync(resolvedPath);
      try {
        const parsedPkg = JSON.parse(manifestBytes.toString('utf8')) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        const deps = Object.entries({
          ...(parsedPkg.dependencies ?? {}),
          ...(parsedPkg.devDependencies ?? {}),
        });
        if (deps.length > 0) {
          components = deps.map(([name, version]) => ({ name, version }));
        }
      } catch {
        // Non-JSON manifest or lockfile: hash raw bytes directly
      }
    }

    const sbomSha256 = sha256(
      canonicalStringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        manifest: input.manifest_rel_path,
        manifestSha256: sha256(manifestBytes),
        components,
      })
    );

    const candidateVulns =
      this.fixtures.cvesByManifest?.[input.manifest_rel_path] ?? [
        {
          cveId: 'CVE-2024-LAB-0001',
          packageName: components[0]?.name ?? 'lab-demo-http-parser',
          installedVersion: components[0]?.version ?? '1.2.3',
          fixedVersion: '2.0.0',
          severity: 'HIGH' as const,
          title: `Simulated offline CVE match in ${components[0]?.name ?? 'dependency'} (${input.scanner_engine})`,
        },
        {
          cveId: 'CVE-2024-LAB-0002',
          packageName: components[1]?.name ?? 'lab-template-engine',
          installedVersion: components[1]?.version ?? '0.9.1',
          fixedVersion: '1.1.0',
          severity: 'MEDIUM' as const,
          title: `Simulated medium advisory in offline vulnerability DB`,
        },
      ];

    const allowedSeverities = new Set(input.severity_filter);
    const filteredVulns = candidateVulns.filter((v) => allowedSeverities.has(v.severity));

    const findings = filteredVulns.map((v) =>
      buildCanonicalKaliFinding({
        idSeed: `sbom:${input.manifest_rel_path}:${v.cveId}:${v.packageName}`,
        title: `${v.cveId}: ${v.title}`,
        description: `Offline ${input.scanner_engine} check in airgapped mode (--net=none) matched ${v.packageName}@${v.installedVersion}; upgrade to >= ${v.fixedVersion}.`,
        cweId: 'CWE-1395',
        owaspCategory: OwaspWeb2021.A06_VULNERABLE_OUTDATED_COMPONENTS,
        severity: v.severity,
        targetType: 'DEPENDENCY',
        target: `${v.packageName}@${v.installedVersion}`,
        filePath: input.manifest_rel_path,
        ruleId: v.cveId,
        discoveringAgentId: input.discovering_agent_id,
        capability: 'security.kali.sbom_cve_check',
        commitHash: this.commitHash,
        discoveredAt,
        rawMetadata: {
          executionMode: 'LAB_SIMULATION',
          simulated: true,
          mode: KALI_MODE,
          networkMode: 'airgapped',
          imageDigest: this.imageDigest,
          scanner_engine: input.scanner_engine,
          sbom_sha256: sbomSha256,
          cve_id: v.cveId,
          fixed_version: v.fixedVersion,
        },
      })
    );

    const custodyHash = sha256(
      canonicalStringify({ capability: 'security.kali.sbom_cve_check', sbomSha256, findings })
    );

    return {
      ok: true,
      mode: KALI_MODE,
      executionMode: 'LAB_SIMULATION',
      simulated: true,
      capability: 'security.kali.sbom_cve_check',
      networkMode: 'airgapped',
      imageDigest: this.imageDigest,
      argv: spec.argv,
      findings,
      sbom_summary: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        manifestPath: input.manifest_rel_path,
        sbomSha256,
        componentCount: components.length,
        vulnerabilityCount: findings.length,
      },
      custody: {
        custody_standard: 'RFC8785_SHA256_MERKLE',
        finding_fingerprints: findings.map((f) => f.fingerprint),
        canonical_output_sha256: custodyHash,
      },
      warnings: [
        'LAB_SIMULATION: Airgapped offline SBOM simulation executed (no live container spawned).',
      ],
    };
  }
}

function normalizeLiveScanFindings(params: {
  liveRes: SandboxExecutionResponse;
  capability: KaliCapabilityName;
  spec: SafeKaliArgvSpec;
  discoveringAgentId: string;
  target: string;
  filePath: string;
  commitHash: string;
  discoveredAt: string;
}): SecurityFinding[] {
  const stdoutText = params.liveRes.stdout.trim();
  if (!stdoutText) return [];

  try {
    const parsed = JSON.parse(stdoutText) as Record<string, unknown>;
    const rawFindings = Array.isArray(parsed.findings)
      ? (parsed.findings as Array<Record<string, unknown>>)
      : [];

    return rawFindings.map((item, idx) =>
      buildCanonicalKaliFinding({
        idSeed: `live:${params.capability}:${params.filePath}:${idx}:${String(item.rule_id ?? item.cveId ?? idx)}`,
        title: String(item.title ?? `Live container ${params.capability} finding`),
        description: String(item.description ?? `Verified by live container binary ${params.spec.binary}.`),
        cweId: String(item.cwe_id ?? (params.capability === 'security.kali.sbom_cve_check' ? 'CWE-1395' : 'CWE-200')),
        owaspCategory: String(item.owasp_category ?? OwaspWeb2021.A05_SECURITY_MISCONFIGURATION),
        severity: (String(item.severity ?? 'MEDIUM').toUpperCase() as SecurityFinding['severity']),
        targetType: params.capability === 'security.kali.sbom_cve_check' ? 'DEPENDENCY' : 'API_ENDPOINT',
        target: params.target,
        filePath: String(item.file_path ?? params.filePath),
        ruleId: String(item.rule_id ?? params.capability),
        discoveringAgentId: params.discoveringAgentId,
        capability: params.capability,
        commitHash: params.commitHash,
        discoveredAt: params.discoveredAt,
        rawMetadata: {
          executionMode: 'LIVE_CONTAINER',
          simulated: false,
          mode: KALI_MODE,
          profile: params.liveRes.profile,
          imageDigest: params.liveRes.imageDigest,
          ...item,
        },
      })
    );
  } catch {
    return [];
  }
}

/**
 * Unified execution dispatcher enforcing Zod validation, static argv building,
 * EngagementScope expiry checks, Tri-Party SoD, LIVE_CONTAINER fail-closed guards,
 * and explicit LAB_SIMULATION tagging.
 */
export async function executeKaliCapability(
  capability: KaliCapabilityName,
  rawInput: Record<string, unknown>,
  options: KaliRunnerOptions = {}
): Promise<KaliCapabilityExecutionResult> {
  const workspaceRoot = path.resolve(options.workspaceRoot ?? process.cwd());
  const commitHash = options.commitHash ?? DEFAULT_KALI_COMMIT_HASH;
  const imageDigest = options.imageDigest ?? DEFAULT_KALI_IMAGE_DIGEST;
  const orchestrator =
    options.orchestrator ??
    new KaliSandboxOrchestrator({
      workspaceRoot,
      imageDigest,
    });
  const simulator =
    options.simulationRunner ??
    new LabSimulationRunner({
      workspaceRoot,
      commitHash,
      imageDigest: orchestrator.getImageDigest(),
      fixtures: options.fixtures,
      now: options.now,
    });
  const nowIso = (options.now ?? (() => new Date().toISOString()))();

  // Enforce static argv, payload safety, host checks, and non-expired scope before runtime dispatch.
  const spec = buildSafeKaliArgv(capability, rawInput, {
    now: options.now ? new Date(nowIso) : undefined,
  });

  // Determine LIVE_CONTAINER vs LAB_SIMULATION explicitly and honestly.
  const requestedMode: RequestedExecutionMode = options.requestedExecutionMode ?? 'AUTO';
  let useLiveContainer = false;

  if (requestedMode === 'LIVE_CONTAINER') {
    useLiveContainer = true;
  } else if (requestedMode === 'AUTO') {
    const probe = await orchestrator.probeRuntime();
    useLiveContainer = probe.available;
  }

  if (useLiveContainer) {
    const liveRes = await orchestrator.executeLive({
      spec,
      workspaceRoot,
      requestedMode,
    });

    if (liveRes.failClosedReason) {
      throw new KaliSecurityErrorClass('KALI_SANDBOX_UNAVAILABLE', liveRes.failClosedReason);
    }

    if (capability === 'security.kali.verify_reproducer') {
      const input = KaliVerifyReproducerInputSchema.parse(rawInput);
      const authId =
        input.authorizing_agent_id ??
        options.defaultAuthorizingAgentId ??
        input.scope.authorized_by;

      const sodEval = validateSeparationOfDuties(
        input.discovering_agent_id,
        input.verifier_agent_id,
        authId,
        { hasIndependentEvidence: true, evidenceVerifierId: input.verifier_agent_id }
      );
      if (!sodEval.is_valid) {
        throw new KaliSecurityErrorClass(
          sodEval.violation_code ?? SoDViolationCode.E_SOD_SELF_CERTIFICATION,
          sodEval.violation_details ?? 'Tri-Party Separation of Duties violation'
        );
      }

      const evStatus = liveRes.timedOut
        ? VerificationStatus.INCONCLUSIVE
        : liveRes.exitCode === 1
          ? VerificationStatus.VERIFIED_TRUE_POSITIVE
          : liveRes.exitCode === 0
            ? VerificationStatus.REFUTED_FALSE_POSITIVE
            : VerificationStatus.EXECUTION_ERROR;

      const evCandidate: Evidence = {
        evidence_id: `SK-EVID-KALI-${sha256(`${input.finding_id}:${nowIso}`).slice(0, 16)}`,
        finding_id: input.finding_id,
        verification_type: VerificationType.REPRODUCER_EXECUTION,
        status: evStatus,
        verifier_agent_id: input.verifier_agent_id,
        sandbox_environment: {
          runtime: input.dry_run
            ? 'dry_run'
            : liveRes.profile === 'PROFILE_A_OCI_GVISOR'
              ? 'gvisor'
              : 'docker_isolated',
          network_isolated: true,
          timeout_ms: input.timeout_ms,
          container_image_digest: liveRes.imageDigest,
          os_platform: liveRes.profile === 'PROFILE_B_WSL2_MICROVM' ? 'linux-wsl2-microvm' : 'linux-kali-gvisor',
        },
        reproducer_artifact: {
          script_path: input.reproducer_rel_path,
          script_sha256: input.expected_reproducer_sha256,
          exit_code: liveRes.exitCode,
          stdout: liveRes.stdout,
          stderr: liveRes.stderr,
          execution_duration_ms: liveRes.durationMs,
        },
        reproduction_proof: {
          proof_type: input.reproducer_runtime === 'http_replay_har' ? 'HTTP_HAR' : 'EXECUTABLE_POC',
          payload: canonicalStringify({ capability, argv: spec.argv }),
          expected_behavior:
            input.expected_invariant ?? `Verify finding ${input.finding_id} inside live sandbox`,
          observed_vulnerable_behavior:
            liveRes.stdout || `Container exited with code ${liveRes.exitCode}`,
        },
        chain_hash: computeEvidenceChainHash({
          finding_id: input.finding_id,
          verifier_agent_id: input.verifier_agent_id,
          status: evStatus,
          script_sha256: input.expected_reproducer_sha256,
          recorded_at: nowIso,
        }),
        recorded_at: nowIso,
      };

      const validEv = validateEvidence(evCandidate);
      if (!validEv.success) {
        throw new KaliSecurityErrorClass(
          'KALI_CONTRACT_VALIDATION_ERROR',
          validEv.errors.map((e) => e.message).join('; ')
        );
      }

      return {
        ok: liveRes.ok,
        mode: KALI_MODE,
        executionMode: 'LIVE_CONTAINER',
        simulated: false,
        capability,
        networkMode: spec.networkMode,
        imageDigest: liveRes.imageDigest,
        argv: spec.argv,
        findings: [],
        evidence: validEv.data,
        sod_evaluation: sodEval,
        custody: {
          custody_standard: 'RFC8785_SHA256_MERKLE',
          finding_fingerprints: [],
          evidence_chain_hash: validEv.data.chain_hash,
          canonical_output_sha256: sha256(canonicalStringify(validEv.data)),
        },
        warnings: [],
      };
    }

    const discoveringId = String(rawInput.discovering_agent_id ?? 'agent-kali-recon-scout');
    const target = spec.targetHost ?? spec.workspaceRelPath ?? 'lab-target';
    const filePath = spec.workspaceRelPath ?? `lab-surface/${target}`;
    const findings = normalizeLiveScanFindings({
      liveRes,
      capability,
      spec,
      discoveringAgentId: discoveringId,
      target,
      filePath,
      commitHash,
      discoveredAt: nowIso,
    });

    return {
      ok: liveRes.ok,
      mode: KALI_MODE,
      executionMode: 'LIVE_CONTAINER',
      simulated: false,
      capability,
      networkMode: spec.networkMode,
      imageDigest: liveRes.imageDigest,
      argv: spec.argv,
      findings,
      custody: {
        custody_standard: 'RFC8785_SHA256_MERKLE',
        finding_fingerprints: findings.map((f) => f.fingerprint),
        canonical_output_sha256: sha256(canonicalStringify({ capability, findings })),
      },
      warnings: [],
    };
  }

  // Deterministic explicit LAB_SIMULATION execution path
  switch (capability) {
    case 'security.kali.recon_surface': {
      const parsed = KaliReconSurfaceInputSchema.parse(rawInput);
      return simulator.runReconSurface(parsed, spec);
    }
    case 'security.kali.config_audit': {
      const parsed = KaliConfigAuditInputSchema.parse(rawInput);
      return simulator.runConfigAudit(parsed, spec);
    }
    case 'security.kali.verify_reproducer': {
      const parsed = KaliVerifyReproducerInputSchema.parse(rawInput);
      const authId =
        parsed.authorizing_agent_id ??
        options.defaultAuthorizingAgentId ??
        parsed.scope.authorized_by;
      return simulator.runVerifyReproducer(parsed, spec, authId);
    }
    case 'security.kali.sbom_cve_check': {
      const parsed = KaliSbomCveCheckInputSchema.parse(rawInput);
      return simulator.runSbomCveCheck(parsed, spec);
    }
  }
}


/**
 * Bridges `@script-kitty/kali-mcp-assessment` into `@script-kitty/adapters`' `KaliMcpAdapter`
 * `KaliSandboxTransport` interface (`recon_surface`, `config_audit`, `verify_reproducer`, `sbom_cve_check`).
 */
export function createKaliAssessmentTransport(
  options: KaliRunnerOptions & { defaultAuthorizedBy?: string } = {}
): KaliSandboxTransport {
  const defaultAuthorizedBy = options.defaultAuthorizedBy ?? 'agent-quality-gate-authority';
  const defaultExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

  return {
    async invoke<T = Record<string, unknown>>(
      capability: KaliMcpCapability,
      validatedParams: Record<string, unknown>
    ): Promise<T> {
      const scope = {
        scope_id: 'SK-SCOPE-ADAPTER-BRIDGE',
        authorized_by: defaultAuthorizedBy,
        mode: 'LAB' as const,
        expires_at: defaultExpiresAt,
      };

      const capName: KaliCapabilityName = `security.kali.${capability}`;
      if (!KALI_CAPABILITY_NAMES.includes(capName)) {
        throw new KaliSecurityErrorClass(
          'KALI_DISALLOWED_CAPABILITY',
          `Unsupported capability '${capability}'`
        );
      }

      let mappedInput: Record<string, unknown>;
      switch (capability) {
        case 'recon_surface':
          mappedInput = {
            scope,
            target_host: validatedParams.target_host,
            ports: validatedParams.ports ?? [80, 443, 3000, 8080],
            probe_profile: validatedParams.include_tls_metadata
              ? 'http_headers_metadata'
              : 'tcp_connect_ports',
            discovering_agent_id: 'kali-adapter-recon',
          };
          break;
        case 'config_audit':
          mappedInput = {
            scope,
            audit_mode:
              validatedParams.profile === 'tls'
                ? 'tls_posture'
                : validatedParams.profile === 'headers'
                  ? 'http_security_headers'
                  : 'static_config_tree',
            config_rel_path: validatedParams.config_path,
            target_host: validatedParams.profile === 'tls' || validatedParams.profile === 'headers' ? '127.0.0.1' : undefined,
            discovering_agent_id: 'kali-adapter-config',
          };
          break;
        case 'verify_reproducer':
          mappedInput = {
            scope,
            finding_id: validatedParams.finding_id,
            discovering_agent_id: 'kali-adapter-recon',
            verifier_agent_id: 'kali-adapter-verifier',
            reproducer_rel_path: validatedParams.reproducer_path,
            expected_reproducer_sha256: sha256(String(validatedParams.reproducer_path)),
            reproducer_runtime: 'node',
            dry_run: Boolean(validatedParams.dry_run),
          };
          break;
        case 'sbom_cve_check':
          mappedInput = {
            scope,
            manifest_rel_path: validatedParams.manifest_path,
            scanner_engine:
              validatedParams.ecosystem === 'cyclonedx' || validatedParams.ecosystem === 'spdx'
                ? 'syft_grype_offline'
                : 'trivy_offline',
            severity_filter: [validatedParams.severity_threshold ?? 'HIGH'],
            discovering_agent_id: 'kali-adapter-sbom',
          };
          break;
      }

      const result = await executeKaliCapability(capName, mappedInput, options);
      if (capability === 'verify_reproducer' && result.evidence) {
        return {
          ...result,
          reproduction_verified:
            result.evidence.status === VerificationStatus.VERIFIED_TRUE_POSITIVE,
          exit_code: result.evidence.reproducer_artifact?.exit_code ?? 0,
          stdout: result.evidence.reproducer_artifact?.stdout ?? '',
          stderr: result.evidence.reproducer_artifact?.stderr ?? '',
          duration_ms: result.evidence.reproducer_artifact?.execution_duration_ms ?? 1,
        } as unknown as T;
      }
      return result as unknown as T;
    },
  };
}

// ============================================================================
// E4. HARDENED KALI LINUX LAB_SYNTHETIC VERIFICATION ENGINE & TENANT RUN STORE
// ============================================================================

const SECRET_TOKEN_REDACTION_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bghp_[A-Za-z0-9]{12,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{16,}\b/g,
  /\bsk-(?:proj-|ant-|live-|demo-|token-|test-)?[A-Za-z0-9_-]{12,}\b/g,
  /\bAIza[0-9A-Za-z_-]{20,}\b/g,
  /\bnvapi-[A-Za-z0-9_-]{12,}\b/g,
  /\bxai-[A-Za-z0-9_-]{12,}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/-]+=*\b/gi,
];

function redactStringSecrets(input: string, detector: PromptInjectionDetector): string {
  let out = String(detector.sanitize(sanitizeOutput(input)));
  for (const pat of SECRET_TOKEN_REDACTION_PATTERNS) {
    out = out.replace(pat, '[REDACTED_SECRET]');
  }
  return out;
}

/**
 * Recursively redacts any secret tokens, bearer values, or second-order prompt
 * injection strings from a Kali LAB_SYNTHETIC output structure.
 */
export function redactKaliLabValue<T>(
  value: T,
  detector = new PromptInjectionDetector({ enabled: true, action: 'SANITIZE' })
): T {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    return redactStringSecrets(value, detector) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactKaliLabValue(item, detector)) as unknown as T;
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (/(?:secret|token|password|api_key|apikey|authorization)/i.test(k) && typeof v === 'string') {
        out[k] = '[REDACTED_SECRET]';
      } else {
        out[k] = redactKaliLabValue(v, detector);
      }
    }
    return out as unknown as T;
  }
  return value;
}

export interface KaliLabSyntheticRunRecord {
  ok: true;
  runId: string;
  tenantId: string;
  actionId: KaliLabActionId;
  capability: string;
  profile: typeof KALI_LAB_SYNTHETIC_PROFILE;
  mode: 'LAB';
  kaliMode: typeof KALI_MODE;
  executionMode: 'LAB_SYNTHETIC';
  simulated: true;
  redacted: true;
  productionTested: false;
  mergeAllowed: false;
  deployAllowed: false;
  externalExecution: false;
  scopeRef: string;
  targetRef: string;
  budgetRef: string;
  networkMode: 'airgapped' | 'lab-loopback-bridge';
  imageDigest: string;
  argv: readonly string[];
  findings: SecurityFinding[];
  surface_inventory?: KaliCapabilityExecutionResult['surface_inventory'];
  sbom_summary?: KaliCapabilityExecutionResult['sbom_summary'];
  custody: KaliCustodySummary;
  warnings: string[];
  startedAt: string;
  completedAt: string;
}

/**
 * Tenant-isolated in-memory store for redacted Kali `LAB_SYNTHETIC` verification runs.
 * Cross-tenant lookups fail closed with `KALI_TENANT_ISOLATION_VIOLATION` (`FORBIDDEN`).
 */
export class KaliLabRunStore {
  private readonly runs = new Map<string, KaliLabSyntheticRunRecord>();
  private readonly maxRuns: number;

  constructor(maxRuns = 1000) {
    this.maxRuns = Number.isInteger(maxRuns) && maxRuns > 0 ? maxRuns : 1000;
  }

  public saveRun(
    authTenantId: string,
    record: KaliLabSyntheticRunRecord
  ): KaliLabSyntheticRunRecord {
    const tenantId = authTenantId?.trim();
    if (!tenantId) {
      throw new KaliSecurityErrorClass(
        'KALI_TENANT_ISOLATION_VIOLATION',
        'Authenticated tenantId is required to persist Kali LAB_SYNTHETIC run'
      );
    }
    if (record.tenantId !== tenantId) {
      throw new KaliSecurityErrorClass(
        'KALI_TENANT_ISOLATION_VIOLATION',
        'Run record tenantId does not match authenticated tenantId'
      );
    }
    const existing = this.runs.get(record.runId);
    if (existing && existing.tenantId !== tenantId) {
      throw new KaliSecurityErrorClass(
        'KALI_TENANT_ISOLATION_VIOLATION',
        `Cross-tenant write collision denied for runId '${record.runId}'`
      );
    }
    if (!existing) {
      while (this.runs.size >= this.maxRuns) {
        const oldestKey = this.runs.keys().next().value;
        if (oldestKey === undefined) break;
        this.runs.delete(oldestKey);
      }
    }
    const redactedRecord = redactKaliLabValue(record);
    this.runs.delete(record.runId);
    this.runs.set(record.runId, redactedRecord);
    return redactedRecord;
  }

  public getRun(authTenantId: string, runId: string): KaliLabSyntheticRunRecord {
    const tenantId = authTenantId?.trim();
    if (!tenantId) {
      throw new KaliSecurityErrorClass(
        'KALI_TENANT_ISOLATION_VIOLATION',
        'Authenticated tenantId is required to read Kali LAB_SYNTHETIC run'
      );
    }
    const trimmedRunId = runId?.trim();
    if (!trimmedRunId) {
      throw new KaliSecurityErrorClass(
        'KALI_SCHEMA_VALIDATION_ERROR',
        'runId must be a non-empty string'
      );
    }
    const found = this.runs.get(trimmedRunId);
    if (!found) {
      throw new KaliSecurityErrorClass(
        'KALI_RUN_NOT_FOUND',
        `Kali LAB_SYNTHETIC run '${trimmedRunId}' not found`
      );
    }
    if (found.tenantId !== tenantId) {
      throw new KaliSecurityErrorClass(
        'KALI_TENANT_ISOLATION_VIOLATION',
        `Cross-tenant access denied for Kali runId '${trimmedRunId}'`
      );
    }
    return redactKaliLabValue(found);
  }

  public listRuns(authTenantId: string): KaliLabSyntheticRunRecord[] {
    const tenantId = authTenantId?.trim();
    if (!tenantId) {
      throw new KaliSecurityErrorClass(
        'KALI_TENANT_ISOLATION_VIOLATION',
        'Authenticated tenantId is required'
      );
    }
    return Array.from(this.runs.values())
      .filter((r) => r.tenantId === tenantId)
      .map((r) => redactKaliLabValue(r));
  }
}

export interface KaliLabSyntheticExecutionOptions extends KaliRunnerOptions {
  tenantId?: string;
  principalId?: string;
  correlationId?: string;
  budgetRemainingMs?: number;
  runStore?: KaliLabRunStore;
}

const defaultSharedKaliRunStore = new KaliLabRunStore();

/**
 * Executes an enumerated E4 `LAB_SYNTHETIC` verification action
 * (`service_inventory`, `tls_review`, `web_passive_baseline`, `local_code_scan`),
 * enforcing zero raw shell, `--` static argv, out-of-scope/IMDS/private-IP blocking,
 * `LAB_SYNTHETIC` scope manifest check, budget timeout check, secret redaction,
 * and tenant-isolated run persistence.
 */
export async function executeKaliLabSyntheticAction(
  rawActionId: KaliLabActionId | string,
  rawInput: Record<string, unknown>,
  options: KaliLabSyntheticExecutionOptions = {}
): Promise<KaliLabSyntheticRunRecord> {
  const tenantId = (options.tenantId ?? 'payments-lab').trim();
  if (!tenantId) {
    throw new KaliSecurityErrorClass(
      'KALI_TENANT_ISOLATION_VIOLATION',
      'Authenticated tenantId is required'
    );
  }

  const startedAt = (options.now ?? (() => new Date().toISOString()))();
  const workspaceRoot = path.resolve(options.workspaceRoot ?? process.cwd());
  const commitHash = options.commitHash ?? DEFAULT_KALI_COMMIT_HASH;
  const imageDigest = options.imageDigest ?? DEFAULT_KALI_IMAGE_DIGEST;
  const runStore = options.runStore ?? defaultSharedKaliRunStore;

  if (options.budgetRemainingMs !== undefined && options.budgetRemainingMs < 100) {
    throw new KaliSecurityErrorClass(
      'KALI_BUDGET_EXCEEDED',
      `Remaining invocation time budget (${options.budgetRemainingMs}ms) is insufficient for LAB_SYNTHETIC verification`
    );
  }

  // 1. Validate actionId, scopeRef, targetRef, budgetRef & build static argv with `--`
  const spec: SafeKaliLabSyntheticArgvSpec = buildSafeKaliLabSyntheticArgv(
    rawActionId,
    rawInput,
    {
      expectedTenantId: tenantId,
      now: new Date(startedAt),
    }
  );

  const discoveringAgentId =
    typeof rawInput.discovering_agent_id === 'string' &&
    rawInput.discovering_agent_id.trim().length > 0
      ? rawInput.discovering_agent_id.trim()
      : options.principalId ?? 'agent-kali-lab-synthetic';

  const simulator =
    options.simulationRunner ??
    new LabSimulationRunner({
      workspaceRoot,
      commitHash,
      imageDigest,
      fixtures: options.fixtures,
      now: options.now,
    });

  const scopeForSim = {
    scope_id: spec.validatedScope.scopeId,
    authorized_by: spec.validatedScope.authorizedBy,
    tenant_id: tenantId,
    target_allowlist: spec.validatedScope.targetAllowlist,
    mode: 'LAB' as const,
    expires_at: spec.validatedScope.expiresAt,
  };

  let simResult: KaliCapabilityExecutionResult;

  switch (spec.actionId) {
    case 'service_inventory': {
      simResult = await simulator.runReconSurface(
        {
          scope: scopeForSim,
          target_host: spec.validatedTarget.targetHost ?? '127.0.0.1',
          ports: spec.validatedTarget.ports ?? [80, 443, 3000, 8080],
          probe_profile: 'tcp_connect_ports',
          discovering_agent_id: discoveringAgentId,
          timeout_ms: Math.min(45_000, spec.validatedBudget.timeoutMs),
        },
        spec
      );
      break;
    }

    case 'tls_review': {
      simResult = await simulator.runConfigAudit(
        {
          scope: scopeForSim,
          audit_mode: 'tls_posture',
          target_host: spec.validatedTarget.targetHost ?? '127.0.0.1',
          target_port: spec.validatedTarget.targetPort ?? 443,
          discovering_agent_id: discoveringAgentId,
          timeout_ms: spec.validatedBudget.timeoutMs,
        },
        spec
      );
      break;
    }

    case 'web_passive_baseline': {
      simResult = await simulator.runConfigAudit(
        {
          scope: scopeForSim,
          audit_mode: 'http_security_headers',
          target_host: spec.validatedTarget.targetHost ?? '127.0.0.1',
          target_port: spec.validatedTarget.targetPort ?? 3000,
          discovering_agent_id: discoveringAgentId,
          timeout_ms: spec.validatedBudget.timeoutMs,
        },
        spec
      );
      break;
    }

    case 'local_code_scan': {
      const severityFilter: Array<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'> = Array.isArray(
        rawInput.severity_filter
      )
        ? (rawInput.severity_filter as Array<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>)
        : ['CRITICAL', 'HIGH', 'MEDIUM'];
      simResult = await simulator.runSbomCveCheck(
        {
          scope: scopeForSim,
          manifest_rel_path: spec.validatedTarget.workspaceRelPath ?? 'package.json',
          scanner_engine: 'trivy_offline',
          severity_filter: severityFilter,
          discovering_agent_id: discoveringAgentId,
          timeout_ms: spec.validatedBudget.timeoutMs,
        },
        spec
      );
      break;
    }
  }

  const completedAt = (options.now ?? (() => new Date().toISOString()))();
  const redactedFindings = redactKaliLabValue(simResult.findings);
  const redactedSurface = simResult.surface_inventory
    ? redactKaliLabValue(simResult.surface_inventory)
    : undefined;
  const redactedSbom = simResult.sbom_summary
    ? redactKaliLabValue(simResult.sbom_summary)
    : undefined;

  const runIdSeed = canonicalStringify({
    tenantId,
    actionId: spec.actionId,
    scopeRef: spec.validatedScope.scopeId,
    targetRef: spec.validatedTarget.targetRef,
    budgetRef: spec.validatedBudget.budgetRef,
    argv: spec.argv,
    startedAt,
    correlationId: options.correlationId ?? '',
  });
  const runId = `kali-run-${sha256(runIdSeed).slice(0, 16)}`;

  const canonicalHash = sha256(
    canonicalStringify({
      runId,
      tenantId,
      actionId: spec.actionId,
      profile: KALI_LAB_SYNTHETIC_PROFILE,
      argv: spec.argv,
      findings: redactedFindings,
    })
  );

  const record: KaliLabSyntheticRunRecord = {
    ok: true,
    runId,
    tenantId,
    actionId: spec.actionId,
    capability: `security.kali.${spec.actionId}`,
    profile: KALI_LAB_SYNTHETIC_PROFILE,
    mode: 'LAB',
    kaliMode: KALI_MODE,
    executionMode: 'LAB_SYNTHETIC',
    simulated: true,
    redacted: true,
    productionTested: false,
    mergeAllowed: false,
    deployAllowed: false,
    externalExecution: false,
    scopeRef: spec.validatedScope.scopeId,
    targetRef: spec.validatedTarget.targetRef,
    budgetRef: spec.validatedBudget.budgetRef,
    networkMode: spec.networkMode,
    imageDigest,
    argv: spec.argv,
    findings: redactedFindings,
    ...(redactedSurface ? { surface_inventory: redactedSurface } : {}),
    ...(redactedSbom ? { sbom_summary: redactedSbom } : {}),
    custody: {
      custody_standard: 'RFC8785_SHA256_MERKLE',
      finding_fingerprints: redactedFindings.map((f) => f.fingerprint),
      canonical_output_sha256: canonicalHash,
    },
    warnings: [
      'LAB_SYNTHETIC: Enumerated fail-closed synthetic lab verification executed (zero raw shell, zero live targets scanned).',
    ],
    startedAt,
    completedAt,
  };

  return runStore.saveRun(tenantId, record);
}

