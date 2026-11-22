/**
 * @file apps/mcp-server/src/server.ts
 * @description Factory for the Script Kitty MCP Server v0.2.0 backed by
 * @script-kitty/security-actions (`createSecurityActionRuntime`),
 * @script-kitty/chainbreak, @script-kitty/jev-judge, real local scanners,
 * and @script-kitty/runtime-guardian (`wrapMcpServer`).
 */

import * as path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import {
  ActionEngineError,
  createSecurityActionRuntime,
  zodToJsonSchemaSimple,
  type AuthPrincipal,
  type SecurityActionRuntime,
} from '../../../packages/security-actions/dist/index.js';
import {
  CANONICAL_FIXTURE_IDS,
  isAllowedFixtureId,
} from '../../../packages/chainbreak/dist/index.js';
import { resolveJevProviderStatus } from '../../../packages/jev-judge/dist/index.js';
import {
  RuntimeGuardian,
  computeToolDefinitionHash,
  createGuardianMiddleware,
  wrapMcpServer,
  type GuardianConfig,
  type ToolDefinition,
} from '../../../packages/runtime-guardian/dist/index.js';
import {
  evaluateHttpHeadersDetailed,
  runGuardianProbeSuite,
  scanLocalWorkspace,
  type LocalScanFinding,
} from './scanner.js';

export const MCP_SERVER_NAME = 'script-kitty-mcp-server';
export const MCP_SERVER_VERSION = '0.2.0';

export const LEGACY_TOOL_NAMES = [
  'scout_target',
  'scan_secrets',
  'evaluate_http_headers',
  'validate_ai_guardrails',
  'verify_finding',
  'generate_patch',
  'run_recheck',
] as const;

const STATE_CHANGING_TOOL_NAMES = [
  'verify_finding',
  'generate_patch',
  'run_recheck',
];

const ScoutTargetArgsSchema = z
  .object({
    target: z.string().trim().min(1, 'target is required'),
  })
  .strict();

const ScanSecretsArgsSchema = z
  .object({
    path: z.string().trim().min(1, 'path is required'),
  })
  .strict();

const EvaluateHttpHeadersArgsSchema = z
  .object({
    target: z.string().trim().min(1, 'target is required'),
  })
  .strict();

const ValidateAiGuardrailsArgsSchema = z
  .object({
    target: z.string().trim().min(1, 'target is required'),
  })
  .strict();

const VerifyFindingArgsSchema = z
  .object({
    target: z.string().trim().min(1, 'target is required'),
    finding_id: z.string().trim().min(1, 'finding_id is required'),
    dry_run: z.boolean().optional().default(true),
  })
  .strict();

const GeneratePatchArgsSchema = z
  .object({
    finding_id: z.string().trim().min(1, 'finding_id is required'),
    category: z.string().trim().optional(),
    target: z.string().trim().optional(),
    analysis_id: z.string().trim().optional(),
    path_id: z.string().trim().optional(),
  })
  .strict();

const RunRecheckArgsSchema = z
  .object({
    target: z.string().trim().min(1, 'target is required'),
    finding_id: z.string().trim().min(1, 'finding_id is required'),
    analysis_id: z.string().trim().optional(),
  })
  .strict();

const LEGACY_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: 'scout_target',
    description:
      'Passive local/loopback discovery scanner inspecting local files (SAST/secrets), ChainBreak fixtures, or HTTP security headers.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'Local workspace path, ChainBreak fixture ID, or HTTP/HTTPS URL',
        },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'scan_secrets',
    description:
      'Scans local workspace files within allowed roots for hardcoded credentials, API keys, tokens, and private keys (with secret redaction).',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Directory or file path within allowed workspace roots' },
      },
      required: ['path'],
      additionalProperties: false,
    },
  },
  {
    name: 'evaluate_http_headers',
    description:
      'Evaluates real HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, CORS) of HTTP/HTTPS endpoints.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'HTTP/HTTPS target URL (cloud IMDS blocked)' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'validate_ai_guardrails',
    description:
      'Runs RuntimeGuardian adversarial probes (PromptInjectionDetector, ToolPoisoningGuard, ScopeBoundaryGuard) against local targets or prompts.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Local file path, loopback HTTP URL, or agent/target label' },
      },
      required: ['target'],
      additionalProperties: false,
    },
  },
  {
    name: 'verify_finding',
    description:
      'Controlled deterministic LAB verification for local findings or ChainBreak fixtures. Enforces Tri-Party SoD and human approval for non-dry-run state changes.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        finding_id: { type: 'string' },
        dry_run: { type: 'boolean', default: true },
      },
      required: ['target', 'finding_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'generate_patch',
    description:
      'Generates minimal reviewable RemediationSpec (for ChainBreak paths) or category-grounded defensive remediation playbooks with human approval required.',
    inputSchema: {
      type: 'object',
      properties: {
        finding_id: { type: 'string' },
        category: { type: 'string' },
        target: { type: 'string' },
        analysis_id: { type: 'string' },
        path_id: { type: 'string' },
      },
      required: ['finding_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'run_recheck',
    description:
      'Executes real regression verification against a local file/directory, HTTP target, or ChainBreak fixture to confirm whether a finding is resolved.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string' },
        finding_id: { type: 'string' },
        analysis_id: { type: 'string' },
      },
      required: ['target', 'finding_id'],
      additionalProperties: false,
    },
  },
];

export interface CreateScriptKittyMcpServerOptions {
  dbPath?: string;
  fixturesDir?: string;
  allowedRoots?: string[];
  principal?: AuthPrincipal;
  hmacSecret?: string;
  requireDelegationToken?: boolean;
  auditLogPath?: string;
  guardianConfig?: GuardianConfig;
  runtime?: SecurityActionRuntime;
}

export interface ScriptKittyMcpServerBundle {
  server: Server;
  guardian: RuntimeGuardian;
  runtime: SecurityActionRuntime;
  tools: ToolDefinition[];
  principal: AuthPrincipal;
  close: () => Promise<void>;
}

function formatToolSuccess(payload: Record<string, unknown>) {
  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(payload, null, 2),
      },
    ],
    structuredContent: payload,
  };
}

function formatToolError(code: string, message: string, details?: unknown) {
  const payload = {
    isError: true,
    code,
    message,
    ...(details !== undefined ? { details } : {}),
  };
  return {
    isError: true,
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function buildCapabilityTools(runtime: SecurityActionRuntime): ToolDefinition[] {
  return runtime.engine.list().map((cap) => {
    const jsonSchema = zodToJsonSchemaSimple(cap.inputSchema);
    return {
      name: cap.id,
      description: cap.description,
      inputSchema: {
        type: 'object',
        ...(jsonSchema as Record<string, unknown>),
      },
    };
  });
}

function buildRemediationPlaybookForCategory(
  findingId: string,
  category?: string,
  matchedFinding?: LocalScanFinding
) {
  const effectiveCategory = matchedFinding?.category ?? category ?? 'General Security Hardening';
  const lowered = `${effectiveCategory} ${findingId} ${matchedFinding?.rule_id ?? ''}`.toLowerCase();

  let steps: string[];
  let title: string;

  if (lowered.includes('secret') || lowered.includes('credential') || lowered.includes('sk-sec')) {
    title = 'Credential Removal, Rotation & Environment Isolation';
    steps = [
      '1. Revoke and rotate the exposed credential immediately at the identity/API provider.',
      '2. Remove the literal secret from source code and load it from environment variables or a secret manager.',
      '3. Run `scan_secrets` and `run_recheck` against the target path to verify zero leaks remain.',
    ];
  } else if (lowered.includes('sqli') || lowered.includes('sql')) {
    title = 'SQL Query Parameterization';
    steps = [
      '1. Replace string-interpolated or concatenated SQL queries with parameterized prepared statements.',
      '2. Enforce strict input validation at route boundaries.',
      '3. Re-run `scout_target` / `run_recheck` and unit tests to confirm remediation.',
    ];
  } else if (lowered.includes('cmdi') || lowered.includes('command')) {
    title = 'Command Injection Elimination';
    steps = [
      '1. Replace shell-interpolated calls (`exec`, `execSync`, `os.system`) with `execFile(..., argv, { shell: false })`.',
      '2. Apply a strict allowlist on subcommands/arguments and reject shell metacharacters.',
      '3. Re-run `scout_target` / `run_recheck` to confirm zero command injection patterns remain.',
    ];
  } else if (lowered.includes('header') || lowered.includes('hdr') || lowered.includes('hsts') || lowered.includes('csp')) {
    title = 'HTTP Security Header Hardening';
    steps = [
      "1. Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
      "2. Add a strict 'Content-Security-Policy', 'X-Frame-Options: DENY', and 'X-Content-Type-Options: nosniff'.",
      '3. Re-run `evaluate_http_headers` / `run_recheck` against the target URL.',
    ];
  } else {
    title = `Defensive Remediation Plan (${effectiveCategory})`;
    steps = [
      '1. Isolate and remove the vulnerable code path or permissive policy edge.',
      '2. Apply least-privilege input validation and boundary checks.',
      '3. Run `run_recheck` with independent verification before closing the finding.',
    ];
  }

  return {
    status: 'COMPLETED',
    mode: 'LAB',
    finding_id: findingId,
    category: effectiveCategory,
    matched_finding: matchedFinding ?? null,
    requiresHumanApproval: true,
    autoApplyAllowed: false,
    mergeAllowed: false,
    deployAllowed: false,
    patch_playbook: {
      title,
      steps,
    },
  };
}

export function createScriptKittyMcpServer(
  options: CreateScriptKittyMcpServerOptions = {}
): ScriptKittyMcpServerBundle {
  const ownsRuntime = options.runtime === undefined;
  const runtime =
    options.runtime ??
    createSecurityActionRuntime({
      name: MCP_SERVER_NAME,
      version: MCP_SERVER_VERSION,
      dbPath: options.dbPath ?? process.env.SCRIPT_KITTY_DB_PATH ?? ':memory:',
      fixturesDir: options.fixturesDir,
    });

  const principal: AuthPrincipal = options.principal ?? {
    principalId: process.env.SCRIPT_KITTY_PRINCIPAL_ID || 'mcp-stdio-operator',
    tenantId: process.env.SCRIPT_KITTY_TENANT_ID || 'payments-lab',
    roles: ['security-operator'],
    scopes: [
      'security:status',
      'security:analyze',
      'security:read',
      'security:judge',
      'security:remediate',
    ],
  };

  const allowedRoots =
    options.allowedRoots && options.allowedRoots.length > 0
      ? options.allowedRoots.map((r) => path.resolve(r))
      : [process.cwd()];

  const capabilityTools = buildCapabilityTools(runtime);
  const allTools: ToolDefinition[] = [...LEGACY_TOOL_DEFINITIONS, ...capabilityTools];
  const capabilityIdSet = new Set(runtime.engine.list().map((c) => c.id));

  const pinnedTools: Record<string, { tool_hash: string; is_state_changing?: boolean }> = {};
  for (const tool of allTools) {
    pinnedTools[tool.name] = {
      tool_hash: computeToolDefinitionHash(tool),
      is_state_changing: STATE_CHANGING_TOOL_NAMES.includes(tool.name),
    };
  }

  const guardian = createGuardianMiddleware(
    options.guardianConfig ?? {
      guardian_id: 'script-kitty-mcp-guardian',
      environment: 'development',
      failClosed: true,
      errorMode: 'tool_result',
      policy: {
        toolPoisoning: {
          enabled: true,
          allowUnregistered: false,
          allowShadowTools: false,
          enforceSchemaHash: true,
          manifest: {
            manifest_version: MCP_SERVER_VERSION,
            pinned_tools: pinnedTools,
          },
        },
        promptInjection: {
          enabled: true,
          action: 'BLOCK',
          blockExfiltration: true,
          detectCredentials: true,
        },
        scopeGuard: {
          enabled: true,
          allowedRoots,
        },
        confusedDeputy: {
          enabled: true,
          enforceSeparationOfDuties: true,
          requireDelegationToken: options.requireDelegationToken ?? false,
          hmacSecret: options.hmacSecret ?? process.env.SCRIPT_KITTY_GUARDIAN_HMAC_SECRET,
          verificationToolNames: ['verify_finding', 'run_recheck'],
          stateChangingToolNames: STATE_CHANGING_TOOL_NAMES,
        },
        ...(options.auditLogPath
          ? {
              auditLogger: {
                enabled: true,
                requireCustodyChain: true,
                logFilePath: options.auditLogPath,
              },
            }
          : {}),
      },
    }
  );

  const server = new Server(
    {
      name: MCP_SERVER_NAME,
      version: MCP_SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: allTools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: rawArgs } = request.params;
    const args =
      rawArgs && typeof rawArgs === 'object' && !Array.isArray(rawArgs)
        ? (rawArgs as Record<string, unknown>)
        : {};

    // Fail-closed: reject caller attempts to spoof tenantId in tool arguments
    if (Object.prototype.hasOwnProperty.call(args, 'tenantId')) {
      return formatToolError(
        'FORBIDDEN',
        'Tool payload must not specify tenantId; tenant scope is derived exclusively from server principal context.'
      );
    }

    const authCtx = {
      principal,
      source: 'mcp-stdio',
    };

    try {
      // 1. Canonical Security Action Engine capabilities (`security.*`)
      if (capabilityIdSet.has(name)) {
        const result = await runtime.engine.invoke<Record<string, unknown>>(
          name,
          args,
          authCtx
        );
        return formatToolSuccess(result);
      }

      // 2. Preserved Legacy Tool Names wired to REAL local scanners / ChainBreak / JEV / Guardian
      if (name === 'scan_secrets') {
        const parsed = ScanSecretsArgsSchema.safeParse(args);
        if (!parsed.success) {
          return formatToolError('INPUT_INVALID', parsed.error.message);
        }
        const safePath = guardian.getScopeBoundaryGuard().validatePath(parsed.data.path);
        const report = scanLocalWorkspace(safePath, { secretsOnly: true });
        return formatToolSuccess({
          ...report,
          tool: 'scan_secrets',
          secret_leaks_found: report.total_findings,
        });
      }

      if (name === 'evaluate_http_headers') {
        const parsed = EvaluateHttpHeadersArgsSchema.safeParse(args);
        if (!parsed.success) {
          return formatToolError('INPUT_INVALID', parsed.error.message);
        }
        const report = await evaluateHttpHeadersDetailed(parsed.data.target);
        if (report.status === 'BLOCKED') {
          return formatToolError('FORBIDDEN', report.error ?? 'Blocked HTTP target');
        }
        return formatToolSuccess({
          ...report,
          tool: 'evaluate_http_headers',
        });
      }

      if (name === 'scout_target') {
        const parsed = ScoutTargetArgsSchema.safeParse(args);
        if (!parsed.success) {
          return formatToolError('INPUT_INVALID', parsed.error.message);
        }
        const target = parsed.data.target;

        if (/^https?:\/\//i.test(target)) {
          const headerReport = await evaluateHttpHeadersDetailed(target);
          if (headerReport.status === 'BLOCKED') {
            return formatToolError('FORBIDDEN', headerReport.error ?? 'Blocked HTTP target');
          }
          return formatToolSuccess({
            status: headerReport.status,
            mode: 'LAB_PASSIVE_SCOUT',
            target_kind: 'HTTP_ENDPOINT',
            target,
            reachable: headerReport.reachable,
            status_code: headerReport.status_code,
            present_headers: headerReport.present_headers,
            missing_headers: headerReport.missing_headers,
            findings: headerReport.findings,
            ...(headerReport.error ? { error: headerReport.error } : {}),
          });
        }

        if (isAllowedFixtureId(target)) {
          const cbResult = await runtime.engine.invoke<Record<string, unknown>>(
            'security.chainbreak.analyze',
            { fixtureId: target },
            authCtx
          );
          return formatToolSuccess({
            status: 'COMPLETED',
            mode: 'LAB_PASSIVE_SCOUT',
            target_kind: 'CHAINBREAK_FIXTURE',
            target,
            ...cbResult,
          });
        }

        const safePath = guardian.getScopeBoundaryGuard().validatePath(target);
        const report = scanLocalWorkspace(safePath, { secretsOnly: false });
        return formatToolSuccess({
          ...report,
          mode: 'LAB_PASSIVE_SCOUT',
          target_kind: 'LOCAL_WORKSPACE',
          target,
        });
      }

      if (name === 'validate_ai_guardrails') {
        const parsed = ValidateAiGuardrailsArgsSchema.safeParse(args);
        if (!parsed.success) {
          return formatToolError('INPUT_INVALID', parsed.error.message);
        }
        const report = runGuardianProbeSuite({
          target: parsed.data.target,
          scopeGuard: guardian.getScopeBoundaryGuard(),
        });
        return formatToolSuccess({
          ...report,
          tool: 'validate_ai_guardrails',
        });
      }

      if (name === 'verify_finding') {
        const parsed = VerifyFindingArgsSchema.safeParse(args);
        if (!parsed.success) {
          return formatToolError('INPUT_INVALID', parsed.error.message);
        }
        const { target, finding_id: findingId, dry_run: dryRun } = parsed.data;

        if (isAllowedFixtureId(target)) {
          const cbRes = await runtime.engine.invoke<{
            analysisId: string;
            analysis: {
              paths: Array<{
                pathId: string;
                status: string;
                violatedPolicyId: string;
                evidenceIds: string[];
              }>;
              legitimateOperationsPreserved: boolean;
            };
          }>('security.chainbreak.analyze', { fixtureId: target }, authCtx);

          const judgeRes = await runtime.engine.invoke<{
            adjudication: Record<string, unknown>;
          }>('security.judge.evaluate', { analysisId: cbRes.analysisId }, authCtx);

          const matchedPath =
            cbRes.analysis.paths.find(
              (p) => p.pathId === findingId || p.violatedPolicyId === findingId
            ) ?? cbRes.analysis.paths[0];

          return formatToolSuccess({
            status: matchedPath
              ? dryRun
                ? 'DRY_RUN_PATH_VALIDATED'
                : 'PENDING_HUMAN_APPROVAL'
              : 'NOT_REPRODUCED',
            mode: 'LAB',
            productionTested: false,
            mergeAllowed: false,
            deployAllowed: false,
            target,
            finding_id: findingId,
            analysisId: cbRes.analysisId,
            path_status: matchedPath?.status ?? 'NOT_REPRODUCED',
            evidenceIds: matchedPath?.evidenceIds ?? [],
            adjudication: judgeRes.adjudication,
            requires_approval: !dryRun,
            autoApplyAllowed: false,
            note: 'PATH_VALIDATED reflects modeled LAB graph reachability only, never production exploitation.',
          });
        }

        if (findingId.startsWith('cb-')) {
          const getRes = await runtime.engine.invoke<Record<string, unknown>>(
            'security.chainbreak.get',
            { analysisId: findingId },
            authCtx
          );
          return formatToolSuccess({
            status: dryRun ? 'DRY_RUN_VERIFIED' : 'PENDING_HUMAN_APPROVAL',
            mode: 'LAB',
            productionTested: false,
            target,
            finding_id: findingId,
            requires_approval: !dryRun,
            autoApplyAllowed: false,
            ...getRes,
          });
        }

        if (/^https?:\/\//i.test(target)) {
          const hdrReport = await evaluateHttpHeadersDetailed(target);
          if (hdrReport.status === 'BLOCKED') {
            return formatToolError('FORBIDDEN', hdrReport.error ?? 'Blocked HTTP target');
          }
          const matched = hdrReport.findings.find(
            (f) => f.finding_id === findingId || f.rule_id === findingId
          );
          return formatToolSuccess({
            status: !hdrReport.reachable
              ? 'INCONCLUSIVE_UNREACHABLE'
              : matched
                ? dryRun
                  ? 'DRY_RUN_REPRODUCED'
                  : 'PENDING_HUMAN_APPROVAL'
                : 'NOT_REPRODUCED',
            mode: 'LAB',
            productionTested: false,
            target,
            finding_id: findingId,
            requires_approval: !dryRun,
            matched_finding: matched ?? null,
          });
        }

        const safePath = guardian.getScopeBoundaryGuard().validatePath(target);
        const scanReport = scanLocalWorkspace(safePath);
        const matched = scanReport.findings.find(
          (f) => f.finding_id === findingId || f.rule_id === findingId
        );
        return formatToolSuccess({
          status: matched
            ? dryRun
              ? 'DRY_RUN_REPRODUCED'
              : 'PENDING_HUMAN_APPROVAL'
            : 'NOT_REPRODUCED',
          mode: 'LAB',
          productionTested: false,
          target: safePath,
          finding_id: findingId,
          requires_approval: !dryRun,
          autoApplyAllowed: false,
          report_sha256: scanReport.report_sha256,
          matched_finding: matched ?? null,
        });
      }

      if (name === 'generate_patch') {
        const parsed = GeneratePatchArgsSchema.safeParse(args);
        if (!parsed.success) {
          return formatToolError('INPUT_INVALID', parsed.error.message);
        }
        const {
          finding_id: findingId,
          category,
          target,
          analysis_id: analysisId,
          path_id: pathId,
        } = parsed.data;

        if (analysisId && pathId) {
          const remRes = await runtime.engine.invoke<Record<string, unknown>>(
            'security.remediation.spec',
            { analysisId, pathId },
            authCtx
          );
          return formatToolSuccess({
            status: 'COMPLETED',
            mode: 'LAB',
            finding_id: findingId,
            ...remRes,
          });
        }

        if (target && isAllowedFixtureId(target)) {
          const cbRes = await runtime.engine.invoke<{
            analysisId: string;
            analysis: { paths: Array<{ pathId: string; violatedPolicyId: string }> };
          }>('security.chainbreak.analyze', { fixtureId: target }, authCtx);
          const matchedPath =
            cbRes.analysis.paths.find(
              (p) => p.pathId === findingId || p.violatedPolicyId === findingId
            ) ?? cbRes.analysis.paths[0];

          if (matchedPath) {
            const remRes = await runtime.engine.invoke<Record<string, unknown>>(
              'security.remediation.spec',
              { analysisId: cbRes.analysisId, pathId: matchedPath.pathId },
              authCtx
            );
            return formatToolSuccess({
              status: 'COMPLETED',
              mode: 'LAB',
              finding_id: findingId,
              ...remRes,
            });
          }
        }

        let matchedFinding: LocalScanFinding | undefined;
        if (target && !/^https?:\/\//i.test(target)) {
          const safePath = guardian.getScopeBoundaryGuard().validatePath(target);
          const report = scanLocalWorkspace(safePath);
          matchedFinding = report.findings.find(
            (f) => f.finding_id === findingId || f.rule_id === findingId
          );
        }

        return formatToolSuccess(
          buildRemediationPlaybookForCategory(findingId, category, matchedFinding)
        );
      }

      if (name === 'run_recheck') {
        const parsed = RunRecheckArgsSchema.safeParse(args);
        if (!parsed.success) {
          return formatToolError('INPUT_INVALID', parsed.error.message);
        }
        const { target, finding_id: findingId } = parsed.data;

        if (isAllowedFixtureId(target)) {
          const cbRes = await runtime.engine.invoke<{
            analysisId: string;
            analysis: {
              paths: Array<{ pathId: string; violatedPolicyId: string }>;
              legitimateOperationsPreserved: boolean;
            };
          }>('security.chainbreak.analyze', { fixtureId: target }, authCtx);

          const clean =
            cbRes.analysis.paths.length === 0 &&
            cbRes.analysis.legitimateOperationsPreserved;
          return formatToolSuccess({
            status: clean ? 'CLOSED' : 'OPEN_VULNERABILITY_PERSISTS',
            mode: 'LAB',
            target,
            finding_id: findingId,
            analysisId: cbRes.analysisId,
            recheck_verified: clean,
            remaining_paths: cbRes.analysis.paths.length,
            legitimateOperationsPreserved: cbRes.analysis.legitimateOperationsPreserved,
            jevProviderStatus: resolveJevProviderStatus(),
          });
        }

        if (/^https?:\/\//i.test(target)) {
          const hdrReport = await evaluateHttpHeadersDetailed(target);
          if (hdrReport.status === 'BLOCKED') {
            return formatToolError('FORBIDDEN', hdrReport.error ?? 'Blocked HTTP target');
          }
          if (!hdrReport.reachable) {
            return formatToolSuccess({
              status: 'INCONCLUSIVE',
              mode: 'LAB',
              target,
              finding_id: findingId,
              recheck_verified: false,
              error: hdrReport.error ?? 'Target unreachable during recheck',
            });
          }
          const remaining =
            findingId.toUpperCase() === 'ALL'
              ? hdrReport.findings
              : hdrReport.findings.filter(
                  (f) => f.finding_id === findingId || f.rule_id === findingId
                );
          const clean = remaining.length === 0;
          return formatToolSuccess({
            status: clean ? 'CLOSED' : 'OPEN_VULNERABILITY_PERSISTS',
            mode: 'LAB',
            target,
            finding_id: findingId,
            recheck_verified: clean,
            remaining_findings: remaining,
          });
        }

        const safePath = guardian.getScopeBoundaryGuard().validatePath(target);
        const scanReport = scanLocalWorkspace(safePath);
        const remaining =
          findingId.toUpperCase() === 'ALL'
            ? scanReport.findings
            : scanReport.findings.filter(
                (f) => f.finding_id === findingId || f.rule_id === findingId
              );
        const clean = remaining.length === 0;
        return formatToolSuccess({
          status: clean ? 'CLOSED' : 'OPEN_VULNERABILITY_PERSISTS',
          mode: 'LAB',
          target: safePath,
          finding_id: findingId,
          recheck_verified: clean,
          total_files_scanned: scanReport.total_files_scanned,
          remaining_findings_count: remaining.length,
          remaining_findings: remaining,
          report_sha256: scanReport.report_sha256,
        });
      }

      return formatToolError('CAPABILITY_NOT_FOUND', `Unknown tool '${name}'`);
    } catch (err) {
      if (err instanceof ActionEngineError) {
        return formatToolError(err.code, err.publicMessage, {
          correlationId: err.correlationId,
        });
      }
      return formatToolError(
        'EXECUTION_FAILED',
        err instanceof Error ? err.message : String(err)
      );
    }
  });

  wrapMcpServer(server, guardian);

  return {
    server,
    guardian,
    runtime,
    tools: allTools,
    principal,
    close: async () => {
      await server.close().catch(() => {});
      if (ownsRuntime) {
        runtime.close();
      }
    },
  };
}

export { CANONICAL_FIXTURE_IDS };
