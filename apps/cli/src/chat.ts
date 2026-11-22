/**
 * @file apps/cli/src/chat.ts
 * @description Detective Patch Cat chat engine backed by @script-kitty/security-actions,
 * @script-kitty/chainbreak, @script-kitty/jev-judge, and real local workspace/HTTP scanners.
 * Always executes deterministically in offline/LAB mode when cloud JEV credentials are absent.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import {
  ANSI_BOLD,
  ANSI_CYAN,
  ANSI_GREEN,
  ANSI_PURPLE,
  ANSI_RESET,
  ANSI_YELLOW,
  printBanner,
} from "./banner.js";
import { loadCredentials, type CredentialStoreOptions } from "./credentials.js";
import { evaluateHttpHeadersDetailed, scanWorkspaceReal } from "./real_scanner.js";
import {
  ActionEngineError,
  createSecurityActionRuntime,
  type AuthPrincipal,
  type SecurityActionRuntime,
} from "../../../packages/security-actions/dist/index.js";
import {
  CANONICAL_FIXTURE_IDS,
  isAllowedFixtureId,
} from "../../../packages/chainbreak/dist/index.js";
import { resolveJevProviderStatus } from "../../../packages/jev-judge/dist/index.js";

export interface ChatSessionContext {
  runtime: SecurityActionRuntime;
  principal: AuthPrincipal;
  allowedRoots: string[];
  dbPath: string;
  lastAnalysisId?: string;
  lastPathId?: string;
  activeProvider: string;
  jevProviderStatus: "LIVE" | "NOT_CONFIGURED";
  offlineMode: boolean;
  close: () => void;
}

export interface CreateChatSessionOptions {
  dbPath?: string;
  fixturesDir?: string;
  allowedRoots?: string[];
  principal?: AuthPrincipal;
  credentialsOptions?: CredentialStoreOptions;
  runtime?: SecurityActionRuntime;
}

export interface ChatTurnResult {
  action:
    | "help"
    | "exit"
    | "status"
    | "chainbreak"
    | "judge"
    | "remediate"
    | "audit"
    | "scan-secrets"
    | "scan-headers"
    | "error";
  ok: boolean;
  mode: "LAB";
  offlineMode: boolean;
  productionTested: false;
  mergeAllowed: false;
  deployAllowed: false;
  summary: string;
  data?: unknown;
  error?: string;
}

function buildHelpText(ctx: ChatSessionContext): string {
  const label = ctx.offlineMode ? "LAB / OFFLINE MODE" : "LAB MODE (JEV LIVE)";
  return [
    `[${label}] Available Patch Cat deterministic security commands:`,
    `  status                          - Check SecurityActionEngine & JEV-as-a-Judge readiness`,
    `  chainbreak <fixtureId>          - Run ChainBreak reachability (${CANONICAL_FIXTURE_IDS.join(", ")})`,
    `  judge [analysisId]              - Run JEV-as-a-Judge advisory evaluation (uses last analysis if omitted)`,
    `  remediate [analysisId] [pathId] - Inspect minimal RemediationSpec (requiresHumanApproval=true)`,
    `  audit [path]                    - Run real local SAST + secret scanner within allowed workspace roots`,
    `  scan-secrets [path]             - Scan for hardcoded secrets (output masked/redacted)`,
    `  scan-headers <url>              - Inspect live HTTP security headers (IMDS blocked)`,
    `  exit | back                     - Return to menu / exit chat`,
  ].join("\n");
}

function resolveAllowedPath(targetPath: string, allowedRoots: string[]): string {
  const resolved = path.resolve(targetPath);
  let realTarget = resolved;
  try {
    realTarget = fs.realpathSync(resolved);
  } catch {
    // Non-existent path checked lexically against realRoot below
  }

  const allowed = allowedRoots.some((root) => {
    const absRoot = path.resolve(root);
    let realRoot = absRoot;
    try {
      realRoot = fs.realpathSync(absRoot);
    } catch {
      // Fallback to resolved root
    }
    const rel = path.relative(realRoot, realTarget);
    const lexicalRel = path.relative(absRoot, resolved);
    const withinReal = rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
    const withinLexical =
      lexicalRel === "" || (!lexicalRel.startsWith("..") && !path.isAbsolute(lexicalRel));
    return withinReal && withinLexical;
  });

  if (!allowed) {
    throw new Error(
      `FORBIDDEN: Target path '${targetPath}' resolves outside allowed workspace roots.`
    );
  }
  return resolved;
}

function makeResult(
  ctx: ChatSessionContext,
  partial: Omit<
    ChatTurnResult,
    "mode" | "offlineMode" | "productionTested" | "mergeAllowed" | "deployAllowed"
  >
): ChatTurnResult {
  return {
    ...partial,
    mode: "LAB",
    offlineMode: ctx.offlineMode,
    productionTested: false,
    mergeAllowed: false,
    deployAllowed: false,
  };
}

function modePrefix(ctx: ChatSessionContext): string {
  return ctx.offlineMode ? "LAB / OFFLINE" : "LAB / JEV-LIVE";
}

export function createChatSessionContext(
  options: CreateChatSessionOptions = {}
): ChatSessionContext {
  const dbPath = options.dbPath ?? process.env.SCRIPT_KITTY_DB_PATH ?? ":memory:";
  const ownsRuntime = options.runtime === undefined;
  const runtime =
    options.runtime ??
    createSecurityActionRuntime({
      name: "@script-kitty/cli-chat",
      version: "1.0.0",
      dbPath,
      fixturesDir: options.fixturesDir,
    });

  const principal: AuthPrincipal = options.principal ?? {
    principalId: process.env.SCRIPT_KITTY_PRINCIPAL_ID || "cli-chat-operator",
    tenantId: process.env.SCRIPT_KITTY_TENANT_ID || "payments-lab",
    roles: ["security-operator"],
    scopes: [
      "security:status",
      "security:analyze",
      "security:read",
      "security:judge",
      "security:remediate",
    ],
  };

  const allowedRoots =
    options.allowedRoots && options.allowedRoots.length > 0
      ? options.allowedRoots.map((r) => path.resolve(r))
      : [process.cwd()];

  let activeProvider = "offline";
  try {
    const creds = loadCredentials(options.credentialsOptions);
    activeProvider = creds.activeProvider;
  } catch {
    activeProvider = "offline";
  }

  const jevProviderStatus = resolveJevProviderStatus();
  const offlineMode = jevProviderStatus !== "LIVE";

  return {
    runtime,
    principal,
    allowedRoots,
    dbPath,
    activeProvider,
    jevProviderStatus,
    offlineMode,
    close: () => {
      if (ownsRuntime) {
        runtime.close();
      }
    },
  };
}

export async function processChatCommand(
  rawInput: string,
  ctx: ChatSessionContext
): Promise<ChatTurnResult> {
  const trimmed = rawInput.trim();
  const prefix = modePrefix(ctx);

  if (!trimmed) {
    return makeResult(ctx, {
      action: "help",
      ok: true,
      summary: buildHelpText(ctx),
    });
  }

  const tokens = trimmed.split(/\s+/);
  const cmd = tokens[0].toLowerCase();
  const lower = trimmed.toLowerCase();

  if (cmd === "exit" || cmd === "quit" || cmd === "back") {
    return makeResult(ctx, {
      action: "exit",
      ok: true,
      summary: `[${prefix}] Closing Patch Cat chat session.`,
    });
  }

  if (cmd === "help" || cmd === "?") {
    return makeResult(ctx, {
      action: "help",
      ok: true,
      summary: buildHelpText(ctx),
    });
  }

  const authCtx = {
    principal: ctx.principal,
    source: "cli-chat",
  };

  try {
    // 1. Direct `status`
    if (cmd === "status") {
      const statusRes = await ctx.runtime.engine.invoke<{
        service: string;
        version: string;
        mode: "LAB";
        productionTested: false;
        HARNESS2_EXPERIMENTS_ENABLED: false;
        mergeAllowed: false;
        deployAllowed: false;
        jevProviderStatus: "LIVE" | "NOT_CONFIGURED";
      }>("security.status", {}, authCtx);

      return makeResult(ctx, {
        action: "status",
        ok: true,
        summary: `[${prefix}] Engine ${statusRes.service} v${statusRes.version} READY | jevProviderStatus=${statusRes.jevProviderStatus} | productionTested=${statusRes.productionTested} | mergeAllowed=${statusRes.mergeAllowed} | deployAllowed=${statusRes.deployAllowed}.`,
        data: statusRes,
      });
    }

    // 2. Direct `chainbreak <fixtureId>`
    if (cmd === "chainbreak" || cmd === "analyze") {
      const fixtureId = tokens[1];
      if (!fixtureId) {
        return makeResult(ctx, {
          action: "error",
          ok: false,
          error: `Missing fixtureId. Allowlisted LAB fixtures: ${CANONICAL_FIXTURE_IDS.join(", ")}`,
          summary: `[${prefix}] Please specify an allowlisted fixtureId: ${CANONICAL_FIXTURE_IDS.join(", ")}.`,
        });
      }

      const cbRes = await ctx.runtime.engine.invoke<{
        analysisId: string;
        status: string;
        idempotentReplay: boolean;
        analysis: {
          fixtureId: string;
          paths: Array<{ pathId: string; status: string; violatedPolicyId: string }>;
          legitimateOperationsPreserved: boolean;
        };
      }>("security.chainbreak.analyze", { fixtureId }, authCtx);

      ctx.lastAnalysisId = cbRes.analysisId;
      ctx.lastPathId = cbRes.analysis.paths[0]?.pathId;

      const pathDesc = cbRes.analysis.paths[0]
        ? `${cbRes.analysis.paths[0].pathId} (${cbRes.analysis.paths[0].status}, policy=${cbRes.analysis.paths[0].violatedPolicyId})`
        : "0 violating paths";

      return makeResult(ctx, {
        action: "chainbreak",
        ok: true,
        summary: `[${prefix}] ChainBreak analyzed '${cbRes.analysis.fixtureId}' -> analysisId=${cbRes.analysisId}, status=${cbRes.status}, paths=${cbRes.analysis.paths.length} [${pathDesc}], productionTested=false, mergeAllowed=false, deployAllowed=false.`,
        data: cbRes,
      });
    }

    // 3. Direct `judge [analysisId]`
    if (cmd === "judge" || cmd === "adjudicate") {
      const analysisId = tokens[1] ?? ctx.lastAnalysisId;
      if (!analysisId) {
        return makeResult(ctx, {
          action: "error",
          ok: false,
          error: "No analysisId specified and no prior ChainBreak analysis in this session.",
          summary: `[${prefix}] Specify an analysisId or run 'chainbreak <fixtureId>' first.`,
        });
      }

      const judgeRes = await ctx.runtime.engine.invoke<{
        analysisId: string;
        adjudication: {
          evaluationId: string;
          status: string;
          decisionSource: string;
          providerStatus: string;
          p0DefinedByJevAlone: boolean;
          confidenceOrUncertainty: {
            thresholdCalibrated: boolean;
          };
          escalationReasons: string[];
        };
      }>("security.judge.evaluate", { analysisId }, authCtx);

      const adj = judgeRes.adjudication;
      return makeResult(ctx, {
        action: "judge",
        ok: true,
        summary: `[${prefix}] JEV-as-a-Judge evaluated '${analysisId}' -> status=${adj.status}, decisionSource=${adj.decisionSource} (${adj.providerStatus}), p0DefinedByJevAlone=${adj.p0DefinedByJevAlone}, thresholdCalibrated=${adj.confidenceOrUncertainty.thresholdCalibrated}${adj.escalationReasons.length > 0 ? `, reasons=[${adj.escalationReasons.join("; ")}]` : ""}.`,
        data: judgeRes,
      });
    }

    // 4. Direct `remediate [analysisId] [pathId]`
    if (cmd === "remediate" || cmd === "patch" || cmd === "fix") {
      let analysisId: string | undefined = tokens[1];
      let pathId: string | undefined = tokens[2];

      if (analysisId && !pathId && analysisId.startsWith("path-") && ctx.lastAnalysisId) {
        pathId = analysisId;
        analysisId = ctx.lastAnalysisId;
      } else {
        analysisId = analysisId ?? ctx.lastAnalysisId;
        pathId = pathId ?? ctx.lastPathId;
      }

      if (!analysisId) {
        return makeResult(ctx, {
          action: "error",
          ok: false,
          error: "No analysisId specified and no prior ChainBreak analysis in this session.",
          summary: `[${prefix}] Run 'chainbreak <fixtureId>' first or pass 'remediate <analysisId> [pathId]'.`,
        });
      }

      if (!pathId) {
        const ctxRes = await ctx.runtime.engine.invoke<{
          analysis: { paths?: Array<{ pathId: string }> };
        }>("security.chainbreak.get", { analysisId }, authCtx);
        pathId = ctxRes.analysis.paths?.[0]?.pathId;
      }

      if (!pathId) {
        return makeResult(ctx, {
          action: "remediate",
          ok: true,
          summary: `[${prefix}] Analysis '${analysisId}' has 0 violating attack paths; no remediation diff needed (requiresHumanApproval=true, autoApplyAllowed=false).`,
          data: {
            analysisId,
            pathsFound: 0,
            requiresHumanApproval: true,
            autoApplyAllowed: false,
          },
        });
      }

      const remRes = await ctx.runtime.engine.invoke<{
        analysisId: string;
        pathId: string;
        remediationSpec: {
          strategy?: string;
          summary?: string;
          actions?: Array<{ actionType: string; edgeId: string }>;
        };
        requiresHumanApproval: true;
        autoApplyAllowed: false;
      }>("security.remediation.spec", { analysisId, pathId }, authCtx);

      return makeResult(ctx, {
        action: "remediate",
        ok: true,
        summary: `[${prefix}] RemediationSpec for ${analysisId}/${pathId} -> strategy=${remRes.remediationSpec.strategy ?? "REMOVE_EDGE"}, requiresHumanApproval=${remRes.requiresHumanApproval}, autoApplyAllowed=${remRes.autoApplyAllowed}. ${remRes.remediationSpec.summary ?? ""}`.trim(),
        data: remRes,
      });
    }

    // 5. Direct `audit [path]` or `sast [path]`
    if (cmd === "audit" || cmd === "sast") {
      const target = tokens[1] ?? ".";
      const safeTarget = resolveAllowedPath(target, ctx.allowedRoots);
      const report = scanWorkspaceReal(safeTarget);
      return makeResult(ctx, {
        action: "audit",
        ok: true,
        summary: `[${prefix}] Scanned ${report.total_files_scanned} file(s) under '${safeTarget}': ${report.total_findings} finding(s) detected (secrets masked, LAB static inspection).`,
        data: report,
      });
    }

    // 6. Direct `scan-secrets [path]` or `secrets [path]`
    if (cmd === "scan-secrets" || cmd === "secrets") {
      const target = tokens[1] ?? ".";
      const safeTarget = resolveAllowedPath(target, ctx.allowedRoots);
      const report = scanWorkspaceReal(safeTarget);
      const secretFindings = report.findings.filter((f) => f.category.includes("Secret"));
      return makeResult(ctx, {
        action: "scan-secrets",
        ok: true,
        summary: `[${prefix}] Secret scan across ${report.total_files_scanned} file(s) found ${secretFindings.length} secret leak(s) (redacted).`,
        data: {
          status: report.status,
          scanned_path: report.scanned_path,
          total_files_scanned: report.total_files_scanned,
          secret_leaks_found: secretFindings.length,
          findings: secretFindings,
        },
      });
    }

    // 7. Direct `scan-headers <url>` or `headers <url>`
    if (cmd === "scan-headers" || cmd === "headers") {
      const targetUrl = tokens[1];
      if (!targetUrl) {
        return makeResult(ctx, {
          action: "error",
          ok: false,
          error: "Missing HTTP/HTTPS target URL.",
          summary: `[${prefix}] Usage: scan-headers <http://host:port/path>`,
        });
      }
      const hdrReport = await evaluateHttpHeadersDetailed(targetUrl);
      if (hdrReport.status === "BLOCKED") {
        return makeResult(ctx, {
          action: "error",
          ok: false,
          error: hdrReport.error ?? "HTTP target blocked",
          summary: `[${prefix}] Blocked HTTP header scan: ${hdrReport.error ?? "Target rejected"}.`,
          data: hdrReport,
        });
      }
      return makeResult(ctx, {
        action: "scan-headers",
        ok: true,
        summary: hdrReport.reachable
          ? `[${prefix}] HTTP ${hdrReport.status_code ?? 200} at ${targetUrl}: ${hdrReport.present_headers.length} present, ${hdrReport.missing_headers.length} missing security headers.`
          : `[${prefix}] Target ${targetUrl} unreachable (${hdrReport.error ?? "connection failed"}).`,
        data: hdrReport,
      });
    }

    // 8. Natural-language dispatch grounded in real engines (never static placeholder replies)
    const matchedFixture = CANONICAL_FIXTURE_IDS.find((id) =>
      lower.includes(id.toLowerCase())
    );
    if (matchedFixture) {
      return processChatCommand(`chainbreak ${matchedFixture}`, ctx);
    }

    const urlMatch = trimmed.match(/https?:\/\/[^\s]+/i);
    if (urlMatch) {
      return processChatCommand(`scan-headers ${urlMatch[0]}`, ctx);
    }

    const candidateFixtureToken = tokens.find((t) =>
      t.includes("/") && !t.startsWith(".") && !t.startsWith("http")
    );
    if (
      (lower.includes("chainbreak") || lower.includes("fixture")) &&
      candidateFixtureToken &&
      !isAllowedFixtureId(candidateFixtureToken)
    ) {
      return processChatCommand(`chainbreak ${candidateFixtureToken}`, ctx);
    }

    if (lower.includes("judge") || lower.includes("adjudicat")) {
      return processChatCommand("judge", ctx);
    }

    if (lower.includes("remediat") || lower.includes("patch") || lower.includes("fix")) {
      if (ctx.lastAnalysisId) {
        return processChatCommand("remediate", ctx);
      }
      return makeResult(ctx, {
        action: "status",
        ok: true,
        summary: `[${prefix}] No active ChainBreak analysis yet. Run 'chainbreak payments-lab/unsafe-rollout' then 'remediate', or run 'audit .' for local static remediation pointers.`,
      });
    }

    if (lower.includes("secret") || lower.includes("credential") || lower.includes("key")) {
      return processChatCommand(`scan-secrets ${ctx.allowedRoots[0] ?? "."}`, ctx);
    }

    if (
      lower.includes("audit") ||
      lower.includes("sast") ||
      lower.includes("vulnerability") ||
      lower.includes("scan")
    ) {
      return processChatCommand(`audit ${ctx.allowedRoots[0] ?? "."}`, ctx);
    }

    if (
      lower.includes("status") ||
      lower.includes("guardrail") ||
      lower.includes("jev") ||
      lower.includes("health")
    ) {
      return processChatCommand("status", ctx);
    }

    // Unrecognized query: dynamically check engine status & return live offline/LAB guidance
    const liveStatus = await ctx.runtime.engine.invoke<Record<string, unknown>>(
      "security.status",
      {},
      authCtx
    );
    return makeResult(ctx, {
      action: "help",
      ok: true,
      summary: `[${prefix}] Active SecurityActionEngine is READY (jevProviderStatus=${String(liveStatus.jevProviderStatus)}, productionTested=false).\n${buildHelpText(ctx)}`,
      data: liveStatus,
    });
  } catch (err) {
    const message =
      err instanceof ActionEngineError
        ? `${err.code}: ${err.publicMessage}`
        : err instanceof Error
          ? err.message
          : "Chat command failed";
    return makeResult(ctx, {
      action: "error",
      ok: false,
      error: message,
      summary: `[${prefix}] Error: ${message}`,
    });
  }
}

export async function runAgentChatSession(
  _lang = "en",
  options: CreateChatSessionOptions = {}
): Promise<void> {
  if (process.stdout.isTTY) {
    console.clear();
  }
  printBanner();

  const ctx = createChatSessionContext(options);

  console.log(
    `${ANSI_BOLD}${ANSI_PURPLE}======================================================================${ANSI_RESET}`
  );
  console.log(
    `${ANSI_BOLD}${ANSI_CYAN}SCRIPT KITTY PATCH CAT CHAT (${ctx.offlineMode ? "LAB / OFFLINE MODE" : "LAB MODE | JEV LIVE"} | Provider: ${ctx.activeProvider.toUpperCase()})${ANSI_RESET}`
  );
  if (ctx.offlineMode) {
    console.log(
      `${ANSI_YELLOW}[OFFLINE / LAB MODE] Running deterministic ChainBreak, local SAST/secret scanners, and JEV Mock fallback (productionTested=false).${ANSI_RESET}`
    );
  }
  console.log(
    `${ANSI_YELLOW}Commands: status | chainbreak <fixtureId> | judge [id] | remediate [id] [pathId] | audit [path] | scan-secrets [path] | scan-headers <url> | help | exit${ANSI_RESET}`
  );
  console.log(
    `${ANSI_BOLD}${ANSI_PURPLE}======================================================================${ANSI_RESET}\n`
  );

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (!settled) {
        settled = true;
        ctx.close();
        resolve();
      }
    };

    rl.on("close", finish);

    const askQuestion = () => {
      if (settled) return;
      rl.question(`${ANSI_BOLD}${ANSI_GREEN}User > ${ANSI_RESET}`, async (userInput) => {
        const result = await processChatCommand(userInput, ctx);
        console.log(
          `\n${ANSI_BOLD}${ANSI_CYAN}Detective Patch Cat [${result.offlineMode ? "LAB/OFFLINE" : "LAB"}]:${ANSI_RESET}`
        );
        console.log(`${ANSI_YELLOW}${result.summary}${ANSI_RESET}\n`);

        if (result.action === "exit") {
          rl.close();
          finish();
          return;
        }
        askQuestion();
      });
    };

    askQuestion();
  });
}
