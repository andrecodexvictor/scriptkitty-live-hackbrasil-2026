#!/usr/bin/env node

import * as fs from "node:fs";
import * as path from "node:path";
import { Command } from "commander";
import {
  ANSI_BOLD,
  ANSI_CYAN,
  ANSI_GREEN,
  ANSI_RED,
  ANSI_RESET,
  ANSI_YELLOW,
  printBanner,
} from "./banner.js";
import { getTranslation } from "./i18n.js";
import {
  loadCredentials,
  redactCredentials,
  resolveCredentialsFilePath,
  saveCredentials,
  type AIProviderName,
  type AICredentials,
} from "./credentials.js";
import { runInteractiveMenu } from "./interactive.js";
import {
  evaluateHttpHeadersDetailed,
  scanWorkspaceReal,
} from "./real_scanner.js";
import {
  ActionEngineError,
  createSecurityActionRuntime,
  type AuthPrincipal,
} from "../../../packages/security-actions/dist/index.js";

const VALID_PROVIDERS: ReadonlySet<AIProviderName> = new Set([
  "openai",
  "google",
  "nvidia",
  "openrouter",
  "claude",
  "grok",
  "codex",
]);

function buildCliPrincipal(tenantId?: string): AuthPrincipal {
  const effectiveTenant =
    tenantId?.trim() || process.env.SCRIPT_KITTY_TENANT_ID?.trim() || "payments-lab";
  return {
    principalId: process.env.SCRIPT_KITTY_PRINCIPAL_ID?.trim() || "cli-operator",
    tenantId: effectiveTenant,
    roles: ["security-operator"],
    scopes: [
      "security:status",
      "security:analyze",
      "security:read",
      "security:judge",
      "security:remediate",
    ],
  };
}

function resolveDefaultDbPath(explicitDb?: string, readOnly = false): string {
  if (explicitDb && explicitDb.trim().length > 0) {
    return explicitDb.trim();
  }
  const envDb = process.env.SCRIPT_KITTY_DB_PATH?.trim();
  if (envDb) {
    return envDb;
  }
  const defaultFile = path.resolve(".context", "runtime", "company-brain.sqlite");
  if (readOnly && !fs.existsSync(defaultFile)) {
    return ":memory:";
  }
  return defaultFile;
}

function printCommandError(err: unknown, asJson: boolean): void {
  const code =
    err instanceof ActionEngineError
      ? err.code
      : "CLI_EXECUTION_ERROR";
  const message =
    err instanceof ActionEngineError
      ? err.publicMessage
      : err instanceof Error
        ? err.message
        : String(err);

  if (asJson) {
    console.log(
      JSON.stringify(
        {
          ok: false,
          mode: "LAB",
          error: {
            code,
            message,
          },
        },
        null,
        2
      )
    );
  } else {
    console.error(`${ANSI_BOLD}${ANSI_RED}[ERROR] ${code}: ${message}${ANSI_RESET}`);
  }
  process.exitCode = 1;
}

const program = new Command();

program
  .name("script-kitty")
  .description(
    "Script Kitty — Your Patch Cat: Enterprise Security Engine, ChainBreak LAB & JEV-as-a-Judge CLI"
  )
  .version("1.0.0")
  .option("-l, --lang <language>", "Language configuration (en, pt, es)", "en")
  .action(async (options: { lang?: string }) => {
    await runInteractiveMenu(options.lang || "en");
  });

program
  .command("audit")
  .description(
    "Execute local static security audit across SAST patterns and hardcoded secret leaks (secret snippets masked)"
  )
  .argument("[path]", "Target workspace path to audit", ".")
  .option("-l, --lang <language>", "Language configuration (en, pt, es)", "en")
  .option("--json", "Emit machine-readable JSON output only", false)
  .action((pathArg: string, options: { lang?: string; json?: boolean }) => {
    const lang = options.lang || program.opts().lang || "en";
    const t = getTranslation(lang);
    const asJson = Boolean(options.json);

    let activeProvider = "offline";
    try {
      activeProvider = loadCredentials().activeProvider;
    } catch {
      activeProvider = "offline";
    }

    const report = scanWorkspaceReal(pathArg);

    if (asJson) {
      console.log(
        JSON.stringify(
          {
            ...report,
            mode: "LAB",
            offlineMode: true,
            activeProvider,
          },
          null,
          2
        )
      );
      return;
    }

    printBanner();
    console.log(
      `${ANSI_BOLD}${ANSI_CYAN}[AI Engine Status]: Active Provider -> ${activeProvider.toUpperCase()} (LAB Local Scanner)${ANSI_RESET}`
    );
    console.log(`${ANSI_BOLD}${ANSI_GREEN}${t.auditStart} '${pathArg}'...${ANSI_RESET}\n`);
    console.log(`Total Files Analyzed: ${report.total_files_scanned}`);
    console.log(`Total Real Findings Detected: ${report.total_findings}\n`);

    if (report.total_findings > 0) {
      report.findings.forEach((finding, idx) => {
        console.log(
          `${ANSI_BOLD}${ANSI_YELLOW}[Finding ${idx + 1}/${report.total_findings}] ${finding.finding_id} (${finding.severity})${ANSI_RESET}`
        );
        console.log(`   File: ${finding.file_path}:${finding.line_number}`);
        console.log(`   Snippet: ${finding.snippet}`);
        console.log(`   Remediation: ${finding.remediation}\n`);
      });
    } else {
      console.log(`${ANSI_BOLD}${ANSI_GREEN}${t.allClean}${ANSI_RESET}\n`);
    }

    console.log(`${ANSI_BOLD}${ANSI_GREEN}${t.auditComplete}${ANSI_RESET}\n`);
  });

program
  .command("scan-secrets")
  .description("Scan codebase for hardcoded credentials, API keys, and private tokens (redacted output)")
  .argument("<path>", "Directory or file path to scan")
  .option("--json", "Emit machine-readable JSON output only", false)
  .action((pathArg: string, options: { json?: boolean }) => {
    const asJson = Boolean(options.json);
    const report = scanWorkspaceReal(pathArg);
    const secretFindings = report.findings.filter((f) =>
      f.category.includes("Secret")
    );
    const payload = {
      status: "COMPLETED" as const,
      mode: "LAB" as const,
      scanned_path: report.scanned_path,
      total_files_scanned: report.total_files_scanned,
      secret_leaks_found: secretFindings.length,
      findings: secretFindings,
    };

    if (!asJson) {
      printBanner();
      console.log(`\n[Real Secret Scanner] Scanning path: ${pathArg}...`);
    }
    console.log(JSON.stringify(payload, null, 2));
  });

program
  .command("scan-headers")
  .description("Evaluate HTTP security headers (HSTS, CSP, X-Frame-Options) of an HTTP/HTTPS endpoint")
  .argument("<target>", "HTTP/HTTPS target URL")
  .option("--json", "Emit machine-readable JSON output only", false)
  .action(async (target: string, options: { json?: boolean }) => {
    const asJson = Boolean(options.json);
    if (!asJson) {
      printBanner();
      console.log(`\n[Real Header Scanner] Evaluating HTTP security headers for ${target}...`);
    }
    const report = await evaluateHttpHeadersDetailed(target);
    if (report.status === "BLOCKED") {
      process.exitCode = 1;
    }
    console.log(JSON.stringify(report, null, 2));
  });

program
  .command("auth")
  .description(
    "Configure encrypted-at-rest AI Provider API Keys (AES-256-GCM + scrypt) with zero raw secret output"
  )
  .option("--set-openai <key>", "Set OpenAI API Key")
  .option("--set-google <key>", "Set Google Gemini API Key")
  .option("--set-nvidia <key>", "Set NVIDIA NIM API Key")
  .option("--set-openrouter <key>", "Set OpenRouter API Key")
  .option("--set-claude <key>", "Set Anthropic Claude API Key")
  .option("--set-grok <key>", "Set xAI Grok API Key")
  .option("--set-codex-token <token>", "Set ChatGPT / Codex Subscription Access Token")
  .option("--set-typesafe <key>", "Set TypeSafe JEV API Key")
  .option(
    "--provider <name>",
    "Select active AI Provider (openai, google, nvidia, openrouter, claude, grok, codex)"
  )
  .option("--file <path>", "Custom encrypted credentials file path")
  .option("--json", "Emit machine-readable JSON output only", false)
  .action(
    (options: {
      setOpenai?: string;
      setGoogle?: string;
      setNvidia?: string;
      setOpenrouter?: string;
      setClaude?: string;
      setGrok?: string;
      setCodexToken?: string;
      setTypesafe?: string;
      provider?: string;
      file?: string;
      json?: boolean;
    }) => {
      const asJson = Boolean(options.json);
      const storeOptions = options.file ? { filePath: options.file } : undefined;
      const targetFile = resolveCredentialsFilePath(storeOptions);

      try {
        if (options.provider && !VALID_PROVIDERS.has(options.provider as AIProviderName)) {
          throw new Error(
            `Invalid provider '${options.provider}'. Allowed: ${Array.from(VALID_PROVIDERS).join(", ")}`
          );
        }

        const updates: Partial<AICredentials> = {};
        if (options.setOpenai) updates.openaiApiKey = options.setOpenai;
        if (options.setGoogle) updates.googleApiKey = options.setGoogle;
        if (options.setNvidia) updates.nvidiaApiKey = options.setNvidia;
        if (options.setOpenrouter) updates.openrouterApiKey = options.setOpenrouter;
        if (options.setClaude) updates.anthropicApiKey = options.setClaude;
        if (options.setGrok) updates.grokApiKey = options.setGrok;
        if (options.setCodexToken) updates.codexSubscriptionToken = options.setCodexToken;
        if (options.setTypesafe) updates.typesafeApiKey = options.setTypesafe;
        if (options.provider) updates.activeProvider = options.provider as AIProviderName;

        const hasMutations = Object.keys(updates).length > 0;
        const creds = hasMutations
          ? saveCredentials(updates, storeOptions)
          : loadCredentials(storeOptions);
        const redacted = redactCredentials(creds);

        const output = {
          ok: true,
          updated: hasMutations,
          storage: {
            algorithm: "aes-256-gcm",
            kdf: "scrypt",
            filePath: targetFile,
          },
          active_provider: redacted.activeProvider,
          configured_keys: redacted.configuredKeys,
          masked_keys: redacted.maskedKeys,
        };

        if (!asJson) {
          printBanner();
          console.log(
            `${ANSI_BOLD}${ANSI_GREEN}AI Credentials configuration ${hasMutations ? "encrypted & saved (AES-256-GCM)" : "inspected (read-only)"}:${ANSI_RESET}\n`
          );
        }
        console.log(JSON.stringify(output, null, 2));
      } catch (err) {
        printCommandError(err, asJson);
      }
    }
  );

program
  .command("chainbreak")
  .description("Run deterministic ChainBreak LAB policy-graph analysis on an allowlisted fixture")
  .argument("<fixtureId>", "Allowlisted ChainBreak fixture ID (e.g. payments-lab/unsafe-rollout)")
  .option("--policy-version <version>", "Expected policy version pin")
  .option("--tenant <tenantId>", "Tenant scope ID", "payments-lab")
  .option("--db <path>", "Path to CompanyBrainStore SQLite DB (or ':memory:')")
  .option("--remediate", "Also fetch minimal RemediationSpec for primary violating path", false)
  .option("--json", "Emit machine-readable JSON output only", false)
  .action(
    async (
      fixtureId: string,
      options: {
        policyVersion?: string;
        tenant?: string;
        db?: string;
        remediate?: boolean;
        json?: boolean;
      }
    ) => {
      const asJson = Boolean(options.json);
      const dbPath = resolveDefaultDbPath(options.db, false);
      const principal = buildCliPrincipal(options.tenant);
      const runtime = createSecurityActionRuntime({
        name: "@script-kitty/cli",
        version: "1.0.0",
        dbPath,
      });

      try {
        const result = await runtime.engine.invoke<{
          analysisId: string;
          status: string;
          idempotentReplay: boolean;
          stored: true;
          analysis: {
            fixtureId: string;
            inputSha256: string;
            paths: Array<{ pathId: string; status: string; violatedPolicyId: string }>;
            legitimateOperationsPreserved: boolean;
          };
          evidence: unknown[];
          mode: "LAB";
          productionTested: false;
          mergeAllowed: false;
          deployAllowed: false;
        }>(
          "security.chainbreak.analyze",
          {
            fixtureId,
            ...(options.policyVersion ? { policyVersion: options.policyVersion } : {}),
          },
          { principal, source: "cli" }
        );

        let remediation: unknown = undefined;
        if (options.remediate && result.analysis.paths.length > 0) {
          remediation = await runtime.engine.invoke(
            "security.remediation.spec",
            {
              analysisId: result.analysisId,
              pathId: result.analysis.paths[0].pathId,
            },
            { principal, source: "cli" }
          );
        }

        const payload = {
          ok: true,
          dbPath,
          tenantId: principal.tenantId,
          ...result,
          ...(remediation !== undefined ? { remediation } : {}),
        };

        if (asJson) {
          console.log(JSON.stringify(payload, null, 2));
          return;
        }

        printBanner();
        console.log(
          `${ANSI_BOLD}${ANSI_CYAN}[ChainBreak LAB Analysis] mode=${result.mode} | productionTested=${result.productionTested} | mergeAllowed=${result.mergeAllowed} | deployAllowed=${result.deployAllowed}${ANSI_RESET}`
        );
        console.log(`Analysis ID : ${result.analysisId}`);
        console.log(`Fixture     : ${result.analysis.fixtureId}`);
        console.log(`Status      : ${result.status}`);
        console.log(`Input SHA256: ${result.analysis.inputSha256}`);
        console.log(`Attack Paths: ${result.analysis.paths.length}`);
        for (const p of result.analysis.paths) {
          console.log(`  - ${p.pathId}: status=${p.status} policy=${p.violatedPolicyId}`);
        }
        console.log(`DB Persisted: ${dbPath}\n`);
      } catch (err) {
        printCommandError(err, asJson);
      } finally {
        runtime.close();
      }
    }
  );

program
  .command("judge")
  .description("Evaluate a persisted ChainBreak analysis with JEV-as-a-Judge advisory verification")
  .argument("<analysisId>", "Persisted ChainBreak analysisId (e.g. cb-...)")
  .option("--expected-sha256 <hex>", "Expected 64-char SHA-256 input hash for integrity check")
  .option("--model <model>", "Override TypeSafe JEV model identifier")
  .option("--tenant <tenantId>", "Tenant scope ID", "payments-lab")
  .option("--db <path>", "Path to CompanyBrainStore SQLite DB")
  .option("--json", "Emit machine-readable JSON output only", false)
  .action(
    async (
      analysisId: string,
      options: {
        expectedSha256?: string;
        model?: string;
        tenant?: string;
        db?: string;
        json?: boolean;
      }
    ) => {
      const asJson = Boolean(options.json);
      const dbPath = resolveDefaultDbPath(options.db, false);
      const principal = buildCliPrincipal(options.tenant);
      const runtime = createSecurityActionRuntime({
        name: "@script-kitty/cli",
        version: "1.0.0",
        dbPath,
      });

      try {
        const result = await runtime.engine.invoke<{
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
          mode: "LAB";
          productionTested: false;
          mergeAllowed: false;
          deployAllowed: false;
        }>(
          "security.judge.evaluate",
          {
            analysisId,
            ...(options.expectedSha256 ? { expectedInputSha256: options.expectedSha256 } : {}),
            ...(options.model ? { model: options.model } : {}),
          },
          { principal, source: "cli" }
        );

        const payload = {
          ok: true,
          dbPath,
          tenantId: principal.tenantId,
          ...result,
        };

        if (asJson) {
          console.log(JSON.stringify(payload, null, 2));
          return;
        }

        printBanner();
        console.log(
          `${ANSI_BOLD}${ANSI_CYAN}[JEV-as-a-Judge LAB] mode=${result.mode} | productionTested=${result.productionTested} | mergeAllowed=${result.mergeAllowed} | deployAllowed=${result.deployAllowed}${ANSI_RESET}`
        );
        console.log(`Analysis ID         : ${result.analysisId}`);
        console.log(`Evaluation ID       : ${result.adjudication.evaluationId}`);
        console.log(`Verdict Status      : ${result.adjudication.status}`);
        console.log(
          `Provider            : ${result.adjudication.decisionSource} (${result.adjudication.providerStatus})`
        );
        console.log(`p0DefinedByJevAlone : ${result.adjudication.p0DefinedByJevAlone}`);
        if (result.adjudication.escalationReasons.length > 0) {
          console.log(`Escalation Reasons  : ${result.adjudication.escalationReasons.join("; ")}`);
        }
        console.log("");
      } catch (err) {
        printCommandError(err, asJson);
      } finally {
        runtime.close();
      }
    }
  );

program
  .command("status")
  .description("Report PatchCat Live engine readiness, LAB boundaries, JEV status, and redacted CLI auth status")
  .option("--tenant <tenantId>", "Tenant scope ID", "payments-lab")
  .option("--db <path>", "Path to CompanyBrainStore SQLite DB")
  .option("--json", "Emit machine-readable JSON output only", false)
  .action(
    async (options: {
      tenant?: string;
      db?: string;
      json?: boolean;
    }) => {
      const asJson = Boolean(options.json);
      const dbPath = resolveDefaultDbPath(options.db, true);
      const principal = buildCliPrincipal(options.tenant);
      const runtime = createSecurityActionRuntime({
        name: "@script-kitty/cli",
        version: "1.0.0",
        dbPath,
      });

      try {
        const statusRes = await runtime.engine.invoke<{
          service: string;
          version: string;
          mode: "LAB";
          productionTested: false;
          HARNESS2_EXPERIMENTS_ENABLED: false;
          mergeAllowed: false;
          deployAllowed: false;
          jevProviderStatus: "LIVE" | "NOT_CONFIGURED";
          components: Record<string, unknown>;
          adapters: Record<string, unknown>;
          timestamp: string;
        }>("security.status", {}, { principal, source: "cli" });

        let credentialsStatus: unknown;
        try {
          credentialsStatus = {
            status: "OK",
            filePath: resolveCredentialsFilePath(),
            ...redactCredentials(loadCredentials()),
          };
        } catch (err) {
          credentialsStatus = {
            status: "ERROR",
            filePath: resolveCredentialsFilePath(),
            error: err instanceof Error ? err.message : "Failed to load credentials",
          };
        }

        const payload = {
          ok: true,
          offlineMode: statusRes.jevProviderStatus !== "LIVE",
          dbPath,
          ...statusRes,
          credentials: credentialsStatus,
        };

        if (asJson) {
          console.log(JSON.stringify(payload, null, 2));
          return;
        }

        printBanner();
        console.log(
          `${ANSI_BOLD}${ANSI_CYAN}[PatchCat Live Status] ${statusRes.service} v${statusRes.version} (${statusRes.mode}${statusRes.jevProviderStatus === "NOT_CONFIGURED" ? " / OFFLINE" : ""})${ANSI_RESET}`
        );
        console.log(`JEV Provider Status : ${statusRes.jevProviderStatus}`);
        console.log(`productionTested    : ${statusRes.productionTested}`);
        console.log(`HARNESS2_EXPERIMENTS: ${statusRes.HARNESS2_EXPERIMENTS_ENABLED}`);
        console.log(`mergeAllowed        : ${statusRes.mergeAllowed}`);
        console.log(`deployAllowed       : ${statusRes.deployAllowed}`);
        console.log(`Credentials Store   : ${resolveCredentialsFilePath()} (encrypted AES-256-GCM)`);
        console.log("");
      } catch (err) {
        printCommandError(err, asJson);
      } finally {
        runtime.close();
      }
    }
  );

await program.parseAsync(process.argv);
