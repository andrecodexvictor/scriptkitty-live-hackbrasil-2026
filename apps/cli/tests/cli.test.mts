/**
 * @file apps/cli/tests/cli.test.mts
 * @description Integration and unit tests for @script-kitty/cli:
 * - Encrypted credential store (AES-256-GCM + scrypt, backward-compatible migration, tamper detection, redaction)
 * - Real Detective Patch Cat chat engine backed by @script-kitty/security-actions + ChainBreak + JEV-judge
 * - Compiled CLI subcommands (--help, status, auth, chainbreak, judge, audit, scan-secrets, scan-headers)
 */

import * as assert from "node:assert/strict";
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  CredentialStoreError,
  isEncryptedCredentialsEnvelope,
  loadCredentials,
  maskSecret,
  migratePlaintextCredentials,
  redactCredentials,
  saveCredentials,
} from "../dist/credentials.js";
import {
  createChatSessionContext,
  processChatCommand,
} from "../dist/chat.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(APP_ROOT, "../..");
const CLI_ENTRY = path.join(APP_ROOT, "dist", "index.js");

interface CliExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function runCli(
  args: string[],
  options: { cwd?: string; env?: Record<string, string | undefined> } = {}
): Promise<CliExecResult> {
  return new Promise((resolve) => {
    const mergedEnv: NodeJS.ProcessEnv = {
      ...process.env,
      NO_COLOR: "1",
      ...options.env,
    };
    delete mergedEnv.TYPESAFE_API_KEY;

    execFile(
      process.execPath,
      [CLI_ENTRY, ...args],
      {
        cwd: options.cwd ?? REPO_ROOT,
        env: mergedEnv,
        timeout: 20_000,
        maxBuffer: 4 * 1024 * 1024,
      },
      (err, stdout, stderr) => {
        const code =
          err && typeof (err as NodeJS.ErrnoException & { code?: number | string }).code === "number"
            ? Number((err as { code?: number }).code)
            : err
              ? 1
              : 0;
        resolve({
          exitCode: code,
          stdout: String(stdout),
          stderr: String(stderr),
        });
      }
    );
  });
}

describe("@script-kitty/cli — Encrypted Credential Store", () => {
  it("encrypts credentials at rest with AES-256-GCM + scrypt and enforces tamper failure", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sk-cli-creds-"));
    const credPath = path.join(tmpDir, "credentials.json");
    const secretOpenAI = "sk-proj-TestSecretValue998877665544332211";
    const secretTypeSafe = "ts_live_TestKeySecretValue1234567890";

    try {
      const saved = saveCredentials(
        {
          activeProvider: "openai",
          openaiApiKey: secretOpenAI,
          typesafeApiKey: secretTypeSafe,
        },
        { filePath: credPath, passphrase: "unit-test-passphrase-123" }
      );

      assert.equal(saved.activeProvider, "openai");
      assert.equal(saved.openaiApiKey, secretOpenAI);

      // Raw disk contents must be encrypted envelope with zero plaintext secrets
      const rawDisk = fs.readFileSync(credPath, "utf-8");
      assert.equal(rawDisk.includes(secretOpenAI), false);
      assert.equal(rawDisk.includes(secretTypeSafe), false);

      const parsedDisk = JSON.parse(rawDisk) as unknown;
      assert.equal(isEncryptedCredentialsEnvelope(parsedDisk), true);

      if (process.platform !== "win32") {
        const mode = fs.statSync(credPath).mode & 0o777;
        assert.equal(mode, 0o600);
      }

      // Decrypt with matching passphrase
      const loaded = loadCredentials({
        filePath: credPath,
        passphrase: "unit-test-passphrase-123",
      });
      assert.equal(loaded.openaiApiKey, secretOpenAI);
      assert.equal(loaded.typesafeApiKey, secretTypeSafe);

      // Redaction must never expose raw secrets
      const redacted = redactCredentials(loaded);
      assert.equal(redacted.configuredKeys.openai, true);
      assert.equal(redacted.configuredKeys.typesafe_jev, true);
      assert.equal(redacted.maskedKeys.openaiApiKey, maskSecret(secretOpenAI));
      assert.equal(JSON.stringify(redacted).includes(secretOpenAI), false);
      assert.equal(JSON.stringify(redacted).includes(secretTypeSafe), false);
      assert.equal(maskSecret("short"), "***");

      // Fail closed on wrong passphrase
      assert.throws(
        () =>
          loadCredentials({
            filePath: credPath,
            passphrase: "wrong-passphrase-999",
          }),
        (err: unknown) =>
          err instanceof CredentialStoreError && err.code === "DECRYPTION_FAILED"
      );

      // Fail closed on tampered ciphertext
      const envelope = JSON.parse(rawDisk) as { ciphertext: string };
      const buf = Buffer.from(envelope.ciphertext, "base64");
      buf[0] = buf[0] ^ 0xff;
      envelope.ciphertext = buf.toString("base64");
      fs.writeFileSync(credPath, JSON.stringify(envelope), "utf-8");

      assert.throws(
        () =>
          loadCredentials({
            filePath: credPath,
            passphrase: "unit-test-passphrase-123",
          }),
        (err: unknown) =>
          err instanceof CredentialStoreError && err.code === "DECRYPTION_FAILED"
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("supports backward-compatible legacy plaintext JSON read and in-place AES migration", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sk-cli-legacy-"));
    const credPath = path.join(tmpDir, "credentials.json");
    const legacyKey = "sk-legacy-PlaintextSecretKey1234567890";

    try {
      fs.writeFileSync(
        credPath,
        JSON.stringify({
          activeProvider: "claude",
          anthropicApiKey: legacyKey,
        }),
        "utf-8"
      );

      const loaded = loadCredentials({
        filePath: credPath,
        passphrase: "migration-passphrase",
      });
      assert.equal(loaded.activeProvider, "claude");
      assert.equal(loaded.anthropicApiKey, legacyKey);

      const mig = migratePlaintextCredentials({
        filePath: credPath,
        passphrase: "migration-passphrase",
      });
      assert.equal(mig.migrated, true);

      const postRaw = fs.readFileSync(credPath, "utf-8");
      assert.equal(postRaw.includes(legacyKey), false);
      assert.equal(isEncryptedCredentialsEnvelope(JSON.parse(postRaw)), true);

      const reloaded = loadCredentials({
        filePath: credPath,
        passphrase: "migration-passphrase",
      });
      assert.equal(reloaded.anthropicApiKey, legacyKey);

      // Re-running migration on already encrypted store is a no-op
      const second = migratePlaintextCredentials({
        filePath: credPath,
        passphrase: "migration-passphrase",
      });
      assert.equal(second.migrated, false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe("@script-kitty/cli — Real Patch Cat Chat Engine", () => {
  it("invokes SecurityActionEngine, ChainBreak, JEV-as-a-Judge, and local scanners in LAB/OFFLINE mode", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sk-cli-chat-"));
    const sampleFile = path.join(tmpDir, "vuln.ts");
    const rawAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";
    fs.writeFileSync(
      sampleFile,
      `const k = "${rawAwsKey}";\nconst x = execSync("echo hi");\n`,
      "utf-8"
    );

    const prevTypeSafe = process.env.TYPESAFE_API_KEY;
    delete process.env.TYPESAFE_API_KEY;

    const ctx = createChatSessionContext({
      dbPath: ":memory:",
      allowedRoots: [tmpDir],
      credentialsOptions: {
        filePath: path.join(tmpDir, "nonexistent-creds.json"),
      },
    });

    try {
      assert.equal(ctx.offlineMode, true);

      const statusTurn = await processChatCommand("status", ctx);
      assert.equal(statusTurn.ok, true);
      assert.equal(statusTurn.action, "status");
      assert.equal(statusTurn.mode, "LAB");
      assert.equal(statusTurn.offlineMode, true);
      assert.equal(statusTurn.productionTested, false);
      assert.equal(statusTurn.mergeAllowed, false);
      assert.equal(statusTurn.deployAllowed, false);
      assert.match(statusTurn.summary, /LAB \/ OFFLINE/);

      // ChainBreak analysis
      const cbTurn = await processChatCommand(
        "chainbreak payments-lab/unsafe-rollout",
        ctx
      );
      assert.equal(cbTurn.ok, true);
      assert.equal(cbTurn.action, "chainbreak");
      assert.ok(ctx.lastAnalysisId?.startsWith("cb-"));
      assert.ok(ctx.lastPathId?.startsWith("path-"));
      assert.match(cbTurn.summary, /PATH_VALIDATED/);

      // JEV-as-a-Judge advisory evaluation on lastAnalysisId
      const judgeTurn = await processChatCommand("judge", ctx);
      assert.equal(judgeTurn.ok, true);
      assert.equal(judgeTurn.action, "judge");
      const judgeData = judgeTurn.data as {
        adjudication: {
          status: string;
          decisionSource: string;
          providerStatus: string;
          p0DefinedByJevAlone: boolean;
        };
      };
      assert.equal(judgeData.adjudication.status, "PENDING_REVIEW");
      assert.equal(judgeData.adjudication.decisionSource, "MOCK");
      assert.equal(judgeData.adjudication.providerStatus, "NOT_CONFIGURED");
      assert.equal(judgeData.adjudication.p0DefinedByJevAlone, false);

      // RemediationSpec inspection
      const remTurn = await processChatCommand("remediate", ctx);
      assert.equal(remTurn.ok, true);
      assert.equal(remTurn.action, "remediate");
      const remData = remTurn.data as {
        requiresHumanApproval: boolean;
        autoApplyAllowed: boolean;
        remediationSpec: { actions: Array<{ edgeId: string }> };
      };
      assert.equal(remData.requiresHumanApproval, true);
      assert.equal(remData.autoApplyAllowed, false);
      assert.equal(
        remData.remediationSpec.actions[0].edgeId,
        "e-rollout-exporter-read-pii"
      );

      // Local scanner with secret redaction
      const secretTurn = await processChatCommand(
        `scan-secrets ${tmpDir}`,
        ctx
      );
      assert.equal(secretTurn.ok, true);
      assert.equal(secretTurn.action, "scan-secrets");
      assert.equal(JSON.stringify(secretTurn.data).includes(rawAwsKey), false);
      const secretData = secretTurn.data as { secret_leaks_found: number };
      assert.equal(secretData.secret_leaks_found, 1);

      // Natural language prompt triggers real ChainBreak fixture (no canned responses)
      const nlTurn = await processChatCommand(
        "Please analyze payments-lab/remediated for violations",
        ctx
      );
      assert.equal(nlTurn.ok, true);
      assert.equal(nlTurn.action, "chainbreak");
      assert.match(nlTurn.summary, /0 violating paths|CLEAR/);

      // Fail-closed negative cases: disallowed fixture, traversal audit, missing analysis
      const badFix = await processChatCommand(
        "chainbreak ../../etc/passwd",
        ctx
      );
      assert.equal(badFix.ok, false);
      assert.match(badFix.error ?? "", /INPUT_INVALID/);

      const travAudit = await processChatCommand("audit ../../outside", ctx);
      assert.equal(travAudit.ok, false);
      assert.match(travAudit.error ?? "", /FORBIDDEN/);

      const missingJudge = await processChatCommand("judge cb-missing-000", ctx);
      assert.equal(missingJudge.ok, false);
      assert.match(missingJudge.error ?? "", /NOT_FOUND/);
    } finally {
      ctx.close();
      if (prevTypeSafe !== undefined) {
        process.env.TYPESAFE_API_KEY = prevTypeSafe;
      }
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe("@script-kitty/cli — Compiled CLI Subcommands (dist/index.js)", () => {
  it("prints complete --help and executes status, auth, chainbreak, judge, scan-secrets, audit, and scan-headers", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sk-cli-proc-"));
    const dbPath = path.join(tmpDir, "company-brain.sqlite");
    const credPath = path.join(tmpDir, "credentials.json");
    const scanDir = path.join(tmpDir, "workspace");
    const cleanDir = path.join(tmpDir, "clean");
    fs.mkdirSync(scanDir, { recursive: true });
    fs.mkdirSync(cleanDir, { recursive: true });

    const plantedToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";
    fs.writeFileSync(
      path.join(scanDir, "leak.ts"),
      `export const token = "${plantedToken}";\nexport function run(x: string) { return execSync(x); }\n`,
      "utf-8"
    );
    fs.writeFileSync(
      path.join(cleanDir, "safe.ts"),
      `export const token = process.env.GITHUB_TOKEN ?? "";\n`,
      "utf-8"
    );

    const httpServer = http.createServer((_req, res) => {
      res.writeHead(200, { "X-Frame-Options": "DENY" });
      res.end("ok");
    });
    await new Promise<void>((resolve) =>
      httpServer.listen(0, "127.0.0.1", resolve)
    );
    const addr = httpServer.address();
    assert.ok(addr && typeof addr === "object");
    const targetUrl = `http://127.0.0.1:${addr.port}/health`;

    const childEnv = {
      SCRIPT_KITTY_CREDENTIALS_FILE: credPath,
      SCRIPT_KITTY_MASTER_KEY: "cli-test-master-key",
    };

    try {
      // 1. --help includes all required commands
      const helpRes = await runCli(["--help"], { env: childEnv });
      assert.equal(helpRes.exitCode, 0);
      for (const expectedCmd of [
        "audit",
        "scan-secrets",
        "scan-headers",
        "auth",
        "chainbreak",
        "judge",
        "status",
      ]) {
        assert.ok(
          helpRes.stdout.includes(expectedCmd),
          `Expected --help to list command '${expectedCmd}'`
        );
      }

      // 2. status --json (read-only)
      const statusRes = await runCli(
        ["status", "--db", dbPath, "--json"],
        { env: childEnv }
      );
      assert.equal(statusRes.exitCode, 0);
      const statusJson = JSON.parse(statusRes.stdout) as {
        ok: boolean;
        mode: string;
        offlineMode: boolean;
        productionTested: boolean;
        mergeAllowed: boolean;
        deployAllowed: boolean;
        HARNESS2_EXPERIMENTS_ENABLED: boolean;
      };
      assert.equal(statusJson.ok, true);
      assert.equal(statusJson.mode, "LAB");
      assert.equal(statusJson.offlineMode, true);
      assert.equal(statusJson.productionTested, false);
      assert.equal(statusJson.mergeAllowed, false);
      assert.equal(statusJson.deployAllowed, false);
      assert.equal(statusJson.HARNESS2_EXPERIMENTS_ENABLED, false);

      // 3. auth writes encrypted envelope and never prints plaintext secret
      const testOpenAiKey = "sk-cli-TestKey99887766554433221100";
      const authRes = await runCli(
        [
          "auth",
          "--set-openai",
          testOpenAiKey,
          "--provider",
          "openai",
          "--json",
        ],
        { env: childEnv }
      );
      assert.equal(authRes.exitCode, 0);
      assert.equal(authRes.stdout.includes(testOpenAiKey), false);
      const authJson = JSON.parse(authRes.stdout) as {
        ok: boolean;
        updated: boolean;
        storage: { algorithm: string; kdf: string };
        active_provider: string;
        configured_keys: { openai: boolean };
        masked_keys: { openaiApiKey: string };
      };
      assert.equal(authJson.ok, true);
      assert.equal(authJson.updated, true);
      assert.equal(authJson.storage.algorithm, "aes-256-gcm");
      assert.equal(authJson.configured_keys.openai, true);
      assert.equal(authJson.masked_keys.openaiApiKey, maskSecret(testOpenAiKey));

      const rawCredFile = fs.readFileSync(credPath, "utf-8");
      assert.equal(rawCredFile.includes(testOpenAiKey), false);
      assert.equal(isEncryptedCredentialsEnvelope(JSON.parse(rawCredFile)), true);

      // 4. chainbreak <fixtureId> --remediate -> persists to SQLite DB
      const cbRes = await runCli(
        [
          "chainbreak",
          "payments-lab/unsafe-rollout",
          "--remediate",
          "--db",
          dbPath,
          "--json",
        ],
        { env: childEnv }
      );
      assert.equal(cbRes.exitCode, 0);
      const cbJson = JSON.parse(cbRes.stdout) as {
        ok: boolean;
        analysisId: string;
        status: string;
        mode: string;
        productionTested: boolean;
        analysis: {
          paths: Array<{ status: string }>;
        };
        remediation: {
          requiresHumanApproval: boolean;
          autoApplyAllowed: boolean;
        };
      };
      assert.equal(cbJson.ok, true);
      assert.ok(cbJson.analysisId.startsWith("cb-"));
      assert.equal(cbJson.status, "COMPLETED");
      assert.equal(cbJson.analysis.paths[0].status, "PATH_VALIDATED");
      assert.equal(cbJson.mode, "LAB");
      assert.equal(cbJson.productionTested, false);
      assert.equal(cbJson.remediation.requiresHumanApproval, true);
      assert.equal(cbJson.remediation.autoApplyAllowed, false);

      // 5. judge <analysisId> reads persisted analysis from same SQLite DB
      const judgeRes = await runCli(
        ["judge", cbJson.analysisId, "--db", dbPath, "--json"],
        { env: childEnv }
      );
      assert.equal(judgeRes.exitCode, 0);
      const judgeJson = JSON.parse(judgeRes.stdout) as {
        ok: boolean;
        analysisId: string;
        mode: string;
        productionTested: boolean;
        adjudication: {
          status: string;
          decisionSource: string;
          providerStatus: string;
          p0DefinedByJevAlone: boolean;
        };
      };
      assert.equal(judgeJson.ok, true);
      assert.equal(judgeJson.analysisId, cbJson.analysisId);
      assert.equal(judgeJson.mode, "LAB");
      assert.equal(judgeJson.productionTested, false);
      assert.equal(judgeJson.adjudication.status, "PENDING_REVIEW");
      assert.equal(judgeJson.adjudication.decisionSource, "MOCK");
      assert.equal(judgeJson.adjudication.providerStatus, "NOT_CONFIGURED");
      assert.equal(judgeJson.adjudication.p0DefinedByJevAlone, false);

      // 6. Negative chainbreak & judge tests fail closed cleanly
      const badCbRes = await runCli(
        ["chainbreak", "../../etc/passwd", "--db", dbPath, "--json"],
        { env: childEnv }
      );
      assert.notEqual(badCbRes.exitCode, 0);
      const badCbJson = JSON.parse(badCbRes.stdout) as { ok: boolean; error: { code: string } };
      assert.equal(badCbJson.ok, false);
      assert.equal(badCbJson.error.code, "INPUT_INVALID");

      const badJudgeRes = await runCli(
        ["judge", "cb-does-not-exist", "--db", dbPath, "--json"],
        { env: childEnv }
      );
      assert.notEqual(badJudgeRes.exitCode, 0);
      const badJudgeJson = JSON.parse(badJudgeRes.stdout) as { ok: boolean; error: { code: string } };
      assert.equal(badJudgeJson.ok, false);
      assert.equal(badJudgeJson.error.code, "NOT_FOUND");

      // 7. scan-secrets & audit detect and redact findings
      const secRes = await runCli(["scan-secrets", scanDir, "--json"], {
        env: childEnv,
      });
      assert.equal(secRes.exitCode, 0);
      assert.equal(secRes.stdout.includes(plantedToken), false);
      const secJson = JSON.parse(secRes.stdout) as { secret_leaks_found: number };
      assert.equal(secJson.secret_leaks_found, 1);

      const vulnAuditRes = await runCli(["audit", scanDir, "--json"], {
        env: childEnv,
      });
      assert.equal(vulnAuditRes.exitCode, 0);
      assert.equal(vulnAuditRes.stdout.includes(plantedToken), false);
      const vulnAuditJson = JSON.parse(vulnAuditRes.stdout) as {
        total_findings: number;
        findings: Array<{ category: string; description: string }>;
      };
      assert.ok(vulnAuditJson.total_findings >= 2);
      assert.ok(
        vulnAuditJson.findings.some((f) =>
          f.description.includes("Command Injection Risk")
        )
      );

      const cleanAuditRes = await runCli(["audit", cleanDir, "--json"], {
        env: childEnv,
      });
      assert.equal(cleanAuditRes.exitCode, 0);
      const cleanAuditJson = JSON.parse(cleanAuditRes.stdout) as {
        total_findings: number;
      };
      assert.equal(cleanAuditJson.total_findings, 0);

      // 8. scan-headers checks real HTTP server and blocks IMDS SSRF
      const hdrRes = await runCli(["scan-headers", targetUrl, "--json"], {
        env: childEnv,
      });
      assert.equal(hdrRes.exitCode, 0);
      const hdrJson = JSON.parse(hdrRes.stdout) as {
        reachable: boolean;
        present_headers: string[];
        missing_headers: string[];
      };
      assert.equal(hdrJson.reachable, true);
      assert.ok(hdrJson.present_headers.includes("X-Frame-Options"));
      assert.ok(hdrJson.missing_headers.includes("Strict-Transport-Security"));

      const imdsRes = await runCli(
        ["scan-headers", "http://169.254.169.254/latest/meta-data/", "--json"],
        { env: childEnv }
      );
      assert.notEqual(imdsRes.exitCode, 0);
      const imdsJson = JSON.parse(imdsRes.stdout) as { status: string };
      assert.equal(imdsJson.status, "BLOCKED");
    } finally {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("rejects encrypted credential envelopes whose kdfParams exceed safe scrypt upper bounds", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sk-cli-kdf-"));
    try {
      const credFile = path.join(tmpDir, "credentials.json");
      saveCredentials(
        { activeProvider: "openai", openaiApiKey: "sk-test-123456" },
        { filePath: credFile, passphrase: "cli-test-passphrase" }
      );
      const envelope = JSON.parse(fs.readFileSync(credFile, "utf8")) as Record<string, any>;

      for (const badParams of [
        { N: 131072, r: 8, p: 1, keyLen: 32 },
        { N: 16384, r: 32, p: 1, keyLen: 32 },
        { N: 16384, r: 8, p: 8, keyLen: 32 },
        { N: 16384, r: 0, p: 1, keyLen: 32 },
      ]) {
        const maliciousFile = path.join(tmpDir, "malicious.json");
        fs.writeFileSync(
          maliciousFile,
          JSON.stringify({ ...envelope, kdfParams: badParams }),
          "utf8"
        );
        assert.throws(
          () => loadCredentials({ filePath: maliciousFile, passphrase: "cli-test-passphrase" }),
          (err: unknown) => {
            assert.ok(err instanceof CredentialStoreError);
            assert.equal(err.code, "INVALID_ENVELOPE");
            return true;
          }
        );
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
