import { createLabApp, type LabAppInstance } from '../dist/index.js';

/**
 * Standalone Deterministic Reproducer: Command Injection (CWE-78)
 *
 * Exit Codes:
 *   1 = Vulnerability CONFIRMED (arbitrary command executed, output contains canary marker)
 *   0 = Exploit NEUTRALIZED (shell metacharacters rejected or executed safely without shell)
 *   2 = Unexpected execution error
 */
async function run(): Promise<void> {
  let app: LabAppInstance | null = null;
  let baseUrl = process.env.LAB_APP_URL;

  if (!baseUrl) {
    app = createLabApp({ port: 0 });
    const port = await app.start();
    baseUrl = `http://127.0.0.1:${port}`;
  }

  const cleanup = async () => {
    if (app) {
      await app.stop();
    }
  };

  try {
    const canaryMarker = 'SCRIPTKITTY_CMDI_CANARY_ECHO_CONFIRMED';
    // Cross-platform command injection payload using & echo
    const payload = `127.0.0.1 & echo ${canaryMarker}`;

    const res = await fetch(`${baseUrl}/api/diagnostics/ping`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: payload })
    });

    if (res.status !== 200) {
      console.error(`ERROR: Endpoint responded with HTTP ${res.status}: ${await res.text()}`);
      await cleanup();
      process.exit(2);
    }

    const data = (await res.json()) as { status: string; output?: string; error?: string };
    const outputText = data.output || data.error || '';

    if (outputText.includes(canaryMarker)) {
      console.log('VULNERABILITY_CONFIRMED: Command Injection (CWE-78) successfully executed arbitrary shell command.');
      console.log(`  Evidence: Canary marker "${canaryMarker}" found in ping diagnostic output.`);
      await cleanup();
      process.exit(1);
    } else if (res.status === 200 && (data.status === 'ERROR' || data.status === 'SUCCESS' || !outputText.includes(canaryMarker))) {
      console.log('EXPLOIT_NEUTRALIZED: Shell metacharacters were rejected or safely escaped.');
      await cleanup();
      process.exit(0);
    } else {
      console.error('ERROR: Unexpected ping diagnostic response:', data);
      await cleanup();
      process.exit(2);
    }
  } catch (err) {
    console.error('ERROR: Unexpected reproducer failure:', err);
    await cleanup();
    process.exit(2);
  }
}

run();
