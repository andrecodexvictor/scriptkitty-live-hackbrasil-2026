import { createLabApp, type LabAppInstance } from '../dist/index.js';

/**
 * Standalone Deterministic Reproducer: Broken Access Control / IDOR (CWE-639 / CWE-284)
 *
 * Exit Codes:
 *   1 = Vulnerability CONFIRMED (unauthorized cross-tenant access succeeded with HTTP 200)
 *   0 = Exploit NEUTRALIZED (access denied with HTTP 403 Forbidden)
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
    // Alice (User 2) attempts to access Bob's (User 3) restricted security report 102
    const aliceUserId = '2';
    const bobRestrictedReportId = 102;

    const res = await fetch(`${baseUrl}/api/reports/${bobRestrictedReportId}`, {
      method: 'GET',
      headers: {
        'x-user-id': aliceUserId
      }
    });

    if (res.status === 200) {
      const data = await res.json();
      console.log('VULNERABILITY_CONFIRMED: Broken Access Control / IDOR (CWE-639) allowed cross-tenant access.');
      console.log(`  Evidence: User ${aliceUserId} successfully fetched Report ${bobRestrictedReportId} with HTTP 200.`);
      console.log(`  Report Target: ${data.system_target}, Classification: ${data.classification}`);
      await cleanup();
      process.exit(1);
    } else if (res.status === 403) {
      console.log('EXPLOIT_NEUTRALIZED: Access control enforced. Request correctly denied with HTTP 403 Forbidden.');
      await cleanup();
      process.exit(0);
    } else {
      console.error(`ERROR: Unexpected HTTP status received: ${res.status}`);
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
