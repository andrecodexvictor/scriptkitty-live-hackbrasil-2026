import { createLabApp, type LabAppInstance } from '../dist/index.js';
import assert from 'node:assert/strict';

async function runSearchEdgeCaseSuite() {
  console.log('=== Starting Search Endpoint Edge Case & Adversarial Stress Suite ===');
  const app = createLabApp({ port: 0 });
  const port = await app.start();
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`Lab App server listening at ${baseUrl}`);

  const testCases: { name: string; query: string; validate: (status: number, data: any, err?: any) => void }[] = [
    {
      name: '1. Standard ASCII search (Gateway)',
      query: 'Gateway',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 1);
        assert.equal(data[0].id, 101);
      }
    },
    {
      name: '2. Empty query string',
      query: '',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 3);
      }
    },
    {
      name: '3. Whitespace only',
      query: '     ',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 0);
      }
    },
    {
      name: '4. SQL wildcard percent sign (%)',
      query: '%',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 3, 'LIKE "%%%" matches all rows');
      }
    },
    {
      name: '5. SQL wildcard underscore sign (_)',
      query: '_',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 3, 'Matches rows with at least one character');
      }
    },
    {
      name: '6. Double quote (")',
      query: '"',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        console.log(`    Double quote parsed as literal within LIKE: HTTP ${status}`);
      }
    },
    {
      name: '7. Standalone single quote (\') — parsed by SQLite as modulo operator',
      query: "'",
      validate: (status, data) => {
        // Because query is interpolated into two LIKE clauses separated by OR:
        // LIKE '%' % ' OR description LIKE ' % '%'
        // The % characters act as binary modulo operators between strings, yielding valid syntax!
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        console.log(`    Single quote successfully handled via SQLite modulo parsing: HTTP ${status}`);
      }
    },
    {
      name: '8. Unbalanced single quote breaking syntax (test\')',
      query: "test'",
      validate: (status, data) => {
        assert.equal(status, 500, 'Syntax error caught by top-level catch handler');
        assert.equal(data.error, 'Internal Server Error');
        assert.ok(data.message.includes('syntax error'), `Expected syntax error, got: ${data.message}`);
        console.log(`    Syntax error handled gracefully: ${data.message}`);
      }
    },
    {
      name: '9. Balanced single quotes (\'\')',
      query: "''",
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
      }
    },
    {
      name: '10. Null byte (%00) — C string termination caught gracefully via 500',
      query: 'Gate\0way',
      validate: (status, data) => {
        assert.equal(status, 500);
        assert.equal(data.error, 'Internal Server Error');
        assert.ok(data.message.includes('unrecognized token') || data.message.includes('syntax error'));
        console.log(`    Null byte error handled gracefully: ${data.message}`);
      }
    },
    {
      name: '11. Unicode Cyrillic (Тестирование)',
      query: 'Тестирование',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 0);
      }
    },
    {
      name: '12. Unicode CJK Chinese/Japanese (漏洞测试)',
      query: '漏洞测试',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 0);
      }
    },
    {
      name: '13. Unicode Emojis (🛡️🔍💻🐱)',
      query: '🛡️🔍💻🐱',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 0);
      }
    },
    {
      name: '14. Right-to-Left Arabic text (اختبار الأمان)',
      query: 'اختبار الأمان',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 0);
      }
    },
    {
      name: '15. Zero-width spaces & control characters',
      query: 'Gate\u200B\u200Cway\uFEFF',
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
      }
    },
    {
      name: '16. Boolean tautology bypass (nomatch\' OR 1=1 --)',
      query: "nomatch' OR 1=1 --",
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 3, 'Tautology dumped all records');
      }
    },
    {
      name: '17. Multi-statement attempt (\'; DROP TABLE incidents; --)',
      query: "'; DROP TABLE incidents; --",
      validate: (status, data) => {
        // SQLite prepare_v2 only prepares the first statement; remainder is ignored safely
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
      }
    },
    {
      name: '18. Large query payload within HTTP header limits (8 KB string)',
      query: 'A'.repeat(8192),
      validate: (status, data) => {
        assert.equal(status, 200);
        assert.ok(Array.isArray(data));
        assert.equal(data.length, 0);
      }
    },
    {
      name: '19. Header overflow threshold query (17 KB string) -> RFC 6585 HTTP 431',
      query: 'B'.repeat(17000),
      validate: (status, data) => {
        assert.equal(status, 431, 'Node http parser correctly returns 431 Request Header Fields Too Large');
        console.log(`    HTTP 431 header boundary protection verified: status ${status}`);
      }
    },
    {
      name: '20. Massive DoS flood query (64 KB string) -> Connection Reset Protection',
      query: 'C'.repeat(65536),
      validate: (status, data, err) => {
        // Node's HTTP parser drops connection with ECONNRESET when request line grossly exceeds limits
        assert.ok(status === 431 || err?.cause?.code === 'ECONNRESET' || err?.message?.includes('fetch failed'));
        console.log(`    DoS connection drop protection verified: ${err ? err.cause?.code || err.message : `HTTP ${status}`}`);
      }
    },
    {
      name: '21. Special characters string: `~!@#$%^&*()-_=+[]{}|;:,.<>?/',
      query: '`~!@#$%^&*()-_=+[]{}|;:,.<>?/',
      validate: (status, data) => {
        assert.ok(status === 200 || status === 500);
        console.log(`    Special symbols result: HTTP ${status}`);
      }
    }
  ];

  let passed = 0;
  for (const tc of testCases) {
    let status = 0;
    let data: any = null;
    let caughtErr: any = null;

    try {
      const url = `${baseUrl}/api/incidents/search?q=${encodeURIComponent(tc.query)}`;
      const res = await fetch(url);
      status = res.status;
      data = await res.json().catch(() => ({}));
    } catch (err: any) {
      caughtErr = err;
    }

    try {
      tc.validate(status, data, caughtErr);
      console.log(`PASS: ${tc.name}`);
      passed++;
    } catch (err: any) {
      console.error(`FAIL: ${tc.name} -> ${err.message}`);
      throw err;
    }
  }

  // Ensure DB table was NOT destroyed by stacked query test
  const verifyRes = await fetch(`${baseUrl}/api/incidents/search?q=`);
  assert.equal(verifyRes.status, 200);
  const verifyData = (await verifyRes.json()) as any[];
  assert.equal(verifyData.length, 3, 'Database incidents table still has all 3 records intact');
  console.log('PASS: Database integrity verified — table incidents remained intact.');

  await app.stop();
  console.log(`\nALL ${passed} SEARCH EDGE CASE STRESS TESTS COMPLETED SUCCESSFULLY.`);
}

runSearchEdgeCaseSuite().catch((err) => {
  console.error('SEARCH STRESS TEST FAILED:', err);
  process.exit(1);
});
