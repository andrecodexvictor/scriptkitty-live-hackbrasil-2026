import { createLabApp, type LabAppInstance } from '../dist/index.js';
import assert from 'node:assert/strict';

async function runRoutesEdgeCaseSuite() {
  console.log('=== Starting Diagnostics & Reports Edge Case Suite ===');
  const app = createLabApp({ port: 0 });
  const port = await app.start();
  const baseUrl = `http://127.0.0.1:${port}`;

  // 1. Diagnostics edge cases
  console.log('--- Testing Diagnostics Endpoint Edge Cases ---');

  // 1.1 Empty body
  const dEmpty = await fetch(`${baseUrl}/api/diagnostics/ping`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: ''
  });
  assert.equal(dEmpty.status, 400);
  const dEmptyData = await dEmpty.json();
  assert.equal(dEmptyData.error, 'Missing host parameter');
  console.log('PASS: Diagnostics empty body returns 400 Missing host parameter');

  // 1.2 Missing host in JSON
  const dMissingHost = await fetch(`${baseUrl}/api/diagnostics/ping`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ wrongKey: 'val' })
  });
  assert.equal(dMissingHost.status, 400);
  console.log('PASS: Diagnostics JSON without host key returns 400');

  // 1.3 Non-JSON raw string body fallback
  const dRawString = await fetch(`${baseUrl}/api/diagnostics/ping`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: '127.0.0.1'
  });
  assert.equal(dRawString.status, 200);
  const dRawData = await dRawString.json();
  assert.equal(dRawData.status, 'SUCCESS');
  console.log('PASS: Diagnostics non-JSON string body handled gracefully via fallback');

  // 2. Reports edge cases
  console.log('--- Testing Reports Endpoint Edge Cases ---');

  // 2.1 Non-numeric x-user-id ('abc')
  const rNanUser = await fetch(`${baseUrl}/api/reports/101`, {
    headers: { 'x-user-id': 'abc' }
  });
  assert.equal(rNanUser.status, 401);
  const rNanUserData = await rNanUser.json();
  assert.ok(rNanUserData.error.includes('Invalid x-user-id header'));
  console.log('PASS: Reports non-numeric x-user-id returns 401 Invalid x-user-id header');

  // 2.2 Unknown user ID ('999')
  const rUnknownUser = await fetch(`${baseUrl}/api/reports/101`, {
    headers: { 'x-user-id': '999' }
  });
  assert.equal(rUnknownUser.status, 401);
  const rUnknownUserData = await rUnknownUser.json();
  assert.ok(rUnknownUserData.error.includes('User not found'));
  console.log('PASS: Reports non-existent user returns 401 User not found');

  // 2.3 Non-numeric report ID in path
  const rNanPath = await fetch(`${baseUrl}/api/reports/abc`, {
    headers: { 'x-user-id': '1' }
  });
  assert.equal(rNanPath.status, 404);
  console.log('PASS: Reports non-numeric ID in path returns 404 Route Not Found');

  // 2.4 Negative report ID
  const rNegativeId = await fetch(`${baseUrl}/api/reports/-101`, {
    headers: { 'x-user-id': '1' }
  });
  assert.equal(rNegativeId.status, 404);
  console.log('PASS: Reports negative ID in path returns 404');

  await app.stop();
  console.log('=== All Diagnostics & Reports Edge Cases Passed ===');
}

runRoutesEdgeCaseSuite().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
