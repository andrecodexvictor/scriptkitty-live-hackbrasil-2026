import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import { createLabApp, type LabAppInstance } from '../dist/index.js';

describe('Lab App Baseline Functional Test Suite', () => {
  let app: LabAppInstance;
  let baseUrl: string;

  before(async () => {
    // Spin up server on dynamic port (port 0) for collision-free testing
    app = createLabApp({ port: 0 });
    const port = await app.start();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    await app.stop();
  });

  it('Baseline 1: Health check endpoint returns 200 OK and app metadata', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'ok');
    assert.equal(data.app, 'lab-app');
  });

  it('Baseline 2: Legitimate incident search returns matching record by title keyword', async () => {
    const res = await fetch(`${baseUrl}/api/incidents/search?q=Gateway`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data));
    assert.equal(data.length, 1);
    assert.equal(data[0].id, 101);
    assert.equal(data[0].title, 'API Gateway Latency Spike');
    assert.equal(data[0].system_target, 'gateway.staging.internal');
  });

  it('Baseline 3: Legitimate incident search returns matching record by description keyword', async () => {
    const res = await fetch(`${baseUrl}/api/incidents/search?q=firewall`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data));
    assert.equal(data.length, 1);
    assert.equal(data[0].id, 103);
    assert.equal(data[0].title, 'Quarterly Firewall Rule Audit');
  });

  it('Baseline 4: Legitimate incident search with empty query returns all seeded incidents', async () => {
    const res = await fetch(`${baseUrl}/api/incidents/search?q=`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data));
    assert.equal(data.length, 3);
  });

  it('Baseline 5: Legitimate incident search with non-matching term returns empty array', async () => {
    const res = await fetch(`${baseUrl}/api/incidents/search?q=nonexistent_token_xyz_99`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data));
    assert.equal(data.length, 0);
  });

  it('Baseline 6: Host diagnostics ping tool pings localhost successfully', async () => {
    const res = await fetch(`${baseUrl}/api/diagnostics/ping`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: '127.0.0.1' })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, 'SUCCESS');
    assert.ok(typeof data.output === 'string');
    assert.ok(data.output.length > 0);
  });

  it('Baseline 7: Report owner (Alice, User 2) can access her own incident report (101)', async () => {
    const res = await fetch(`${baseUrl}/api/reports/101`, {
      method: 'GET',
      headers: { 'x-user-id': '2' }
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.id, 101);
    assert.equal(data.owner_id, 2);
    assert.equal(data.title, 'API Gateway Latency Spike');
    assert.equal(data.classification, 'INTERNAL');
  });

  it('Baseline 8: Administrator (User 1) can access any incident report (102)', async () => {
    const res = await fetch(`${baseUrl}/api/reports/102`, {
      method: 'GET',
      headers: { 'x-user-id': '1' }
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.id, 102);
    assert.equal(data.owner_id, 3);
    assert.equal(data.classification, 'RESTRICTED');
  });

  it('Baseline 9: Report request lacking x-user-id header is rejected with 401 Unauthorized', async () => {
    const res = await fetch(`${baseUrl}/api/reports/101`, {
      method: 'GET'
    });
    assert.equal(res.status, 401);
    const data = await res.json();
    assert.ok(data.error.includes('Unauthorized'));
  });

  it('Baseline 10: Non-existent report ID returns 404 Not Found', async () => {
    const res = await fetch(`${baseUrl}/api/reports/9999`, {
      method: 'GET',
      headers: { 'x-user-id': '1' }
    });
    assert.equal(res.status, 404);
    const data = await res.json();
    assert.ok(data.error.toLowerCase().includes('not found'));
  });
});
