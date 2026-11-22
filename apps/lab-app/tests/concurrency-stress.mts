import { createLabApp, type LabAppInstance } from '../dist/index.js';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

async function testInProcessConcurrency() {
  console.log('=== Step 1: Testing 20 Concurrent Server Instances (Ephemeral Port Allocation) ===');
  const count = 20;
  const instances: LabAppInstance[] = [];

  for (let i = 0; i < count; i++) {
    instances.push(createLabApp({ port: 0 }));
  }

  // Start all 20 instances concurrently
  const startTime = Date.now();
  const ports = await Promise.all(instances.map((inst) => inst.start()));
  console.log(`Successfully started ${count} instances in ${Date.now() - startTime}ms.`);
  console.log('Allocated Ports:', ports);

  // Invariant 1: All ports must be unique
  const uniquePorts = new Set(ports);
  assert.equal(uniquePorts.size, count, `Port collision detected! Only ${uniquePorts.size} unique ports out of ${count}`);
  console.log('PASS: All 20 allocated ports are completely distinct (no port collisions).');

  // Invariant 2: Concurrently query all 20 instances
  console.log('=== Step 2: Concurrent Workload Across All 20 Instances ===');
  const queryPromises = instances.map(async (inst, idx) => {
    const port = inst.getPort();
    // 1. Health check
    const hRes = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(hRes.status, 200);
    const hData = await hRes.json();
    assert.equal(hData.status, 'ok');

    // 2. Incident search
    const sRes = await fetch(`http://127.0.0.1:${port}/api/incidents/search?q=Gateway`);
    assert.equal(sRes.status, 200);
    const sData = (await sRes.json()) as any[];
    assert.equal(sData.length, 1);
    assert.equal(sData[0].id, 101);

    // 3. Diagnostics
    const dRes = await fetch(`http://127.0.0.1:${port}/api/diagnostics/ping`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: '127.0.0.1' })
    });
    assert.equal(dRes.status, 200);
    const dData = (await dRes.json()) as any;
    assert.equal(dData.status, 'SUCCESS');

    // 4. Report retrieval
    const rRes = await fetch(`http://127.0.0.1:${port}/api/reports/101`, {
      headers: { 'x-user-id': '2' }
    });
    assert.equal(rRes.status, 200);
    const rData = (await rRes.json()) as any;
    assert.equal(rData.id, 101);

    return idx;
  });

  const completed = await Promise.all(queryPromises);
  assert.equal(completed.length, count);
  console.log(`PASS: All ${count} concurrent server instances handled 4 distinct endpoints successfully.`);

  // Invariant 3: Clean shutdown of all instances without lingering sockets
  console.log('=== Step 3: Tear-down and Resource Release Verification ===');
  await Promise.all(instances.map((inst) => inst.stop()));

  for (const inst of instances) {
    assert.equal(inst.server.listening, false, 'Server still listening after stop()');
  }
  console.log('PASS: All 20 server instances cleanly stopped and released listener handles.');

  // Invariant 4: Immediate re-allocation of new instances does not fail
  const nextApp = createLabApp({ port: 0 });
  const nextPort = await nextApp.start();
  assert.ok(nextPort > 0);
  await nextApp.stop();
  console.log('PASS: Immediate re-binding after batch shutdown succeeds without EADDRINUSE.');
}

async function testMultiProcessConcurrency() {
  console.log('=== Step 4: Testing 5 Concurrent Baseline Test Runs Across Processes ===');
  const count = 5;
  const promises: Promise<number>[] = [];

  for (let i = 1; i <= count; i++) {
    const p = new Promise<number>((resolve, reject) => {
      const child = spawn('npm', ['run', 'test', '--workspace=@script-kitty/lab-app'], {
        shell: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';
      child.stdout?.on('data', (d) => { stdout += d.toString(); });
      child.stderr?.on('data', (d) => { stderr += d.toString(); });

      child.on('close', (code) => {
        if (code === 0) {
          console.log(`  Process #${i} finished successfully (code 0).`);
          resolve(0);
        } else {
          console.error(`  Process #${i} failed (code ${code}):\n${stderr || stdout}`);
          reject(new Error(`Process #${i} exited with code ${code}`));
        }
      });
    });
    promises.push(p);
  }

  await Promise.all(promises);
  console.log(`PASS: All ${count} concurrent test suite processes executed and exited 0 without port collision.`);
}

async function main() {
  await testInProcessConcurrency();
  await testMultiProcessConcurrency();
  console.log('\n========================================');
  console.log('ALL CONCURRENCY & PORT TESTS PASSED 100%');
  console.log('========================================');
}

main().catch((err) => {
  console.error('CONCURRENCY TEST FAILED:', err);
  process.exit(1);
});
