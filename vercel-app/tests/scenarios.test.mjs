import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { VERCEL_SCENARIOS } from '../src/scenarios.ts';

for (const [id, scenario] of Object.entries(VERCEL_SCENARIOS)) {
  test(`${id} displays the canonical fixture metadata and operations`, () => {
    const fixture = JSON.parse(readFileSync(new URL(`../../fixtures/${id}.json`, import.meta.url), 'utf8'));
    assert.equal(scenario.id, fixture.fixtureId);
    assert.equal(scenario.inputSha256, fixture.declaredInputSha256);
    assert.equal(scenario.policyVersion, fixture.policyVersion);
    assert.deepEqual(
      scenario.operations.map(({ id }) => id).sort(),
      fixture.legitimateOperations.map(({ operationId }) => operationId).sort(),
    );
  });
}
