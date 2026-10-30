import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { credentialInput, readCredential } from '../tool/setup-credential.mjs';

test('custom definition and sample claims validate through the core and bind preparation immutably', async () => {
  const root = mkdtempSync(join(tmpdir(), 'setup-credential-'));
  const file = join(root, 'credential.json'), state = join(root, 'issuer');
  const origin = 'https://issuer.team.example';
  const input = credentialInput({ binding: { runtimeOrigin: origin } });
  input.definition.id = origin + '/definitions/workshop';
  input.definition.version = '2';
  input.definition.credential_type = 'SyntheticWorkshopAccess';
  const run = (...extra) => spawnSync(process.execPath, ['--import', 'tsx', 'tool/setup.mjs', 'prepare', '--role', 'issuer', '--state', state,
    '--runtime-origin', origin, '--architecture', 'arm64', '--definition', file, ...extra], { encoding: 'utf8' });
  try {
    writeFileSync(file, JSON.stringify(input));
    assert.deepEqual(await readCredential(file, origin), input);
    let result = run();
    assert.equal(result.status, 0, result.stderr);
    const saved = readFileSync(join(state, 'state.json'));
    assert.deepEqual(JSON.parse(saved).binding.credential, input);
    assert.equal(run().status, 0);
    input.claims.member = false;
    writeFileSync(file, JSON.stringify(input));
    assert.match(run().stderr, /SETUP_STATE_REFUSED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    for (const mutate of [
      value => { value.definition.id = 'https://other.example/definitions/workshop'; },
      value => { value.claims.member = 'true'; },
      value => { value.definition.profiles[0].claim_paths = [['credentialSubject', 'unknown']]; },
      value => { value.managementToken = 'not-configuration'; },
    ]) {
      const invalid = structuredClone(input); mutate(invalid);
      writeFileSync(file, JSON.stringify(invalid));
      await assert.rejects(readCredential(file, origin), /SETUP_DEFINITION_REFUSED/);
      assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    }
    writeFileSync(file, 'x'.repeat(16385));
    await assert.rejects(readCredential(file, origin), /SETUP_DEFINITION_REFUSED/);
    assert(!existsSync(join(state, 'registration-result.json')));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
