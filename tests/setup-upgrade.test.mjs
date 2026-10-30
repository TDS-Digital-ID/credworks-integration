import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, statSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function fixture(run) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'result-retry-upgrade-'))), kit = join(root, 'kit'), state = join(root, 'state');
  try {
    mkdirSync(kit);
    for (const path of ['config', 'tool']) cpSync(path, join(kit, path), { recursive: true });
    const previous = JSON.parse(readFileSync(join(kit, 'config/setup-candidate-20261013.json')));
    const manifest = join(kit, 'config/setup-candidate.json');
    writeFileSync(manifest, JSON.stringify(previous));
    const invoke = (...args) => spawnSync(process.execPath, [join(kit, 'tool/setup.mjs'), ...args], { encoding: 'utf8' });
    const prepare = invoke('prepare', '--state', state, '--architecture', 'arm64', '--kit-root', kit,
      '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example');
    assert.equal(prepare.status, 0, prepare.stderr);
    const before = JSON.parse(readFileSync(join(state, 'state.json')));
    const candidate = { ...previous, sourceRevision: 'f'.repeat(40), platforms: { arm64: { partner: 'sha256:' + 'a'.repeat(64), application: 'sha256:' + 'b'.repeat(64) } } };
    writeFileSync(manifest, JSON.stringify(candidate));
    const images = join(root, 'images.json');
    const inspection = [candidate.platforms.arm64.partner, candidate.platforms.arm64.application].map(Id => ({ Id, Os: 'linux', Architecture: 'arm64', Config: { User: '10001:10001', Labels: { 'org.opencontainers.image.revision': candidate.sourceRevision } } }));
    writeFileSync(images, JSON.stringify(inspection));
    const args = ['upgrade', '--state', state, '--kit-root', kit, '--partner-image', candidate.platforms.arm64.partner,
      '--app-image', candidate.platforms.arm64.application, '--image-inspection', images];
    run({ root, state, kit, before, candidate, images, inspection, invoke, args });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test('upgrade accepts only inspected pinned images and preserves identity, account and registration configuration', () => fixture(({ state, before, candidate, images, inspection, invoke, args }) => {
  assert.equal(invoke('get', '--state', state, '--field', 'partnerImage').status, 0, 'older installations must remain operable');
  const original = readFileSync(join(state, 'state.json'));
  inspection[0].Config.Labels['org.opencontainers.image.revision'] = '0'.repeat(40);
  writeFileSync(images, JSON.stringify(inspection));
  assert.match(invoke(...args).stderr, /SETUP_IMAGE_REFUSED/);
  assert.deepEqual(readFileSync(join(state, 'state.json')), original);
  inspection[0].Config.Labels['org.opencontainers.image.revision'] = candidate.sourceRevision;
  writeFileSync(images, JSON.stringify(inspection));
  const upgraded = invoke(...args);
  assert.equal(upgraded.status, 0, upgraded.stderr);
  const after = JSON.parse(readFileSync(join(state, 'state.json')));
  assert.deepEqual({ ...after, binding: before.binding, configurationHashes: before.configurationHashes }, before);
  assert.deepEqual({ ...after.binding, partnerImage: before.binding.partnerImage, appImage: before.binding.appImage, sourceRevision: before.binding.sourceRevision }, before.binding);
  const backup = join(state, `runtime-upgrade-backup.${before.binding.sourceRevision}.json`);
  assert.equal(statSync(backup).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(readFileSync(backup)).before, before);
  const saved = readFileSync(join(state, 'state.json'));
  assert.equal(invoke(...args).status, 0);
  assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
  assert.equal(invoke('get', '--state', state, '--field', 'partnerImage').stdout.trim(), candidate.platforms.arm64.partner);
  assert(!upgraded.stdout.includes(before.unlockKey));
}));

test('interrupted upgrades resume only the same transition at every file boundary', () => fixture(({ state, before, invoke, args }) => {
  assert.equal(invoke(...args).status, 0);
  const backupBytes = readFileSync(join(state, `runtime-upgrade-backup.${before.binding.sourceRevision}.json`));
  const journal = JSON.parse(backupBytes), names = Object.keys(journal.files);
  const after = Object.fromEntries(names.map(name => [name, readFileSync(join(state, name))]));
  for (let step = 0; step <= names.length; step++) {
    for (const name of names) writeFileSync(join(state, name), journal.files[name], { mode: 0o600 });
    writeFileSync(join(state, 'runtime-upgrade.json'), backupBytes, { mode: 0o600 });
    for (const name of names.slice(0, step)) writeFileSync(join(state, name), after[name]);
    if (step < names.length) writeFileSync(join(state, names[step] + '.pending'), after[names[step]], { mode: 0o600 });
    assert.match(invoke('get', '--state', state, '--field', 'project').stderr, /SETUP_UPGRADE_PENDING/);
    const recovered = invoke(...args);
    assert.equal(recovered.status, 0, `step ${step}: ${recovered.stderr}`);
    for (const name of names) assert.deepEqual(readFileSync(join(state, name)), after[name]);
  }
  for (const name of names) writeFileSync(join(state, name), journal.files[name]);
  writeFileSync(join(state, 'runtime-upgrade.json.pending'), backupBytes, { mode: 0o600 });
  assert.equal(invoke(...args).status, 0, 'recover a journal interrupted before rename');
  writeFileSync(join(state, 'runtime-upgrade.json'), backupBytes, { mode: 0o600 });
  writeFileSync(join(state, 'team.env.pending'), 'different transition', { mode: 0o600 });
  const refused = invoke(...args);
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /SETUP_UPGRADE_REFUSED/);
  assert.deepEqual(readFileSync(join(state, 'state.json')), after['state.json']);
}));
