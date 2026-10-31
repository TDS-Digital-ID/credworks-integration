import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, renameSync, readdirSync, symlinkSync, writeFileSync, readFileSync, existsSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readCourseBundle } from '../tool/setup.mjs';
const helper = new URL('../tool/setup.mjs', import.meta.url);
const invoke = (...args) => spawnSync(process.execPath, [helper.pathname, ...args], { encoding: 'utf8' });
function courseFixture(parent) {
  const state = join(parent, 'team'), bundlePath = join(parent, 'example-team.json');
  const credentials = { TunnelID: '11111111-1111-4111-8111-111111111111', AccountTag: 'a'.repeat(32), TunnelSecret: Buffer.alloc(32, 7).toString('base64') };
  const bundle = { version: 1, group: 'example-team', runtimeOrigin: 'https://example-team-verify.course.example', appOrigin: 'https://example-team-app.course.example', accountId: credentials.AccountTag, tunnelId: credentials.TunnelID, credentials };
  const binding = ['--state', state, '--group', 'example-team', '--tunnel-bundle', bundlePath, '--runtime-origin', bundle.runtimeOrigin, '--app-origin', bundle.appOrigin];
  return { state, bundlePath, credentials, bundle, binding, args: ['prepare', ...binding, '--architecture', 'arm64'] };
}
test('course assignments use bounded DNS labels without embedding a roster', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-group-'));
  const { bundlePath, bundle } = courseFixture(parent);
  try {
    for (const group of ['a', 'example-team', 'other-team', 'a'.repeat(56)]) {
      const candidate = { ...bundle, group, runtimeOrigin: `https://${group}-verify.course.example`, appOrigin: `https://${group}-app.course.example` };
      writeFileSync(bundlePath, JSON.stringify(candidate), { mode: 0o600 });
      assert.deepEqual(readCourseBundle(bundlePath), candidate);
    }
    for (const group of ['', '-team', 'team-', 'Example-Team', 'team.name', 'team_name', 'a'.repeat(57), null, 1, {}]) {
      writeFileSync(bundlePath, JSON.stringify({ ...bundle, group }));
      assert.throws(() => readCourseBundle(bundlePath), /SETUP_TUNNEL_BUNDLE_REFUSED/);
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});
test('setup refuses a temporary runtime origin before creating protected state', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-test-'));
  try {
    const result = invoke('prepare', '--state', join(parent, 'team'), '--runtime-origin', 'https://random.trycloudflare.com', '--app-origin', 'https://app.team.example');
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_ORIGIN_REFUSED/);
    assert.equal(existsSync(join(parent, 'team')), false);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('prepare preserves configuration on retry and refuses changed origins', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-test-'));
  const state = join(parent, 'team');
  const args = ['prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64', '--kit-root', new URL('..', import.meta.url).pathname.replace(/\/$/, '')];
  try {
    let result = invoke(...args);
    assert.equal(result.status, 0, result.stderr);
    const before = readFileSync(join(state, 'state.json'));
    const env = readFileSync(join(state, 'team.env'));
    assert.equal(statSync(state).mode & 0o777, 0o700);
    assert.equal(statSync(join(state, 'state.json')).mode & 0o777, 0o600);
    result = invoke(...args);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    assert.deepEqual(readFileSync(join(state, 'team.env')), env);
    result = invoke(...args.map(value => value === 'https://verify.team.example' ? 'https://other.team.example' : value));
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_STATE_REFUSED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    assert(!result.stderr.includes('PARTNER_UNLOCK_KEY'));
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('interrupted tunnel creation refuses duplicate creation and recovers the exact authenticated tunnel', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-test-'));
  const state = join(parent, 'team');
  try {
    assert.equal(invoke('prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64').status, 0);
    const listing = join(parent, 'list.json');
    writeFileSync(listing, '[]');
    let result = invoke('tunnel-reconcile', '--state', state, '--list', listing);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'CREATE');
    result = invoke('tunnel-reconcile', '--state', state, '--list', listing);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_TUNNEL_OUTCOME_UNKNOWN/);
    const saved = JSON.parse(readFileSync(join(state, 'state.json')));
    const id = '11111111-1111-4111-8111-111111111111';
    writeFileSync(listing, JSON.stringify([{ id, name: saved.tunnelName, deleted_at: '0001-01-01T00:00:00Z' }]));
    writeFileSync(join(state, 'tunnel-credentials.json'), JSON.stringify({ TunnelID: id, AccountTag: 'a'.repeat(32), TunnelSecret: Buffer.alloc(32, 7).toString('base64') }), { mode: 0o600 });
    result = invoke('tunnel-reconcile', '--state', state, '--list', listing);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), id);
    assert.equal(JSON.parse(readFileSync(join(state, 'state.json'))).tunnelId, id);
    const tunnel = JSON.parse(readFileSync(join(state, 'tunnel.yml')));
    assert.equal(tunnel.ingress.at(-1).service, 'http_status:404');
    assert(!JSON.stringify(tunnel).includes('3081'));
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('Cloudflare null listing starts once while unexpected result types refuse without changing state', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-test-'));
  const state = join(parent, 'team'), listing = join(parent, 'list.json');
  try {
    assert.equal(invoke('prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64').status, 0);
    const before = readFileSync(join(state, 'state.json'));
    for (const invalid of ['{}', 'false', '0', '"not-a-list"']) {
      writeFileSync(listing, invalid);
      const refused = invoke('tunnel-reconcile', '--state', state, '--list', listing);
      assert.equal(refused.status, 1);
      assert.match(refused.stderr, /SETUP_TUNNEL_LIST_REFUSED/);
      assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    }
    writeFileSync(listing, 'null');
    const created = invoke('tunnel-reconcile', '--state', state, '--list', listing);
    assert.equal(created.status, 0, created.stderr);
    assert.equal(created.stdout.trim(), 'CREATE');
    const saved = readFileSync(join(state, 'state.json'));
    const repeated = invoke('tunnel-reconcile', '--state', state, '--list', listing);
    assert.equal(repeated.status, 1);
    assert.match(repeated.stderr, /SETUP_TUNNEL_OUTCOME_UNKNOWN/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('changed trust input and unsafe existing state stop before any replacement', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-test-'));
  const state = join(parent, 'team');
  const args = ['prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64'];
  try {
    assert.equal(invoke(...args).status, 0);
    const before = readFileSync(join(state, 'state.json'));
    const changed = join(parent, 'ecosystem.json');
    const config = readFileSync(new URL('../config/credworks-sandbox-20261011.json', import.meta.url), 'utf8').replace('unsw.edu.au', 'other.example');
    writeFileSync(changed, config);
    let result = invoke(...args, '--ecosystem', changed);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_TRUST_INPUT_REFUSED/);
    result = invoke(...args, '--ecosystem', changed, '--ecosystem-sha256', createHash('sha256').update(config).digest('hex'));
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_STATE_REFUSED/);
    writeFileSync(join(state, 'state.json.pending'), 'interrupted');
    result = invoke(...args);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_STORAGE_REFUSED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('setup rejects a wrongly labelled selected image and never prints its environment', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-test-'));
  const state = join(parent, 'team');
  try {
    assert.equal(invoke('prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64').status, 0);
    const inspection = join(parent, 'inspection.json');
    writeFileSync(inspection, JSON.stringify([{ Id: 'wrong', Config: { Env: ['SECRET=do-not-log'] } }, {}]));
    const result = invoke('inspect-images', '--state', state, '--input', inspection);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_IMAGE_REFUSED/);
    assert(!result.stderr.includes('do-not-log'));
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('edited generated secrets are refused before start instead of replacing the saved identity', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-test-'));
  const state = join(parent, 'team');
  try {
    assert.equal(invoke('prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64').status, 0);
    const saved = readFileSync(join(state, 'state.json'));
    writeFileSync(join(state, 'team.env'), 'PARTNER_UNLOCK_KEY=replacement\n');
    const result = invoke('get', '--state', state, '--field', 'project');
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_STATE_REFUSED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('issuer preparation owns separate protected state and refuses changing its role', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-issuer-test-'));
  const state = join(parent, 'issuer');
  const args = ['prepare', '--state', state, '--role', 'issuer', '--runtime-origin', 'https://issuer.team.example', '--architecture', 'arm64'];
  try {
    const result = invoke(...args);
    assert.equal(result.status, 0, result.stderr);
    const before = readFileSync(join(state, 'state.json'));
    const env = readFileSync(join(state, 'team.env'), 'utf8');
    assert.match(env, /PARTNER_ISSUER_POSTGRES_PASSWORD=/);
    assert.doesNotMatch(env, /EDUCATION_APP_DATABASE_URL=/);
    assert.equal(invoke(...args).status, 0);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    const changed = invoke('prepare', '--state', state, '--runtime-origin', 'https://issuer.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64');
    assert.equal(changed.status, 1);
    assert.match(changed.stderr, /SETUP_STATE_REFUSED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('issuer tunnel exposes only issuance routes and refuses management', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-issuer-ingress-'));
  const state = join(parent, 'issuer');
  try {
    assert.equal(invoke('prepare', '--state', state, '--role', 'issuer', '--runtime-origin', 'https://issuer.team.example', '--architecture', 'arm64').status, 0);
    const saved = JSON.parse(readFileSync(join(state, 'state.json')));
    const id = '11111111-1111-4111-8111-111111111111';
    const listing = join(parent, 'list.json');
    writeFileSync(listing, JSON.stringify([{ id, name: saved.tunnelName }]));
    writeFileSync(join(state, 'tunnel-credentials.json'), JSON.stringify({ TunnelID: id, AccountTag: 'a'.repeat(32), TunnelSecret: Buffer.alloc(32, 7).toString('base64') }), { mode: 0o600 });
    const result = invoke('tunnel-reconcile', '--state', state, '--list', listing);
    assert.equal(result.status, 0, result.stderr);
    const ingress = JSON.parse(readFileSync(join(state, 'tunnel.yml'))).ingress;
    const route = new RegExp(ingress[0].path);
    for (const path of ['/.well-known/did.json', '/.well-known/openid-credential-issuer', '/oid4vci/offers/example', '/oid4vci/credential', '/oid4vci/status/revocation.jwt']) assert(route.test(path), path);
    for (const path of ['/management/issuer/offers', '/oid4vp/request/example', '/unknown', '/oid4vci/credential/extra', '/%2e%2e/management/sign']) assert(!route.test(path), path);
    assert.equal(ingress.length, 3);
    assert.equal(ingress.at(-1).service, 'http_status:404');
    assert(!JSON.stringify(ingress).includes('3081'));
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

for (const command of ['eligibility', 'sign-in', 'android-offer']) test(`${command} refuses an unregistered setup without creating a software holder`, () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-eligibility-'));
  const state = join(parent, 'team');
  try {
    assert.equal(invoke('prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64').status, 0);
    const result = invoke(command, '--state', state);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_REGISTRATION_INCOMPLETE/);
    assert.equal(existsSync(join(state, 'software-holder')), false);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('custom verifier preparation requires a distinct prepared issuer and preserves that binding', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-verifier-test-'));
  const issuer = join(parent, 'issuer'), verifier = join(parent, 'verifier');
  try {
    assert.equal(invoke('prepare', '--state', issuer, '--role', 'issuer', '--runtime-origin', 'https://issuer.team.example', '--architecture', 'arm64').status, 0);
    const args = ['prepare', '--state', verifier, '--role', 'verifier', '--runtime-origin', 'https://verify.team.example', '--issuer-state', issuer, '--architecture', 'arm64'];
    const result = invoke(...args);
    assert.equal(result.status, 0, result.stderr);
    const before = readFileSync(join(verifier, 'state.json'));
    assert.equal(invoke(...args).status, 0);
    assert.deepEqual(readFileSync(join(verifier, 'state.json')), before);
    const collision = invoke(...args.map(value => value === 'https://verify.team.example' ? 'https://issuer.team.example' : value));
    assert.equal(collision.status, 1);
    assert.match(collision.stderr, /SETUP_ORIGIN_REFUSED/);
    const issuerState = JSON.parse(readFileSync(join(issuer, 'state.json')));
    const verifierState = JSON.parse(before);
    assert.notEqual(verifierState.managementToken, issuerState.managementToken);
    assert.notEqual(verifierState.unlockKey, issuerState.unlockKey);
    for (const command of ['eligibility', 'sign-in']) {
      const education = invoke(command, '--state', verifier);
      assert.equal(education.status, 1);
      assert.match(education.stderr, /SETUP_ROLE_REFUSED/);
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('a supplied course tunnel prepares protected state and repeats without replacing its identity', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-course-'));
  const { state, bundlePath, credentials, bundle, args } = courseFixture(parent);
  try {
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    chmodSync(bundlePath, 0o644);
    assert.match(invoke(...args).stderr, /SETUP_STORAGE_REFUSED/);
    assert.equal(existsSync(join(state, 'state.json')), false);
    chmodSync(bundlePath, 0o600);
    const alias = join(parent, 'bundle-alias.json');
    symlinkSync(bundlePath, alias);
    assert.match(invoke(...args.map(value => value === bundlePath ? alias : value)).stderr, /SETUP_STORAGE_REFUSED/);
    const prepared = invoke(...args);
    assert.equal(prepared.status, 0, prepared.stderr);
    assert.equal(invoke('get', '--state', state, '--field', 'tunnelMode').stdout.trim(), 'supplied');
    assert.equal(invoke('get', '--state', state, '--field', 'tunnelId').stdout.trim(), credentials.TunnelID);
    assert.equal(statSync(join(state, 'tunnel-credentials.json')).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(readFileSync(join(state, 'tunnel-credentials.json'))), credentials);
    const saved = readFileSync(join(state, 'state.json'));
    const env = readFileSync(join(state, 'team.env'));
    assert.equal(invoke(...args).status, 0);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    assert.deepEqual(readFileSync(join(state, 'team.env')), env);
    assert(!prepared.stdout.includes(credentials.TunnelSecret));
    for (const changed of [args.map(value => value === 'example-team' ? 'other-team' : value), args.map(value => value === bundle.runtimeOrigin ? 'https://other-verify.course.example' : value)]) {
      const refused = invoke(...changed);
      assert.equal(refused.status, 1);
      assert.match(refused.stderr, /SETUP_TUNNEL_BUNDLE_REFUSED/);
      assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    }
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('course bundle import refuses unrelated authority, malformed data and changed saved capabilities', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-course-refusal-'));
  const { state, bundlePath, credentials, bundle, args } = courseFixture(parent);
  try {
    for (const invalid of [
      { ...bundle, certPem: 'account-wide-certificate' },
      { ...bundle, ecosystem: { trustAnchorJwk: {} } },
      { ...bundle, environment: { PARTNER_UNLOCK_KEY: 'replacement' } },
      { ...bundle, mounts: ['/private:/private'] },
      { ...bundle, command: 'touch /tmp/should-not-execute' },
      { ...bundle, version: 2 },
      { ...bundle, credentials: { ...credentials, TunnelID: '22222222-2222-4222-8222-222222222222' } },
      { ...bundle, credentials: { ...credentials, AccountTag: 'b'.repeat(32) } },
      { ...bundle, credentials: { ...credentials, TunnelSecret: credentials.TunnelSecret + '\n' } },
      { ...bundle, credentials: { ...credentials, certPem: 'account-wide-certificate' } },
      { ...bundle, group: 'other-team' },
      { ...bundle, appOrigin: 'https://other-team-app.course.example' },
      null,
    ]) {
      writeFileSync(bundlePath, JSON.stringify(invalid), { mode: 0o600 });
      const refused = invoke(...args);
      assert.equal(refused.status, 1);
      assert.match(refused.stderr, /SETUP_TUNNEL_BUNDLE_REFUSED/);
      assert.equal(existsSync(join(state, 'state.json')), false);
      assert(!refused.stderr.includes(credentials.TunnelSecret));
    }
    writeFileSync(bundlePath, JSON.stringify(bundle) + ' '.repeat(4096), { mode: 0o600 });
    assert.match(invoke(...args).stderr, /SETUP_TUNNEL_BUNDLE_REFUSED/);
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    assert.equal(invoke(...args).status, 0);
    const saved = readFileSync(join(state, 'state.json'));
    const keyFile = readFileSync(join(state, 'tunnel-credentials.json'));
    for (const changed of [
      { ...bundle, credentials: { ...credentials, TunnelSecret: Buffer.alloc(32, 8).toString('base64') } },
      { ...bundle, accountId: 'b'.repeat(32), credentials: { ...credentials, AccountTag: 'b'.repeat(32) } },
      { ...bundle, tunnelId: '22222222-2222-4222-8222-222222222222', credentials: { ...credentials, TunnelID: '22222222-2222-4222-8222-222222222222' } },
    ]) {
      writeFileSync(bundlePath, JSON.stringify(changed));
      assert.equal(invoke(...args).status, 1);
      assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
      assert.deepEqual(readFileSync(join(state, 'tunnel-credentials.json')), keyFile);
    }
    writeFileSync(join(state, 'tunnel-credentials.json'), JSON.stringify({ ...credentials, TunnelSecret: Buffer.alloc(32, 8).toString('base64') }));
    assert.match(invoke('get', '--state', state, '--field', 'project').stderr, /SETUP_TUNNEL_IDENTITY_REFUSED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    rmSync(join(state, 'tunnel-credentials.json'));
    assert.match(invoke('get', '--state', state, '--field', 'project').stderr, /SETUP_TUNNEL_CREDENTIAL_REQUIRED/);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('explicit supplied tunnel replacement preserves application state and repeats with the same bundle', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-replace-'));
  const { state, bundlePath, credentials, bundle, binding } = courseFixture(parent);
  try {
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    assert.equal(invoke('prepare', ...binding, '--architecture', 'arm64').status, 0);
    const before = JSON.parse(readFileSync(join(state, 'state.json')));
    const configuration = readFileSync(join(state, 'team.env'));
    const replacementId = '22222222-2222-4222-8222-222222222222';
    const replacement = { ...bundle, tunnelId: replacementId, credentials: { ...credentials, TunnelID: replacementId, TunnelSecret: Buffer.alloc(32, 8).toString('base64') } };
    writeFileSync(bundlePath, JSON.stringify(replacement));
    const args = ['replace-tunnel', ...binding, '--from-tunnel', credentials.TunnelID];
    const result = invoke(...args);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /SETUP_TUNNEL_REPLACED/);
    assert.equal(invoke('get', '--state', state, '--field', 'tunnelId').stdout.trim(), replacementId);
    const after = JSON.parse(readFileSync(join(state, 'state.json')));
    for (const key of Object.keys(before).filter(key => !key.startsWith('tunnel'))) assert.deepEqual(after[key], before[key], key);
    assert.deepEqual(readFileSync(join(state, 'team.env')), configuration);
    assert.equal(invoke(...args).status, 0);
    assert.deepEqual(JSON.parse(readFileSync(join(state, 'state.json'))), after);
    assert.equal(invoke('tunnel-reconcile', '--state', state).status, 0);
    assert.equal(JSON.parse(readFileSync(join(state, 'tunnel.yml'))).tunnel, replacementId);
    assert(!result.stdout.includes(replacement.credentials.TunnelSecret));
    writeFileSync(bundlePath, JSON.stringify(bundle));
    assert.match(invoke(...args).stderr, /SETUP_TUNNEL_REPLACEMENT_REFUSED/);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('lost supplied credentials recover only through an explicit same-binding replacement', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-lost-tunnel-'));
  const state = join(parent, 'team'), bundlePath = join(parent, 'other-team.json');
  const credentials = { TunnelID: '33333333-3333-4333-8333-333333333333', AccountTag: 'a'.repeat(32), TunnelSecret: Buffer.alloc(32, 3).toString('base64') };
  const bundle = { version: 1, group: 'other-team', runtimeOrigin: 'https://other-team-verify.course.example', appOrigin: 'https://other-team-app.course.example', accountId: credentials.AccountTag, tunnelId: credentials.TunnelID, credentials };
  const binding = ['--state', state, '--group', 'other-team', '--tunnel-bundle', bundlePath, '--runtime-origin', bundle.runtimeOrigin, '--app-origin', bundle.appOrigin];
  try {
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    assert.equal(invoke('prepare', ...binding, '--architecture', 'arm64').status, 0);
    const saved = readFileSync(join(state, 'state.json'));
    rmSync(join(state, 'tunnel-credentials.json'));
    const replacementId = '44444444-4444-4444-8444-444444444444';
    const replacement = { ...bundle, tunnelId: replacementId, credentials: { ...credentials, TunnelID: replacementId, TunnelSecret: Buffer.alloc(32, 4).toString('base64') } };
    const args = ['replace-tunnel', ...binding, '--from-tunnel', credentials.TunnelID];
    for (const invalid of [
      { ...replacement, accountId: 'b'.repeat(32), credentials: { ...replacement.credentials, AccountTag: 'b'.repeat(32) } },
      { ...replacement, group: 'example-team' },
      { ...replacement, appOrigin: 'https://example-team-app.course.example' },
      { ...replacement, ecosystem: {} },
    ]) {
      writeFileSync(bundlePath, JSON.stringify(invalid));
      assert.equal(invoke(...args).status, 1);
      assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    }
    writeFileSync(bundlePath, JSON.stringify(replacement));
    assert.match(invoke(...args, '--ecosystem', bundlePath).stderr, /SETUP_ARGUMENTS_REFUSED/);
    assert.equal(invoke('get', '--state', state, '--field', 'project').status, 1);
    const recovered = invoke(...args);
    assert.equal(recovered.status, 0, recovered.stderr);
    assert.equal(invoke('get', '--state', state, '--field', 'tunnelId').stdout.trim(), replacementId);
    const after = JSON.parse(readFileSync(join(state, 'state.json')));
    rmSync(join(state, after.tunnelCredentialFile));
    assert.equal(invoke(...args).status, 0, 'the exact accepted bundle restores a lost replacement file');
    assert.equal(invoke('prepare', ...binding, '--architecture', 'arm64').status, 0);
    writeFileSync(join(state, after.tunnelCredentialFile), JSON.stringify(credentials));
    assert.match(invoke('get', '--state', state, '--field', 'project').stderr, /SETUP_TUNNEL_IDENTITY_REFUSED/);
    assert.equal(invoke(...args).status, 1, 'unexpected existing bytes require operator reconciliation');
    writeFileSync(join(state, 'team.env'), 'PARTNER_UNLOCK_KEY=changed\n');
    assert.match(invoke(...args).stderr, /SETUP_STATE_REFUSED/);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('interrupted tunnel replacement resumes the recorded change and refuses ambiguous partial files', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-interrupted-replacement-'));
  const { state, bundlePath, credentials, bundle, binding } = courseFixture(parent);
  try {
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    assert.equal(invoke('prepare', ...binding, '--architecture', 'arm64').status, 0);
    const before = readFileSync(join(state, 'state.json'));
    const replacementId = '22222222-2222-4222-8222-222222222222';
    const replacement = { ...bundle, tunnelId: replacementId, credentials: { ...credentials, TunnelID: replacementId, TunnelSecret: Buffer.alloc(32, 8).toString('base64') } };
    writeFileSync(bundlePath, JSON.stringify(replacement));
    const args = ['replace-tunnel', ...binding, '--from-tunnel', credentials.TunnelID];
    const credentialPath = join(state, `tunnel-credentials.${replacementId}.json`);
    writeFileSync(credentialPath, 'conflicting protected input', { mode: 0o600 });
    assert.equal(invoke(...args).status, 1);
    assert.equal(existsSync(join(state, 'tunnel-replacement.json')), false, 'conflicting input must not create a replacement journal');
    assert.equal(invoke('get', '--state', state, '--field', 'project').status, 0);
    rmSync(credentialPath);
    const interrupted = spawnSync('bash', ['-c', 'ulimit -f 1; exec "$@"', 'setup-storage-failure', process.execPath, helper.pathname, ...args], { encoding: 'utf8' });
    assert.notEqual(interrupted.status, 0, 'a filesystem failure must retain the selected replacement');
    assert.match(invoke('get', '--state', state, '--field', 'project').stderr, /SETUP_TUNNEL_REPLACEMENT_PENDING/);
    const journal = readFileSync(join(state, 'tunnel-replacement.json'));
    writeFileSync(bundlePath, JSON.stringify({ ...replacement, credentials: { ...replacement.credentials, TunnelSecret: Buffer.alloc(32, 9).toString('base64') } }));
    assert.match(invoke(...args).stderr, /SETUP_TUNNEL_REPLACEMENT_REFUSED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    writeFileSync(bundlePath, JSON.stringify(replacement));
    assert.match(invoke(...args).stderr, /SETUP_TUNNEL_REPLACEMENT_AMBIGUOUS/);
    renameSync(join(state, 'state.json.pending'), join(parent, 'preserved-incomplete-state'));
    rmSync(credentialPath);
    writeFileSync(credentialPath + '.pending', JSON.stringify(replacement.credentials) + '\n', { mode: 0o600 });
    assert.equal(invoke(...args).status, 0, 'a complete interrupted credential write is recoverable');
    const after = readFileSync(join(state, 'state.json'));
    // Recover a completed state write whose final rename did not reach disk.
    writeFileSync(join(state, 'state.json'), before);
    writeFileSync(join(state, 'state.json.pending'), after, { mode: 0o600 });
    writeFileSync(join(state, 'tunnel-replacement.json'), journal, { mode: 0o600 });
    assert.equal(invoke(...args).status, 0);
    assert.deepEqual(readFileSync(join(state, 'state.json')), after);
    assert.equal(existsSync(join(state, 'tunnel-replacement.json')), false);
    writeFileSync(join(state, 'state.json'), before);
    writeFileSync(join(state, 'state.json.pending'), 'truncated', { mode: 0o600 });
    writeFileSync(join(state, 'tunnel-replacement.json'), journal, { mode: 0o600 });
    assert.match(invoke(...args).stderr, /SETUP_TUNNEL_REPLACEMENT_AMBIGUOUS/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    assert.equal(readFileSync(join(state, 'state.json.pending'), 'utf8'), 'truncated');
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('interrupted first course import retries with the same bundle and local identity', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-interrupted-import-'));
  const { state, bundlePath, credentials, bundle, args } = courseFixture(parent);
  try {
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    const preload = join(parent, 'interrupt.cjs');
    writeFileSync(preload, `
      const fs = require('node:fs');
      const rename = fs.renameSync, sync = fs.fsyncSync;
      let renamed = false;
      fs.renameSync = (...args) => {
        rename(...args);
        if (String(args[1]).endsWith('/tunnel-credentials.json')) renamed = true;
      };
      fs.fsyncSync = fd => { sync(fd); if (renamed) process.exit(97); };
      require('node:module').syncBuiltinESMExports();
    `);
    const interrupted = spawnSync(process.execPath, ['--require', preload, helper.pathname, ...args], { encoding: 'utf8' });
    assert.equal(interrupted.status, 97, interrupted.stderr);
    assert.deepEqual(JSON.parse(readFileSync(join(state, 'tunnel-credentials.json'))), credentials);
    const identityPath = ['state.json', 'tunnel-import.json'].map(name => join(state, name)).find(existsSync);
    const before = identityPath && JSON.parse(readFileSync(identityPath));
    const recovered = invoke(...args);
    assert.equal(recovered.status, 0, recovered.stderr);
    assert.equal(invoke('get', '--state', state, '--field', 'tunnelId').stdout.trim(), credentials.TunnelID);
    const after = JSON.parse(readFileSync(join(state, 'state.json')));
    assert(before, 'the interrupted import must retain its selected identity');
    for (const key of ['project', 'tunnelName', 'unlockKey', 'managementToken', 'databasePassword', 'binding']) assert.deepEqual(after[key], before[key], key);
    const complete = readFileSync(join(state, 'state.json'));
    assert.equal(invoke(...args).status, 0);
    assert.deepEqual(readFileSync(join(state, 'state.json')), complete);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

for (const file of ['tunnel-import.json', 'tunnel-credentials.json', 'team.env', 'partner-image', 'registration-config.json', 'state.json']) {
  for (const pending of [true, false]) test(`course import recovers after syncing ${file}${pending ? '.pending' : ''}`, () => {
    const parent = mkdtempSync(join(tmpdir(), 'setup-import-sync-'));
    const { state, bundlePath, credentials, bundle, args } = courseFixture(parent);
    try {
      writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
      const preload = join(parent, 'interrupt.cjs');
      writeFileSync(preload, `
        const fs = require('node:fs');
        const open = fs.openSync, rename = fs.renameSync, sync = fs.fsyncSync;
        const paths = new Map();
        let renamed = false;
        fs.openSync = (...args) => { const fd = open(...args); paths.set(fd, String(args[0])); return fd; };
        fs.renameSync = (...args) => { rename(...args); if (String(args[1]).endsWith('/${file}')) renamed = true; };
        fs.fsyncSync = fd => {
          sync(fd);
          if (${pending} ? paths.get(fd)?.endsWith('/${file}.pending') : renamed) process.exit(97);
        };
        require('node:module').syncBuiltinESMExports();
      `);
      const interrupted = spawnSync(process.execPath, ['--require', preload, helper.pathname, ...args], { encoding: 'utf8' });
      assert.equal(interrupted.status, 97, interrupted.stderr);
      const journalPath = [join(state, 'tunnel-import.json'), join(state, 'tunnel-import.json.pending')].find(existsSync);
      const before = JSON.parse(readFileSync(journalPath));
      for (const command of ['get', 'check-local', 'check-public', 'ready', 'register', 'tunnel-reconcile', 'configure', 'mark', 'replace-tunnel']) {
        const refused = invoke(command, '--state', state);
        assert.equal(refused.status, 1);
        assert.match(refused.stderr, /SETUP_TUNNEL_IMPORT_PENDING/);
      }
      const recovered = invoke(...args);
      assert.equal(recovered.status, 0, recovered.stderr);
      const after = JSON.parse(readFileSync(join(state, 'state.json')));
      for (const key of Object.keys(before)) assert.deepEqual(after[key], before[key], key);
      assert.equal(invoke('get', '--state', state, '--field', 'tunnelId').stdout.trim(), credentials.TunnelID);
      assert.equal(existsSync(join(state, 'tunnel-import.json')), false);
      assert.equal(readdirSync(state).some(name => name.endsWith('.pending')), false);
      assert.equal(statSync(join(state, 'public')).isDirectory(), true);
      const complete = readFileSync(join(state, 'state.json'));
      assert.equal(invoke(...args).status, 0);
      assert.deepEqual(readFileSync(join(state, 'state.json')), complete);
    } finally { rmSync(parent, { recursive: true, force: true }); }
  });
}

test('interrupted course import refuses changed bindings and conflicting files without overwriting evidence', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-import-refusal-'));
  const { state, bundlePath, credentials, bundle, args } = courseFixture(parent);
  try {
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    assert.equal(invoke(...args).status, 0);
    const complete = readFileSync(join(state, 'state.json'));
    const initial = JSON.parse(complete);
    delete initial.configurationHashes;
    const journal = join(state, 'tunnel-import.json');
    writeFileSync(journal, JSON.stringify(initial, null, 2) + '\n', { mode: 0o600 });
    const snapshot = () => Object.fromEntries(readdirSync(state).filter(name => statSync(join(state, name)).isFile()).map(name => [name, readFileSync(join(state, name))]));
    const before = snapshot();
    for (const changed of [
      { ...bundle, credentials: { ...credentials, TunnelSecret: Buffer.alloc(32, 8).toString('base64') } },
      { ...bundle, accountId: 'b'.repeat(32), credentials: { ...credentials, AccountTag: 'b'.repeat(32) } },
      { ...bundle, tunnelId: '22222222-2222-4222-8222-222222222222', credentials: { ...credentials, TunnelID: '22222222-2222-4222-8222-222222222222' } },
    ]) {
      writeFileSync(bundlePath, JSON.stringify(changed));
      assert.match(invoke(...args).stderr, /SETUP_STATE_REFUSED/);
      assert.deepEqual(snapshot(), before);
    }
    writeFileSync(bundlePath, JSON.stringify(bundle));
    for (const extra of [['--runtime-port', '4567'], ['--kit-root', parent]]) {
      assert.match(invoke(...args, ...extra).stderr, /SETUP_STATE_REFUSED/);
      assert.deepEqual(snapshot(), before);
    }
    for (const name of ['tunnel-import.json.pending', 'tunnel-credentials.json.pending', 'team.env.pending', 'state.json.pending']) {
      const path = join(state, name);
      writeFileSync(path, 'truncated', { mode: 0o600 });
      const conflicting = snapshot();
      assert.match(invoke(...args).stderr, /SETUP_TUNNEL_IMPORT_AMBIGUOUS/);
      assert.deepEqual(snapshot(), conflicting);
      renameSync(path, join(parent, name));
    }
    const unexpected = join(state, 'unrelated');
    writeFileSync(unexpected, 'preserve', { mode: 0o600 });
    assert.match(invoke(...args).stderr, /SETUP_STORAGE_REFUSED/);
    assert.equal(readFileSync(unexpected, 'utf8'), 'preserve');
    renameSync(unexpected, join(parent, 'unrelated'));
    const alias = join(state, 'team.env.pending');
    symlinkSync(join(state, 'team.env'), alias);
    assert.match(invoke(...args).stderr, /SETUP_STORAGE_REFUSED/);
    rmSync(alias);
    assert.equal(invoke(...args).status, 0);
    assert.deepEqual(readFileSync(join(state, 'state.json')), complete);
  } finally { rmSync(parent, { recursive: true, force: true }); }
});
