import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const helper = new URL('../tool/setup.mjs', import.meta.url);
const invoke = (...args) => spawnSync(process.execPath, [helper.pathname, ...args], { encoding: 'utf8' });
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
