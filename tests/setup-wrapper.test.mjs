import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
const kit = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const helper = join(kit, 'tool/setup.mjs');

test('saved setup ignores ambient Compose configuration while preserving Docker authorization context', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-wrapper-'));
  const state = join(parent, 'team'), bin = join(parent, 'bin');
  try {
    mkdirSync(bin);
    const prepared = spawnSync(process.execPath, [helper, 'prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example', '--architecture', 'arm64', '--kit-root', kit], { encoding: 'utf8' });
    assert.equal(prepared.status, 0, prepared.stderr);
    const saved = readFileSync(join(state, 'state.json'));
    // Docker is the external boundary. Setup's real helper still reads and validates its files.
    writeFileSync(join(bin, 'docker'), `#!${process.execPath}\n${String.raw`
const {spawnSync}=require('node:child_process');
const {readFileSync}=require('node:fs');
const args=process.argv.slice(2), kit=process.env.TEST_KIT;
if(args[0]==='info') {console.log('linux arm64');process.exit(0)}
if(args[0]==='image') {
 if(args.includes('--format')) {console.log(args.at(-1));process.exit(0)}
 const candidate=JSON.parse(readFileSync(kit+'/config/setup-candidate.json'));
 console.log(JSON.stringify(args.slice(2).map(Id=>({Id,Os:'linux',Architecture:'arm64',Config:{User:'10001:10001',Labels:{'org.opencontainers.image.revision':candidate.sourceRevision}}}))));process.exit(0);
}
if(args[0]==='run') {
 const index=args.indexOf('/partner/operator-kit/tool/setup.mjs');
 const child=spawnSync(process.execPath,[kit+'/tool/setup.mjs',...args.slice(index+1)],{stdio:'inherit'});process.exit(child.status);
}
if(args[0]==='compose' && args[1]==='version') process.exit(0);
if(args[0]==='compose' && args.at(-1)==='stop') {
 if(Object.keys(process.env).some(key=>/^(PARTNER_|EDUCATION_)/.test(key))) { console.error('COMPOSE_AMBIENT_CONFIG_LEAK');process.exit(1); }
 if(process.env.DOCKER_CONTEXT!=='retained-context') {console.error('DOCKER_AUTH_CONTEXT_LOST');process.exit(1)}
 process.exit(0);
}
process.exit(2);
`}`, { mode: 0o755 });
    const result = spawnSync('bash', [join(kit, 'setup'), 'stop', '--state', state], { encoding: 'utf8', env: { ...process.env, PATH: bin + ':' + process.env.PATH, TEST_KIT: kit, DOCKER_CONTEXT: 'retained-context', PARTNER_ORIGIN: 'https://wrong.example', PARTNER_UNLOCK_KEY: 'wrong-secret', PARTNER_ISSUER_CONFIG: '/unexpected/issuer.json', EDUCATION_APP_IMAGE: 'wrong-image', PARTNER_HOST_PORT: '9999' }, timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /SETUP_STOPPED/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    assert(!result.stdout.includes('wrong-secret'));
  } finally { rmSync(parent, { recursive: true, force: true }); }
});

test('resume refuses preparation-only flags before any Docker or Cloudflare operation', () => {
  const result = spawnSync('bash', [join(kit, 'setup'), 'resume', '--state', '/unused/private/path', '--runtime-origin', 'https://changed.example'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /SETUP_ARGUMENTS_REFUSED/);
});

test('loaded archive image identities prepare and repeat without replacing the saved binding', () => {
  const parent = mkdtempSync(join(tmpdir(), 'setup-import-'));
  const state = join(parent, 'team'), bin = join(parent, 'bin');
  const partner = 'sha256:9fd6aabe535529c5e7a94c02bbb28d837a3d8d9fc2266d05e2cff65e5b0a39d2';
  const application = 'sha256:68bb7faf4b72fbc94cf28f2df4e7584fbf33d5726ba251019b1729b7c5f1d594';
  try {
    mkdirSync(bin);
    writeFileSync(join(bin, 'docker'), `#!${process.execPath}\n${String.raw`
const {spawnSync}=require('node:child_process');
const {readFileSync}=require('node:fs');
const args=process.argv.slice(2), kit=process.env.TEST_KIT;
const candidate=JSON.parse(readFileSync(kit+'/config/setup-candidate.json'));
const allowed=[process.env.TEST_PARTNER,process.env.TEST_APPLICATION];
if(process.env.TEST_BUILDER==='1') allowed.push(candidate.platforms.arm64.partner,candidate.platforms.arm64.application);
if(args[0]==='info') {console.error('private diagnostic: tool version is outdated');console.log('linux arm64');process.exit(0)}
if(args[0]==='compose' && args[1]==='version') process.exit(0);
if(args[0]==='image') {
 const ids=args.filter(arg=>arg.startsWith('sha256:'));
 if(ids.some(id=>!allowed.includes(id))) process.exit(1);
 if(args.includes('--format')) {console.log(ids[0]);process.exit(0)}
 console.log(JSON.stringify(ids.map(Id=>({Id,Os:'linux',Architecture:process.env.TEST_WRONG_ARCH?'amd64':'arm64',Config:{User:'10001:10001',Labels:{'org.opencontainers.image.revision':candidate.sourceRevision}}}))));process.exit(0);
}
if(args[0]==='run') {
 const index=args.indexOf('/partner/operator-kit/tool/setup.mjs');
 const child=spawnSync(process.execPath,[kit+'/tool/setup.mjs',...args.slice(index+1)],{stdio:'inherit'});process.exit(child.status);
}
process.exit(2);
`}`, { mode: 0o755 });
    const env = { ...process.env, PATH: bin + ':' + process.env.PATH, TEST_KIT: kit, TEST_PARTNER: partner, TEST_APPLICATION: application };
    const args = [join(kit, 'setup'), 'prepare', '--state', state, '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example'];
    let result = spawnSync('bash', args, { encoding: 'utf8', env, timeout: 15000 });
    assert.equal(result.status, 0, result.stderr);
    assert(![result.stdout, result.stderr].some(value => value.includes('private diagnostic')));
    const before = readFileSync(join(state, 'state.json'));
    assert.equal(JSON.parse(before).binding.partnerImage, partner);
    assert.equal(JSON.parse(before).binding.appImage, application);
    result = spawnSync('bash', args, { encoding: 'utf8', env: { ...env, TEST_BUILDER: '1' }, timeout: 15000 });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    const candidate = JSON.parse(readFileSync(join(kit, 'config/setup-candidate.json')));
    result = spawnSync('bash', args, { encoding: 'utf8', env: { ...env, TEST_PARTNER: candidate.platforms.arm64.partner, TEST_APPLICATION: candidate.platforms.arm64.application }, timeout: 15000 });
    assert.equal(result.status, 1, 'an available alias must not replace the unavailable saved binding');
    assert.deepEqual(readFileSync(join(state, 'state.json')), before);
    result = spawnSync('bash', args.map(v => v === state ? join(parent, 'wrong') : v), { encoding: 'utf8', env: { ...env, TEST_WRONG_ARCH: '1' }, timeout: 15000 });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_IMAGE_REFUSED/);
    const issuer = join(parent, 'issuer'), verifier = join(parent, 'verifier');
    const issuerPrepared = spawnSync(process.execPath, [helper, 'prepare', '--state', issuer, '--role', 'issuer', '--runtime-origin', 'https://issuer.team.example', '--architecture', 'arm64', '--kit-root', kit], { encoding: 'utf8' });
    assert.equal(issuerPrepared.status, 0, issuerPrepared.stderr);
    const verifierArgs = [join(kit, 'setup'), 'prepare', '--role', 'verifier', '--state', verifier, '--runtime-origin', 'https://custom.team.example', '--issuer-state', issuer];
    result = spawnSync('bash', verifierArgs, { encoding: 'utf8', env, timeout: 15000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(existsSync(join(issuer, '.lock')), false);
    assert.equal(existsSync(join(verifier, '.lock')), false);
    mkdirSync(join(issuer, '.lock'));
    result = spawnSync('bash', [join(kit, 'setup'), 'doctor', '--state', verifier], { encoding: 'utf8', env, timeout: 15000 });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SETUP_BUSY/);
    assert.equal(existsSync(join(issuer, '.lock')), true, 'must preserve another operation lock');
    assert.equal(existsSync(join(verifier, '.lock')), false, 'must release only its own lock');
  } finally { rmSync(parent, { recursive: true, force: true }); }
});
