import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

test('one-command course setup confirms once, resumes the same identity and opens only after eligibility passes', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'setup-up-'))), kit = join(root, 'kit'), bin = join(root, 'bin'), state = join(root, 'state');
  const credentials = { TunnelID: '11111111-1111-4111-8111-111111111111', AccountTag: 'a'.repeat(32), TunnelSecret: Buffer.alloc(32, 7).toString('base64') };
  const bundle = { version: 1, group: 'banana', runtimeOrigin: 'https://banana-verify.course.example', appOrigin: 'https://banana-app.course.example', accountId: credentials.AccountTag, tunnelId: credentials.TunnelID, credentials };
  try {
    mkdirSync(kit); mkdirSync(bin);
    for (const file of ['setup', 'config', 'tool']) cpSync(file, join(kit, file), { recursive: true });
    const bundlePath = join(kit, 'team.json');
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o644 });
    writeFileSync(join(bin, 'open'), `#!${process.execPath}\nrequire('node:fs').writeFileSync(process.env.TEST_ROOT+'/opened',process.argv[2]);\n`, { mode: 0o755 });
    writeFileSync(join(bin, 'cloudflared'), `#!${process.execPath}\nrequire('node:fs').writeFileSync(process.env.TEST_ROOT+'/account-called','yes');process.exit(1);\n`, { mode: 0o755 });
    // Docker is external. The setup helper still performs actual validation and protected state writes.
    writeFileSync(join(bin, 'docker'), `#!${process.execPath}\n${String.raw`
const fs=require('node:fs'),{spawnSync}=require('node:child_process'),args=process.argv.slice(2),root=process.env.TEST_ROOT,kit=root+'/kit';
if(args[0]==='info'){console.log('linux arm64');process.exit(0)}
if(args[0]==='image'){
 if(args.includes('--format')){console.log(args.at(-1));process.exit(0)}
 const candidate=JSON.parse(fs.readFileSync(kit+'/config/setup-candidate.json'));
 console.log(JSON.stringify(args.slice(2).map(Id=>({Id,Os:'linux',Architecture:'arm64',Config:{User:'10001:10001',Labels:{'org.opencontainers.image.revision':candidate.sourceRevision}}}))));process.exit(0);
}
if(args[0]==='run'){
 const i=args.indexOf('/partner/operator-kit/tool/setup.mjs'),command=args[i+1];
 fs.appendFileSync(root+'/commands',command+'\n');
 if(['check-local','check-public','register','configure','ready','eligibility'].includes(command)){
  if(process.env.TEST_FAIL===command){console.error('SETUP_TEST_REFUSED');process.exit(1)}
  console.log(command==='eligibility'?'{"status":"eligible","account":"none"}':'SETUP_TEST_OK');process.exit(0);
 }
 const result=spawnSync(process.execPath,[kit+'/tool/setup.mjs',...args.slice(i+1)],{stdio:['ignore','inherit','inherit']});process.exit(result.status);
}
if(args[0]==='compose'){
 if(args.includes('bootstrap'))fs.appendFileSync(root+'/bootstraps','once\n');
 if(args.includes('ps'))console.log('a'.repeat(64));
 process.exit(0);
}
process.exit(2);
`}`, { mode: 0o755 });
    const run = (input = '', fail = '') => spawnSync('bash', [join(kit, 'setup'), 'up', '--state', state], { input, encoding: 'utf8', env: { ...process.env, PATH: bin + ':' + process.env.PATH, TEST_ROOT: root, TEST_FAIL: fail }, timeout: 20000 });
    for (const input of ['', 'cherry\n']) {
      const result = run(input);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /SETUP_CONFIRMATION_(REQUIRED|REFUSED)/);
      assert(!existsSync(join(state, 'state.json')));
      assert(!existsSync(join(root, 'opened')));
    }
    let result = run('banana\n');
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /TEAM_READY: Eligibility checked/);
    assert.equal(readFileSync(join(root, 'opened'), 'utf8'), bundle.appOrigin);
    const saved = readFileSync(join(state, 'state.json'));
    const original = readFileSync(bundlePath);
    writeFileSync(bundlePath, JSON.stringify({ ...bundle, appOrigin: 'https://banana-app.wrong.example' }));
    assert.equal(run().status, 1);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    writeFileSync(bundlePath, original);
    result = run();
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stdout, /Type banana/);
    assert.deepEqual(readFileSync(join(state, 'state.json')), saved);
    rmSync(bundlePath);
    rmSync(join(root, 'opened'));
    result = run('', 'eligibility');
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stdout, /TEAM_READY/);
    assert(!existsSync(join(root, 'opened')));
    assert.equal(run().status, 0, 'the original bundle is no longer needed');
    assert.equal(readFileSync(join(root, 'bootstraps'), 'utf8'), 'once\n');
    assert(!existsSync(join(root, 'account-called')));
    assert(!existsSync(join(state, '.lock')));
    for (const value of [credentials.TunnelSecret, ...['unlockKey','managementToken','databasePassword'].map(key => JSON.parse(saved)[key])]) assert(!result.stdout.includes(value) && !result.stderr.includes(value));
    symlinkSync(join(root, 'opened'), bundlePath);
    assert.match(run().stderr, /SETUP_STORAGE_REFUSED/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
