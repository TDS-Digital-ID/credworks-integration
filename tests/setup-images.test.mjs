import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

test('prepare downloads the selected archive once and never loads corrupt or unavailable bytes', () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'setup-images-'))), kit = join(root, 'kit'), bin = join(root, 'bin');
  try {
    mkdirSync(kit); mkdirSync(bin);
    for (const file of ['setup', 'config', 'tool']) cpSync(file, join(kit, file), { recursive: true });
    const candidate = JSON.parse(readFileSync(join(kit, 'config/setup-candidate.json')));
    const bytes = Buffer.from('test archive');
    candidate.archives.find(a => a.architecture === 'arm64').size = bytes.length;
    candidate.archives.find(a => a.architecture === 'arm64').sha256 = createHash('sha256').update(bytes).digest('hex');
    writeFileSync(join(kit, 'config/setup-candidate.json'), JSON.stringify(candidate, null, 2));
    writeFileSync(join(bin, 'curl'), `#!${process.execPath}\n${String.raw`
const fs=require('node:fs'),args=process.argv.slice(2);
fs.appendFileSync(process.env.TEST_ROOT+'/downloads',args.at(-1)+'\n');
if(process.env.TEST_FAILURE==='unavailable')process.exit(22);
fs.writeFileSync(args[args.indexOf('--output')+1],process.env.TEST_FAILURE==='checksum'?'bad! archive':'test archive');
`}`, { mode: 0o755 });
    writeFileSync(join(bin, 'docker'), `#!${process.execPath}\n${String.raw`
const fs=require('node:fs'),{spawnSync}=require('node:child_process'),args=process.argv.slice(2),root=process.env.TEST_ROOT,kit=root+'/kit';
if(args[0]==='info'){console.log('linux aarch64');process.exit(0)}
if(args[0]==='compose'&&args[1]==='version')process.exit(0);
if(args[0]==='load'){fs.writeFileSync(root+'/loaded','yes');process.exit(0)}
if(args[0]==='image'){
 if(!fs.existsSync(root+'/loaded'))process.exit(1);
 if(args.includes('--format')){console.log(args.at(-1));process.exit(0)}
 const candidate=JSON.parse(fs.readFileSync(kit+'/config/setup-candidate.json'));
 console.log(JSON.stringify(args.slice(2).map(Id=>({Id,Os:'linux',Architecture:'arm64',Config:{User:'10001:10001',Labels:{'org.opencontainers.image.revision':candidate.sourceRevision}}}))));process.exit(0);
}
if(args[0]==='run'){
 const index=args.indexOf('/partner/operator-kit/tool/setup.mjs');
 const result=spawnSync(process.execPath,[kit+'/tool/setup.mjs',...args.slice(index+1)],{stdio:'inherit'});process.exit(result.status);
}
process.exit(2);
`}`, { mode: 0o755 });
    const run = failure => spawnSync('bash', [join(kit, 'setup'), 'prepare', '--state', join(root, 'state'),
      '--runtime-origin', 'https://verify.team.example', '--app-origin', 'https://app.team.example'],
      { encoding: 'utf8', env: { ...process.env, PATH: bin + ':' + process.env.PATH, TEST_ROOT: root, TEST_FAILURE: failure }, timeout: 15000 });
    for (const failure of ['unavailable', 'checksum']) {
      const result = run(failure);
      assert.notEqual(result.status, 0, result.stderr);
      assert.match(result.stderr, failure === 'checksum' ? /SETUP_IMAGE_CHECKSUM_REFUSED/ : /SETUP_IMAGE_DOWNLOAD_FAILED/);
      assert(!existsSync(join(root, 'loaded')));
      assert(!existsSync(join(root, 'state/state.json')));
    }
    let result = run('');
    assert.equal(result.status, 0, result.stderr);
    const downloads = readFileSync(join(root, 'downloads'), 'utf8');
    assert(downloads.split('\n').filter(Boolean).every(url => url.endsWith('-arm64.tar')));
    const state = readFileSync(join(root, 'state/state.json'));
    result = run('');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(join(root, 'downloads'), 'utf8'), downloads);
    assert.deepEqual(readFileSync(join(root, 'state/state.json')), state);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
