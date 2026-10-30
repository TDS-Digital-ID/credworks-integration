import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

test('private starter contains only committed kit files and its validated team, and refuses overwrite or dirty source', () => {
  const root = mkdtempSync(join(tmpdir(), 'package-team-')), kit = join(root, 'kit'), bundlePath = join(root, 'bundle.json'), output = join(root, 'starter.tar.gz');
  try {
    mkdirSync(kit);
    for (const file of ['setup', 'config', 'tool', '.gitignore']) cpSync(file, join(kit, file), { recursive: true });
    const git = (...args) => execFileSync('git', ['-C', kit, ...args], { stdio: ['ignore','pipe','pipe'] });
    git('init'); git('add', '.'); git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-m','reviewed kit');
    writeFileSync(join(kit, 'operator-secret'), 'must not ship');
    const credentials = { TunnelID: '11111111-1111-4111-8111-111111111111', AccountTag: 'a'.repeat(32), TunnelSecret: Buffer.alloc(32, 7).toString('base64') };
    const bundle = { version: 1, group: 'banana', runtimeOrigin: 'https://banana-verify.course.example', appOrigin: 'https://banana-app.course.example', accountId: credentials.AccountTag, tunnelId: credentials.TunnelID, credentials };
    writeFileSync(bundlePath, JSON.stringify(bundle), { mode: 0o600 });
    const run = destination => spawnSync(process.execPath, [join(kit, 'tool/package-team.mjs'), bundlePath, destination], { encoding: 'utf8' });
    let result = run(output);
    assert.equal(result.status, 0, result.stderr);
    assert(!result.stdout.includes(credentials.TunnelSecret));
    assert.equal(statSync(output).mode & 0o777, 0o600);
    execFileSync('tar', ['-xzf', output, '-C', root]);
    assert.deepEqual(JSON.parse(readFileSync(join(root, 'credworks-team/team.json'))), bundle);
    assert.equal(statSync(join(root, 'credworks-team/team.json')).mode & 0o777, 0o600);
    assert(!existsSync(join(root, 'credworks-team/operator-secret')));
    assert.match(readFileSync(join(root, 'credworks-team/START-HERE.txt'), 'utf8'), /run \.\/setup/);
    const before = readFileSync(output);
    assert.equal(run(output).status, 1);
    assert.deepEqual(readFileSync(output), before);
    assert.equal(run(join(kit, 'private.tar.gz')).status, 1);
    writeFileSync(join(kit, 'setup'), 'unreviewed');
    result = run(join(root, 'dirty.tar.gz'));
    assert.equal(result.status, 1);
    assert(!existsSync(join(root, 'dirty.tar.gz')));
  } finally { rmSync(root, { recursive: true, force: true }); }
});
