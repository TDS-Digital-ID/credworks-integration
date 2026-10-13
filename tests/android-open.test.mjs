import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

test('Android launcher refuses ambiguous devices and passes one quoted private intent without disclosure', () => {
  const dir = mkdtempSync(join(tmpdir(), 'android-launch-'));
  const uri = 'openid4vp://authorize?client_id=decentralized_identifier%3Adid%3Aweb%3Aissuer.example&request_uri=https%3A%2F%2Fissuer.example%2Foid4vp%2Fenrolment%2Frequest%2Fsecret';
  const file = join(dir, 'activation');
  writeFileSync(file, uri + '\n', {mode:0o600});
  const adb = join(dir, 'adb');
  writeFileSync(adb, `#!/usr/bin/env bash
if [[ "$1" == devices ]]; then
  printf 'List of devices attached\\n'
  case "$DEVICE_MODE" in one) printf 'test-device\\tdevice\\n';; unauthorized) printf 'test-device\\tunauthorized\\n';; many) printf 'a\\tdevice\\nb\\tdevice\\n';; esac
else
  printf '%s\\n' "$@" > "$ARGUMENT_FILE"
  printf 'Starting: Intent { dat=private-activation }\\n'
fi
`); chmodSync(adb, 0o700);
  const invoke = mode => spawnSync('bash', [new URL('../tool/android-open', import.meta.url).pathname, file], {encoding:'utf8', env:{...process.env,PATH:dir+':'+process.env.PATH,DEVICE_MODE:mode,ARGUMENT_FILE:join(dir,'args')}});
  try {
    for (const mode of ['none','unauthorized','many']) {
      const result = invoke(mode); assert.equal(result.status, 1);
      assert.match(result.stderr, /ANDROID_(DEVICE_REQUIRED|USB_AUTHORIZATION_REQUIRED|ONE_DEVICE_REQUIRED)/);
      assert.equal((result.stdout+result.stderr).includes(uri), false);
    }
    const result = invoke('one'); assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'ANDROID_ACTIVATION_OPENED');
    assert.deepEqual(readFileSync(join(dir,'args'),'utf8').trim().split('\n'), ['shell','am','start','--user','current','-a','android.intent.action.VIEW','-p','au.edu.unsw.vc.unsw_wallet','-d',"'"+uri+"'"]);
    writeFileSync(file, uri+"'; touch /tmp/unsafe\n");
    const refused = invoke('one'); assert.equal(refused.status, 1); assert.match(refused.stderr,/ANDROID_ACTIVATION_REFUSED/);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
