import { createHash } from 'node:crypto';
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
test("standalone builds default to fixture-free production addon", () => {
  const binding = JSON.parse(
    readFileSync("packages/identity-core-node/package.json"),
  );
  assert.match(binding.scripts["build:native"], /--features partner-runtime/);
  assert.match(binding.scripts["build:test-native"], /native-test/);
  const workspace = readFileSync("Cargo.toml", "utf8");
  assert.doesNotMatch(workspace, /bindings-python|bindings-dart|oidf-/);
});
test('generic distribution resolves issuer protocol and complete packaged migration ledger without private producers', () => {
  const runtime=JSON.parse(readFileSync('apps/partner-runtime/package.json'));
  assert.equal(runtime.dependencies['@unsw-vc/issuer-protocol'],'workspace:*');
  assert(runtime.files.includes('drizzle'));
  const journal=JSON.parse(readFileSync('apps/partner-runtime/drizzle/meta/_journal.json'));
  assert.equal(journal.entries.length,5);
  for(const item of journal.entries) {
    assert(readFileSync(`apps/partner-runtime/drizzle/${item.tag}.sql`).length>0);
    assert(readFileSync(`apps/partner-runtime/drizzle/meta/${String(item.idx).padStart(4,'0')}_snapshot.json`).length>0);
  }
  const migrations=readFileSync('apps/partner-runtime/src/issuer-migrate.ts','utf8');
  assert.match(migrations,/new URL\("\.\.\/drizzle", import.meta.url\)/);
  const runner=readFileSync('tool/test-fixture-addon.mjs','utf8');
  for(const suite of ['issuer-lifecycle','issuer-renewal','linked-issuance','issuer-process','issuer-container','verifier-revocation','issuer-key-authority','structured-definitions','scalar-renewal-predecessor'])assert(runner.includes('"'+suite+'"'));
  assert.match(readFileSync('apps/partner-runtime/Dockerfile','utf8'),/napi build --release --features partner-runtime[^\n]+-- --locked/);
});

test('finite export matches original and transformed hashes and excludes private ecosystem producers', () => {
  const manifest=JSON.parse(readFileSync('provenance/generic-source-files.json'));
  assert.equal(manifest.revision,'5f00a507a892200cf1fd3b857dc875d556f16c17');
  assert.equal(new Set(manifest.files.map(f=>f.path)).size,manifest.files.length);
  for(const file of manifest.files) {
    const hash=createHash('sha256').update(readFileSync(file.path)).digest('hex');
    assert.equal(hash,file.export_sha256,file.path);
    if(file.source_sha256!==hash) assert(file.transformation,file.path);
    if(file.path.startsWith('core/') || file.path==='packages/identity-core-node/src/index.ts') assert.equal(hash,file.source_sha256,file.path);
  }
  for(const path of ['apps/trust-registry','apps/wallet-provider','packages/db','apps/partner-runtime/tests/issuer-registry.test.mjs','apps/partner-runtime/tests/issuer-rotation-http.test.mjs','apps/partner-runtime/tests/registered-setup.test.mjs']) assert.equal(existsSync(path),false,path);
  for(const directory of ['apps/partner-runtime/src','apps/partner-runtime/tests','packages/issuer-protocol','tool']) for(const path of readdirSync(directory,{recursive:true})) {
    if(!/\.(?:ts|mjs)$/.test(path))continue;
    const source=readFileSync(directory+'/'+path,'utf8');
    assert.doesNotMatch(source,/(?:from\s*["']|import\s*\(["'])[^"']*(?:trust-registry|wallet-provider|packages\/db)\//,path);
  }
  assert.equal(JSON.parse(readFileSync('provenance/source-files.json')).revision,'14096ed41ee259e81414fcfa0c3b2ad622a5b426');
});
