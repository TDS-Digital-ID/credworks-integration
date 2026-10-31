import { createHash } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const linkedSources=['docs/guides','README.md','LICENSE','DISTRIBUTION.md','apps/partner-runtime/README.md','apps/education-sign-in/src/public/fonts.md','apps/education-sign-in/README.md','apps/education-sign-in/src/client.ts','infra/education-sign-in','docs/setup','config/setup-candidate.json','config/credworks-sandbox-20261011.json','provenance/GENERIC-TRANSFORMS.md','provenance/GENERIC-ACCEPTANCE.md','apps/partner-runtime/examples','infra/partner','infra/partner-issuer','tool/generic-http.ts'];
const run=(root)=>execFileSync(process.execPath,['tool/check-docs.mjs','--root',root],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
test('canonical docs validate real OpenAPI contracts and refuse broken source links',()=>{
 const root=mkdtempSync(join(tmpdir(),'education-docs-'));
 try{
  for(const p of [...linkedSources,'docs/education','docs/partner','apps/partner-runtime/openapi.json','apps/education-sign-in/src/public/openapi.json','tool/examples/partner-runtime-http.json'])cpSync(p,join(root,p),{recursive:true});
  assert.match(run(root),/EDUCATION_DOCS_VALID/);
  const api=join(root,'docs/education/api.md');
  const original=readFileSync(api,'utf8');
  writeFileSync(api,original.replace('Content-Type: application/json','Content-Type: text/plain'));
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_EXAMPLE_MEDIA_INVALID'));
  writeFileSync(api,original);
  const inventory=join(root,'tool/examples/partner-runtime-http.json');
  const entries=JSON.parse(readFileSync(inventory,'utf8'));
  writeFileSync(api,original.replace('# contract runtime POST /management/sign','# removed runtime POST /management/sign'));
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_EXAMPLE_MISSING'));
  writeFileSync(api,original);
  writeFileSync(inventory,JSON.stringify(entries.slice(1)));
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_CONTRACT_PARTITION_INVALID'));
  for(const [field,value,error] of [['media','text/plain','DOCS_EXAMPLE_MEDIA_INVALID'],['security',[],'DOCS_EXAMPLE_SECURITY_INVALID'],['curl',entries.find(e=>e.path==='/management/issuer/offers').curl.replace('"enabled":false','"enabled":null'),'DOCS_EXAMPLE_INVALID']]) {
    const changed=structuredClone(entries); const item=changed.find(e=>e.path==='/management/issuer/offers'); item[field]=value;
    writeFileSync(inventory,JSON.stringify(changed));
    assert.throws(()=>run(root),e=>e.stderr.includes(error));
  }
  writeFileSync(inventory,JSON.stringify(entries));
  const overview=join(root,'docs/education/overview.md');
  const clean=readFileSync(overview,'utf8');
  writeFileSync(overview,clean+'\n[Unsafe](javascript:alert)\n');
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_LINK_INVALID'));
  writeFileSync(overview,clean);
  const page=join(root,'docs/education/overview.md');
  writeFileSync(page,readFileSync(page,'utf8')+'\n[Broken](missing.md)\n');
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_LINK_INVALID'));
 }finally{rmSync(root,{recursive:true,force:true});}
});

test('partner narrative and its finite index are mandatory',()=>{
 const root=mkdtempSync(join(tmpdir(),'partner-docs-'));
 try {
  for(const p of [...linkedSources,'docs/education','apps/partner-runtime/openapi.json','apps/education-sign-in/src/public/openapi.json','tool/examples/partner-runtime-http.json']) cpSync(p,join(root,p),{recursive:true});
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_INDEX_INVALID'));
 } finally { rmSync(root,{recursive:true,force:true}); }
});

test('the public setup index refuses operator material even when its navigation matches',()=>{
 const root=mkdtempSync(join(tmpdir(),'private-docs-'));
 try {
  for(const p of [...linkedSources,'docs/education','docs/partner','apps/partner-runtime/openapi.json','apps/education-sign-in/src/public/openapi.json','tool/examples/partner-runtime-http.json']) cpSync(p,join(root,p),{recursive:true});
  const path=join(root,'docs/setup/index.json');
  const index=JSON.parse(readFileSync(path,'utf8'));
  index.push({slug:'course-operator',title:'Course operator procedures',order:4,source:'operator.md',group:'Run your services'});
  writeFileSync(path,JSON.stringify(index));
  writeFileSync(join(root,'docs/setup/operator.md'),'# Course operator procedures\n');
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_INDEX_INVALID'));
 } finally { rmSync(root,{recursive:true,force:true}); }
});

test('partner docs refuse missing operations, inventory drift and broken cross-section links',()=>{
 const root=mkdtempSync(join(tmpdir(),'partner-docs-'));
 try {
  for(const p of [...linkedSources,'docs/education','docs/partner','apps/partner-runtime/openapi.json','apps/education-sign-in/src/public/openapi.json','tool/examples/partner-runtime-http.json']) cpSync(p,join(root,p),{recursive:true});
  assert.match(run(root),/PARTNER_DOCS_VALID/);
  const api=join(root,'docs/partner/api.md');
  const original=readFileSync(api,'utf8');
  for(const [changed,error] of [
   [original.replace('| POST | /management/issuer/offers | application/json | RuntimeBearer |',''),'DOCS_CONTRACT_INVALID'],
   [original.replace('# contract runtime POST /management/issuer/offers','# removed runtime POST /management/issuer/offers'),'DOCS_EXAMPLE_MISSING'],
   [original.replace('"enabled":false','"enabled":true'),'DOCS_EXAMPLE_DRIFT'],
   [original+'\n[Missing Education section](../education/profiles.md#missing-heading)\n','DOCS_LINK_INVALID'],
   [original+'\n[Unsafe](https://user:secret@example.org/)\n','DOCS_LINK_INVALID'],
  ]) {
   writeFileSync(api,changed);
   assert.throws(()=>run(root),e=>e.stderr.includes(error));
  }
  writeFileSync(api,original);
  const path=join(root,'docs/partner/index.json');
  const index=JSON.parse(readFileSync(path,'utf8'));
  index[0].source='../education/overview.md';
  writeFileSync(path,JSON.stringify(index));
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_INDEX_INVALID'));
 } finally { rmSync(root,{recursive:true,force:true}); }
});

test('standalone entry points refuse missing local targets',()=>{
 const root=mkdtempSync(join(tmpdir(),'kit-docs-'));
 try {
  for(const p of [...linkedSources,'docs/education','docs/partner','apps/partner-runtime/openapi.json','apps/education-sign-in/src/public/openapi.json','tool/examples/partner-runtime-http.json']) cpSync(p,join(root,p),{recursive:true});
  const readme=join(root,'apps/partner-runtime/README.md');
  writeFileSync(readme,'# Runtime\n\n[API](openapi.json)\n[External evidence](https://github.com/TDS-Digital-ID/university-vc-monorepo/issues/435)\n');
  assert.match(run(root),/PARTNER_DOCS_VALID/);
  writeFileSync(readme,readFileSync(readme,'utf8')+'\n[Missing runbook](../../docs/partner/scalar-issuer.md)\n');
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_LINK_INVALID'));
 } finally { rmSync(root,{recursive:true,force:true}); }
});

test('published sandbox configuration is public-only and matches its documented checksum',()=>{
 const bytes=readFileSync('config/credworks-sandbox-20261011.json');
 const config=JSON.parse(bytes);
 assert.deepEqual(Object.keys(config).sort(),['version','observedAt','registryOrigin','registryDid','trustAnchorJwk','portalOrigin','providerOrigin','providerDid','providerJwk','education','government','provenance','compatibility'].sort());
 const key=jwk=>{
  assert.deepEqual(Object.keys(jwk).sort(),['crv','kid','kty','x','y']);
  assert.equal(jwk.kty,'EC'); assert.equal(jwk.crv,'P-256');
  for(const coordinate of [jwk.x,jwk.y]) assert.match(coordinate,/^[A-Za-z0-9_-]{43}$/);
 };
 for(const jwk of [config.trustAnchorJwk,config.providerJwk]) key(jwk);
 for(const name of ['registryOrigin','portalOrigin','providerOrigin']) {
  const url=new URL(config[name]);
  assert.equal(url.protocol,'https:'); assert.equal(url.origin,config[name]);
 }
 assert.equal(config.registryDid,'did:web:'+new URL(config.registryOrigin).host);
 assert.equal(config.providerDid,'did:web:'+new URL(config.providerOrigin).host);
 for(const role of ['education','government']) {
  const issuer=config[role];
  assert.deepEqual(Object.keys(issuer).sort(),(role==='education'?['institution','issuerDid','issuerJwk','statusSources']:['issuerDid','issuerJwk','statusSources']).sort());
  key(issuer.issuerJwk); assert(issuer.issuerJwk.kid.startsWith(issuer.issuerDid+'#'));
  assert.deepEqual(issuer.statusSources.map(s=>s.purpose).sort(),role==='education'?['revocation','suspension']:['revocation']);
  for(const status of issuer.statusSources) {
   assert.deepEqual(Object.keys(status).sort(),['publicJwk','purpose','url']); key(status.publicJwk);
   const url=new URL(status.url); assert.equal(url.protocol,'https:'); assert(!url.username&&!url.password&&!url.search&&!url.hash);
  }
 }
 assert(readFileSync('docs/education/quickstart.md','utf8').includes(createHash('sha256').update(bytes).digest('hex')));
});
