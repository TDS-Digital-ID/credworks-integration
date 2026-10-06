import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const linkedSources=['provenance/GENERIC-TRANSFORMS.md','provenance/GENERIC-ACCEPTANCE.md','apps/partner-runtime/examples','infra/partner','infra/partner-issuer','tool/generic-http.ts'];
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
