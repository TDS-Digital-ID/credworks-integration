import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const run=(root)=>execFileSync(process.execPath,['tool/check-docs.mjs','--root',root],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
test('canonical docs validate real OpenAPI contracts and refuse broken source links',()=>{
 const root=mkdtempSync(join(tmpdir(),'education-docs-'));
 try{
  for(const p of ['docs/education','apps/partner-runtime/openapi.json','apps/education-sign-in/src/public/openapi.json'])cpSync(p,join(root,p),{recursive:true});
  assert.match(run(root),/EDUCATION_DOCS_VALID/);
  const api=join(root,'docs/education/api.md');
  const original=readFileSync(api,'utf8');
  writeFileSync(api,original.replace('Content-Type: application/json','Content-Type: text/plain'));
  assert.throws(()=>run(root),e=>e.stderr.includes('DOCS_EXAMPLE_MEDIA_INVALID'));
  writeFileSync(api,original);
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
