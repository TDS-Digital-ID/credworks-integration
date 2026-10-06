import { readFileSync, readdirSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import assert from 'node:assert/strict';

const root = resolve(process.argv.includes('--root') ? process.argv[process.argv.indexOf('--root') + 1] : '.');
const read = path => readFileSync(resolve(root, path), 'utf8');
const heading = text => text.toLowerCase().replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-');
const partnerPages = ['overview', 'quickstart', 'definitions', 'api', 'operations'];
const slugs = new Set();
for (const section of ['education', 'partner']) {
  const directory = resolve(root, 'docs/'+section);
  let index;
  try { index = JSON.parse(read('docs/'+section+'/index.json')); } catch { throw Error('DOCS_INDEX_INVALID'); }
  assert(Array.isArray(index), 'DOCS_INDEX_INVALID');
  assert.deepEqual([...index].sort((a,b) => a.order-b.order), index, 'DOCS_INDEX_INVALID');
  assert.equal(new Set(index.map(p => p.slug)).size, index.length, 'DOCS_INDEX_INVALID');
  if (section === 'partner') {
    assert.deepEqual(index.map(p => p.slug), partnerPages.map(p => 'partner-'+p), 'DOCS_INDEX_INVALID');
    assert.deepEqual(index.map(p => p.source), partnerPages.map(p => p+'.md'), 'DOCS_INDEX_INVALID');
  }
  const filename = page => section === 'partner' ? page.source : page.slug+'.md';
  assert.deepEqual(readdirSync(directory).filter(p => p.endsWith('.md')).sort(), index.map(filename).sort(), 'DOCS_INDEX_INVALID');
  for (const page of index) {
    assert.match(page.slug, /^[a-z][a-z-]*$/, 'DOCS_INDEX_INVALID');
    assert(!slugs.has(page.slug), 'DOCS_INDEX_INVALID'); slugs.add(page.slug);
    const source = read('docs/'+section+'/'+filename(page));
    assert(source.startsWith(`# ${page.title}\n`), 'DOCS_INDEX_INVALID');
  }
}

function checkLinks(directory) {
 for (const entry of readdirSync(directory, {withFileTypes:true})) {
  if (['.git','node_modules','target','native','native-test','.logs','.artifacts','.cache','.next'].includes(entry.name)) continue;
  const path = resolve(directory, entry.name);
  if (entry.isDirectory()) { checkLinks(path); continue; }
  if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
  const name = entry.name;
  const source = readFileSync(path, 'utf8');
  const prose = source.replace(/```[^\n]*\n[\s\S]*?```/g, '');
  for (const [,link] of prose.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    if (/^https:\/\//.test(link)) { const url = new URL(link); assert(!url.username && !url.password, 'DOCS_LINK_INVALID'); continue; }
    assert(!/^(?:[a-z]+:|\/\/|\/)/i.test(link), 'DOCS_LINK_INVALID');
    const [file,fragment] = link.split('#');
    const target = resolve(directory, file || name);
    assert(!relative(root,target).startsWith('..'), 'DOCS_LINK_INVALID');
    let contents;
    try { contents = readFileSync(target,'utf8'); } catch { throw Error('DOCS_LINK_INVALID: '+link); }
    if (fragment) assert([...contents.matchAll(/^#+ (.+)$/gm)].some(m => heading(m[1]) === fragment), 'DOCS_LINK_INVALID: '+link);
  }
 }
}
checkLinks(root);

const api = read('docs/education/api.md');
const partnerApi = read('docs/partner/api.md');
const contracts = {runtime:'apps/partner-runtime/openapi.json', application:'apps/education-sign-in/src/public/openapi.json'};
const educationOperations = new Set([
  'GET /.well-known/did.json', 'GET /oid4vp/request/{capability}',
  'POST /oid4vp/response/{capability}', 'POST /management/sign',
  'POST /management/sessions', 'GET /management/sessions/{session_id}',
  'POST /management/sessions/{session_id}/result', 'POST /management/evidence/refresh',
]);
const generic = JSON.parse(read('tool/examples/partner-runtime-http.json'));
const keys = generic.map(example => example.method+' '+example.path);
assert.equal(new Set(keys).size, keys.length, 'DOCS_CONTRACT_PARTITION_INVALID');
assert(keys.every(key => !educationOperations.has(key)), 'DOCS_CONTRACT_PARTITION_INVALID');
const runtime = JSON.parse(read(contracts.runtime));
const actual = Object.entries(runtime.paths).flatMap(([route, operations]) => Object.keys(operations).map(method => method.toUpperCase()+' '+route)).sort();
assert.deepEqual([...educationOperations, ...keys].sort(), actual, 'DOCS_CONTRACT_PARTITION_INVALID');
function validate(value,schema,spec) {
  if(schema.$ref) schema=spec.components.schemas[schema.$ref.split('/').at(-1)];
  if(schema.oneOf) {
    const matches=schema.oneOf.filter(option => { try { validate(value,option,spec); return true; } catch { return false; } });
    assert.equal(matches.length,1,'DOCS_EXAMPLE_INVALID'); return;
  }
  if('const' in schema) assert.deepEqual(value,schema.const,'DOCS_EXAMPLE_INVALID');
  if(schema.type==='array') {
    assert(Array.isArray(value),'DOCS_EXAMPLE_INVALID');
    assert(value.length >= (schema.minItems||0) && value.length <= (schema.maxItems||Infinity),'DOCS_EXAMPLE_INVALID');
    for(const item of value) validate(item,schema.items,spec);
  }
  if(schema.type==='boolean') assert.equal(typeof value,'boolean','DOCS_EXAMPLE_INVALID');
  if(schema.type==='number'||schema.type==='integer') {
    assert(typeof value==='number' && Number.isFinite(value),'DOCS_EXAMPLE_INVALID');
    if(schema.type==='integer') assert(Number.isInteger(value),'DOCS_EXAMPLE_INVALID');
    if(schema.minimum!==undefined) assert(value>=schema.minimum,'DOCS_EXAMPLE_INVALID');
    if(schema.maximum!==undefined) assert(value<=schema.maximum,'DOCS_EXAMPLE_INVALID');
  }
  if(schema.type==='object') {
    assert(value && typeof value==='object' && !Array.isArray(value),'DOCS_EXAMPLE_INVALID');
    for(const key of schema.required||[]) assert(key in value,'DOCS_EXAMPLE_INVALID');
    if(schema.additionalProperties===false) for(const key of Object.keys(value)) assert(key in (schema.properties||{}),'DOCS_EXAMPLE_INVALID');
    for(const [key,item] of Object.entries(value)) {
      if(schema.properties?.[key]) validate(item,schema.properties[key],spec);
      else if(schema.additionalProperties && typeof schema.additionalProperties==='object') validate(item,schema.additionalProperties,spec);
    }
  }
  if(schema.type==='string') {
    assert.equal(typeof value,'string','DOCS_EXAMPLE_INVALID');
    if(schema.pattern) assert(new RegExp(schema.pattern).test(value),'DOCS_EXAMPLE_INVALID');
    if(schema.minLength) assert(value.length>=schema.minLength,'DOCS_EXAMPLE_INVALID');
    if(schema.maxLength) assert(value.length<=schema.maxLength,'DOCS_EXAMPLE_INVALID');
  }
  if(schema.enum) assert(schema.enum.includes(value),'DOCS_EXAMPLE_INVALID');
}
for (const [name,path] of Object.entries(contracts)) {
  const spec=JSON.parse(read(path));
  for(const [route,operations] of Object.entries(spec.paths)) for(const [method,operation] of Object.entries(operations)) {
    const media=Object.keys(operation.requestBody?.content||{}).join(',')||'-';
    const security=[...new Set((operation.security||spec.security||[]).flatMap(s=>Object.keys(s)))].sort();
    const row=`| ${method.toUpperCase()} | ${route} | ${media} | ${security.join(',')||'-'} |`;
    const example=name==='runtime'&&!educationOperations.has(method.toUpperCase()+' '+route) ? generic.find(e=>e.method===method.toUpperCase()&&e.path===route) : undefined;
    if(example) { assert.equal(example.media,media,'DOCS_EXAMPLE_MEDIA_INVALID'); assert.deepEqual(example.security,security,'DOCS_EXAMPLE_SECURITY_INVALID'); }
    else assert(api.includes(row),'DOCS_CONTRACT_INVALID: '+row);
    const marker=`# contract ${name} ${method.toUpperCase()} ${route}\n`;
    const blocks=example ? [marker+example.curl] : [...api.matchAll(/```sh\n([\s\S]*?)```/g)].map(m=>m[1]).filter(b=>b.startsWith(marker));
    assert.equal(blocks.length,1,'DOCS_EXAMPLE_MISSING: '+marker);
    const curl=blocks[0].slice(marker.length);
    assert(curl.includes(`-X ${method.toUpperCase()}`)&&curl.includes(route),'DOCS_EXAMPLE_INVALID');
    for(const scheme of security) {
      const s=spec.components.securitySchemes[scheme];
      assert(curl.includes(s.type==='http'?'Authorization: Bearer':s.in==='cookie'?'browser.cookies':s.name+':'),'DOCS_EXAMPLE_SECURITY_INVALID');
    }
    if(name==='application' && method==='post') assert(curl.includes('Origin: $APP') && curl.includes('X-CSRF-Token: $CSRF'), 'DOCS_EXAMPLE_SECURITY_INVALID');
    if(media!=='-') {
      assert(curl.includes('Content-Type: '+media),'DOCS_EXAMPLE_MEDIA_INVALID');
      const schema=operation.requestBody.content[media].schema;
      if(media==='application/json') {
        const data=curl.match(/--data '([^']*)'/);
        assert(data,'DOCS_EXAMPLE_BODY_MISSING'); validate(JSON.parse(data[1]),schema,spec);
      } else {
        for(const key of schema.required||[]) assert(curl.includes(`--data-urlencode ${key==='state'?'"':"'"}${key}=`),'DOCS_EXAMPLE_BODY_INVALID');
      }
    }
    if(name==='runtime') {
      assert(partnerApi.includes(row),'DOCS_CONTRACT_INVALID: '+row);
      assert(partnerApi.includes('\n## '+method.toUpperCase()+' '+route+'\n'),'DOCS_CONTRACT_INVALID: '+route);
      const narrative=[...partnerApi.matchAll(/```sh\n([\s\S]*?)```/g)].map(m=>m[1]).filter(b=>b.startsWith(marker));
      assert.equal(narrative.length,1,'DOCS_EXAMPLE_MISSING: '+marker);
      assert.equal(narrative[0].slice(marker.length).trim(),blocks[0].slice(marker.length).trim(),'DOCS_EXAMPLE_DRIFT: '+marker);
    }
  }
}
console.log('EDUCATION_DOCS_VALID PARTNER_DOCS_VALID');
