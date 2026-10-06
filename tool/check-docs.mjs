import { readFileSync, readdirSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import assert from 'node:assert/strict';

const root = resolve(process.argv.includes('--root') ? process.argv[process.argv.indexOf('--root') + 1] : '.');
const directory = resolve(root, 'docs/education');
const read = path => readFileSync(resolve(root, path), 'utf8');
const index = JSON.parse(read('docs/education/index.json'));
const heading = text => text.toLowerCase().replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-');
assert.deepEqual([...index].sort((a,b) => a.order-b.order), index, 'DOCS_INDEX_INVALID');
assert.equal(new Set(index.map(p => p.slug)).size, index.length, 'DOCS_INDEX_INVALID');
assert.deepEqual(readdirSync(directory).filter(p => p.endsWith('.md')).sort(), index.map(p => p.slug+'.md').sort(), 'DOCS_INDEX_INVALID');
for (const page of index) {
  assert.match(page.slug, /^[a-z][a-z-]*$/, 'DOCS_INDEX_INVALID');
  const source = read(`docs/education/${page.slug}.md`);
  assert(source.startsWith(`# ${page.title}\n`), 'DOCS_INDEX_INVALID');
  const prose = source.replace(/```[^\n]*\n[\s\S]*?```/g, '');
  for (const [,link] of prose.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    if (/^https:\/\//.test(link)) { assert(!new URL(link).username, 'DOCS_LINK_INVALID'); continue; }
    assert(!/^(?:[a-z]+:|\/\/|\/)/i.test(link), 'DOCS_LINK_INVALID');
    const [file,fragment] = link.split('#');
    const target = resolve(directory, file || page.slug+'.md');
    assert(!relative(root,target).startsWith('..'), 'DOCS_LINK_INVALID');
    let contents;
    try { contents = readFileSync(target,'utf8'); } catch { throw Error('DOCS_LINK_INVALID: '+link); }
    if (fragment) assert([...contents.matchAll(/^#+ (.+)$/gm)].some(m => heading(m[1]) === fragment), 'DOCS_LINK_INVALID: '+link);
  }
}
const api = read('docs/education/api.md');
const contracts = {runtime:'apps/partner-runtime/openapi.json', application:'apps/education-sign-in/src/public/openapi.json'};
function validate(value,schema,spec) {
  if(schema.$ref) schema=spec.components.schemas[schema.$ref.split('/').at(-1)];
  if(schema.type==='object') {
    assert(value && typeof value==='object' && !Array.isArray(value),'DOCS_EXAMPLE_INVALID');
    for(const key of schema.required||[]) assert(key in value,'DOCS_EXAMPLE_INVALID');
    if(schema.additionalProperties===false) for(const key of Object.keys(value)) assert(key in (schema.properties||{}),'DOCS_EXAMPLE_INVALID');
    for(const [key,item] of Object.entries(value)) if(schema.properties?.[key]) validate(item,schema.properties[key],spec);
  }
  if(schema.type==='string') {
    assert.equal(typeof value,'string','DOCS_EXAMPLE_INVALID');
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
    assert(api.includes(row),'DOCS_CONTRACT_INVALID: '+row);
    const marker=`# contract ${name} ${method.toUpperCase()} ${route}\n`;
    const blocks=[...api.matchAll(/```sh\n([\s\S]*?)```/g)].map(m=>m[1]).filter(b=>b.startsWith(marker));
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
  }
}
console.log('EDUCATION_DOCS_VALID');
