import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = new URL('../../', import.meta.url);
const contracts = [
  'apps/partner-runtime/openapi.json',
  'apps/education-sign-in/src/public/openapi.json',
];

for (const path of contracts) {
  test(`${path}: published request and response examples satisfy their schemas`, () => {
    const spec = JSON.parse(readFileSync(new URL(path, root), 'utf8'));
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    addFormats(ajv);
    let count = 0;
    for (const [route, methods] of Object.entries(spec.paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        const contents = [operation.requestBody, ...Object.values(operation.responses ?? {})];
        for (const content of contents) {
          for (const media of Object.values(content?.content ?? {})) {
            if (!media.schema) continue;
            const validate = ajv.compile({ ...media.schema, components: spec.components });
            const examples = media.examples ? Object.values(media.examples).map(e => e.value) : [];
            if (Object.hasOwn(media, 'example')) examples.push(media.example);
            for (const value of examples) {
              assert(validate(value), `${method} ${route}: ${ajv.errorsText(validate.errors)}`);
              count++;
            }
          }
        }
      }
    }
    assert(count >= 6, 'The reference needs concrete request and response examples.');
  });
}

test('the result examples distinguish HTTP delivery from verification and consumption', () => {
  const spec = JSON.parse(readFileSync(new URL(contracts[0], root), 'utf8'));
  const responses = spec.paths['/management/sessions/{session_id}/result'].post.responses;
  const examples = status => responses[status].content['application/json'].examples;
  assert.equal(examples('200')?.verified?.value.status, 'verified');
  assert.equal(examples('200')?.statusRefused?.value.status, 'refused');
  assert.equal(examples('200')?.statusRefused?.value.error.code, 'STATUS_CHECK_FAILED');
  assert.equal(examples('200')?.freshnessRefused?.value.error.code, 'FRESHNESS_CHECK_FAILED');
  assert.equal(examples('409')?.pending?.value.error.code, 'RESULT_PENDING');
  assert.equal(examples('409')?.consumed?.value.error.code, 'RESULT_CONSUMED');
  assert.equal(examples('410')?.expired?.value.error.code, 'SESSION_EXPIRED');
});
