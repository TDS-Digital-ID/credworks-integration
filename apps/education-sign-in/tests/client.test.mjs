import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { educationClient, Refusal } from '../src/client.ts';

async function fixture(run) {
  let clock = 1000, outcome, pending = false, unavailable = false, mutate = value => value;
  const calls = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    calls.push({ path: req.url, headers: req.headers, body });
    res.setHeader('content-type', 'application/json');
    if (req.url === '/management/sessions') {
      const fields = ['enrolled', 'institution_id', ...(body.profile === 'education_sign_in' ? ['student_id'] : [])];
      outcome = { status: 'verified', interaction_id: body.interaction_id,
        claims: { enrolled: true, institution_id: 'unsw.edu.au', ...(body.profile === 'education_sign_in' ? { student_id: 'synthetic-1' } : {}) },
        evidence: { expires_at: clock + 200, issuer_did: 'did:web:issuer.example', verifier_did: 'did:web:verifier.example',
          credential_type: 'UniversityEducationCredential', definition_id: 'urn:credworks:education', definition_version: '1',
          profile: body.profile, claim_paths: fields.map(field => ['credentialSubject', field]) } };
      res.writeHead(201);
      res.end(JSON.stringify({ interaction_id: body.interaction_id, session_id: 'session', correlation_capability: 'private-capability',
        expires_at: clock + 120, request_uri: 'https://verifier.example/request', activation_uri: 'openid4vp://request' }));
    } else {
      if (unavailable) {
        res.writeHead(503);
        res.end(JSON.stringify({ error: { code: 'SERVICE_UNAVAILABLE' } }));
        return;
      }
      res.writeHead(pending ? 409 : 200);
      res.end(JSON.stringify(pending ? { error: { code: 'RESULT_PENDING' } } : mutate(structuredClone(outcome))));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = educationClient({ runtimeManagement: `http://127.0.0.1:${server.address().port}`, runtimeToken: 'private-token',
    issuer: 'did:web:issuer.example', verifierDid: 'did:web:verifier.example', institution: 'unsw.edu.au' }, () => clock);
  try { await run({ client, calls, advance: seconds => { clock += seconds; }, pending: value => { pending = value; }, unavailable: value => { unavailable = value; }, mutate: fn => { mutate = fn; } }); }
  finally { await new Promise(resolve => server.close(resolve)); }
}
const code = expected => error => error instanceof Refusal && error.code === expected;

test('transient result errors permit retries only before application effects and the original deadline', () => fixture(async ({ client, calls, unavailable, advance }) => {
  let applications = 0;
  const apply = () => { applications++; return 'ok'; };
  const request = await client.create('education_sign_in', () => {});
  unavailable(true);
  await assert.rejects(client.consume(request, apply), code('RUNTIME_UNAVAILABLE'));
  assert.equal(applications, 0);
  unavailable(false);
  assert.equal(await client.consume(request, apply), 'ok');
  await assert.rejects(client.consume(request, apply), code('INTERACTION_CONSUMED'));
  assert.equal(applications, 1);
  const uncertain = await client.create('education_sign_in', () => {});
  await assert.rejects(client.consume(uncertain, () => { applications++; throw Error('commit reply lost'); }), /commit reply lost/);
  await assert.rejects(client.consume(uncertain, apply), code('INTERACTION_CONSUMED'));
  assert.equal(applications, 2);
  const expired = await client.create('education_sign_in', () => {});
  unavailable(true);
  await assert.rejects(client.consume(expired, apply), code('RUNTIME_UNAVAILABLE'));
  const count = calls.length;
  advance(240);
  await assert.rejects(client.consume(expired, apply), code('INTERACTION_EXPIRED'));
  assert.equal(calls.length, count);
  assert.equal(applications, 2);
}));

test('client keeps capabilities server-side, permits pending retries and consumes only once', () => fixture(async ({ client, calls, pending }) => {
  const request = await client.create('education_sign_in', () => {});
  assert(!JSON.stringify(request).includes('private-'));
  pending(true);
  await assert.rejects(client.consume(request, () => assert.fail('pending result reached application')), code('RESULT_PENDING'));
  pending(false);
  const results = await Promise.allSettled([client.consume(request, claims => claims.student_id), client.consume(request, () => assert.fail('duplicate'))]);
  assert.equal(results[0].value, 'synthetic-1');
  assert.equal(results[1].reason.code, 'INTERACTION_CONSUMED');
  assert.equal(calls.at(-1).headers['x-session-capability'], 'private-capability');
  assert.equal(calls.at(-1).headers.authorization, 'Bearer private-token');
  await assert.rejects(client.consume({ ...request }, () => {}), code('INTERACTION_NOT_FOUND'));
}));

test('client checks browser and evidence deadlines across application I/O', () => fixture(async ({ client, advance, mutate }) => {
  const request = await client.create('education_sign_in', () => {});
  await assert.rejects(client.consume(request, () => { advance(200); return 'must-not-login'; }), code('EVIDENCE_STALE'));
  let retired = false;
  const other = await client.create('education_eligibility', () => { if (retired) throw new Refusal('BROWSER_RETIRED', 409); });
  mutate(value => { retired = true; return value; });
  await assert.rejects(client.consume(other, () => assert.fail('retired browser')), code('BROWSER_RETIRED'));
}));

test('client rejects misbound, excessive, stale and policy-refused results before application effects', () => fixture(async ({ client, mutate }) => {
  for (const [change, expected] of [
    [value => { value.interaction_id = 'another-browser'; }, 'RESULT_INVALID'],
    [value => { value.evidence.verifier_did = 'did:web:other.example'; }, 'RESULT_INVALID'],
    [value => { value.claims.student_id = 'overdisclosed'; }, 'RESULT_INVALID'],
    [value => { value.evidence.claim_paths.push(['credentialSubject', 'student_id']); }, 'RESULT_INVALID'],
    [value => { value.evidence.expires_at = 1000; }, 'EVIDENCE_STALE'],
    [value => { value.claims.enrolled = false; }, 'ENROLMENT_REQUIRED'],
    [value => { value.claims.institution_id = 'another.example'; }, 'INSTITUTION_NOT_ALLOWED'],
  ]) {
    const request = await client.create('education_eligibility', () => {});
    mutate(value => { change(value); return value; });
    await assert.rejects(client.consume(request, () => assert.fail('unvalidated result')), code(expected));
    await assert.rejects(client.consume(request, () => {}), code('INTERACTION_CONSUMED'));
  }
}));
