/** Run a neutral public-HTTP acceptance against an independently configured ecosystem. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { openGeneric } from './generic-http.js';
try {
    assert.ok(process.argv[2] && process.argv[3], 'CONFIG_AND_INPUT_REQUIRED');
    const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
    const input = JSON.parse(readFileSync(process.argv[3], 'utf8'));
    // An operator may supply a strict CA/DNS/loopback transport for their external sandbox.
    // The module must export client; production defaults use the shipped bounded HTTP client.
    const client = process.argv[4] ? (await import(pathToFileURL(resolve(process.argv[4])).href)).client : undefined;
    if (process.argv[4])
        assert.equal(typeof client, 'function', 'TRANSPORT_CLIENT_REQUIRED');
    const flow = openGeneric(config, client);
    const name = 'acceptance-' + randomUUID();
    const now = Math.floor(Date.now() / 1000);
    await flow.management('verifier', '/management/evidence/refresh', {});
    const offer = await flow.createOffer({ claims: input.claims, valid_from: now, valid_until: now + 1800, offer_expires_at: now + 120 });
    flow.save(name + '-offer', offer);
    const receipt = await flow.receive(offer, name + '-delivery');
    const session = await flow.createSession(name);
    flow.save(name + '-session', session);
    await flow.present(session, receipt);
    const result = await flow.result(session);
    assert.equal(result.status, 'verified');
    assert.equal(result.evidence.definition_id, config.definitionId);
    assert.deepEqual(result.evidence.claim_paths, config.claimPaths);
    assert.deepEqual(result.claims, input.expectedClaims);
    flow.save(name + '-report', { status: 'passed', credentialId: receipt.payload.id, issuerKeyId: receipt.issuerKeyId, sessionId: session.session_id, physical: 'NOT RUN' });
    console.log('GENERIC_PUBLIC_HTTP_ACCEPTANCE_PASSED');
}
catch {
    console.error('GENERIC_PUBLIC_HTTP_ACCEPTANCE_FAILED');
    process.exitCode = 1;
}
