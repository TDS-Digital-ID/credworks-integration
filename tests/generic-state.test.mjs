import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync, chmodSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { openGeneric } from '../tool/generic-http.ts';
test('software holder resumes the same Rust-managed identity and refuses exposed state', () => {
    const stateDir = mkdtempSync(join(tmpdir(), 'vc408-holder-'));
    const jwk = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'A'.repeat(43) };
    const config = { registryOrigin: 'https://registry.example', registryDid: 'did:web:registry.example', trustAnchorJwk: jwk, providerOrigin: 'https://provider.example', providerDid: 'did:web:provider.example', providerJwk: jwk, issuerOrigin: 'https://issuer.example', issuerManagementOrigin: 'http://127.0.0.1:29280', issuerManagementToken: 'protected-test-only', verifierOrigin: 'https://verifier.example', verifierManagementOrigin: 'http://127.0.0.1:29281', verifierManagementToken: 'protected-test-only', stateDir, configurationId: 'entitlement', definitionId: 'https://issuer.example/definitions/entitlement', definitionVersion: '1', credentialType: 'NeutralEntitlement', profileName: 'check', claimPaths: [['credentialSubject', 'enabled']], authorizationPath: '/issuer-authorizations/00000000-0000-4000-8000-000000000001.jwt', permissionPath: '/scoped-verifier-permissions/00000000-0000-4000-8000-000000000002.jwt', statusKeyId: 'did:web:issuer.example#key-1', statusPublicJwk: jwk };
    try {
        const first = openGeneric(config);
        first.save('operation', { originalDeadline: 17, values: { enabled: false, score: 0 } });
        const resumed = JSON.parse(execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `import {openGeneric} from './tool/generic-http.ts';const flow=openGeneric(${JSON.stringify(config)});console.log(JSON.stringify({holder:flow.holder,keyId:flow.holderKeyId,operation:flow.load('operation')}));`], { encoding: 'utf8' }));
        assert.deepEqual(resumed.holder, first.holder);
        assert.equal(resumed.keyId, first.holderKeyId);
        const second = first;
        assert.deepEqual(second.load('operation'), { originalDeadline: 17, values: { enabled: false, score: 0 } });
        assert.equal(statSync(join(stateDir, 'holder.json')).mode & 0o777, 0o600);
        assert.equal(statSync(join(stateDir, 'operation.json')).mode & 0o777, 0o600);
        chmodSync(join(stateDir, 'operation.json'), 0o644);
        assert.throws(() => second.load('operation'), { message: 'PRIVATE_STATE_REFUSED' });
        assert.throws(() => first.save('../escape', {}), { message: 'PRIVATE_STATE_REFUSED' });
        unlinkSync(join(stateDir, 'holder.key'));
        assert.throws(() => openGeneric(config), { message: 'PRIVATE_STATE_REFUSED' });
        chmodSync(stateDir, 0o755);
        assert.throws(() => openGeneric(config), { message: 'PRIVATE_STATE_REFUSED' });
    }
    finally {
        rmSync(stateDir, { recursive: true, force: true });
    }
});
