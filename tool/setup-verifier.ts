import * as core from '@unsw-vc/identity-core-node';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { randomUUID } from 'node:crypto';
import { httpClient } from './http-client.mjs';
import { openGeneric } from './generic-http.js';
import { exampleConfig } from './setup-issuer.js';

const check = (condition: unknown, code: string) => { if (!condition) throw Error(code); };
function read(path: string) {
  const info = lstatSync(path);
  check(info.isFile() && info.uid === process.getuid?.() && (info.mode & 0o177) === 0, 'SETUP_STORAGE_REFUSED');
  return JSON.parse(readFileSync(path, 'utf8'));
}
export async function configureCustomVerifier(root: string, state: any, issuer: any, atomic: (path: string, bytes: string, mode?: number) => void) {
  const issuerRoot = state.binding.issuerState;
  const config = exampleConfig(issuerRoot, issuer);
  const issuerOwner = read(join(issuerRoot, 'registration-result.json'));
  const verifier = read(join(root, 'registration-result.json'));
  const definition = read(join(issuerRoot, 'custom-definition.json'));
  const request = { verifier_registration_id: verifier.registration.registration_id, profile_name: config.profileName, claim_paths: config.claimPaths };
  const grantUrl = config.registryOrigin + `/api/projects/${issuerOwner.project.project_id}/issuers/${issuerOwner.registration.issuer_registration_id}/adoptions/${definition.adopted.adoption_id}/verifier-grants`;
  const path = join(root, 'custom-permission.json');
  const progress = existsSync(path) ? read(path) : { grantUrl, request };
  check(progress.grantUrl === grantUrl && isDeepStrictEqual(progress.request, request), 'SETUP_PERMISSION_REFUSED');
  const save = () => atomic(path, JSON.stringify(progress, null, 2) + '\n');
  save();
  const call = httpClient();
  if (!progress.granted) {
    const response = await call(grantUrl, { method: 'POST', headers: { authorization: 'Bearer ' + issuerOwner.management_credential, 'content-type': 'application/json' }, body: JSON.stringify(request) });
    check(response.status === 201, 'SETUP_PERMISSION_UNAVAILABLE');
    progress.granted = response.json(); save();
  }
  check(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(progress.granted.grant_id) && progress.granted.permission_url === config.registryOrigin + '/scoped-verifier-permissions/' + progress.granted.grant_id + '.jwt', 'SETUP_PERMISSION_REFUSED');
  const response = await call(progress.granted.permission_url);
  check(response.status === 200, 'SETUP_PERMISSION_UNAVAILABLE');
  const publication = core.verifyCompactJwsJson({ compactJws: response.text, publicJwk: config.trustAnchorJwk }).payload as any;
  check(publication.issuer === config.registryDid && publication.id === progress.granted.permission_url, 'SETUP_PERMISSION_REFUSED');
  core.verifyScopedVerifierPermission({ compactJws: response.text, trustAnchorJwk: config.trustAnchorJwk, request: { credential_issuer_did: issuerOwner.issuerDid, definition_id: config.definitionId, definition_version: config.definitionVersion, credential_type: config.credentialType, verifier_did: verifier.verifierDid, verifier_origin: state.binding.runtimeOrigin, verifier_public_jwk: verifier.verifierPublicJwk, profile_name: config.profileName, claim_paths: config.claimPaths }, nowUnixSeconds: Math.floor(Date.now() / 1000) });
  atomic(join(root, 'public/verifier.json'), JSON.stringify({ issuerDid: issuerOwner.issuerDid, issuerJwk: issuerOwner.issuerPublicJwk, registryOrigin: config.registryOrigin, trustAnchorJwk: config.trustAnchorJwk, maxCacheAgeSeconds: 300, statusSources: [{ url: issuer.binding.runtimeOrigin + '/oid4vci/status/revocation.jwt', purpose: 'revocation', publicJwk: issuerOwner.issuerPublicJwk }], scalar: { registryDid: config.registryDid, issuerKeyId: issuerOwner.keyId, definitions: [{ configurationId: config.configurationId, authorizationId: definition.adopted.adoption_id, definitionId: config.definitionId, definitionVersion: config.definitionVersion, credentialType: config.credentialType, profiles: [{ name: config.profileName, permissionId: progress.granted.grant_id }] }] } }, null, 2) + '\n', 0o644);
}
export async function verifyExample(root: string, state: any, issuer: any) {
  const config = exampleConfig(state.binding.issuerState, issuer);
  const permission = read(join(root, 'custom-permission.json'));
  const receiptPath = join(config.stateDir, 'example-receipt.json');
  check(existsSync(receiptPath), 'SETUP_EXAMPLE_REQUIRED');
  const receipt = read(receiptPath);
  const flow = openGeneric({ ...config, verifierOrigin: state.binding.runtimeOrigin, verifierManagementOrigin: 'http://127.0.0.1:3081', verifierManagementToken: state.managementToken, permissionPath: new URL(permission.granted.permission_url).pathname });
  await flow.fresh(receipt);
  await flow.management('verifier', '/management/evidence/refresh', {});
  const session = await flow.createSession('membership-' + randomUUID(), 'Check synthetic club membership without the club name');
  await flow.present(session, receipt);
  const result = await flow.result(session);
  check(result.status === 'verified' && result.evidence.definition_id === config.definitionId && isDeepStrictEqual(result.evidence.claim_paths, config.claimPaths) && isDeepStrictEqual(result.claims, { member: true }), 'SETUP_VERIFICATION_REFUSED');
  console.log('SOFTWARE_HOLDER_CUSTOM_VERIFIED: {"member":true}. Club name withheld. Authenticated verifier result checked; software development evidence only.');
}
