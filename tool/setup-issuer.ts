import * as core from '@unsw-vc/identity-core-node';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { httpClient } from './http-client.mjs';
import { openGeneric, type GenericConfig } from './generic-http.js';

const check = (value: unknown, code: string) => { if (!value) throw Error(code); };
const read = (path: string) => {
  const info = lstatSync(path);
  check(info.isFile() && info.uid === process.getuid?.() && (info.mode & 0o177) === 0, 'SETUP_STORAGE_REFUSED');
  return JSON.parse(readFileSync(path, 'utf8'));
};
const uuid = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
export async function configureIssuer(root: string, state: any, atomic: (path: string, bytes: string) => void) {
  const owner = read(join(root, 'registration-result.json'));
  const e = state.ecosystem;
  check(e.providerDid === core.didWebFromHost(new URL(e.providerOrigin).host), 'SETUP_TRUST_INPUT_REFUSED');
  core.publicJwkSha256Thumbprint(e.providerJwk);
  const definition = {
    id: state.binding.runtimeOrigin + '/definitions/club-membership', version: '1',
    credential_type: 'SyntheticClubMembership', label: 'Synthetic club membership', max_validity_seconds: 3600,
    claims: [
      { name: 'member', label: 'Member', value_type: 'boolean', required: true },
      { name: 'club', label: 'Club', value_type: 'string', required: true },
    ],
    profiles: [{ name: 'membership', claim_paths: [['credentialSubject', 'member']] }],
  };
  core.validateScalarDefinition(definition as core.ScalarCredentialDefinition);
  const path = join(root, 'custom-definition.json');
  const progress = existsSync(path) ? read(path) : { definition };
  check(isDeepStrictEqual(progress.definition, definition), 'SETUP_DEFINITION_REFUSED');
  const save = () => atomic(path, JSON.stringify(progress, null, 2) + '\n');
  save();
  const call = httpClient();
  const ownerUrl = e.registryOrigin + `/api/projects/${owner.project.project_id}/issuers/${owner.registration.issuer_registration_id}`;
  const post = async (suffix: string, body: unknown) => {
    const response = await call(ownerUrl + suffix, { method: 'POST', headers: { authorization: 'Bearer ' + owner.management_credential, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    check(response.status === 201, 'SETUP_DEFINITION_UNAVAILABLE');
    return response.json();
  };
  // Both registry operations accept the same immutable request again after response loss.
  if (!progress.registered) { progress.registered = await post('/definitions', { definition }); save(); }
  check(uuid(progress.registered.definition_record_id) && progress.registered.metadata_url === e.registryOrigin + '/definitions/' + progress.registered.definition_record_id + '.json', 'SETUP_DEFINITION_REFUSED');
  if (!progress.adopted) { progress.adopted = await post('/adoptions', { definition_record_id: progress.registered.definition_record_id }); save(); }
  check(uuid(progress.adopted.adoption_id) && progress.adopted.authorization_url === e.registryOrigin + '/issuer-authorizations/' + progress.adopted.adoption_id + '.jwt', 'SETUP_DEFINITION_REFUSED');
  const authorization = await call(progress.adopted.authorization_url);
  check(authorization.status === 200, 'SETUP_SIGNED_EVIDENCE_UNAVAILABLE');
  const publication = core.verifyCompactJwsJson({ compactJws: authorization.text, publicJwk: e.trustAnchorJwk }).payload as any;
  check(publication.issuer === e.registryDid && publication.id === progress.adopted.authorization_url, 'SETUP_SIGNED_EVIDENCE_REFUSED');
  const authority = core.verifyIssuerAuthorization({ compactJws: authorization.text, trustAnchorJwk: e.trustAnchorJwk, request: { credential_issuer_did: owner.issuerDid, credential_issuer_key_id: owner.keyId, credential_issuer_public_jwk: owner.issuerPublicJwk, definition_id: definition.id, definition_version: '1', credential_type: definition.credential_type, registry_did: e.registryDid, purpose: 'issuance' }, nowUnixSeconds: Math.floor(Date.now() / 1000) });
  check(isDeepStrictEqual(authority.definition, definition), 'SETUP_DEFINITION_REFUSED');
  atomic(join(root, 'issuer.json'), JSON.stringify({
    databaseUrl: `postgres://credworks:${state.databasePassword}@issuer-db:5432/partner_issuer`,
    registryOrigin: e.registryOrigin, registryDid: e.registryDid, trustAnchorJwk: e.trustAnchorJwk,
    walletProviderDid: e.providerDid, walletProviderJwk: e.providerJwk,
    definitions: [{ configurationId: 'club-membership', authorizationId: progress.adopted.adoption_id, definitionId: definition.id, definitionVersion: '1', credentialType: definition.credential_type }],
  }, null, 2) + '\n');
}
export async function issuerReady(root: string, state: any) {
  const progress = read(join(root, 'custom-definition.json'));
  const response = await httpClient()(state.binding.runtimeOrigin + '/.well-known/openid-credential-issuer');
  check(response.status === 200, 'SETUP_ISSUER_UNAVAILABLE');
  const metadata = response.json();
  const supported = metadata.credential_configurations_supported?.['club-membership'];
  check(metadata.credential_issuer === state.binding.runtimeOrigin && supported?.credentialDefinition?.id === progress.definition.id && supported.credworks_issuer_authorization?.path === '/issuer-authorizations/' + progress.adopted.adoption_id + '.jwt', 'SETUP_ISSUER_CONFIGURATION_REFUSED');
}
export function exampleConfig(root: string, state: any): GenericConfig {
  const progress = read(join(root, 'custom-definition.json'));
  const owner = read(join(root, 'registration-result.json'));
  const e = state.ecosystem;
  return { registryOrigin: e.registryOrigin, registryDid: e.registryDid, trustAnchorJwk: e.trustAnchorJwk, providerOrigin: e.providerOrigin, providerDid: e.providerDid, providerJwk: e.providerJwk,
    issuerOrigin: state.binding.runtimeOrigin, issuerManagementOrigin: 'http://127.0.0.1:3081', issuerManagementToken: state.managementToken,
    // The existing driver requires verifier fields; issuance never requests their permissions or routes.
    verifierOrigin: state.binding.runtimeOrigin, verifierManagementOrigin: 'http://127.0.0.1:3081', verifierManagementToken: state.managementToken,
    stateDir: join(root, 'software-holder'), configurationId: 'club-membership', definitionId: progress.definition.id, definitionVersion: '1', credentialType: progress.definition.credential_type,
    profileName: 'membership', claimPaths: [['credentialSubject', 'member']], authorizationPath: '/issuer-authorizations/' + progress.adopted.adoption_id + '.jwt', permissionPath: '/scoped-verifier-permissions/' + progress.adopted.adoption_id + '.jwt', statusKeyId: owner.keyId, statusPublicJwk: owner.issuerPublicJwk,
  };
}
export async function revokeExample(root: string, state: any) {
  const path = join(root, 'software-holder/example-receipt.json');
  check(existsSync(path), 'SETUP_EXAMPLE_REQUIRED');
  const receipt = read(path), config = exampleConfig(root, state);
  const flow = openGeneric(config);
  const verified = core.verifyScalarCredentialAuthorization({ compactSdJwt: receipt.compact, issuerJwk: receipt.issuerJwk, compactAuthorization: receipt.authorization, trustAnchorJwk: config.trustAnchorJwk, registryDid: config.registryDid, nowUnixSeconds: receipt.observedAt, mode: 'complete' });
  check((verified.processed_payload as any).id === config.issuerOrigin + '/credentials/' + receipt.issuanceId, 'BINDING_CHECK_FAILED');
  if (!(await flow.status(receipt)).revoked) await flow.revoke(receipt.issuanceId);
  check((await flow.status(receipt)).revoked, 'STATUS_CHECK_FAILED');
  console.log('SYNTHETIC_EXAMPLE_REVOKED: Only the saved example credential was revoked. Its receipt and holder key are retained. Verification must now refuse it.');
}
export async function issueExample(root: string, state: any) {
  await issuerReady(root, state);
  const flow = openGeneric(exampleConfig(root, state));
  let attempt: any;
  try { attempt = flow.load('example'); } catch (error: any) { if (error.code !== 'ENOENT') throw error; }
  if (!attempt) {
    const now = Math.floor(Date.now() / 1000);
    attempt = { phase: 'creating-offer', input: { claims: { member: true, club: 'Example Robotics Club' }, valid_from: now, valid_until: now + 3600, offer_expires_at: now + 600 } };
    flow.save('example', attempt);
    attempt.offer = await flow.createOffer(attempt.input);
    attempt.phase = 'offered'; flow.save('example', attempt);
  }
  check(attempt.phase === 'offered' && attempt.offer, 'SETUP_OFFER_OUTCOME_UNKNOWN');
  const receipt = await flow.receive(attempt.offer, 'example-delivery');
  await flow.fresh(receipt);
  if (!existsSync(join(root, 'software-holder/example-receipt.json'))) flow.save('example-receipt', receipt);
  console.log('SOFTWARE_HOLDER_RECEIPT_VERIFIED: Synthetic club membership received and stored. Issuer authority, holder binding and live status verified by the shared Rust core. This is a software-holder development check, not Android acceptance.');
}
