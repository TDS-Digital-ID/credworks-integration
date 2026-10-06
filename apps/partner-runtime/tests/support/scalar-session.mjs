import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as core from "@unsw-vc/identity-core-node";
import { openIdentity, startRuntime } from "../../src/runtime.ts";
export async function fixture({
  maxAge = 30,
  authorityTTL = 300,
  permissionTTL = 300,
  statusTTL = 300,
  prepareState,
  retainedKeys = false,
  separateStatusKey = false,
  issuerDid: configuredIssuerDid,
  statusUrl: configuredStatusUrl,
} = {}) {
  const root = await mkdtemp(join(tmpdir(), "vc372-scalar-"));
  let now = Math.floor(Date.now() / 1000);
  const config = {
    origin:
      "https://verifier" +
      core
        .randomUrlSafe(16)
        .replace(/[^a-z0-9]/gi, "")
        .toLowerCase() +
      ".example",
    stateDir: join(root, "identity"),
    unlockKey: core.randomUrlSafe(32),
    managementToken: core.randomUrlSafe(32),
    publicPort: 0,
    managementPort: 0,
  };
  const identity = openIdentity(config, true);
  const issuerDid = configuredIssuerDid ?? "did:web:issuer372.example",
    issuerKeyId = issuerDid + "#key-1";
  const issuerJwk = core.installDeterministicTestKey(issuerKeyId, "issuer:230");
  const newIssuerKeyId = issuerDid + "#key-2";
  const newIssuerJwk = core.installDeterministicTestKey(newIssuerKeyId, "issuer:234");
  const statusKeyId = separateStatusKey ? issuerDid + "#status" : issuerKeyId;
  const statusJwk = separateStatusKey ? core.installDeterministicTestKey(statusKeyId, "issuer:236") : issuerJwk;
  const registryDid = "did:web:registry372.example",
    registryKeyId = registryDid + "#anchor";
  const anchor = core.installDeterministicTestKey(registryKeyId, "issuer:231");
  const definition = {
    id: "https://issuer372.example/definitions/pass",
    version: "1",
    credential_type: "NeutralPassCredential",
    label: "Neutral pass",
    max_validity_seconds: 3600,
    claims: [
      {
        name: "active",
        label: "Active",
        value_type: "boolean",
        required: true,
      },
      {
        name: "hidden",
        label: "Hidden value",
        value_type: "string",
        required: false,
      },
    ],
    profiles: [
      { name: "neutral_check", claim_paths: [["credentialSubject", "active"]] },
    ],
  };
  const authorizationId = "00000372-0000-4000-8000-000000000001";
  const statusUrl =
    configuredStatusUrl ?? "https://issuer372.example/status/revocation.jwt";
  config.verifier = {
    issuerDid,
    issuerJwk,
    registryOrigin: "https://registry372.example",
    trustAnchorJwk: anchor,
    statusSources: [
      { url: statusUrl, publicJwk: statusJwk, purpose: "revocation" },
    ],
    maxCacheAgeSeconds: maxAge,
    scalar: {
      registryDid,
      issuerKeyId,
      definitions: [
        {
          configurationId: "neutral-pass",
          authorizationId,
          definitionId: definition.id,
          definitionVersion: "1",
          credentialType: definition.credential_type,
          profiles: [
            {
              name: "neutral_check",
              permissionId: "00000372-0000-4000-8000-000000000002",
            },
          ],
        },
      ],
    },
  };
  const permissionsUrl =
    config.verifier.registryOrigin +
    "/scoped-verifier-permissions/00000372-0000-4000-8000-000000000002.jwt";
  const authorityUrl =
    config.verifier.registryOrigin +
    "/issuer-authorizations/" +
    authorizationId +
    ".jwt";
  const evidence = new Map();
  const statusAuthority = { key_id: statusKeyId, public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(statusJwk) };
  const signAuthority = (changes = {}, members) =>
    core.signIssuerAuthorizations({
      keyId: registryKeyId,
      header: {
        alg: "ES256",
        typ: "issuer-authorizations+jwt",
        kid: registryKeyId,
      },
      payload: {
        version: 1,
        id: authorityUrl,
        issuer: registryDid,
        iat: now,
        exp: now + authorityTTL,
        authorizations: members ?? (retainedKeys ? [
          { credential_issuer_did: issuerDid, credential_issuer_key_id: issuerKeyId,
            credential_issuer_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(issuerJwk),
            definition, status: "active", key_state: "retained", status_authority: statusAuthority, ...changes },
          { credential_issuer_did: issuerDid, credential_issuer_key_id: newIssuerKeyId,
            credential_issuer_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(newIssuerJwk),
            definition, status: "active", key_state: "current", status_authority: statusAuthority },
        ] : [
          {
            credential_issuer_did: issuerDid,
            credential_issuer_key_id: issuerKeyId,
            credential_issuer_public_jwk_sha256_thumbprint:
              core.publicJwkSha256Thumbprint(issuerJwk),
            definition,
            status: "active",
            ...changes,
          },
        ]),
      },
    });
  evidence.set(core.didWebToHttpsUrl(issuerDid), JSON.stringify(core.buildDidWebDocument(issuerDid, [
    { ...issuerJwk, kid: issuerKeyId }, { ...newIssuerJwk, kid: newIssuerKeyId },
  ])));
  evidence.set(authorityUrl, signAuthority());
  const signPermission = (changes = {}) =>
    core.signScopedVerifierPermissions({
      keyId: registryKeyId,
      header: {
        alg: "ES256",
        typ: "scoped-verifier-permissions+jwt",
        kid: registryKeyId,
      },
      payload: {
        version: 1,
        id: permissionsUrl,
        issuer: registryDid,
        iat: now,
        exp: now + permissionTTL,
        permissions: [
          {
            credential_issuer_did: issuerDid,
            definition_id: definition.id,
            definition_version: "1",
            credential_type: definition.credential_type,
            verifier_did: identity.did,
            verifier_origin: config.origin,
            verifier_public_jwk_sha256_thumbprint:
              core.publicJwkSha256Thumbprint(identity.publicJwk),
            profile_name: "neutral_check",
            claim_paths: definition.profiles[0].claim_paths,
            status: "active",
            ...changes,
          },
        ],
      },
    });
  evidence.set(permissionsUrl, signPermission());
  evidence.set(
    statusUrl,
    core.signBitstringStatusListCredential({
      keyId: statusKeyId,
      header: { alg: "ES256", typ: "statuslist+jwt", kid: statusKeyId },
      payload: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "BitstringStatusListCredential"],
        issuer: issuerDid,
        validFrom: new Date(now * 1000).toISOString().replace(".000Z", "Z"),
        validUntil: new Date((now + statusTTL) * 1000)
          .toISOString()
          .replace(".000Z", "Z"),
        credentialSubject: {
          id: statusUrl + "#list",
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList: core.encodeBitstringStatusList(131072, []),
        },
      },
    }),
  );
  const dependencies = {
    clock: () => now,
    fetchEvidence: async (url) => {
      if (!evidence.has(url)) throw Error("offline");
      return evidence.get(url);
    },
  };
  let runtime;
  try {
    await prepareState?.({ config, identity });
    runtime = await startRuntime(config, identity, dependencies);
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
  const app = (path, body, capability) =>
    fetch(runtime.management + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        authorization: "Bearer " + config.managementToken,
        "content-type": "application/json",
        ...(capability ? { "x-session-capability": capability } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  return {
    config,
    identity,
    definition,
    issuerDid,
    issuerKeyId,
    issuerJwk,
    newIssuerKeyId,
    newIssuerJwk,
    statusAuthority,
    statusJwk,
    statusKeyId,
    registryDid,
    anchor,
    statusUrl,
    get runtime() {
      return runtime;
    },
    set runtime(value) {
      runtime = value;
    },
    restart: async () => {
      await runtime.close();
      runtime = await startRuntime(config, identity, dependencies);
    },
    app,
    evidence,
    authorityUrl,
    signAuthority,
    signPermission,
    permissionsUrl,
    clock: () => now,
    advance: (seconds) => {
      now += seconds;
    },
    close: async () => {
      await runtime.close();
      await rm(root, { recursive: true, force: true });
    },
  };
}
export async function create(f) {
  const response = await f.app("/management/sessions", {
    configuration_id: "neutral-pass",
    profile: "neutral_check",
    interaction_id: "browser-372",
    purpose: "Check active value",
  });
  assert.equal(response.status, 201, await response.clone().text());
  const session = await response.json();
  const jwt = await (
    await fetch(f.runtime.public + new URL(session.request_uri).pathname)
  ).text();
  const request = core.verifyOid4vpRequestObject({
    compactJws: jwt,
    resolverResponses: {
      [core.didWebToHttpsUrl(f.identity.did)]: JSON.stringify(
        core.buildDidWebDocument(f.identity.did, [f.identity.publicJwk]),
      ),
    },
    nowUnixSeconds: f.clock(),
  }).payload;
  return { session, request };
}
export function presentation(f, request, changes = {}) {
  const holderKeyId = "holder372",
    holder = core.installDeterministicTestKey(holderKeyId, "holder");
  const now = f.clock();
  const payload = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "https://issuer372.example/credentials/test",
    type: ["VerifiableCredential", f.definition.credential_type],
    iss: f.issuerDid,
    issuer: f.issuerDid,
    iat: now,
    exp: now + 300,
    validFrom: new Date(now * 1000).toISOString().replace(".000Z", "Z"),
    validUntil: new Date((now + 300) * 1000)
      .toISOString()
      .replace(".000Z", "Z"),
    cnf: { jwk: holder },
    credentialDefinition: { id: f.definition.id, version: "1" },
    credentialStatus: {
      id: f.statusUrl + "#7",
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "7",
      statusListCredential: f.statusUrl,
    },
    credentialSubject: { active: false, hidden: "private" },
    ...changes.payload,
  };
  const fields = Object.keys(payload.credentialSubject);
  const credential = core.issueSdJwtWithFormat({
    payload,
    keyId: changes.issuerKeyId ?? f.issuerKeyId,
    header: {
      alg: "ES256",
      typ: "vc+sd-jwt",
      kid: changes.issuerKeyId ?? f.issuerKeyId,
    },
    disclosureSpecs: fields.map((claim_name) => ({
      object_path: ["credentialSubject"],
      claim_name,
    })),
    salts: fields.map(() => core.randomUrlSafe(16)),
    format: "w3c_vc_data_model",
  });
  return core.presentSdJwt({
    compactSdJwt: credential.compact,
    profile: {
      name: "neutral_check",
      claim_paths: changes.paths ?? f.definition.profiles[0].claim_paths,
    },
    holderKeyId: changes.holderKeyId ?? holderKeyId,
    audience: changes.audience ?? request.client_id,
    nonce: changes.nonce ?? request.nonce,
    iat: now,
  }).presentation;
}
export async function complete(f, request, token) {
  const response = await fetch(
    f.runtime.public + new URL(request.response_uri).pathname,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        state: request.state,
        vp_token: JSON.stringify({ neutral_check: [token] }),
      }),
    },
  );
  assert.equal(response.status, 200, await response.clone().text());
  assert.deepEqual(await response.json(), { status: "accepted" });
}
export async function consume(f, session) {
  const response = await f.app(
    "/management/sessions/" + session.session_id + "/result",
    {},
    session.correlation_capability,
  );
  assert.equal(response.status, 200, await response.clone().text());
  return response.json();
}
