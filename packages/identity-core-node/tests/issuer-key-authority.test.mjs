import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as core from "../src/index.ts";
const v = JSON.parse(readFileSync(new URL("../../../vectors/conformance/issuer-key-authority.json", import.meta.url), "utf8"));
const authority = (request, compactJws = v.compact_authorization, nowUnixSeconds = 150) => core.verifyIssuerAuthorization({compactJws,trustAnchorJwk:v.anchor,request,nowUnixSeconds});
const credential = (compactSdJwt, issuerJwk, compactAuthorization = v.compact_authorization) => core.verifyScalarCredentialAuthorization({compactSdJwt,issuerJwk,compactAuthorization,trustAnchorJwk:v.anchor,registryDid:v.document.issuer,nowUnixSeconds:150,mode:"complete"});

test("Node preserves legacy signed document bytes and exact authenticated result fields", () => {
  const legacy = JSON.parse(readFileSync(new URL("../../../vectors/conformance/scalar-definitions.json", import.meta.url), "utf8"));
  core.installDeterministicTestKey(legacy.header.kid,"issuer:250");
  assert.equal(core.signIssuerAuthorizations({payload:legacy.document,header:legacy.header,keyId:legacy.header.kid}),legacy.compact_authorization);
  assert.deepEqual(core.verifyIssuerAuthorization({compactJws:legacy.compact_authorization,trustAnchorJwk:legacy.anchor,request:legacy.request,nowUnixSeconds:150}),legacy.document.authorizations[0]);
});

test("Node authenticates retained/current exact keys and issuance-safe defaults", () => {
  const retained = authority({...v.old_request,purpose:"verification"});
  assert.equal(retained.key_state,"retained");
  assert.deepEqual(retained.status_authority,v.status_authority);
  for (const purpose of [undefined,"issuance"]) {
    assert.throws(() => authority({...v.old_request,...(purpose ? {purpose} : {})}), /TRUST_CHECK_FAILED/);
  }
  assert.equal(authority(v.new_request).key_state,"current");
  for (const [token,key,kid] of [[v.old_credential,v.bootstrap,v.old_request.credential_issuer_key_id],[v.new_credential,v.current,v.new_request.credential_issuer_key_id]]) {
    assert.equal(credential(token,key).issuer_header.kid,kid);
  }
  assert.throws(() => credential(v.old_credential,v.current), /INVALID_SIGNATURE/);
  assert.throws(() => credential(v.old_credential,v.bootstrap,v.withdrawn_authorization), /TRUST_CHECK_FAILED/);
  credential(v.new_credential,v.current,v.withdrawn_authorization);
  assert.throws(() => authority({...v.old_request,purpose:"verification"},v.compact_authorization,200), /FRESHNESS_CHECK_FAILED/);
});

test("Node preserves exact bootstrap status authority and original authenticated negative evidence after credential withdrawal", () => {
  const current = authority(v.new_request,v.withdrawn_authorization);
  const [header,payload] = core.verifyBitstringStatusListCredentialAt({compactJws:v.revoked_status,statusListJwk:v.bootstrap,nowUnixSeconds:150});
  assert.equal(header.kid,current.status_authority.key_id);
  assert.equal(core.publicJwkSha256Thumbprint(v.bootstrap),current.status_authority.public_jwk_sha256_thumbprint);
  assert.equal(payload.issuer,v.old_request.credential_issuer_did);
  assert.throws(() => core.verifyBitstringStatusListCredentialAt({compactJws:v.revoked_status,statusListJwk:v.current,nowUnixSeconds:150}), /INVALID_SIGNATURE/);
  authority({...v.old_request,purpose:"verification"}); // Original grant at observation time, no positive use of the withdrawn grant.
  for (const [compact,revoked] of [[v.active_status,false],[v.revoked_status,true]]) {
    const result = core.resolveCredentialStatusAt({status:v.status,resolverResponses:{[v.status.statusListCredential]:compact},statusListJwk:v.bootstrap,nowUnixSeconds:150});
    assert.equal(result.revoked,revoked);
  }
});

test("Node rejects null and unsupported authority vocabulary with stable binding errors", () => {
  for (const purpose of [null,"historical"]) {
    assert.throws(() => authority({...v.old_request,purpose}), /JSON_SERIALIZATION/);
  }
  core.installDeterministicTestKey("did:web:trust.example#fixture-401","issuer:240");
  for (const state of [null,"retired"]) {
    const payload = structuredClone(v.document);
    payload.authorizations[0].key_state = state;
    assert.throws(() => core.signIssuerAuthorizations({payload,header:{alg:"ES256",typ:"issuer-authorizations+jwt",kid:"did:web:trust.example#fixture-401"},keyId:"did:web:trust.example#fixture-401"}), /JSON_SERIALIZATION/);
  }
});
