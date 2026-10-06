import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as core from "../src/index.ts";
const fixture = JSON.parse(
  readFileSync("../../vectors/conformance/scalar-definitions.json", "utf8"),
);
const verification = {
  compactSdJwt: fixture.compact_credential,
  issuerJwk: fixture.issuer_jwk,
  compactAuthorization: fixture.compact_authorization,
  trustAnchorJwk: fixture.anchor,
  registryDid: fixture.document.issuer,
  nowUnixSeconds: 150,
  mode: "complete",
};
test("Node verifies portable scalar authority and actual W3C credential; hidden mandatory claims stay hidden", () => {
  core.validateScalarDefinition(fixture.definition);
  core.validateScalarSubject({
    definition: fixture.definition,
    subject: fixture.subject,
    mode: "complete",
  });
  const result = core.verifyScalarCredentialAuthorization(verification);
  assert.equal(result.processed_payload.credentialSubject.member, true);
  assert.equal(
    result.processed_payload.credentialSubject.member_id,
    "example-member-42",
  );
  assert.equal(result.processed_payload.credentialSubject.score, 3.5);
  assert.equal(result.processed_payload.credentialSubject.visits, 2);
  const disclosed = core.verifyScalarCredentialAuthorization({
    ...verification,
    compactSdJwt: fixture.disclosed_credential,
    mode: "disclosed",
  });
  assert.equal(disclosed.processed_payload.credentialSubject.member, true);
  assert.equal(
    disclosed.processed_payload.credentialSubject.member_id,
    undefined,
  );
  assert.throws(
    () =>
      core.verifyScalarCredentialAuthorization({
        ...verification,
        compactSdJwt: fixture.disclosed_credential,
      }),
    /INVALID_INPUT/,
  );
  assert.throws(
    () =>
      core.verifyTrustList({
        compactJws: fixture.compact_authorization,
        trustAnchorJwk: fixture.anchor,
      }),
    /TRUST_CHECK_FAILED/,
  );
});
test("Node signs authority with Rust handle and refuses wrong authority, version, key, future and stale evidence", () => {
  const anchor = core.installDeterministicTestKey(
    fixture.header.kid,
    "issuer:250",
  );
  const signed = core.signIssuerAuthorizations({
    payload: fixture.document,
    header: fixture.header,
    keyId: fixture.header.kid,
  });
  const input = {
    compactJws: signed,
    trustAnchorJwk: anchor,
    request: fixture.request,
    nowUnixSeconds: 150,
  };
  assert.deepEqual(
    core.verifyIssuerAuthorization(input).definition,
    fixture.definition,
  );
  for (const change of [
    { definition_version: "2" },
    { credential_issuer_did: "did:web:other.example" },
    { registry_did: "did:web:other.example" },
    { credential_issuer_key_id: "did:web:issuer.example#another" },
    { credential_issuer_public_jwk: fixture.anchor },
  ]) {
    assert.throws(
      () =>
        core.verifyIssuerAuthorization({
          ...input,
          request: { ...fixture.request, ...change },
        }),
      /TRUST_CHECK_FAILED/,
    );
  }
  for (const nowUnixSeconds of [99, 200])
    assert.throws(
      () => core.verifyIssuerAuthorization({ ...input, nowUnixSeconds }),
      /FRESHNESS_CHECK_FAILED/,
    );
  assert.throws(
    () =>
      core.verifyIssuerAuthorization({
        ...input,
        trustAnchorJwk: fixture.issuer_jwk,
      }),
    /INVALID_SIGNATURE/,
  );
});
test("Node scalar types reject coercion, null, structures, unknown claims and unsafe numeric values", () => {
  for (const subject of [
    { ...fixture.subject, member: "true" },
    { ...fixture.subject, visits: 1.5 },
    { ...fixture.subject, visits: 9007199254740992 },
    { ...fixture.subject, score: Infinity },
    { ...fixture.subject, member_id: null },
    { ...fixture.subject, member_id: [] },
    { ...fixture.subject, member_id: {} },
    { ...fixture.subject, extra: true },
  ]) {
    assert.throws(
      () =>
        core.validateScalarSubject({
          definition: fixture.definition,
          subject,
          mode: "complete",
        }),
      /INVALID_INPUT/,
    );
  }
  core.validateScalarSubject({
    definition: fixture.definition,
    subject: { member: true },
    mode: "disclosed",
  });
});
test("actual signed credential cannot copy authorization fields to override issuer/version/type/key or lifetime", () => {
  core.installDeterministicTestKey(fixture.issuer_header.kid, "issuer:251");
  const segments = fixture.compact_credential.split("~");
  const original = JSON.parse(
    Buffer.from(segments[0].split(".")[1], "base64url").toString(),
  );
  for (const change of [
    { credentialDefinition: { id: fixture.definition.id, version: "2" } },
    { iss: "did:web:other.example", issuer: "did:web:other.example" },
    { type: ["VerifiableCredential", "OtherMembershipCredential"] },
    { credentialDefinition: null },
    { exp: 4000 },
    { validUntil: "1970-01-01T00:03:21Z" },
  ]) {
    const signed = core.signCompactJwsJson({
      payload: { ...original, ...change },
      header: fixture.issuer_header,
      keyId: fixture.issuer_header.kid,
    });
    assert.throws(
      () =>
        core.verifyScalarCredentialAuthorization({
          ...verification,
          compactSdJwt: [signed, ...segments.slice(1)].join("~"),
        }),
      /TRUST_CHECK_FAILED/,
    );
  }
  const wrongKid = core.signCompactJwsJson({
    payload: original,
    header: { ...fixture.issuer_header, kid: "did:web:issuer.example#other" },
    keyId: fixture.issuer_header.kid,
  });
  assert.throws(
    () =>
      core.verifyScalarCredentialAuthorization({
        ...verification,
        compactSdJwt: [wrongKid, ...segments.slice(1)].join("~"),
      }),
    /TRUST_CHECK_FAILED/,
  );
  const hidden = core.issueSdJwt({
    payload: { ...original, credentialSubject: fixture.subject },
    header: fixture.issuer_header,
    keyId: fixture.issuer_header.kid,
    disclosureSpecs: [{ object_path: [], claim_name: "credentialDefinition" }],
    salts: ["AgICAgICAgICAgICAgICAg"],
  });
  assert.throws(
    () =>
      core.verifyScalarCredentialAuthorization({
        ...verification,
        compactSdJwt: hidden.compact,
      }),
    /TRUST_CHECK_FAILED/,
  );
});
