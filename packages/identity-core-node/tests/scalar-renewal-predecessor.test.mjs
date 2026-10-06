import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as core from "../src/index.ts";

const fixture = JSON.parse(
  readFileSync(new URL("../../../vectors/conformance/scalar-definitions.json", import.meta.url), "utf8"),
);
core.installDeterministicTestKey(fixture.header.kid, "issuer:250");
const statusAuthority = {
  key_id: fixture.issuer_header.kid,
  public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(fixture.issuer_jwk),
};
const document = {
  ...fixture.document, iat: 250, exp: 350,
  authorizations: fixture.document.authorizations.map((entry) => ({
    ...entry, key_state: "current", status_authority: statusAuthority,
  })),
};
const signGrant = (payload) => core.signIssuerAuthorizations({
  payload, header: fixture.header, keyId: fixture.header.kid,
});
const verification = {
  compactSdJwt: fixture.compact_credential,
  issuerJwk: fixture.issuer_jwk,
  compactAuthorization: signGrant(document),
  trustAnchorJwk: fixture.anchor,
  registryDid: fixture.document.issuer,
  nowUnixSeconds: 300,
};

test("Node authenticates an expired predecessor for renewal without restoring presentation validity", () => {
  assert.throws(
    () => core.verifyScalarCredentialAuthorization({ ...verification, mode: "complete" }),
    /FRESHNESS_CHECK_FAILED/,
  );
  const result = core.verifyScalarRenewalPredecessor(verification);
  assert.equal(result.processed_payload.iat, 100);
  assert.equal(result.processed_payload.exp, 200);
  assert.equal(result.processed_payload.credentialSubject.member_id, "example-member-42");
});

test("Node renewal requires a current exact grant for current or retained issuer keys", () => {
  for (const key_state of ["current", "retained"]) {
    const grant = {
      ...document,
      authorizations: document.authorizations.map((entry) => ({ ...entry, key_state })),
    };
    assert.equal(core.verifyScalarRenewalPredecessor({
      ...verification, compactAuthorization: signGrant(grant),
    }).issuer_header.kid, fixture.issuer_header.kid);
  }
  for (const nowUnixSeconds of [249, 350]) {
    assert.throws(
      () => core.verifyScalarRenewalPredecessor({ ...verification, nowUnixSeconds }),
      /FRESHNESS_CHECK_FAILED/,
    );
  }
  for (const change of [
    { status: "inactive" },
    { key_state: "withdrawn" },
    { credential_issuer_key_id: "did:web:issuer.example#other" },
    {
      credential_issuer_did: "did:web:other.example",
      credential_issuer_key_id: "did:web:other.example#key",
      status_authority: { ...statusAuthority, key_id: "did:web:other.example#key" },
    },
    {
      credential_issuer_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(fixture.anchor),
      status_authority: { ...statusAuthority, key_id: "did:web:issuer.example#status" },
    },
    { definition: { ...fixture.definition, version: "2" } },
  ]) {
    const compactAuthorization = signGrant({
      ...document,
      authorizations: document.authorizations.map((entry) => ({ ...entry, ...change })),
    });
    assert.throws(
      () => core.verifyScalarRenewalPredecessor({ ...verification, compactAuthorization }),
      /TRUST_CHECK_FAILED/,
    );
  }
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({ ...verification, issuerJwk: fixture.anchor }),
    /INVALID_SIGNATURE/,
  );
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({ ...verification, trustAnchorJwk: fixture.issuer_jwk }),
    /INVALID_SIGNATURE/,
  );
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({ ...verification, registryDid: "did:web:other.example" }),
    /TRUST_CHECK_FAILED/,
  );
});

const segments = fixture.compact_credential.split("~");
const original = JSON.parse(Buffer.from(segments[0].split(".")[1], "base64url").toString());
core.installDeterministicTestKey(fixture.issuer_header.kid, "issuer:251");
const signCredential = (payload) => [
  core.signCompactJwsJson({ payload, header: fixture.issuer_header, keyId: fixture.issuer_header.kid }),
  ...segments.slice(1),
].join("~");

test("Node renewal derives authenticated integer iat and refuses future, absent or invalid values", () => {
  const missing = { ...original };
  delete missing.iat;
  for (const payload of [missing, ...[null, "100", 100.5, true].map((iat) => ({ ...original, iat }))]) {
    const compactSdJwt = signCredential(payload);
    assert.throws(
      () => core.verifyScalarRenewalPredecessor({ ...verification, compactSdJwt }),
      /TRUST_CHECK_FAILED/,
    );
  }
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({
      ...verification,
      compactSdJwt: signCredential({
        ...original, iat: 400, exp: 500,
        validFrom: "1970-01-01T00:06:40Z", validUntil: "1970-01-01T00:08:20Z",
      }),
    }),
    /FRESHNESS_CHECK_FAILED/,
  );
  const jwt = segments[0].split(".");
  jwt[1] = Buffer.from(JSON.stringify({ ...original, iat: 150 })).toString("base64url");
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({ ...verification, compactSdJwt: [jwt.join("."), ...segments.slice(1)].join("~") }),
    /INVALID_SIGNATURE/,
  );
});

test("Node renewal refuses a predecessor valid at receipt time but invalid at signed iat", () => {
  // nbf exceeds the existing 60-second future skew at iat=100, but precedes receipt=180.
  const compactSdJwt = signCredential({ ...original, nbf: 170 });
  const received = core.verifyScalarCredentialAuthorization({
    ...verification,
    compactSdJwt,
    compactAuthorization: signGrant({ ...document, iat: 100 }),
    nowUnixSeconds: 180,
    mode: "complete",
  });
  assert.equal(received.processed_payload.nbf, 170);
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({ ...verification, compactSdJwt }),
    /FRESHNESS_CHECK_FAILED/,
  );
});

test("Node renewal retains complete scalar and disclosure validation", () => {
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({ ...verification, compactSdJwt: fixture.disclosed_credential }),
    /INVALID_INPUT/,
  );
  assert.throws(
    () => core.verifyScalarRenewalPredecessor({
      ...verification,
      compactSdJwt: signCredential({
        ...original, credentialSubject: { ...original.credentialSubject, visits: "2" },
      }),
    }),
    /INVALID_INPUT/,
  );
});
