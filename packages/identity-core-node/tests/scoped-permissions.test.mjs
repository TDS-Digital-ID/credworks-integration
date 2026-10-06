import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  installDeterministicTestKey,
  publicJwkSha256Thumbprint,
  signScopedVerifierPermissions,
  verifyScopedVerifierPermission,
  verifyTrustList,
  verifyVerifierTrustListAccreditation,
} from "../src/index.ts";
const fixture = JSON.parse(
  readFileSync(
    "../../vectors/conformance/scoped-verifier-permissions.json",
    "utf8",
  ),
);

test("Node signs scoped permissions with an opaque handle and verifies the portable fixture", () => {
  const anchor = installDeterministicTestKey(fixture.header.kid, "issuer:254");
  const compactJws = signScopedVerifierPermissions({
    payload: fixture.document,
    header: fixture.header,
    keyId: fixture.header.kid,
  });
  assert.deepEqual(anchor, fixture.anchor);
  assert.deepEqual(
    verifyScopedVerifierPermission({
      compactJws,
      trustAnchorJwk: anchor,
      request: fixture.request,
      nowUnixSeconds: 150,
    }).claim_paths,
    [
      ["credentialSubject", "enrolled"],
      ["credentialSubject", "institution_id"],
    ],
  );
  assert.equal(
    verifyScopedVerifierPermission({
      compactJws: fixture.compact_jws,
      trustAnchorJwk: anchor,
      request: fixture.request,
      nowUnixSeconds: 150,
    }).active,
    true,
  );
  assert.throws(
    () =>
      verifyScopedVerifierPermission({
        compactJws,
        trustAnchorJwk: anchor,
        request: { ...fixture.request, definition_version: "2" },
        nowUnixSeconds: 150,
      }),
    /TRUST_CHECK_FAILED/,
  );
  assert.throws(
    () => verifyTrustList({ compactJws, trustAnchorJwk: anchor }),
    /TRUST_CHECK_FAILED/,
  );
  assert.throws(
    () =>
      verifyVerifierTrustListAccreditation({
        compactJws,
        trustAnchorJwk: anchor,
        verifierDid: fixture.request.verifier_did,
        credentialType: fixture.request.credential_type,
        profileName: fixture.request.profile_name,
        requestedClaimPaths: fixture.request.claim_paths,
        nowUnixSeconds: 150,
      }),
    /TRUST_CHECK_FAILED/,
  );
});

test("missing scope fields and unknown authority fields never become permissive defaults", () => {
  for (const field of [
    "credential_issuer_did",
    "definition_id",
    "definition_version",
    "verifier_origin",
  ]) {
    const request = { ...fixture.request };
    delete request[field];
    assert.throws(
      () =>
        verifyScopedVerifierPermission({
          compactJws: fixture.compact_jws,
          trustAnchorJwk: fixture.anchor,
          request,
          nowUnixSeconds: 150,
        }),
      /JSON_SERIALIZATION/,
    );
  }
  assert.throws(
    () =>
      signScopedVerifierPermissions({
        payload: { ...fixture.document, operator_override: true },
        header: fixture.header,
        keyId: fixture.header.kid,
      }),
    /JSON_SERIALIZATION/,
  );
  assert.equal(
    publicJwkSha256Thumbprint(fixture.request.verifier_public_jwk),
    fixture.document.permissions[0].verifier_public_jwk_sha256_thumbprint,
  );
});
