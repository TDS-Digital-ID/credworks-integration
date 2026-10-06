import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as core from "../src/index.ts";
const fixture = JSON.parse(
  readFileSync("../../vectors/conformance/structured-definitions.json", "utf8"),
);
const verify = (compactSdJwt, mode = "complete") =>
  core.verifyScalarCredentialAuthorization({
    compactSdJwt,
    mode,
    issuerJwk: fixture.issuer_jwk,
    compactAuthorization: fixture.compact_authorization,
    trustAnchorJwk: fixture.anchor,
    registryDid: fixture.document.issuer,
    nowUnixSeconds: 150,
  });
test("Node authenticates exact nested names and complete structured values from the portable credential", () => {
  core.validateScalarDefinition(fixture.definition);
  core.validateScalarSubject({
    definition: fixture.definition,
    subject: fixture.subject,
    mode: "complete",
  });
  const subject = verify(fixture.compact_credential).processed_payload
    .credentialSubject;
  assert.equal(subject.left.name, "North");
  assert.equal(subject.right.name, "South");
  assert.deepEqual(subject.details, fixture.subject.details);
  assert.deepEqual(subject.entries, fixture.subject.entries);
  for (const row of fixture.presentations) {
    const result = core.verifySdJwtPresentation({
      presentation: row.presentation,
      issuerJwk: fixture.issuer_jwk,
      options: {
        audience: "https://verifier.example",
        nonce: row.nonce,
        now_unix_seconds: 150,
        max_kb_age_seconds: 60,
        required_claims: row.profile.claim_paths,
      },
    });
    const disclosed = verify(row.disclosed_credential, "disclosed")
      .processed_payload.credentialSubject;
    if (row.profile.name === "left_only") {
      assert.equal(
        result.processed_payload.credentialSubject.left.name,
        "North",
      );
      assert.equal(disclosed.right.name, undefined);
      assert.equal(disclosed.details, undefined);
    } else {
      assert.deepEqual(disclosed.details, fixture.subject.details);
      assert.deepEqual(disclosed.entries, fixture.subject.entries);
      assert.equal(disclosed.left.name, undefined);
      assert.equal(disclosed.right.name, undefined);
    }
    assert.throws(() => verify(row.disclosed_credential), /INVALID_INPUT/);
    assert.throws(
      () =>
        core.verifySdJwtPresentation({
          presentation: row.presentation,
          issuerJwk: fixture.issuer_jwk,
          options: {
            audience: "https://verifier.example",
            nonce: "different",
            now_unix_seconds: 150,
            max_kb_age_seconds: 60,
            required_claims: row.profile.claim_paths,
          },
        }),
      /BINDING_CHECK_FAILED/,
    );
  }
});
test("Node refuses ancestor, partial whole-value and array-element signed disclosures", () => {
  for (const token of [
    fixture.overlapping_credential,
    fixture.ancestor_credential,
    fixture.partial_whole_credential,
    fixture.array_element_credential,
  ])
    assert.throws(() => verify(token), /TRUST_CHECK_FAILED/);
});
test("Node preserves semantic versus malformed-JSON refusal codes", () => {
  for (const subject of fixture.invalid_subjects)
    assert.throws(
      () =>
        core.validateScalarSubject({
          definition: fixture.definition,
          subject,
          mode: "complete",
        }),
      /INVALID_INPUT/,
    );
  for (const definition of fixture.invalid_definitions)
    assert.throws(
      () => core.validateScalarDefinition(definition),
      /INVALID_INPUT/,
    );
  for (const definition of fixture.malformed_definitions)
    assert.throws(
      () => core.validateScalarDefinition(definition),
      /JSON_SERIALIZATION/,
    );
});
