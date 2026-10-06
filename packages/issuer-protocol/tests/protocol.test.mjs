import assert from "node:assert/strict";
import { test } from "node:test";
import * as core from "@unsw-vc/identity-core-node";
import {
  verifyHolderProof,
  verifyWalletInstanceAttestation,
  IssuerProtocolError,
} from "../src/index.ts";
test("shared issuance checks retain exact proof and WIA audience, holder and freshness boundaries", () => {
  const holderId = "shared-protocol-holder",
    holder = core.installDeterministicTestKey(holderId, "holder");
  const providerId = "did:web:shared-provider.example#key-1",
    provider = core.installDeterministicTestKey(providerId, "issuer:242");
  const origin = "https://shared-issuer.example",
    now = 2000000000;
  const proof = core.signCompactJwsJson({
    header: { alg: "ES256", typ: "openid4vci-proof+jwt", kid: holderId },
    payload: { aud: origin, nonce: "nonce", iat: now },
    keyId: holderId,
  });
  const proofInput = {
    core,
    proofJwt: proof,
    holderPublicJwk: holder,
    expectedAudience: origin,
    nowUnixSeconds: now,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 5,
  };
  assert.equal(verifyHolderProof(proofInput), "nonce");
  assert.throws(
    () =>
      verifyHolderProof({
        ...proofInput,
        expectedAudience: "https://other.example",
      }),
    new IssuerProtocolError("proof audience is invalid"),
  );
  assert.throws(
    () => verifyHolderProof({ ...proofInput, nowUnixSeconds: now + 301 }),
    new IssuerProtocolError(
      "proof issued-at is outside the accepted freshness window",
    ),
  );
  const wia = core.signCompactJwsJson({
    header: {
      alg: "ES256",
      typ: "wallet-instance-attestation+jwt",
      kid: providerId,
    },
    payload: {
      iss: "did:web:shared-provider.example",
      aud: origin,
      iat: now,
      exp: now + 60,
      cnf: { jwk: holder },
      attestation_method: "mock_platform_attestation",
    },
    keyId: providerId,
  });
  const wiaInput = {
    core,
    compactJws: wia,
    providerPublicJwk: provider,
    providerDid: "did:web:shared-provider.example",
    expectedAudience: origin,
    holderPublicJwk: holder,
    nowUnixSeconds: now,
  };
  assert.equal(
    verifyWalletInstanceAttestation(wiaInput),
    "mock_platform_attestation",
  );
  const bypass = core.signCompactJwsJson({
    header: {
      alg: "ES256",
      typ: "wallet-instance-attestation+jwt",
      kid: providerId,
    },
    payload: {
      ...core.verifyCompactJwsJson({ compactJws: wia, publicJwk: provider })
        .payload,
      attestation_method: "dev_bypass",
    },
    keyId: providerId,
  });
  assert.equal(
    verifyWalletInstanceAttestation({ ...wiaInput, compactJws: bypass }),
    "dev_bypass",
  );
  assert.throws(
    () =>
      verifyWalletInstanceAttestation({ ...wiaInput, nowUnixSeconds: now - 1 }),
    new IssuerProtocolError("WIA freshness is invalid"),
  );
  assert.throws(
    () =>
      verifyWalletInstanceAttestation({
        ...wiaInput,
        nowUnixSeconds: now + 60,
      }),
    new IssuerProtocolError("WIA freshness is invalid"),
  );
  assert.throws(
    () =>
      verifyWalletInstanceAttestation({
        ...wiaInput,
        holderPublicJwk: provider,
      }),
    new IssuerProtocolError("WIA holder binding is invalid"),
  );
});
