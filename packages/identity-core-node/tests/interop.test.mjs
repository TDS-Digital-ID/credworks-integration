import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { describe, it } from "node:test";

import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";

import {
  installDeterministicTestKey,
  issueSdJwtWithFormat,
  verifySdJwtCredential,
} from "../src/index.ts";

const issuerKeyId = "did:web:issuer.unsw.example.edu.au#interop-issuer";
const holderKeyId = "interop-holder";
const vct = "https://credentials.unsw.example/UniversityEducationCredential";
const issuerPrivateScalar = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index),
).toString("base64url");

describe("identity-core SD-JWT VC interop seam", () => {
  it("round-trips with the independent @sd-jwt/sd-jwt-vc implementation", async () => {
    const issuerJwk = installDeterministicTestKey(issuerKeyId, "issuer");
    const holderJwk = installDeterministicTestKey(holderKeyId, "holder");
    const independent = sdJwtVcInstance({ ...issuerJwk, d: issuerPrivateScalar });
    const payload = interopPayload(holderJwk);
    const disclosureSpecs = [
      { object_path: ["credentialSubject"], claim_name: "enrolled" },
      { object_path: ["credentialSubject"], claim_name: "student_id" },
    ];

    const issuedByCore = issueSdJwtWithFormat({
      payload,
      disclosureSpecs,
      header: { alg: "ES256", typ: "dc+sd-jwt", kid: issuerKeyId },
      keyId: issuerKeyId,
      salts: fixedSalts(2),
      format: "ietf_sd_jwt_vc",
    });
    const verifiedByIndependent = await independent.verify(issuedByCore.compact);

    assert.equal(verifiedByIndependent.header?.typ, "dc+sd-jwt");
    assert.equal(verifiedByIndependent.payload.vct, vct);
    assert.equal(
      verifiedByIndependent.payload.credentialSubject.institution_id,
      "unsw.edu.au",
    );
    assert.equal(verifiedByIndependent.payload.credentialSubject.enrolled, true);

    const issuedByIndependent = await independent.issue(
      payload,
      { credentialSubject: { _sd: ["enrolled", "student_id"] } },
      { header: { kid: issuerKeyId } },
    );
    const verifiedByCore = verifySdJwtCredential({
      compactSdJwt: issuedByIndependent,
      issuerJwk,
      options: {
        now_unix_seconds: 1783000110,
        required_claims: [["credentialSubject", "enrolled"]],
        format: "ietf_sd_jwt_vc",
      },
    });

    assert.equal(verifiedByCore.issuer_header.typ, "dc+sd-jwt");
    assert.equal(verifiedByCore.processed_payload.vct, vct);
    assert.equal(
      verifiedByCore.processed_payload.credentialSubject.institution_id,
      "unsw.edu.au",
    );
    assert.equal(verifiedByCore.processed_payload.credentialSubject.enrolled, true);
  });
});

function sdJwtVcInstance(privateJwk) {
  const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
  const publicKey = createPublicKey(privateKey);
  let saltIndex = 0;
  return new SDJwtVcInstance({
    signer: async (data) =>
      sign("sha256", Buffer.from(data), {
        key: privateKey,
        dsaEncoding: "ieee-p1363",
      }).toString("base64url"),
    verifier: async (data, signature) =>
      verify(
        "sha256",
        Buffer.from(data),
        { key: publicKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(signature, "base64url"),
      ),
    signAlg: "ES256",
    hasher: async (data, alg) => {
      const bytes =
        typeof data === "string"
          ? Buffer.from(data)
          : Buffer.from(new Uint8Array(data));
      return new Uint8Array(createHash(alg.replace("-", "")).update(bytes).digest());
    },
    hashAlg: "sha-256",
    saltGenerator: async () => fixedSalts(8)[saltIndex++ % 8],
  });
}

function interopPayload(holderJwk) {
  return {
    iss: "did:web:issuer.unsw.example.edu.au",
    iat: 1783000000,
    exp: 1883000000,
    vct,
    credentialSubject: {
      institution_id: "unsw.edu.au",
      enrolled: true,
      student_id: "z5555555",
    },
    cnf: { jwk: holderJwk },
  };
}

function fixedSalts(count) {
  return Array.from({ length: count }, (_, index) =>
    Buffer.alloc(16, index).toString("base64url"),
  );
}
