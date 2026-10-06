import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";

import {
  buildDidWebDocument,
  createKeyProof,
  decryptOid4vciJwe,
  didWebToHttpsUrl,
  encodeBitstringStatusList,
  encryptOid4vciCredentialResponse,
  encryptOid4vciJwe,
  generateOidfEncryptionKey,
  installDeterministicTestKey,
  issueSdJwt,
  plannedIssuerDidWebIdentities,
  presentSdJwt,
  publicJwk,
  oid4vciEncryptionPublicJwk,
  randomUrlSafe,
  resolveCredentialStatus,
  sha256B64Url as coreSha256B64Url,
  signCompactJwsJson,
  signBitstringStatusListCredential,
  statusListSizeReport,
  uc3StudySpaceProfile,
  verifyAttachment,
  verifyBitstringStatusListCredentialAt,
  verifyCredentialStatusActive,
  verifyCompactJwsJson,
  verifyDpopProof,
  verifySdJwtPresentation,
  verifySdJwtPresentationWithDidWeb,
} from "../src/index.ts";

const fixture = JSON.parse(
  readFileSync(
    new URL("../../../usecases/webapp-explainer/example.json", import.meta.url),
    "utf8",
  ),
);

describe("identity-core node binding", () => {
  it("keeps OID4VCI request and response JWE cryptography inside Rust", () => {
    const keyId = "oid4vci-encryption-key";
    installDeterministicTestKey(keyId, "issuer:9");
    const jwk = oid4vciEncryptionPublicJwk(keyId);
    const plaintext = {
      credentials: [{ credential: "synthetic-credential" }],
    };

    const compactJwe = encryptOid4vciCredentialResponse({
      plaintext,
      parameters: { jwk, enc: "A256GCM", zip: "DEF" },
    });
    const decrypted = decryptOid4vciJwe({ compactJwe, keyId });

    assert.deepEqual(decrypted, plaintext);
    assert.equal(compactJwe.split(".").length, 5);
    assert.equal(jwk.alg, "ECDH-ES");
    assert.equal(jwk.use, "enc");
    assert.equal("d" in jwk, false);
    assert.throws(
      () => encryptOid4vciCredentialResponse({
        plaintext,
        parameters: {
          ...{ jwk, enc: "A256GCM" },
          jwk: { ...jwk, d: "private-material-must-not-cross" },
        },
      }),
      /invalid JSON|unknown field|INVALID_KEY/iu,
    );
  });

  it("keeps OID4VCI randomness and JWE key material inside Rust", () => {
    assert.equal(randomUrlSafe(16).length, 22);
    const keyId = "node-wallet-jwe-parity";
    const jwk = generateOidfEncryptionKey(keyId);
    assert.equal("d" in jwk, false);
    const compactJwe = encryptOid4vciJwe({
      plaintext: { accepted: true },
      parameters: { jwk, enc: "A256GCM" },
    });
    assert.deepEqual(decryptOid4vciJwe({ compactJwe, keyId }), {
      accepted: true,
    });
  });

  it("verifies the committed golden UC3 vector through the addon", () => {
    const uc3 = fixture.presentations.uc3_study_space;

    const verified = verifySdJwtPresentation({
      presentation: uc3.sd_jwt_kb,
      issuerJwk: fixture.issuer_public_jwk,
      options: {
        audience: uc3.audience,
        nonce: uc3.nonce,
        now_unix_seconds: uc3.iat + 10,
        max_kb_age_seconds: 300,
        required_claims: uc3StudySpaceProfile().claim_paths,
        expected_typ: "vc+sd-jwt",
      },
    });

    assert.equal(verified.issuer_header.typ, "vc+sd-jwt");
    assert.equal(verified.kb_header.typ, "kb+jwt");
    assert.equal(
      verified.processed_payload.credentialSubject.institution_id,
      "unsw.edu.au",
    );
    assert.equal(verified.processed_payload.credentialSubject.enrolled, true);
    assert.equal(
      verified.processed_payload.credentialSubject.photo_hash,
      undefined,
    );
  });

  it("issues, presents, and verifies a did:web credential through Node", () => {
    const did = "did:web:issuer.unsw.example.edu.au";
    const issuerKeyId = `${did}#issuer-1`;
    const holderKeyId = "holder-1";
    const issuerJwk = installDeterministicTestKey(issuerKeyId, "issuer");
    const holderJwk = installDeterministicTestKey(holderKeyId, "holder");
    const payload = studentPayload(did, holderJwk);
    const issued = issueSdJwt({
      payload,
      disclosureSpecs: studentDisclosureSpecs(),
      header: {
        alg: "ES256",
        typ: "vc+sd-jwt",
        kid: issuerKeyId,
      },
      keyId: issuerKeyId,
      salts: fixedSalts(8),
    });
    const presentation = presentSdJwt({
      compactSdJwt: issued.compact,
      profile: uc3StudySpaceProfile(),
      holderKeyId,
      audience: "https://study-space.example/oid4vp",
      nonce: "node-nonce",
      iat: 1783000100,
    });
    const document = buildDidWebDocument(did, [issuerJwk]);
    const resolverResponses = {
      [didWebToHttpsUrl(did)]: JSON.stringify(document),
    };

    const verified = verifySdJwtPresentationWithDidWeb({
      presentation: presentation.presentation,
      resolverResponses,
      options: {
        audience: "https://study-space.example/oid4vp",
        nonce: "node-nonce",
        now_unix_seconds: 1783000110,
        max_kb_age_seconds: 300,
        required_claims: uc3StudySpaceProfile().claim_paths,
        expected_typ: "vc+sd-jwt",
      },
    });

    assert.equal(issued.disclosures.length, 8);
    assert.equal(verified.processed_payload.iss, did);
    assert.equal(verified.processed_payload.credentialSubject.enrolled, true);
    assert.equal(
      verified.processed_payload.credentialSubject.institution_id,
      "unsw.edu.au",
    );
  });

  it("covers did document, status, key proof, and attachment wrapper calls", () => {
    const issuerKeyId = "issuer-1";
    const issuerJwk = installDeterministicTestKey(issuerKeyId, "issuer");
    const identities = plannedIssuerDidWebIdentities("example.edu.au");
    const document = buildDidWebDocument(identities[0].did, [issuerJwk]);

    assert.equal(identities.length, 5);
    assert.equal(document.id, "did:web:issuer.unsw.example.edu.au");
    assert.equal(
      document.verificationMethod[0].id,
      "did:web:issuer.unsw.example.edu.au#issuer-1",
    );

    const proof = createKeyProof({
      audience: "https://issuer.example",
      nonce: "c-nonce",
      iat: 1783000000,
      keyId: issuerKeyId,
    });
    assert.equal(proof.split(".").length, 3);
    assert.deepEqual(verifyCompactJwsJson({
      compactJws: proof,
      publicJwk: issuerJwk,
    }).payload, {
      aud: "https://issuer.example",
      nonce: "c-nonce",
      iat: 1783000000,
    });
    assert.equal(coreSha256B64Url("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");

    const encodedList = encodeBitstringStatusList(131072, [42]);
    assert.ok(statusListSizeReport(131072, encodedList).encoded_list_bytes < 400);
    const statusList = signBitstringStatusListCredential({
      payload: statusListPayload(encodedList),
      header: {
        alg: "ES256",
        typ: "status-list+jwt",
        kid: issuerKeyId,
      },
      keyId: issuerKeyId,
    });
    const status = statusEntry(42);
    const resolverResponses = {
      [status.statusListCredential]: statusList,
    };

    assert.equal(
      resolveCredentialStatus({
        status,
        resolverResponses,
        statusListJwk: publicJwk(issuerKeyId),
      }).revoked,
      true,
    );
    assert.throws(() =>
      verifyCredentialStatusActive({
        status,
        resolverResponses,
        statusListJwk: publicJwk(issuerKeyId),
      }),
    );
    verifyBitstringStatusListCredentialAt({
      compactJws: statusList,
      statusListJwk: publicJwk(issuerKeyId),
      nowUnixSeconds: 1_783_000_100,
    });
    assert.throws(
      () =>
        verifyBitstringStatusListCredentialAt({
          compactJws: statusList,
          statusListJwk: publicJwk(issuerKeyId),
          nowUnixSeconds: 1_814_400_000,
        }),
      /STATUS_LIST_STALE/u,
    );

    const photoBytes = Buffer.from("mock university photo bytes");
    verifyAttachment(photoBytes, sha256B64Url(photoBytes));
    assert.throws(() => verifyAttachment(Buffer.from("tampered"), sha256B64Url(photoBytes)));
  });

  it("verifies DPoP request and access-token binding entirely through Rust", () => {
    const keyId = "holder-dpop";
    const holderJwk = installDeterministicTestKey(keyId, "holder");
    const accessToken = "opaque-access-token";
    const proof = signCompactJwsJson({
      header: { alg: "ES256", typ: "dpop+jwt", jwk: holderJwk },
      payload: {
        htu: "https://issuer.example/oid4vci/credential",
        htm: "POST",
        iat: 1_783_376_100,
        jti: "dpop-node-proof-1",
        ath: coreSha256B64Url(accessToken),
      },
      keyId,
    });

    const verified = verifyDpopProof({
      compactJws: proof,
      options: {
        expected_htu: "https://issuer.example/oid4vci/credential",
        expected_htm: "POST",
        now_unix_seconds: 1_783_376_120,
        max_age_seconds: 300,
        access_token: accessToken,
      },
    });

    assert.equal(verified.jti, "dpop-node-proof-1");
    assert.deepEqual(verified.public_jwk, holderJwk);
    assert.throws(
      () => verifyDpopProof({
        compactJws: proof,
        options: {
          expected_htu: "https://issuer.example/oid4vci/credential",
          expected_htm: "POST",
          now_unix_seconds: 1_783_376_120,
          max_age_seconds: 300,
          access_token: "different-access-token",
        },
      }),
      /BINDING_CHECK_FAILED/u,
    );
  });
});

function studentPayload(issuer, holderJwk) {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential", "UniversityEducationCredential"],
    iss: issuer,
    issuer,
    iat: 1783000000,
    exp: 1883000000,
    validFrom: "2026-07-01T00:00:00Z",
    validUntil: "2027-07-01T00:00:00Z",
    credentialSubject: {
      institution_id: "unsw.edu.au",
      enrolled: true,
      affiliation: "student",
      family_name: "Citizen",
      given_name: "Avery",
      student_id: "z5555555",
      program: "BSc Computer Science",
      date_of_birth: "2001-02-03",
      photo_hash: "6EoT5S7F9B0x3uYcSO7tmQeI6dAUcFxxS4M1blj6Vb0",
    },
    credentialStatus: statusEntry(42),
    cnf: {
      jwk: holderJwk,
    },
  };
}

function studentDisclosureSpecs() {
  return [
    "enrolled",
    "affiliation",
    "family_name",
    "given_name",
    "student_id",
    "program",
    "date_of_birth",
    "photo_hash",
  ].map((claimName) => ({
    object_path: ["credentialSubject"],
    claim_name: claimName,
  }));
}

function fixedSalts(count) {
  return Array.from({ length: count }, (_, index) =>
    Buffer.alloc(16, index).toString("base64url"),
  );
}

function statusListPayload(encodedList) {
  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/status/v1",
    ],
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: "did:web:issuer.unsw.example.edu.au",
    credentialSubject: {
      id: "https://status.unsw.example/status/1#list",
      type: "BitstringStatusList",
      statusPurpose: "revocation",
      encodedList,
    },
    validFrom: "2026-07-01T00:00:00Z",
    validUntil: "2027-07-01T00:00:00Z",
  };
}

function statusEntry(index) {
  return {
    id: `https://status.unsw.example/status/1#${index}`,
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: String(index),
    statusListCredential: "https://status.unsw.example/status/1",
  };
}

function sha256B64Url(bytes) {
  return createHash("sha256").update(bytes).digest("base64url");
}
