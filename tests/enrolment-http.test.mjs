import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as core from "@unsw-vc/identity-core-node";
import { presentEnrolment } from "../tool/education-http.ts";
import { httpClient } from "../tool/http-client.mjs";

test("actual signed enrolment HTTP refuses late evidence and wrong scope/location before signing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kit-enrolment-"));
  const did = "did:web:enrolment.example",
    keyId = did + "#request";
  const key = core.persistentSigningKey({
    path: join(dir, "request.key"),
    unlockKey: core.randomUrlSafe(32),
    keyId,
    create: true,
  });
  const anchorId = "did:web:registry.example#anchor";
  const anchor = core.persistentSigningKey({
    path: join(dir, "anchor.key"),
    unlockKey: core.randomUrlSafe(32),
    keyId: anchorId,
    create: true,
  });
  const claims = ["family_name", "given_name", "date_of_birth"].map((field) => [
    "credentialSubject",
    field,
  ]);
  const payload = {
    client_id: "decentralized_identifier:" + did,
    nonce: core.randomUrlSafe(32),
    response_type: "vp_token",
    response_mode: "direct_post",
    response_uri: "https://enrolment.example/response",
    aud: "https://self-issued.me/v2",
    iat: 100,
    exp: 110,
    state: core.randomUrlSafe(32),
    dcql_query: {
      credentials: [
        {
          id: "enrolment_government_identity",
          format: "vc+sd-jwt",
          meta: {
            type_values: [
              [
                "https://www.w3.org/2018/credentials#VerifiableCredential",
                "GovernmentIdentityCredential",
              ],
            ],
          },
          claims: claims.map((path) => ({ path })),
        },
      ],
    },
  };
  const trust = core.signTrustList({
    keyId: anchorId,
    header: { alg: "ES256", typ: "trust-list+jwt", kid: anchorId },
    payload: {
      id: "https://registry.example/trust-list.jwt",
      issuer: "did:web:registry.example",
      iat: 100,
      exp: 200,
      entries: [
        {
          issuer_did: "did:web:government.example",
          credential_types: ["GovernmentIdentityCredential"],
          status: "active",
          public_jwk: anchor,
        },
      ],
      verifiers: [
        {
          verifier_did: did,
          credential_type: "GovernmentIdentityCredential",
          profile_name: "enrolment_government_identity",
          claim_paths: claims,
          status: "active",
        },
      ],
    },
  });
  let request = payload,
    clock = 100,
    late = false,
    posts = 0,
    signs = 0;
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      join(dir, "tls.key"),
      "-out",
      join(dir, "tls.pem"),
      "-days",
      "1",
      "-subj",
      "/CN=enrolment.example",
      "-addext",
      "subjectAltName=DNS:enrolment.example,DNS:registry.example",
      "-addext",
      "extendedKeyUsage=serverAuth",
    ],
    { stdio: "ignore" },
  );
  const ca = readFileSync(join(dir, "tls.pem"));
  const server = createServer(
    { key: readFileSync(join(dir, "tls.key")), cert: ca },
    (req, res) => {
      if (req.method === "POST") {
        posts++;
        res.end("{}");
        return;
      }
      if (req.url === "/request")
        res.end(
          core.signCompactJwsJson({
            keyId,
            header: { alg: "ES256", typ: "oauth-authz-req+jwt", kid: keyId },
            payload: request,
          }),
        );
      else if (req.url === "/.well-known/did.json")
        res.end(JSON.stringify(core.buildDidWebDocument(did, [key])));
      else {
        if (late) clock = 110;
        res.end(trust);
      }
    },
  );
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const transport = httpClient(
    {
      ca,
      port: server.address().port,
      lookup: (_host, opts, callback) =>
        opts.all
          ? callback(null, [{ address: "127.0.0.1", family: 4 }])
          : callback(null, "127.0.0.1", 4),
    },
    undefined,
    () => clock,
  );
  const text = async (url) =>
    (await transport(url, { headers: { host: new URL(url).host } })).text;
  const post = async (url, body, deadline) =>
    transport(url, {
      method: "POST",
      headers: {
        host: new URL(url).host,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(body).toString(),
      deadline,
    });
  const sign = (input) => {
    signs++;
    return core.presentSdJwt(input);
  };
  try {
    late = true;
    await assert.rejects(
      presentEnrolment(
        { registryOrigin: "https://registry.example", trustAnchorJwk: anchor },
        "https://enrolment.example/request",
        "not-accessed",
        "not-accessed",
        text,
        post,
        () => clock,
        sign,
      ),
      (error) => error.message.startsWith("FRESHNESS_CHECK_FAILED"),
    );
    late = false;
    clock = 100;
    for (const [mutate, expected] of [
      [
        (value) => {
          value.dcql_query.credentials[0].claims.reverse();
        },
        "REQUEST_SCOPE_NOT_PERMITTED",
      ],
      [
        (value) => {
          value.dcql_query.credentials[0].meta.type_values[0][1] =
            "UniversityEducationCredential";
        },
        "REQUEST_SCOPE_NOT_PERMITTED",
      ],
      [
        (value) => {
          value.dcql_query.credentials[0].format = "dc+sd-jwt";
        },
        "REQUEST_SCOPE_NOT_PERMITTED",
      ],
      [
        (value) => {
          value.response_uri = "http://127.0.0.1/response";
        },
        "VERIFICATION_FAILED",
      ],
      [
        (value) => {
          value.response_uri += "\u0023fragment";
        },
        "REQUEST_LOCATION_REFUSED",
      ],
      [
        (value) => {
          value.response_uri = "https://other.example/response";
        },
        "BINDING_CHECK_FAILED",
      ],
    ]) {
      request = structuredClone(payload);
      mutate(request);
      await assert.rejects(
        presentEnrolment(
          {
            registryOrigin: "https://registry.example",
            trustAnchorJwk: anchor,
          },
          "https://enrolment.example/request",
          "not-accessed",
          "not-accessed",
          text,
          post,
          () => clock,
          sign,
        ),
        (error) => error.message.split(":")[0] === expected,
      );
    }
    assert.equal(signs, 0);
    assert.equal(posts, 0);
    request = structuredClone(payload);
    const holderKeyId = "holder:kit-test:" + core.randomUrlSafe(16);
    const holder = core.persistentSigningKey({
      path: join(dir, "holder.key"),
      unlockKey: core.randomUrlSafe(32),
      keyId: holderKeyId,
      create: true,
    });
    const government = core.issueSdJwtWithFormat({
      keyId,
      header: { alg: "ES256", typ: "vc+sd-jwt", kid: keyId },
      format: "w3c_vc_data_model",
      payload: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        id: "urn:uuid:kit-government",
        type: ["VerifiableCredential", "GovernmentIdentityCredential"],
        iss: did,
        issuer: did,
        iat: 100,
        exp: 200,
        cnf: { jwk: holder },
        credentialSubject: {
          family_name: "Sandbox",
          given_name: "Holder",
          date_of_birth: "2000-01-01",
        },
      },
      disclosureSpecs: claims.map((path) => ({
        object_path: ["credentialSubject"],
        claim_name: path[1],
      })),
      salts: claims.map(() => core.randomUrlSafe(16)),
    }).compact;
    const success = await presentEnrolment(
      { registryOrigin: "https://registry.example", trustAnchorJwk: anchor },
      "https://enrolment.example/request",
      government,
      holderKeyId,
      text,
      post,
      () => clock,
      sign,
    );
    assert.equal(success.status, 200);
    assert.equal(signs, 1);
    assert.equal(posts, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});
