import assert from "node:assert/strict";
import { test } from "node:test";
import * as core from "@unsw-vc/identity-core-node";
import {
  fixture,
  create,
  presentation,
  complete,
  consume,
} from "./support/scalar-session.mjs";
test("scalar session signs explicit issuer, immutable definition and registered exact paths", async () => {
  const f = await fixture();
  try {
    const { request } = await create(f);
    assert.deepEqual(request.credworks_scalar, {
      credential_issuer_did: f.issuerDid,
      credential_issuer_key_id: f.issuerKeyId,
      definition_id: f.definition.id,
      definition_version: "1",
      authorization_path:
        "/issuer-authorizations/00000372-0000-4000-8000-000000000001.jwt",
      permission_path:
        "/scoped-verifier-permissions/00000372-0000-4000-8000-000000000002.jwt",
      profile_name: "neutral_check",
    });
    assert.deepEqual(request.dcql_query.credentials[0].claims, [
      { path: ["credentialSubject", "active"] },
    ]);
    assert.deepEqual(request.dcql_query.credentials[0].meta.type_values, [
      [
        "https://www.w3.org/2018/credentials#VerifiableCredential",
        "NeutralPassCredential",
      ],
    ]);
  } finally {
    await f.close();
  }
});
test("scalar verified result preserves typed false separately from application eligibility and is consumed once", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    await complete(f, request, presentation(f, request));
    const result = await consume(f, session);
    assert.equal(result.status, "verified", JSON.stringify(result));
    assert.deepEqual(result.claims, { active: false });
    assert.equal(result.evidence.definition_id, f.definition.id);
    assert.equal(result.evidence.definition_version, "1");
    assert.equal(result.evidence.issuer_did, f.issuerDid);
    assert.equal(result.evidence.verifier_did, f.identity.did);
    assert.equal(result.evidence.expires_at, f.clock() + 30);
    const replay = await f.app(
      "/management/sessions/" + session.session_id + "/result",
      {},
      session.correlation_capability,
    );
    assert.equal(replay.status, 409);
    assert.deepEqual(await replay.json(), {
      error: { code: "RESULT_CONSUMED" },
    });
  } finally {
    await f.close();
  }
});
test("refresh cannot resurrect a scalar request after its original evidence deadline", async () => {
  const f = await fixture();
  try {
    const { session } = await create(f);
    f.advance(29);
    const refresh = await f.app("/management/evidence/refresh", {});
    assert.equal(refresh.status, 200, await refresh.clone().text());
    f.advance(1);
    const request = await fetch(
      f.runtime.public + new URL(session.request_uri).pathname,
    );
    assert.equal(request.status, 503);
    assert.deepEqual(await request.json(), {
      error: { code: "EVIDENCE_STALE" },
    });
  } finally {
    await f.close();
  }
});
test("scalar HTTP verification refuses issuer, version, type, holder, replay, excess disclosure and value mismatches", async () => {
  const f = await fixture();
  try {
    const otherIssuerKey = "did:web:other372.example#key-1";
    core.installDeterministicTestKey(otherIssuerKey, "issuer:232");
    const otherHolderKey = "other-holder372";
    core.installDeterministicTestKey(otherHolderKey, "issuer:233");
    const cases = [
      [
        {
          payload: {
            iss: "did:web:other372.example",
            issuer: "did:web:other372.example",
          },
        },
        "ISSUER_NOT_ACCEPTED",
      ],
      [{ issuerKeyId: otherIssuerKey }, "INVALID_SIGNATURE"],
      [
        {
          payload: {
            credentialDefinition: { id: f.definition.id, version: "2" },
          },
        },
        "DEFINITION_NOT_ACCEPTED",
      ],
      [
        {
          payload: {
            credentialDefinition: {
              id: "https://issuer372.example/definitions/other",
              version: "1",
            },
          },
        },
        "DEFINITION_NOT_ACCEPTED",
      ],
      [
        { payload: { type: ["VerifiableCredential", "OtherCredential"] } },
        "TYPE_NOT_ACCEPTED",
      ],
      [{ holderKeyId: otherHolderKey }, "INVALID_SIGNATURE"],
      [
        {
          audience:
            "decentralized_identifier:did:web:other-verifier372.example",
        },
        "BINDING_CHECK_FAILED",
      ],
      [{ nonce: "another-request" }, "BINDING_CHECK_FAILED"],
      [
        {
          paths: [
            ["credentialSubject", "active"],
            ["credentialSubject", "hidden"],
          ],
        },
        "CLAIM_PATHS_NOT_PERMITTED",
      ],
      [
        { payload: { credentialSubject: { active: "false" } } },
        "INVALID_INPUT",
      ],
    ];
    for (const [changes, code] of cases) {
      const { session, request } = await create(f);
      await complete(f, request, presentation(f, request, changes));
      assert.deepEqual(
        await consume(f, session),
        { status: "refused", interaction_id: "browser-372", error: { code } },
        JSON.stringify(changes),
      );
    }
    const original = await create(f),
      different = await create(f);
    const token = presentation(f, original.request);
    await complete(f, different.request, token);
    assert.equal(
      (await consume(f, different.session)).error.code,
      "BINDING_CHECK_FAILED",
    );
    await complete(f, original.request, token);
    assert.equal((await consume(f, original.session)).status, "verified");
    const replay = await fetch(
      f.runtime.public + new URL(original.request.response_uri).pathname,
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          state: original.request.state,
          vp_token: JSON.stringify({ neutral_check: [token] }),
        }),
      },
    );
    assert.equal(replay.status, 409);
    assert.deepEqual(await replay.json(), {
      error: { code: "SESSION_ALREADY_COMPLETED" },
    });
  } finally {
    await f.close();
  }
});
test("scalar completed result rechecks current exact issuer authority instead of trusting its cached success", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    await complete(f, request, presentation(f, request));
    f.evidence.set(f.authorityUrl, f.signAuthority({ status: "inactive" }));
    const refresh = await f.app("/management/evidence/refresh", {});
    assert.equal(refresh.status, 200, await refresh.clone().text());
    assert.deepEqual(await consume(f, session), {
      status: "refused",
      interaction_id: "browser-372",
      error: { code: "ISSUER_NOT_AUTHORIZED" },
    });
  } finally {
    await f.close();
  }
});
test("same definition, type and profile cannot transfer authority from another issuer or verifier", async () => {
  const f = await fixture();
  try {
    for (const changes of [
      { credential_issuer_did: "did:web:other372.example" },
      { definition_version: "2" },
      {
        verifier_did: "did:web:other-verifier372.example",
        verifier_origin: "https://other-verifier372.example",
      },
      { claim_paths: [["credentialSubject", "hidden"]] },
    ]) {
      f.evidence.set(f.permissionsUrl, f.signPermission(changes));
      assert.equal(
        (await f.app("/management/evidence/refresh", {})).status,
        200,
      );
      const refused = await f.app("/management/sessions", {
        configuration_id: "neutral-pass",
        profile: "neutral_check",
        interaction_id: "browser",
        purpose: "Test",
      });
      assert.equal(refused.status, 403);
      assert.deepEqual(await refused.json(), {
        error: { code: "SCOPE_NOT_PERMITTED" },
      });
    }
  } finally {
    await f.close();
  }
});
test("scalar selectors are explicit and cannot fall through to Education or caller-supplied paths", async () => {
  const f = await fixture();
  try {
    const valid = {
      configuration_id: "neutral-pass",
      profile: "neutral_check",
      interaction_id: "browser",
      purpose: "Test",
    };
    for (const body of [
      { profile: "neutral_check", interaction_id: "browser", purpose: "Test" },
      { ...valid, configuration_id: 7 },
      { ...valid, claim_paths: [["credentialSubject", "hidden"]] },
    ]) {
      const response = await f.app("/management/sessions", body);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), {
        error: { code: "SESSION_BAD_REQUEST" },
      });
    }
    for (const body of [
      { ...valid, configuration_id: "unknown" },
      { ...valid, profile: "education_eligibility" },
    ]) {
      const response = await f.app("/management/sessions", body);
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), {
        error: { code: "SCOPE_NOT_PERMITTED" },
      });
    }
  } finally {
    await f.close();
  }
});
for (const [name, options] of [
  ["issuer authorization", { maxAge: 300, authorityTTL: 15 }],
  ["verifier permission", { maxAge: 300, permissionTTL: 15 }],
  ["signed status", { maxAge: 300, statusTTL: 15 }],
  ["configured cache age", { maxAge: 15 }],
  ["signed request", { maxAge: 300 }],
])
  test(`scalar result preserves the original ${name} deadline across refresh`, async () => {
    const f = await fixture(options);
    try {
      const { session, request } = await create(f);
      await complete(f, request, presentation(f, request));
      const bound = name === "signed request" ? 120 : 15;
      f.advance(bound - 1);
      f.evidence.set(f.authorityUrl, f.signAuthority());
      f.evidence.set(f.permissionsUrl, f.signPermission());
      assert.equal(
        (await f.app("/management/evidence/refresh", {})).status,
        200,
      );
      f.advance(1);
      assert.deepEqual(await consume(f, session), {
        status: "refused",
        interaction_id: "browser-372",
        error: { code: "EVIDENCE_STALE" },
      });
    } finally {
      await f.close();
    }
  });
test("completed scalar result refuses newly withdrawn exact verifier permission", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    await complete(f, request, presentation(f, request));
    f.evidence.set(f.permissionsUrl, f.signPermission({ status: "inactive" }));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    assert.deepEqual(await consume(f, session), {
      status: "refused",
      interaction_id: "browser-372",
      error: { code: "SCOPE_NOT_PERMITTED" },
    });
  } finally {
    await f.close();
  }
});
test("signed issuer authority cannot be inferred from a shared definition/type or a different key/version", async () => {
  const f = await fixture();
  try {
    for (const changes of [
      {
        credential_issuer_did: "did:web:other372.example",
        credential_issuer_key_id: "did:web:other372.example#key-1",
      },
      { credential_issuer_key_id: f.issuerDid + "#other" },
      {
        credential_issuer_public_jwk_sha256_thumbprint:
          core.publicJwkSha256Thumbprint(f.anchor),
      },
      { definition: { ...f.definition, version: "2" } },
    ]) {
      const compact = f.signAuthority(changes);
      assert.equal(
        core.verifyCompactJwsJson({ compactJws: compact, publicJwk: f.anchor })
          .header.typ,
        "issuer-authorizations+jwt",
      );
      f.evidence.set(f.authorityUrl, compact);
      assert.equal(
        (await f.app("/management/evidence/refresh", {})).status,
        200,
      );
      const response = await f.app("/management/sessions", {
        configuration_id: "neutral-pass",
        profile: "neutral_check",
        interaction_id: "browser",
        purpose: "Test",
      });
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), {
        error: { code: "ISSUER_NOT_AUTHORIZED" },
      });
    }
  } finally {
    await f.close();
  }
});
test("current signed revocation suppresses completed scalar claims and unauthorized status destinations are refused", async () => {
  const f = await fixture();
  try {
    const bad = await create(f);
    await complete(
      f,
      bad.request,
      presentation(f, bad.request, {
        payload: {
          credentialStatus: {
            id: "https://other372.example/list.jwt#7",
            type: "BitstringStatusListEntry",
            statusPurpose: "revocation",
            statusListIndex: "7",
            statusListCredential: "https://other372.example/list.jwt",
          },
        },
      }),
    );
    assert.equal(
      (await consume(f, bad.session)).error.code,
      "STATUS_DESTINATION_UNAUTHORIZED",
    );
    const { session, request } = await create(f);
    await complete(f, request, presentation(f, request));
    f.evidence.set(
      f.statusUrl,
      core.signBitstringStatusListCredential({
        keyId: f.issuerKeyId,
        header: { alg: "ES256", typ: "statuslist+jwt", kid: f.issuerKeyId },
        payload: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          type: ["VerifiableCredential", "BitstringStatusListCredential"],
          issuer: f.issuerDid,
          validFrom: new Date(f.clock() * 1000)
            .toISOString()
            .replace(".000Z", "Z"),
          validUntil: new Date((f.clock() + 300) * 1000)
            .toISOString()
            .replace(".000Z", "Z"),
          credentialSubject: {
            id: f.statusUrl + "#list",
            type: "BitstringStatusList",
            statusPurpose: "revocation",
            encodedList: core.encodeBitstringStatusList(131072, [7]),
          },
        },
      }),
    );
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    assert.deepEqual(await consume(f, session), {
      status: "refused",
      interaction_id: "browser-372",
      error: { code: "STATUS_CHECK_FAILED" },
    });
  } finally {
    await f.close();
  }
});

test("retained history request authenticates and freezes old/new members and accepts each exact key", async () => {
  const f = await fixture({ retainedKeys: true });
  try {
    for (const keyId of [f.issuerKeyId, f.newIssuerKeyId]) {
      const { session, request } = await create(f);
      assert.deepEqual(request.credworks_scalar.credential_issuer_keys, [
        { key_id: f.issuerKeyId, public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(f.issuerJwk) },
        { key_id: f.newIssuerKeyId, public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(f.newIssuerJwk) },
      ]);
      assert.equal(Object.hasOwn(request.credworks_scalar, "credential_issuer_key_id"), false);
      await complete(f, request, presentation(f, request, { issuerKeyId: keyId }));
      const result = await consume(f, session);
      assert.equal(result.status, "verified", JSON.stringify(result));
      assert.equal(result.evidence.issuer_public_jwk_sha256_thumbprint,
        core.publicJwkSha256Thumbprint(keyId === f.issuerKeyId ? f.issuerJwk : f.newIssuerJwk));
    }
  } finally { await f.close(); }
});

test("pending set freezes members; later publication cannot add a signing key", async () => {
  const f = await fixture({ retainedKeys: true });
  try {
    const original = await create(f);
    const thirdId = f.issuerDid + "#key-3";
    const thirdJwk = core.installDeterministicTestKey(thirdId, "issuer:235");
    const { payload } = core.verifyCompactJwsJson({ compactJws: f.evidence.get(f.authorityUrl), publicJwk: f.anchor });
    const third = { ...payload.authorizations[1], credential_issuer_key_id: thirdId,
      credential_issuer_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(thirdJwk) };
    payload.authorizations[1].key_state = "retained";
    f.evidence.set(f.authorityUrl, f.signAuthority({}, [...payload.authorizations, third]));
    f.evidence.set(core.didWebToHttpsUrl(f.issuerDid), JSON.stringify(core.buildDidWebDocument(f.issuerDid, [
      { ...f.issuerJwk, kid: f.issuerKeyId }, { ...f.newIssuerJwk, kid: f.newIssuerKeyId }, { ...thirdJwk, kid: thirdId },
    ])));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    await complete(f, original.request, presentation(f, original.request, { issuerKeyId: thirdId }));
    assert.equal((await consume(f, original.session)).error.code, "ISSUER_NOT_AUTHORIZED");
    const fresh = await create(f);
    assert.equal(fresh.request.credworks_scalar.credential_issuer_keys.length, 3);
    await complete(f, fresh.request, presentation(f, fresh.request, { issuerKeyId: thirdId }));
    assert.equal((await consume(f, fresh.session)).status, "verified");
  } finally { await f.close(); }
});

test("retained withdrawal refuses pending completion and completed consumption without widening surviving requests", async () => {
  const f = await fixture({ retainedKeys: true });
  try {
    const pending = await create(f), completed = await create(f);
    await complete(f, completed.request, presentation(f, completed.request));
    f.evidence.set(f.authorityUrl, f.signAuthority({ key_state: "withdrawn" }));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    await complete(f, pending.request, presentation(f, pending.request));
    for (const session of [pending.session, completed.session]) {
      assert.equal((await consume(f, session)).error.code, "ISSUER_NOT_AUTHORIZED");
      const replay = await f.app("/management/sessions/" + session.session_id + "/result", {}, session.correlation_capability);
      assert.equal(replay.status, 409);
    }
    const fresh = await create(f);
    assert.deepEqual(fresh.request.credworks_scalar.credential_issuer_keys.map(key => key.key_id), [f.newIssuerKeyId]);
    await complete(f, fresh.request, presentation(f, fresh.request, { issuerKeyId: f.newIssuerKeyId }));
    assert.equal((await consume(f, fresh.session)).status, "verified");
  } finally { await f.close(); }
});

test("set authority requires core-authenticated immutable issuer pins and exact bounded DID members", async () => {
  const f = await fixture({ retainedKeys: true });
  try {
    const original = f.evidence.get(f.authorityUrl);
    const document = core.verifyCompactJwsJson({ compactJws: original, publicJwk: f.anchor });
    const cases = [
      value => { value.authorizations[1].credential_issuer_public_jwk_sha256_thumbprint = core.publicJwkSha256Thumbprint(f.anchor); },
      value => { value.authorizations[1].credential_issuer_public_jwk_sha256_thumbprint = "invalid"; },
      value => { value.authorizations.push(value.authorizations[1]); },
      value => { value.authorizations[1].extra = true; },
      value => { value.authorizations[1].credential_issuer_key_id = "did:web:other372.example#key-2"; },
      value => { value.authorizations[1].status_authority = { key_id: f.newIssuerKeyId, public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(f.newIssuerJwk) }; },
    ];
    for (const change of cases) {
      const payload = structuredClone(document.payload); change(payload);
      f.evidence.set(f.authorityUrl, core.signCompactJwsJson({ keyId: f.registryDid + "#anchor", header: document.header, payload }));
      assert.equal((await f.app("/management/evidence/refresh", {})).status, 503);
    }
    f.evidence.set(f.authorityUrl, original);
    f.evidence.set(core.didWebToHttpsUrl(f.issuerDid), " ".repeat(262145));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 503);
  } finally { await f.close(); }
});

test("legacy bootstrap requests keep working without issuer DID network availability", async () => {
  const f = await fixture();
  try {
    f.evidence.delete(core.didWebToHttpsUrl(f.issuerDid));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const { session, request } = await create(f);
    assert.equal(request.credworks_scalar.credential_issuer_key_id, f.issuerKeyId);
    assert.equal(request.exp, f.clock() + 120);
    await complete(f, request, presentation(f, request));
    assert.equal((await consume(f, session)).status, "verified");
  } finally { await f.close(); }
});

for (const [name, options] of [["cache", { maxAge: 5 }], ["authority", { authorityTTL: 5 }],
  ["permission", { permissionTTL: 5 }], ["status", { statusTTL: 5 }]]) {
  test("set request signs original " + name + " deadline; refresh cannot extend equality", async () => {
    const f = await fixture({ ...options, retainedKeys: true });
    try {
      const pending = await create(f), completed = await create(f);
      assert.equal(pending.request.exp, f.clock() + 5);
      await complete(f, completed.request, presentation(f, completed.request, { issuerKeyId: f.newIssuerKeyId }));
      f.advance(4);
      const [header, payload] = core.verifyBitstringStatusListCredential({ compactJws: f.evidence.get(f.statusUrl), statusListJwk: f.issuerJwk });
      payload.validUntil = new Date((f.clock() + 300) * 1000).toISOString().replace(".000Z", "Z");
      f.evidence.set(f.statusUrl, core.signBitstringStatusListCredential({ keyId: f.issuerKeyId, header, payload }));
      f.evidence.set(f.authorityUrl, f.signAuthority()); f.evidence.set(f.permissionsUrl, f.signPermission());
      assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
      f.advance(1);
      assert.equal((await fetch(f.runtime.public + new URL(pending.session.request_uri).pathname)).status, 410);
      assert.equal((await consume(f, completed.session)).error.code, "EVIDENCE_STALE");
    } finally { await f.close(); }
  });
}

test("same public key under another ID cannot escape the original legacy ceremony membership", async () => {
  const f = await fixture();
  try {
    const original = await create(f);
    const aliasId = f.issuerDid + "#same-public-key";
    const aliasJwk = core.installDeterministicTestKey(aliasId, "issuer:230");
    assert.equal(core.publicJwkSha256Thumbprint(aliasJwk), core.publicJwkSha256Thumbprint(f.issuerJwk));
    const document = core.verifyCompactJwsJson({ compactJws: f.evidence.get(f.authorityUrl), publicJwk: f.anchor }).payload;
    const bootstrap = { ...document.authorizations[0], key_state: "retained", status_authority: f.statusAuthority };
    const alias = { ...bootstrap, key_state: "current", credential_issuer_key_id: aliasId };
    f.evidence.set(f.authorityUrl, f.signAuthority({}, [bootstrap, alias]));
    f.evidence.set(core.didWebToHttpsUrl(f.issuerDid), JSON.stringify(core.buildDidWebDocument(f.issuerDid, [
      { ...f.issuerJwk, kid: f.issuerKeyId }, { ...aliasJwk, kid: aliasId },
    ])));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    await complete(f, original.request, presentation(f, original.request, { issuerKeyId: aliasId }));
    assert.equal((await consume(f, original.session)).error?.code, "ISSUER_NOT_AUTHORIZED");
    const fresh = await create(f);
    assert.equal(fresh.request.credworks_scalar.credential_issuer_keys.length, 2, "distinct IDs sharing a pin are permitted");
    await complete(f, fresh.request, presentation(f, fresh.request, { issuerKeyId: aliasId }));
    assert.equal((await consume(f, fresh.session)).status, "verified");
  } finally { await f.close(); }
});

test("fractional status-list times remain unsupported and cannot enter the set cache", async () => {
  await assert.rejects(fixture({ retainedKeys: true, statusTTL: 5.5 }), { code: "EVIDENCE_REFRESH_FAILED" });
});

test("set outage cannot renew an original positive deadline or add authority", async () => {
  const f = await fixture({ retainedKeys: true, maxAge: 5 });
  try {
    const original = await create(f);
    const issuerDocument = f.evidence.get(core.didWebToHttpsUrl(f.issuerDid));
    f.evidence.delete(core.didWebToHttpsUrl(f.issuerDid));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 503);
    f.advance(4);
    for (const issuerKeyId of [f.issuerKeyId, f.newIssuerKeyId]) {
      const { session, request } = await create(f);
      await complete(f, request, presentation(f, request, { issuerKeyId }));
      assert.equal((await consume(f, session)).status, "verified");
    }
    f.advance(1);
    assert.equal((await fetch(f.runtime.public + new URL(original.session.request_uri).pathname)).status, 410);
    const expired = await f.app("/management/sessions", { configuration_id: "neutral-pass", profile: "neutral_check",
      interaction_id: "outage", purpose: "Must refuse expired authority" });
    assert.equal(expired.status, 503);
    f.evidence.set(core.didWebToHttpsUrl(f.issuerDid), issuerDocument);
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    assert.equal((await fetch(f.runtime.public + new URL(original.session.request_uri).pathname)).status, 410);
  } finally { await f.close(); }
});

test("set emission admits 64 unique exact IDs in ordinal order and refuses the 65th", async () => {
  const f = await fixture();
  try {
    const original = core.verifyCompactJwsJson({ compactJws: f.evidence.get(f.authorityUrl), publicJwk: f.anchor });
    const bootstrap = { ...original.payload.authorizations[0], key_state: "retained", status_authority: f.statusAuthority };
    const members = [bootstrap];
    const methods = [{ ...f.issuerJwk, kid: f.issuerKeyId }];
    for (let index = 0; index < 63; index++) {
      const keyId = f.issuerDid + "#history-" + String(index).padStart(2, "0");
      const publicJwk = core.installDeterministicTestKey(keyId, "issuer:230");
      methods.push({ ...publicJwk, kid: keyId });
      members.push({ ...bootstrap, credential_issuer_key_id: keyId, key_state: index === 62 ? "current" : "retained" });
    }
    f.evidence.set(f.authorityUrl, f.signAuthority({}, members));
    f.evidence.set(core.didWebToHttpsUrl(f.issuerDid), JSON.stringify(core.buildDidWebDocument(f.issuerDid, methods)));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const { request } = await create(f);
    const keys = request.credworks_scalar.credential_issuer_keys;
    assert.equal(keys.length, 64);
    assert.equal(keys[0].key_id, f.issuerDid + "#history-00");
    assert.equal(keys[62].key_id, f.issuerDid + "#history-62");
    assert.equal(keys[63].key_id, f.issuerKeyId);
    const payload = { ...original.payload, authorizations: [...members, { ...bootstrap, credential_issuer_key_id: f.issuerDid + "#history-63" }] };
    f.evidence.set(f.authorityUrl, core.signCompactJwsJson({ keyId: f.registryDid + "#anchor", header: original.header, payload }));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 503);
  } finally { await f.close(); }
});
