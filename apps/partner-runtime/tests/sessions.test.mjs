import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as core from "@unsw-vc/identity-core-node";
import { openIdentity, startRuntime } from "../src/runtime.ts";

async function fixture({
  trustTTL = 300,
  permissionTTL = 300,
  statusTTL = 300,
  maxAge = 30,
} = {}) {
  const root = await mkdtemp(join(tmpdir(), "vc362-session-"));
  const config = {
    origin:
      "https://partner" +
      core.randomUrlSafe(16).toLowerCase().replaceAll("_", "a") +
      ".example",
    stateDir: join(root, "identity"),
    unlockKey: core.randomUrlSafe(32),
    managementToken: core.randomUrlSafe(32),
    publicPort: Number(process.env.PARTNER_SESSION_HTTP_PORT ?? 29200),
    managementPort: Number(process.env.PARTNER_SESSION_HTTP_PORT ?? 29200) + 1,
  };
  const identity = openIdentity(config, true);
  let clock = Math.floor(Date.now() / 1000);
  const issuerDid = "did:web:education362.example",
    issuerKeyId = issuerDid + "#key-1";
  const issuerJwk = core.installDeterministicTestKey(issuerKeyId, "issuer:220");
  const trustDid = "did:web:registry362.example",
    trustKeyId = trustDid + "#trust-anchor-1";
  const trustAnchorJwk = core.installDeterministicTestKey(
    trustKeyId,
    "issuer:221",
  );
  const statusUrl = "https://status362.example/education.jwt";
  const statusKeyId = issuerDid + "#status-1",
    statusJwk = core.installDeterministicTestKey(statusKeyId, "issuer:222");
  config.verifier = {
    issuerDid,
    issuerJwk,
    registryOrigin: "https://registry362.example",
    trustAnchorJwk,
    statusSources: [
      { url: statusUrl, publicJwk: statusJwk, purpose: "revocation" },
    ],
    maxCacheAgeSeconds: maxAge,
  };
  const permissionsUrl =
    config.verifier.registryOrigin +
    "/scoped-verifier-permissions.jwt?verifier_did=" +
    encodeURIComponent(identity.did);
  const profiles = {
    education_eligibility: [
      ["credentialSubject", "enrolled"],
      ["credentialSubject", "institution_id"],
    ],
    education_sign_in: [
      ["credentialSubject", "enrolled"],
      ["credentialSubject", "institution_id"],
      ["credentialSubject", "student_id"],
    ],
  };
  const evidence = new Map();
  evidence.set(
    config.verifier.registryOrigin + "/trust-list.jwt",
    core.signTrustList({
      payload: {
        id: config.verifier.registryOrigin + "/trust-list.jwt",
        issuer: trustDid,
        iat: clock,
        exp: clock + trustTTL,
        entries: [
          {
            issuer_did: issuerDid,
            credential_types: ["UniversityEducationCredential"],
            status: "active",
            public_jwk: issuerJwk,
            public_jwk_sha256_thumbprint:
              core.publicJwkSha256Thumbprint(issuerJwk),
          },
        ],
        verifiers: [],
      },
      header: { alg: "ES256", typ: "trust-list+jwt", kid: trustKeyId },
      keyId: trustKeyId,
    }),
  );
  evidence.set(
    permissionsUrl,
    core.signScopedVerifierPermissions({
      payload: {
        version: 1,
        id: permissionsUrl,
        issuer: trustDid,
        iat: clock,
        exp: clock + permissionTTL,
        permissions: Object.entries(profiles).map(
          ([profile_name, claim_paths]) => ({
            credential_issuer_did: issuerDid,
            definition_id: "urn:credworks:education",
            definition_version: "1",
            credential_type: "UniversityEducationCredential",
            verifier_did: identity.did,
            verifier_origin: config.origin,
            verifier_public_jwk_sha256_thumbprint:
              core.publicJwkSha256Thumbprint(identity.publicJwk),
            profile_name,
            claim_paths,
            status: "active",
          }),
        ),
      },
      header: {
        alg: "ES256",
        typ: "scoped-verifier-permissions+jwt",
        kid: trustKeyId,
      },
      keyId: trustKeyId,
    }),
  );
  evidence.set(
    statusUrl,
    core.signBitstringStatusListCredential({
      payload: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "BitstringStatusListCredential"],
        issuer: issuerDid,
        validFrom: new Date(clock * 1000).toISOString().replace(".000Z", "Z"),
        validUntil: new Date((clock + statusTTL) * 1000)
          .toISOString()
          .replace(".000Z", "Z"),
        credentialSubject: {
          id: statusUrl + "#list",
          type: "BitstringStatusList",
          statusPurpose: "revocation",
          encodedList: core.encodeBitstringStatusList(131072, []),
        },
      },
      header: { alg: "ES256", typ: "statuslist+jwt", kid: statusKeyId },
      keyId: statusKeyId,
    }),
  );
  const runtime = await startRuntime(config, identity, {
    clock: () => clock,
    fetchEvidence: async (url) => {
      if (!evidence.has(url)) throw Error("offline");
      return evidence.get(url);
    },
  });
  const app = (path, body, capability, token = config.managementToken) =>
    fetch(runtime.management + path, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        authorization: "Bearer " + token,
        "content-type": "application/json",
        ...(capability ? { "x-session-capability": capability } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  return {
    config,
    identity,
    clock: () => clock,
    advance: (seconds) => {
      clock += seconds;
    },
    profiles,
    evidence,
    permissionsUrl,
    issuerDid,
    issuerKeyId,
    issuerJwk,
    statusUrl,
    runtime,
    app,
    async close() {
      runtime.close();
      await rm(root, { recursive: true, force: true });
    },
  };
}
test("authenticated session returns a creation-anchored signed Education request on the public listener", async () => {
  const f = await fixture();
  try {
    const created = await f.app("/management/sessions", {
      profile: "education_eligibility",
      interaction_id: "browser-one",
      purpose: "Library eligibility",
    });
    assert.equal(created.status, 201, await created.clone().text());
    const session = await created.json();
    const request = await fetch(
      f.runtime.public + new URL(session.request_uri).pathname,
    );
    assert.equal(request.status, 200);
    const jwt = await request.text();
    const verified = core.verifyOid4vpRequestObject({
      compactJws: jwt,
      resolverResponses: {
        [core.didWebToHttpsUrl(f.identity.did)]: JSON.stringify(
          core.buildDidWebDocument(f.identity.did, [f.identity.publicJwk]),
        ),
      },
      nowUnixSeconds: f.clock(),
    });
    assert.equal(verified.payload.exp, verified.payload.iat + 120);
    assert.deepEqual(verified.payload.dcql_query.credentials[0].claims, [
      { path: ["credentialSubject", "enrolled"] },
      { path: ["credentialSubject", "institution_id"] },
    ]);
    f.advance(10);
    assert.equal(
      await (
        await fetch(f.runtime.public + new URL(session.request_uri).pathname)
      ).text(),
      jwt,
    );
    assert.equal(
      (
        await fetch(f.runtime.public + "/management/sessions", {
          method: "POST",
        })
      ).status,
      404,
    );
  } finally {
    await f.close();
  }
});

async function create(f, profile = "education_eligibility") {
  const response = await f.app("/management/sessions", {
    profile,
    interaction_id: "browser",
    purpose: "Test access",
  });
  assert.equal(response.status, 201, await response.clone().text());
  const session = await response.json();
  const jwt = await (
    await fetch(f.runtime.public + new URL(session.request_uri).pathname)
  ).text();
  const request = core.verifyOid4vpRequestObject({
    compactJws: jwt,
    resolverResponses: {
      [core.didWebToHttpsUrl(f.identity.did)]: JSON.stringify(
        core.buildDidWebDocument(f.identity.did, [f.identity.publicJwk]),
      ),
    },
    nowUnixSeconds: f.clock(),
  }).payload;
  return { session, request };
}
function presentation(
  f,
  request,
  profile = "education_eligibility",
  overrides = {},
) {
  const holderId = "session-holder362",
    holder = core.installDeterministicTestKey(holderId, "issuer:223");
  const subject = {
    enrolled: true,
    institution_id: "unsw.edu.au",
    student_id: "synthetic-362",
    ...overrides.subject,
  };
  const payload = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "https://education362.example/credentials/one",
    type: ["VerifiableCredential", "UniversityEducationCredential"],
    iss: f.issuerDid,
    issuer: f.issuerDid,
    iat: f.clock(),
    exp: f.clock() + 300,
    validFrom: new Date(f.clock() * 1000).toISOString().replace(".000Z", "Z"),
    validUntil: new Date((f.clock() + 300) * 1000)
      .toISOString()
      .replace(".000Z", "Z"),
    cnf: { jwk: holder },
    credentialSubject: subject,
    credentialStatus: {
      id: f.statusUrl + "#7",
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: "7",
      statusListCredential: f.statusUrl,
    },
    ...overrides.payload,
  };
  const credential = core.issueSdJwtWithFormat({
    payload,
    disclosureSpecs: Object.keys(subject).map((key) => ({
      object_path: ["credentialSubject"],
      claim_name: key,
    })),
    salts: Object.keys(subject).map(() => core.randomUrlSafe(16)),
    header: { alg: "ES256", typ: "vc+sd-jwt", kid: f.issuerKeyId },
    keyId: overrides.issuerKeyId ?? f.issuerKeyId,
    format: "w3c_vc_data_model",
  });
  return core.presentSdJwt({
    compactSdJwt: credential.compact,
    profile: {
      name: profile,
      claim_paths: overrides.paths ?? f.profiles[profile],
    },
    holderKeyId: overrides.holderKeyId ?? holderId,
    audience: overrides.audience ?? request.client_id,
    nonce: overrides.nonce ?? request.nonce,
    iat: overrides.iat ?? f.clock(),
  }).presentation;
}
async function respond(f, request, token, state = request.state) {
  return fetch(f.runtime.public + new URL(request.response_uri).pathname, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      state,
      vp_token: JSON.stringify({
        [request.dcql_query.credentials[0].id]: [token],
      }),
    }),
  });
}
test("real holder presentation yields one protected typed result and concurrent completion is claimed once", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f, "education_sign_in");
    const token = presentation(f, request, "education_sign_in", {
      subject: { enrolled: false },
    });
    const responses = await Promise.all([
      respond(f, request, token),
      respond(f, request, token),
    ]);
    assert.deepEqual(responses.map((r) => r.status).sort(), [200, 409]);
    const wrong = await f.app(
      `/management/sessions/${session.session_id}/result`,
      {},
      "wrong",
    );
    assert.equal(wrong.status, 401);
    const result = await f.app(
      `/management/sessions/${session.session_id}/result`,
      {},
      session.correlation_capability,
    );
    assert.equal(result.status, 200);
    const verified = await result.json();
    assert.equal(verified.status, "verified", JSON.stringify(verified));
    assert.deepEqual(verified.claims, {
      enrolled: false,
      institution_id: "unsw.edu.au",
      student_id: "synthetic-362",
    });
    assert.equal(
      (
        await f.app(
          `/management/sessions/${session.session_id}/result`,
          {},
          session.correlation_capability,
        )
      ).status,
      409,
    );
  } finally {
    await f.close();
  }
});

test("HTTP verification refuses mismatched bindings, issuer/type, excess disclosure and expired credentials", async () => {
  const f = await fixture();
  try {
    core.installDeterministicTestKey("other-issuer362", "issuer:225");
    const cases = [
      [
        { payload: { credentialStatus: undefined } },
        "PRESENTATION_VERIFICATION_FAILED",
      ],
      [{ issuerKeyId: "other-issuer362" }, "INVALID_SIGNATURE"],
      [
        { payload: { extra_personal_data: "must-not-disclose" } },
        "CLAIM_PATHS_NOT_PERMITTED",
      ],
      [{ paths: [["credentialSubject", "enrolled"]] }, "MISSING_DISCLOSURE"],
      [{ nonce: "another-nonce" }, "BINDING_CHECK_FAILED"],
      [
        { audience: "decentralized_identifier:did:web:other.example" },
        "BINDING_CHECK_FAILED",
      ],
      [
        {
          payload: {
            iss: "did:web:another.example",
            issuer: "did:web:another.example",
          },
        },
        "ISSUER_NOT_ACCEPTED",
      ],
      [
        {
          payload: {
            type: ["VerifiableCredential", "GovernmentIdentityCredential"],
          },
        },
        "TYPE_NOT_ACCEPTED",
      ],
      [{ paths: f.profiles.education_sign_in }, "CLAIM_PATHS_NOT_PERMITTED"],
      [{ payload: { exp: f.clock() - 1 } }, "FRESHNESS_CHECK_FAILED"],
      [{ iat: f.clock() - 121 }, "FRESHNESS_CHECK_FAILED"],
      [
        {
          payload: {
            cnf: {
              jwk: core.installDeterministicTestKey(
                "different-holder362",
                "issuer:224",
              ),
            },
          },
        },
        "INVALID_SIGNATURE",
      ],
    ];
    for (const [overrides, code] of cases) {
      const { session, request } = await create(f);
      const token = presentation(
        f,
        request,
        "education_eligibility",
        overrides,
      );
      assert.equal((await respond(f, request, token)).status, 200);
      const result = await (
        await f.app(
          `/management/sessions/${session.session_id}/result`,
          {},
          session.correlation_capability,
        )
      ).json();
      assert.equal(result.status, "refused", JSON.stringify(result));
      assert.equal(result.error.code, code, JSON.stringify(overrides));
      assert.equal(result.claims, undefined);
    }
  } finally {
    await f.close();
  }
});
test("public state is distinct from protected correlation and expiry is creation anchored", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    const token = presentation(f, request);
    const bad = await respond(f, request, token, "other-state");
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error.code, "RESPONSE_STATE_MISMATCH");
    assert.equal(
      (
        await f.app(
          `/management/sessions/${session.session_id}/result`,
          {},
          request.state,
        )
      ).status,
      401,
    );
    f.advance(120);
    const expired = await respond(f, request, token);
    assert.equal(expired.status, 410);
    assert.equal((await expired.json()).error.code, "SESSION_EXPIRED");
    assert.equal(
      (await fetch(f.runtime.public + new URL(session.request_uri).pathname))
        .status,
      410,
    );
  } finally {
    await f.close();
  }
});
test("authenticated fresh cache allows offline completion while stale evidence fails closed", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    const token = presentation(f, request);
    f.evidence.clear();
    const refresh = await f.app("/management/evidence/refresh", {});
    assert.equal(refresh.status, 503);
    assert.equal((await refresh.json()).error.code, "EVIDENCE_REFRESH_FAILED");
    assert.equal((await respond(f, request, token)).status, 200);
    assert.equal(
      (
        await (
          await f.app(
            `/management/sessions/${session.session_id}/result`,
            {},
            session.correlation_capability,
          )
        ).json()
      ).status,
      "verified",
    );
    const fresh = await create(f);
    f.advance(30);
    const stale = await f.app("/management/sessions", {
      profile: "education_eligibility",
      interaction_id: "offline",
      purpose: "Test",
    });
    assert.equal(stale.status, 503);
    assert.equal((await stale.json()).error.code, "EVIDENCE_STALE");
    assert.equal(
      (await respond(f, fresh.request, presentation(f, fresh.request))).status,
      200,
    );
    const result = await (
      await f.app(
        `/management/sessions/${fresh.session.session_id}/result`,
        {},
        fresh.session.correlation_capability,
      )
    ).json();
    assert.equal(result.error.code, "EVIDENCE_STALE");
  } finally {
    await f.close();
  }
});

test("cache refresh changes scoped authority for existing sessions and rejects unauthenticated refresh", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    const token = presentation(f, request);
    assert.equal(
      (await f.app("/management/evidence/refresh", {}, undefined, "invalid"))
        .status,
      401,
    );
    const trustKeyId = "did:web:registry362.example#trust-anchor-1";
    f.evidence.set(
      f.permissionsUrl,
      core.signScopedVerifierPermissions({
        payload: {
          version: 1,
          id: f.permissionsUrl,
          issuer: "did:web:registry362.example",
          iat: f.clock(),
          exp: f.clock() + 300,
          permissions: [],
        },
        header: {
          alg: "ES256",
          typ: "scoped-verifier-permissions+jwt",
          kid: trustKeyId,
        },
        keyId: trustKeyId,
      }),
    );
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    assert.equal((await respond(f, request, token)).status, 200);
    const result = await (
      await f.app(
        `/management/sessions/${session.session_id}/result`,
        {},
        session.correlation_capability,
      )
    ).json();
    assert.equal(result.error.code, "SCOPE_NOT_PERMITTED");
    const denied = await f.app("/management/sessions", {
      profile: "education_eligibility",
      interaction_id: "new",
      purpose: "Test",
    });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).error.code, "SCOPE_NOT_PERMITTED");
  } finally {
    await f.close();
  }
});
test("management input is bounded and result consumption is atomic across concurrent callers", async () => {
  const f = await fixture();
  try {
    const malformed = await f.app("/management/sessions", {
      profile: "education_sign_in",
      interaction_id: "x",
      purpose: "x",
      issuer: "did:web:attacker.example",
    });
    assert.equal(malformed.status, 400);
    assert.equal((await malformed.json()).error.code, "SESSION_BAD_REQUEST");
    const oversized = await f.app("/management/sessions", {
      profile: "education_sign_in",
      interaction_id: "x",
      purpose: "x".repeat(5000),
    });
    assert.equal(oversized.status, 413);
    assert.equal((await oversized.json()).error.code, "REQUEST_TOO_LARGE");
    const { session, request } = await create(f);
    assert.equal(
      (await respond(f, request, presentation(f, request))).status,
      200,
    );
    const results = await Promise.all([
      f.app(
        `/management/sessions/${session.session_id}/result`,
        {},
        session.correlation_capability,
      ),
      f.app(
        `/management/sessions/${session.session_id}/result`,
        {},
        session.correlation_capability,
      ),
    ]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  } finally {
    await f.close();
  }
});

test("authenticated status refresh refuses revoked evidence and invalid signatures do not replace the snapshot", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    const token = presentation(f, request);
    const statusKeyId = f.issuerDid + "#status-1";
    f.evidence.set(
      f.statusUrl,
      core.signBitstringStatusListCredential({
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
        header: { alg: "ES256", typ: "statuslist+jwt", kid: statusKeyId },
        keyId: statusKeyId,
      }),
    );
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    assert.equal((await respond(f, request, token)).status, 200);
    const result = await (
      await f.app(
        `/management/sessions/${session.session_id}/result`,
        {},
        session.correlation_capability,
      )
    ).json();
    assert.equal(result.error.code, "STATUS_CHECK_FAILED");
    const original = f.evidence.get(f.permissionsUrl);
    f.evidence.set(f.permissionsUrl, original.slice(0, -12) + "AAAAAAAAAAAA");
    const refresh = await f.app("/management/evidence/refresh", {});
    assert.equal(refresh.status, 503);
    assert.equal((await refresh.json()).error.code, "EVIDENCE_REFRESH_FAILED");
    await create(f);
    f.advance(30);
    const stale = await f.app("/management/sessions", {
      profile: "education_eligibility",
      interaction_id: "new",
      purpose: "Test",
    });
    assert.equal(stale.status, 503);
    assert.equal((await stale.json()).error.code, "EVIDENCE_STALE");
  } finally {
    await f.close();
  }
});
test("configuration changes cannot transfer existing sessions or their protected correlation", async () => {
  const f = await fixture();
  try {
    const first = await create(f);
    const second = await create(f);
    assert.equal(
      (
        await f.app(
          `/management/sessions/${first.session.session_id}/result`,
          {},
          second.session.correlation_capability,
        )
      ).status,
      401,
    );
    f.config.verifier.issuerDid = "did:web:changed.example";
    f.identity.did = "did:web:changed-partner.example";
    assert.equal(
      (await respond(f, first.request, presentation(f, first.request))).status,
      200,
    );
    const result = await (
      await f.app(
        `/management/sessions/${first.session.session_id}/result`,
        {},
        first.session.correlation_capability,
      )
    ).json();
    assert.equal(result.status, "verified");
    assert.equal(result.evidence.issuer_did, f.issuerDid);
    assert.notEqual(result.evidence.verifier_did, f.identity.did);
  } finally {
    await f.close();
  }
});

test("HTTP session capacity is bounded and creation-anchored retention frees expired records", async () => {
  const f = await fixture();
  try {
    for (let index = 0; index < 100; index++) {
      const response = await f.app("/management/sessions", {
        profile: "education_eligibility",
        interaction_id: "capacity-" + index,
        purpose: "Test",
      });
      assert.equal(response.status, 201);
    }
    const full = await f.app("/management/sessions", {
      profile: "education_eligibility",
      interaction_id: "overflow",
      purpose: "Test",
    });
    assert.equal(full.status, 429);
    assert.equal((await full.json()).error.code, "SESSION_CAPACITY");
    f.advance(240);
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const next = await f.app("/management/sessions", {
      profile: "education_eligibility",
      interaction_id: "after-retention",
      purpose: "Test",
    });
    assert.equal(next.status, 201);
  } finally {
    await f.close();
  }
});

for (const [name, options] of [
  ["configured maximum age", { maxAge: 7 }],
  ["signed trust expiry", { trustTTL: 7, maxAge: 300 }],
  ["signed scoped permission expiry", { permissionTTL: 7, maxAge: 300 }],
  ["signed status expiry", { statusTTL: 7, maxAge: 300 }],
]) {
  test(`HTTP refuses offline evidence at the exact ${name} bound`, async () => {
    const f = await fixture(options);
    try {
      const { session, request } = await create(f);
      const token = presentation(f, request);
      const completed = await create(f);
      assert.equal(
        (
          await respond(
            f,
            completed.request,
            presentation(f, completed.request),
          )
        ).status,
        200,
      );
      const fresh = await create(f);
      const freshToken = presentation(f, fresh.request);
      f.evidence.clear();
      f.advance(6);
      assert.equal((await respond(f, fresh.request, freshToken)).status, 200);
      const freshResult = await (
        await f.app(
          `/management/sessions/${fresh.session.session_id}/result`,
          {},
          fresh.session.correlation_capability,
        )
      ).json();
      assert.equal(freshResult.status, "verified");
      f.advance(1);
      const completedResult = await (
        await f.app(
          `/management/sessions/${completed.session.session_id}/result`,
          {},
          completed.session.correlation_capability,
        )
      ).json();
      assert.deepEqual(completedResult, {
        status: "refused",
        interaction_id: completed.session.interaction_id,
        error: { code: "EVIDENCE_STALE" },
      });
      const denied = await f.app("/management/sessions", {
        profile: "education_eligibility",
        interaction_id: "bound",
        purpose: "Test",
      });
      assert.equal(denied.status, 503);
      assert.equal((await denied.json()).error.code, "EVIDENCE_STALE");
      assert.equal((await respond(f, request, token)).status, 200);
      const result = await (
        await f.app(
          `/management/sessions/${session.session_id}/result`,
          {},
          session.correlation_capability,
        )
      ).json();
      assert.equal(result.status, "refused");
      assert.equal(result.error.code, "EVIDENCE_STALE");
      assert.equal(result.claims, undefined);
    } finally {
      await f.close();
    }
  });
}

test("refresh cannot extend a completed result's original evidence deadline", async () => {
  const f = await fixture({ maxAge: 10 });
  try {
    const began = f.clock();
    const { session, request } = await create(f);
    assert.equal(
      (await respond(f, request, presentation(f, request))).status,
      200,
    );
    f.advance(9);
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    f.advance(1);
    const outcomes = await Promise.all(
      [1, 2].map(() =>
        f.app(
          `/management/sessions/${session.session_id}/result`,
          {},
          session.correlation_capability,
        ),
      ),
    );
    assert.deepEqual(outcomes.map((r) => r.status).sort(), [200, 409]);
    const result = await outcomes.find((r) => r.status === 200).json();
    assert.deepEqual(result, {
      status: "refused",
      interaction_id: session.interaction_id,
      error: { code: "EVIDENCE_STALE" },
    });
    const current = await create(f);
    assert.equal(
      (await respond(f, current.request, presentation(f, current.request)))
        .status,
      200,
    );
    const fresh = await (
      await f.app(
        `/management/sessions/${current.session.session_id}/result`,
        {},
        current.session.correlation_capability,
      )
    ).json();
    assert.equal(fresh.status, "verified");
    assert.equal(fresh.evidence.expires_at, began + 19);
  } finally {
    await f.close();
  }
});

test("completed result delivery refuses a withdrawn exact permission", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    assert.equal(
      (await respond(f, request, presentation(f, request))).status,
      200,
    );
    const payload = core.verifyCompactJwsJson({
      compactJws: f.evidence.get(f.permissionsUrl),
      publicJwk: f.config.verifier.trustAnchorJwk,
    }).payload;
    f.evidence.set(
      f.permissionsUrl,
      core.signScopedVerifierPermissions({
        payload: { ...payload, permissions: [] },
        header: {
          alg: "ES256",
          typ: "scoped-verifier-permissions+jwt",
          kid: "did:web:registry362.example#trust-anchor-1",
        },
        keyId: "did:web:registry362.example#trust-anchor-1",
      }),
    );
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const response = await f.app(
      `/management/sessions/${session.session_id}/result`,
      {},
      session.correlation_capability,
    );
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      status: "refused",
      interaction_id: session.interaction_id,
      error: { code: "SCOPE_NOT_PERMITTED" },
    });
    assert.equal(
      (
        await f.app(
          `/management/sessions/${session.session_id}/result`,
          {},
          session.correlation_capability,
        )
      ).status,
      409,
    );
  } finally {
    await f.close();
  }
});

test("completed result delivery refuses refreshed credential revocation", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    assert.equal(
      (await respond(f, request, presentation(f, request))).status,
      200,
    );
    const statusKeyId = f.issuerDid + "#status-1";
    f.evidence.set(
      f.statusUrl,
      core.signBitstringStatusListCredential({
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
        header: { alg: "ES256", typ: "statuslist+jwt", kid: statusKeyId },
        keyId: statusKeyId,
      }),
    );
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const response = await f.app(
      `/management/sessions/${session.session_id}/result`,
      {},
      session.correlation_capability,
    );
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      status: "refused",
      interaction_id: session.interaction_id,
      error: { code: "STATUS_CHECK_FAILED" },
    });
  } finally {
    await f.close();
  }
});

test("authenticated fractional credential expiry caps completed result delivery", async () => {
  const f = await fixture();
  try {
    const { session, request } = await create(f);
    const expires = f.clock() + 5.5;
    assert.equal(
      (
        await respond(
          f,
          request,
          presentation(f, request, "education_eligibility", {
            payload: { exp: expires },
          }),
        )
      ).status,
      200,
    );
    f.advance(6);
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const response = await f.app(
      `/management/sessions/${session.session_id}/result`,
      {},
      session.correlation_capability,
    );
    assert.deepEqual(await response.json(), {
      status: "refused",
      interaction_id: session.interaction_id,
      error: { code: "EVIDENCE_STALE" },
    });
  } finally {
    await f.close();
  }
});

test("pending request retrieval enforces current permission without changing its original deadline", async () => {
  const f = await fixture({ maxAge: 10 });
  try {
    const { session } = await create(f);
    const requestPath = new URL(session.request_uri).pathname;
    const original = await (await fetch(f.runtime.public + requestPath)).text();
    f.advance(9);
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const refreshed = await fetch(f.runtime.public + requestPath);
    assert.equal(refreshed.status, 200);
    assert.equal(await refreshed.text(), original);
    f.advance(10);
    const stale = await fetch(f.runtime.public + requestPath);
    assert.equal(stale.status, 503);
    assert.equal((await stale.json()).error.code, "EVIDENCE_STALE");
  } finally {
    await f.close();
  }
});

test("completed ceremony remains deliverable after request expiry within original authority and retention", async () => {
  const f = await fixture({ maxAge: 300 });
  try {
    const { session, request } = await create(f);
    assert.equal(
      (await respond(f, request, presentation(f, request))).status,
      200,
    );
    const unconsumed = await create(f);
    assert.equal(
      (
        await respond(
          f,
          unconsumed.request,
          presentation(f, unconsumed.request),
        )
      ).status,
      200,
    );
    f.advance(121);
    const expiredRequest = await fetch(
      f.runtime.public + new URL(session.request_uri).pathname,
    );
    assert.equal(expiredRequest.status, 410);
    assert.equal((await expiredRequest.json()).error.code, "SESSION_EXPIRED");
    const result = await f.app(
      `/management/sessions/${session.session_id}/result`,
      {},
      session.correlation_capability,
    );
    assert.equal(result.status, 200);
    assert.equal((await result.json()).status, "verified");
    f.advance(118);
    const retained = await f.app(
      `/management/sessions/${unconsumed.session.session_id}/result`,
      {},
      unconsumed.session.correlation_capability,
    );
    assert.equal(retained.status, 200);
    assert.equal((await retained.json()).status, "verified");
    f.advance(1);
    const retired = await f.app(
      `/management/sessions/${session.session_id}/result`,
      {},
      session.correlation_capability,
    );
    assert.equal(retired.status, 401);
    assert.equal((await retired.json()).error.code, "SESSION_ACCESS_DENIED");
  } finally {
    await f.close();
  }
});
