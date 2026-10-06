import assert from "node:assert/strict";
import { test } from "node:test";
import { Pool } from "pg";
import { request as httpRequest } from "node:http";
import * as core from "@unsw-vc/identity-core-node";
import { startRuntime } from "../src/runtime.ts";
import { bootstrapIssuerState } from "../src/issuer-state.ts";
import {
  fixture,
  create,
  presentation,
  complete,
} from "./support/scalar-session.mjs";

const database = process.env.PARTNER_ISSUER_DATABASE_URL;
async function linkedFixture({ education = false, sourceOptions = {} } = {}) {
  const f = await fixture({ maxAge: 300, ...sourceOptions });
  let runtime = f.runtime;
  try {
    const definition = {
      id: f.config.origin + "/definitions/neutral-score",
      version: "1",
      credential_type: "NeutralScoreCredential",
      label: "Neutral score",
      max_validity_seconds: 3600,
      claims: [
        {
          name: "score",
          label: "Score",
          value_type: "integer",
          required: true,
        },
      ],
      profiles: [
        { name: "score_check", claim_paths: [["credentialSubject", "score"]] },
      ],
    };
    const providerDid = "did:web:wallet342.example",
      providerKey = providerDid + "#key-1";
    const provider = core.installDeterministicTestKey(
      providerKey,
      "issuer:241",
    );
    const authorizationId = "00000342-0000-4000-8000-000000000001";
    f.config.issuer = {
      databaseUrl: database,
      registryOrigin: f.config.verifier.registryOrigin,
      registryDid: f.registryDid,
      trustAnchorJwk: f.anchor,
      definitions: [
        {
          configurationId: "neutral-score",
          authorizationId,
          definitionId: definition.id,
          definitionVersion: "1",
          credentialType: definition.credential_type,
        },
      ],
      walletProviderDid: providerDid,
      walletProviderJwk: provider,
    };
    const now = f.clock();
    f.evidence.set(
      f.config.issuer.registryOrigin +
        "/issuer-authorizations/" +
        authorizationId +
        ".jwt",
      core.signIssuerAuthorizations({
        keyId: f.registryDid + "#anchor",
        header: {
          alg: "ES256",
          typ: "issuer-authorizations+jwt",
          kid: f.registryDid + "#anchor",
        },
        payload: {
          version: 1,
          id:
            f.config.issuer.registryOrigin +
            "/issuer-authorizations/" +
            authorizationId +
            ".jwt",
          issuer: f.registryDid,
          iat: now,
          exp: now + 300,
          authorizations: [
            {
              credential_issuer_did: f.identity.did,
              credential_issuer_key_id: f.identity.keyId,
              credential_issuer_public_jwk_sha256_thumbprint:
                core.publicJwkSha256Thumbprint(f.identity.publicJwk),
              definition,
              status: "active",
            },
          ],
        },
      }),
    );
    f.evidence.set(
      f.config.issuer.registryOrigin + "/trust-list.jwt",
      core.signTrustList({
        keyId: f.registryDid + "#anchor",
        header: {
          alg: "ES256",
          typ: "trust-list+jwt",
          kid: f.registryDid + "#anchor",
        },
        payload: {
          id: f.config.issuer.registryOrigin + "/trust-list.jwt",
          issuer: f.registryDid,
          iat: now,
          exp: now + 300,
          entries: [
            {
              issuer_did: providerDid,
              credential_types: ["WalletInstanceAttestation"],
              status: "active",
              public_jwk: provider,
            },
            ...(education
              ? [
                  {
                    issuer_did: f.issuerDid,
                    credential_types: ["UniversityEducationCredential"],
                    status: "active",
                    public_jwk: f.issuerJwk,
                    public_jwk_sha256_thumbprint:
                      core.publicJwkSha256Thumbprint(f.issuerJwk),
                  },
                ]
              : []),
          ],
        },
      }),
    );
    if (education) {
      delete f.config.verifier.scalar;
      const url =
        f.config.verifier.registryOrigin +
        "/scoped-verifier-permissions.jwt?verifier_did=" +
        encodeURIComponent(f.identity.did);
      f.evidence.set(
        url,
        core.signScopedVerifierPermissions({
          keyId: f.registryDid + "#anchor",
          header: {
            alg: "ES256",
            typ: "scoped-verifier-permissions+jwt",
            kid: f.registryDid + "#anchor",
          },
          payload: {
            version: 1,
            id: url,
            issuer: f.registryDid,
            iat: now,
            exp: now + 300,
            permissions: [
              {
                credential_issuer_did: f.issuerDid,
                definition_id: "urn:credworks:education",
                definition_version: "1",
                credential_type: "UniversityEducationCredential",
                verifier_did: f.identity.did,
                verifier_origin: f.config.origin,
                verifier_public_jwk_sha256_thumbprint:
                  core.publicJwkSha256Thumbprint(f.identity.publicJwk),
                profile_name: "education_eligibility",
                claim_paths: [
                  ["credentialSubject", "enrolled"],
                  ["credentialSubject", "institution_id"],
                ],
                status: "active",
              },
            ],
          },
        }),
      );
    }
    const pool = new Pool({ connectionString: database });
    try {
      await pool.query(
        "TRUNCATE partner_issuer_renewals,partner_issuer_offers,partner_issuer_nonces,partner_issuer_status,partner_issuer_identity",
      );
    } finally {
      await pool.end();
    }
    await bootstrapIssuerState(database, f.config.origin, f.identity);
    const restart = async () => {
      await runtime.close();
      runtime = await startRuntime(f.config, f.identity, {
        clock: f.clock,
        fetchEvidence: async (url) => {
          await f.beforeEvidence?.(url);
          assert(
            f.evidence.has(url),
            "only pinned fixture publications may resolve",
          );
          return f.evidence.get(url);
        },
      });
      f.runtime = runtime;
    };
    await restart();
    f.app = (path, body, capability) =>
      fetch(runtime.management + path, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          authorization: "Bearer " + f.config.managementToken,
          "content-type": "application/json",
          ...(capability ? { "x-session-capability": capability } : {}),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    const originalClose = f.close;
    return Object.assign(f, {
      restart,
      providerDid,
      providerKey,
      provider,
      close: async () => {
        await runtime.close();
        await originalClose();
      },
    });
  } catch (error) {
    await runtime.close();
    await f.close();
    throw error;
  }
}
async function linkedSession(f) {
  const { session, request } = await create(f);
  await complete(f, request, presentation(f, request));
  return session;
}
function input(f) {
  return {
    configuration_id: "neutral-score",
    interaction_id: "browser-372",
    claims: { score: 7 },
    valid_from: f.clock(),
    valid_until: f.clock() + 600,
    offer_expires_at: f.clock() + 100,
  };
}
function link(f, session, value = input(f)) {
  return f.app(
    `/management/sessions/${session.session_id}/issuance-offer`,
    value,
    session.correlation_capability,
  );
}
async function redeem(f, offer) {
  const response = await fetch(f.runtime.public + "/oid4vci/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": offer.pre_authorized_code,
    }),
  });
  assert.equal(response.status, 200, await response.clone().text());
  return response.json();
}
async function receive(
  f,
  token,
  holderId = "holder372",
  holder = core.installDeterministicTestKey(holderId, "holder"),
  nonceOverride,
) {
  const nonce =
    nonceOverride ??
    (await (
      await fetch(f.runtime.public + "/oid4vci/nonce", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      })
    ).json());
  const now = f.clock();
  const response = await fetch(f.runtime.public + "/oid4vci/credential", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer " + token.access_token,
    },
    body: JSON.stringify(
      (f.lastReceiptInput = {
        credential_configuration_id: "neutral-score",
        holder_public_jwk: holder,
        proofs: {
          jwt: [
            core.signCompactJwsJson({
              keyId: holderId,
              header: {
                alg: "ES256",
                typ: "openid4vci-proof+jwt",
                kid: holderId,
              },
              payload: { aud: f.config.origin, iat: now, nonce: nonce.c_nonce },
            }),
          ],
        },
        wallet_instance_attestation: core.signCompactJwsJson({
          keyId: f.providerKey,
          header: {
            alg: "ES256",
            typ: "wallet-instance-attestation+jwt",
            kid: f.providerKey,
          },
          payload: {
            iss: f.providerDid,
            aud: f.config.origin,
            iat: now,
            exp: now + 120,
            cnf: { jwk: holder },
            attestation_method: "mock_platform_attestation",
          },
        }),
      }),
    ),
  });
  return response;
}
test(
  "a delayed linked retry cannot invert issuance's offer-to-identity lock order",
  { skip: !database, timeout: 30000 },
  async () => {
    const f = await linkedFixture();
    const pool = new Pool({ connectionString: database });
    const lock = await pool.connect();
    let release;
    try {
      const session = await linkedSession(f),
        value = input(f);
      const offered = await link(f, session, value);
      assert.equal(offered.status, 201);
      const offer = await offered.json();
      let reached;
      const waiting = new Promise((resolve) => {
        reached = resolve;
      });
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      let pause = true;
      f.beforeEvidence = async (url) => {
        if (pause && url.includes("/issuer-authorizations/00000342")) {
          pause = false;
          reached();
          await gate;
        }
      };
      const delayed = link(f, session, value);
      await waiting;
      const token = await redeem(f, offer);
      const nonce = await (
        await fetch(f.runtime.public + "/oid4vci/nonce", { method: "POST" })
      ).json();
      await lock.query("BEGIN");
      await lock.query(
        "SELECT hash FROM partner_issuer_nonces WHERE hash=$1 FOR UPDATE",
        [core.sha256B64Url(nonce.c_nonce)],
      );
      const receiving = receive(
        f,
        token,
        "holder372",
        core.installDeterministicTestKey("holder372", "holder"),
        nonce,
      );
      const waitFor = async (table) => {
        const deadline = Date.now() + 3000;
        while (
          !(
            await pool.query(
              "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1) AS waiting",
              [`%${table}%`],
            )
          ).rows[0].waiting
        ) {
          if (Date.now() >= deadline)
            throw Error("HTTP operation did not reach fixture lock: " + table);
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      };
      await waitFor("partner_issuer_nonces");
      release();
      await waitFor("partner_issuer_offers");
      await lock.query("COMMIT");
      const [receipt, retry] = await Promise.all([receiving, delayed]);
      assert.equal(receipt.status, 200, await receipt.clone().text());
      assert.equal(retry.status, 409, await retry.clone().text());
      assert.deepEqual(await retry.json(), {
        error: { code: "ISSUER_OFFER_CONSUMED" },
      });
    } finally {
      release?.();
      await lock.query("ROLLBACK");
      lock.release();
      await pool.end();
      await f.close();
    }
  },
);
test(
  "a permitted neutral verification binds subsequent issuance to its authenticated holder",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      assert.notEqual(f.identity.did, f.issuerDid);
      const session = await linkedSession(f);
      const response = await link(f, session);
      assert.equal(response.status, 201, await response.clone().text());
      const offer = await response.json();
      const receipt = await receive(f, await redeem(f, offer));
      assert.equal(receipt.status, 200, await receipt.clone().text());
      const compact = (await receipt.json()).credentials[0].credential;
      const payload = core.verifySdJwtCredential({
        compactSdJwt: compact,
        issuerJwk: f.identity.publicJwk,
        options: {
          now_unix_seconds: f.clock(),
          required_claims: [["credentialSubject", "score"]],
          format: "w3c_vc_data_model",
        },
      }).processed_payload;
      assert.equal(payload.issuer, f.identity.did);
      assert.equal(payload.credentialSubject.score, 7);
      assert.equal(
        core.publicJwkSha256Thumbprint(payload.cnf.jwk),
        core.publicJwkSha256Thumbprint(
          core.installDeterministicTestKey("holder372", "holder"),
        ),
      );
    } finally {
      await f.close();
    }
  },
);
test(
  "concurrent linked creation and lost reply recover one original offer after restart",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const session = await linkedSession(f),
        value = input(f);
      // The server commits before publishing201 headers; the application loses the
      // response body and therefore has no offer ID or pre-authorized code.
      await new Promise((resolve, reject) => {
        const request = httpRequest(
          f.runtime.management +
            `/management/sessions/${session.session_id}/issuance-offer`,
          {
            method: "POST",
            headers: {
              authorization: "Bearer " + f.config.managementToken,
              "x-session-capability": session.correlation_capability,
              "content-type": "application/json",
            },
          },
          (response) => {
            assert.equal(response.statusCode, 201);
            response.destroy();
            resolve();
          },
        );
        request.on("error", reject);
        request.end(JSON.stringify(value));
      });
      await f.restart();
      const replies = await Promise.all(
        Array.from({ length: 8 }, () => link(f, session, value)),
      );
      const offers = [];
      for (const reply of replies) {
        assert.equal(reply.status, 201, await reply.clone().text());
        offers.push(await reply.json());
      }
      for (const offer of offers) assert.deepEqual(offer, offers[0]);
      const copiedAfterRestart = await link(
        f,
        { ...session, correlation_capability: core.randomUrlSafe(32) },
        value,
      );
      assert.equal(copiedAfterRestart.status, 409);
      assert.deepEqual(await copiedAfterRestart.json(), {
        error: { code: "ISSUER_BINDING_MISMATCH" },
      });
      const mismatch = await link(f, session, {
        ...value,
        claims: { score: 8 },
      });
      assert.equal(mismatch.status, 409);
      assert.deepEqual(await mismatch.json(), {
        error: { code: "ISSUER_BINDING_MISMATCH" },
      });
      const exchanges = await Promise.all(
        Array.from({ length: 8 }, () =>
          fetch(f.runtime.public + "/oid4vci/token", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type:
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
              "pre-authorized_code": offers[0].pre_authorized_code,
            }),
          }),
        ),
      );
      assert.equal(
        exchanges.filter((response) => response.status === 200).length,
        1,
      );
      for (const response of exchanges.filter(
        (response) => response.status !== 200,
      )) {
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { error: "invalid_grant" });
      }
      const token = await exchanges
        .find((response) => response.status === 200)
        .json();
      const receipt = await receive(f, token);
      assert.equal(receipt.status, 200);
      const originalReceipt = await receipt.json();
      const retryBody = f.lastReceiptInput;
      await f.restart();
      const recoveredReceipt = await fetch(
        f.runtime.public + "/oid4vci/credential",
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: "Bearer " + token.access_token,
          },
          body: JSON.stringify(retryBody),
        },
      );
      assert.equal(
        recoveredReceipt.status,
        200,
        await recoveredReceipt.clone().text(),
      );
      assert.deepEqual(await recoveredReceipt.json(), originalReceipt);
      const replay = await link(f, session, value);
      assert.equal(replay.status, 409);
      assert.deepEqual(await replay.json(), {
        error: { code: "ISSUER_OFFER_CONSUMED" },
      });
    } finally {
      await f.close();
    }
  },
);
test(
  "current source permission withdrawal refuses linked offer redemption",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const session = await linkedSession(f);
      const offer = await (await link(f, session)).json();
      f.evidence.set(
        f.permissionsUrl,
        f.signPermission({ status: "inactive" }),
      );
      assert.equal(
        (await f.app("/management/evidence/refresh", {})).status,
        200,
      );
      const response = await fetch(f.runtime.public + "/oid4vci/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": offer.pre_authorized_code,
        }),
      });
      assert.equal(response.status, 403);
      assert.deepEqual(await response.json(), { error: "scope_not_permitted" });
    } finally {
      await f.close();
    }
  },
);
test(
  "expiry after durable commit cannot restore result consumption or authorize a new offer",
  { skip: !database },
  async () => {
    const f = await linkedFixture(),
      pool = new Pool({ connectionString: database });
    const lock = await pool.connect();
    try {
      const session = await linkedSession(f),
        value = input(f);
      // Deferred trigger pauses COMMIT after all precommit application checks.
      // Database access injects the fault only; assertions use published HTTP.
      await pool.query(
        "CREATE OR REPLACE FUNCTION fixture342_commit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(342,2); RETURN NEW; END $$",
      );
      await pool.query(
        "CREATE CONSTRAINT TRIGGER fixture342_commit_wait AFTER INSERT ON partner_issuer_offers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fixture342_commit_wait()",
      );
      await lock.query("SELECT pg_advisory_lock(342,2)");
      const pending = link(f, session, value);
      const deadline = Date.now() + 3000;
      while (
        !(
          await pool.query(
            "SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=342 AND objid=2 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
          )
        ).rowCount
      ) {
        if (Date.now() > deadline)
          throw Error("linked creation did not reach deferred commit");
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      f.advance(120);
      await lock.query("SELECT pg_advisory_unlock(342,2)");
      const refused = await pending;
      assert.equal(refused.status, 503);
      assert.deepEqual(await refused.json(), {
        error: { code: "EVIDENCE_STALE" },
      });
      const consume = await f.app(
        `/management/sessions/${session.session_id}/result`,
        {},
        session.correlation_capability,
      );
      assert.equal(consume.status, 409);
      assert.deepEqual(await consume.json(), {
        error: { code: "RESULT_LINKED" },
      });
      await f.restart();
      const retry = await link(f, session, value);
      assert.equal(retry.status, 503);
      assert.deepEqual(await retry.json(), {
        error: { code: "EVIDENCE_STALE" },
      });
      const changed = await link(f, session, {
        ...value,
        claims: { score: 8 },
      });
      assert.equal(changed.status, 409);
      assert.deepEqual(await changed.json(), {
        error: { code: "ISSUER_BINDING_MISMATCH" },
      });
    } finally {
      await lock.query("SELECT pg_advisory_unlock_all()");
      lock.release();
      await pool.query(
        "DROP TRIGGER IF EXISTS fixture342_commit_wait ON partner_issuer_offers",
      );
      await pool.query("DROP FUNCTION IF EXISTS fixture342_commit_wait()");
      await pool.end();
      await f.close();
    }
  },
);
test(
  "copied references, different interactions, forged holder inputs and copied offers cannot transfer issuance",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const session = await linkedSession(f),
        value = input(f);
      const protectedPath = `/management/sessions/${session.session_id}/issuance-offer`;
      for (const bearer of [undefined, "Bearer forged-runtime-token"]) {
        const unauthorized = await fetch(f.runtime.management + protectedPath, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-session-capability": session.correlation_capability,
            ...(bearer ? { authorization: bearer } : {}),
          },
          body: JSON.stringify(value),
        });
        assert.equal(unauthorized.status, 401);
        assert.deepEqual(await unauthorized.json(), { error: "unauthorized" });
      }
      const publicReference = await fetch(f.runtime.public + protectedPath, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(value),
      });
      assert.equal(publicReference.status, 404);
      for (const [reference, body, expectedStatus, code] of [
        [
          { ...session, session_id: core.randomUrlSafe(32) },
          value,
          401,
          "SESSION_ACCESS_DENIED",
        ],
        [
          { ...session, correlation_capability: core.randomUrlSafe(32) },
          value,
          401,
          "SESSION_ACCESS_DENIED",
        ],
        [
          session,
          { ...value, interaction_id: "different-browser" },
          403,
          "ISSUER_BINDING_MISMATCH",
        ],
        [
          session,
          { ...value, recipient_jwk_thumbprint: core.randomUrlSafe(32) },
          400,
          "ISSUER_OFFER_BAD_REQUEST",
        ],
        [
          session,
          { ...value, issuer_did: "did:web:other342.example" },
          400,
          "ISSUER_OFFER_BAD_REQUEST",
        ],
      ]) {
        const refusal = await link(f, reference, body);
        assert.equal(
          refusal.status,
          expectedStatus,
          await refusal.clone().text(),
        );
        assert.deepEqual(await refusal.json(), { error: { code } });
      }
      const offer = await (await link(f, session, value)).json(),
        token = await redeem(f, offer);
      const otherId = "holder342-other",
        other = core.installDeterministicTestKey(otherId, "issuer:242");
      const copied = await receive(f, token, otherId, other);
      assert.equal(copied.status, 400);
      assert.deepEqual(await copied.json(), { error: "invalid_proof" });
      assert.equal((await receive(f, token)).status, 200);
      const consumed = await f.app(
        `/management/sessions/${session.session_id}/result`,
        {},
        session.correlation_capability,
      );
      assert.equal(consumed.status, 409);
      assert.deepEqual(await consumed.json(), {
        error: { code: "RESULT_CONSUMED" },
      });
    } finally {
      await f.close();
    }
  },
);
test(
  "a permitted built-in credential can bind a generic offer across persisted restart",
  { skip: !database },
  async () => {
    const f = await linkedFixture({ education: true });
    try {
      const created = await f.app("/management/sessions", {
        profile: "education_eligibility",
        interaction_id: "browser-372",
        purpose: "Authorize a synthetic holder for a neutral offer",
      });
      assert.equal(created.status, 201, await created.clone().text());
      const session = await created.json();
      const compactRequest = await (
        await fetch(f.runtime.public + new URL(session.request_uri).pathname)
      ).text();
      const request = core.verifyOid4vpRequestObject({
        compactJws: compactRequest,
        resolverResponses: {
          [core.didWebToHttpsUrl(f.identity.did)]: JSON.stringify(
            core.buildDidWebDocument(f.identity.did, [f.identity.publicJwk]),
          ),
        },
        nowUnixSeconds: f.clock(),
      }).payload;
      const holder = core.installDeterministicTestKey("holder372", "holder"),
        now = f.clock();
      const credential = core.issueSdJwtWithFormat({
        keyId: f.issuerKeyId,
        header: { alg: "ES256", typ: "vc+sd-jwt", kid: f.issuerKeyId },
        format: "w3c_vc_data_model",
        payload: {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          id: "https://issuer372.example/credentials/education-test",
          type: ["VerifiableCredential", "UniversityEducationCredential"],
          iss: f.issuerDid,
          issuer: f.issuerDid,
          iat: now,
          exp: now + 300,
          cnf: { jwk: holder },
          credentialSubject: { enrolled: true, institution_id: "example.edu" },
          credentialStatus: {
            id: f.statusUrl + "#7",
            type: "BitstringStatusListEntry",
            statusPurpose: "revocation",
            statusListIndex: "7",
            statusListCredential: f.statusUrl,
          },
        },
        disclosureSpecs: ["enrolled", "institution_id"].map((claim_name) => ({
          object_path: ["credentialSubject"],
          claim_name,
        })),
        salts: [core.randomUrlSafe(16), core.randomUrlSafe(16)],
      });
      const token = core.presentSdJwt({
        compactSdJwt: credential.compact,
        holderKeyId: "holder372",
        profile: {
          name: "education_eligibility",
          claim_paths: [
            ["credentialSubject", "enrolled"],
            ["credentialSubject", "institution_id"],
          ],
        },
        audience: request.client_id,
        nonce: request.nonce,
        iat: now,
      }).presentation;
      const delivered = await fetch(
        f.runtime.public + new URL(request.response_uri).pathname,
        {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            state: request.state,
            vp_token: JSON.stringify({ education_eligibility: [token] }),
          }),
        },
      );
      assert.equal(delivered.status, 200);
      assert.deepEqual(await delivered.json(), { status: "accepted" });
      const value = input(f);
      const barrier = new Pool({ connectionString: database });
      const lock = await barrier.connect();
      let replies;
      try {
        await lock.query("select pg_advisory_lock(368,1)");
        const pending = Array.from({ length: 8 }, () =>
          link(f, session, value),
        );
        // Hold allocation until concurrent requests authenticate the same live result.
        await new Promise((resolve) => setTimeout(resolve, 150));
        await lock.query("select pg_advisory_unlock(368,1)");
        replies = await Promise.all(pending);
      } finally {
        await lock.query("select pg_advisory_unlock_all()");
        lock.release();
        await barrier.end();
      }
      const offers = [];
      for (const response of replies) {
        assert.equal(response.status, 201, await response.clone().text());
        offers.push(await response.json());
      }
      for (const offer of offers) assert.deepEqual(offer, offers[0]);
      const offer = offers[0];
      await f.restart();
      const retried = await link(f, session, value);
      assert.equal(retried.status, 201, await retried.clone().text());
      assert.deepEqual(await retried.json(), offer);
      assert.equal((await receive(f, await redeem(f, offer))).status, 200);
    } finally {
      await f.close();
    }
  },
);

test(
  "restart cannot transfer a linked source key grant to a different fragment using the same JWK",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const session = await linkedSession(f),
        value = input(f);
      const linked = await link(f, session, value);
      assert.equal(linked.status, 201);
      const offer = await linked.json();
      const replacementKeyId = f.issuerDid + "#replacement";
      f.evidence.set(
        f.authorityUrl,
        f.signAuthority({ credential_issuer_key_id: replacementKeyId }),
      );
      f.config.verifier.scalar.issuerKeyId = replacementKeyId;
      // Supply current status under the replacement pin so the retained original
      // holder binding, rather than invalid startup evidence, is what refuses.
      const [statusHeader, statusPayload] =
        core.verifyBitstringStatusListCredential({
          compactJws: f.evidence.get(f.statusUrl),
          statusListJwk: f.issuerJwk,
        });
      f.evidence.set(
        f.statusUrl,
        core.signBitstringStatusListCredential({
          keyId: f.issuerKeyId,
          header: { ...statusHeader, kid: replacementKeyId },
          payload: statusPayload,
        }),
      );
      await f.restart();
      const retry = await link(f, session, value);
      assert.equal(retry.status, 403, await retry.clone().text());
      assert.deepEqual(await retry.json(), {
        error: { code: "ISSUER_BINDING_MISMATCH" },
      });
      const retrieved = await fetch(
        f.runtime.public +
          new URL(offer.credential_offer_uri).pathname +
          new URL(offer.credential_offer_uri).search,
      );
      assert.equal(retrieved.status, 403);
      const token = await fetch(f.runtime.public + "/oid4vci/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": offer.pre_authorized_code,
        }),
      });
      assert.equal(token.status, 403);
    } finally {
      await f.close();
    }
  },
);

test(
  "an identical link delayed in authority fetch resolves the concurrently committed offer",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    let release;
    try {
      const session = await linkedSession(f),
        value = input(f);
      let reached;
      const waiting = new Promise((resolve) => {
        reached = resolve;
      });
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      let pause = true;
      f.beforeEvidence = async (url) => {
        if (pause && url.includes("/issuer-authorizations/00000342")) {
          pause = false;
          reached();
          await gate;
        }
      };
      const delayed = link(f, session, value);
      await waiting;
      const committed = await link(f, session, value);
      assert.equal(committed.status, 201, await committed.clone().text());
      const offer = await committed.json();
      release();
      const retry = await delayed;
      assert.equal(retry.status, 201, await retry.clone().text());
      assert.deepEqual(await retry.json(), offer);
    } finally {
      release?.();
      await f.close();
    }
  },
);

test(
  "rollback before commit retains only the exact live link retry and restart never revives a lost verification",
  { skip: !database },
  async () => {
    const f = await linkedFixture(),
      pool = new Pool({ connectionString: database });
    const inject = async () => {
      await pool.query(
        "CREATE OR REPLACE FUNCTION fixture342_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture342 injected rollback'; END $$",
      );
      await pool.query(
        "CREATE TRIGGER fixture342_rollback BEFORE INSERT ON partner_issuer_offers FOR EACH ROW EXECUTE FUNCTION fixture342_rollback()",
      );
    };
    const clear = async () => {
      await pool.query(
        "DROP TRIGGER IF EXISTS fixture342_rollback ON partner_issuer_offers",
      );
      await pool.query("DROP FUNCTION IF EXISTS fixture342_rollback()");
    };
    try {
      const session = await linkedSession(f),
        value = input(f);
      await inject();
      const refused = await link(f, session, value);
      assert.equal(refused.status, 503);
      assert.deepEqual(await refused.json(), {
        error: { code: "ISSUER_STATE_UNAVAILABLE" },
      });
      const ordinary = await f.app(
        `/management/sessions/${session.session_id}/result`,
        {},
        session.correlation_capability,
      );
      assert.equal(ordinary.status, 409);
      assert.deepEqual(await ordinary.json(), {
        error: { code: "RESULT_LINKED" },
      });
      const different = await link(f, session, {
        ...value,
        claims: { score: 8 },
      });
      assert.equal(different.status, 409);
      await clear();
      const recovered = await link(f, session, value);
      assert.equal(recovered.status, 201, await recovered.clone().text());
      assert.equal(
        (await receive(f, await redeem(f, await recovered.json()))).status,
        200,
      );
      const lost = await linkedSession(f);
      await inject();
      assert.equal((await link(f, lost, value)).status, 503);
      await clear();
      await f.restart();
      const restarted = await link(f, lost, value);
      assert.equal(restarted.status, 401);
      assert.deepEqual(await restarted.json(), {
        error: { code: "SESSION_ACCESS_DENIED" },
      });
    } finally {
      await clear();
      await pool.end();
      await f.close();
    }
  },
);
test(
  "original source deadline bounds both linked offer and redeemed token across evidence refresh",
  { skip: !database },
  async () => {
    const f = await linkedFixture({ sourceOptions: { permissionTTL: 20 } });
    try {
      const original = f.clock(),
        session = await linkedSession(f),
        value = input(f);
      const response = await link(f, session, value);
      assert.equal(response.status, 201);
      const offer = await response.json();
      assert.equal(offer.expires_at, original + 20);
      const token = await redeem(f, offer);
      assert.equal(token.expires_in, 20);
      f.advance(21);
      f.evidence.set(f.permissionsUrl, f.signPermission());
      assert.equal(
        (await f.app("/management/evidence/refresh", {})).status,
        200,
      );
      const retried = await link(f, session, value);
      assert.equal(retried.status, 503);
      assert.deepEqual(await retried.json(), {
        error: { code: "EVIDENCE_STALE" },
      });
      const receipt = await receive(f, token);
      assert.equal(receipt.status, 401);
      assert.deepEqual(await receipt.json(), { error: "invalid_token" });
    } finally {
      await f.close();
    }
  },
);
test(
  "current revocation after token redemption refuses the bound credential",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const session = await linkedSession(f),
        offer = await (await link(f, session)).json(),
        token = await redeem(f, offer);
      const status = core.verifyCompactJwsJson({
        compactJws: f.evidence.get(f.statusUrl),
        publicJwk: f.issuerJwk,
      });
      status.payload.credentialSubject.encodedList =
        core.encodeBitstringStatusList(131072, [7]);
      f.evidence.set(
        f.statusUrl,
        core.signBitstringStatusListCredential({
          keyId: f.issuerKeyId,
          header: status.header,
          payload: status.payload,
        }),
      );
      assert.equal(
        (await f.app("/management/evidence/refresh", {})).status,
        200,
      );
      const receipt = await receive(f, token);
      assert.equal(receipt.status, 403);
      assert.deepEqual(await receipt.json(), { error: "status_check_failed" });
    } finally {
      await f.close();
    }
  },
);
test(
  "pending, refused and ordinarily consumed verifications cannot authorize linked issuance",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const pending = await create(f);
      const early = await link(f, pending.session);
      assert.equal(early.status, 409);
      assert.deepEqual(await early.json(), {
        error: { code: "RESULT_PENDING" },
      });
      await complete(
        f,
        pending.request,
        presentation(f, pending.request, {
          payload: { credentialSubject: { active: "false" } },
        }),
      );
      const denied = await link(f, pending.session);
      assert.equal(denied.status, 403);
      assert.deepEqual(await denied.json(), {
        error: { code: "VERIFICATION_NOT_PERMITTED" },
      });
      const consumed = await linkedSession(f);
      assert.equal(
        (
          await f.app(
            `/management/sessions/${consumed.session_id}/result`,
            {},
            consumed.correlation_capability,
          )
        ).status,
        200,
      );
      const spent = await link(f, consumed);
      assert.equal(spent.status, 409);
      assert.deepEqual(await spent.json(), {
        error: { code: "RESULT_CONSUMED" },
      });
    } finally {
      await f.close();
    }
  },
);

test(
  "a current grant for another issuing DID cannot authorize recovery or redemption of the linked output",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const session = await linkedSession(f),
        value = input(f),
        offer = await (await link(f, session, value)).json();
      await f.restart();
      const target =
        f.config.issuer.registryOrigin +
        "/issuer-authorizations/00000342-0000-4000-8000-000000000001.jwt";
      const authority = core.verifyCompactJwsJson({
        compactJws: f.evidence.get(target),
        publicJwk: f.anchor,
      });
      authority.payload.authorizations[0].credential_issuer_did = f.issuerDid;
      authority.payload.authorizations[0].credential_issuer_key_id =
        f.issuerKeyId;
      authority.payload.authorizations[0].credential_issuer_public_jwk_sha256_thumbprint =
        core.publicJwkSha256Thumbprint(f.issuerJwk);
      f.evidence.set(
        target,
        core.signIssuerAuthorizations({
          keyId: f.registryDid + "#anchor",
          header: authority.header,
          payload: authority.payload,
        }),
      );
      const retry = await link(f, session, value);
      assert.equal(retry.status, 503);
      assert.deepEqual(await retry.json(), {
        error: { code: "ISSUER_AUTHORITY_UNAVAILABLE" },
      });
      const uri = new URL(offer.credential_offer_uri);
      assert.equal(
        (await fetch(f.runtime.public + uri.pathname + uri.search)).status,
        503,
      );
      const token = await fetch(f.runtime.public + "/oid4vci/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": offer.pre_authorized_code,
        }),
      });
      assert.equal(token.status, 503);
      assert.deepEqual(await token.json(), {
        error: "issuer_authority_unavailable",
      });
    } finally {
      await f.close();
    }
  },
);

test(
  "the original signed credential expiry also caps linked offer validity",
  { skip: !database },
  async () => {
    const f = await linkedFixture();
    try {
      const original = f.clock(),
        { session, request } = await create(f);
      await complete(
        f,
        request,
        presentation(f, request, {
          payload: {
            exp: original + 45,
            validUntil: new Date((original + 45) * 1000)
              .toISOString()
              .replace(".000Z", "Z"),
          },
        }),
      );
      const value = input(f),
        response = await link(f, session, value);
      assert.equal(response.status, 201, await response.clone().text());
      const offer = await response.json();
      assert.equal(offer.expires_at, original + 45);
      const token = await redeem(f, offer);
      assert.equal(token.expires_in, 45);
      f.advance(46);
      await f.restart();
      const retry = await link(f, session, value);
      assert.equal(retry.status, 503);
      assert.deepEqual(await retry.json(), {
        error: { code: "EVIDENCE_STALE" },
      });
    } finally {
      await f.close();
    }
  },
);

test("linked issuance preserves actual retained-history source key and rechecks withdrawal after restart", { skip: !database }, async () => {
  const f = await linkedFixture({ sourceOptions: { retainedKeys: true } });
  try {
    const { session, request } = await create(f);
    await complete(f, request, presentation(f, request, { issuerKeyId: f.newIssuerKeyId }));
    const value = input(f);
    const response = await link(f, session, value);
    assert.equal(response.status, 201, await response.clone().text());
    const offer = await response.json();
    await f.restart();
    const retry = await link(f, session, value);
    assert.equal(retry.status, 201, await retry.clone().text());
    assert.deepEqual(await retry.json(), offer);
    const authority = core.verifyCompactJwsJson({ compactJws: f.evidence.get(f.authorityUrl), publicJwk: f.anchor });
    authority.payload.authorizations[1].key_state = "withdrawn";
    f.evidence.set(f.authorityUrl, f.signAuthority({}, authority.payload.authorizations));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const withdrawn = await link(f, session, value);
    assert.equal(withdrawn.status, 403, await withdrawn.clone().text());
    assert.equal((await withdrawn.json()).error.code, "ISSUER_BINDING_MISMATCH");
    const retrieved = await fetch(f.runtime.public + new URL(offer.credential_offer_uri).pathname + new URL(offer.credential_offer_uri).search);
    assert.equal(retrieved.status, 403, await retrieved.clone().text());
    const token = await fetch(f.runtime.public + "/oid4vci/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": offer.pre_authorized_code }),
    });
    assert.equal(token.status, 403, await token.clone().text());
    await f.restart();
    assert.equal((await link(f, session, value)).status, 403);
  } finally { await f.close(); }
});

test("withdrawn retained source cannot first link or restore consumed verification", { skip: !database }, async () => {
  const f = await linkedFixture({ sourceOptions: { retainedKeys: true } });
  try {
    const { session, request } = await create(f);
    await complete(f, request, presentation(f, request));
    f.evidence.set(f.authorityUrl, f.signAuthority({ key_state: "withdrawn" }));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    assert.equal((await link(f, session)).status, 403);
    const result = await f.app(`/management/sessions/${session.session_id}/result`, {}, session.correlation_capability);
    assert.equal((await result.json()).error.code, "ISSUER_NOT_AUTHORIZED");
    f.evidence.set(f.authorityUrl, f.signAuthority());
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 200);
    const refused = await link(f, session);
    assert.equal(refused.status, 409);
    assert.equal((await refused.json()).error.code, "RESULT_CONSUMED");
  } finally { await f.close(); }
});
