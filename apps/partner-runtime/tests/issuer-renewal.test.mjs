import assert from "node:assert/strict";
import { test } from "node:test";
import * as core from "@unsw-vc/identity-core-node";
import { issuerFixture } from "./support/issuer-lifecycle.mjs";

const database = process.env.PARTNER_ISSUER_DATABASE_URL;
const otherDatabase = process.env.PARTNER_OTHER_ISSUER_DATABASE_URL;

test(
  "protected renewal freezes an exact predecessor without retirement or successor delivery",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, {
      public: 29220,
      management: 29221,
      evidence: 29222,
    });
    try {
      const predecessor = await issuer.issue("holder:399");
      const correlation = core.randomUrlSafe(32);
      const input = {
        version: 1,
        predecessor_issuance_id: predecessor.id,
        configuration_id: "entitlement",
        claims: { enabled: false },
        valid_from: issuer.initial,
        valid_until: issuer.initial + 3600,
        offer_expires_at: issuer.initial + 120,
      };
      const response = await fetch(
        issuer.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + issuer.config.managementToken,
            "content-type": "application/json",
            "idempotency-key": correlation,
          },
          body: JSON.stringify(input),
        },
      );
      assert.equal(response.status, 201, await response.clone().text());
      const renewal = await response.json();
      assert.equal(renewal.version, 1);
      assert.equal(renewal.status, "awaiting_holder");
      assert.match(renewal.renewal_id, /^[A-Za-z0-9_-]{22}$/);
      assert.equal(await issuer.status(predecessor), false);
      const uri = new URL(renewal.renewal_request_uri);
      assert.equal(uri.origin, issuer.config.origin);
      const request = await fetch(
        issuer.runtime.public + uri.pathname + uri.search,
      );
      assert.equal(request.status, 200, await request.clone().text());
      const intent = await request.json();
      assert.equal(intent.predecessor.credential_id, predecessor.payload.id);
      assert.deepEqual(intent.claims, { enabled: false });
      const retry = await fetch(
        issuer.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + issuer.config.managementToken,
            "content-type": "application/json",
            "idempotency-key": correlation,
          },
          body: JSON.stringify(input),
        },
      );
      assert.equal(retry.status, 201, await retry.clone().text());
      assert.deepEqual(await retry.json(), renewal);
      const changed = await fetch(
        issuer.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + issuer.config.managementToken,
            "content-type": "application/json",
            "idempotency-key": correlation,
          },
          body: JSON.stringify({ ...input, claims: { enabled: true } }),
        },
      );
      assert.equal(changed.status, 409, await changed.clone().text());
      assert.equal(
        (await changed.json()).error.code,
        "ISSUER_RENEWAL_BINDING_MISMATCH",
      );
      const forbiddenRead = await fetch(
        issuer.runtime.public +
          uri.pathname +
          "?capability=" +
          core.randomUrlSafe(32),
      );
      assert.equal(forbiddenRead.status, 404);
      const count = await issuer.pool.query(
        "SELECT count(*)::int AS count FROM partner_issuer_offers",
      );
      assert.equal(count.rows[0].count, 1);
      assert.equal(
        intent.authorize_uri,
        issuer.config.origin +
          "/partner-renewals/" +
          renewal.renewal_id +
          "/authorize",
      );
    } finally {
      await issuer.close();
    }
  },
);

async function createRenewal(
  issuer,
  predecessor,
  correlation = core.randomUrlSafe(32),
  overrides = {},
) {
  const input = {
    version: 1,
    predecessor_issuance_id: predecessor.id,
    configuration_id: "entitlement",
    claims: { enabled: false },
    valid_from: issuer.initial,
    valid_until: issuer.initial + 3600,
    offer_expires_at: issuer.initial + 120,
    ...overrides,
  };
  const response = await fetch(
    issuer.runtime.management + "/management/issuer/renewals",
    {
      method: "POST",
      headers: {
        authorization: "Bearer " + issuer.config.managementToken,
        "content-type": "application/json",
        "idempotency-key": correlation,
      },
      body: JSON.stringify(input),
    },
  );
  assert.equal(response.status, 201, await response.clone().text());
  return await response.json();
}
async function holderProof(issuer, audience, keyId = "holder:399") {
  const response = await fetch(issuer.runtime.public + "/oid4vci/nonce", {
    method: "POST",
  });
  assert.equal(response.status, 200);
  const nonce = (await response.json()).c_nonce;
  return core.signCompactJwsJson({
    header: { alg: "ES256", typ: "openid4vci-proof+jwt", kid: keyId },
    payload: { aud: audience, iat: issuer.now, nonce },
    keyId,
  });
}
function publicPost(issuer, path, body) {
  return fetch(issuer.runtime.public + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}
test(
  "fresh exact holder authorization consumes nonce and allocates only one immutable successor",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, {
      public: 29220,
      management: 29221,
      evidence: 29222,
    });
    try {
      const predecessor = await issuer.issue("holder:399");
      const renewal = await createRenewal(issuer, predecessor);
      const capability = new URL(renewal.renewal_request_uri).searchParams.get(
        "capability",
      );
      const path = "/partner-renewals/" + renewal.renewal_id + "/authorize";
      const proof = await holderProof(issuer, issuer.config.origin + path);
      const authorized = await publicPost(issuer, path, {
        version: 1,
        capability,
        proof: { proof_type: "jwt", jwt: proof },
      });
      assert.equal(authorized.status, 200, await authorized.clone().text());
      const offer = await authorized.json();
      assert.equal(offer.renewal_id, renewal.renewal_id);
      assert.equal(await issuer.status(predecessor), false);
      const replay = await publicPost(issuer, path, {
        version: 1,
        capability,
        proof: { proof_type: "jwt", jwt: proof },
      });
      assert.equal(replay.status, 400, await replay.clone().text());
      assert.equal(
        (await replay.json()).error.code,
        "ISSUER_RENEWAL_INVALID_PROOF",
      );
      const retry = await publicPost(issuer, path, {
        version: 1,
        capability,
        proof: {
          proof_type: "jwt",
          jwt: await holderProof(issuer, issuer.config.origin + path),
        },
      });
      assert.equal(retry.status, 200, await retry.clone().text());
      assert.deepEqual(await retry.json(), offer);
      const capsOnly = await publicPost(issuer, path, {
        version: 1,
        capability,
      });
      assert.equal(capsOnly.status, 400);
      const count = await issuer.pool.query(
        "SELECT count(*)::int AS count FROM partner_issuer_offers",
      );
      assert.equal(count.rows[0].count, 2);
    } finally {
      await issuer.close();
    }
  },
);

test(
  "successor issuance delivers a bound pending receipt without retiring the predecessor",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, {
      public: 29220,
      management: 29221,
      evidence: 29222,
    });
    try {
      const predecessor = await issuer.issue("holder:399");
      const renewal = await createRenewal(issuer, predecessor);
      const capability = new URL(renewal.renewal_request_uri).searchParams.get(
        "capability",
      );
      const path = "/partner-renewals/" + renewal.renewal_id + "/authorize";
      const response = await publicPost(issuer, path, {
        version: 1,
        capability,
        proof: {
          proof_type: "jwt",
          jwt: await holderProof(issuer, issuer.config.origin + path),
        },
      });
      assert.equal(response.status, 200, await response.clone().text());
      const offer = await response.json();
      const successor = await issuer.issueOffer({
        ...offer,
        holderId: "holder:399",
        holder: predecessor.payload.cnf.jwk,
      });
      const receipt = successor.responseBody.x_credworks_renewal;
      assert.equal(receipt.version, 1);
      assert.equal(receipt.renewal_id, renewal.renewal_id);
      assert.equal(receipt.predecessor_credential_id, predecessor.payload.id);
      assert.equal(receipt.successor_credential_id, successor.payload.id);
      assert.equal(receipt.status, "pending_confirmation");
      assert.equal(await issuer.status(predecessor), false);
      assert.equal(await issuer.status(successor), false);
      assert.equal(
        receipt.confirm_uri,
        issuer.config.origin +
          "/partner-renewals/" +
          renewal.renewal_id +
          "/receipts/" +
          receipt.receipt_id +
          "/successors/" +
          successor.id +
          "/confirm",
      );
      const pathConfirm = new URL(receipt.confirm_uri).pathname;
      const confirmation = await publicPost(issuer, pathConfirm, {
        version: 1,
        event: "credential_accepted",
        proof: {
          proof_type: "jwt",
          jwt: await holderProof(issuer, receipt.confirm_uri),
        },
      });
      assert.equal(confirmation.status, 200, await confirmation.clone().text());
      const confirmed = await confirmation.json();
      assert.equal(confirmed.status, "completed");
      assert.equal(confirmed.predecessor_credential_id, predecessor.payload.id);
      assert.equal(confirmed.successor_credential_id, successor.payload.id);
      assert.equal(await issuer.status(predecessor), true);
      assert.equal(await issuer.status(successor), false);
      await issuer.restart();
      const recovered = await publicPost(
        issuer,
        new URL(receipt.status_uri).pathname,
        {
          version: 1,
          proof: {
            proof_type: "jwt",
            jwt: await holderProof(issuer, receipt.status_uri),
          },
        },
      );
      assert.equal(recovered.status, 200, await recovered.clone().text());
      assert.deepEqual(await recovered.json(), confirmed);
    } finally {
      await issuer.close();
    }
  },
);

test(
  "expired unissued authorization invalidates the old offer before a fresh attempt",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, {
      public: 29220,
      management: 29221,
      evidence: 29222,
    });
    try {
      const predecessor = await issuer.issue("holder:399");
      const renewal = await createRenewal(issuer, predecessor);
      const capability = new URL(renewal.renewal_request_uri).searchParams.get(
        "capability",
      );
      const path = "/partner-renewals/" + renewal.renewal_id + "/authorize";
      const response = await publicPost(issuer, path, {
        version: 1,
        capability,
        proof: {
          proof_type: "jwt",
          jwt: await holderProof(issuer, issuer.config.origin + path),
        },
      });
      assert.equal(response.status, 200, await response.clone().text());
      const offer = await response.json();
      issuer.now = issuer.initial + 120;
      const next = await fetch(
        issuer.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + issuer.config.managementToken,
            "content-type": "application/json",
            "idempotency-key": core.randomUrlSafe(32),
          },
          body: JSON.stringify({
            version: 1,
            predecessor_issuance_id: predecessor.id,
            configuration_id: "entitlement",
            claims: { enabled: false },
            valid_from: issuer.initial,
            valid_until: issuer.initial + 3600,
            offer_expires_at: issuer.initial + 240,
          }),
        },
      );
      assert.equal(next.status, 201, await next.clone().text());
      const oldToken = await fetch(issuer.runtime.public + "/oid4vci/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": offer.pre_authorized_code,
        }),
      });
      assert.equal(oldToken.status, 400);
      assert.equal(await issuer.status(predecessor), false);
      await issuer.restart();
    } finally {
      await issuer.close();
    }
  },
);

async function renewedPair(issuer) {
  const predecessor = await issuer.issue("holder:399");
  const renewal = await createRenewal(issuer, predecessor);
  const path = "/partner-renewals/" + renewal.renewal_id + "/authorize";
  const capability = new URL(renewal.renewal_request_uri).searchParams.get(
    "capability",
  );
  const response = await publicPost(issuer, path, {
    version: 1,
    capability,
    proof: {
      proof_type: "jwt",
      jwt: await holderProof(issuer, issuer.config.origin + path),
    },
  });
  assert.equal(response.status, 200, await response.clone().text());
  const offer = await response.json();
  const successor = await issuer.issueOffer({
    ...offer,
    holderId: "holder:399",
    holder: predecessor.payload.cnf.jwk,
  });
  return {
    predecessor,
    renewal,
    offer,
    successor,
    receipt: successor.responseBody.x_credworks_renewal,
  };
}
async function operation(
  issuer,
  uri,
  event,
  key = "holder:399",
  target = issuer.runtime.public,
) {
  const proof = await holderProof(issuer, uri, key);
  return fetch(target + new URL(uri).pathname, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      version: 1,
      ...(event ? { event } : {}),
      proof: { proof_type: "jwt", jwt: proof },
    }),
  });
}
test(
  "lost credential reply returns the same signed successor and receipt without spent-code recovery",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, {
      public: 29220,
      management: 29221,
      evidence: 29222,
    });
    try {
      const pair = await renewedPair(issuer);
      await issuer.restart();
      const repeated = await fetch(
        issuer.runtime.public + "/oid4vci/credential",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + pair.successor.token,
            "content-type": "application/json",
          },
          body: JSON.stringify(pair.successor.credentialBody),
        },
      );
      assert.equal(repeated.status, 200, await repeated.clone().text());
      assert.deepEqual(await repeated.json(), pair.successor.responseBody);
      const spent = await fetch(issuer.runtime.public + "/oid4vci/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": pair.offer.pre_authorized_code,
        }),
      });
      assert.equal(spent.status, 400);
      assert.equal(await issuer.status(pair.predecessor), false);
      assert.equal(
        (
          await issuer.pool.query(
            "SELECT count(*)::int AS count FROM partner_issuer_offers",
          )
        ).rows[0].count,
        2,
      );
    } finally {
      await issuer.close();
    }
  },
);
test(
  "fresh cancellation retires only an issued unconfirmed successor before another attempt",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, {
      public: 29220,
      management: 29221,
      evidence: 29222,
    });
    try {
      const unrelated = await issuer.issue("holder:397-owner");
      const pair = await renewedPair(issuer);
      const cancellation = await operation(issuer, pair.receipt.cancel_uri);
      assert.equal(cancellation.status, 200, await cancellation.clone().text());
      assert.equal((await cancellation.json()).status, "cancelled");
      assert.equal(await issuer.status(pair.predecessor), false);
      assert.equal(await issuer.status(pair.successor), true);
      assert.equal(await issuer.status(unrelated), false);
      const confirmation = await operation(
        issuer,
        pair.receipt.confirm_uri,
        "credential_accepted",
      );
      assert.equal(confirmation.status, 409);
      assert.equal(
        (await confirmation.json()).error.code,
        "ISSUER_RENEWAL_NOT_CONFIRMABLE",
      );
      const next = await createRenewal(issuer, pair.predecessor);
      assert.notEqual(next.renewal_id, pair.renewal.renewal_id);
      await issuer.restart();
      assert.equal(await issuer.status(pair.successor), true);
    } finally {
      await issuer.close();
    }
  },
);
test(
  "wrong holder, audience, receipt and capability-only calls cannot authorize retirement",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, {
      public: 29220,
      management: 29221,
      evidence: 29222,
    });
    try {
      core.installDeterministicTestKey("holder:399-wrong", "issuer:244");
      const pair = await renewedPair(issuer);
      for (const [uri, event, key] of [
        [pair.receipt.confirm_uri, "credential_accepted", "holder:399-wrong"],
        [pair.receipt.cancel_uri, undefined, "holder:399-wrong"],
        [pair.receipt.status_uri, undefined, "holder:399-wrong"],
      ]) {
        const response = await operation(issuer, uri, event, key);
        assert.equal(response.status, 400, await response.clone().text());
        assert.equal(
          (await response.json()).error.code,
          "ISSUER_RENEWAL_INVALID_PROOF",
        );
      }
      const wrongAudience = await publicPost(
        issuer,
        new URL(pair.receipt.confirm_uri).pathname,
        {
          version: 1,
          event: "credential_accepted",
          proof: {
            proof_type: "jwt",
            jwt: await holderProof(
              issuer,
              "https://other-issuer.example" +
                new URL(pair.receipt.confirm_uri).pathname,
            ),
          },
        },
      );
      assert.equal(wrongAudience.status, 400);
      assert.equal(
        (await wrongAudience.json()).error.code,
        "ISSUER_RENEWAL_INVALID_PROOF",
      );
      for (const uri of [
        pair.receipt.confirm_uri.replace(
          pair.receipt.receipt_id,
          core.randomUrlSafe(32),
        ),
        pair.receipt.confirm_uri.replace(
          "/successors/" + pair.successor.id,
          "/successors/" + pair.predecessor.id,
        ),
      ]) {
        const wrong = await operation(issuer, uri, "credential_accepted");
        assert.equal(wrong.status, 409, await wrong.clone().text());
        assert.equal(
          (await wrong.json()).error.code,
          "ISSUER_RENEWAL_BINDING_MISMATCH",
        );
      }
      for (const uri of [pair.receipt.confirm_uri, pair.receipt.cancel_uri]) {
        const noProof = await publicPost(issuer, new URL(uri).pathname, {
          version: 1,
          capability: pair.receipt.receipt_id,
          ...(uri === pair.receipt.confirm_uri
            ? { event: "credential_accepted" }
            : {}),
        });
        assert.equal(noProof.status, 400);
        assert.equal(
          (await noProof.json()).error.code,
          "ISSUER_RENEWAL_BAD_REQUEST",
        );
      }
      assert.equal(await issuer.status(pair.predecessor), false);
      assert.equal(await issuer.status(pair.successor), false);
    } finally {
      await issuer.close();
    }
  },
);

async function authorize(
  issuer,
  renewal,
  target = issuer.runtime.public,
  key = "holder:399",
  audience,
) {
  const path = "/partner-renewals/" + renewal.renewal_id + "/authorize";
  return fetch(target + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      version: 1,
      capability: new URL(renewal.renewal_request_uri).searchParams.get(
        "capability",
      ),
      proof: {
        proof_type: "jwt",
        jwt: await holderProof(
          issuer,
          audience ?? issuer.config.origin + path,
          key,
        ),
      },
    }),
  });
}
const fixturePorts = { public: 29220, management: 29221, evidence: 29222 };
test(
  "independent runtime processes serialize fresh authorization and confirmation retries",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    let child;
    try {
      const predecessor = await issuer.issue("holder:399");
      const correlation = core.randomUrlSafe(32);
      const renewal = await createRenewal(issuer, predecessor, correlation);
      child = await issuer.process({ public: 29240, management: 29241 });
      const authorized = await Promise.all([
        authorize(issuer, renewal),
        authorize(issuer, renewal, child.public),
      ]);
      for (const response of authorized)
        assert.equal(response.status, 200, await response.clone().text());
      const [offer, other] = await Promise.all(
        authorized.map((response) => response.json()),
      );
      assert.deepEqual(other, offer);
      const successor = await issuer.issueOffer({
        ...offer,
        holderId: "holder:399",
        holder: predecessor.payload.cnf.jwk,
      });
      const receipt = successor.responseBody.x_credworks_renewal;
      const confirmations = await Promise.all([
        operation(issuer, receipt.confirm_uri, "credential_accepted"),
        operation(
          issuer,
          receipt.confirm_uri,
          "credential_accepted",
          "holder:399",
          child.public,
        ),
      ]);
      for (const response of confirmations)
        assert.equal(response.status, 200, await response.clone().text());
      const [first, second] = await Promise.all(
        confirmations.map((response) => response.json()),
      );
      assert.deepEqual(first, second);
      assert.equal(first.status, "completed");
      assert.equal(await issuer.status(predecessor), true);
      assert.equal(await issuer.status(successor), false);
      const recovered = await createRenewal(issuer, predecessor, correlation);
      assert.equal(recovered.renewal_id, renewal.renewal_id);
      assert.equal(recovered.status, "completed");
      issuer.now = issuer.initial + 121;
      const pastDeadline = await createRenewal(
        issuer,
        predecessor,
        correlation,
      );
      assert.equal(pastDeadline.status, "completed");
      assert.equal(pastDeadline.expires_at, renewal.expires_at);
      assert.equal(
        (
          await issuer.pool.query(
            "SELECT count(*)::int AS count FROM partner_issuer_offers",
          )
        ).rows[0].count,
        2,
      );
    } finally {
      await child?.stop();
      await issuer.close();
    }
  },
);
test(
  "confirmation and cancellation race has one durable winner without changing an unrelated instance",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    let child;
    try {
      const unrelated = await issuer.issue("holder:397-owner");
      const pair = await renewedPair(issuer);
      child = await issuer.process({ public: 29240, management: 29241 });
      const [confirmation, cancellation] = await Promise.all([
        operation(issuer, pair.receipt.confirm_uri, "credential_accepted"),
        operation(
          issuer,
          pair.receipt.cancel_uri,
          undefined,
          "holder:399",
          child.public,
        ),
      ]);
      assert.deepEqual(
        [confirmation.status, cancellation.status].sort(),
        [200, 409],
      );
      if (confirmation.status === 200) {
        assert.equal((await confirmation.json()).status, "completed");
        assert.equal(await issuer.status(pair.predecessor), true);
        assert.equal(await issuer.status(pair.successor), false);
      } else {
        assert.equal((await cancellation.json()).status, "cancelled");
        assert.equal(await issuer.status(pair.predecessor), false);
        assert.equal(await issuer.status(pair.successor), true);
      }
      assert.equal(await issuer.status(unrelated), false);
      await child.stop();
      child = undefined;
      await issuer.restart();
      assert.equal(await issuer.status(unrelated), false);
    } finally {
      await child?.stop();
      await issuer.close();
    }
  },
);
async function failRevocation(issuer, id) {
  // Inject an actual PostgreSQL write failure. All transitions under test still
  // enter through HTTP; no issuer method or cryptographic helper is replaced.
  assert.match(id, /^[A-Za-z0-9_-]{22}$/);
  await issuer.pool.query(
    `CREATE FUNCTION vc399_fail_retirement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id = '${id}' AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN RAISE EXCEPTION 'vc399 controlled persistence failure'; END IF; RETURN NEW; END $$`,
  );
  await issuer.pool.query(
    "CREATE TRIGGER vc399_fail_retirement BEFORE UPDATE ON partner_issuer_offers FOR EACH ROW EXECUTE FUNCTION vc399_fail_retirement()",
  );
}
async function clearFailure(issuer) {
  await issuer.pool.query(
    "DROP TRIGGER IF EXISTS vc399_fail_retirement ON partner_issuer_offers",
  );
  await issuer.pool.query("DROP FUNCTION IF EXISTS vc399_fail_retirement()");
}
test(
  "retirement rollback keeps durable confirmation recoverable across process restart",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const pair = await renewedPair(issuer);
      await failRevocation(issuer, pair.predecessor.id);
      const response = await operation(
        issuer,
        pair.receipt.confirm_uri,
        "credential_accepted",
      );
      assert.equal(response.status, 503, await response.clone().text());
      assert.equal(
        (await response.json()).error.code,
        "ISSUER_STATE_UNAVAILABLE",
      );
      assert.equal(await issuer.status(pair.predecessor), false);
      assert.equal(await issuer.status(pair.successor), false);
      const [retained] = (
        await issuer.pool.query(
          "SELECT phase,confirmed_at,live_predecessor_id FROM partner_issuer_renewals WHERE id=$1",
          [pair.renewal.renewal_id],
        )
      ).rows;
      assert.equal(retained.phase, "retiring");
      assert.equal(typeof retained.confirmed_at, "number");
      assert.equal(retained.live_predecessor_id, pair.predecessor.id);
      await clearFailure(issuer);
      issuer.now = issuer.initial + 3600;
      await issuer.restart();
      assert.equal(await issuer.status(pair.predecessor), true);
      assert.equal(await issuer.status(pair.successor), false);
      const recovered = await operation(issuer, pair.receipt.status_uri);
      assert.equal(recovered.status, 200, await recovered.clone().text());
      const result = await recovered.json();
      assert.equal(result.status, "completed");
      assert.equal(result.confirmed_at, retained.confirmed_at);
      assert.equal(result.successor_credential_id, pair.successor.payload.id);
    } finally {
      await clearFailure(issuer);
      await issuer.close();
    }
  },
);
test(
  "cancellation rollback preserves active successor and live lease until a fresh holder retry",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const pair = await renewedPair(issuer);
      await failRevocation(issuer, pair.successor.id);
      const response = await operation(issuer, pair.receipt.cancel_uri);
      assert.equal(response.status, 503, await response.clone().text());
      assert.equal(await issuer.status(pair.predecessor), false);
      assert.equal(await issuer.status(pair.successor), false);
      const [retained] = (
        await issuer.pool.query(
          "SELECT phase,live_predecessor_id FROM partner_issuer_renewals WHERE id=$1",
          [pair.renewal.renewal_id],
        )
      ).rows;
      assert.equal(retained.phase, "awaiting_receipt");
      assert.equal(retained.live_predecessor_id, pair.predecessor.id);
      await clearFailure(issuer);
      const cancelled = await operation(issuer, pair.receipt.cancel_uri);
      assert.equal(cancelled.status, 200, await cancelled.clone().text());
      assert.equal((await cancelled.json()).status, "cancelled");
      assert.equal(await issuer.status(pair.predecessor), false);
      assert.equal(await issuer.status(pair.successor), true);
    } finally {
      await clearFailure(issuer);
      await issuer.close();
    }
  },
);

test(
  "urgent predecessor revocation before authorization or issuance never allocates a usable successor",
  { skip: !database, timeout: 30000 },
  async () => {
    for (const stage of ["authorize", "issue"]) {
      const issuer = await issuerFixture(database, fixturePorts);
      try {
        const predecessor = await issuer.issue("holder:399");
        const renewal = await createRenewal(issuer, predecessor);
        let offer;
        if (stage === "issue") {
          const response = await authorize(issuer, renewal);
          assert.equal(response.status, 200);
          offer = await response.json();
        }
        const revoked = await issuer.management(
          issuer.runtime,
          predecessor.id,
          { state: "revoked" },
        );
        assert.equal(revoked.status, 200);
        const urgent = await revoked.json();
        if (stage === "authorize") {
          const refused = await authorize(issuer, renewal);
          assert.equal(refused.status, 409, await refused.clone().text());
          assert.equal(
            (await refused.json()).error.code,
            "ISSUER_RENEWAL_NOT_CONFIRMABLE",
          );
        } else {
          const refused = await issuer.issueOffer(
            {
              ...offer,
              holderId: "holder:399",
              holder: predecessor.payload.cnf.jwk,
            },
            409,
          );
          assert.equal(refused.error, "issuer_renewal_not_confirmable");
        }
        const rows = await issuer.pool.query(
          "SELECT count(*)::int AS count FROM partner_issuer_offers WHERE phase='issued'",
        );
        assert.equal(rows.rows[0].count, 1);
        const preserved = await issuer.management(
          issuer.runtime,
          predecessor.id,
        );
        assert.deepEqual(await preserved.json(), urgent);
        await issuer.restart();
        assert.equal(await issuer.status(predecessor), true);
      } finally {
        await issuer.close();
      }
    }
  },
);
test(
  "urgent successor revocation refuses first confirmation and remains revoked through cancellation",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const pair = await renewedPair(issuer);
      const urgent = await issuer.management(
        issuer.runtime,
        pair.successor.id,
        { state: "revoked" },
      );
      assert.equal(urgent.status, 200);
      const snapshot = await urgent.json();
      const response = await operation(
        issuer,
        pair.receipt.confirm_uri,
        "credential_accepted",
      );
      assert.equal(response.status, 409, await response.clone().text());
      assert.equal(
        (await response.json()).error.code,
        "ISSUER_RENEWAL_NOT_CONFIRMABLE",
      );
      const cancelled = await operation(issuer, pair.receipt.cancel_uri);
      assert.equal(cancelled.status, 200);
      assert.equal((await cancelled.json()).status, "cancelled");
      const preserved = await issuer.management(
        issuer.runtime,
        pair.successor.id,
      );
      assert.deepEqual(await preserved.json(), snapshot);
      assert.equal(await issuer.status(pair.predecessor), false);
    } finally {
      await issuer.close();
    }
  },
);
test(
  "already durable confirmation retires its exact predecessor after later urgent successor revocation",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const unrelated = await issuer.issue("holder:397-owner");
      const pair = await renewedPair(issuer);
      await failRevocation(issuer, pair.predecessor.id);
      const response = await operation(
        issuer,
        pair.receipt.confirm_uri,
        "credential_accepted",
      );
      assert.equal(response.status, 503);
      const urgent = await issuer.management(
        issuer.runtime,
        pair.successor.id,
        { state: "revoked" },
      );
      assert.equal(urgent.status, 200);
      const snapshot = await urgent.json();
      await clearFailure(issuer);
      await issuer.restart();
      const recovered = await operation(issuer, pair.receipt.status_uri);
      assert.equal(recovered.status, 200);
      assert.equal((await recovered.json()).status, "completed");
      assert.equal(await issuer.status(pair.predecessor), true);
      assert.equal(await issuer.status(unrelated), false);
      const preserved = await issuer.management(
        issuer.runtime,
        pair.successor.id,
      );
      assert.deepEqual(await preserved.json(), snapshot);
    } finally {
      await clearFailure(issuer);
      await issuer.close();
    }
  },
);
test(
  "expired unrevoked predecessor renews using its authenticated historical holder without becoming presentable",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const predecessor = await issuer.issue("holder:399");
      issuer.now = issuer.initial + 3600;
      issuer.refreshEvidence();
      assert.throws(() =>
        core.verifySdJwtCredential({
          compactSdJwt: predecessor.compact,
          issuerJwk: issuer.identity.publicJwk,
          options: {
            now_unix_seconds: issuer.now,
            format: "w3c_vc_data_model",
          },
        }),
      );
      const renewal = await createRenewal(issuer, predecessor, undefined, {
        valid_from: issuer.now,
        valid_until: issuer.now + 3600,
        offer_expires_at: issuer.now + 120,
      });
      const response = await authorize(issuer, renewal);
      assert.equal(response.status, 200, await response.clone().text());
      const offer = await response.json();
      const successor = await issuer.issueOffer({
        ...offer,
        holderId: "holder:399",
        holder: predecessor.payload.cnf.jwk,
      });
      assert.equal(successor.payload.exp, issuer.now + 3600);
      assert.equal(predecessor.payload.exp, issuer.initial + 3600);
      assert.equal(await issuer.status(predecessor), false);
      const receipt = successor.responseBody.x_credworks_renewal;
      const confirmation = await operation(
        issuer,
        receipt.confirm_uri,
        "credential_accepted",
      );
      assert.equal(confirmation.status, 200, await confirmation.clone().text());
      assert.equal((await confirmation.json()).status, "completed");
      assert.equal(await issuer.status(predecessor), true);
    } finally {
      await issuer.close();
    }
  },
);
test(
  "current signed withdrawal, changed definition and unavailable authority refuse holder authorization",
  { skip: !database, timeout: 30000 },
  async () => {
    for (const mode of ["withdraw", "definition", "outage"]) {
      const issuer = await issuerFixture(database, fixturePorts);
      try {
        const predecessor = await issuer.issue("holder:399");
        const renewal = await createRenewal(issuer, predecessor);
        if (mode === "withdraw") issuer.authorizationStatus = "inactive";
        if (mode === "definition") issuer.definitionVersion = "2";
        if (mode === "outage") issuer.available = false;
        const response = await authorize(issuer, renewal);
        assert.equal(response.status, 503, await response.clone().text());
        assert.equal(
          (await response.json()).error.code,
          "ISSUER_AUTHORITY_UNAVAILABLE",
        );
        assert.equal(
          (
            await issuer.pool.query(
              "SELECT count(*)::int AS count FROM partner_issuer_offers",
            )
          ).rows[0].count,
          1,
        );
        assert.equal(await issuer.status(predecessor), false);
      } finally {
        await issuer.close();
      }
    }
  },
);
test(
  "public proof and management body bounds refuse oversized requests without protocol mutations",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const predecessor = await issuer.issue("holder:399");
      const renewal = await createRenewal(issuer, predecessor);
      const path = "/partner-renewals/" + renewal.renewal_id + "/authorize";
      const response = await fetch(issuer.runtime.public + path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: " ".repeat(16385),
      });
      assert.equal(response.status, 413);
      assert.equal((await response.json()).error.code, "REQUEST_TOO_LARGE");
      const tooLarge = await fetch(
        issuer.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + issuer.config.managementToken,
            "content-type": "application/json",
            "idempotency-key": core.randomUrlSafe(32),
          },
          body: " ".repeat(262145),
        },
      );
      assert.equal(tooLarge.status, 413);
      assert.equal((await tooLarge.json()).error.code, "REQUEST_TOO_LARGE");
      assert.equal(
        (
          await issuer.pool.query(
            "SELECT count(*)::int AS count FROM partner_issuer_offers",
          )
        ).rows[0].count,
        1,
      );
      assert.equal(await issuer.status(predecessor), false);
    } finally {
      await issuer.close();
    }
  },
);

test(
  "deadline equality refuses old authorization and nonce; issued unconfirmed lease stays held",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const predecessor = await issuer.issue("holder:399");
      const correlation = core.randomUrlSafe(32);
      const renewal = await createRenewal(issuer, predecessor, correlation);
      const path = "/partner-renewals/" + renewal.renewal_id + "/authorize";
      const expiredProof = await holderProof(
        issuer,
        issuer.config.origin + path,
      );
      issuer.now = issuer.initial + 120;
      const expired = await publicPost(issuer, path, {
        version: 1,
        capability: new URL(renewal.renewal_request_uri).searchParams.get(
          "capability",
        ),
        proof: { proof_type: "jwt", jwt: expiredProof },
      });
      assert.equal(expired.status, 410);
      assert.equal((await expired.json()).error.code, "ISSUER_RENEWAL_EXPIRED");
      const recovered = await createRenewal(issuer, predecessor, correlation);
      assert.equal(recovered.renewal_id, renewal.renewal_id);
      assert.equal(recovered.expires_at, renewal.expires_at);
      const next = await createRenewal(issuer, predecessor, undefined, {
        offer_expires_at: issuer.now + 120,
      });
      const old = await createRenewal(issuer, predecessor, correlation);
      assert.equal(old.status, "expired");
      const cancelUri =
        issuer.config.origin +
        "/partner-renewals/" +
        next.renewal_id +
        "/cancel";
      const cancelProof = await holderProof(issuer, cancelUri);
      issuer.now += 300;
      const stale = await publicPost(issuer, new URL(cancelUri).pathname, {
        version: 1,
        proof: { proof_type: "jwt", jwt: cancelProof },
      });
      assert.equal(stale.status, 400);
      assert.equal(
        (await stale.json()).error.code,
        "ISSUER_RENEWAL_INVALID_PROOF",
      );
      const cancelled = await operation(issuer, cancelUri);
      assert.equal(cancelled.status, 200);
      assert.equal((await cancelled.json()).status, "cancelled");
      assert.equal(await issuer.status(predecessor), false);
    } finally {
      await issuer.close();
    }
    const held = await issuerFixture(database, fixturePorts);
    try {
      const pair = await renewedPair(held);
      held.now = held.initial + 120;
      const correlation = core.randomUrlSafe(32);
      const input = {
        version: 1,
        predecessor_issuance_id: pair.predecessor.id,
        configuration_id: "entitlement",
        claims: { enabled: true },
        valid_from: held.initial,
        valid_until: held.initial + 3600,
        offer_expires_at: held.now + 120,
      };
      const refused = await fetch(
        held.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + held.config.managementToken,
            "content-type": "application/json",
            "idempotency-key": correlation,
          },
          body: JSON.stringify(input),
        },
      );
      assert.equal(refused.status, 409);
      assert.equal(
        (await refused.json()).error.code,
        "ISSUER_RENEWAL_CONFLICT",
      );
      const cancel = await operation(held, pair.receipt.cancel_uri);
      assert.equal(cancel.status, 200);
      assert.equal(await held.status(pair.predecessor), false);
      assert.equal(await held.status(pair.successor), true);
    } finally {
      await held.close();
    }
  },
);
test(
  "expired successor cannot establish new confirmation, and lost successful confirmation reply reconciles without token",
  { skip: !database, timeout: 30000 },
  async () => {
    const expired = await issuerFixture(database, fixturePorts);
    try {
      const pair = await renewedPair(expired);
      expired.now = expired.initial + 3600;
      expired.refreshEvidence();
      const refused = await operation(
        expired,
        pair.receipt.confirm_uri,
        "credential_accepted",
      );
      assert.equal(refused.status, 409, await refused.clone().text());
      assert.equal(
        (await refused.json()).error.code,
        "ISSUER_RENEWAL_NOT_CONFIRMABLE",
      );
      assert.equal(await expired.status(pair.predecessor), false);
      const cancellation = await operation(expired, pair.receipt.cancel_uri);
      assert.equal(cancellation.status, 200);
      assert.equal(await expired.status(pair.successor), true);
    } finally {
      await expired.close();
    }
    const issuer = await issuerFixture(database, fixturePorts);
    try {
      const pair = await renewedPair(issuer);
      const proof = await holderProof(issuer, pair.receipt.confirm_uri);
      const confirmed = await publicPost(
        issuer,
        new URL(pair.receipt.confirm_uri).pathname,
        {
          version: 1,
          event: "credential_accepted",
          proof: { proof_type: "jwt", jwt: proof },
        },
      );
      assert.equal(confirmed.status, 200);
      await confirmed.body.cancel(); // Deliberately discard the accepted reply body.
      await issuer.restart();
      const replay = await publicPost(
        issuer,
        new URL(pair.receipt.confirm_uri).pathname,
        {
          version: 1,
          event: "credential_accepted",
          proof: { proof_type: "jwt", jwt: proof },
        },
      );
      assert.equal(replay.status, 400);
      assert.equal(
        (await replay.json()).error.code,
        "ISSUER_RENEWAL_INVALID_PROOF",
      );
      const recovered = await operation(issuer, pair.receipt.status_uri);
      assert.equal(recovered.status, 200);
      assert.equal((await recovered.json()).status, "completed");
      const repeated = await operation(
        issuer,
        pair.receipt.confirm_uri,
        "credential_accepted",
      );
      assert.equal(repeated.status, 200);
      assert.equal((await repeated.json()).status, "completed");
      assert.equal(await issuer.status(pair.predecessor), true);
      assert.equal(await issuer.status(pair.successor), false);
    } finally {
      await issuer.close();
    }
  },
);
test(
  "another real issuer reference, wrong holder and management bearer cannot change the operation",
  { skip: !database, timeout: 30000 },
  async () => {
    assert.ok(
      otherDatabase,
      "PARTNER_OTHER_ISSUER_DATABASE_URL is required when renewal HTTP tests are enabled",
    );
    assert.notEqual(
      otherDatabase,
      database,
      "Independent issuer ledger must be isolated",
    );
    const issuer = await issuerFixture(database, fixturePorts);
    const other = await issuerFixture(otherDatabase, {
      public: 29223,
      management: 29224,
      evidence: 29225,
    });
    try {
      const predecessor = await issuer.issue("holder:399");
      const foreign = await other.issue("holder:399");
      const foreignRequest = await fetch(
        issuer.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + issuer.config.managementToken,
            "content-type": "application/json",
            "idempotency-key": core.randomUrlSafe(32),
          },
          body: JSON.stringify({
            version: 1,
            predecessor_issuance_id: foreign.id,
            configuration_id: "entitlement",
            claims: { enabled: false },
            valid_from: issuer.initial,
            valid_until: issuer.initial + 3600,
            offer_expires_at: issuer.initial + 120,
          }),
        },
      );
      assert.equal(foreignRequest.status, 404);
      assert.equal(
        (await foreignRequest.json()).error.code,
        "ISSUER_RENEWAL_NOT_FOUND",
      );
      const renewal = await createRenewal(issuer, predecessor);
      core.installDeterministicTestKey("holder:399-wrong", "issuer:244");
      for (const [key, audience] of [
        ["holder:399-wrong", undefined],
        [
          "holder:399",
          other.config.origin +
            "/partner-renewals/" +
            renewal.renewal_id +
            "/authorize",
        ],
      ]) {
        const response = await authorize(
          issuer,
          renewal,
          issuer.runtime.public,
          key,
          audience,
        );
        assert.equal(response.status, 400);
        assert.equal(
          (await response.json()).error.code,
          "ISSUER_RENEWAL_INVALID_PROOF",
        );
      }
      const unauthorized = await fetch(
        issuer.runtime.management + "/management/issuer/renewals",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        },
      );
      assert.equal(unauthorized.status, 401);
      assert.deepEqual(await unauthorized.json(), { error: "unauthorized" });
      assert.equal(
        (
          await issuer.pool.query(
            "SELECT count(*)::int AS count FROM partner_issuer_offers",
          )
        ).rows[0].count,
        1,
      );
      assert.equal(await issuer.status(predecessor), false);
      assert.equal(await other.status(foreign), false);
    } finally {
      await other.close();
      await issuer.close();
    }
  },
);

test(
  "urgent revocation racing independent-process confirmation is irreversible and touches no unrelated instance",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database, fixturePorts);
    let child;
    try {
      const unrelated = await issuer.issue("holder:397-owner");
      const pair = await renewedPair(issuer);
      child = await issuer.process({ public: 29240, management: 29241 });
      const [confirmation, urgent] = await Promise.all([
        operation(issuer, pair.receipt.confirm_uri, "credential_accepted"),
        issuer.management(child, pair.successor.id, { state: "revoked" }),
      ]);
      assert.equal(urgent.status, 200, await urgent.clone().text());
      const snapshot = await urgent.json();
      assert.equal(snapshot.state, "revoked");
      assert.ok(
        [200, 409].includes(confirmation.status),
        await confirmation.clone().text(),
      );
      if (confirmation.status === 200) {
        assert.equal((await confirmation.json()).status, "completed");
        assert.equal(await issuer.status(pair.predecessor), true);
      } else {
        assert.equal(
          (await confirmation.json()).error.code,
          "ISSUER_RENEWAL_NOT_CONFIRMABLE",
        );
        assert.equal(await issuer.status(pair.predecessor), false);
        const cancellation = await operation(issuer, pair.receipt.cancel_uri);
        assert.equal(cancellation.status, 200);
      }
      assert.equal(await issuer.status(pair.successor), true);
      assert.equal(await issuer.status(unrelated), false);
      await child.stop();
      child = undefined;
      await issuer.restart();
      const preserved = await issuer.management(
        issuer.runtime,
        pair.successor.id,
      );
      assert.deepEqual(await preserved.json(), snapshot);
      assert.equal(await issuer.status(unrelated), false);
    } finally {
      await child?.stop();
      await issuer.close();
    }
  },
);
