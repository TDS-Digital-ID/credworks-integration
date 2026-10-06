import assert from "node:assert/strict";
import { test } from "node:test";
import * as core from "@unsw-vc/identity-core-node";
import { issuerFixture } from "./support/issuer-lifecycle.mjs";

const database = process.env.PARTNER_ISSUER_DATABASE_URL;
const otherDatabase = process.env.PARTNER_OTHER_ISSUER_DATABASE_URL;

test(
  "protected exact issuance revocation is permanent and isolated from holders and other ledgers",
  { skip: !database, timeout: 30000 },
  async () => {
    assert.ok(
      otherDatabase,
      "PARTNER_OTHER_ISSUER_DATABASE_URL is required when the issuer lifecycle fixture is enabled",
    );
    assert.notEqual(
      database,
      otherDatabase,
      "issuer lifecycle ledgers must be independent",
    );
    const issuer = await issuerFixture(database);
    let other;
    try {
      other = await issuerFixture(otherDatabase);
      const first = await issuer.issue();
      const sameHolder = await issuer.issue();
      const differentHolder = await issuer.issue("holder:397-other");
      const otherProject = await other.issue();
      const pending = await issuer.offer();
      const pendingId = new URL(pending.credential_offer_uri).pathname
        .split("/")
        .at(-1);
      const expected = {
        issuance_id: first.id,
        credential_id: first.payload.id,
        state: "active",
        revoked_at: null,
        status_list_credential:
          issuer.config.origin + "/oid4vci/status/revocation.jwt",
        status_list_index: first.payload.credentialStatus.statusListIndex,
      };
      const read = await issuer.management(issuer.runtime, first.id);
      assert.equal(read.status, 200, await read.clone().text());
      assert.equal(read.headers.get("cache-control"), "no-store");
      assert.deepEqual(await read.json(), expected);
      for (const token of [
        "wrong",
        first.token,
        first.proof,
        other.config.managementToken,
      ]) {
        const denied = await issuer.management(
          issuer.runtime,
          first.id,
          { state: "revoked" },
          token,
        );
        assert.equal(denied.status, 401);
        assert.deepEqual(await denied.json(), { error: "unauthorized" });
      }
      assert.equal(
        (
          await fetch(issuer.runtime.public + issuer.path(first.id), {
            method: "POST",
            headers: {
              authorization: "Bearer " + issuer.config.managementToken,
              "content-type": "application/json",
            },
            body: '{"state":"revoked"}',
          })
        ).status,
        404,
      );
      for (const [id, code, status] of [
        [core.randomUrlSafe(16), "ISSUER_ISSUANCE_NOT_FOUND", 404],
        [otherProject.id, "ISSUER_ISSUANCE_NOT_FOUND", 404],
        [pendingId, "ISSUER_ISSUANCE_NOT_ISSUED", 409],
      ]) {
        const denied = await issuer.management(issuer.runtime, id, {
          state: "revoked",
        });
        assert.equal(denied.status, status);
        assert.deepEqual(await denied.json(), { error: { code } });
      }
      for (const body of [
        { state: "suspended" },
        { state: "active" },
        { state: "reinstated" },
        { state: "revoked", status_list_index: "1" },
        { state: "revoked", issuer_did: other.identity.did },
        {},
        null,
        [],
      ]) {
        const denied = await issuer.management(issuer.runtime, first.id, body);
        assert.equal(denied.status, 400);
        assert.deepEqual(await denied.json(), {
          error: {
            code:
              body && !Array.isArray(body) && Object.keys(body).length === 1
                ? "ISSUER_STATUS_UNSUPPORTED"
                : "ISSUER_STATUS_BAD_REQUEST",
          },
        });
      }
      assert.equal(await issuer.status(first), false);
      for (const [body, contentType, status, code] of [
        ["{", "application/json", 400, "ISSUER_STATUS_BAD_REQUEST"],
        ['{"state":"revoked"}', "text/plain", 415, "ISSUER_STATUS_BAD_REQUEST"],
        [
          JSON.stringify({ state: "revoked", padding: "x".repeat(1024) }),
          "application/json",
          413,
          "REQUEST_TOO_LARGE",
        ],
      ]) {
        const malformed = await fetch(
          issuer.runtime.management + issuer.path(first.id),
          {
            method: "POST",
            headers: {
              authorization: "Bearer " + issuer.config.managementToken,
              "content-type": contentType,
            },
            body,
          },
        );
        assert.equal(malformed.status, status);
        assert.deepEqual(await malformed.json(), { error: { code } });
      }
      const revoke = await issuer.management(issuer.runtime, first.id, {
        state: "revoked",
      });
      assert.equal(revoke.status, 200, await revoke.clone().text());
      const committed = await revoke.json();
      assert.deepEqual(committed, {
        ...expected,
        state: "revoked",
        revoked_at: issuer.initial,
      });
      issuer.now = issuer.initial + 10;
      for (const result of await Promise.all(
        Array.from({ length: 8 }, () =>
          issuer.management(issuer.runtime, first.id, { state: "revoked" }),
        ),
      )) {
        assert.equal(result.status, 200);
        assert.deepEqual(await result.json(), committed);
      }
      await issuer.restart();
      assert.deepEqual(
        await (await issuer.management(issuer.runtime, first.id)).json(),
        committed,
      );
      assert.equal(await issuer.status(first), true);
      assert.equal(await issuer.status(sameHolder), false);
      assert.equal(await issuer.status(differentHolder), false);
      assert.equal(await other.status(otherProject), false);
      // Retirement authority is independent of a current new-issuance grant.
      issuer.now = issuer.initial + 600;
      const withoutAuthority = await issuer.management(
        issuer.runtime,
        sameHolder.id,
        { state: "revoked" },
      );
      assert.equal(withoutAuthority.status, 200);
      assert.equal(await issuer.status(sameHolder), true);
      await assert.rejects(() => issuer.offer(), /503/);
      issuer.available = false;
      const unavailableGrant = await issuer.management(
        issuer.runtime,
        differentHolder.id,
        { state: "revoked" },
      );
      assert.equal(unavailableGrant.status, 200);
      assert.equal(await issuer.status(differentHolder), true);
    } finally {
      await issuer.close();
      if (other) await other.close();
    }
  },
);

test(
  "independent processes preserve concurrent revocations and a committed lost response",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database);
    try {
      const first = await issuer.issue();
      const second = await issuer.issue();
      const third = await issuer.issue();
      const childA = await issuer.process(),
        childB = await issuer.process();
      const updates = await Promise.all([
        issuer.management(childA, first.id, { state: "revoked" }),
        issuer.management(childB, second.id, { state: "revoked" }),
        issuer.management(issuer.runtime, first.id, { state: "revoked" }),
        issuer.status(third, childA),
        issuer.issue("holder:397-concurrent"),
      ]);
      for (const result of updates.slice(0, 3))
        assert.equal(result.status, 200, await result.clone().text());
      assert.equal(updates[3], false);
      assert.equal(await issuer.status(updates[4]), false);
      assert.notEqual(
        updates[4].payload.credentialStatus.statusListIndex,
        third.payload.credentialStatus.statusListIndex,
      );
      assert.equal(await issuer.status(first, childB), true);
      assert.equal(await issuer.status(second, childA), true);
      // The response is intentionally discarded after its HTTP headers prove a
      // committed transition. Recovery must be from durable state, not a reply.
      const lost = await issuer.management(childA, third.id, {
        state: "revoked",
      });
      assert.equal(lost.status, 200);
      await lost.body.cancel();
      await childA.stop();
      const replacement = await issuer.process();
      const recovered = await issuer.management(replacement, third.id, {
        state: "revoked",
      });
      assert.equal(recovered.status, 200);
      assert.equal((await recovered.json()).state, "revoked");
      assert.equal(await issuer.status(first), true);
      assert.equal(await issuer.status(second), true);
      assert.equal(await issuer.status(third), true);
    } finally {
      await issuer.close();
    }
  },
);

test(
  "a failed revocation transaction rolls back publication and retries without restoring spent issuance",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database);
    try {
      const issued = await issuer.issue();
      await issuer.pool
        .query(`CREATE FUNCTION fixture397_revoke_failure() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'fixture397 interrupted write'; END IF;
        RETURN NEW; END $$`);
      await issuer.pool.query(
        "CREATE TRIGGER fixture397_revoke_failure BEFORE UPDATE ON partner_issuer_offers FOR EACH ROW EXECUTE FUNCTION fixture397_revoke_failure()",
      );
      const failed = await issuer.management(issuer.runtime, issued.id, {
        state: "revoked",
      });
      assert.equal(failed.status, 503);
      assert.deepEqual(await failed.json(), {
        error: { code: "ISSUER_STATE_UNAVAILABLE" },
      });
      assert.equal(await issuer.status(issued), false);
      const retained = await (
        await issuer.management(issuer.runtime, issued.id)
      ).json();
      assert.equal(retained.state, "active");
      assert.equal(retained.revoked_at, null);
      await issuer.pool.query(
        "DROP TRIGGER fixture397_revoke_failure ON partner_issuer_offers",
      );
      await issuer.pool.query("DROP FUNCTION fixture397_revoke_failure()");
      await issuer.restart();
      const recovered = await issuer.management(issuer.runtime, issued.id, {
        state: "revoked",
      });
      assert.equal(recovered.status, 200);
      assert.equal((await recovered.json()).revoked_at, issuer.initial);
      assert.equal(await issuer.status(issued), true);
    } finally {
      await issuer.pool.query(
        "DROP TRIGGER IF EXISTS fixture397_revoke_failure ON partner_issuer_offers",
      );
      await issuer.pool.query(
        "DROP FUNCTION IF EXISTS fixture397_revoke_failure()",
      );
      await issuer.close();
    }
  },
);

test(
  "legacy signed revocation keeps its unknown time and corrupted allocation/history refuses restart",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database);
    try {
      const issued = await issuer.issue();
      const original = await (
        await fetch(issuer.runtime.public + "/oid4vci/status/revocation.jwt")
      ).text();
      const [, payload] = core.verifyBitstringStatusListCredential({
        compactJws: original,
        statusListJwk: issuer.identity.publicJwk,
      });
      payload.credentialSubject.encodedList = core.encodeBitstringStatusList(
        131072,
        [0],
      );
      const legacy = core.signBitstringStatusListCredential({
        payload,
        header: {
          alg: "ES256",
          typ: "status-list+jwt",
          kid: issuer.identity.keyId,
        },
        keyId: issuer.identity.keyId,
      });
      // Compatibility setup for the prior ledger: a signed bit had no timestamp.
      await issuer.pool.query(
        "UPDATE partner_issuer_status SET signed_credential=$1",
        [legacy],
      );
      await issuer.restart();
      const retained = await issuer.management(issuer.runtime, issued.id, {
        state: "revoked",
      });
      assert.equal(retained.status, 200);
      const known = await retained.json();
      assert.equal(known.state, "revoked");
      assert.equal(known.revoked_at, null);
      assert.equal(await issuer.status(issued), true);
      await issuer.pool.query(
        "UPDATE partner_issuer_offers SET revoked_at=$1 WHERE id=$2",
        [issuer.initial, issued.id],
      );
      await issuer.pool.query(
        "UPDATE partner_issuer_status SET signed_credential=$1",
        [original],
      );
      await assert.rejects(() => issuer.restart(), /issuer state unavailable/);
      await issuer.pool.query(
        "UPDATE partner_issuer_status SET signed_credential=$1",
        [legacy],
      );
      await issuer.restart();
      assert.equal(await issuer.status(issued), true);
      await issuer.pool.query("UPDATE partner_issuer_status SET next_index=2");
      await assert.rejects(() => issuer.restart(), /issuer state unavailable/);
      await issuer.pool.query("UPDATE partner_issuer_status SET next_index=1");
      await issuer.restart();
      assert.equal(await issuer.status(issued), true);
      const bound = (
        await issuer.pool.query("SELECT * FROM partner_issuer_identity")
      ).rows[0];
      await issuer.pool.query("DELETE FROM partner_issuer_identity");
      try {
        const orphaned = await issuer.management(issuer.runtime, issued.id, {
          state: "revoked",
        });
        assert.equal(orphaned.status, 503);
        assert.deepEqual(await orphaned.json(), {
          error: { code: "ISSUER_STATE_UNAVAILABLE" },
        });
        const unsafePublication = await fetch(
          issuer.runtime.public + "/oid4vci/status/revocation.jwt",
        );
        assert.equal(unsafePublication.status, 503);
      } finally {
        await issuer.pool.query(
          "INSERT INTO partner_issuer_identity(singleton,origin,did,key_id,public_thumbprint) VALUES($1,$2,$3,$4,$5)",
          [
            bound.singleton,
            bound.origin,
            bound.did,
            bound.key_id,
            bound.public_thumbprint,
          ],
        );
      }
      await issuer.pool.query(
        "UPDATE partner_issuer_offers SET credential_id='https://foreign.example/credentials/copied' WHERE id=$1",
        [issued.id],
      );
      try {
        const foreignReference = await issuer.management(
          issuer.runtime,
          issued.id,
        );
        assert.equal(foreignReference.status, 503);
        assert.deepEqual(await foreignReference.json(), {
          error: { code: "ISSUER_STATE_UNAVAILABLE" },
        });
      } finally {
        await issuer.pool.query(
          "UPDATE partner_issuer_offers SET credential_id=$1 WHERE id=$2",
          [issued.payload.id, issued.id],
        );
      }
    } finally {
      await issuer.close();
    }
  },
);

test(
  "live swapped allocations cannot redirect revocation from one signed issuance to another",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database);
    try {
      const first = await issuer.issue(),
        second = await issuer.issue();
      const original = await (
        await fetch(issuer.runtime.public + "/oid4vci/status/revocation.jwt")
      ).text();
      const connection = await issuer.pool.connect();
      const map = async (swapped) => {
        await connection.query("BEGIN");
        try {
          await connection.query(
            "UPDATE partner_issuer_offers SET status_index=NULL WHERE id=$1",
            [first.id],
          );
          await connection.query(
            "UPDATE partner_issuer_offers SET status_index=$1 WHERE id=$2",
            [swapped ? 0 : 1, second.id],
          );
          await connection.query(
            "UPDATE partner_issuer_offers SET status_index=$1 WHERE id=$2",
            [swapped ? 1 : 0, first.id],
          );
          await connection.query("COMMIT");
        } catch (error) {
          await connection.query("ROLLBACK");
          throw error;
        }
      };
      try {
        await map(true);
        for (const mutation of [{ state: "revoked" }, undefined]) {
          const refused = await issuer.management(
            issuer.runtime,
            first.id,
            mutation,
          );
          if (refused.status === 200) {
            assert.equal(
              await issuer.status(second),
              false,
              "revoking first through a swapped mapping must never revoke the second signed index",
            );
          }
          assert.equal(refused.status, 503);
          assert.deepEqual(await refused.json(), {
            error: { code: "ISSUER_STATE_UNAVAILABLE" },
          });
        }
        const publication = await fetch(
          issuer.runtime.public + "/oid4vci/status/revocation.jwt",
        );
        assert.equal(publication.status, 503);
      } finally {
        await map(false);
        await connection.query(
          "UPDATE partner_issuer_offers SET revoked_at=NULL",
        );
        await connection.query(
          "UPDATE partner_issuer_status SET signed_credential=$1",
          [original],
        );
        connection.release();
      }
      assert.equal(await issuer.status(first), false);
      assert.equal(await issuer.status(second), false);
      const legitimate = await issuer.management(issuer.runtime, first.id, {
        state: "revoked",
      });
      assert.equal(legitimate.status, 200);
      assert.equal(await issuer.status(first), true);
      assert.equal(await issuer.status(second), false);
    } finally {
      await issuer.close();
    }
  },
);

test(
  "a missing established status publication refuses503 while a fresh empty ledger publishes normally",
  { skip: !database, timeout: 30000 },
  async () => {
    const issuer = await issuerFixture(database);
    try {
      const unused = await fetch(
        issuer.runtime.public + "/oid4vci/status/revocation.jwt",
      );
      assert.equal(unused.status, 200);
      core.verifyBitstringStatusListCredentialAt({
        compactJws: await unused.text(),
        statusListJwk: issuer.identity.publicJwk,
        nowUnixSeconds: issuer.initial,
      });
      const issued = await issuer.issue();
      const retained = (
        await issuer.pool.query("SELECT * FROM partner_issuer_status")
      ).rows[0];
      await issuer.pool.query("DELETE FROM partner_issuer_status");
      try {
        const publication = await fetch(
          issuer.runtime.public + "/oid4vci/status/revocation.jwt",
        );
        assert.equal(publication.status, 503);
        assert.deepEqual(await publication.json(), {
          error: "issuer_state_unavailable",
        });
        const exact = await issuer.management(issuer.runtime, issued.id);
        assert.equal(exact.status, 503);
        assert.deepEqual(await exact.json(), {
          error: { code: "ISSUER_STATE_UNAVAILABLE" },
        });
      } finally {
        await issuer.pool.query(
          "INSERT INTO partner_issuer_status(singleton,next_index,signed_credential) VALUES($1,$2,$3)",
          [retained.singleton, retained.next_index, retained.signed_credential],
        );
      }
      assert.equal(await issuer.status(issued), false);
    } finally {
      await issuer.close();
    }
  },
);
