import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { once } from "node:events";
import { Pool } from "pg";
import * as core from "@unsw-vc/identity-core-node";
const database = process.env.PARTNER_ISSUER_DATABASE_URL,
  port = Number(process.env.PARTNER_ISSUER_HTTP_PORT ?? 29230) + 2;
test(
  "independent issuer processes preserve confidential offers and committed lost responses",
  { skip: !database, timeout: 30000 },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "vc368-process-"));
    const origin =
      "https://process" +
      core.randomUrlSafe(16).toLowerCase().replaceAll("_", "a") +
      ".example";
    const registryDid = "did:web:registry368-process.example",
      registryKey = registryDid + "#anchor";
    const anchor = core.installDeterministicTestKey(registryKey, "issuer:245");
    const providerDid = "did:web:provider368-process.example",
      providerKey = providerDid + "#wia-1",
      provider = core.installDeterministicTestKey(providerKey, "issuer:246");
    const authorizationId = crypto.randomUUID(),
      definition = {
        id: origin + "/definitions/entitlement",
        version: "1",
        credential_type: "NeutralEntitlementCredential",
        label: "Entitlement",
        max_validity_seconds: 3600,
        claims: [
          {
            name: "enabled",
            label: "Enabled",
            value_type: "boolean",
            required: true,
          },
        ],
        profiles: [
          {
            name: "entitlement",
            claim_paths: [["credentialSubject", "enabled"]],
          },
        ],
      };
    const issuer = {
      databaseUrl: database,
      registryOrigin: "https://registry368-process.example",
      registryDid,
      trustAnchorJwk: anchor,
      definitions: [
        {
          configurationId: "entitlement",
          authorizationId,
          definitionId: definition.id,
          definitionVersion: "1",
          credentialType: definition.credential_type,
        },
      ],
      walletProviderDid: providerDid,
      walletProviderJwk: provider,
    };
    const configPath = join(dir, "issuer.json");
    await writeFile(configPath, JSON.stringify(issuer));
    const env = {
      ...process.env,
      PARTNER_ORIGIN: origin,
      PARTNER_STATE_DIR: join(dir, "identity"),
      PARTNER_UNLOCK_KEY: core.randomUrlSafe(32),
      PARTNER_MANAGEMENT_TOKEN: core.randomUrlSafe(32),
      PARTNER_PUBLIC_PORT: String(port),
      PARTNER_MANAGEMENT_PORT: String(port + 1),
      PARTNER_ISSUER_CONFIG: configPath,
      PARTNER_ISSUER_TEST_EVIDENCE_SOURCE: `http://127.0.0.1:${port + 2}`,
    };
    delete env.PARTNER_VERIFIER_CONFIG;
    const pool = new Pool({ connectionString: database });
    await pool.query(
      "TRUNCATE partner_issuer_renewals,partner_issuer_identity,partner_issuer_offers,partner_issuer_nonces,partner_issuer_status",
    );
    await pool.end();
    const identity = JSON.parse(
      execFileSync(
        process.execPath,
        ["--import", "tsx", "src/cli.ts", "bootstrap"],
        {
          env: { ...env, PARTNER_ISSUER_CONFIG: "" },
          encoding: "utf8",
          timeout: 10000,
        },
      ),
    );
    const orphanPool = new Pool({ connectionString: database });
    try {
      for (const phase of ["offered", "redeemed"]) {
        await orphanPool.query(
          `INSERT INTO partner_issuer_offers
           (id,code_hash,expires_at,configuration_id,definition,claims,valid_from,valid_until,recipient_thumbprint,phase)
           VALUES ($1,$2,$3,'entitlement',$4,$5,$3,$6,$7,$8)`,
          [
            core.randomUrlSafe(16),
            core.randomUrlSafe(32),
            2000000000,
            definition,
            { enabled: true },
            2000000300,
            core.randomUrlSafe(32),
            phase,
          ],
        );
        assert.throws(
          () =>
            execFileSync(
              process.execPath,
              ["--import", "tsx", "src/cli.ts", "bootstrap-issuer"],
              { env, encoding: "utf8", timeout: 10000, stdio: "pipe" },
            ),
          /partner_identity_unavailable/,
        );
        const retained = await orphanPool.query(
          "SELECT phase FROM partner_issuer_offers",
        );
        assert.equal(retained.rows[0].phase, phase);
        assert.equal(
          (await orphanPool.query("SELECT * FROM partner_issuer_identity"))
            .rowCount,
          0,
        );
        assert.equal(
          (await orphanPool.query("SELECT * FROM partner_issuer_status"))
            .rowCount,
          0,
        );
        await orphanPool.query("DELETE FROM partner_issuer_offers");
      }
      await orphanPool.query(
        "INSERT INTO partner_issuer_nonces VALUES ($1,$2,'available')",
        [core.randomUrlSafe(32), 2000000000],
      );
      assert.throws(
        () =>
          execFileSync(
            process.execPath,
            ["--import", "tsx", "src/cli.ts", "bootstrap-issuer"],
            { env, encoding: "utf8", timeout: 10000, stdio: "pipe" },
          ),
        /partner_identity_unavailable/,
      );
      assert.equal(
        (await orphanPool.query("SELECT * FROM partner_issuer_nonces"))
          .rowCount,
        1,
      );
      await orphanPool.query("DELETE FROM partner_issuer_nonces");
      const blocker = await orphanPool.connect();
      await blocker.query("BEGIN");
      await blocker.query("SELECT pg_advisory_xact_lock(368,1)");
      const competing = spawn(
        process.execPath,
        ["--import", "tsx", "src/cli.ts", "bootstrap-issuer"],
        { env, stdio: ["ignore", "pipe", "pipe"] },
      );
      let competingError = "";
      competing.stderr.on("data", (data) => {
        competingError += data.toString();
      });
      const completed = once(competing, "exit");
      try {
        let waiting = false;
        for (let attempt = 0; attempt < 100; attempt++) {
          const result = await orphanPool.query(
            "SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=368 AND objid=1 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())",
          );
          if (result.rowCount) {
            waiting = true;
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        assert.equal(
          waiting,
          true,
          "bootstrap waits for the active allocation transaction",
        );
        await blocker.query(
          "INSERT INTO partner_issuer_nonces VALUES ($1,$2,'available')",
          [core.randomUrlSafe(32), 2000000000],
        );
        await blocker.query("COMMIT");
        assert.equal((await completed)[0], 1);
        assert.match(competingError, /partner_identity_unavailable/);
        assert.equal(
          (await orphanPool.query("SELECT * FROM partner_issuer_identity"))
            .rowCount,
          0,
        );
        assert.equal(
          (await orphanPool.query("SELECT * FROM partner_issuer_status"))
            .rowCount,
          0,
        );
        assert.equal(
          (await orphanPool.query("SELECT * FROM partner_issuer_nonces"))
            .rowCount,
          1,
        );
      } finally {
        await blocker.query("ROLLBACK");
        blocker.release();
        if (competing.exitCode === null) {
          competing.kill();
          await completed;
        }
      }
      await orphanPool.query("DELETE FROM partner_issuer_nonces");
    } finally {
      await orphanPool.end();
    }
    const bound = JSON.parse(
      execFileSync(
        process.execPath,
        ["--import", "tsx", "src/cli.ts", "bootstrap-issuer"],
        { env, encoding: "utf8", timeout: 10000 },
      ),
    );
    assert.deepEqual(bound, identity);
    assert.throws(
      () =>
        execFileSync(
          process.execPath,
          ["--import", "tsx", "src/cli.ts", "bootstrap-issuer"],
          { env, encoding: "utf8", timeout: 10000, stdio: "pipe" },
        ),
      /partner_identity_unavailable/,
    );
    const now = Math.floor(Date.now() / 1000);
    const auth = core.signIssuerAuthorizations({
      payload: {
        version: 1,
        id:
          issuer.registryOrigin +
          "/issuer-authorizations/" +
          authorizationId +
          ".jwt",
        issuer: registryDid,
        iat: now,
        exp: now + 300,
        authorizations: [
          {
            credential_issuer_did: identity.did,
            credential_issuer_key_id: identity.did + "#key-1",
            credential_issuer_public_jwk_sha256_thumbprint:
              core.publicJwkSha256Thumbprint(identity.publicJwk),
            definition,
            status: "active",
          },
        ],
      },
      header: {
        alg: "ES256",
        typ: "issuer-authorizations+jwt",
        kid: registryKey,
      },
      keyId: registryKey,
    });
    const trust = core.signTrustList({
      payload: {
        id: issuer.registryOrigin + "/trust-list.jwt",
        issuer: registryDid,
        iat: now,
        exp: now + 300,
        entries: [
          {
            issuer_did: providerDid,
            credential_types: ["WalletInstanceAttestation"],
            status: "active",
            public_jwk: provider,
          },
        ],
      },
      header: { alg: "ES256", typ: "trust-list+jwt", kid: registryKey },
      keyId: registryKey,
    });
    const evidence = createServer((req, res) => {
      res.setHeader("content-type", "application/jose");
      res.end(req.url === "/trust-list.jwt" ? trust : auth);
    });
    await new Promise((resolve) =>
      evidence.listen(port + 2, "127.0.0.1", resolve),
    );
    let child;
    const start = async (extra = {}) => {
      child = spawn(
        process.execPath,
        ["--import", "tsx", "tests/support/issuer-process.mjs"],
        { env: { ...env, ...extra }, stdio: ["ignore", "pipe", "pipe"] },
      );
      let output = "",
        errors = "";
      child.stderr.on("data", (chunk) => {
        errors += chunk;
      });
      return await new Promise((resolve, reject) => {
        const deadline = setTimeout(() => {
          child.kill("SIGKILL");
          reject(Error("issuer process startup deadline"));
        }, 10000);
        child.once("exit", () => {
          clearTimeout(deadline);
          reject(Error("issuer process unavailable"));
        });
        child.stdout.on("data", (chunk) => {
          output += chunk;
          if (output.includes("READY ")) {
            clearTimeout(deadline);
            resolve(JSON.parse(output.trim().slice(6)));
          }
        });
      });
    };
    const stop = async () => {
      if (child && child.exitCode === null) {
        const exited = once(child, "exit");
        child.kill("SIGTERM");
        await exited;
      }
    };
    try {
      let runtime = await start();
      const holderId = "holder:368-process",
        holder = core.installDeterministicTestKey(holderId, "holder");
      const management = await fetch(
        runtime.management + "/management/issuer/offers",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + env.PARTNER_MANAGEMENT_TOKEN,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            configuration_id: "entitlement",
            claims: { enabled: true },
            valid_from: now,
            valid_until: now + 1800,
            offer_expires_at: now + 120,
            recipient_jwk_thumbprint: core.publicJwkSha256Thumbprint(holder),
          }),
        },
      );
      assert.equal(management.status, 201, await management.clone().text());
      const offer = await management.json();
      await stop();
      runtime = await start();
      const ref = new URL(offer.credential_offer_uri),
        retrieved = await fetch(runtime.public + ref.pathname + ref.search);
      assert.equal(retrieved.status, 200);
      const code = (await retrieved.json()).grants[
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ]["pre-authorized_code"];
      const tokenResponse = await fetch(runtime.public + "/oid4vci/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": code,
        }),
      });
      assert.equal(tokenResponse.status, 200);
      const token = await tokenResponse.json();
      const nonce = (
        await (
          await fetch(runtime.public + "/oid4vci/nonce", { method: "POST" })
        ).json()
      ).c_nonce;
      const proof = core.signCompactJwsJson({
        payload: { aud: origin, nonce, iat: Math.floor(Date.now() / 1000) },
        header: { alg: "ES256", typ: "openid4vci-proof+jwt", jwk: holder },
        keyId: holderId,
      });
      const wia = core.signCompactJwsJson({
        payload: {
          iss: providerDid,
          aud: origin,
          iat: now,
          exp: now + 120,
          cnf: { jwk: holder },
          attestation_method: "mock_platform_attestation",
        },
        header: {
          alg: "ES256",
          typ: "wallet-instance-attestation+jwt",
          kid: providerKey,
        },
        keyId: providerKey,
      });
      const receive = () =>
        fetch(runtime.public + "/oid4vci/credential", {
          method: "POST",
          headers: {
            authorization: "Bearer " + token.access_token,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            credential_configuration_id: "entitlement",
            proofs: { jwt: [proof] },
            wallet_instance_attestation: wia,
          }),
        });
      const lost = await receive();
      assert.equal(lost.status, 200);
      await lost.body.cancel();
      await stop();
      runtime = await start();
      const recovered = await receive();
      assert.equal(recovered.status, 200, await recovered.clone().text());
      const credential = (await recovered.json()).credentials[0].credential;
      core.verifyScalarCredentialAuthorization({
        compactSdJwt: credential,
        issuerJwk: identity.publicJwk,
        compactAuthorization: auth,
        trustAnchorJwk: anchor,
        registryDid,
        nowUnixSeconds: Math.floor(Date.now() / 1000),
        mode: "complete",
      });
      const repeat = await receive();
      assert.equal(repeat.status, 200);
      assert.equal((await repeat.json()).credentials[0].credential, credential);
      await stop();
      await assert.rejects(
        start({ PARTNER_ORIGIN: "https://replacement.example" }),
        /issuer process unavailable/,
      );
      await assert.rejects(
        start({ PARTNER_UNLOCK_KEY: core.randomUrlSafe(32) }),
        /issuer process unavailable/,
      );
    } finally {
      await stop();
      evidence.closeAllConnections();
      await new Promise((resolve) => evidence.close(resolve));
      await rm(dir, { recursive: true, force: true });
    }
  },
);
