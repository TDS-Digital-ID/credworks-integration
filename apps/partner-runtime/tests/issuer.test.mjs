import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as core from "@unsw-vc/identity-core-node";
import { Pool } from "pg";
import { bootstrapIssuerState } from "../src/issuer-state.ts";
import { configFromEnv, openIdentity, startRuntime } from "../src/runtime.ts";
const database = process.env.PARTNER_ISSUER_DATABASE_URL;

const definitions = [
  {
    configurationId: "neutral-pass",
    type: "NeutralPassCredential",
    label: "Neutral pass",
    values: { active: true },
    claims: [
      {
        name: "active",
        label: "Active",
        value_type: "boolean",
        required: true,
      },
    ],
  },
  {
    configurationId: "neutral-score",
    type: "NeutralScoreCredential",
    label: "Neutral score",
    values: { score: 7, label: "Example" },
    claims: [
      { name: "score", label: "Score", value_type: "integer", required: true },
      { name: "label", label: "Label", value_type: "string", required: true },
    ],
  },
];
for (const scenario of definitions)
  test(
    `actual ${scenario.type} issuance preserves recipient, authority and durable response`,
    { skip: !database },
    async () => {
      const root = await mkdtemp(join(tmpdir(), "vc368-issuer-"));
      const config = {
        origin:
          "https://issuer" +
          core.randomUrlSafe(16).toLowerCase().replaceAll("_", "a") +
          ".example",
        stateDir: join(root, "identity"),
        unlockKey: core.randomUrlSafe(32),
        managementToken: core.randomUrlSafe(32),
        publicPort: 0,
        managementPort: 0,
      };
      const identity = openIdentity(config, true);
      const registryDid = "did:web:registry368.example",
        registryKey = registryDid + "#trust-anchor-1";
      const anchor = core.installDeterministicTestKey(
        registryKey,
        "issuer:240",
      );
      const authorizationId = crypto.randomUUID();
      const definition = {
        id: config.origin + "/definitions/" + scenario.configurationId,
        version: "1",
        credential_type: scenario.type,
        label: scenario.label,
        max_validity_seconds: 3600,
        claims: scenario.claims,
        profiles: [
          {
            name: "neutral_check",
            claim_paths: scenario.claims.map((claim) => [
              "credentialSubject",
              claim.name,
            ]),
          },
        ],
      };
      config.issuer = {
        databaseUrl: database,
        registryOrigin: "https://registry368.example",
        registryDid,
        trustAnchorJwk: anchor,
        definitions: [
          {
            configurationId: scenario.configurationId,
            authorizationId,
            definitionId: definition.id,
            definitionVersion: "1",
            credentialType: definition.credential_type,
          },
        ],
        walletProviderDid: "did:web:wallet368.example",
        walletProviderJwk: core.installDeterministicTestKey(
          "did:web:wallet368.example#key-1",
          "issuer:241",
        ),
      };
      const issuerConfigPath = join(root, "issuer.json");
      await writeFile(issuerConfigPath, JSON.stringify(config.issuer));
      const parsed = configFromEnv({
        PARTNER_ORIGIN: config.origin,
        PARTNER_STATE_DIR: config.stateDir,
        PARTNER_UNLOCK_KEY: config.unlockKey,
        PARTNER_MANAGEMENT_TOKEN: config.managementToken,
        PARTNER_ISSUER_CONFIG: issuerConfigPath,
      });
      assert.deepEqual(parsed.issuer, config.issuer);
      const now = Math.floor(Date.now() / 1000);
      const authorization = core.signIssuerAuthorizations({
        payload: {
          version: 1,
          id:
            config.issuer.registryOrigin +
            "/issuer-authorizations/" +
            authorizationId +
            ".jwt",
          issuer: registryDid,
          iat: now,
          exp: now + 20,
          authorizations: [
            {
              credential_issuer_did: identity.did,
              credential_issuer_key_id: identity.keyId,
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
      const pool = new Pool({ connectionString: database });
      await pool.query(
        "TRUNCATE partner_issuer_renewals,partner_issuer_identity,partner_issuer_offers,partner_issuer_nonces,partner_issuer_status",
      );
      await pool.end();
      await bootstrapIssuerState(database, config.origin, identity);
      const providerTrust = core.signTrustList({
        payload: {
          id: config.issuer.registryOrigin + "/trust-list.jwt",
          issuer: registryDid,
          iat: now,
          exp: now + 300,
          entries: [
            {
              issuer_did: config.issuer.walletProviderDid,
              credential_types: ["WalletInstanceAttestation"],
              status: "active",
              public_jwk: config.issuer.walletProviderJwk,
            },
          ],
        },
        header: { alg: "ES256", typ: "trust-list+jwt", kid: registryKey },
        keyId: registryKey,
      });
      const ledgerFault = new Pool({ connectionString: database });
      const originalLedger = (
        await ledgerFault.query("SELECT * FROM partner_issuer_status")
      ).rows[0];
      await ledgerFault.query("DELETE FROM partner_issuer_status");
      await assert.rejects(async () => {
        const unexpected = await startRuntime(config, identity, {
          clock: () => now,
          fetchEvidence: async () => authorization,
        });
        await unexpected.close();
      }, /issuer state unavailable/);
      await ledgerFault.query(
        "INSERT INTO partner_issuer_status(singleton,next_index,signed_credential) VALUES($1,$2,$3)",
        [
          originalLedger.singleton,
          originalLedger.next_index,
          originalLedger.signed_credential,
        ],
      );
      await ledgerFault.end();
      let runtime = await startRuntime(config, identity, {
        clock: () => now,
        fetchEvidence: async (url) =>
          url.endsWith("/trust-list.jwt") ? providerTrust : authorization,
      });
      const holder = core.installDeterministicTestKey(
        "holder:368-recipient",
        "holder",
      );
      const input = {
        configuration_id: scenario.configurationId,
        claims: scenario.values,
        valid_from: now,
        valid_until: now + 1800,
        offer_expires_at: now + 120,
        recipient_jwk_thumbprint: core.publicJwkSha256Thumbprint(holder),
      };
      const create = (token, value = input) =>
        fetch(runtime.management + "/management/issuer/offers", {
          method: "POST",
          headers: {
            authorization: "Bearer " + token,
            "content-type": "application/json",
          },
          body: JSON.stringify(value),
        });
      try {
        assert.equal((await create("wrong-management-token")).status, 401);
        for (const [origin, path, expected] of [
          [
            runtime.management,
            "/management/issuer/offers",
            { error: { code: "ISSUER_OFFER_BAD_REQUEST" } },
          ],
          [runtime.public, "/oid4vci/credential", { error: "invalid_request" }],
        ]) {
          const malformed = await fetch(origin + path, {
            method: "POST",
            headers: {
              authorization: "Bearer " + config.managementToken,
              "content-type": "application/json",
            },
            body: "{",
          });
          assert.equal(malformed.status, 400);
          assert.deepEqual(await malformed.json(), expected);
        }

        for (const bad of [
          {
            ...input,
            claims: { ...scenario.values, [scenario.claims[0].name]: null },
          },
          { ...input, claims: { ...scenario.values, unexpected: "value" } },
          { ...input, valid_until: now + 7200 },
          { ...input, valid_from: now + 1 },
          { ...input, offer_expires_at: now },
        ]) {
          const refusal = await create(config.managementToken, bad);
          assert.equal(refusal.status, 400);
          assert.deepEqual(await refusal.json(), {
            error: {
              code:
                bad.claims !== input.claims
                  ? "ISSUER_VALUES_INVALID"
                  : "ISSUER_VALIDITY_INVALID",
            },
          });
        }
        const response = await create(config.managementToken);
        assert.equal(response.status, 201, await response.clone().text());
        const offer = await response.json();
        assert.equal(offer.expires_at, now + 120);
        assert.equal(new URL(offer.credential_offer_uri).origin, config.origin);
        await runtime.close();
        runtime = await startRuntime(config, identity, {
          clock: () => now,
          fetchEvidence: async (url) =>
            url.endsWith("/trust-list.jwt") ? providerTrust : authorization,
        });
        const offerUrl = new URL(offer.credential_offer_uri);
        const retrieved = await fetch(
          runtime.public + offerUrl.pathname + offerUrl.search,
        );
        assert.equal(retrieved.status, 200, await retrieved.clone().text());
        const discoveredOffer = await retrieved.json();
        assert.equal(discoveredOffer.credential_issuer, config.origin);
        const preCode =
          discoveredOffer.grants[
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
          ]["pre-authorized_code"];
        const redeem = () =>
          fetch(runtime.public + "/oid4vci/token", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type:
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
              "pre-authorized_code": preCode,
            }),
          });
        const tokenResults = await Promise.all([redeem(), redeem()]);
        assert.deepEqual(tokenResults.map((r) => r.status).sort(), [200, 400]);
        assert.deepEqual(
          await tokenResults.find((r) => r.status === 400).json(),
          { error: "invalid_grant" },
        );
        const tokenResponse = tokenResults.find((r) => r.status === 200);
        assert.equal(
          tokenResponse.status,
          200,
          await tokenResponse.clone().text(),
        );
        const token = await tokenResponse.json();
        assert.equal(token.token_type, "Bearer");
        const replay = await fetch(runtime.public + "/oid4vci/token", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": preCode,
          }),
        });
        assert.equal(replay.status, 400);
        assert.equal((await replay.json()).error, "invalid_grant");
        const nonceResponse = await fetch(runtime.public + "/oid4vci/nonce", {
          method: "POST",
        });
        assert.equal(
          nonceResponse.status,
          200,
          await nonceResponse.clone().text(),
        );
        const nonce = (await nonceResponse.json()).c_nonce;
        const proof = core.signCompactJwsJson({
          header: {
            alg: "ES256",
            typ: "openid4vci-proof+jwt",
            kid: "holder:368-recipient",
          },
          payload: { aud: config.origin, iat: now, nonce },
          keyId: "holder:368-recipient",
        });
        const wia = core.signCompactJwsJson({
          header: {
            alg: "ES256",
            typ: "wallet-instance-attestation+jwt",
            kid: config.issuer.walletProviderDid + "#key-1",
          },
          payload: {
            iss: config.issuer.walletProviderDid,
            aud: config.origin,
            iat: now,
            exp: now + 120,
            cnf: { jwk: holder },
            attestation_method: "mock_platform_attestation",
          },
          keyId: config.issuer.walletProviderDid + "#key-1",
        });
        const credentialInput = {
          credential_configuration_id: scenario.configurationId,
          proofs: { jwt: [proof] },
          holder_public_jwk: holder,
          wallet_instance_attestation: wia,
        };
        const receive = () =>
          fetch(runtime.public + "/oid4vci/credential", {
            method: "POST",
            headers: {
              authorization: "Bearer " + token.access_token,
              "content-type": "application/json",
            },
            body: JSON.stringify(credentialInput),
          });
        const wrongId = "holder:368-forwarded",
          wrongHolder = core.installDeterministicTestKey(wrongId, "issuer:243");
        const wrongProof = core.signCompactJwsJson({
          header: {
            alg: "ES256",
            typ: "openid4vci-proof+jwt",
            jwk: wrongHolder,
          },
          payload: { aud: config.origin, iat: now, nonce },
          keyId: wrongId,
        });
        const wrongReceipt = await fetch(
          runtime.public + "/oid4vci/credential",
          {
            method: "POST",
            headers: {
              authorization: "Bearer " + token.access_token,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              ...credentialInput,
              proofs: { jwt: [wrongProof] },
              holder_public_jwk: wrongHolder,
            }),
          },
        );
        assert.equal(wrongReceipt.status, 400);
        assert.deepEqual(await wrongReceipt.json(), { error: "invalid_proof" });
        for (const payload of [
          { aud: "https://wrong-audience.example", iat: now, nonce },
          { aud: config.origin, iat: now, nonce: core.randomUrlSafe(32) },
          { aud: config.origin, iat: now + 6, nonce },
          { aud: config.origin, iat: now - 301, nonce },
        ]) {
          const invalidProof = core.signCompactJwsJson({
            header: {
              alg: "ES256",
              typ: "openid4vci-proof+jwt",
              kid: "holder:368-recipient",
            },
            payload,
            keyId: "holder:368-recipient",
          });
          const refused = await fetch(runtime.public + "/oid4vci/credential", {
            method: "POST",
            headers: {
              authorization: "Bearer " + token.access_token,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              ...credentialInput,
              proofs: { jwt: [invalidProof] },
            }),
          });
          assert.equal(refused.status, 400);
          assert.deepEqual(await refused.json(), { error: "invalid_proof" });
        }
        const bypassWia = core.signCompactJwsJson({
          header: {
            alg: "ES256",
            typ: "wallet-instance-attestation+jwt",
            kid: config.issuer.walletProviderDid + "#key-1",
          },
          payload: {
            iss: config.issuer.walletProviderDid,
            aud: config.origin,
            iat: now,
            exp: now + 120,
            cnf: { jwk: holder },
            attestation_method: "dev_bypass",
          },
          keyId: config.issuer.walletProviderDid + "#key-1",
        });
        const bypassReceipt = await fetch(
          runtime.public + "/oid4vci/credential",
          {
            method: "POST",
            headers: {
              authorization: "Bearer " + token.access_token,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              ...credentialInput,
              wallet_instance_attestation: bypassWia,
            }),
          },
        );
        assert.equal(bypassReceipt.status, 400);
        assert.deepEqual(await bypassReceipt.json(), {
          error: "invalid_wallet_instance_attestation",
        });
        const badWia = await fetch(runtime.public + "/oid4vci/credential", {
          method: "POST",
          headers: {
            authorization: "Bearer " + token.access_token,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            ...credentialInput,
            wallet_instance_attestation: "bad.jwt.signature",
          }),
        });
        assert.equal(badWia.status, 400);
        assert.deepEqual(await badWia.json(), {
          error: "invalid_wallet_instance_attestation",
        });
        const receipts = await Promise.all([receive(), receive()]);
        assert.deepEqual(
          receipts.map((r) => r.status),
          [200, 200],
        );
        const duplicateBytes = (await receipts[1].json()).credentials[0]
          .credential;
        const receipt = receipts[0];
        assert.equal(receipt.status, 200, await receipt.clone().text());
        const credential = (await receipt.json()).credentials[0].credential;
        assert.equal(duplicateBytes, credential);
        core.verifyScalarCredentialAuthorization({
          compactSdJwt: credential,
          issuerJwk: identity.publicJwk,
          compactAuthorization: authorization,
          trustAnchorJwk: anchor,
          registryDid,
          nowUnixSeconds: now,
          mode: "complete",
        });
        const retry = await receive();
        assert.equal(retry.status, 200);
        assert.equal(
          (await retry.json()).credentials[0].credential,
          credential,
        );
        const verified = core.verifyScalarCredentialAuthorization({
          compactSdJwt: credential,
          issuerJwk: identity.publicJwk,
          compactAuthorization: authorization,
          trustAnchorJwk: anchor,
          registryDid,
          nowUnixSeconds: now,
          mode: "complete",
        });
        const statusResponse = await fetch(
          runtime.public + "/oid4vci/status/revocation.jwt",
        );
        assert.equal(statusResponse.status, 200);
        const signedStatus = await statusResponse.text();
        const forgedStatus =
          signedStatus.split(".").slice(0, 2).join(".") + "." + "A".repeat(86);
        assert.throws(
          () =>
            core.verifyBitstringStatusListCredential({
              compactJws: forgedStatus,
              statusListJwk: identity.publicJwk,
            }),
          /INVALID_SIGNATURE/,
        );

        core.verifyCredentialStatusActive({
          status: verified.processed_payload.credentialStatus,
          resolverResponses: {
            [config.origin + "/oid4vci/status/revocation.jwt"]: signedStatus,
          },
          statusListJwk: identity.publicJwk,
        });
        const issuanceId = new URL(verified.processed_payload.id).pathname
          .split("/")
          .at(-1);
        const statusPath = `/management/issuer/issuances/${issuanceId}/status`;
        const readStatus = await fetch(runtime.management + statusPath, {
          headers: { authorization: "Bearer " + config.managementToken },
        });
        assert.equal(readStatus.status, 200, await readStatus.clone().text());
        assert.equal((await readStatus.json()).state, "active");
        const revoke = await fetch(runtime.management + statusPath, {
          method: "POST",
          headers: {
            authorization: "Bearer " + config.managementToken,
            "content-type": "application/json",
          },
          body: JSON.stringify({ state: "revoked" }),
        });
        assert.equal(revoke.status, 200, await revoke.clone().text());
        assert.equal((await revoke.json()).state, "revoked");
        const currentStatus = await (
          await fetch(runtime.public + "/oid4vci/status/revocation.jwt")
        ).text();
        assert.equal(
          core.resolveCredentialStatus({
            status: verified.processed_payload.credentialStatus,
            resolverResponses: {
              [config.origin + "/oid4vci/status/revocation.jwt"]: currentStatus,
            },
            statusListJwk: identity.publicJwk,
          }).revoked,
          true,
        );
        const corrupted = new Pool({ connectionString: database });
        try {
          // Approved fault injection: discard a committed bit while retaining
          // its durable transition history. Public refresh must not bless it.
          await corrupted.query(
            "UPDATE partner_issuer_status SET signed_credential=$1",
            [signedStatus],
          );
          const unsafeRefresh = await fetch(
            runtime.public + "/oid4vci/status/revocation.jwt",
          );
          assert.equal(
            unsafeRefresh.status,
            503,
            await unsafeRefresh.clone().text(),
          );
        } finally {
          await corrupted.query(
            "UPDATE partner_issuer_status SET signed_credential=$1",
            [currentStatus],
          );
          await corrupted.end();
        }
        await runtime.close();
        runtime = await startRuntime(config, identity, {
          clock: () => now,
          fetchEvidence: async (url) =>
            url.endsWith("/trust-list.jwt") ? providerTrust : authorization,
        });
        const restarted = await receive();
        assert.equal(restarted.status, 200);
        assert.equal(
          (await restarted.json()).credentials[0].credential,
          credential,
        );
        let delayedClock = now;
        await runtime.close();
        runtime = await startRuntime(config, identity, {
          clock: () => delayedClock,
          fetchEvidence: async (url) => {
            if (url.endsWith("/trust-list.jwt")) {
              delayedClock = now + 20;
              return providerTrust;
            }
            return authorization;
          },
        });
        const delayedReceipt = await receive();
        assert.equal(delayedReceipt.status, 503);
        assert.deepEqual(await delayedReceipt.json(), {
          error: "issuer_authority_unavailable",
        });
        await runtime.close();
        runtime = await startRuntime(config, identity, {
          clock: () => now,
          fetchEvidence: async (url) =>
            url.endsWith("/trust-list.jwt") ? providerTrust : authorization,
        });
        const authorizationMetadata = await fetch(
          runtime.public + "/.well-known/oauth-authorization-server",
        );
        assert.equal(authorizationMetadata.status, 200);
        const discoveredAuthorization = await authorizationMetadata.json();
        assert.equal(discoveredAuthorization.issuer, config.origin);
        assert.equal(
          discoveredAuthorization.token_endpoint,
          config.origin + "/oid4vci/token",
        );
        assert.deepEqual(discoveredAuthorization.grant_types_supported, [
          "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ]);
        const metadata = await fetch(
          runtime.public + "/.well-known/openid-credential-issuer",
        );
        assert.equal(metadata.status, 200);
        const discovered = await metadata.json();
        assert.equal(discovered.credential_issuer, config.origin);
        assert.equal(
          discovered.credential_configurations_supported[
            scenario.configurationId
          ].format,
          "vc+sd-jwt",
        );
        await runtime.close();
        const freshAuthorization = core.signIssuerAuthorizations({
          payload: {
            ...JSON.parse(
              Buffer.from(authorization.split(".")[1], "base64url").toString(),
            ),
            exp: now + 600,
          },
          header: {
            alg: "ES256",
            typ: "issuer-authorizations+jwt",
            kid: registryKey,
          },
          keyId: registryKey,
        });
        for (const [document, offset, status, error] of [
          [authorization, 20, 503, "issuer_authority_unavailable"],
          [freshAuthorization, 300, 400, "invalid_token"],
        ]) {
          let blockedClock = now;
          runtime = await startRuntime(config, identity, {
            clock: () => blockedClock,
            fetchEvidence: async (url) =>
              url.endsWith("/trust-list.jwt") ? providerTrust : document,
          });
          const fault = new Pool({ connectionString: database }),
            observer = new Pool({ connectionString: database });
          const lock = await fault.connect();
          try {
            await lock.query("BEGIN");
            await lock.query(
              "SELECT hash FROM partner_issuer_nonces WHERE hash=$1 FOR UPDATE",
              [core.sha256B64Url(nonce)],
            );
            const blocked = receive();
            const deadline = Date.now() + 2000;
            while (true) {
              const waiting = (
                await observer.query(
                  "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock') AS waiting",
                )
              ).rows[0].waiting;
              if (waiting) break;
              if (Date.now() >= deadline)
                throw Error("fixture request did not reach the held lock");
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
            blockedClock = now + offset;
            await lock.query("COMMIT");
            const refused = await blocked;
            assert.equal(refused.status, status);
            assert.deepEqual(await refused.json(), { error });
          } finally {
            await lock.query("ROLLBACK");
            lock.release();
            await fault.end();
            await observer.end();
            await runtime.close();
          }
        }
        let redemptionClock = now;
        runtime = await startRuntime(config, identity, {
          clock: () => redemptionClock,
          fetchEvidence: async (url) =>
            url.endsWith("/trust-list.jwt")
              ? providerTrust
              : freshAuthorization,
        });
        const expiringOffer = await (
          await create(config.managementToken)
        ).json();
        const lockPool = new Pool({ connectionString: database });
        const codeLock = await lockPool.connect();
        try {
          await codeLock.query("BEGIN");
          await codeLock.query(
            "SELECT id FROM partner_issuer_offers WHERE code_hash=$1 FOR UPDATE",
            [core.sha256B64Url(expiringOffer.pre_authorized_code)],
          );
          const blockedToken = fetch(runtime.public + "/oid4vci/token", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type:
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
              "pre-authorized_code": expiringOffer.pre_authorized_code,
            }),
          });
          const deadline = Date.now() + 2000;
          while (
            !(
              await lockPool.query(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock') AS waiting",
              )
            ).rows[0].waiting
          ) {
            if (Date.now() >= deadline)
              throw Error("token request did not reach held offer lock");
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
          redemptionClock = now + 120;
          await codeLock.query("COMMIT");
          const refusal = await blockedToken;
          assert.equal(refusal.status, 400);
          assert.deepEqual(await refusal.json(), { error: "invalid_grant" });
        } finally {
          await codeLock.query("ROLLBACK");
          codeLock.release();
          await lockPool.end();
          await runtime.close();
        }
        redemptionClock = now;
        runtime = await startRuntime(config, identity, {
          clock: () => redemptionClock,
          fetchEvidence: async (url) =>
            url.endsWith("/trust-list.jwt")
              ? providerTrust
              : freshAuthorization,
        });
        const delayedWriteOffer = await (
          await create(config.managementToken)
        ).json();
        const finalWaitPool = new Pool({ connectionString: database });
        const finalWait = await finalWaitPool.connect();
        try {
          await finalWait.query(
            "CREATE OR REPLACE FUNCTION fixture_token_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.phase='redeemed' THEN PERFORM pg_advisory_xact_lock(368,2); END IF; RETURN NEW; END $$",
          );
          await finalWait.query(
            "CREATE TRIGGER fixture_token_wait BEFORE UPDATE ON partner_issuer_offers FOR EACH ROW EXECUTE FUNCTION fixture_token_wait()",
          );
          await finalWait.query("BEGIN");
          await finalWait.query("SELECT pg_advisory_xact_lock(368,2)");
          const blockedToken = fetch(runtime.public + "/oid4vci/token", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type:
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
              "pre-authorized_code": delayedWriteOffer.pre_authorized_code,
            }),
          });
          const deadline = Date.now() + 2000;
          while (
            !(
              await finalWaitPool.query(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock') AS waiting",
              )
            ).rows[0].waiting
          ) {
            if (Date.now() >= deadline)
              throw Error("token update did not reach final wait");
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
          redemptionClock = now + 120;
          await finalWait.query("COMMIT");
          const refusal = await blockedToken;
          assert.equal(refusal.status, 400);
          assert.deepEqual(await refusal.json(), { error: "invalid_grant" });
          // A refused final write rolled back the code consumption. Use that
          // original code for a separate final issuance-write boundary.
          redemptionClock = now;
          const recoveredToken = await (
            await fetch(runtime.public + "/oid4vci/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type:
                  "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": delayedWriteOffer.pre_authorized_code,
              }),
            })
          ).json();
          assert.equal(typeof recoveredToken.access_token, "string");
          const finalNonce = (
            await (
              await fetch(runtime.public + "/oid4vci/nonce", { method: "POST" })
            ).json()
          ).c_nonce;
          const finalProof = core.signCompactJwsJson({
            header: {
              alg: "ES256",
              typ: "openid4vci-proof+jwt",
              kid: "holder:368-recipient",
            },
            payload: { aud: config.origin, iat: now, nonce: finalNonce },
            keyId: "holder:368-recipient",
          });
          await finalWait.query(
            "CREATE OR REPLACE FUNCTION fixture_token_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.phase='issued' THEN PERFORM pg_advisory_xact_lock(368,2); END IF; RETURN NEW; END $$",
          );
          await finalWait.query("BEGIN");
          await finalWait.query("SELECT pg_advisory_xact_lock(368,2)");
          const blockedCredential = fetch(
            runtime.public + "/oid4vci/credential",
            {
              method: "POST",
              headers: {
                authorization: "Bearer " + recoveredToken.access_token,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                ...credentialInput,
                proofs: { jwt: [finalProof] },
              }),
            },
          );
          const finalDeadline = Date.now() + 2000;
          while (
            !(
              await finalWaitPool.query(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock') AS waiting",
              )
            ).rows[0].waiting
          ) {
            if (Date.now() >= finalDeadline)
              throw Error("credential update did not reach final wait");
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
          redemptionClock = now + 120;
          await finalWait.query("COMMIT");
          const finalRefusal = await blockedCredential;
          assert.equal(finalRefusal.status, 400);
          assert.deepEqual(await finalRefusal.json(), {
            error: "invalid_wallet_instance_attestation",
          });
          const retryNonce = (
            await (
              await fetch(runtime.public + "/oid4vci/nonce", { method: "POST" })
            ).json()
          ).c_nonce;
          const retryProof = core.signCompactJwsJson({
            header: {
              alg: "ES256",
              typ: "openid4vci-proof+jwt",
              kid: "holder:368-recipient",
            },
            payload: {
              aud: config.origin,
              iat: redemptionClock,
              nonce: retryNonce,
            },
            keyId: "holder:368-recipient",
          });
          const retryWia = core.signCompactJwsJson({
            header: {
              alg: "ES256",
              typ: "wallet-instance-attestation+jwt",
              kid: config.issuer.walletProviderDid + "#key-1",
            },
            payload: {
              iss: config.issuer.walletProviderDid,
              aud: config.origin,
              iat: redemptionClock,
              exp: redemptionClock + 120,
              cnf: { jwk: holder },
              attestation_method: "mock_platform_attestation",
            },
            keyId: config.issuer.walletProviderDid + "#key-1",
          });
          const safelyRetried = await fetch(
            runtime.public + "/oid4vci/credential",
            {
              method: "POST",
              headers: {
                authorization: "Bearer " + recoveredToken.access_token,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                ...credentialInput,
                proofs: { jwt: [retryProof] },
                wallet_instance_attestation: retryWia,
              }),
            },
          );
          // A new nonce succeeds only if the refused mutation rolled back;
          // a committed response would remain bound to its original nonce.
          assert.equal(
            safelyRetried.status,
            200,
            await safelyRetried.clone().text(),
          );
        } finally {
          await finalWait.query("ROLLBACK");
          await finalWait.query(
            "DROP TRIGGER IF EXISTS fixture_token_wait ON partner_issuer_offers",
          );
          await finalWait.query("DROP FUNCTION IF EXISTS fixture_token_wait()");
          finalWait.release();
          await finalWaitPool.end();
          await runtime.close();
        }
        runtime = await startRuntime(config, identity, {
          clock: () => now + 86400,
          fetchEvidence: async () => {
            throw Error("status refresh must not require registry access");
          },
        });
        const idleStatus = await fetch(
          runtime.public + "/oid4vci/status/revocation.jwt",
        );
        assert.equal(idleStatus.status, 200);
        const idleCompact = await idleStatus.text();
        core.verifyBitstringStatusListCredential({
          compactJws: idleCompact,
          statusListJwk: identity.publicJwk,
        });
        const idlePayload = core.verifyCompactJwsJson({
          compactJws: idleCompact,
          publicJwk: identity.publicJwk,
        }).payload;
        assert.equal(Date.parse(idlePayload.validFrom) / 1000, now + 86400);
        assert.equal(Date.parse(idlePayload.validUntil) / 1000, now + 86700);
        assert.throws(
          () =>
            core.verifyCredentialStatusActive({
              status: verified.processed_payload.credentialStatus,
              resolverResponses: {
                [config.origin + "/oid4vci/status/revocation.jwt"]: idleCompact,
              },
              statusListJwk: identity.publicJwk,
            }),
          /STATUS_CHECK_FAILED/,
        );
        await runtime.close();
        const forgedAuthorization =
          authorization.split(".").slice(0, 2).join(".") + "." + "A".repeat(86);
        runtime = await startRuntime(config, identity, {
          clock: () => now,
          fetchEvidence: async () => forgedAuthorization,
        });
        const badAuthority = await create(config.managementToken);
        assert.equal(badAuthority.status, 503);
        assert.deepEqual(await badAuthority.json(), {
          error: { code: "ISSUER_AUTHORITY_UNAVAILABLE" },
        });
        await runtime.close();
        const faultPool = new Pool({ connectionString: database });
        await faultPool.query(
          "UPDATE partner_issuer_offers SET phase='uncertain'",
        );
        await faultPool.end();
        await assert.rejects(async () => {
          const unexpected = await startRuntime(config, identity, {
            clock: () => now,
            fetchEvidence: async (url) =>
              url.endsWith("/trust-list.jwt") ? providerTrust : authorization,
          });
          await unexpected.close();
        }, /issuer state unavailable/);
      } finally {
        await runtime.close();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
