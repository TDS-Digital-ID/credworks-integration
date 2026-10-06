// Public HTTP fixture with real core credentials/authority. Only evidence
// transport is mapped to localhost; production signing and ledger rules run.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Pool } from "pg";
import * as core from "@unsw-vc/identity-core-node";
import { bootstrapIssuerState } from "../../src/issuer-state.ts";
import { openIdentity, startRuntime } from "../../src/runtime.ts";

export async function issuerFixture(database, ports = {}) {
  const directory = await mkdtemp(join(tmpdir(), "vc397-issuer-"));
  let now = Math.floor(Date.now() / 1000),
    available = true,
    authorizationStatus = "active";
  const config = {
    origin: `https://issuer${core
      .randomUrlSafe(16)
      .replace(/[^a-z0-9]/gi, "")
      .toLowerCase()}.example`,
    stateDir: join(directory, "identity"),
    unlockKey: core.randomUrlSafe(32),
    managementToken: core.randomUrlSafe(32),
    publicPort: ports.public ?? 0,
    managementPort: ports.management ?? 0,
  };
  const identity = openIdentity(config, true);
  const registryDid = "did:web:registry397.example",
    registryKey = registryDid + "#anchor";
  const anchor = core.installDeterministicTestKey(registryKey, "issuer:240");
  const providerDid = "did:web:provider397.example",
    providerKey = providerDid + "#key-1";
  const provider = core.installDeterministicTestKey(providerKey, "issuer:241");
  const definition = {
    id: config.origin + "/definitions/entitlement",
    version: "1",
    credential_type: "NeutralEntitlementCredential",
    label: "Neutral entitlement",
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
      { name: "entitlement", claim_paths: [["credentialSubject", "enabled"]] },
    ],
  };
  const authorizationId = crypto.randomUUID();
  config.issuer = {
    databaseUrl: database,
    registryOrigin: "https://registry397.example",
    registryDid,
    trustAnchorJwk: anchor,
    walletProviderDid: providerDid,
    walletProviderJwk: provider,
    definitions: [
      {
        configurationId: "entitlement",
        authorizationId,
        definitionId: definition.id,
        definitionVersion: "1",
        credentialType: definition.credential_type,
      },
    ],
  };
  const issuerPath = join(directory, "issuer.json");
  await writeFile(issuerPath, JSON.stringify(config.issuer));
  const pool = new Pool({ connectionString: database });
  await pool.query(
    "TRUNCATE partner_issuer_renewals,partner_issuer_identity,partner_issuer_offers,partner_issuer_nonces,partner_issuer_status",
  );
  await bootstrapIssuerState(database, config.origin, identity);
  const initial = now;
  const documents = () => ({
    authorization: core.signIssuerAuthorizations({
      payload: {
        version: 1,
        id: `${config.issuer.registryOrigin}/issuer-authorizations/${authorizationId}.jwt`,
        issuer: registryDid,
        iat: now,
        exp: now + 600,
        authorizations: [
          {
            credential_issuer_did: identity.did,
            credential_issuer_key_id: identity.keyId,
            credential_issuer_public_jwk_sha256_thumbprint:
              core.publicJwkSha256Thumbprint(identity.publicJwk),
            definition,
            status: authorizationStatus,
          },
        ],
      },
      header: {
        alg: "ES256",
        typ: "issuer-authorizations+jwt",
        kid: registryKey,
      },
      keyId: registryKey,
    }),
    trust: core.signTrustList({
      payload: {
        id: config.issuer.registryOrigin + "/trust-list.jwt",
        issuer: registryDid,
        iat: now,
        exp: now + 600,
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
    }),
  });
  let signed = documents();
  const evidence = createServer((request, response) => {
    response.statusCode = available ? 200 : 503;
    response.end(
      request.url === "/trust-list.jwt" ? signed.trust : signed.authorization,
    );
  });
  await new Promise((resolve) =>
    evidence.listen(ports.evidence ?? 0, "127.0.0.1", resolve),
  );
  const transport = async (url) => {
    if (!available) throw Error("fixture authority unavailable");
    return url.endsWith("/trust-list.jwt")
      ? signed.trust
      : signed.authorization;
  };
  let runtime = await startRuntime(config, identity, {
    clock: () => now,
    fetchEvidence: transport,
  });
  const children = new Set();
  const path = (id) => `/management/issuer/issuances/${id}/status`;
  const management = (target, id, body, token = config.managementToken) =>
    fetch(target.management + path(id), {
      method: body === undefined ? "GET" : "POST",
      headers: {
        authorization: "Bearer " + token,
        "content-type": "application/json",
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const offer = async (holderId = "holder:397-owner") => {
    const holder = core.installDeterministicTestKey(
      holderId,
      holderId === "holder:397-owner" ? "holder" : "issuer:243",
    );
    const response = await fetch(
      runtime.management + "/management/issuer/offers",
      {
        method: "POST",
        headers: {
          authorization: "Bearer " + config.managementToken,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          configuration_id: "entitlement",
          claims: { enabled: true },
          valid_from: initial,
          valid_until: initial + 3600,
          offer_expires_at: initial + 120,
          recipient_jwk_thumbprint: core.publicJwkSha256Thumbprint(holder),
        }),
      },
    );
    assert.equal(response.status, 201, await response.clone().text());
    return { holder, holderId, ...(await response.json()) };
  };
  const issueOffer = async (offered, expectedStatus = 200) => {
    const id = new URL(offered.credential_offer_uri).pathname.split("/").at(-1);
    const tokenResponse = await fetch(runtime.public + "/oid4vci/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": offered.pre_authorized_code,
      }),
    });
    assert.equal(tokenResponse.status, 200, await tokenResponse.clone().text());
    const token = (await tokenResponse.json()).access_token;
    const nonce = (
      await (
        await fetch(runtime.public + "/oid4vci/nonce", { method: "POST" })
      ).json()
    ).c_nonce;
    const proof = core.signCompactJwsJson({
      header: {
        alg: "ES256",
        typ: "openid4vci-proof+jwt",
        kid: offered.holderId,
      },
      payload: { aud: config.origin, iat: now, nonce },
      keyId: offered.holderId,
    });
    const wia = core.signCompactJwsJson({
      header: {
        alg: "ES256",
        typ: "wallet-instance-attestation+jwt",
        kid: providerKey,
      },
      payload: {
        iss: providerDid,
        aud: config.origin,
        iat: now,
        exp: now + 120,
        cnf: { jwk: offered.holder },
        attestation_method: "mock_platform_attestation",
      },
      keyId: providerKey,
    });
    const credentialBody = {
      credential_configuration_id: "entitlement",
      proofs: { jwt: [proof] },
      holder_public_jwk: offered.holder,
      wallet_instance_attestation: wia,
    };
    const receipt = await fetch(runtime.public + "/oid4vci/credential", {
      method: "POST",
      headers: {
        authorization: "Bearer " + token,
        "content-type": "application/json",
      },
      body: JSON.stringify(credentialBody),
    });
    assert.equal(receipt.status, expectedStatus, await receipt.clone().text());
    if (expectedStatus !== 200) return await receipt.json();
    const responseBody = await receipt.json();
    const compact = responseBody.credentials[0].credential;
    const payload = core.verifyScalarCredentialAuthorization({
      compactSdJwt: compact,
      issuerJwk: identity.publicJwk,
      compactAuthorization: signed.authorization,
      trustAnchorJwk: anchor,
      registryDid,
      nowUnixSeconds: now,
      mode: "complete",
    }).processed_payload;
    return { id, compact, payload, token, proof, responseBody, credentialBody };
  };
  return {
    config,
    identity,
    pool,
    issue: async (holderId) => issueOffer(await offer(holderId)),
    issueOffer,
    offer,
    path,
    management,
    initial,
    get runtime() {
      return runtime;
    },
    get now() {
      return now;
    },
    set now(value) {
      now = value;
    },
    set available(value) {
      available = value;
    },
    set authorizationStatus(value) {
      authorizationStatus = value;
      signed = documents();
    },
    set definitionVersion(value) {
      definition.version = value;
      signed = documents();
    },
    refreshEvidence() {
      signed = documents();
    },
    async restart() {
      await runtime.close();
      runtime = await startRuntime(config, identity, {
        clock: () => now,
        fetchEvidence: transport,
      });
    },
    async process(ports = {}) {
      const child = spawn(
        process.execPath,
        ["--import", "tsx", "tests/support/issuer-process.mjs"],
        {
          env: {
            ...process.env,
            PARTNER_ORIGIN: config.origin,
            PARTNER_STATE_DIR: config.stateDir,
            PARTNER_UNLOCK_KEY: config.unlockKey,
            PARTNER_MANAGEMENT_TOKEN: config.managementToken,
            PARTNER_PUBLIC_PORT: String(ports.public ?? 0),
            PARTNER_MANAGEMENT_PORT: String(ports.management ?? 0),
            PARTNER_ISSUER_CONFIG: issuerPath,
            PARTNER_VERIFIER_CONFIG: "",
            PARTNER_ISSUER_TEST_EVIDENCE_SOURCE: `http://127.0.0.1:${evidence.address().port}`,
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      children.add(child);
      return await new Promise((resolve, reject) => {
        let output = "",
          errors = "";
        const deadline = setTimeout(() => {
          child.kill("SIGKILL");
          reject(Error("issuer startup deadline"));
        }, 10000);
        child.stderr.on("data", (chunk) => {
          errors += chunk;
        });
        child.once("exit", () => {
          clearTimeout(deadline);
          reject(Error("issuer process unavailable: " + errors));
        });
        child.stdout.on("data", (chunk) => {
          output += chunk;
          if (output.includes("READY ")) {
            clearTimeout(deadline);
            resolve({
              ...JSON.parse(output.trim().slice(6)),
              async stop() {
                if (child.exitCode === null) {
                  const exit = once(child, "exit");
                  child.kill("SIGTERM");
                  await exit;
                }
              },
            });
          }
        });
      });
    },
    async status(issued, target = runtime) {
      const response = await fetch(
        target.public + "/oid4vci/status/revocation.jwt",
      );
      assert.equal(response.status, 200, await response.clone().text());
      return core.resolveCredentialStatusAt({
        status: issued.payload.credentialStatus,
        resolverResponses: {
          [config.origin + "/oid4vci/status/revocation.jwt"]:
            await response.text(),
        },
        statusListJwk: identity.publicJwk,
        nowUnixSeconds: Math.max(now, Math.floor(Date.now() / 1000)),
      }).revoked;
    },
    async close() {
      for (const child of children)
        if (child.exitCode === null) {
          const exit = once(child, "exit");
          child.kill("SIGTERM");
          await exit;
        }
      await runtime.close();
      await pool.end();
      await new Promise((resolve) => evidence.close(resolve));
      await rm(directory, { recursive: true, force: true });
    },
  };
}
