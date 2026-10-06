import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, chmod, rm } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as core from "@unsw-vc/identity-core-node";
const image = process.env.PARTNER_CONTAINER_IMAGE;
const upgradeImage = process.env.PARTNER_RECOVERY_UPGRADE_IMAGE;
function docker(...args) {
  try {
    return execFileSync("docker", args, {
      encoding: "utf8",
      timeout: 30000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    if (String(error.stderr).includes("partner_identity_unavailable:"))
      throw Error("partner_identity_unavailable");
    throw Error("issuer fixture Docker operation failed: " + args[0]);
  }
}
const delay = () => new Promise((resolve) => setTimeout(resolve, 100));
test(
  "packaged issuer and scalar verifier preserve separate identities and verify recipient-authorized credentials",
  { skip: !image, timeout: 180000 },
  async () => {
    let runningImage = image;
    const suffix = core
      .randomUrlSafe(16)
      .replace(/[^a-z0-9]/gi, "")
      .toLowerCase();
    const network = "vc408-network-" + suffix,
      db = "vc408-db-" + suffix,
      registry = "vc408-registry-" + suffix,
      runtime = "vc408-issuer-" + suffix,
      verifier = "vc408-verifier-" + suffix,
      refusedRestore = "vc408-refused-restore-" + suffix;
    const identityVolume = "vc408-identity-" + suffix,
      databaseVolume = "vc408-database-" + suffix,
      verifierVolume = "vc408-verifier-identity-" + suffix,
      restoredIdentityVolume = "vc408-restored-issuer-" + suffix,
      restoredVerifierVolume = "vc408-restored-verifier-" + suffix,
      rotatedIdentityVolume = "vc408-rotated-issuer-" + suffix;
    // macOS tmpdir (/var/folders) is not visible inside the Docker VM. Keep
    // disposable bind fixtures in the checkout's ignored shared directory.
    const artifacts = fileURLToPath(
      new URL("../../../.artifacts/", import.meta.url),
    );
    await mkdir(artifacts, { recursive: true });
    const root = await mkdtemp(join(artifacts, "vc408-container-")),
      configDir = join(root, "config"),
      registryDir = join(root, "registry");
    await mkdir(configDir);
    await mkdir(registryDir);
    await chmod(configDir, 0o755);
    await chmod(registryDir, 0o755);
    const port = Number(
      process.env.PARTNER_ISSUER_CONTAINER_HTTP_PORT ?? 29250,
    );
    const issuerHost = `issuer${suffix}.example`;
    const origin = `https://${issuerHost}:3443`,
      registryHost = `registry${suffix}.example`,
      registryOrigin = `https://${registryHost}:3443`,
      registryDid = `did:web:${registryHost}%3A3443`,
      registryKey = registryDid + "#trust-anchor-1";
    const providerDid = `did:web:provider${suffix}.example`,
      providerKey = providerDid + "#wia-1";
    const anchor = core.installDeterministicTestKey(registryKey, "issuer:240"),
      provider = core.installDeterministicTestKey(providerKey, "issuer:241");
    const authorizationId = crypto.randomUUID(),
      permissionId = crypto.randomUUID(),
      unlock = core.randomUrlSafe(32),
      managementToken = core.randomUrlSafe(32),
      dbPassword = core.randomUrlSafe(32);
    const definition = {
      id: origin + "/definitions/entitlement",
      version: "1",
      credential_type: "PartnerEntitlement",
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
    const databaseUrl = `postgres://credworks:${dbPassword}@${db}:5432/partner_issuer`;
    const config = {
      databaseUrl,
      registryOrigin,
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
    await writeFile(join(configDir, "issuer.json"), JSON.stringify(config));
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        join(registryDir, "tls.key"),
        "-out",
        join(registryDir, "tls.crt"),
        "-days",
        "1",
        "-subj",
        "/CN=" + registryHost,
        "-addext",
        "subjectAltName=DNS:" + registryHost + ",DNS:" + issuerHost,
      ],
      { stdio: "ignore" },
    );
    await chmod(join(registryDir, "tls.key"), 0o644);
    await writeFile(
      join(registryDir, "server.mjs"),
      `import {createServer} from 'node:https'; import {readFileSync,existsSync} from 'node:fs'; const routes=new Map([['/issuer-authorizations/${authorizationId}.jwt','authority.jwt'],['/scoped-verifier-permissions/${permissionId}.jwt','permission.jwt'],['/trust-list.jwt','trust.jwt']]); createServer({key:readFileSync('/registry/tls.key'),cert:readFileSync('/registry/tls.crt')},async(req,res)=>{if(req.url==='/oid4vci/status/revocation.jwt'){if(existsSync('/registry/status-override.jwt')){res.setHeader('content-type','application/jwt');res.end(readFileSync('/registry/status-override.jwt'));return;}try{const response=await fetch('http://${runtime}:3080'+req.url);res.writeHead(response.status,{'content-type':'application/jwt'});res.end(await response.text());}catch{res.writeHead(503);res.end();}return;} const file=routes.get(req.url); if(!file){res.writeHead(404);res.end();return;} res.setHeader('content-type','application/jwt');res.end(readFileSync('/registry/'+file));}).listen(3443,'0.0.0.0',()=>console.log('READY'));`,
    );
    const env = [
      "-e",
      "PARTNER_ORIGIN=" + origin,
      "-e",
      "PARTNER_STATE_DIR=/state/identity",
      "-e",
      "PARTNER_UNLOCK_KEY=" + unlock,
      "-e",
      "PARTNER_MANAGEMENT_TOKEN=" + managementToken,
      "-e",
      "PARTNER_ISSUER_CONFIG=/config/issuer.json",
      "-e",
      "NODE_EXTRA_CA_CERTS=/registry/tls.crt",
    ];
    const mounts = [
      "--mount",
      `type=volume,src=${identityVolume},dst=/state`,
      "--mount",
      `type=bind,src=${configDir},dst=/config,readonly`,
      "--mount",
      `type=bind,src=${registryDir},dst=/registry,readonly`,
    ];
    const now = () =>
      Number(
        docker("exec", registry, "node", "-p", "Math.floor(Date.now()/1000)"),
      );
    const publicUrl = `http://127.0.0.1:${port}`;
    const composeProject = "vc408-compose-" + suffix;
    const composeFile = fileURLToPath(
      new URL("../../../infra/partner-issuer/compose.yml", import.meta.url),
    );
    const override = join(root, "compose.fixture.json");
    await writeFile(
      override,
      JSON.stringify({
        services: {
          partner: {
            environment: { NODE_EXTRA_CA_CERTS: "/registry/tls.crt" },
            volumes: [`${registryDir}:/registry:ro`],
          },
        },
        volumes: { partner_identity: { external: true, name: identityVolume } },
        networks: { default: { external: true, name: network } },
      }),
    );
    const compose = (...args) => {
      try {
        return execFileSync(
          "docker",
          [
            "compose",
            "-p",
            composeProject,
            "-f",
            composeFile,
            "-f",
            override,
            ...args,
          ],
          {
            encoding: "utf8",
            timeout: 30000,
            stdio: ["ignore", "pipe", "pipe"],
            env: {
              ...process.env,
              PARTNER_IMAGE: image,
              PARTNER_ORIGIN: origin,
              PARTNER_CONFIG_DIR: configDir,
              PARTNER_UNLOCK_KEY: unlock,
              PARTNER_MANAGEMENT_TOKEN: managementToken,
              PARTNER_HOST_PORT: String(port),
              PARTNER_ISSUER_POSTGRES_PASSWORD: dbPassword,
            },
          },
        ).trim();
      } catch {
        throw Error("issuer fixture Compose operation failed");
      }
    };

    const management = (path, body, target = runtime, capability = "", idempotencyKey = "") =>
      JSON.parse(
        docker(
          "exec",
          target,
          "node",
          "--input-type=module",
          "-e",
          `const response=await fetch('http://127.0.0.1:3081${path}',{method:'POST',headers:{authorization:'Bearer '+process.env.PARTNER_MANAGEMENT_TOKEN,'content-type':'application/json','x-session-capability':${JSON.stringify(capability)},'idempotency-key':${JSON.stringify(idempotencyKey)}},body:${JSON.stringify(JSON.stringify(body))}});console.log(JSON.stringify({status:response.status,body:await response.json()}));`,
        ),
      );
    const start = () =>
      docker(
        "run",
        "-d",
        "--name",
        runtime,
        "--network",
        network,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=32m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "512m",
        "--cpus",
        "2",
        "-p",
        `127.0.0.1:${port}:3080`,
        ...env,
        ...mounts,
        runningImage,
      );
    const ready = async () => {
      const deadline = Date.now() + 15000;
      while (true) {
        try {
          const response = await fetch(publicUrl + "/.well-known/did.json");
          if (response.status === 200) return response.json();
        } catch {}
        if (Date.now() >= deadline)
          throw Error("packaged issuer did not become ready");
        await delay();
      }
    };
    const replace = async () => {
      docker("rm", "-f", runtime);
      start();
      return ready();
    };
    try {
      const source = docker(
        "image",
        "inspect",
        "--format",
        '{{index .Config.Labels "org.opencontainers.image.revision"}}',
        image,
      );
      assert.match(source, /^[0-9a-f]{40}$/);
      if (process.env.PARTNER_CONTAINER_SOURCE_REVISION)
        assert.equal(source, process.env.PARTNER_CONTAINER_SOURCE_REVISION);
      docker("network", "create", network);
      docker("volume", "create", identityVolume);
      docker("volume", "create", databaseVolume);
      docker("volume", "create", verifierVolume);
      docker(
        "run",
        "-d",
        "--name",
        db,
        "--network",
        network,
        "-e",
        "POSTGRES_DB=partner_issuer",
        "-e",
        "POSTGRES_USER=credworks",
        "-e",
        "POSTGRES_PASSWORD=" + dbPassword,
        "--mount",
        `type=volume,src=${databaseVolume},dst=/var/lib/postgresql/data`,
        "postgres:17.10-alpine3.23",
      );
      const deadline = Date.now() + 20000;
      while (true) {
        try {
          docker(
            "exec",
            db,
            "pg_isready",
            "-U",
            "credworks",
            "-d",
            "partner_issuer",
          );
          break;
        } catch {
          if (Date.now() >= deadline)
            throw Error("owned issuer database unavailable");
          await delay();
        }
      }
      docker(
        "run",
        "--rm",
        "--network",
        network,
        "--entrypoint",
        "node",
        "-e",
        "PARTNER_ISSUER_DATABASE_URL=" + databaseUrl,
        image,
        "--import",
        "tsx",
        "src/issuer-migrate.ts",
      );
      const identity = JSON.parse(
        docker(
          "run",
          "--rm",
          "--network",
          network,
          ...env,
          ...mounts,
          image,
          "bootstrap",
        ),
      );
      const issuerKey = identity.did + "#key-1";
      // Use an independent container clock before signing fixture public evidence;
      // verification never derives acceptance time from token claims.
      const clock = Number(
        docker(
          "run",
          "--rm",
          "--entrypoint",
          "node",
          image,
          "-p",
          "Math.floor(Date.now()/1000)",
        ),
      );
      assert.ok(Number.isSafeInteger(clock));
      const authority = core.signIssuerAuthorizations({
        header: {
          alg: "ES256",
          typ: "issuer-authorizations+jwt",
          kid: registryKey,
        },
        payload: {
          version: 1,
          id: registryOrigin + `/issuer-authorizations/${authorizationId}.jwt`,
          issuer: registryDid,
          iat: clock,
          exp: clock + 600,
          authorizations: [
            {
              credential_issuer_did: identity.did,
              credential_issuer_key_id: issuerKey,
              credential_issuer_public_jwk_sha256_thumbprint:
                core.publicJwkSha256Thumbprint(identity.publicJwk),
              definition,
              status: "active",
            },
          ],
        },
        keyId: registryKey,
      });
      const trust = core.signTrustList({
        header: { alg: "ES256", typ: "trust-list+jwt", kid: registryKey },
        payload: {
          id: registryOrigin + "/trust-list.jwt",
          issuer: registryDid,
          iat: clock,
          exp: clock + 600,
          entries: [
            {
              issuer_did: providerDid,
              credential_types: ["WalletInstanceAttestation"],
              status: "active",
              public_jwk: provider,
            },
          ],
        },
        keyId: registryKey,
      });
      await writeFile(join(registryDir, "authority.jwt"), authority);
      await writeFile(join(registryDir, "trust.jwt"), trust);
      docker(
        "run",
        "-d",
        "--name",
        registry,
        "--network",
        network,
        "--network-alias",
        registryHost,
        "--network-alias",
        issuerHost,
        "--read-only",
        "--mount",
        `type=bind,src=${registryDir},dst=/registry,readonly`,
        "--entrypoint",
        "node",
        image,
        "/registry/server.mjs",
      );
      start();
      const did = await ready();
      assert.equal(did.id, identity.did);
      const holderId = "holder:368-container",
        holder = core.installDeterministicTestKey(holderId, "issuer:249");
      const prepareIssuance = async (authorizedOffer, expectedDid = did) => {
        const issuedAt = now();
        const offer = authorizedOffer ? { status: 201, body: authorizedOffer } : management("/management/issuer/offers", {
          configuration_id: "entitlement",
          claims: { enabled: true },
          valid_from: issuedAt,
          valid_until: issuedAt + 600,
          offer_expires_at: issuedAt + 120,
          recipient_jwk_thumbprint: core.publicJwkSha256Thumbprint(holder),
        });
        assert.equal(offer.status, 201);
        assert.deepEqual(await replace(), expectedDid);
        const capability = new URL(offer.body.credential_offer_uri);
        const retrieved = await fetch(
          publicUrl + capability.pathname + capability.search,
        );
        assert.equal(retrieved.status, 200);
        const code = (await retrieved.json()).grants[
          "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        ]["pre-authorized_code"];
        const redeem = () =>
          fetch(publicUrl + "/oid4vci/token", {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
              "pre-authorized_code": code,
            }),
          });
        const tokenResponse = await redeem();
        assert.equal(tokenResponse.status, 200);
        const token = await tokenResponse.json();
        const nonceResponse = await fetch(publicUrl + "/oid4vci/nonce", {
          method: "POST",
        });
        const nonce = (await nonceResponse.json()).c_nonce;
        const proofNow = now();
        const proof = core.signCompactJwsJson({
          header: { alg: "ES256", typ: "openid4vci-proof+jwt", kid: holderId },
          payload: { aud: origin, iat: proofNow, nonce },
          keyId: holderId,
        });
        const wia = core.signCompactJwsJson({
          header: {
            alg: "ES256",
            typ: "wallet-instance-attestation+jwt",
            kid: providerKey,
          },
          payload: {
            iss: providerDid,
            aud: origin,
            iat: proofNow,
            exp: proofNow + 120,
            cnf: { jwk: holder },
            attestation_method: "mock_platform_attestation",
          },
          keyId: providerKey,
        });
        const receive = () =>
          fetch(publicUrl + "/oid4vci/credential", {
            method: "POST",
            headers: {
              authorization: "Bearer " + token.access_token,
              "content-type": "application/json",
            },
            body: JSON.stringify({
              credential_configuration_id: "entitlement",
              holder_public_jwk: holder,
              proofs: { jwt: [proof] },
              wallet_instance_attestation: wia,
            }),
          });
        return { receive, redeem };
      };
      const { receive, redeem } = await prepareIssuance();
      const lost = await receive();
      assert.equal(lost.status, 200);
      await lost.body.cancel();
      assert.deepEqual(await replace(), did);
      const replay = await redeem();
      assert.equal(replay.status, 400);
      assert.deepEqual(await replay.json(), { error: "invalid_grant" });
      const recovered = await receive();
      assert.equal(recovered.status, 200);
      const compact = (await recovered.json()).credentials[0].credential;
      const verificationNow = now();
      assert.ok(Number.isSafeInteger(verificationNow));
      const verified = core.verifyScalarCredentialAuthorization({
        compactSdJwt: compact,
        issuerJwk: identity.publicJwk,
        compactAuthorization: authority,
        trustAnchorJwk: anchor,
        registryDid,
        nowUnixSeconds: verificationNow,
        mode: "complete",
      });
      assert.equal(verified.processed_payload.credentialSubject.enabled, true);
      const repeated = await receive();
      assert.equal(repeated.status, 200);
      assert.equal((await repeated.json()).credentials[0].credential, compact);
      const statusResponse = await fetch(
        publicUrl + "/oid4vci/status/revocation.jwt",
      );
      assert.equal(statusResponse.status, 200);
      const signedStatus = await statusResponse.text();
      core.verifyCredentialStatusActive({
        status: verified.processed_payload.credentialStatus,
        resolverResponses: {
          [origin + "/oid4vci/status/revocation.jwt"]: signedStatus,
        },
        statusListJwk: identity.publicJwk,
      });
      const unaffected = await prepareIssuance();
      const unaffectedResponse = await unaffected.receive();
      assert.equal(unaffectedResponse.status, 200);
      const unaffectedCompact = (await unaffectedResponse.json()).credentials[0].credential;
      const renewalPost = async (uri, additions = {}) => {
        const nonceResponse = await fetch(publicUrl + "/oid4vci/nonce", { method: "POST" });
        assert.equal(nonceResponse.status, 200);
        const proof = core.signCompactJwsJson({
          header: { alg: "ES256", typ: "openid4vci-proof+jwt", kid: holderId },
          payload: { aud: uri, iat: now(), nonce: (await nonceResponse.json()).c_nonce },
          keyId: holderId,
        });
        const response = await fetch(publicUrl + new URL(uri).pathname, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ version: 1, ...additions, proof: { proof_type: "jwt", jwt: proof } }),
        });
        assert.equal(response.status, 200);
        return response.json();
      };
      const renewalPairs = [];
      for (const confirm of [false, true]) {
        const prior = await prepareIssuance();
        const priorResponse = await prior.receive();
        assert.equal(priorResponse.status, 200);
        const priorCompact = (await priorResponse.json()).credentials[0].credential;
        const priorVerified = core.verifyScalarCredentialAuthorization({
          compactSdJwt: priorCompact, issuerJwk: identity.publicJwk,
          compactAuthorization: authority, trustAnchorJwk: anchor,
          registryDid, nowUnixSeconds: now(), mode: "complete",
        });
        const priorId = new URL(priorVerified.processed_payload.id).pathname.split("/").at(-1);
        const time = now();
        const input = { version: 1, predecessor_issuance_id: priorId,
          configuration_id: "entitlement", claims: { enabled: true },
          valid_from: time, valid_until: time + 600, offer_expires_at: time + 120 };
        const correlation = core.randomUrlSafe(32);
        const proposal = management("/management/issuer/renewals", input, runtime, "", correlation);
        assert.equal(proposal.status, 201);
        const requestUri = new URL(proposal.body.renewal_request_uri);
        const requestResponse = await fetch(publicUrl + requestUri.pathname + requestUri.search);
        assert.equal(requestResponse.status, 200);
        const request = await requestResponse.json();
        const authorized = await renewalPost(request.authorize_uri, { capability: requestUri.searchParams.get("capability") });
        const successor = await prepareIssuance(authorized);
        const successorResponse = await successor.receive();
        assert.equal(successorResponse.status, 200);
        const successorBody = await successorResponse.json();
        const receipt = successorBody.x_credworks_renewal;
        assert.equal(receipt.status, "pending_confirmation");
        assert.equal(receipt.predecessor_credential_id, priorVerified.processed_payload.id);
        const successorVerified = core.verifyScalarCredentialAuthorization({
          compactSdJwt: successorBody.credentials[0].credential, issuerJwk: identity.publicJwk,
          compactAuthorization: authority, trustAnchorJwk: anchor,
          registryDid, nowUnixSeconds: now(), mode: "complete",
        });
        assert.equal(receipt.successor_credential_id, successorVerified.processed_payload.id);
        const state = confirm
          ? await renewalPost(receipt.confirm_uri, { event: "credential_accepted" })
          : await renewalPost(receipt.status_uri);
        assert.equal(state.status, confirm ? "completed" : "awaiting_receipt");
        renewalPairs.push({ confirm, priorId, input, correlation, proposal, receipt, state, successor, successorBody });
      }
      const verifierOrigin = `https://verifier${suffix}.example`;
      const verifierEnv = [
        "-e",
        "PARTNER_ORIGIN=" + verifierOrigin,
        "-e",
        "PARTNER_STATE_DIR=/state/identity",
        "-e",
        "PARTNER_UNLOCK_KEY=" + core.randomUrlSafe(32),
        "-e",
        "PARTNER_MANAGEMENT_TOKEN=" + core.randomUrlSafe(32),
        "-e",
        "NODE_EXTRA_CA_CERTS=/registry/tls.crt",
      ];
      const verifierMounts = [
        "--mount",
        `type=volume,src=${verifierVolume},dst=/state`,
        "--mount",
        `type=bind,src=${configDir},dst=/config,readonly`,
        "--mount",
        `type=bind,src=${registryDir},dst=/registry,readonly`,
      ];
      const verifierIdentity = JSON.parse(
        docker(
          "run",
          "--rm",
          "--network",
          network,
          ...verifierEnv,
          ...verifierMounts,
          image,
          "bootstrap",
        ),
      );
      assert.notEqual(verifierIdentity.did, identity.did);
      assert.notEqual(
        core.publicJwkSha256Thumbprint(verifierIdentity.publicJwk),
        core.publicJwkSha256Thumbprint(identity.publicJwk),
      );
      const permission = core.signScopedVerifierPermissions({
        keyId: registryKey,
        header: {
          alg: "ES256",
          typ: "scoped-verifier-permissions+jwt",
          kid: registryKey,
        },
        payload: {
          version: 1,
          id:
            registryOrigin + `/scoped-verifier-permissions/${permissionId}.jwt`,
          issuer: registryDid,
          iat: now(),
          exp: now() + 300,
          permissions: [
            {
              credential_issuer_did: identity.did,
              definition_id: definition.id,
              definition_version: "1",
              credential_type: definition.credential_type,
              verifier_did: verifierIdentity.did,
              verifier_origin: verifierOrigin,
              verifier_public_jwk_sha256_thumbprint:
                core.publicJwkSha256Thumbprint(verifierIdentity.publicJwk),
              profile_name: "entitlement",
              claim_paths: [["credentialSubject", "enabled"]],
              status: "active",
            },
          ],
        },
      });
      await writeFile(join(registryDir, "permission.jwt"), permission);
      await writeFile(
        join(configDir, "verifier.json"),
        JSON.stringify({
          issuerDid: identity.did,
          issuerJwk: identity.publicJwk,
          registryOrigin,
          trustAnchorJwk: anchor,
          maxCacheAgeSeconds: 300,
          statusSources: [
            {
              url: origin + "/oid4vci/status/revocation.jwt",
              publicJwk: identity.publicJwk,
              purpose: "revocation",
            },
          ],
          scalar: {
            registryDid,
            issuerKeyId: issuerKey,
            definitions: [
              {
                ...config.definitions[0],
                profiles: [{ name: "entitlement", permissionId }],
              },
            ],
          },
        }),
      );
      const verifierUrl = `http://127.0.0.1:${port + 1}`;
      const launchVerifier = async () => {
        docker(
          "run",
          "-d",
          "--name",
          verifier,
          "--network",
          network,
          "--read-only",
          "--tmpfs",
          "/tmp:rw,noexec,nosuid,size=32m",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges",
          "--memory",
          "512m",
          "--cpus",
          "2",
          "-p",
          `127.0.0.1:${port + 1}:3080`,
          ...verifierEnv,
          "-e",
          "PARTNER_VERIFIER_CONFIG=/config/verifier.json",
          ...verifierMounts,
          runningImage,
        );
        const deadline = Date.now() + 15000;
        while (Date.now() < deadline) {
          try {
            const response = await fetch(verifierUrl + "/.well-known/did.json");
            if (response.status === 200) return response.json();
          } catch {}
          await delay();
        }
        throw Error("packaged scalar verifier did not become ready");
      };
      const verifierDid = await launchVerifier();
      assert.equal(verifierDid.id, verifierIdentity.did);
      const verifyCredential = async (credential) => {
        const session = management(
          "/management/sessions",
          {
            configuration_id: "entitlement",
            profile: "entitlement",
            interaction_id: "container-browser",
            purpose: "Check synthetic value",
          },
          verifier,
        );
        assert.equal(session.status, 201, JSON.stringify(session.body));
        const signedRequest = await fetch(
          verifierUrl + new URL(session.body.request_uri).pathname,
        );
        assert.equal(signedRequest.status, 200);
        const request = core.verifyOid4vpRequestObject({
          compactJws: await signedRequest.text(),
          resolverResponses: {
            [core.didWebToHttpsUrl(verifierIdentity.did)]:
              JSON.stringify(verifierDid),
          },
          nowUnixSeconds: now(),
        }).payload;
        assert.equal(
          request.credworks_scalar.permission_path,
          `/scoped-verifier-permissions/${permissionId}.jwt`,
        );
        const presentation = core.presentSdJwt({
          compactSdJwt: credential,
          holderKeyId: holderId,
          profile: {
            name: "entitlement",
            claim_paths: [["credentialSubject", "enabled"]],
          },
          audience: request.client_id,
          nonce: request.nonce,
          iat: now(),
        }).presentation;
        const submitted = await fetch(
          verifierUrl + new URL(request.response_uri).pathname,
          {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              state: request.state,
              vp_token: JSON.stringify({ entitlement: [presentation] }),
            }),
          },
        );
        assert.equal(submitted.status, 200);
        const result = management(
          `/management/sessions/${session.body.session_id}/result`,
          {},
          verifier,
          session.body.correlation_capability,
        );
        assert.equal(result.status, 200);
        return { session, result };
      };
      const { session, result } = await verifyCredential(compact);
      assert.equal(result.body.status, "verified", JSON.stringify(result.body));
      assert.deepEqual(result.body.claims, { enabled: true });
      assert.equal(result.body.evidence.issuer_did, identity.did);
      assert.equal(result.body.evidence.verifier_did, verifierIdentity.did);
      assert.equal(
        management(
          `/management/sessions/${session.body.session_id}/result`,
          {},
          verifier,
          session.body.correlation_capability,
        ).status,
        409,
      );
      assert.equal(
        (await fetch(verifierUrl + "/management/sessions", { method: "POST" }))
          .status,
        404,
      );
      docker("rm", "-f", verifier);
      assert.deepEqual(await launchVerifier(), verifierDid);
      docker("rm", "-f", verifier);
      const issuanceId = new URL(verified.processed_payload.id).pathname
        .split("/")
        .at(-1);
      const lifecyclePath = `/management/issuer/issuances/${issuanceId}/status`;
      const retired = management(lifecyclePath, { state: "revoked" });
      assert.equal(retired.status, 200);
      assert.equal(retired.body.state, "revoked");
      docker("rm", "-f", runtime);
      compose("up", "-d", "partner");
      assert.deepEqual(await ready(), did);
      const composedReceipt = await receive();
      assert.equal(composedReceipt.status, 200);
      assert.equal(
        (await composedReceipt.json()).credentials[0].credential,
        compact,
      );
      const retirementRetry = management(
        lifecyclePath,
        { state: "revoked" },
        compose("ps", "-q", "partner").trim(),
      );
      assert.equal(retirementRetry.status, 200);
      assert.deepEqual(retirementRetry.body, retired.body);
      const retainedStatus = await (
        await fetch(publicUrl + "/oid4vci/status/revocation.jwt")
      ).text();
      assert.equal(
        core.resolveCredentialStatusAt({
          status: verified.processed_payload.credentialStatus,
          resolverResponses: {
            [origin + "/oid4vci/status/revocation.jwt"]: retainedStatus,
          },
          statusListJwk: identity.publicJwk,
          nowUnixSeconds: now(),
        }).revoked,
        true,
      );
      compose("down");
      // Capture an actual negative before stopping every writer for backup.
      start();
      assert.deepEqual(await ready(), did);
      assert.deepEqual(await launchVerifier(), verifierDid);
      assert.equal((await verifyCredential(unaffectedCompact)).result.body.status, "verified");
      const observedNegative = (await verifyCredential(compact)).result;
      assert.equal(observedNegative.body.error.code, "STATUS_CHECK_FAILED");
      docker("stop", runtime, verifier);

      const backup = join(root, "recovery-backup");
      await mkdir(backup, { mode: 0o700 });
      const transfer = (args, input) => {
        try {
          return execFileSync("docker", args, {
            input,
            timeout: 30000,
            maxBuffer: 16 * 1024 * 1024,
            stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
          });
        } catch {
          throw Error("owned recovery fixture transfer failed");
        }
      };
      const archives = [
        ["issuer.tar", identityVolume, restoredIdentityVolume],
        ["verifier.tar", verifierVolume, restoredVerifierVolume],
      ];
      for (const [name, sourceVolume] of archives)
        await writeFile(join(backup, name), transfer([
          "run", "--rm", "--read-only", "--user", "10001:10001",
          "--cap-drop", "ALL", "--mount", `type=volume,src=${sourceVolume},dst=/state,readonly`,
          "--entrypoint", "tar", image, "-C", "/state", "-cf", "-", ".",
        ]), { mode: 0o600, flag: "wx" });
      await writeFile(join(backup, "issuer.dump"), transfer([
        "exec", db, "pg_dump", "-U", "credworks", "-Fc", "partner_issuer",
      ]), { mode: 0o600, flag: "wx" });
      for (const name of ["issuer.json", "verifier.json"])
        await writeFile(join(backup, name), await readFile(join(configDir, name)), { mode: 0o600, flag: "wx" });
      const hashes = {};
      for (const name of ["issuer.tar", "verifier.tar", "issuer.dump", "issuer.json", "verifier.json"])
        hashes[name] = createHash("sha256").update(await readFile(join(backup, name))).digest("hex");
      await writeFile(join(backup, "manifest.json"), JSON.stringify({ source, image, imageId: docker("image", "inspect", "--format", "{{.Id}}", image), hashes }), { mode: 0o600, flag: "wx" });

      for (const [name, , destinationVolume] of archives) {
        assert.equal(docker("volume", "ls", "--filter", `name=^${destinationVolume}$`, "--format", "{{.Name}}"), "");
        docker("volume", "create", destinationVolume);
        transfer([
          "run", "--rm", "-i", "--read-only", "--user", "10001:10001",
          "--cap-drop", "ALL", "--mount", `type=volume,src=${destinationVolume},dst=/state`,
          "--entrypoint", "tar", image, "-C", "/state", "-xf", "-",
        ], await readFile(join(backup, name)));
      }
      docker("exec", db, "createdb", "-U", "credworks", "partner_restored");
      transfer([
        "exec", "-i", db, "pg_restore", "-U", "credworks", "--single-transaction", "--exit-on-error", "-d", "partner_restored",
      ], await readFile(join(backup, "issuer.dump")));
      config.databaseUrl = databaseUrl.replace("/partner_issuer", "/partner_restored");
      await writeFile(join(configDir, "issuer.json"), JSON.stringify(config));
      mounts[1] = `type=volume,src=${restoredIdentityVolume},dst=/state`;
      verifierMounts[1] = `type=volume,src=${restoredVerifierVolume},dst=/state`;
      if (upgradeImage) {
        const upgradeSource = docker("image", "inspect", "--format", '{{index .Config.Labels "org.opencontainers.image.revision"}}', upgradeImage);
        assert.match(upgradeSource, /^[0-9a-f]{40}$/);
        assert.equal(upgradeSource, process.env.PARTNER_RECOVERY_UPGRADE_SOURCE_REVISION);
        const upgradeId = docker("image", "inspect", "--format", "{{.Id}}", upgradeImage);
        assert.notEqual(upgradeId, docker("image", "inspect", "--format", "{{.Id}}", image), "upgrade requires a distinct pinned image");
        runningImage = upgradeImage;
        await writeFile(join(backup, "upgrade.json"), JSON.stringify({ source: upgradeSource, image: upgradeImage, imageId: upgradeId }), { mode: 0o600, flag: "wx" });
      } else {
        assert.equal(process.env.PARTNER_RECOVERY_UPGRADE_SOURCE_REVISION, undefined);
      }
      docker("run", "--rm", "--network", network, "--entrypoint", "node", "-e",
        "PARTNER_ISSUER_DATABASE_URL=" + config.databaseUrl, runningImage, "--import", "tsx", "src/issuer-migrate.ts");
      docker("rm", runtime, verifier);
      start();
      assert.deepEqual(await ready(), did);
      // Restore must retain the negative before any live revoked list can recreate it.
      await writeFile(join(registryDir, "status-override.jwt"), signedStatus);
      assert.deepEqual(await launchVerifier(), verifierDid);
      assert.equal((await redeem()).status, 400);
      const restoredReceipt = await receive();
      assert.equal(restoredReceipt.status, 200);
      assert.equal((await restoredReceipt.json()).credentials[0].credential, compact);
      assert.deepEqual(management(lifecyclePath, { state: "revoked" }).body, retired.body);
      assert.equal((await verifyCredential(compact)).result.body.error.code, "STATUS_CHECK_FAILED");
      assert.equal((await verifyCredential(unaffectedCompact)).result.body.status, "verified");
      for (const pair of renewalPairs) {
        const state = await renewalPost(pair.receipt.status_uri);
        assert.deepEqual(state, pair.state);
        const retry = management("/management/issuer/renewals", pair.input, runtime, "", pair.correlation);
        assert.deepEqual(retry, { ...pair.proposal, body: { ...pair.proposal.body, status: pair.state.status } });
        const repeatedSuccessor = await pair.successor.receive();
        assert.equal(repeatedSuccessor.status, pair.confirm ? 409 : 200);
        if (pair.confirm)
          assert.deepEqual(await repeatedSuccessor.json(), { error: "issuer_renewal_conflict" });
        else
          assert.deepEqual(await repeatedSuccessor.json(), pair.successorBody);
        assert.equal((await verifyCredential(pair.successorBody.credentials[0].credential)).result.body.status, "verified");
        assert.equal((await pair.successor.redeem()).status, 400);
        const priorState = JSON.parse(docker("exec", runtime, "node", "--input-type=module", "-e",
          `const response=await fetch('http://127.0.0.1:3081/management/issuer/issuances/${pair.priorId}/status',{headers:{authorization:'Bearer '+process.env.PARTNER_MANAGEMENT_TOKEN}});console.log(JSON.stringify({status:response.status,body:await response.json()}));`));
        assert.equal(priorState.status, 200);
        assert.equal(priorState.body.state, pair.confirm ? "revoked" : "active");
        if (!pair.confirm) {
          const completed = await renewalPost(pair.receipt.confirm_uri, { event: "credential_accepted" });
          assert.equal(completed.status, "completed");
          assert.equal(completed.successor_credential_id, pair.receipt.successor_credential_id);
          assert.equal(completed.predecessor_credential_id, pair.receipt.predecessor_credential_id);
          assert.deepEqual(await renewalPost(pair.receipt.status_uri), completed);
        }
      }
      // The same old active list remains installed throughout restored verification.
      assert.equal((await verifyCredential(compact)).result.body.error.code, "STATUS_CHECK_FAILED");
      assert.equal((await verifyCredential(unaffectedCompact)).result.body.status, "verified");
      const restoredStatus = await (await fetch(publicUrl + "/oid4vci/status/revocation.jwt")).text();
      assert.equal(core.resolveCredentialStatusAt({
        status: verified.processed_payload.credentialStatus,
        resolverResponses: { [origin + "/oid4vci/status/revocation.jwt"]: restoredStatus },
        statusListJwk: identity.publicJwk,
        nowUnixSeconds: now(),
      }).revoked, true);
      // Rotation is exercised after the independent verifier checks: retained-key
      // consumer acceptance is #403, while this check owns complete state restoration.
      const keys = () => JSON.parse(docker("exec", runtime, "node", "--input-type=module", "-e",
        `const r=await fetch('http://127.0.0.1:3081/management/issuer/keys',{headers:{authorization:'Bearer '+process.env.PARTNER_MANAGEMENT_TOKEN}});console.log(JSON.stringify({status:r.status,body:await r.json()}));`));
      const initialKeys = keys();
      assert.equal(initialKeys.status, 200);
      assert.equal(initialKeys.body.selected_key_id, issuerKey);
      const stageInput = { expected_revision: initialKeys.body.revision,
        project_id: crypto.randomUUID(), issuer_registration_id: crypto.randomUUID(),
        expected_registry_revision: 0, key_fragment: "recovered-current" };
      const staged = management("/management/issuer/keys/stage", stageInput);
      assert.equal(staged.status, 201);
      const current = staged.body.credential_keys.find((key) => key.key_id === staged.body.pending.key_id);
      assert.ok(current?.public_jwk);
      const grantTime = now();
      // Explicit synthetic registry evidence, signed by the existing Rust core.
      // Real owner registration/proof/publication is covered by #420's HTTP check.
      const rotatedAuthority = core.signIssuerAuthorizations({
        header: { alg: "ES256", typ: "issuer-authorizations+jwt", kid: registryKey },
        payload: { version: 1, id: registryOrigin + `/issuer-authorizations/${authorizationId}.jwt`,
          issuer: registryDid, iat: grantTime, exp: grantTime + 300,
          authorizations: [
            { key_id: issuerKey, public_jwk: identity.publicJwk, key_state: "retained" },
            { key_id: current.key_id, public_jwk: current.public_jwk, key_state: "current" },
          ].map((key) => ({ credential_issuer_did: identity.did,
            credential_issuer_key_id: key.key_id,
            credential_issuer_public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(key.public_jwk),
            definition, status: "active", key_state: key.key_state,
            status_authority: { key_id: issuerKey, public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(identity.publicJwk) },
          })),
        }, keyId: registryKey,
      });
      await writeFile(join(registryDir, "authority.jwt"), rotatedAuthority);
      const activated = management("/management/issuer/keys/activate", {
        expected_revision: staged.body.revision, key_id: current.key_id });
      assert.equal(activated.status, 200);
      assert.equal(activated.body.selected_key_id, current.key_id);
      const rotatedDid = await ready();
      assert.equal(rotatedDid.id, identity.did);
      const rotatedOffer = await prepareIssuance(undefined, rotatedDid);
      const rotatedResponse = await rotatedOffer.receive();
      assert.equal(rotatedResponse.status, 200);
      const rotatedBody = await rotatedResponse.json();
      const rotatedVerified = core.verifyScalarCredentialAuthorization({
        compactSdJwt: rotatedBody.credentials[0].credential, issuerJwk: current.public_jwk,
        compactAuthorization: rotatedAuthority, trustAnchorJwk: anchor, registryDid,
        nowUnixSeconds: now(), mode: "complete",
      });
      const pending = management("/management/issuer/keys/stage", {
        ...stageInput, expected_revision: activated.body.revision,
        expected_registry_revision: 1, key_fragment: "recovered-pending" });
      assert.equal(pending.status, 201);
      assert.equal(pending.body.pending.phase, "staged");
      assert.equal(pending.body.selected_key_id, current.key_id);
      const pendingDid = await ready();
      assert.equal(pendingDid.id, identity.did);
      docker("stop", runtime);
      // Capture another consistent whole issuer generation, including both sealed
      // credential keys. Existing original and first-restored resources stay intact.
      const rotatedArchive = transfer(["run", "--rm", "--read-only", "--user", "10001:10001",
        "--cap-drop", "ALL", "--mount", `type=volume,src=${restoredIdentityVolume},dst=/state,readonly`,
        "--entrypoint", "tar", runningImage, "-C", "/state", "-cf", "-", "."]);
      const rotatedDump = transfer(["exec", db, "pg_dump", "-U", "credworks", "-Fc", "partner_restored"]);
      await writeFile(join(backup, "rotated-issuer.tar"), rotatedArchive, { mode: 0o600, flag: "wx" });
      await writeFile(join(backup, "rotated-issuer.dump"), rotatedDump, { mode: 0o600, flag: "wx" });
      const rotatedConfig = await readFile(join(configDir, "issuer.json"));
      await writeFile(join(backup, "rotated-issuer.json"), rotatedConfig, { mode: 0o600, flag: "wx" });
      await writeFile(join(backup, "rotated-manifest.json"), JSON.stringify({
        image: runningImage, imageId: docker("image", "inspect", "--format", "{{.Id}}", runningImage),
        source: docker("image", "inspect", "--format", '{{index .Config.Labels "org.opencontainers.image.revision"}}', runningImage),
        keys: pending.body,
        hashes: Object.fromEntries([["rotated-issuer.tar", rotatedArchive], ["rotated-issuer.dump", rotatedDump],
          ["rotated-issuer.json", rotatedConfig]].map(([name, bytes]) => [name, createHash("sha256").update(bytes).digest("hex")])),
      }), { mode: 0o600, flag: "wx" });
      assert.equal(docker("volume", "ls", "--filter", `name=^${rotatedIdentityVolume}$`, "--format", "{{.Name}}"), "");
      docker("volume", "create", rotatedIdentityVolume);
      transfer(["run", "--rm", "-i", "--read-only", "--user", "10001:10001", "--cap-drop", "ALL",
        "--mount", `type=volume,src=${rotatedIdentityVolume},dst=/state`, "--entrypoint", "tar",
        runningImage, "-C", "/state", "-xf", "-"], rotatedArchive);
      docker("exec", db, "createdb", "-U", "credworks", "partner_rotated_restore");
      transfer(["exec", "-i", db, "pg_restore", "-U", "credworks", "--single-transaction", "--exit-on-error",
        "-d", "partner_rotated_restore"], rotatedDump);
      config.databaseUrl = databaseUrl.replace("/partner_issuer", "/partner_rotated_restore");
      await writeFile(join(configDir, "issuer.json"), JSON.stringify(config));
      mounts[1] = `type=volume,src=${rotatedIdentityVolume},dst=/state`;
      docker("rm", runtime);
      start();
      assert.deepEqual(await ready(), pendingDid);
      assert.deepEqual(keys(), { status: 200, body: pending.body });
      const recoveredOldReceipt = await receive();
      assert.equal(recoveredOldReceipt.status, 200);
      assert.equal((await recoveredOldReceipt.json()).credentials[0].credential, compact);
      const recoveredNewReceipt = await rotatedOffer.receive();
      assert.equal(recoveredNewReceipt.status, 200);
      assert.deepEqual(await recoveredNewReceipt.json(), rotatedBody);
      assert.equal((await redeem()).status, 400);
      assert.equal((await rotatedOffer.redeem()).status, 400);
      assert.deepEqual(management(lifecyclePath, { state: "revoked" }).body, retired.body);
      for (const pair of renewalPairs)
        assert.equal((await renewalPost(pair.receipt.status_uri)).status, "completed");
      const paused = management("/management/issuer/offers", {
        configuration_id: "entitlement", claims: { enabled: true }, valid_from: now(),
        valid_until: now() + 600, offer_expires_at: now() + 120,
        recipient_jwk_thumbprint: core.publicJwkSha256Thumbprint(holder) });
      assert.equal(paused.status, 409);
      assert.equal(paused.body.error.code, "ISSUER_KEY_STAGING");
      const preservedList = await (await fetch(publicUrl + "/oid4vci/status/revocation.jwt")).text();
      for (const [credential, revoked] of [[verified, true], [rotatedVerified, false]])
        assert.equal(core.resolveCredentialStatusAt({
          status: credential.processed_payload.credentialStatus,
          resolverResponses: { [origin + "/oid4vci/status/revocation.jwt"]: preservedList },
          statusListJwk: identity.publicJwk, nowUnixSeconds: now(),
        }).revoked, revoked);
      docker("stop", runtime, verifier);
      // Faults apply only to the fresh restored resources, never the originals.
      const missingKeyPath = "/state/identity/credential-keys/" + core.sha256B64Url(current.key_id) + ".sealed";
      docker("run", "--rm", "--mount", `type=volume,src=${rotatedIdentityVolume},dst=/state`,
        "--entrypoint", "node", runningImage, "-e", `require('node:fs').unlinkSync(${JSON.stringify(missingKeyPath)})`);
      assert.throws(() => docker(
        "run", "--rm", "--name", refusedRestore, "--network", network,
        ...env, ...mounts, runningImage, "start",
      ), /partner_identity_unavailable/);
      docker("run", "--rm", "--mount", `type=volume,src=${rotatedIdentityVolume},dst=/state,readonly`,
        "--entrypoint", "node", runningImage, "-e", `if(require('node:fs').existsSync(${JSON.stringify(missingKeyPath)}))process.exit(1)`);
      // Restore the exact captured key generation before independent refusal checks.
      transfer(["run", "--rm", "-i", "--read-only", "--user", "10001:10001", "--cap-drop", "ALL",
        "--mount", `type=volume,src=${rotatedIdentityVolume},dst=/state`, "--entrypoint", "tar",
        runningImage, "-C", "/state", "-xf", "-"], rotatedArchive);
      docker("start", runtime);
      assert.deepEqual(await ready(), pendingDid);
      assert.deepEqual(keys(), { status: 200, body: pending.body });
      docker("stop", runtime);
      assert.throws(() => docker(
        "run", "--rm", "--name", refusedRestore, "--network", network,
        ...env, "-e", "PARTNER_UNLOCK_KEY=" + core.randomUrlSafe(32), ...mounts, runningImage, "start",
      ), /partner_identity_unavailable/);
      assert.throws(() => docker(
        "run", "--rm", "--name", refusedRestore, "--network", network,
        ...env, "-e", "PARTNER_ORIGIN=https://changed.example", ...mounts, runningImage, "start",
      ), /partner_identity_unavailable/);
      // An initialized manifest without its signed inventory must not become empty.
      docker("run", "--rm", "--mount", `type=volume,src=${restoredVerifierVolume},dst=/state`,
        "--entrypoint", "node", runningImage, "-e", "require('node:fs').unlinkSync('/state/identity/revocation-proofs/inventory.jwt')");
      assert.throws(() => docker(
        "run", "--rm", "--name", refusedRestore, "--network", network,
        ...verifierEnv, "-e", "PARTNER_VERIFIER_CONFIG=/config/verifier.json",
        ...verifierMounts, runningImage, "start",
      ), /partner_identity_unavailable/);
      docker("run", "--rm", "--mount", `type=volume,src=${restoredVerifierVolume},dst=/state,readonly`,
        "--entrypoint", "node", runningImage, "-e", "if(require('node:fs').existsSync('/state/identity/revocation-proofs/inventory.jwt'))process.exit(1)");
      // Corruption is fixture setup only; the assertion observes normal CLI startup.
      docker(
        "exec",
        db,
        "psql",
        "-U",
        "credworks",
        "-d",
        "partner_rotated_restore",
        "-c",
        "DELETE FROM partner_issuer_status",
      );
      assert.throws(
        () =>
          docker(
            "run",
            "--rm",
            "--network",
            network,
            ...env,
            ...mounts,
            runningImage,
            "start",
          ),
        /partner_identity_unavailable/,
      );
    } finally {
      try {
        compose("down");
      } catch {}
      for (const name of [refusedRestore, verifier, runtime, registry, db]) {
        try {
          docker("rm", "-f", name);
        } catch {}
      }
      for (const volume of [rotatedIdentityVolume, restoredVerifierVolume, restoredIdentityVolume, verifierVolume, identityVolume, databaseVolume]) {
        try {
          docker("volume", "rm", volume);
        } catch {}
      }
      try {
        docker("network", "rm", network);
      } catch {}
      await rm(root, { recursive: true, force: true });
    }
  },
);
