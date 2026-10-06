import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as core from "@unsw-vc/identity-core-node";
const image = process.env.PARTNER_CONTAINER_IMAGE;
const docker = (...args) =>
  execFileSync("docker", args, {
    encoding: "utf8",
    timeout: 30000,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
test(
  "packaged partner excludes demo keys and container replacement preserves protected signing identity",
  { skip: !image, timeout: 120000 },
  async () => {
    const suffix = core.randomUrlSafe(16).toLowerCase().replaceAll("_", "a"),
      volume = "vc387-identity-" + suffix,
      name = "vc387-runtime-" + suffix;
    const origin = "https://container" + suffix + ".example";
    const unlock = core.randomUrlSafe(32),
      token = core.randomUrlSafe(32);
    const env = [
      "-e",
      "PARTNER_ORIGIN=" + origin,
      "-e",
      "PARTNER_STATE_DIR=/state/identity",
      "-e",
      "PARTNER_UNLOCK_KEY=" + unlock,
      "-e",
      "PARTNER_MANAGEMENT_TOKEN=" + token,
    ];
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
    assert.match(
      docker(
        "run",
        "--rm",
        "--entrypoint",
        "node",
        image,
        "--input-type=module",
        "-e",
        `import assert from "node:assert/strict"; import { createRequire } from "node:module"; import { dirname, join } from "node:path"; import { existsSync } from "node:fs"; const require=createRequire(import.meta.url); const nativeDir=join(dirname(dirname(require.resolve("@unsw-vc/identity-core-node"))),"native"); const addon=require(join(nativeDir,"index.cjs")); assert.equal(addon.installDeterministicTestKeyRaw,undefined); assert.equal(addon.installDeterministicTestX509KeyRaw,undefined); assert.equal(typeof addon.persistentSigningKeyRaw,"function"); assert.equal(existsSync("/partner/tool/check-packaged-addon.mjs"),false,"build-only key scanner must not ship"); console.log("excludes fixture exports and build-only checker");`,
      ),
      /excludes fixture exports/,
    );
    docker("volume", "create", volume);
    try {
      const boot = JSON.parse(
        docker(
          "run",
          "--rm",
          ...env,
          "-v",
          volume + ":/state",
          image,
          "bootstrap",
        ),
      );
      async function launch() {
        docker(
          "run",
          "-d",
          "--name",
          name,
          "--cpus",
          "2",
          "--memory",
          "512m",
          "--pids-limit",
          "128",
          "--read-only",
          "--cap-drop",
          "ALL",
          "--security-opt",
          "no-new-privileges",
          "--tmpfs",
          "/tmp:rw,noexec,nosuid,size=32m",
          ...env,
          "-v",
          volume + ":/state",
          "-p",
          "127.0.0.1:38730:3080",
          image,
          "start",
        );
        for (let attempt = 0; attempt < 80; attempt++) {
          try {
            const response = await fetch(
              "http://127.0.0.1:38730/.well-known/did.json",
            );
            if (response.status === 200) return response.json();
          } catch {}
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        throw Error("container readiness deadline");
      }
      const did = await launch();
      assert.equal(did.id, boot.did);
      assert.deepEqual(did.verificationMethod[0].publicKeyJwk, boot.publicJwk);
      assert.equal(
        (
          await fetch("http://127.0.0.1:38730/management/sign", {
            method: "POST",
          })
        ).status,
        404,
      );
      const ports = JSON.parse(
        docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", name),
      );
      assert.equal(ports["3081/tcp"], undefined);
      async function sign() {
        const code = `const response=await fetch('http://127.0.0.1:3081/management/sign',{method:'POST',headers:{authorization:'Bearer '+process.env.PARTNER_MANAGEMENT_TOKEN,'content-type':'application/json'},body:JSON.stringify({nonce:'container-restart-challenge',audience:'https://registry.example/challenges/one'})});if(response.status!==200)process.exit(1);console.log(await response.text());`;
        return JSON.parse(
          docker("exec", name, "node", "--input-type=module", "-e", code),
        ).jwt;
      }
      const verify = (jwt, nowUnixSeconds) =>
        core.verifyPartnerIdentityProof({
          jwt,
          publicJwk: boot.publicJwk,
          options: {
            issuer: boot.did,
            key_id: boot.did + "#key-1",
            audience: "https://registry.example/challenges/one",
            nonce: "container-restart-challenge",
            now_unix_seconds: nowUnixSeconds,
          },
        });
      async function verifySignedProof() {
        const jwt = await sign();
        // Sample the signing environment independently, never infer time from the token.
        const nowUnixSeconds = Number(docker(
          "exec", name, "node", "-e", "console.log(Math.floor(Date.now()/1000))",
        ));
        assert.ok(Number.isSafeInteger(nowUnixSeconds) && nowUnixSeconds > 0);
        verify(jwt, nowUnixSeconds);
        for (const offset of [-61, 60, 61]) {
          assert.throws(
            () => verify(jwt, nowUnixSeconds + offset),
            (error) => /^TRUST_CHECK_FAILED(?:\b|:)/.test(error.message),
          );
        }
      }
      await verifySignedProof();
      docker("rm", "-f", name);
      assert.deepEqual(await launch(), did);
      await verifySignedProof();
      docker("rm", "-f", name);
      assert.throws(
        () => docker("run", "--rm", ...env, image, "start"),
        (error) =>
          error.status !== 0 &&
          String(error.stderr).includes("partner_identity_unavailable"),
      );
      assert.throws(
        () =>
          docker(
            "run",
            "--rm",
            ...env,
            "-v",
            volume + ":/state",
            image,
            "bootstrap",
          ),
        (error) =>
          error.status !== 0 &&
          String(error.stderr).includes("partner_identity_unavailable"),
      );
    } finally {
      try {
        docker("rm", "-f", name);
      } catch {}
      docker("volume", "rm", volume);
    }
  },
);


test(
  "actual Compose configuration bootstraps and starts the preserved partner identity",
  { skip: !image, timeout: 120000 },
  async () => {
    const project = "vc387-compose-" + core.randomUrlSafe(16).toLowerCase().replaceAll("_", "a");
    const environment = {
      ...process.env,
      PARTNER_IMAGE: image,
      PARTNER_ORIGIN: "https://" + project + ".example",
      PARTNER_UNLOCK_KEY: core.randomUrlSafe(32),
      PARTNER_MANAGEMENT_TOKEN: core.randomUrlSafe(32),
      PARTNER_CONFIG_DIR: fileURLToPath(new URL("../examples/", import.meta.url)),
      PARTNER_VERIFIER_CONFIG: "",
      PARTNER_HOST_PORT: "38731",
    };
    const compose = (...args) => execFileSync("docker", [
      "compose", "-f", fileURLToPath(new URL("../../../infra/partner/compose.yml", import.meta.url)),
      "-p", project, ...args,
    ], { env: environment, encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] }).trim();
    const config = JSON.parse(compose("config", "--format", "json"));
    assert.deepEqual(config.services.partner.tmpfs, ["/tmp:rw,noexec,nosuid,size=32m"]);
    try {
      const identity = JSON.parse(compose("run", "--rm", "partner", "bootstrap"));
      compose("up", "-d", "partner");
      let document;
      for (let attempt = 0; attempt < 80; attempt++) {
        try {
          const response = await fetch("http://127.0.0.1:38731/.well-known/did.json");
          if (response.status === 200) { document = await response.json(); break; }
        } catch {}
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.equal(document?.id, identity.did, "Compose service readiness and identity");
      assert.deepEqual(document.verificationMethod[0].publicKeyJwk, identity.publicJwk);
      assert.equal((await fetch("http://127.0.0.1:38731/management/sign", { method: "POST" })).status, 404);
    } finally {
      compose("down", "--volumes");
    }
  },
);
