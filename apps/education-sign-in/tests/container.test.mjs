import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
const image = process.env.EDUCATION_APP_CONTAINER_IMAGE,
  partner = process.env.PARTNER_CONTAINER_IMAGE,
  database = process.env.EDUCATION_APP_DATABASE_URL;
test(
  "Compose serves the packaged app with isolated management and app-local migrations",
  { skip: !image || !partner, timeout: 180000 },
  async () => {
    const suffix = randomBytes(8).toString("hex"),
      project = "vc336-" + suffix,
      dir = mkdtempSync(join(tmpdir(), "vc336-compose-"));
    const base = Number(process.env.EDUCATION_APP_HTTP_PORT ?? 33600);
    const password = randomBytes(32).toString("base64url");
    const env = {
      ...process.env,
      PARTNER_IMAGE: partner,
      EDUCATION_APP_IMAGE: image,
      PARTNER_ORIGIN: `https://compose${suffix}.example`,
      PARTNER_UNLOCK_KEY: randomBytes(32).toString("base64url"),
      PARTNER_MANAGEMENT_TOKEN: randomBytes(32).toString("base64url"),
      PARTNER_CONFIG_DIR: dir,
      PARTNER_VERIFIER_CONFIG: "",
      PARTNER_HOST_PORT: String(base + 10),
      EDUCATION_APP_HOST_PORT: String(base + 11),
      EDUCATION_APP_ORIGIN: "https://app.example",
      EDUCATION_TRUSTED_ISSUER: "did:web:issuer.example",
      EDUCATION_VERIFIER_DID: `did:web:compose${suffix}.example`,
      EDUCATION_INSTITUTION: "unsw.edu.au",
      EDUCATION_APP_DATABASE_URL: database
        ? database.replace("127.0.0.1", "host.docker.internal")
        : `postgres://education:${password}@database:5432/education`,
      EDUCATION_DB_PASSWORD: password,
    };
    const compose = (...args) =>
      execFileSync(
        "docker",
        [
          "compose",
          ...(!database ? ["--profile", "local-db"] : []),
          "-f",
          fileURLToPath(
            new URL(
              "../../../infra/education-sign-in/compose.yml",
              import.meta.url,
            ),
          ),
          "-p",
          project,
          ...args,
        ],
        {
          env,
          encoding: "utf8",
          timeout: 60000,
          stdio: ["ignore", "pipe", "pipe"],
        },
      ).trim();
    try {
      const config = JSON.parse(compose("config", "--format", "json"));
      assert.equal(config.services.application.network_mode, "service:partner");
      assert.equal(config.services.application.ports, undefined);
      assert.equal(
        config.services.partner.ports.some((port) => port.target === 3081),
        false,
      );
      const identity = JSON.parse(
        compose("run", "--rm", "partner", "bootstrap"),
      );
      assert.equal(identity.did, env.EDUCATION_VERIFIER_DID);
      if (!database) compose("up", "-d", "--wait", "database");
      compose("up", "-d", "partner", "application");
      const session = async () => {
        let response;
        for (let attempt = 0; attempt < 150; attempt++) {
          try {
            response = await fetch(`http://127.0.0.1:${base + 11}/api/session`, {
              signal: AbortSignal.timeout(1000),
            });
            if (response.ok) break;
          } catch {}
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        assert.equal(response?.status, 200);
        return response;
      };
      const response = await session();
      assert.equal((await response.json()).status, "anonymous");
      assert.match(
        response.headers.get("set-cookie"),
        /Secure; HttpOnly; SameSite=Strict/,
      );
      const didUrl = `http://127.0.0.1:${base + 10}/.well-known/did.json`;
      const did = await (await fetch(didUrl)).json();
      const html = await (await fetch(`http://127.0.0.1:${base + 11}/`)).text();
      assert.match(html, /Open CredWorks wallet on Android/);
      assert.match(html, /Synthetic demo/);
      assert.equal(html.includes(env.PARTNER_MANAGEMENT_TOKEN), false);
      assert.equal(html.includes(password), false);
      compose("stop", "application", "partner", ...(!database ? ["database"] : []));
      if (!database) compose("up", "-d", "--wait", "database");
      compose("up", "-d", "partner", "application");
      assert.equal((await (await session()).json()).status, "anonymous");
      assert.deepEqual(await (await fetch(didUrl)).json(), did);
      assert.throws(() => compose("run", "--rm", "partner", "bootstrap"));
      assert.deepEqual(await (await fetch(didUrl)).json(), did);
      assert.equal(
        (
          await fetch(`http://127.0.0.1:${base + 10}/management/sign`, {
            method: "POST",
          })
        ).status,
        404,
      );
      const id = compose("ps", "-q", "partner");
      const ports = JSON.parse(
        execFileSync(
          "docker",
          ["inspect", "--format", "{{json .NetworkSettings.Ports}}", id],
          { encoding: "utf8" },
        ),
      );
      assert.equal(ports["3081/tcp"], undefined);
      const appId = compose("ps", "-q", "application");
      const revision = execFileSync(
        "docker",
        [
          "inspect",
          "--format",
          '{{index .Config.Labels "org.opencontainers.image.revision"}}',
          appId,
        ],
        { encoding: "utf8" },
      ).trim();
      assert.match(revision, /^[0-9a-f]{40}$/);
      if (process.env.EDUCATION_APP_CONTAINER_REVISION)
        assert.equal(revision, process.env.EDUCATION_APP_CONTAINER_REVISION);
    } finally {
      compose("down", "--volumes");
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
