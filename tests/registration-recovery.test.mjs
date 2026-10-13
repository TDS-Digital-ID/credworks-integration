import { test } from "node:test";
import { randomUUID } from "node:crypto";
import assert from "node:assert/strict";
import { createServer as httpsServer } from "node:https";
import { createServer as httpServer } from "node:http";
import { spawn, execFileSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  statSync,
  rmSync,
  rmdirSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as core from "@unsw-vc/identity-core-node";

async function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "registration-recovery-"));
  const projectId = "11111111-1111-4111-8111-111111111111";
  let registrationId = "33333333-3333-4333-8333-333333333333";
  const token = "cw_project_" + "a".repeat(43);
  const calls = [];
  const behavior = { permission: false };
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      join(dir, "tls.key"),
      "-out",
      join(dir, "tls.pem"),
      "-days",
      "1",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost",
      "-addext",
      "extendedKeyUsage=serverAuth",
    ],
    { stdio: "ignore" },
  );
  let config,
    key,
    registration,
    completed = false;
  const handler = async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    calls.push(req.method + " " + req.url);
    if (behavior.pauseAt?.(req)) await behavior.paused();
    const send = (status, value) => {
      res.statusCode = status;
      res.end(typeof value === "string" ? value : JSON.stringify(value));
    };
    if (req.url === "/.well-known/did.json")
      return send(
        200,
        core.buildDidWebDocument(registration.verifier_did, [key]),
      );
    if (req.url === "/api/projects" && req.method === "POST") {
      if (behavior.pauseProject) await behavior.pauseProject();
      if (behavior.lose === "project") return req.socket.destroy();
      return send(201, {
        project: { project_id: projectId },
        management_credential: token,
      });
    }
    if (req.url.startsWith("/api/projects/")) {
      assert.equal(req.headers.authorization, "Bearer " + token);
      if (behavior.authDenied && req.method === "GET")
        return send(401, { error: { code: token } });
      if (req.method === "GET" && req.url === "/api/projects/" + projectId)
        return send(200, { project: { project_id: projectId } });
      if (req.method === "GET") {
        assert.equal(
          req.url,
          `/api/projects/${projectId}/verifiers/${registrationId}`,
        );
        return send(
          completed && !behavior.registrationUnavailable ? 200 : 503,
          completed
            ? {
                ...registration,
                ...(behavior.registrationMismatch
                  ? { key_id: "did:web:other.example#key" }
                  : {}),
              }
            : {},
        );
      }
      if (req.url.endsWith("/challenges")) {
        if (behavior.lose === "challenge") return req.socket.destroy();
        registrationId = randomUUID();
        registration.registration_id = registrationId;
        return send(201, {
          challenge_id: registrationId,
          nonce: "nonce",
          audience:
            config.registryOrigin +
            req.url +
            "/" +
            registrationId +
            "/complete",
          expires_at: new Date(
            Date.now() + (behavior.expiring ? 1 : 120000),
          ).toISOString(),
        });
      }
      if (behavior.lose === "completion-before-commit")
        return req.socket.destroy();
      completed = true;
      if (behavior.lose === "completion") return req.socket.destroy();
      return send(201, registration);
    }
    if (req.url === "/management/sign") {
      if (behavior.signUnavailable) return send(503, {});
      assert.equal(
        req.headers.authorization,
        "Bearer " + config.managementToken,
      );
      return send(200, { jwt: "opaque-proof-from-runtime" });
    }
    if (req.url.startsWith("/scoped-verifier-permissions.jwt")) {
      if (!behavior.permission) return send(503, {});
      const iat = Math.floor(Date.now() / 1000);
      return send(
        200,
        core.signScopedVerifierPermissions({
          keyId: config.registryDid + "#anchor",
          header: {
            alg: "ES256",
            typ: "scoped-verifier-permissions+jwt",
            kid: config.registryDid + "#anchor",
          },
          payload: {
            version: 1,
            id: config.registryOrigin + req.url,
            issuer: config.registryDid,
            iat,
            exp: iat + 300,
            permissions: ["education_eligibility", "education_sign_in"].map(
              (profile) => ({
                credential_issuer_did: config.educationIssuerDid,
                definition_id: "urn:credworks:education",
                definition_version: "1",
                credential_type: "UniversityEducationCredential",
                verifier_did: registration.verifier_did,
                verifier_origin: config.runtimeOrigin,
                verifier_public_jwk_sha256_thumbprint:
                  core.publicJwkSha256Thumbprint(key),
                profile_name: profile,
                claim_paths: [
                  "enrolled",
                  "institution_id",
                  ...(profile === "education_sign_in" ? ["student_id"] : []),
                ].map((f) => ["credentialSubject", f]),
                status: "active",
              }),
            ),
          },
        }),
      );
    }
    send(404, {});
  };
  const server = httpsServer(
    {
      key: readFileSync(join(dir, "tls.key")),
      cert: readFileSync(join(dir, "tls.pem")),
    },
    handler,
  );
  const management = httpServer(handler);
  await Promise.all([
    new Promise((r) => server.listen(0, "127.0.0.1", r)),
    new Promise((r) => management.listen(0, "127.0.0.1", r)),
  ]);
  const origin = "https://localhost:" + server.address().port;
  const did = core.didWebFromHost(new URL(origin).host);
  key = core.persistentSigningKey({
    path: join(dir, "runtime.key"),
    unlockKey: core.randomUrlSafe(32),
    keyId: did + "#key",
    create: true,
  });
  const anchor = core.persistentSigningKey({
    path: join(dir, "anchor.key"),
    unlockKey: core.randomUrlSafe(32),
    keyId: did + "#anchor",
    create: true,
  });
  config = {
    registryOrigin: origin,
    registryDid: did,
    trustAnchorJwk: anchor,
    educationIssuerDid: "did:web:education.example",
    runtimeOrigin: origin,
    managementOrigin: "http://127.0.0.1:" + management.address().port,
    managementToken: "private-runtime-token",
  };
  registration = {
    registration_id: registrationId,
    project_id: projectId,
    verifier_did: did,
    verifier_origin: origin,
    key_id: did + "#key",
    public_jwk: key,
    revision: 0,
    withdrawn_at: null,
    profiles: ["education_eligibility", "education_sign_in"],
  };
  const configPath = join(dir, "config.json"),
    statePath = join(dir, "registration.json");
  writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  const start = () => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "tool/register-verifier.ts", configPath, statePath],
      { env: { ...process.env, NODE_EXTRA_CA_CERTS: join(dir, "tls.pem") } },
    );
    const result = new Promise((resolve, reject) => {
      let output = "";
      child.stdout.on("data", (d) => (output += d));
      child.stderr.on("data", (d) => (output += d));
      child.on("error", reject);
      child.on("exit", (code) => resolve({ code, output }));
    });
    return { child, result };
  };
  const run = () => start().result;
  t.after(async () => {
    await Promise.all([
      new Promise((r) => server.close(r)),
      new Promise((r) => management.close(r)),
    ]);
    rmSync(dir, { recursive: true, force: true });
  });
  return { run, start, calls, behavior, statePath, token, config, configPath };
}

test("registration keeps the received project credential and resumes after signed permission retrieval fails", async (t) => {
  const f = await fixture(t);
  assert.equal((await f.run()).code, 1);
  const saved = JSON.parse(readFileSync(f.statePath, "utf8"));
  assert.equal(saved.management_credential, f.token);
  assert.equal(statSync(f.statePath).mode & 0o777, 0o600);
  f.behavior.permission = true;
  const retry = await f.run();
  assert.equal(retry.code, 0, retry.output);
  assert.equal(f.calls.filter((c) => c === "POST /api/projects").length, 1);
  assert.equal(f.calls.filter((c) => c.endsWith("/challenges")).length, 1);
  assert.equal(f.calls.filter((c) => c.endsWith("/complete")).length, 1);
  assert(
    f.calls.some(
      (c) => c.startsWith("GET /api/projects/") && c.includes("/verifiers/"),
    ),
  );
  assert(!retry.output.includes(f.token));
});

for (const [step, code] of [
  ["project", "PROJECT"],
  ["challenge", "CHALLENGE"],
]) {
  test(`lost ${step} response stops with a precise recovery instruction and never creates a replacement`, async (t) => {
    const f = await fixture(t);
    f.behavior.lose = step;
    const first = await f.run();
    assert.equal(first.code, 1);
    assert.match(
      first.output,
      new RegExp("REGISTRATION_" + code + "_OUTCOME_UNKNOWN"),
    );
    f.behavior.lose = undefined;
    const retry = await f.run();
    assert.equal(retry.code, 1);
    assert.match(
      retry.output,
      new RegExp("REGISTRATION_" + code + "_OUTCOME_UNKNOWN"),
    );
    assert.equal(f.calls.filter((c) => c === "POST /api/projects").length, 1);
    assert.equal(
      f.calls.filter((c) => c.endsWith("/challenges")).length,
      step === "project" ? 0 : 1,
    );
    assert.equal(
      f.calls.filter((c) => c.endsWith("/complete")).length,
      step === "completion" ? 1 : 0,
    );
    assert(!first.output.includes(f.token));
  });
}

test("expired known challenges renew without losing the project or replacing the runtime key", async (t) => {
  const f = await fixture(t);
  f.behavior.expiring = true;
  f.behavior.signUnavailable = true;
  assert.equal((await f.run()).code, 1);
  f.behavior.expiring = false;
  f.behavior.signUnavailable = false;
  f.behavior.permission = true;
  const retry = await f.run();
  assert.equal(retry.code, 0, retry.output);
  assert.equal(f.calls.filter((c) => c === "POST /api/projects").length, 1);
  assert.equal(f.calls.filter((c) => c.endsWith("/challenges")).length, 2);
  assert.equal(f.calls.filter((c) => c.endsWith("/complete")).length, 1);
});

test("a concurrent registration refuses before network work; a changed origin cannot reuse saved credentials", async (t) => {
  const f = await fixture(t);
  let entered, release;
  const waiting = new Promise((resolve) => {
    entered = resolve;
  });
  const paused = new Promise((resolve) => {
    release = resolve;
  });
  f.behavior.pauseProject = () => {
    entered();
    return paused;
  };
  const first = f.run();
  await waiting;
  const second = await f.run();
  assert.equal(second.code, 1);
  assert.match(second.output, /REGISTRATION_BUSY/);
  assert.equal(f.calls.filter((c) => c === "POST /api/projects").length, 1);
  release();
  await first;
  const count = f.calls.length;
  writeFileSync(
    f.configPath,
    JSON.stringify({ ...f.config, runtimeOrigin: "https://different.example" }),
  );
  const mismatch = await f.run();
  assert.equal(mismatch.code, 1);
  assert.match(mismatch.output, /REGISTRATION_STATE_REFUSED/);
  assert.equal(f.calls.length, count);
  assert.equal(
    JSON.parse(readFileSync(f.statePath, "utf8")).management_credential,
    f.token,
  );
});

for (const stage of [
  "before-credential",
  "after-credential",
  "after-completion",
  "before-permissions",
]) {
  test(`process interruption ${stage} preserves progress and requires stale-lock confirmation`, async (t) => {
    const f = await fixture(t);
    let entered, release;
    const waiting = new Promise((resolve) => {
      entered = resolve;
    });
    const paused = new Promise((resolve) => {
      release = resolve;
    });
    f.behavior.pauseAt = (req) =>
      stage === "before-credential"
        ? req.url === "/api/projects"
        : stage === "after-credential"
          ? req.method === "GET" &&
            req.url.startsWith("/api/projects/") &&
            !req.url.includes("/verifiers/")
          : stage === "after-completion"
            ? req.method === "GET" && req.url.includes("/verifiers/")
            : req.url.startsWith("/scoped-verifier-permissions.jwt");
    f.behavior.paused = () => {
      entered();
      return paused;
    };
    const running = f.start();
    await waiting;
    running.child.kill("SIGKILL");
    await running.result;
    release();
    f.behavior.pauseAt = undefined;
    f.behavior.permission = true;
    assert.match((await f.run()).output, /REGISTRATION_BUSY/);
    // The operator has confirmed the original process exited before removing its lock.
    rmdirSync(f.statePath + ".lock");
    const retry = await f.run();
    if (stage === "before-credential")
      assert.match(retry.output, /REGISTRATION_PROJECT_OUTCOME_UNKNOWN/);
    else assert.equal(retry.code, 0, retry.output);
    assert.equal(f.calls.filter((c) => c === "POST /api/projects").length, 1);
    assert.equal(
      f.calls.filter((c) => c.endsWith("/complete")).length,
      stage === "before-credential" ? 0 : 1,
    );
  });
}

test("an exposed state file is refused without network requests or overwriting its credential", async (t) => {
  const f = await fixture(t);
  await f.run();
  const saved = readFileSync(f.statePath, "utf8"),
    count = f.calls.length;
  chmodSync(f.statePath, 0o644);
  const retry = await f.run();
  assert.equal(retry.code, 1);
  assert.match(retry.output, /REGISTRATION_STATE_REFUSED/);
  assert.equal(readFileSync(f.statePath, "utf8"), saved);
  assert.equal(f.calls.length, count);
});

test("an interrupted pending write is preserved and reported before attempting any HTTP recovery", async (t) => {
  const f = await fixture(t);
  await f.run();
  const pending = f.statePath + ".pending";
  writeFileSync(pending, "protected interrupted journal", { mode: 0o600 });
  const count = f.calls.length;
  const retry = await f.run();
  assert.equal(retry.code, 1);
  assert.match(retry.output, /REGISTRATION_STORAGE_REFUSED/);
  assert.equal(f.calls.length, count);
  assert.equal(readFileSync(pending, "utf8"), "protected interrupted journal");
});

test("retry requires authenticated registry state and suppresses response diagnostics", async (t) => {
  const f = await fixture(t);
  await f.run();
  const saved = readFileSync(f.statePath, "utf8");
  f.behavior.permission = true;
  f.behavior.authDenied = true;
  const denied = await f.run();
  assert.equal(denied.code, 1);
  assert(!denied.output.includes(f.token));
  assert(!denied.output.includes(f.config.managementToken));
  assert.equal(readFileSync(f.statePath, "utf8"), saved);
  assert.equal(f.calls.filter((c) => c.endsWith("/complete")).length, 1);
  f.behavior.authDenied = false;
  assert.equal((await f.run()).code, 0);
});

for (const journal of ["null", "false", "0", '""', "[]"]) {
  test(`existing non-object journal ${journal} is preserved without HTTP requests`, async (t) => {
    const f = await fixture(t);
    writeFileSync(f.statePath, journal, { mode: 0o600 });
    const result = await f.run();
    assert.equal(result.code, 1);
    assert.match(result.output, /REGISTRATION_STATE_REFUSED/);
    assert.equal(readFileSync(f.statePath, "utf8"), journal);
    assert.deepEqual(f.calls, []);
  });
}

test("a lost completion response recovers the original registration through authenticated HTTP", async (t) => {
  const f = await fixture(t);
  f.behavior.lose = "completion";
  f.behavior.permission = true;
  const result = await f.run();
  assert.equal(result.code, 0, result.output);
  assert.equal(f.calls.filter((c) => c.endsWith("/complete")).length, 1);
  assert.equal(f.calls.filter((c) => c === "POST /api/projects").length, 1);
  assert.equal((await f.run()).code, 0);
  assert.equal(f.calls.filter((c) => c.endsWith("/complete")).length, 1);
});

for (const lose of ["completion", "completion-before-commit"]) {
  test(`ambiguous ${lose} remains stopped until authenticated registration is available`, async (t) => {
    const f = await fixture(t);
    f.behavior.lose = lose;
    f.behavior.registrationUnavailable = true;
    f.behavior.permission = true;
    assert.match(
      (await f.run()).output,
      /REGISTRATION_COMPLETION_OUTCOME_UNKNOWN/,
    );
    assert.match(
      (await f.run()).output,
      /REGISTRATION_COMPLETION_OUTCOME_UNKNOWN/,
    );
    f.behavior.registrationUnavailable = false;
    const result = await f.run();
    if (lose === "completion") assert.equal(result.code, 0, result.output);
    else assert.match(result.output, /REGISTRATION_COMPLETION_OUTCOME_UNKNOWN/);
    assert.equal(f.calls.filter((c) => c.endsWith("/complete")).length, 1);
    assert.equal(f.calls.filter((c) => c === "POST /api/projects").length, 1);
  });
}

test("recovered registration must match the original identity before progress is trusted", async (t) => {
  const f = await fixture(t);
  f.behavior.lose = "completion";
  f.behavior.permission = true;
  f.behavior.registrationMismatch = true;
  assert.match((await f.run()).output, /REGISTRATION_STATE_REFUSED/);
  assert.equal(
    JSON.parse(readFileSync(f.statePath, "utf8")).phase,
    "completing",
  );
  f.behavior.registrationMismatch = false;
  assert.equal((await f.run()).code, 0);
  assert.equal(f.calls.filter((c) => c.endsWith("/complete")).length, 1);
});
