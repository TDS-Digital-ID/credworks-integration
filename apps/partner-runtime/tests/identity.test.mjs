import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile, writeFile, chmod, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { once } from "node:events";
import { verifyCompactJwsJson } from "@unsw-vc/identity-core-node";

function run(command, env) {
  const child = spawn(
    process.execPath,
    ["--import", "tsx", "src/cli.ts", command],
    { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout.on("data", (data) => {
    output += data;
  });
  child.stderr.on("data", (data) => {
    output += data;
  });
  return { child, output: () => output };
}
async function boot(env) {
  const proc = run("start", env);
  for (let attempt = 0; attempt < 100; attempt++) {
    const match = proc.output().match(/READY (.+)/);
    if (match) return { ...proc, addresses: JSON.parse(match[1]) };
    if (proc.child.exitCode !== null) throw Error(proc.output());
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  proc.child.kill();
  throw Error("runtime did not start");
}
async function stop(proc) {
  proc.child.kill();
  await once(proc.child, "exit");
}

for (const name of ["PARTNER_ISSUER_CONFIG", "PARTNER_VERIFIER_CONFIG"])
  for (const linked of [false, true])
    test(`${name} refuses ${linked ? "symlinked " : ""}FIFO configuration without hanging startup`, async () => {
      const root = await mkdtemp(join(tmpdir(), "partner-347-config-"));
      const fifo = join(root, "config.fifo");
      const path = linked ? join(root, "config.json") : fifo;
      const env = {
        PARTNER_ORIGIN: "https://partner.example",
        PARTNER_STATE_DIR: join(root, "identity"),
        PARTNER_UNLOCK_KEY: "JSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSU",
        PARTNER_MANAGEMENT_TOKEN: "management-secret-with-32-characters",
        [name]: path,
      };
      try {
        execFileSync("mkfifo", [fifo]);
        if (linked) await symlink(fifo, path);
        const proc = run("start", env);
        const timeout = setTimeout(() => proc.child.kill("SIGKILL"), 3000);
        try {
          const [code, signal] = await once(proc.child, "exit");
          assert.equal(signal, null, "configuration read hung startup");
          assert.equal(code, 1);
          assert.match(proc.output(), /partner_identity_unavailable/);
          assert(!proc.output().includes("READY"));
          assert(!proc.output().includes(env.PARTNER_UNLOCK_KEY));
          assert(!proc.output().includes(env.PARTNER_MANAGEMENT_TOKEN));
          await assert.rejects(readFile(join(root, "identity", "identity.json")), { code: "ENOENT" });
        } finally {
          clearTimeout(timeout);
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });

test("authenticated signing verifies under the public DID before and after process replacement", async () => {
  const root = await mkdtemp(join(tmpdir(), "partner-331-"));
  const env = {
    PARTNER_ORIGIN: "https://partner.example",
    PARTNER_STATE_DIR: join(root, "identity"),
    PARTNER_UNLOCK_KEY: "JSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSU",
    PARTNER_MANAGEMENT_TOKEN: "management-secret-with-32-characters",
    PARTNER_PUBLIC_PORT: "0",
    PARTNER_MANAGEMENT_PORT: "0",
  };
  let proc;
  try {
    const bootstrap = run("bootstrap", env);
    assert.equal(
      (await once(bootstrap.child, "exit"))[0],
      0,
      bootstrap.output(),
    );
    proc = await boot(env);
    const did = await (
      await fetch(proc.addresses.public + "/.well-known/did.json")
    ).json();
    assert.equal(did.id, "did:web:partner.example");
    assert.deepEqual(
      Object.keys(did.verificationMethod[0].publicKeyJwk).sort(),
      ["crv", "kid", "kty", "x", "y"],
    );
    assert.equal(
      (
        await fetch(proc.addresses.public + "/management/sign", {
          method: "POST",
        })
      ).status,
      404,
    );
    assert.equal(
      (
        await fetch(proc.addresses.management + "/management/sign", {
          method: "POST",
          body: "{}",
        })
      ).status,
      401,
    );
    async function sign() {
      const response = await fetch(
        proc.addresses.management + "/management/sign",
        {
          method: "POST",
          headers: {
            authorization: "Bearer " + env.PARTNER_MANAGEMENT_TOKEN,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            nonce: "restart-proof",
            audience: "https://registry.example/partner-challenges",
          }),
        },
      );
      assert.equal(response.status, 200);
      const { jwt } = await response.json();
      assert.equal(
        verifyCompactJwsJson({
          compactJws: jwt,
          publicJwk: did.verificationMethod[0].publicKeyJwk,
        }).payload.nonce,
        "restart-proof",
      );
    }
    for (const invalid of [
      { nonce: "short", audience: "https://registry.example" },
      { nonce: "restart-proof", audience: "http://registry.example" },
      {
        nonce: "restart-proof",
        audience: "https://registry.example",
        payload: { admin: true },
      },
    ]) {
      const refusal = await fetch(
        proc.addresses.management + "/management/sign",
        {
          method: "POST",
          headers: { authorization: "Bearer " + env.PARTNER_MANAGEMENT_TOKEN },
          body: JSON.stringify(invalid),
        },
      );
      assert.equal(refusal.status, 400);
    }
    const oversized = await fetch(
      proc.addresses.management + "/management/sign",
      {
        method: "POST",
        headers: { authorization: "Bearer " + env.PARTNER_MANAGEMENT_TOKEN },
        body: "x".repeat(4097),
      },
    );
    assert.equal(oversized.status, 400);
    await sign();
    await stop(proc);
    proc = undefined;
    proc = await boot(env);
    assert.deepEqual(
      await (
        await fetch(proc.addresses.public + "/.well-known/did.json")
      ).json(),
      did,
    );
    await sign();
  } finally {
    if (proc) await stop(proc);
    await rm(root, { recursive: true, force: true });
  }
});

test("deployments have unique keys and established or partial identities never regenerate", async () => {
  const root = await mkdtemp(join(tmpdir(), "partner-331-failure-"));
  const base = {
    PARTNER_ORIGIN: "https://partner.example",
    PARTNER_UNLOCK_KEY: "JSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSU",
    PARTNER_MANAGEMENT_TOKEN: "management-secret-with-32-characters",
    PARTNER_PUBLIC_PORT: "0",
    PARTNER_MANAGEMENT_PORT: "0",
  };
  async function command(mode, env, expected) {
    const proc = run(mode, { ...base, ...env });
    const timeout = setTimeout(() => proc.child.kill(), 3000);
    try {
      assert.equal(
        (await once(proc.child, "exit"))[0],
        expected,
        proc.output(),
      );
    } finally {
      clearTimeout(timeout);
    }
    if (expected !== 0) {
      assert.match(proc.output(), /partner_identity_unavailable/);
      assert(!proc.output().includes(base.PARTNER_UNLOCK_KEY));
      assert(!proc.output().includes(base.PARTNER_MANAGEMENT_TOKEN));
    }
    return proc.output();
  }
  try {
    const state = join(root, "first");
    const env = { PARTNER_STATE_DIR: state };
    const first = JSON.parse(await command("bootstrap", env, 0));
    const second = JSON.parse(
      await command(
        "bootstrap",
        { PARTNER_STATE_DIR: join(root, "second") },
        0,
      ),
    );
    assert.notEqual(first.publicJwk.x, second.publicJwk.x);
    await command("bootstrap", env, 1);
    await command(
      "start",
      {
        ...env,
        PARTNER_UNLOCK_KEY: "JiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiY",
      },
      1,
    );
    await command(
      "start",
      { ...env, PARTNER_ORIGIN: "https://changed.example" },
      1,
    );
    const manifest = join(state, "identity.json");
    const manifestBytes = await readFile(manifest);
    await writeFile(manifest, "null");
    await command("start", env, 1);
    await writeFile(manifest, manifestBytes);
    const key = join(state, "signing-key.sealed");
    const original = await readFile(key);
    await writeFile(key, Buffer.alloc(original.length));
    await command("start", env, 1);
    assert.deepEqual(await readFile(key), Buffer.alloc(original.length));
    await writeFile(key, original);
    await chmod(key, 0o644);
    await command("start", env, 1);
    await chmod(key, 0o600);
    await rm(key);
    await command("start", env, 1);
    await assert.rejects(readFile(key), { code: "ENOENT" });
    await rm(state, { recursive: true });
    await command("start", env, 1);
    await assert.rejects(readFile(join(state, "identity.json")), {
      code: "ENOENT",
    });
    for (const origin of [
      "http://partner.example",
      "https://user:pass@partner.example",
      "https://partner.example/path",
      "https://partner.example?query=true",
    ]) {
      await command("bootstrap", { ...env, PARTNER_ORIGIN: origin }, 1);
    }
    await command("bootstrap", { ...env, PARTNER_UNLOCK_KEY: "bad-key" }, 1);
    await assert.rejects(readFile(join(state, "identity.json")), {
      code: "ENOENT",
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("identity state with unsafe directory permissions fails before opening a listener", async () => {
  const root = await mkdtemp(join(tmpdir(), "partner-331-permissions-"));
  const state = join(root, "identity");
  const env = {
    PARTNER_ORIGIN: "https://partner.example",
    PARTNER_STATE_DIR: state,
    PARTNER_UNLOCK_KEY: "JSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSU",
    PARTNER_MANAGEMENT_TOKEN: "management-secret-with-32-characters",
    PARTNER_PUBLIC_PORT: "0",
    PARTNER_MANAGEMENT_PORT: "0",
  };
  try {
    const bootstrap = run("bootstrap", env);
    assert.equal((await once(bootstrap.child, "exit"))[0], 0);
    await chmod(state, 0o777);
    const proc = run("start", env);
    const result = await Promise.race([
      once(proc.child, "exit"),
      new Promise((resolve) => setTimeout(() => resolve("running"), 1000)),
    ]);
    if (result === "running") {
      proc.child.kill();
      await once(proc.child, "exit");
    }
    assert.notEqual(result, "running", "unsafe state directory was accepted");
    assert.equal(result[0], 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
