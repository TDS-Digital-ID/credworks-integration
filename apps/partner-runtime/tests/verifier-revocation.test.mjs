import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readFile,
  writeFile,
  rm,
  mkdir,
  readdir,
  chmod,
  symlink,
} from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { processFixture } from "./support/verifier-process-fixture.mjs";
import * as core from "@unsw-vc/identity-core-node";
import {
  fixture,
  create,
  presentation,
  complete,
  consume,
} from "./support/scalar-session.mjs";

function revokedList(f, indices, changes = {}) {
  const [header, payload] = core.verifyBitstringStatusListCredential({
    compactJws: f.evidence.get(f.statusUrl),
    statusListJwk: f.statusJwk,
  });
  return core.signBitstringStatusListCredential({
    keyId: f.statusKeyId,
    header,
    payload: {
      ...payload,
      ...changes,
      validFrom: new Date(f.clock() * 1000).toISOString().replace(".000Z", "Z"),
      credentialSubject: {
        ...payload.credentialSubject,
        encodedList: core.encodeBitstringStatusList(131072, indices),
      },
    },
  });
}

async function observed(f, changes) {
  const { session, request } = await create(f);
  await complete(f, request, presentation(f, request, changes));
  return consume(f, session);
}

async function refresh(f) {
  const response = await f.app("/management/evidence/refresh", {});
  assert.equal(response.status, 200, await response.clone().text());
}

function entry(f, index) {
  return {
    payload: {
      credentialStatus: {
        id: f.statusUrl + "#" + index,
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: String(index),
        statusListCredential: f.statusUrl,
      },
    },
  };
}

test("storage that cannot begin observation refuses before a writable negative survives replay and restart", async () => {
  assert.notEqual(
    process.getuid?.(),
    0,
    "the POSIX permission fixture requires an unprivileged test user",
  );
  const f = await fixture();
  try {
    const active = f.evidence.get(f.statusUrl);
    f.evidence.set(f.statusUrl, revokedList(f, [7]));
    await refresh(f);
    await chmod(f.config.stateDir, 0o500);
    assert.equal((await observed(f)).error.code, "EVIDENCE_UNAVAILABLE");
    await chmod(f.config.stateDir, 0o700);
    // Only this writable observation authenticates the new negative behind the
    // durable barrier. The preceding refusal did not begin bit resolution.
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    f.evidence.set(f.statusUrl, active);
    await refresh(f);
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    await f.restart();
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
  } finally {
    await chmod(f.config.stateDir, 0o700);
    await f.close();
  }
});

test(
  "FIFO proof, inventory and manifest refuse startup and live HTTP without blocking",
  { timeout: 60000 },
  async () => {
    for (const target of ["proof", "inventory", "manifest"]) {
      const f = await fixture();
      let processes;
      try {
        f.evidence.set(f.statusUrl, revokedList(f, [7]));
        await refresh(f);
        assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
        const directory = join(f.config.stateDir, "revocation-proofs");
        const proof = (await readdir(directory)).find(
          (name) => name !== "inventory.jwt",
        );
        const path =
          target === "proof"
            ? join(directory, proof)
            : target === "inventory"
              ? join(directory, "inventory.jwt")
              : join(f.config.stateDir, "identity.json");
        processes = await processFixture(f);
        const running = await processes.start();
        await rm(path);
        execFileSync("mkfifo", ["-m", "600", path]);
        const result = await Promise.race([
          observed(running),
          delay(3000).then(() => {
            throw Error("FIFO HTTP refusal deadline");
          }),
        ]);
        assert.equal(result.error.code, "EVIDENCE_UNAVAILABLE");
        await running.stop();
        await assert.rejects(processes.start(), /EVIDENCE_UNAVAILABLE/);
      } finally {
        await processes?.close();
        await f.close();
      }
    }
  },
);

test("a generic status refusal does not create permanent revocation evidence", async () => {
  const f = await fixture();
  try {
    const wrong = entry(f, 7);
    wrong.payload.credentialStatus.id = f.statusUrl + "#8";
    assert.equal((await observed(f, wrong)).error.code, "STATUS_CHECK_FAILED");
    assert.equal((await observed(f)).status, "verified");
    await f.restart();
    assert.equal((await observed(f)).status, "verified");
  } finally {
    await f.close();
  }
});

test("issuer outage and failed refresh preserve only the original positive-cache deadline", async () => {
  const f = await fixture({ maxAge: 30 });
  try {
    f.evidence.delete(f.statusUrl);
    f.evidence.set(f.permissionsUrl, f.signPermission({ status: "inactive" }));
    const failed = await f.app("/management/evidence/refresh", {});
    assert.equal(failed.status, 503);
    assert.deepEqual(await failed.json(), {
      error: { code: "EVIDENCE_REFRESH_FAILED" },
    });
    f.advance(29);
    assert.equal(
      (await observed(f)).status,
      "verified",
      "failed refresh cannot partially install inactive permission",
    );
    f.advance(1);
    const expired = await f.app("/management/sessions", {
      configuration_id: "neutral-pass",
      profile: "neutral_check",
      interaction_id: "browser-372",
      purpose: "Check cached evidence",
    });
    assert.equal(expired.status, 503);
    assert.deepEqual(await expired.json(), {
      error: { code: "EVIDENCE_STALE" },
    });
    await assert.rejects(
      f.restart(),
      { code: "EVIDENCE_REFRESH_FAILED" },
      "cold startup still requires current positive evidence",
    );
  } finally {
    await f.close();
  }
});

// External filesystem fixture for the documented signed-store capacity boundary.
// Proofs and inventory are produced and authenticated by the existing public core.
async function seedProofs(f, compact, count) {
  const directory = join(f.config.stateDir, "revocation-proofs");
  const entries = Array.from({ length: count }, (_, index) => {
    const tuple = {
      issuerDid: f.issuerDid,
      issuerKeyId: f.issuerKeyId,
      issuerThumbprint: core.publicJwkSha256Thumbprint(f.issuerJwk),
      statusThumbprint: core.publicJwkSha256Thumbprint(f.issuerJwk),
      statusKeyId: f.issuerKeyId,
      url: f.statusUrl,
      index: String(index),
    };
    const id = core.sha256B64Url(
      JSON.stringify([
        "credworks-revocation-proof-v1",
        tuple.issuerDid,
        tuple.issuerKeyId,
        tuple.issuerThumbprint,
        tuple.statusThumbprint,
        tuple.statusKeyId,
        tuple.url,
        tuple.index,
      ]),
    );
    return {
      id,
      tuple,
      observedAt: f.clock(),
      proofHash: core.sha256B64Url(compact),
      proofBytes: Buffer.byteLength(compact),
    };
  });
  for (let start = 0; start < entries.length; start += 64)
    await Promise.all(
      entries.slice(start, start + 64).map((value) =>
        writeFile(join(directory, value.id + ".jwt"), compact, {
          mode: 0o600,
        }),
      ),
    );
  await writeFile(
    join(directory, "inventory.jwt"),
    core.signCompactJwsJson({
      keyId: f.identity.keyId,
      header: {
        alg: "ES256",
        typ: "credworks-revocation-inventory+jwt",
        kid: f.identity.keyId,
      },
      payload: { version: 1, runtimeDid: f.identity.did, entries },
    }),
    { mode: 0o600 },
  );
  return entries;
}

async function capacityRefusal(f, index, active) {
  const directory = join(f.config.stateDir, "revocation-proofs");
  const inventory = await readFile(join(directory, "inventory.jwt"), "utf8");
  const entries = core.verifyCompactJwsJson({
    compactJws: inventory,
    publicJwk: f.identity.publicJwk,
  }).payload.entries;
  const proofPath = join(
    directory,
    entries.find((value) => value.tuple.index === "7").id + ".jwt",
  );
  const proof = await readFile(proofPath, "utf8");
  assert.equal(
    core.resolveCredentialStatusAt({
      status: entry(f, 7).payload.credentialStatus,
      resolverResponses: { [f.statusUrl]: proof },
      statusListJwk: f.issuerJwk,
      nowUnixSeconds: f.clock(),
    }).revoked,
    true,
  );
  assert.equal(
    (await observed(f, entry(f, index))).error.code,
    "EVIDENCE_UNAVAILABLE",
  );
  assert.equal(
    await readFile(join(directory, "inventory.jwt"), "utf8"),
    inventory,
  );
  assert.equal(await readFile(proofPath, "utf8"), proof);
  f.evidence.set(f.statusUrl, active);
  await refresh(f);
  assert.deepEqual(await observed(f, entry(f, index)), {
    status: "refused",
    interaction_id: "browser-372",
    error: { code: "EVIDENCE_UNAVAILABLE" },
  });
  assert.equal(
    (await observed(f, entry(f, 7))).error.code,
    "EVIDENCE_UNAVAILABLE",
  );
  await assert.rejects(f.restart(), { code: "EVIDENCE_UNAVAILABLE" });
}

test(
  "inventory signing bounds retain conservative refusal for the newly observed exact negative",
  { timeout: 180000 },
  async () => {
    const f = await fixture({
      maxAge: 300,
      issuerDid: "did:web:issuer372.example:" + "x".repeat(450),
      statusUrl:
        "https://issuer372.example/status/" + "x".repeat(1950) + ".jwt",
    });
    try {
      const active = f.evidence.get(f.statusUrl);
      const compact = revokedList(
        f,
        Array.from({ length: 10000 }, (_, i) => i),
      );
      f.evidence.set(f.statusUrl, compact);
      await refresh(f);
      const one = await seedProofs(f, compact, 1);
      let count = Math.floor(
        (12 * 1024 * 1024 - 8192) / Buffer.byteLength(JSON.stringify(one[0])),
      );
      let entries = await seedProofs(f, compact, count);
      while (
        Buffer.byteLength(
          JSON.stringify({ version: 1, runtimeDid: f.identity.did, entries }),
        ) +
          Buffer.byteLength(JSON.stringify(entries[0])) <
        12 * 1024 * 1024
      ) {
        entries = await seedProofs(f, compact, ++count);
      }
      assert.ok(
        count < 10000 && count * Buffer.byteLength(compact) < 64 * 1024 * 1024,
      );
      await capacityRefusal(f, count, active);
    } finally {
      await f.close();
    }
  },
);

test(
  "the 10,000-tuple ceiling refuses a new negative without losing an existing one",
  { timeout: 180000 },
  async () => {
    const f = await fixture({ maxAge: 300 });
    try {
      const active = f.evidence.get(f.statusUrl);
      const compact = revokedList(
        f,
        Array.from({ length: 10001 }, (_, i) => i),
      );
      f.evidence.set(f.statusUrl, compact);
      await refresh(f);
      await seedProofs(f, compact, 10000);
      await capacityRefusal(f, 10000, active);
    } finally {
      await f.close();
    }
  },
);

test(
  "the 64 MiB aggregate ceiling refuses a new proof while preserving authenticated history",
  { timeout: 180000 },
  async () => {
    const f = await fixture({ maxAge: 300 });
    try {
      const active = f.evidence.get(f.statusUrl);
      const original = revokedList(
        f,
        Array.from({ length: 400 }, (_, i) => i),
      );
      const [header, payload] = core.verifyBitstringStatusListCredential({
        compactJws: original,
        statusListJwk: f.issuerJwk,
      });
      const compact = core.signBitstringStatusListCredential({
        keyId: f.issuerKeyId,
        header: { ...header, cty: "x".repeat(180000) },
        payload,
      });
      const bytes = Buffer.byteLength(compact);
      assert.ok(
        bytes < 262144 && bytes > 230000,
        "each native signed proof fits the per-proof bound",
      );
      const count = Math.floor((64 * 1024 * 1024) / bytes);
      assert.ok(count < 400);
      f.evidence.set(f.statusUrl, compact);
      await refresh(f);
      await seedProofs(f, compact, count);
      await capacityRefusal(f, count, active);
    } finally {
      await f.close();
    }
  },
);

test("Education suspension is reversible and never becomes a permanent revocation mark", async () => {
  const f = await fixture();
  try {
    delete f.config.verifier.scalar;
    f.config.verifier.statusSources[0].purpose = "suspension";
    const type = "UniversityEducationCredential";
    const paths = [
      ["credentialSubject", "enrolled"],
      ["credentialSubject", "institution_id"],
    ];
    const registryKeyId = f.registryDid + "#anchor";
    const permissionsUrl =
      f.config.verifier.registryOrigin +
      "/scoped-verifier-permissions.jwt?verifier_did=" +
      encodeURIComponent(f.identity.did);
    f.evidence.set(
      f.config.verifier.registryOrigin + "/trust-list.jwt",
      core.signTrustList({
        keyId: registryKeyId,
        header: { alg: "ES256", typ: "trust-list+jwt", kid: registryKeyId },
        payload: {
          id: f.config.verifier.registryOrigin + "/trust-list.jwt",
          issuer: f.registryDid,
          iat: f.clock(),
          exp: f.clock() + 300,
          entries: [
            {
              issuer_did: f.issuerDid,
              credential_types: [type],
              status: "active",
              public_jwk: f.issuerJwk,
              public_jwk_sha256_thumbprint: core.publicJwkSha256Thumbprint(
                f.issuerJwk,
              ),
            },
          ],
          verifiers: [],
        },
      }),
    );
    f.evidence.set(
      permissionsUrl,
      core.signScopedVerifierPermissions({
        keyId: registryKeyId,
        header: {
          alg: "ES256",
          typ: "scoped-verifier-permissions+jwt",
          kid: registryKeyId,
        },
        payload: {
          version: 1,
          id: permissionsUrl,
          issuer: f.registryDid,
          iat: f.clock(),
          exp: f.clock() + 300,
          permissions: [
            {
              credential_issuer_did: f.issuerDid,
              definition_id: "urn:credworks:education",
              definition_version: "1",
              credential_type: type,
              verifier_did: f.identity.did,
              verifier_origin: f.config.origin,
              verifier_public_jwk_sha256_thumbprint:
                core.publicJwkSha256Thumbprint(f.identity.publicJwk),
              profile_name: "education_eligibility",
              claim_paths: paths,
              status: "active",
            },
          ],
        },
      }),
    );
    const [header, payload] = core.verifyBitstringStatusListCredential({
      compactJws: f.evidence.get(f.statusUrl),
      statusListJwk: f.issuerJwk,
    });
    const signed = (indices) =>
      core.signBitstringStatusListCredential({
        keyId: f.issuerKeyId,
        header,
        payload: {
          ...payload,
          credentialSubject: {
            ...payload.credentialSubject,
            statusPurpose: "suspension",
            encodedList: core.encodeBitstringStatusList(131072, indices),
          },
        },
      });
    f.evidence.set(f.statusUrl, signed([]));
    await f.restart();
    async function educationResult() {
      const response = await f.app("/management/sessions", {
        profile: "education_eligibility",
        interaction_id: "browser-372",
        purpose: "Check Education suspension",
      });
      assert.equal(response.status, 201, await response.clone().text());
      const session = await response.json();
      const request = core.verifyOid4vpRequestObject({
        compactJws: await (
          await fetch(f.runtime.public + new URL(session.request_uri).pathname)
        ).text(),
        resolverResponses: {
          [core.didWebToHttpsUrl(f.identity.did)]: JSON.stringify(
            core.buildDidWebDocument(f.identity.did, [f.identity.publicJwk]),
          ),
        },
        nowUnixSeconds: f.clock(),
      }).payload;
      const token = presentation(f, request, {
        paths,
        payload: {
          type: ["VerifiableCredential", type],
          credentialDefinition: undefined,
          credentialSubject: { enrolled: true, institution_id: "example.edu" },
          credentialStatus: {
            ...entry(f, 7).payload.credentialStatus,
            statusPurpose: "suspension",
          },
        },
      });
      const delivered = await fetch(
        f.runtime.public + new URL(request.response_uri).pathname,
        {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            state: request.state,
            vp_token: JSON.stringify({ education_eligibility: [token] }),
          }),
        },
      );
      assert.equal(delivered.status, 200, await delivered.clone().text());
      assert.deepEqual(await delivered.json(), { status: "accepted" });
      return consume(f, session);
    }
    assert.equal((await educationResult()).status, "verified");
    f.evidence.set(f.statusUrl, signed([7]));
    await refresh(f);
    assert.equal((await educationResult()).error.code, "STATUS_CHECK_FAILED");
    f.evidence.set(f.statusUrl, signed([]));
    await f.restart();
    assert.equal((await educationResult()).status, "verified");
  } finally {
    await f.close();
  }
});

for (const [bound, options] of [
  ["cache age", { maxAge: 1 }],
  ["signed status validity", { statusTTL: 1 }],
])
  test(
    `${bound} that expires while durable proof state is contended cannot return verified`,
    { timeout: 30000 },
    async () => {
      const f = await fixture(options);
      let processes;
      try {
        processes = await processFixture(f, { controlledClock: true });
        const target = await processes.start();
        const { session, request } = await create(target);
        await complete(target, request, presentation(target, request));
        const lock = join(f.config.stateDir, "revocation-proofs.lock");
        await mkdir(lock, { mode: 0o700 });
        let settled = false;
        const result = consume(target, session).then((value) => {
          settled = true;
          return value;
        });
        await delay(120);
        assert.equal(
          settled,
          false,
          "protected result must still await the contended proof state",
        );
        await processes.setClock(f.clock() + 1);
        await rm(lock, { recursive: true });
        assert.deepEqual(await result, {
          status: "refused",
          interaction_id: "browser-372",
          error: { code: "EVIDENCE_STALE" },
        });
      } finally {
        await processes?.close();
        await f.close();
      }
    },
  );

test(
  "protected result refuses a credential deadline crossed during proof contention",
  { timeout: 30000 },
  async () => {
    const f = await fixture({ maxAge: 30 });
    let processes;
    try {
      processes = await processFixture(f, { controlledClock: true });
      const target = await processes.start();
      const { session, request } = await create(target);
      await complete(
        target,
        request,
        presentation(target, request, {
          payload: {
            exp: f.clock() + 1,
            validUntil: new Date((f.clock() + 1) * 1000)
              .toISOString()
              .replace(".000Z", "Z"),
          },
        }),
      );
      const lock = join(f.config.stateDir, "revocation-proofs.lock");
      await mkdir(lock, { mode: 0o700 });
      let settled = false;
      const result = consume(target, session).then((value) => {
        settled = true;
        return value;
      });
      await delay(120);
      assert.equal(settled, false, "result must wait for proof state");
      await processes.setClock(f.clock() + 1);
      await rm(lock, { recursive: true });
      assert.deepEqual(await result, {
        status: "refused",
        interaction_id: "browser-372",
        error: { code: "EVIDENCE_STALE" },
      });
    } finally {
      await processes?.close();
      await f.close();
    }
  },
);

test("an interrupted first initialization cannot recreate an empty proof store", async () => {
  for (const lock of [false, true]) {
    await assert.rejects(
      fixture({
        prepareState: async ({ config }) => {
          await mkdir(join(config.stateDir, "revocation-proofs"), {
            mode: 0o700,
          });
          if (lock)
            await mkdir(join(config.stateDir, "revocation-proofs.lock"), {
              mode: 0o700,
            });
        },
      }),
      { code: "EVIDENCE_UNAVAILABLE" },
    );
  }
});

test("unsafe or missing retained proof cannot restore an authenticated revoked issuance", async () => {
  for (const corruption of [
    "missing",
    "signature",
    "permissions",
    "symlink",
    "inventory",
    "oversized-proof",
    "oversized-inventory",
    "future-observation",
    "active-proof",
  ]) {
    const f = await fixture();
    try {
      f.evidence.set(f.statusUrl, revokedList(f, [7]));
      await refresh(f);
      assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
      const directory = join(f.config.stateDir, "revocation-proofs");
      const file = (await readdir(directory)).find(
        (value) => value !== "inventory.jwt",
      );
      const path = join(directory, file);
      if (corruption === "missing") await rm(path);
      if (corruption === "signature") {
        const compact = await readFile(path, "utf8");
        await writeFile(
          path,
          compact.slice(0, -1) + (compact.endsWith("A") ? "B" : "A"),
        );
      }
      if (corruption === "permissions") await chmod(path, 0o644);
      if (corruption === "symlink") {
        const copy = join(f.config.stateDir, "untrusted-proof.jwt");
        await writeFile(copy, await readFile(path));
        await rm(path);
        await symlink(copy, path);
      }
      if (corruption === "inventory")
        await rm(join(directory, "inventory.jwt"));
      if (corruption === "oversized-proof")
        await writeFile(path, "x".repeat(262145));
      if (corruption === "oversized-inventory")
        await writeFile(
          join(directory, "inventory.jwt"),
          "x".repeat(16 * 1024 * 1024 + 1),
        );
      if (
        corruption === "future-observation" ||
        corruption === "active-proof"
      ) {
        const verified = core.verifyCompactJwsJson({
          compactJws: await readFile(join(directory, "inventory.jwt"), "utf8"),
          publicJwk: f.identity.publicJwk,
        });
        if (corruption === "future-observation")
          verified.payload.entries[0].observedAt = f.clock() + 1;
        else {
          const active = revokedList(f, []);
          await writeFile(path, active);
          verified.payload.entries[0].proofHash = core.sha256B64Url(active);
          verified.payload.entries[0].proofBytes = Buffer.byteLength(active);
        }
        await writeFile(
          join(directory, "inventory.jwt"),
          core.signCompactJwsJson({
            keyId: f.identity.keyId,
            header: verified.header,
            payload: verified.payload,
          }),
        );
      }
      assert.equal(
        (await observed(f)).error.code,
        "EVIDENCE_UNAVAILABLE",
        corruption,
      );
      await assert.rejects(
        f.restart(),
        { code: "EVIDENCE_UNAVAILABLE" },
        corruption,
      );
    } finally {
      await f.close();
    }
  }
});

test("preexisting interrupted inventory publication refuses partial state", async () => {
  const f = await fixture();
  let processes;
  try {
    f.evidence.set(f.statusUrl, revokedList(f, [7, 8]));
    await refresh(f);
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    // Existing pending state simulates an interrupted exclusive publication.
    await writeFile(
      join(f.config.stateDir, "revocation-proofs", "inventory.jwt.pending"),
      "interrupted",
      { mode: 0o600 },
    );
    assert.equal(
      (await observed(f, entry(f, 8))).error.code,
      "EVIDENCE_UNAVAILABLE",
    );
    assert.equal((await observed(f)).error.code, "EVIDENCE_UNAVAILABLE");
    processes = await processFixture(f);
    await assert.rejects(processes.start(), /EVIDENCE_UNAVAILABLE/);
  } finally {
    await processes?.close();
    await f.close();
  }
});

test(
  "a native file-size failure after proof publication cannot return acceptance or reset history",
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    let processes;
    try {
      const compact = revokedList(
        f,
        Array.from({ length: 10 }, (_, i) => i),
      );
      assert.ok(
        Buffer.byteLength(compact) < 4096,
        "proof fits the child RLIMIT_FSIZE",
      );
      f.evidence.set(f.statusUrl, compact);
      await refresh(f);
      for (let index = 0; index < 9; index++)
        assert.equal(
          (await observed(f, entry(f, index))).error.code,
          "STATUS_CHECK_FAILED",
        );
      const directory = join(f.config.stateDir, "revocation-proofs");
      const original = await readFile(join(directory, "inventory.jwt"), "utf8");
      assert.ok(
        Buffer.byteLength(original) > 4096,
        "inventory exceeds the child RLIMIT_FSIZE",
      );
      const previousFiles = await readdir(directory);
      processes = await processFixture(f);
      const child = await processes.start(0, { fileSizeLimit: 4096 });
      let result;
      try {
        result = await observed(child, entry(f, 9));
      } catch (error) {
        assert.equal(
          error.name,
          "TypeError",
          "killed writer closes its HTTP connection",
        );
      }
      if (result) assert.equal(result.error.code, "EVIDENCE_UNAVAILABLE");
      assert.equal(
        await readFile(join(directory, "inventory.jwt"), "utf8"),
        original,
      );
      const newFiles = (await readdir(directory)).filter(
        (name) => !previousFiles.includes(name),
      );
      const proof = newFiles.find(
        (name) => name.endsWith(".jwt") && name !== "inventory.jwt",
      );
      assert.ok(
        proof,
        "the signed proof was published before inventory failure",
      );
      assert.equal(await readFile(join(directory, proof), "utf8"), compact);
      assert.equal(
        (await readFile(join(directory, "inventory.jwt.pending"))).length,
        4096,
      );
      assert.equal((await observed(f)).error.code, "EVIDENCE_UNAVAILABLE");
      await assert.rejects(processes.start(1), /EVIDENCE_UNAVAILABLE/);
    } finally {
      await processes?.close();
      await f.close();
    }
  },
);

test(
  "separate verifier processes retain concurrent observed revocations across replacement",
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    let processes;
    try {
      const active = f.evidence.get(f.statusUrl);
      f.evidence.set(f.statusUrl, revokedList(f, [7, 8]));
      processes = await processFixture(f);
      const first = await processes.start(0),
        second = await processes.start(1);
      const results = await Promise.all([
        observed(first, entry(f, 7)),
        observed(second, entry(f, 8)),
      ]);
      for (const result of results)
        assert.equal(result.error.code, "STATUS_CHECK_FAILED");
      f.evidence.set(f.statusUrl, active);
      const concurrent = await Promise.all([
        refresh(first),
        refresh(second),
        observed(second, entry(f, 7)),
      ]);
      assert.equal(concurrent[2].error.code, "STATUS_CHECK_FAILED");
      for (const target of [first, second]) {
        assert.equal(
          (await observed(target, entry(f, 7))).error.code,
          "STATUS_CHECK_FAILED",
        );
        assert.equal(
          (await observed(target, entry(f, 8))).error.code,
          "STATUS_CHECK_FAILED",
        );
        assert.equal((await observed(target, entry(f, 9))).status, "verified");
      }
      await Promise.all([first.stop(), second.stop()]);
      const replacement = await processes.start(0);
      assert.equal(
        (await observed(replacement, entry(f, 7))).error.code,
        "STATUS_CHECK_FAILED",
      );
      assert.equal(
        (await observed(replacement, entry(f, 8))).error.code,
        "STATUS_CHECK_FAILED",
      );
      assert.equal(
        (await observed(replacement, entry(f, 9))).status,
        "verified",
      );
    } finally {
      await processes?.close();
      await f.close();
    }
  },
);

test("authenticated revocation cannot be undone by an older otherwise-valid active list", async () => {
  const f = await fixture();
  try {
    const active = f.evidence.get(f.statusUrl);
    assert.equal((await observed(f)).status, "verified");
    f.advance(1);
    f.evidence.set(f.statusUrl, revokedList(f, [7]));
    await refresh(f);
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    f.evidence.set(f.statusUrl, active);
    await refresh(f);
    assert.deepEqual(await observed(f), {
      status: "refused",
      interaction_id: "browser-372",
      error: { code: "STATUS_CHECK_FAILED" },
    });
  } finally {
    await f.close();
  }
});

test("an established missing proof store refuses live use and restart", async () => {
  const f = await fixture();
  try {
    f.evidence.set(f.statusUrl, revokedList(f, [7]));
    await refresh(f);
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    await rm(join(f.config.stateDir, "revocation-proofs"), { recursive: true });
    assert.equal((await observed(f)).error.code, "EVIDENCE_UNAVAILABLE");
    await assert.rejects(f.restart(), { code: "EVIDENCE_UNAVAILABLE" });
  } finally {
    await f.close();
  }
});

test("a removed initialized marker cannot reset retained revocation history", async () => {
  const f = await fixture();
  try {
    f.evidence.set(f.statusUrl, revokedList(f, [7]));
    await refresh(f);
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    const path = join(f.config.stateDir, "identity.json");
    const manifest = JSON.parse(await readFile(path, "utf8"));
    delete manifest.revocationProofStoreVersion;
    await writeFile(path, JSON.stringify(manifest), { mode: 0o600 });
    assert.equal((await observed(f)).error.code, "EVIDENCE_UNAVAILABLE");
    await assert.rejects(f.restart(), { code: "EVIDENCE_UNAVAILABLE" });
  } finally {
    await f.close();
  }
});

test("permanent negative proof survives its old signed validity under fresh active evidence", async () => {
  const f = await fixture();
  try {
    f.evidence.set(f.statusUrl, revokedList(f, [7]));
    await refresh(f);
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    f.advance(400);
    f.evidence.set(f.authorityUrl, f.signAuthority());
    f.evidence.set(f.permissionsUrl, f.signPermission());
    f.evidence.set(
      f.statusUrl,
      revokedList(f, [], {
        validUntil: new Date((f.clock() + 300) * 1000)
          .toISOString()
          .replace(".000Z", "Z"),
      }),
    );
    await f.restart();
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    assert.equal(
      (
        await observed(f, {
          payload: {
            credentialStatus: {
              id: f.statusUrl + "#8",
              type: "BitstringStatusListEntry",
              statusPurpose: "revocation",
              statusListIndex: "8",
              statusListCredential: f.statusUrl,
            },
          },
        })
      ).status,
      "verified",
    );
  } finally {
    await f.close();
  }
});

test("a status header cannot substitute another key fragment under the same configured JWK", async () => {
  const f = await fixture();
  try {
    const [header, payload] = core.verifyBitstringStatusListCredential({
      compactJws: f.evidence.get(f.statusUrl),
      statusListJwk: f.issuerJwk,
    });
    f.evidence.set(
      f.statusUrl,
      core.signBitstringStatusListCredential({
        keyId: f.issuerKeyId,
        header: { ...header, kid: f.issuerDid + "#other" },
        payload,
      }),
    );
    const response = await f.app("/management/evidence/refresh", {});
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
      error: { code: "EVIDENCE_REFRESH_FAILED" },
    });
  } finally {
    await f.close();
  }
});

test("a restarted verifier refuses a previously authenticated revoked issuance under an older active list", async () => {
  const f = await fixture();
  try {
    const active = f.evidence.get(f.statusUrl);
    f.evidence.set(f.statusUrl, revokedList(f, [7]));
    await refresh(f);
    assert.equal((await observed(f)).error.code, "STATUS_CHECK_FAILED");
    f.evidence.set(f.statusUrl, active);
    await f.restart();
    assert.equal((await observed(f)).error?.code, "STATUS_CHECK_FAILED");
  } finally {
    await f.close();
  }
});

test("retained old/new negatives preserve exact credential and separate status pins after withdrawal and restart", async () => {
  const f = await fixture({ retainedKeys: true });
  let processes;
  try {
    const active = f.evidence.get(f.statusUrl);
    f.evidence.set(f.statusUrl, revokedList(f, [7, 8]));
    await refresh(f);
    assert.equal((await observed(f, entry(f, 7))).error.code, "STATUS_CHECK_FAILED");
    assert.equal((await observed(f, { ...entry(f, 8), issuerKeyId: f.newIssuerKeyId })).error.code, "STATUS_CHECK_FAILED");
    const path = join(f.config.stateDir, "revocation-proofs", "inventory.jwt");
    const original = await readFile(path, "utf8");
    const inventory = core.verifyCompactJwsJson({ compactJws: original, publicJwk: f.identity.publicJwk }).payload;
    assert.deepEqual(inventory.entries.map(record => [record.tuple.issuerKeyId, record.tuple.issuerThumbprint,
      record.tuple.statusKeyId, record.tuple.statusThumbprint, record.tuple.index]), [
      [f.issuerKeyId, core.publicJwkSha256Thumbprint(f.issuerJwk), f.issuerKeyId, core.publicJwkSha256Thumbprint(f.issuerJwk), "7"],
      [f.newIssuerKeyId, core.publicJwkSha256Thumbprint(f.newIssuerJwk), f.issuerKeyId, core.publicJwkSha256Thumbprint(f.issuerJwk), "8"],
    ]);
    f.evidence.set(f.statusUrl, active);
    f.evidence.set(f.authorityUrl, f.signAuthority({ key_state: "withdrawn" }));
    await f.restart();
    assert.equal(await readFile(path, "utf8"), original, "reload does not rewrite signed inventory or observation times");
    const { session, request } = await create(f);
    await complete(f, request, presentation(f, request));
    assert.equal((await consume(f, session)).error.code, "ISSUER_NOT_AUTHORIZED");
    assert.equal((await observed(f, { ...entry(f, 8), issuerKeyId: f.newIssuerKeyId })).error.code, "STATUS_CHECK_FAILED");
    assert.equal((await observed(f, { ...entry(f, 9), issuerKeyId: f.newIssuerKeyId })).status, "verified");
    const withdrawn = core.verifyCompactJwsJson({ compactJws: f.evidence.get(f.authorityUrl), publicJwk: f.anchor }).payload.authorizations;
    withdrawn[1].key_state = "withdrawn";
    f.evidence.set(f.authorityUrl, f.signAuthority({}, withdrawn));
    await f.restart();
    assert.equal(await readFile(path, "utf8"), original);
    const noAuthority = await f.app("/management/sessions", { configuration_id: "neutral-pass", profile: "neutral_check",
      interaction_id: "negative-only", purpose: "Cannot grant positive authority" });
    assert.equal(noAuthority.status, 403);
    f.evidence.delete(f.authorityUrl);
    await assert.rejects(f.restart(), { code: "EVIDENCE_REFRESH_FAILED" });
    assert.equal(await readFile(path, "utf8"), original, "outage cannot clear negative history");
    f.evidence.set(f.authorityUrl, f.signAuthority());
    await f.restart();
    assert.equal((await observed(f, entry(f, 7))).error.code, "STATUS_CHECK_FAILED");
    processes = await processFixture(f);
    const replacement = await processes.start();
    assert.equal((await observed(replacement, entry(f, 7))).error.code, "STATUS_CHECK_FAILED");
    assert.equal((await observed(replacement, { ...entry(f, 8), issuerKeyId: f.newIssuerKeyId })).error.code, "STATUS_CHECK_FAILED");
    assert.equal((await observed(replacement, { ...entry(f, 9), issuerKeyId: f.newIssuerKeyId })).status, "verified");
    assert.equal(await readFile(path, "utf8"), original);
  } finally { await processes?.close(); await f.close(); }
});

test("independent status signer governs exact old/new instances and never follows the credential key", async () => {
  const f = await fixture({ retainedKeys: true, separateStatusKey: true });
  try {
    const active = f.evidence.get(f.statusUrl);
    for (const issuerKeyId of [f.issuerKeyId, f.newIssuerKeyId]) {
      assert.equal((await observed(f, { ...entry(f, 7), issuerKeyId })).status, "verified");
    }
    f.evidence.set(f.statusUrl, revokedList(f, [7]));
    await refresh(f);
    for (const issuerKeyId of [f.issuerKeyId, f.newIssuerKeyId]) {
      assert.equal((await observed(f, { ...entry(f, 7), issuerKeyId })).error.code, "STATUS_CHECK_FAILED");
      assert.equal((await observed(f, { ...entry(f, 8), issuerKeyId })).status, "verified");
    }
    const inventory = core.verifyCompactJwsJson({ compactJws: await readFile(join(f.config.stateDir, "revocation-proofs", "inventory.jwt"), "utf8"), publicJwk: f.identity.publicJwk }).payload;
    assert.equal(inventory.entries.length, 2);
    for (const record of inventory.entries) {
      assert.equal(record.tuple.statusKeyId, f.statusKeyId);
      assert.equal(record.tuple.statusThumbprint, core.publicJwkSha256Thumbprint(f.statusJwk));
    }
    const [header, payload] = core.verifyBitstringStatusListCredential({ compactJws: active, statusListJwk: f.statusJwk });
    f.evidence.set(f.statusUrl, core.signBitstringStatusListCredential({ keyId: f.newIssuerKeyId, header: { ...header, kid: f.newIssuerKeyId }, payload }));
    assert.equal((await f.app("/management/evidence/refresh", {})).status, 503);
    f.evidence.set(f.statusUrl, active);
    await f.restart();
    assert.equal((await observed(f, { ...entry(f, 7), issuerKeyId: f.newIssuerKeyId })).error.code, "STATUS_CHECK_FAILED");
  } finally { await f.close(); }
});
