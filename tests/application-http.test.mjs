import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
const database = process.env.EDUCATION_APP_DATABASE_URL;
test(
  "standalone application HTTP keeps Secure browser cookies and exact CSRF refusals",
  { skip: !database, timeout: 30000 },
  async () => {
    const port = Number(process.env.EDUCATION_APP_TEST_PORT ?? 29270);
    const origin = "https://application.example";
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts"], {
      cwd: fileURLToPath(
        new URL("../apps/education-sign-in/", import.meta.url),
      ),
      env: {
        ...process.env,
        EDUCATION_APP_DATABASE_URL: database,
        EDUCATION_APP_ORIGIN: origin,
        EDUCATION_APP_PORT: String(port),
        EDUCATION_RUNTIME_MANAGEMENT: "http://127.0.0.1:29271",
        PARTNER_MANAGEMENT_TOKEN: "bounded-test-management-credential-only",
        EDUCATION_TRUSTED_ISSUER: "did:web:education.example",
        EDUCATION_VERIFIER_DID: "did:web:partner.example",
        EDUCATION_INSTITUTION: "unsw.edu.au",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const ended = once(child, "exit");
    try {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(Error("APPLICATION_STARTUP_FAILED")),
          10000,
        );
        child.stdout.on("data", (data) => {
          if (data.toString().includes("education_application_ready")) {
            clearTimeout(timer);
            resolve();
          }
        });
        child.once("exit", () => {
          clearTimeout(timer);
          reject(Error("APPLICATION_STARTUP_FAILED"));
        });
      });
      const base = `http://127.0.0.1:${port}`;
      const session = await fetch(base + "/api/session");
      assert.equal(session.status, 200);
      const cookie = session.headers.get("set-cookie");
      for (const flag of ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"])
        assert.equal(cookie.includes(flag), true);
      const body = await session.json();
      assert.equal(body.status, "anonymous");
      for (const [headers, status, code] of [
        [{}, 401, "BROWSER_REQUIRED"],
        [
          {
            cookie: cookie.split(";")[0],
            origin: "https://other.example",
            "x-csrf-token": body.csrf,
          },
          403,
          "CSRF_REFUSED",
        ],
        [
          { cookie: cookie.split(";")[0], origin, "x-csrf-token": "wrong" },
          403,
          "CSRF_REFUSED",
        ],
        [
          { cookie: cookie.split(";")[0], origin, "x-csrf-token": body.csrf },
          400,
          "REQUEST_BAD_REQUEST",
        ],
      ]) {
        const result = await fetch(base + "/api/interactions", {
          method: "POST",
          headers: { ...headers, "content-type": "application/json" },
          body: JSON.stringify({ profile: "not-authorized" }),
        });
        assert.equal(result.status, status);
        assert.deepEqual(await result.json(), { error: { code } });
      }
    } finally {
      if (child.exitCode === null) {
        child.kill("SIGTERM");
        await ended;
      }
    }
  },
);
