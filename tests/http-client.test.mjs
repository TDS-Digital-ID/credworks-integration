import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:https";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { httpClient } from "../tool/http-client.mjs";
test("public HTTPS client rejects redirects and streamed oversized responses without body diagnostics", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kit-tls-"));
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      join(dir, "key.pem"),
      "-out",
      join(dir, "cert.pem"),
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
  const ca = readFileSync(join(dir, "cert.pem"));
  let presentationBytes = 0;
  const server = createServer(
    { key: readFileSync(join(dir, "key.pem")), cert: ca },
    (req, res) => {
      req.on("data", (chunk) => {
        presentationBytes += chunk.length;
      });
      if (req.url === "/history") {
        res.end("x".repeat(200000));
      } else if (req.url === "/redirect") {
        res.writeHead(302, { location: "/success" });
        res.end();
      } else if (req.url === "/large") {
        res.end("credential-secret".repeat(20000));
      } else {
        res.writeHead(503);
        res.end("credential-secret");
      }
    },
  );
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const client = httpClient({
    ca,
    lookup: (_host, opts, callback) =>
      opts.all
        ? callback(null, [{ address: "127.0.0.1", family: 4 }])
        : callback(null, "127.0.0.1", 4),
  });
  const origin = `https://localhost:${server.address().port}`;
  try {
    assert.throws(() => httpClient({ rejectUnauthorized: false }), {
      message: "HTTPS_OPTIONS_REFUSED",
    });
    await assert.rejects(
      client(`https://wrong.example:${server.address().port}/failure`),
      { message: "HTTP_TRANSPORT_UNAVAILABLE" },
    );
    await assert.rejects(client(origin + "/redirect"), {
      message: "HTTP_REDIRECT_REFUSED",
    });
    await assert.rejects(client(origin + "/large"), {
      message: "HTTP_RESPONSE_TOO_LARGE",
    });
    await assert.rejects(client(origin + '/history'), { message: 'HTTP_RESPONSE_TOO_LARGE' });
    assert.equal((await client(origin + '/history', { responseLimit: 262144 })).text.length, 200000);
    await assert.rejects(client(origin + '/history', { responseLimit: Infinity }), { message: 'HTTP_RESPONSE_LIMIT_REFUSED' });
    let clock = 10;
    const delayed = httpClient(
      {
        ca,
        lookup: (_host, opts, callback) => {
          clock = 20;
          opts.all
            ? callback(null, [{ address: "127.0.0.1", family: 4 }])
            : callback(null, "127.0.0.1", 4);
        },
      },
      undefined,
      () => clock,
    );
    await assert.rejects(
      delayed(origin + "/presentation", {
        method: "POST",
        body: "credential-secret",
        deadline: 20,
      }),
      { message: "FRESHNESS_CHECK_FAILED" },
    );
    assert.equal(presentationBytes, 0);
    await assert.rejects(client(origin + '/definition', { method: 'POST', body: 'x'.repeat(200000) }), { message: 'HTTP_REQUEST_TOO_LARGE' });
    assert.equal((await client(origin + '/definition', { method: 'POST', body: 'x'.repeat(200000), requestLimit: 262144 })).status, 503);
    await assert.rejects(client(origin + '/definition', { method: 'POST', body: 'x', requestLimit: Infinity }), { message: 'HTTP_REQUEST_LIMIT_REFUSED' });
    const response = await client(origin + "/failure");
    assert.equal(response.status, 503);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});
