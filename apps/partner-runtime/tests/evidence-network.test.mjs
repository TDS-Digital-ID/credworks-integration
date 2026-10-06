import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:https";
import { execFileSync, execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
const port = Number(process.env.PARTNER_EVIDENCE_HTTP_PORT ?? 33172);

test(
  "default evidence transport retains TLS checks and bounds response bytes, redirects and deadline",
  { timeout: 20000 },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "vc362-tls-"));
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
      ],
      { stdio: "ignore" },
    );
    const server = createServer(
      {
        key: readFileSync(join(dir, "key.pem")),
        cert: readFileSync(join(dir, "cert.pem")),
      },
      (request, response) => {
        if (request.url === "/oversized") response.end("x".repeat(262145));
        else if (request.url === "/redirect") {
          response.writeHead(302, {
            location: `https://localhost:${port}/valid`,
          });
          response.end();
        } else if (request.url === "/deadline") {
          response.writeHead(200);
          response.flushHeaders();
        } else response.end("signed-evidence-fixture");
      },
    );
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", resolve);
    });
    try {
      const code = `import assert from 'node:assert/strict';import {fetchEvidence} from './src/evidence-cache.ts';
 assert.equal(await fetchEvidence('https://localhost:${port}/valid'),'signed-evidence-fixture');
 await assert.rejects(()=>fetchEvidence('https://127.0.0.1:${port}/valid'));
 await assert.rejects(()=>fetchEvidence('https://localhost:${port}/oversized'),/evidence too large/);
 await assert.rejects(()=>fetchEvidence('https://localhost:${port}/redirect'),/fetch failed/);
 const start=Date.now();await assert.rejects(()=>fetchEvidence('https://localhost:${port}/deadline'),/timeout|aborted/i);assert(Date.now()-start<6500);`;
      const result = await promisify(execFile)(
        process.execPath,
        ["--import", "tsx", "--input-type=module", "-e", code],
        {
          cwd: new URL("..", import.meta.url),
          env: { ...process.env, NODE_EXTRA_CA_CERTS: join(dir, "cert.pem") },
          timeout: 15000,
        },
      );
      assert.equal(result.stderr, "");
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
