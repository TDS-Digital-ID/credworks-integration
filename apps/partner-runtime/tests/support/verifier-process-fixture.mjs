import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";

export async function processFixture(f, { controlledClock = false } = {}) {
  const port = Number(process.env.PARTNER_REVOCATION_HTTP_PORT ?? 29210);
  const evidence = createServer((request, response) => {
    const target = new URL(
      request.url,
      "http://fixture.invalid",
    ).searchParams.get("url");
    const signed = f.evidence.get(target);
    response.statusCode = signed ? 200 : 503;
    response.end(signed ?? "unavailable");
  });
  await new Promise((resolve, reject) => {
    evidence.once("error", reject);
    evidence.listen(port, "127.0.0.1", resolve);
  });
  const configPath = join(dirname(f.config.stateDir), "verifier-process.json");
  await writeFile(configPath, JSON.stringify(f.config.verifier), {
    mode: 0o600,
  });
  const children = new Set();
  const clockPath = join(dirname(f.config.stateDir), "verifier-clock.txt");
  let clock = f.clock();
  if (controlledClock)
    await writeFile(clockPath, String(clock), { mode: 0o600 });
  return {
    async setClock(value) {
      if (!controlledClock) throw Error("controlled fixture clock required");
      clock = value;
      await writeFile(clockPath, String(clock));
    },
    async start(index = 0, { fileSizeLimit } = {}) {
      const child = spawn(
        fileSizeLimit === undefined ? process.execPath : "python3",
        fileSizeLimit === undefined
          ? ["--import", "tsx", "tests/support/verifier-process.mjs"]
          : [
              "-c",
              "import os,resource,sys; resource.setrlimit(resource.RLIMIT_FSIZE,(int(sys.argv[1]),int(sys.argv[1]))); os.execv(sys.argv[2],sys.argv[2:])",
              String(fileSizeLimit),
              process.execPath,
              "--import",
              "tsx",
              "tests/support/verifier-process.mjs",
            ],
        {
          cwd: new URL("../..", import.meta.url),
          env: {
            ...process.env,
            PARTNER_ORIGIN: f.config.origin,
            PARTNER_STATE_DIR: f.config.stateDir,
            PARTNER_UNLOCK_KEY: f.config.unlockKey,
            PARTNER_MANAGEMENT_TOKEN: f.config.managementToken,
            PARTNER_ISSUER_CONFIG: "",
            PARTNER_VERIFIER_CONFIG: configPath,
            PARTNER_PUBLIC_PORT: String(port + index * 2 + 1),
            PARTNER_MANAGEMENT_PORT: String(port + index * 2 + 2),
            PARTNER_REVOCATION_TEST_EVIDENCE_SOURCE: `http://127.0.0.1:${port}`,
            PARTNER_REVOCATION_TEST_CLOCK_FILE: controlledClock
              ? clockPath
              : "",
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      children.add(child);
      let output = "",
        errors = "";
      child.stderr.on("data", (bytes) => {
        errors += bytes;
      });
      const runtime = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          reject(Error("verifier fixture deadline"));
        }, 15000);
        child.once("error", (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.once("exit", () => {
          clearTimeout(timer);
          reject(Error("verifier fixture exited: " + errors));
        });
        child.stdout.on("data", (bytes) => {
          output += bytes;
          const ready = /^READY (.+)$/m.exec(output);
          if (ready) {
            clearTimeout(timer);
            resolve(JSON.parse(ready[1]));
          }
        });
      });
      const app = (path, body, capability) =>
        fetch(runtime.management + path, {
          method: body === undefined ? "GET" : "POST",
          headers: {
            authorization: "Bearer " + f.config.managementToken,
            "content-type": "application/json",
            ...(capability ? { "x-session-capability": capability } : {}),
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
      return {
        ...f,
        runtime,
        app,
        clock: () => (controlledClock ? clock : Math.floor(Date.now() / 1000)),
        async stop() {
          if (child.exitCode === null && child.signalCode === null) {
            const exited = once(child, "exit");
            child.kill("SIGTERM");
            await exited;
          }
        },
      };
    },
    async close() {
      for (const child of children)
        if (child.exitCode === null && child.signalCode === null) {
          const exited = once(child, "exit");
          child.kill("SIGTERM");
          await exited;
        }
      evidence.closeAllConnections();
      await new Promise((resolve) => evidence.close(resolve));
    },
  };
}
