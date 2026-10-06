// Test-only fixed transport mapping. Production runtime configuration and all core trust/proof
// decisions are unchanged. Public signed evidence is served by an independent HTTP fixture.
import {
  configFromEnv,
  openIdentity,
  startRuntime,
} from "../../src/runtime.ts";
const config = configFromEnv();
const source = process.env.PARTNER_ISSUER_TEST_EVIDENCE_SOURCE;
if (!source || !/^http:\/\/127\.0\.0\.1:\d+$/.test(source))
  throw Error("test evidence source required");
const runtime = await startRuntime(config, openIdentity(config), {
  fetchEvidence: async (target) => {
    const url = new URL(target);
    if (url.origin !== config.issuer.registryOrigin)
      throw Error("test evidence origin mismatch");
    const response = await fetch(source + url.pathname, {
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw Error("test evidence unavailable");
    const text = await response.text();
    if (Buffer.byteLength(text) > 262144)
      throw Error("test evidence too large");
    return text;
  },
});
console.log(
  "READY " +
    JSON.stringify({ public: runtime.public, management: runtime.management }),
);
for (const signal of ["SIGTERM", "SIGINT"])
  process.once(signal, () => {
    void runtime.close().then(() => process.exit(0));
  });
