// Test-only finite evidence transport mapping. All signatures, authority,
// filesystem publication and verifier decisions run through production code.
import {
  configFromEnv,
  openIdentity,
  startRuntime,
} from "../../src/runtime.ts";
import { didWebToHttpsUrl } from "@unsw-vc/identity-core-node";
import { readFileSync } from "node:fs";
const config = configFromEnv();
const source = process.env.PARTNER_REVOCATION_TEST_EVIDENCE_SOURCE;
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(source ?? ""))
  throw Error("fixture source required");
const allowed = new Set([
  didWebToHttpsUrl(config.verifier.issuerDid),
  ...config.verifier.statusSources.map((entry) => entry.url),
  ...config.verifier.scalar.definitions.flatMap((entry) => [
    config.verifier.registryOrigin +
      `/issuer-authorizations/${entry.authorizationId}.jwt`,
    ...entry.profiles.map(
      (profile) =>
        config.verifier.registryOrigin +
        `/scoped-verifier-permissions/${profile.permissionId}.jwt`,
    ),
  ]),
]);
const runtime = await startRuntime(config, openIdentity(config), {
  ...(process.env.PARTNER_REVOCATION_TEST_CLOCK_FILE
    ? {
        clock: () =>
          Number(
            readFileSync(
              process.env.PARTNER_REVOCATION_TEST_CLOCK_FILE,
              "utf8",
            ),
          ),
      }
    : {}),
  fetchEvidence: async (target) => {
    if (!allowed.has(target)) throw Error("fixture destination refused");
    const response = await fetch(
      source + "/?url=" + encodeURIComponent(target),
      {
        redirect: "error",
        signal: AbortSignal.timeout(5000),
      },
    );
    if (!response.ok) throw Error("fixture evidence unavailable");
    const text = await response.text();
    if (Buffer.byteLength(text) > 262144)
      throw Error("fixture evidence too large");
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
