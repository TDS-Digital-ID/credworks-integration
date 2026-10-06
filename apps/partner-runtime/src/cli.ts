import { bootstrapIssuerState } from "./issuer-state.js";
import { configFromEnv, openIdentity, startRuntime } from "./runtime.js";
try {
  const command = process.argv[2];
  if (
    command !== "bootstrap" &&
    command !== "bootstrap-issuer" &&
    command !== "start"
  )
    throw Error("unknown command");
  const config = configFromEnv();
  const identity = openIdentity(config, command === "bootstrap");
  if (command === "bootstrap" || command === "bootstrap-issuer") {
    if (command === "bootstrap-issuer" && !config.issuer)
      throw Error("issuer configuration required");
    if (config.issuer)
      await bootstrapIssuerState(
        config.issuer.databaseUrl,
        config.origin,
        identity,
      );
    console.log(
      JSON.stringify({ did: identity.did, publicJwk: identity.publicJwk }),
    );
  } else {
    const runtime = await startRuntime(config, identity);
    console.log(
      `READY ${JSON.stringify({ public: runtime.public, management: runtime.management })}`,
    );
    process.once("SIGTERM", runtime.close);
    process.once("SIGINT", runtime.close);
  }
} catch {
  console.error(
    "partner_identity_unavailable: check configuration, preserved state, unlock secret and listener availability",
  );
  process.exitCode = 1;
}
