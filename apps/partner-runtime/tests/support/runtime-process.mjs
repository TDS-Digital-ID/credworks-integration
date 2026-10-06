// Test-only process boundary: keys stay in each child's Rust signer handles.
import { openIdentity, startRuntime } from "../../src/runtime.ts";
let runtime;
let clock;
process.on(
  "message",
  async ({ id, action, config, bootstrap, now, sources }) => {
    try {
      if (action === "start") {
        clock = now;
        const identity = openIdentity(config, bootstrap);
        runtime = await startRuntime(config, identity, {
          clock: () => clock,
          fetchEvidence: async (url) => {
            const parsed = new URL(url);
            const source =
              parsed.origin === config.verifier.registryOrigin
                ? sources.registry
                : sources.status;
            const response = await fetch(
              source + parsed.pathname + parsed.search,
              { signal: AbortSignal.timeout(5000) },
            );
            clock = Math.max(clock, Math.floor(Date.now() / 1000));
            if (!response.ok) throw Error("fixture evidence unavailable");
            return response.text();
          },
        });
        process.send({
          id,
          value: {
            public: runtime.public,
            management: runtime.management,
            identity,
          },
        });
      } else if (action === "clock") {
        if (now !== undefined) clock = now;
        process.send({ id, value: clock });
      } else throw Error("unknown fixture action");
    } catch {
      process.send({ id, error: "partner_identity_unavailable" });
    }
  },
);
process.once("SIGTERM", () => {
  runtime?.close();
  process.exit(0);
});
