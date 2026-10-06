// Fixture-enabled output and execution live outside production native output.
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
if (process.env.PARTNER_REQUIRE_ALL_CHECKS === '1' && (!process.env.PARTNER_ISSUER_DATABASE_URL || !process.env.PARTNER_OTHER_ISSUER_DATABASE_URL || !process.env.PARTNER_CONTAINER_IMAGE)) throw Error('STANDALONE_ACCEPTANCE_INPUTS_REQUIRED');
const root = resolve(import.meta.dirname, "..");
const run = (args, cwd) => {
  const result = spawnSync("pnpm", args, { cwd, stdio: "inherit" });
  if (result.status !== 0) throw Error("fixture conformance command failed");
};
run(["run", "build:test-native"], join(root, "packages/identity-core-node"));
// Docker on macOS cannot mount /var/folders. Keep the disposable exported
// workspace under the ignored, Docker-shared checkout artifact directory.
await mkdir(join(root, '.artifacts'), { recursive: true, mode: 0o700 });
const scratch = await mkdtemp(join(root, '.artifacts', 'credworks-fixture-'));
try {
  for (const path of [
    "apps",
    "infra",
    "packages",
    "vectors",
    "usecases",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "tsconfig.base.json",
  ]) {
    await cp(join(root, path), join(scratch, path), {
      recursive: true,
      filter: (location) =>
        !["node_modules", "native", "native-test"].includes(
          location.split(/[\\/]/).at(-1),
        ),
    });
  }
  await cp(
    join(root, "packages/identity-core-node/native-test"),
    join(scratch, "packages/identity-core-node/native"),
    { recursive: true },
  );
  run(["install", "--frozen-lockfile", "--offline"], scratch);
  run(
    [
      "exec",
      "node",
      "--import",
      "tsx",
      "--test",
      ...[
        "interop",
        "round-trip",
        "scalar-definitions",
        "scalar-renewal-predecessor",
        "scoped-permissions",
        "structured-definitions",
        "issuer-key-authority",
      ].map((name) => `tests/${name}.test.mjs`),
    ],
    join(scratch, "packages/identity-core-node"),
  );
  run(["exec", "node", "--import", "tsx", "--test", "tests/protocol.test.mjs"], join(scratch, "packages/issuer-protocol"));
  run(
    [
      "exec",
      "node",
      "--import",
      "tsx",
      "--test",
      "--test-concurrency=1",
      ...["identity", "sessions", "evidence-network", "scalar-sessions", "verifier-revocation", "issuer", "issuer-lifecycle", "issuer-renewal", "linked-issuance", "issuer-process", "container", "issuer-container"].map(
        (name) => `tests/${name}.test.mjs`,
      ),
    ],
    join(scratch, "apps/partner-runtime"),
  );
} finally {
  await rm(scratch, { recursive: true, force: true });
}
