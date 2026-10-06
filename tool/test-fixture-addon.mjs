// Fixture-enabled output and execution live outside production native output.
import { cp, mkdtemp, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
const root = resolve(import.meta.dirname, "..");
const run = (args, cwd) => {
  const result = spawnSync("pnpm", args, { cwd, stdio: "inherit" });
  if (result.status !== 0) throw Error("fixture conformance command failed");
};
run(["run", "build:test-native"], join(root, "packages/identity-core-node"));
const scratch = await mkdtemp(join(tmpdir(), "credworks-fixture-"));
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
        "scoped-permissions",
      ].map((name) => `tests/${name}.test.mjs`),
    ],
    join(scratch, "packages/identity-core-node"),
  );
  run(
    [
      "exec",
      "node",
      "--import",
      "tsx",
      "--test",
      "--test-concurrency=1",
      ...["identity", "sessions", "evidence-network", "container"].map(
        (name) => `tests/${name}.test.mjs`,
      ),
    ],
    join(scratch, "apps/partner-runtime"),
  );
} finally {
  await rm(scratch, { recursive: true, force: true });
}
