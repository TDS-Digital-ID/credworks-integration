import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
test("standalone builds default to fixture-free production addon", () => {
  const binding = JSON.parse(
    readFileSync("packages/identity-core-node/package.json"),
  );
  assert.match(binding.scripts["build:native"], /--features partner-runtime/);
  assert.match(binding.scripts["build:test-native"], /native-test/);
  const workspace = readFileSync("Cargo.toml", "utf8");
  assert.doesNotMatch(workspace, /bindings-python|bindings-dart|oidf-/);
});
