import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { readFileSync, readdirSync } from "node:fs";
const require = createRequire(import.meta.url);
const nativeDir = join(
  dirname(dirname(require.resolve("@unsw-vc/identity-core-node"))),
  "native",
);
const addon = require(join(nativeDir, "index.cjs"));
assert.equal(addon.installDeterministicTestKeyRaw, undefined);
assert.equal(addon.installDeterministicTestX509KeyRaw, undefined);
assert.equal(typeof addon.persistentSigningKeyRaw, "function");
const binaries = readdirSync(nativeDir).filter((name) =>
  name.endsWith(".node"),
);
assert.equal(binaries.length, 1);
const bytes = readFileSync(join(nativeDir, binaries[0]));
const issuer = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
const holder = Buffer.from([
  ...Array.from({ length: 31 }, (_, index) => 31 - index),
  1,
]);
assert.equal(
  bytes.includes(issuer),
  false,
  "fixture issuer scalar remains in addon",
);
assert.equal(
  bytes.includes(holder),
  false,
  "fixture holder scalar remains in addon",
);
console.log(
  "packaged addon excludes fixture exports/private scalars and retains persistent identity",
);
