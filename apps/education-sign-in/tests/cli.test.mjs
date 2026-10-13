import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

test("startup names missing configuration without printing configured secrets", () => {
  const secret = "must-not-appear-in-startup-output";
  const result = spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts"], {
    cwd: new URL("..", import.meta.url),
    env: { PATH: process.env.PATH, PARTNER_MANAGEMENT_TOKEN: secret },
    encoding: "utf8",
    timeout: 10000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /education_application_configuration_missing: EDUCATION_APP_ORIGIN/);
  assert.match(result.stderr, /EDUCATION_APP_DATABASE_URL/);
  assert.doesNotMatch(result.stderr, new RegExp(secret));
  assert.equal(result.stdout, "");
});
