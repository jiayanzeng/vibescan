import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const npmRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const shim = path.join(npmRoot, "vibescan", "bin", "vibescan.js");
const exitFixture = path.join(npmRoot, "test", "fixtures", "exit-code.mjs");

function shimEnv(overrides = {}) {
  const env = { ...process.env, ...overrides };
  delete env.NODE_OPTIONS;
  return env;
}

test("shim preserves zero and nonzero child exit codes", () => {
  for (const expected of [0, 7]) {
    const result = spawnSync(process.execPath, [shim, exitFixture, String(expected)], {
      encoding: "utf8",
      env: shimEnv({ VIBESCAN_BINARY_PATH: process.execPath }),
    });
    assert.equal(result.status, expected, result.stderr);
  }
});

test("missing optional dependency is actionable and never downloads", () => {
  const env = shimEnv();
  delete env.VIBESCAN_BINARY_PATH;

  const result = spawnSync(process.execPath, [shim, "--version"], {
    encoding: "utf8",
    env,
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /optional dependency was probably skipped/i);
  assert.match(result.stderr, /cached across operating systems/i);
  assert.match(result.stderr, /lockfile is stale/i);
  assert.match(result.stderr, /npm ci/i);
  assert.match(result.stderr, /@vibescan\/cli/i);
  assert.match(result.stderr, /cargo install vibescan-cli/i);
  assert.match(result.stderr, /will not download or execute/i);
  assert.doesNotMatch(result.stderr, /\n\s+at\s/);
});
