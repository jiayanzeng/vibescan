import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { platforms, repositoryRoot } from "../scripts/platforms.mjs";

test("publish plan sends platform packages before the main package with provenance", () => {
  const packagesRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vibescan-publish-plan-"));
  try {
    const manifest = {
      main: "vibescan-0.1.0.tgz",
      platforms: {},
    };
    fs.writeFileSync(path.join(packagesRoot, manifest.main), "main");

    for (const platform of platforms) {
      const file = `${platform.directory}-0.1.0.tgz`;
      manifest.platforms[platform.target] = {
        package: platform.packageName,
        file,
      };
      fs.writeFileSync(path.join(packagesRoot, file), platform.target);
    }
    fs.writeFileSync(
      path.join(packagesRoot, "packages.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );

    const result = spawnSync(
      process.execPath,
      [
        path.join(repositoryRoot, "npm", "scripts", "publish-packages.mjs"),
        "--packages",
        packagesRoot,
        "--print-plan",
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);

    const plan = JSON.parse(result.stdout);
    assert.deepEqual(
      plan.map((entry) => entry.name),
      [...platforms.map((platform) => platform.packageName), "vibescan"],
    );
    for (const entry of plan) {
      assert.deepEqual(entry.args, ["--access", "public", "--provenance"]);
    }

    const unsafeDefault = spawnSync(
      process.execPath,
      [
        path.join(repositoryRoot, "npm", "scripts", "publish-packages.mjs"),
        "--packages",
        packagesRoot,
      ],
      { encoding: "utf8" },
    );
    assert.notEqual(unsafeDefault.status, 0);
    assert.match(unsafeDefault.stderr, /choose exactly one mode/i);
  } finally {
    fs.rmSync(packagesRoot, { recursive: true, force: true });
  }
});
