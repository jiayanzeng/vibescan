import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  cliVersion,
  mainPackageName,
  npmRoot,
  platforms,
  readJson,
} from "./platforms.mjs";

function option(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function assertNoInstallFetch(packageManifest, shimSource = "") {
  assert.equal(packageManifest.scripts, undefined, `${packageManifest.name} must have no scripts`);
  assert.doesNotMatch(
    shimSource,
    /\b(?:fetch|XMLHttpRequest|curl|wget)\b|require\(["']node:https?["']\)/,
    "npm shim must not contain a network fetch implementation",
  );
}

function verifySource() {
  const version = cliVersion();
  const main = readJson(path.join(npmRoot, "vibescan", "package.json"));
  const shim = fs.readFileSync(path.join(npmRoot, "vibescan", "bin", "vibescan.js"), "utf8");

  assert.equal(main.name, mainPackageName);
  assert.equal(main.version, version);
  assert.deepEqual(main.bin, { vibescan: "bin/vibescan.js" });
  assert.deepEqual(main.publishConfig, { access: "public", provenance: true });
  assertNoInstallFetch(main, shim);

  const expectedDependencies = Object.fromEntries(
    platforms.map((platform) => [platform.packageName, version]),
  );
  assert.deepEqual(main.optionalDependencies, expectedDependencies);
  for (const dependencyVersion of Object.values(main.optionalDependencies)) {
    assert.match(dependencyVersion, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  }

  const sourceDirectories = fs
    .readdirSync(path.join(npmRoot, "platforms"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(
    sourceDirectories,
    platforms.map((platform) => platform.directory).sort(),
  );

  for (const platform of platforms) {
    const manifest = readJson(
      path.join(npmRoot, "platforms", platform.directory, "package.json"),
    );
    assert.equal(manifest.name, platform.packageName);
    assert.equal(manifest.version, version);
    assert.deepEqual(manifest.os, [platform.os]);
    assert.deepEqual(manifest.cpu, [platform.cpu]);
    assert.equal(manifest.libc, undefined, `${platform.packageName} must not restrict libc`);
    assert.deepEqual(manifest.files, [platform.binary]);
    assert.deepEqual(manifest.publishConfig, { access: "public", provenance: true });
    assertNoInstallFetch(manifest);
  }
}

function extractTarball(tarball, destination) {
  const result = spawnSync("tar", ["-xzf", tarball, "-C", destination], {
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
}

function verifyPacked(packagesRoot) {
  const manifest = readJson(path.join(packagesRoot, "packages.json"));
  const expectedFiles = [
    manifest.main,
    ...Object.values(manifest.platforms).map((platform) => platform.file),
  ].sort();
  const actualFiles = fs
    .readdirSync(packagesRoot)
    .filter((file) => file.endsWith(".tgz"))
    .sort();
  assert.deepEqual(actualFiles, expectedFiles);

  for (const file of expectedFiles) {
    const extractRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vibescan-npm-verify-"));
    try {
      extractTarball(path.join(packagesRoot, file), extractRoot);
      const packageRoot = path.join(extractRoot, "package");
      const packageManifest = readJson(path.join(packageRoot, "package.json"));
      if (packageManifest.name === mainPackageName) {
        const shim = fs.readFileSync(path.join(packageRoot, "bin", "vibescan.js"), "utf8");
        assertNoInstallFetch(packageManifest, shim);
      } else {
        const platform = platforms.find(
          (candidate) => candidate.packageName === packageManifest.name,
        );
        assert.ok(platform, `unexpected packed platform ${packageManifest.name}`);
        assert.ok(fs.statSync(path.join(packageRoot, platform.binary)).isFile());
        assertNoInstallFetch(packageManifest);
      }
    } finally {
      fs.rmSync(extractRoot, { recursive: true, force: true });
    }
  }
}

verifySource();
const packagesRoot = option("--packages");
if (packagesRoot) {
  verifyPacked(path.resolve(packagesRoot));
}
process.stdout.write("npm package contracts verified\n");
