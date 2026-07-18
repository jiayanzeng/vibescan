import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { platforms, readJson } from "./platforms.mjs";

function option(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function publishArgs(tarball, dryRun) {
  const args = ["publish", tarball, "--access", "public", "--provenance"];
  if (dryRun) {
    args.push("--dry-run");
  }
  return args;
}

const packagesRoot = path.resolve(option("--packages") ?? "target/npm-packages");
const printPlan = process.argv.includes("--print-plan");
const dryRun = process.argv.includes("--dry-run");
const publish = process.argv.includes("--publish");
assert.equal(
  Number(printPlan) + Number(dryRun) + Number(publish),
  1,
  "choose exactly one mode: --print-plan, --dry-run, or --publish",
);
const manifest = readJson(path.join(packagesRoot, "packages.json"));

const plannedPackages = platforms.map((platform) => {
  const record = manifest.platforms[platform.target];
  assert.ok(record, `packages.json has no entry for ${platform.target}`);
  assert.equal(record.package, platform.packageName);
  return {
    name: record.package,
    tarball: path.join(packagesRoot, record.file),
  };
});
plannedPackages.push({
  name: "vibescan",
  tarball: path.join(packagesRoot, manifest.main),
});

for (const planned of plannedPackages) {
  assert.ok(fs.statSync(planned.tarball).isFile(), `${planned.tarball} is not a file`);
}

const plan = plannedPackages.map((planned) => ({
  name: planned.name,
  tarball: path.basename(planned.tarball),
  args: publishArgs(planned.tarball, dryRun).slice(2),
}));

if (printPlan) {
  process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  process.exit(0);
}

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
for (const planned of plannedPackages) {
  process.stdout.write(`publishing ${planned.name}\n`);
  const result = spawnSync(npmCommand, publishArgs(planned.tarball, dryRun), {
    encoding: "utf8",
    shell: process.platform === "win32",
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`npm publish failed for ${planned.name} with status ${result.status}`);
  }
}
