import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { platformForTarget, readJson, repositoryRoot } from "./platforms.mjs";

function option(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function run(command, args, options = {}) {
  return spawnSync(command, args, {
    encoding: "utf8",
    shell: process.platform === "win32",
    ...options,
  });
}

function assertSuccess(result, context) {
  assert.equal(
    result.status,
    0,
    `${context} failed with status ${result.status}\n${result.stdout ?? ""}${result.stderr ?? ""}`,
  );
}

function writeProject(directory) {
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(
    path.join(directory, "package.json"),
    '{"name":"vibescan-smoke","private":true}\n',
  );
}

function initializeFixture(source, destination) {
  fs.cpSync(source, destination, { recursive: true });
  const initialized = run("git", ["-C", destination, "init", "--initial-branch=main"]);
  assertSuccess(initialized, `git init ${destination}`);
}

const packagesRoot = path.resolve(option("--packages") ?? "target/npm-packages");
const target = option("--target");
const platform = platformForTarget(target);
if (!platform) {
  throw new Error(`unsupported or missing --target: ${target ?? "<none>"}`);
}

const manifest = readJson(path.join(packagesRoot, "packages.json"));
const platformRecord = manifest.platforms[target];
assert.ok(platformRecord, `packages.json has no entry for ${target}`);
const mainTarball = path.join(packagesRoot, manifest.main);
const platformTarball = path.join(packagesRoot, platformRecord.file);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const npxCommand = process.platform === "win32" ? "npx.cmd" : "npx";
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vibescan-npm-smoke-"));
const commandEnvironment = {
  ...process.env,
  npm_config_cache: path.join(tempRoot, "npm-cache"),
};

try {
  const workingProject = path.join(tempRoot, "working");
  writeProject(workingProject);
  const installed = run(
    npmCommand,
    [
      "install",
      "--ignore-scripts",
      "--offline",
      "--no-audit",
      "--no-fund",
      "--no-package-lock",
      "--no-save",
      mainTarball,
      platformTarball,
    ],
    { cwd: workingProject, env: commandEnvironment },
  );
  assertSuccess(installed, "npm install --ignore-scripts");

  const version = run(npxCommand, ["--no-install", "vibescan", "--version"], {
    cwd: workingProject,
    env: commandEnvironment,
  });
  assertSuccess(version, "npx vibescan --version");
  assert.match(version.stdout, new RegExp(`vibescan ${manifest.version.replaceAll(".", "\\.")}`));

  const cleanFixture = path.join(tempRoot, "clean");
  const triggerFixture = path.join(tempRoot, "trigger");
  initializeFixture(
    path.join(repositoryRoot, "tests", "fixtures", "clean-control", "repo"),
    cleanFixture,
  );
  initializeFixture(
    path.join(repositoryRoot, "tests", "fixtures", "nested-gitignore", "repo"),
    triggerFixture,
  );

  const clean = run(
    npxCommand,
    ["--no-install", "vibescan", "--no-history", "--format", "json", cleanFixture],
    { cwd: workingProject, env: commandEnvironment },
  );
  assert.equal(clean.status, 0, `${clean.stdout}${clean.stderr}`);

  const trigger = run(
    npxCommand,
    ["--no-install", "vibescan", "--no-history", "--format", "json", triggerFixture],
    { cwd: workingProject, env: commandEnvironment },
  );
  assert.equal(trigger.status, 1, `${trigger.stdout}${trigger.stderr}`);

  const missingProject = path.join(tempRoot, "missing-optional");
  writeProject(missingProject);
  const omitted = run(
    npmCommand,
    [
      "install",
      "--ignore-scripts",
      "--omit=optional",
      "--offline",
      "--no-audit",
      "--no-fund",
      "--no-package-lock",
      "--no-save",
      mainTarball,
    ],
    { cwd: missingProject, env: commandEnvironment },
  );
  assertSuccess(omitted, "npm install --omit=optional");

  const missing = run(npxCommand, ["--no-install", "vibescan", "--version"], {
    cwd: missingProject,
    env: commandEnvironment,
  });
  assert.equal(missing.status, 1);
  const missingOutput = `${missing.stdout}${missing.stderr}`;
  assert.match(missingOutput, /cached across operating systems/i);
  assert.match(missingOutput, /lockfile is stale/i);
  assert.match(missingOutput, /npm ci/i);
  assert.match(missingOutput, /cargo install vibescan-cli/i);
  assert.match(missingOutput, /will not download or execute/i);
  assert.doesNotMatch(missingOutput, /\n\s+at\s/);

  process.stdout.write(`npm smoke passed for ${target}\n`);
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
