import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  cliVersion,
  mainPackageName,
  npmRoot,
  platformForTarget,
  platforms,
  readJson,
} from "./platforms.mjs";

function option(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: process.platform === "win32",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed with status ${result.status}\n${result.stdout ?? ""}${result.stderr ?? ""}`,
    );
  }
  return result.stdout;
}

function walkFiles(root) {
  const files = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const absolute = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(absolute));
    } else if (entry.isFile()) {
      files.push(absolute);
    }
  }
  return files;
}

function findArtifact(artifactsRoot, fileName) {
  const matches = walkFiles(artifactsRoot).filter(
    (candidate) => path.basename(candidate) === fileName,
  );
  assert.equal(
    matches.length,
    1,
    `expected exactly one ${fileName} under ${artifactsRoot}, found ${matches.length}`,
  );
  return matches[0];
}

function extractBinary(archive, platform, scratchRoot) {
  const extractRoot = fs.mkdtempSync(path.join(scratchRoot, "extract-"));
  if (archive.endsWith(".zip")) {
    run("unzip", ["-q", archive, "-d", extractRoot]);
  } else if (archive.endsWith(".tar.xz")) {
    run("tar", ["-xJf", archive, "-C", extractRoot]);
  } else {
    throw new Error(`unsupported release archive: ${archive}`);
  }

  const matches = walkFiles(extractRoot).filter(
    (candidate) => path.basename(candidate) === platform.binary,
  );
  assert.equal(
    matches.length,
    1,
    `expected exactly one ${platform.binary} in ${archive}, found ${matches.length}`,
  );
  return matches[0];
}

function pack(packageRoot, outputRoot, cacheRoot) {
  const output = run(
    process.platform === "win32" ? "npm.cmd" : "npm",
    ["pack", "--json", "--cache", cacheRoot, "--pack-destination", outputRoot],
    { cwd: packageRoot },
  );
  const records = JSON.parse(output);
  assert.equal(records.length, 1, `npm pack returned ${records.length} records`);
  return records[0].filename;
}

const outputRoot = path.resolve(option("--out") ?? "target/npm-packages");
const requestedTarget = option("--target");
const directBinary = option("--binary");
const artifactsRoot = option("--artifacts");

if (Boolean(requestedTarget) !== Boolean(directBinary)) {
  throw new Error("--target and --binary must be supplied together");
}
if (Boolean(artifactsRoot) === Boolean(requestedTarget)) {
  throw new Error("supply either --artifacts or the --target/--binary pair");
}

const selectedPlatforms = requestedTarget
  ? [platformForTarget(requestedTarget)]
  : [...platforms];
if (selectedPlatforms.some((platform) => !platform)) {
  throw new Error(`unsupported target: ${requestedTarget}`);
}

const version = cliVersion();
const mainTemplate = path.join(npmRoot, "vibescan");
const mainManifest = readJson(path.join(mainTemplate, "package.json"));
assert.equal(
  mainManifest.name,
  mainPackageName,
  "main npm package name is not the approved scoped identity",
);
assert.equal(mainManifest.version, version, "main npm package version must match vibescan-cli");

const scratchRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vibescan-npm-pack-"));
const stageRoot = path.join(scratchRoot, "stage");
const cacheRoot = path.join(scratchRoot, "npm-cache");
fs.mkdirSync(stageRoot, { recursive: true });
fs.mkdirSync(outputRoot, { recursive: true });

try {
  const stagedMain = path.join(stageRoot, "vibescan");
  fs.cpSync(mainTemplate, stagedMain, { recursive: true });
  fs.chmodSync(path.join(stagedMain, "bin", "vibescan.js"), 0o755);

  const manifest = {
    version,
    main: pack(stagedMain, outputRoot, cacheRoot),
    platforms: {},
  };

  for (const platform of selectedPlatforms) {
    const templateRoot = path.join(npmRoot, "platforms", platform.directory);
    const platformManifest = readJson(path.join(templateRoot, "package.json"));
    assert.equal(platformManifest.name, platform.packageName);
    assert.equal(platformManifest.version, version);

    const stagedPlatform = path.join(stageRoot, platform.directory);
    fs.cpSync(templateRoot, stagedPlatform, { recursive: true });

    const sourceBinary = requestedTarget
      ? path.resolve(directBinary)
      : extractBinary(
          findArtifact(path.resolve(artifactsRoot), platform.archive),
          platform,
          scratchRoot,
        );
    assert.ok(fs.statSync(sourceBinary).isFile(), `${sourceBinary} is not a file`);

    const stagedBinary = path.join(stagedPlatform, platform.binary);
    fs.copyFileSync(sourceBinary, stagedBinary);
    if (platform.os !== "win32") {
      fs.chmodSync(stagedBinary, 0o755);
    }

    manifest.platforms[platform.target] = {
      package: platform.packageName,
      file: pack(stagedPlatform, outputRoot, cacheRoot),
    };
  }

  fs.writeFileSync(
    path.join(outputRoot, "packages.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
} finally {
  fs.rmSync(scratchRoot, { recursive: true, force: true });
}
