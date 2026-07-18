#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { spawnSync } = require("node:child_process");

const PLATFORM_PACKAGES = Object.freeze({
  "darwin-arm64": {
    packageName: "@vibescan/cli-darwin-arm64",
    binaryName: "vibescan",
  },
  "darwin-x64": {
    packageName: "@vibescan/cli-darwin-x64",
    binaryName: "vibescan",
  },
  "linux-arm64": {
    packageName: "@vibescan/cli-linux-arm64-musl",
    binaryName: "vibescan",
  },
  "linux-x64": {
    packageName: "@vibescan/cli-linux-x64-musl",
    binaryName: "vibescan",
  },
  "win32-x64": {
    packageName: "@vibescan/cli-win32-x64-msvc",
    binaryName: "vibescan.exe",
  },
});

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function missingOptionalDependency(packageName, cause) {
  const detail = cause && cause.code ? ` (${cause.code})` : "";
  fail(
    [
      `@vibescan/cli could not find its platform package ${packageName}${detail}.`,
      "The optional dependency was probably skipped because node_modules was cached across operating systems, optional dependencies were disabled, or the lockfile is stale.",
      "Reinstall `@vibescan/cli` with `npm ci` on a clean tree and do not share node_modules across operating systems.",
      "If optional packages are intentionally disabled, use `cargo install vibescan-cli` or the shell installer from the GitHub release instead.",
      "vibescan will not download or execute a replacement binary automatically.",
    ].join("\n"),
  );
}

function resolveBinary() {
  const override = process.env.VIBESCAN_BINARY_PATH;
  if (override) {
    return path.resolve(process.cwd(), override);
  }

  const platformKey = `${process.platform}-${process.arch}`;
  const platformPackage = PLATFORM_PACKAGES[platformKey];
  if (!platformPackage) {
    fail(
      `vibescan does not provide a prebuilt binary for ${process.platform}/${process.arch}. Use \`cargo install vibescan-cli\` or the shell installer instead.`,
    );
  }

  try {
    const packageJson = require.resolve(`${platformPackage.packageName}/package.json`);
    return path.join(path.dirname(packageJson), platformPackage.binaryName);
  } catch (error) {
    missingOptionalDependency(platformPackage.packageName, error);
  }
}

const binaryPath = resolveBinary();
const result = spawnSync(binaryPath, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  fail(`vibescan could not start ${binaryPath}: ${result.error.message}`);
}

process.exit(result.status ?? 1);
