import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const npmRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const repositoryRoot = path.resolve(npmRoot, "..");

export const platforms = Object.freeze([
  {
    target: "aarch64-apple-darwin",
    packageName: "@vibescan/cli-darwin-arm64",
    directory: "cli-darwin-arm64",
    os: "darwin",
    cpu: "arm64",
    binary: "vibescan",
    archive: "vibescan-cli-aarch64-apple-darwin.tar.xz",
  },
  {
    target: "x86_64-apple-darwin",
    packageName: "@vibescan/cli-darwin-x64",
    directory: "cli-darwin-x64",
    os: "darwin",
    cpu: "x64",
    binary: "vibescan",
    archive: "vibescan-cli-x86_64-apple-darwin.tar.xz",
  },
  {
    target: "aarch64-unknown-linux-musl",
    packageName: "@vibescan/cli-linux-arm64-musl",
    directory: "cli-linux-arm64-musl",
    os: "linux",
    cpu: "arm64",
    binary: "vibescan",
    archive: "vibescan-cli-aarch64-unknown-linux-musl.tar.xz",
  },
  {
    target: "x86_64-unknown-linux-musl",
    packageName: "@vibescan/cli-linux-x64-musl",
    directory: "cli-linux-x64-musl",
    os: "linux",
    cpu: "x64",
    binary: "vibescan",
    archive: "vibescan-cli-x86_64-unknown-linux-musl.tar.xz",
  },
  {
    target: "x86_64-pc-windows-msvc",
    packageName: "@vibescan/cli-win32-x64-msvc",
    directory: "cli-win32-x64-msvc",
    os: "win32",
    cpu: "x64",
    binary: "vibescan.exe",
    archive: "vibescan-cli-x86_64-pc-windows-msvc.zip",
  },
]);

export function platformForTarget(target) {
  return platforms.find((platform) => platform.target === target);
}

export function cliVersion() {
  const manifest = fs.readFileSync(
    path.join(repositoryRoot, "crates", "vibescan-cli", "Cargo.toml"),
    "utf8",
  );
  const match = manifest.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) {
    throw new Error("could not read the vibescan-cli version from Cargo.toml");
  }
  return match[1];
}

export function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
