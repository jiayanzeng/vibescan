# vibescan — Codex Instructions: Track G (release & distribution)

Reviewed: 2026-07-18
Author: architecture review (Claude), for implementation by Codex

## How to consume this document

This is the distribution track — architecture **§13.1** (single static binary; the
five-target matrix; npm as the primary channel with `cargo install` and Homebrew
secondary). It is **orthogonal to the scan engine**: it touches CI, packaging, and
a thin JS shim, not detections or correlation, so it can proceed in parallel with
Tracks E/F under a separate owner. It is also, per the roadmap, **decision-first** —
the release-architecture decisions are made in G0 below and then built.

Three dependency-ordered tasks in the house format. Authority is
`vibescan-architecture.md`, **not** `STATE.md`.

Build order (respect it — G1's release-ready workspace + `dist` scaffold is what
G2/G3 publish from):

1. **G1 — Release-ready workspace + `dist` cross-compile matrix** (P1; §13.1)
2. **G2 — The npm channel (`npx @jiayanzeng/vibescan`), ships-not-downloads**
   (P1; §13.1, §13.4)
3. **G3 — Secondary channels (`cargo install`, Homebrew) + provenance + runbook** (P1; §13.1)

**Verification surface (read this up front).** Unlike Tracks C–F, Track G **cannot
be fully validated in a single Linux sandbox** — you cannot execute the macOS/Windows
binaries here, and the npm platform-package behavior is inherently multi-OS. Its
acceptance criteria are therefore **release-CI-observable** (a tagged build producing
N artifacts + checksums + attestations; a per-platform `npx --version` smoke matrix)
plus a **local `dist plan` / Linux-target `dist build` dry run**. This mirrors how
Tier D's real-repo validation is CI-gated rather than sandbox-proven. Do not fake a
single-sandbox test that pretends to prove cross-platform distribution.

---

## G0 — Release-architecture decisions (made here; one item flagged for the spec)

Three decisions §13.1 leaves to implementation, resolved:

**1. Orchestrator: adopt `dist` (axodotdev, formerly `cargo-dist`).** It is the
tool the Rust ecosystem converged on for exactly this problem: it cross-compiles the
target matrix (macOS native, Linux via `cargo-zigbuild`, Windows via `cargo-xwin`),
generates the tag-triggered GitHub release CI, and emits installers — **including the
npm installer** (the optionalDependencies platform-package pattern), a Homebrew
formula, shell/PowerShell installers, unified checksums, and **GitHub Artifact
Attestations** for provenance. Hand-rolling a five-target matrix + an npm shim +
a Homebrew formula from scratch would reinvent all of this worse. Use `dist`; the
tasks below are mostly `dist` configuration plus the workspace prep it requires.

**2. Linux is musl-static, not glibc-dynamic.** §13.1 says **single static binary,
no C-toolchain / runtime dependency**. `dist` defaults Linux to glibc-dynamic with a
glibc-version preflight check — that violates the invariant and reintroduces the
"which glibc?" compatibility problem `npx` users must never hit. Configure the Linux
targets as **`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`** so the
binary is truly static and runs anywhere. This is the whole point of the pure-Rust
constraint (gix, rustls, no OpenSSL): musl-static is painless *because* nothing links
libc/OpenSSL.

**3. The npm channel ships binaries; it never downloads-and-executes at install.**
§13.1 phrases the npm channel as one that "ships/downloads" the binary — an either/or.
**Resolved to *ships*, and this is a hard security requirement, not a preference.** A
`postinstall` that fetches-and-runs a binary is *precisely the pattern vibescan
flags in other people's projects*; a security scanner must not ship it. It also
breaks under `npm --ignore-scripts` and in air-gapped/locked-down CI — exactly where
security-conscious users run. So the npm channel uses **per-platform packages via
`optionalDependencies`** (the esbuild/swc/Biome/Turbo pattern, which `dist` generates)
with **no download-executing postinstall**. Users who disable optional dependencies
get a clear error pointing at `cargo install`/the shell installer, never a silent
fetch. (Verified current pattern: platform packages carry `os`/`cpu` (and `libc`)
fields; npm installs only the match; exact versions are required for reproducibility.)

> **Spec item to surface (do not silently resolve):** §13.1's "ships/downloads"
> should be narrowed to "ships (never downloads-and-executes at install), for the
> security-posture reasons in G2." Flag a one-line §13.1 clarification in the PR; the
> architecture owner applies it. Do not edit §13.1 from within this change.

---

## Task G1 — Release-ready workspace + `dist` cross-compile matrix

### Spec basis

- **§13.1:** single static binary; targets macOS arm64/x64, Linux x64/arm64,
  Windows x64; pure-Rust so per-target prebuilds are painless.
- **§13.1 secondary channel `cargo install`:** implies the workspace must be
  crates.io-publishable — which it currently is **not**.

### Problem (root-caused)

- **No release pipeline exists.** `.github/workflows/` contains only `ci.yml`
  (fmt/clippy/test/boundary). There is no tag-triggered build, no cross-compilation,
  no artifact upload.
- **The workspace is not crates.io-publishable.** Root `Cargo.toml`
  `workspace.dependencies` use **path-only** deps (e.g. `vibescan-core = { path =
  "crates/vibescan-core" }`, no `version`). crates.io rejects path-only intra-workspace
  deps; publish requires `{ path = "...", version = "..." }`. `dist init` also errors
  on absent/placeholder `repository` URLs (the workspace `repository` is
  `github.com/vibescan/vibescan` — confirm it is the real repo before release).
- The binary is named `vibescan` (`crates/vibescan-cli` `[[bin]] name = "vibescan"`),
  which is the artifact `dist` and the npm shim key off.

### File targets

- **New:** `dist-workspace.toml` (or `[workspace.metadata.dist]` in root
  `Cargo.toml`) — the `dist` config; **new** `.github/workflows/release.yml` —
  generated by `dist init`/`dist generate` (do **not** hand-edit generated CI beyond
  `dist`'s config).
- **Edit:** root `Cargo.toml` — add `version = "..."` alongside every intra-workspace
  `path` dependency; confirm `repository`.
- **Edit:** `rust-toolchain.toml` (new if absent) — pin the toolchain the release
  builds use (matches `rust-version = "1.85"`), and declare the musl targets.

### Implementation guidance

**Publish-readiness (do first).** For each `vibescan-*` intra-workspace dependency in
`workspace.dependencies`, add a `version` matching the crate's `version` (all are
`0.1.0`). This makes them dual path+version deps: `cargo build` uses the path,
crates.io uses the version. No behavior change; it only unblocks publishing (G3) and
`dist`.

**`dist` setup.** Run `dist init`; configure:
- `targets`: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
  **`x86_64-unknown-linux-musl`**, **`aarch64-unknown-linux-musl`**,
  `x86_64-pc-windows-msvc` (musl per G0 decision 2).
- `installers`: start with `shell` + `powershell` (npm and Homebrew are added in
  G2/G3 as separate, reviewable steps).
- `ci = github`; enable GitHub Artifact Attestations; enable the unified checksum
  file.
- Note the documented constraint: `cargo-zigbuild` cross-compile and
  `cargo-auditable` are mutually exclusive. If a `cargo auditable`-style embedded
  dependency manifest is wanted, decide it here (it trades against zigbuild
  cross-compile); default to zigbuild cross-compile for the musl targets and record
  the choice.

**Static-linking check.** Add a CI step that asserts the Linux artifacts are actually
static — `ldd <bin>` reports "not a dynamic executable" (or `file` shows
"statically linked"). This is the machine-checkable form of §13.1's single-static-binary
invariant and belongs in the release job, not left to trust.

### Acceptance criteria (self-verifiable / CI-observable)

1. Every intra-workspace dep in root `Cargo.toml` carries a `version`; `cargo build
   --workspace` and the full existing test suite are unchanged and green (path deps
   still used locally).
2. `dist plan` (run locally) succeeds and lists exactly the five targets with musl
   for both Linux arches; `dist build` for the host Linux musl target produces a
   `vibescan` binary.
3. A CI release job (tag-triggered) exists and, on a test tag, produces **five**
   platform artifacts, a unified checksum file, and GitHub Artifact Attestations
   (`gh attestation verify` succeeds against the repo).
4. **Static-linking assertion:** the release job asserts each Linux artifact is
   statically linked (`ldd` "not a dynamic executable"); the job fails if a Linux
   binary is dynamically linked.
5. `cargo fmt`/`clippy -D warnings`/`cargo test --workspace` (and the network/registry
   feature graphs from Tracks E/F, if present) remain green — the release plumbing
   does not disturb the engine.

---

## Task G2 — The npm channel (`npx @jiayanzeng/vibescan`), ships-not-downloads

### Spec basis

- **§13.1 primary channel:** an npm wrapper so
  `npx @jiayanzeng/vibescan` works for the JS-native audience.
- **§13.4 exit codes:** exit `0` when nothing meets the severity gate, non-zero
  otherwise, so CI can fail the build. **The npm shim must pass the child's exit code
  through faithfully** — a wrapper that swallows or remaps it silently breaks every
  CI gate. (`crates/vibescan-cli/src/main.rs` returns the scan's exit code via
  `ExitCode::from(code)`; the shim must preserve it end-to-end.)
- **G0 decision 3:** platform packages via `optionalDependencies`, **no
  download-executing postinstall.**

### Problem (root-caused)

No npm package exists. The naïve approach — a single wrapper with a `postinstall`
that downloads the right binary — is the one Track F would flag as a supply-chain
smell and the one that breaks under `--ignore-scripts`/air-gapped CI. The correct
mechanism (per-platform packages + `optionalDependencies`, os/cpu/libc filtering) is
non-obvious and has a well-known CI failure mode (a cached cross-OS `node_modules` or
a stale lockfile skips the matching optional dep, then the shim can't find a binary),
which the shim must handle with a clear message rather than a stack trace.

### File targets

- **Edit:** the `dist` config — enable the `npm` installer; set the controlled
  personal-scope main package to `@jiayanzeng/vibescan` (no organization is
  required), with per-platform packages such as
  `@jiayanzeng/vibescan-linux-x64-musl`; pin exact versions.
- **Review (do not blindly accept):** the generated npm shim — confirm it uses the
  platform-package/`optionalDependencies` resolution and **not** a
  download-at-postinstall. If `dist`'s npm installer does any install-time fetch,
  **do not ship it as-is**: fall back to hand-rolled esbuild-style packages (a thin
  `@jiayanzeng/vibescan` main package + N
  `@jiayanzeng/vibescan-<os>-<cpu>[-<libc>]` packages, each with
  `os`/`cpu`/`libc` and one binary; main shim does `require.resolve` +
  `spawnSync(bin, process.argv.slice(2))` and re-exits with the child code).
- **New:** an npm smoke test in CI (matrix across the five platforms) that installs
  the freshly-published (or locally-packed) package and runs `vibescan --version`.

### Implementation guidance

**The shim contract (whatever generates it):**
1. Resolve the platform binary via the installed optional package
   (`require.resolve("@jiayanzeng/vibescan-<os>-<cpu>[-<libc>]/vibescan")`), honoring an
   env override (e.g. `VIBESCAN_BINARY_PATH`) for advanced/air-gapped users.
2. `spawnSync(binaryPath, process.argv.slice(2), { stdio: "inherit" })`.
3. **Re-exit with the child's exit code** (`process.exit(result.status ?? 1)`), so
   §13.4's severity-gate code reaches CI unchanged.
4. If resolution fails, print an **esbuild-style actionable error** — name the likely
   cause (optional dependency skipped: cross-OS `node_modules` cache or stale
   lockfile) and the fixes (`npm ci` on a clean tree; don't share `node_modules`
   across OSes; or use `cargo install vibescan-cli` / the shell installer). Never fall
   back to a silent download.

**Static-musl + the `libc` field.** Because the Linux binary is **static musl** (G1),
it runs on both musl and glibc hosts. Do **not** over-constrain the Linux platform
package with `libc: ["musl"]` in a way that excludes glibc hosts — a static binary
has no libc dependency, and excluding glibc Linux would defeat "npx just works."
Verify the resulting package installs on a glibc Linux runner (the smoke matrix
covers this).

**Exact versions.** The main package's `optionalDependencies` must pin the
per-platform packages to the **exact** release version (npm/pnpm reject ranges/tags
for these and it keeps installs reproducible).

### Acceptance criteria (self-verifiable / CI-observable)

1. `npx @jiayanzeng/vibescan@<version> --version` succeeds on **each** of the
   five platforms in a CI smoke matrix (including at least one **glibc** Linux
   runner, proving the static-musl binary installs and runs there).
2. **Exit-code passthrough:** a CI check runs the npm-installed `vibescan` against a
   fixture that trips the severity gate and asserts a **non-zero** exit, and against a
   clean fixture and asserts **zero** — proving the shim preserves §13.4 semantics.
3. **No download-executing postinstall:** the published main package has no
   `postinstall` (or a `postinstall` that does not fetch/execute a binary); installing
   with `npm install --ignore-scripts` still yields a working `vibescan` via the
   optional package. Assert the package tarball contains no network-fetch install
   script.
4. **Graceful skip:** simulating the "optional dependency skipped" state (e.g.
   `--no-optional`) yields the actionable error message (naming cache/lockfile causes
   and the `cargo install` fallback), not a stack trace or a silent download.
5. Per-platform packages pin exact versions in the main package's
   `optionalDependencies`.

---

## Task G3 — Secondary channels, provenance, and the release runbook

### Spec basis

- **§13.1 secondary channels:** `cargo install` and Homebrew.
- **Provenance (implied by shipping a security tool):** artifacts must be verifiable —
  attestations (G1) plus npm publish provenance and a documented, reproducible
  release process.

### Problem (root-caused)

`cargo install vibescan-cli` cannot work until the workspace is published to crates.io in
dependency order, and there is no Homebrew formula, no npm-publish provenance, and no
written release process — so releases would be ad hoc and unverifiable.

### File targets

- **Edit:** the `dist` config — enable the Homebrew installer and (if used) a tap repo;
  enable npm publish provenance.
- **New:** `RELEASING.md` — the tag → build → publish runbook (versioning, crates.io
  publish order, npm/Homebrew publish, attestation verification).
- **Edit:** `.github/workflows/release.yml` (via `dist` config) — the publish steps.

### Implementation guidance

**crates.io publish order.** Publish bottom-up so each crate's dependencies already
exist on the registry: `vibescan-types` → `vibescan-secrets` → `vibescan-git` →
`vibescan-report` → `vibescan-supabase` → (`vibescan-registry`, if Track F landed) →
`vibescan-core` → `vibescan-cli`. `cargo install vibescan-cli` then installs the CLI. (**Package-name decision, ratified:** the Cargo package is `vibescan-cli` per the exact crate DAG and boundary checker, and it installs the `vibescan` binary. The instruction's earlier literal `cargo install vibescan` is corrected to `cargo install vibescan-cli` throughout; no ninth alias crate is added and the architecture DAG is unchanged.) The
version-bearing deps from G1 are the prerequisite. Document this order in `RELEASING.md`
and let `dist`/`cargo` enforce it where possible.

**Homebrew.** Use `dist`'s Homebrew formula generation targeting a tap
(`vibescan/homebrew-tap` or similar). The formula installs the prebuilt binary, not a
from-source build, so it is fast and needs no toolchain.

**Provenance.** Two layers: GitHub Artifact Attestations on the release binaries
(G1), and **npm provenance** on the published packages (`npm publish --provenance`
via GitHub Actions OIDC), so `npm` shows the verified build origin. Ship the unified
checksum file alongside the release.

**Runbook.** `RELEASING.md` covers: how to cut a version (workspace version bump),
what the tag triggers, the crates.io publish order, the npm/Homebrew publish, and how
a *user* verifies an artifact (`gh attestation verify`, checksum, `npm` provenance).
Keep it short and executable.

### Acceptance criteria (self-verifiable / CI-observable)

1. On a test tag, the release job publishes (or dry-run-publishes) the crates in the
   documented dependency order without an unresolved-dependency error; `cargo install
   vibescan-cli` from crates.io installs a working CLI (verifiable post-publish, or via a
   `--dry-run`/`cargo publish -p ... --dry-run` chain in CI).
2. A Homebrew formula is generated and `brew install vibescan/tap/vibescan` yields a
   working `vibescan` (CI or documented manual check).
3. Published npm packages carry provenance (`npm` shows the verified origin);
   release binaries carry attestations that `gh attestation verify` accepts; the
   unified checksum file is present and correct.
4. `RELEASING.md` exists and documents versioning, the crates.io publish order, the
   npm/Homebrew publish, and user-side artifact verification.
5. The engine test suites (default + network + registry graphs) remain green — the
   distribution track never altered scan behavior.

---

## Completion status this track closes

Track G makes vibescan installable the way its audience expects:
`npx @jiayanzeng/vibescan` via per-platform packages with no install-time fetch
(the security-appropriate mechanism),
`cargo install vibescan-cli` from a crates.io-published workspace, and `brew install` from
a tap — all built from a `dist`-orchestrated, tag-triggered release that cross-compiles
**static musl** Linux binaries alongside macOS/Windows, with unified checksums and
GitHub Artifact Attestations, and npm publish provenance. After Track G, the pure-Rust
single-static-binary invariant (§13.1) is not just an architectural claim but a
machine-checked release property, and the tool reaches the JS-native audience §13.1
was written for. This track is orthogonal to the engine; the deferred DAST/write-probe
track (I) remains the only post-v1 work left, security-design-first behind the §7.4
ownership gate.

## Notes for review

- **Track G's verification is CI + `dist plan`, not a single sandbox.** Do not accept
  a self-contained test that claims to prove cross-platform install — the smoke matrix
  and the tagged release are the real evidence. This honesty is the point, the same
  way D1's real-repo validation is CI-gated.
- **The npm "ships not downloads" decision is a security invariant, not a style
  choice** (G0.3). A security scanner shipping a fetch-and-execute postinstall would be
  flagging that exact pattern in users' repos while doing it itself. The acceptance
  test that installing with `--ignore-scripts` still works (G2 #3) is what pins it.
- **musl-static is what makes §13.1 true** (G0.2). `dist`'s glibc default would
  reintroduce the compatibility problem `npx` users must never hit; the `ldd`
  "not a dynamic executable" assertion (G1 #4) is the machine check.
- **Exit-code passthrough is load-bearing for CI adoption** (G2 #2). The whole reason
  §13.4 defines exit codes is so CI can gate on findings; an npm shim that drops the
  child code silently defeats it. Assert both the zero and non-zero cases.
- **Adopt `dist`; don't hand-roll** — but *review* its generated npm installer against
  G0.3 rather than trusting it. If it fetches at install time, fall back to the
  hand-rolled esbuild-style packages. This is the one place to verify rather than
  accept the tool's default.
- **This is decision-first work with one spec item to surface:** §13.1's
  "ships/downloads" should be narrowed to "ships." Flag it in the PR; don't edit the
  architecture from the implementation change.
