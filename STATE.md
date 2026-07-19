# vibescan State

Reviewed: 2026-07-19

Current committed checkout: `4b5fb87` on
`codex/track-g3-release-publishing` (Tasks G4.0–G4.1). Its G3 implementation ancestor
`330a3b2` was merged by pull request #5 to `main` as `cb048b9`. The current
worktree records the completed G4.1 external identity bootstrap after the
release owner configured the required account controls, bootstrap secrets, and
public Homebrew tap without disclosing credential values.

Prior architecture-audit baseline: `e7e9263`.

Authority: `vibescan-architecture.md`. This file records observed status; it
does not override the architecture or prove completion by itself.

## Executive verdict

vibescan is a substantial, runnable local-first Rust CLI. Every build-order
step in architecture section 15 (steps 1–8) has an implementation, Tier C has
landed, Phase 1 preserves exact content/source occurrences, and Phase 2 now
uses that identity for exact Supabase enrichment, conservative project-aware
coalescing, Tier 0 input preparation, and provenance-aware correlation. Phase
3A now distinguishes root-enumeration unavailability from table-level key
rejection, and Phase 3B now scopes typed LocalStatic API references to exact or
unambiguous projects before Tier 0 probing. Phase 3C now records every attempted
Tier 0 root/table GET as redacted scan-scope evidence and renders it in JSON,
SARIF, TTY, and HTML. Phase 4 now enforces the authoritative post-v1
eight-crate DAG across normal, build, dev, target, optional, and
feature-activated dependencies.
Phase 5 now enforces default < repository config < explicit CLI precedence,
strict repository-root path handling, named-baseline failures, and additive
custom rules without allowing repository config alone to enable Network work.

The strict **buildable-v1** verdict is now **complete and proven** through
architecture §15 step 9. Tier E1 added credentialed, read-only Postgres catalog
transport and input plumbing. Tier E2 added the four mechanically decidable
catalog detections and catalog-native evidence. Tier E3 now integrates the two
confirmed Tier 1 read-exposure shapes with both v1 correlation rules, activates
the RLS-off and permissive-policy mock goldens, and incorporates them into the
committed corpus metrics. Track F1 provides the separately gated registry crate,
rustls transport boundary, dependency-input plumbing, explicit CLI opt-in, and
auditable scope shapes. Track F2 adds local OSV snapshot matching, public
package-existence checks, precision guards, failure taxonomy, and 24-hour
public-data caches. Track F3 activates the last gated corpus fixture through a
mock registry and adds it to the committed metrics baseline. Task G1 is
complete: the workspace is publish-ready, `dist` plans exactly the
architecture's five targets with musl-only Linux, the tagged `v0.1.0` release
run produced all five archives plus checksums, the blocking custom job proved
both Linux binaries are static, and all five GitHub Artifact Attestations
verified against the release workflow and merge commit. Task G2 is complete:
the npm shim selects one of five exact-version optional platform packages,
executes only the shipped binary, preserves its exit status, and has passed the
hosted five-platform `npx` smoke matrix. Task G3's local
implementation now wires bottom-up crates.io publication, platform-first npm
publication with OIDC provenance, and cargo-dist's prebuilt Homebrew formula
publisher, and provides an executable release runbook. Task G4.0 is complete:
the release owner selected the controlled personal-scope
`@jiayanzeng/vibescan` entry point, the publisher plans only the six approved
`@jiayanzeng/vibescan*` identities, and neither the third-party-owned unscoped
`vibescan` package nor an unavailable `@vibescan` organization scope is a
publication target.
Task G4.1 is complete: all fourteen registry identities remain free to claim,
the release owner confirmed the crates.io and npm bootstrap secrets plus npm
two-factor authentication, and the public Homebrew tap and its `Formula/`
layout exist with workflow push credentials configured. Track G's operational
rollout remains partial because G4.2 preflight, G4.3 publication, and G4.4
public verification have not run, and
the literal instruction
`cargo install vibescan` conflicts with the architecture-named
`vibescan-cli` package (which installs the `vibescan` binary).
Architecture §17.8 explicitly defers the noisy user-writable-metadata
heuristic, so its absence is not an E2 gap. The verdict for the entire
architecture document is therefore partial.

Use these three lenses when discussing completion:

- **Runnable v1 coverage:** all eight section-15 steps exist and the Phase
  1–5 regression matrix is green.
- **Strict buildable-v1 conformance:** complete. The previously identified
  identity, Network semantics, auditability, crate-DAG, CLI/config,
  real-repository, precision/recall, deterministic performance-counter, and
  resolved-decision ratification blockers are all covered by passing gates.
- **Entire architecture document:** partial. Tier E's E1–E3 implementation,
  Track F's registry intelligence/corpus activation, Track G1–G3's repository
  implementation, G4.0's npm identity decision, and G4.1's external bootstrap
  are complete; G4.2–G4.4 and
  other deferred tracks remain incomplete.

No target-project write path was found. Tier 0 exposes GET only and discards
returned row data after counting. Tier E1's Postgres transport accepts only
validated Supabase DB hosts and ports and issues fixed, read-only catalog
`SELECT`s. E2 infers write exposure only from catalog grants plus policy absence
and never attempts a write. The default production dependency graph remains
transport-free.

## Current worktree context

The checkout was clean at `1dfa85c` when Task G1 began. Pull request
[#1](https://github.com/jiayanzeng/vibescan/pull/1) merged the initial G1
implementation (`1225975`) and its test-fixture portability correction
(`09eb065`) to `main` as `fba689c`. The correction was exposed by the first
hosted branch-push run; no production collection behavior changed. The
annotated `v0.1.0` tag points to that merge. No pre-existing user change was
present or modified.

Task G2 began from a clean `main` at `ac3757a`, after pull request #2 had landed
the G1 close-out record. Pull request
[#3](https://github.com/jiayanzeng/vibescan/pull/3) merged the G2 implementation
commit (`e0092ab`) and verification record (`69167a1`) to `main` as `1dbe6f2`.
No pre-existing user change was present or modified. G2 changes only packaging,
release workflow integration, tests, and documentation; it does not change a
crate, dependency edge, scanner phase, target-project access, or Network
capability.

Task G3 began from a clean `main` at `0ebca9b`, after pull request #4 landed the
G2 close-out record. Work is on `codex/track-g3-release-publishing`; no
pre-existing user change was present or modified. Before the G3 commit, the
worktree intentionally contains only release metadata, generated workflow,
publisher scripts/tests, npm manifest provenance, documentation, and this
status update. It does not change Rust scanner behavior, dependencies, the
eight-crate DAG, target-project access, or any runtime Network capability.

Pull request #5 merged G3 to `main` as `cb048b9` with 26/26 checks green. The
current branch then gained the user-authored documentation commit `4479cfb` and
the user-owned untracked
`docs/vibescan-trackG-closeout-instructions.md`. Task G4.0 began from that
checkout; the untracked instruction file was read and preserved without edits.
After the initial G4.0 commit, the release owner approved correcting the npm
identity to the personal `@jiayanzeng` scope; that correction updates the
instruction file as well. The current G4.0 worktree changes only npm package
identity, publisher/package contract tests, release documentation,
architecture §13.1's approved primary-channel wording, and this status record.
It does not change Rust scanner behavior, the eight-crate DAG, runtime Network
capability, or target-project access.

The corrected G4.0 implementation was committed as `4b5fb87`. The worktree was
clean and synchronized with `origin/codex/track-g3-release-publishing` when the
final G4.1 checks began. G4.1 changes no source, manifest, workflow, crate edge,
or architecture behavior; this status update records only the release owner's
external bootstrap actions and the corresponding read-only acceptance checks.

## Track G4.0 verification observed on 2026-07-19

The release owner approved the controlled personal-scope identity
`@jiayanzeng/vibescan`; `npx @jiayanzeng/vibescan` is the primary npm command.
This corrects the earlier option-1 implementation, which wrongly treated a 404
package lookup as proof that an `@vibescan` organization scope could be created.
The npm user `jiayanzeng` owns the personal `@jiayanzeng` scope without an
organization. The third-party-owned unscoped `vibescan` name and the unavailable
`@vibescan` organization scope are explicitly excluded from the package
manifests, publisher plan, architecture, runbook, and current user-facing
distribution documentation.

The source contract centralizes the main package name as
`@jiayanzeng/vibescan`. `publish-packages.mjs --print-plan` emits the five exact
`@jiayanzeng/vibescan-*` platform identities first and
`@jiayanzeng/vibescan` last; a regression assertion requires every planned
name to begin with `@jiayanzeng/vibescan` and separately rejects the exact
unscoped `vibescan` name. All six planned publishes retain `--access public`
and `--provenance`. The packed main tarball is
`jiayanzeng-vibescan-0.1.0.tgz`, retains the `vibescan` binary name, and has no
lifecycle fetch path.

The following G4.0-specific checks passed without registry mutation:

```sh
npm --prefix npm test
python3 scripts/verify-release-publishing.py
node --check npm/scripts/platforms.mjs
node --check npm/scripts/build-packages.mjs
node --check npm/scripts/verify-packages.mjs
node --check npm/scripts/publish-packages.mjs
node --check npm/scripts/smoke-packages.mjs
node --check npm/vibescan/bin/vibescan.js
node npm/scripts/build-packages.mjs \
  --artifacts target/distrib --out <temporary-directory>
node npm/scripts/verify-packages.mjs --packages <temporary-directory>
node npm/scripts/publish-packages.mjs \
  --packages <temporary-directory> --print-plan
node npm/scripts/smoke-packages.mjs \
  --packages <temporary-directory> --target aarch64-apple-darwin
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/publish-npm.yml")'
```

The current architecture gate also passed: format; all four default,
`network`, `registry`, and combined clippy matrices; all four workspace test
matrices; the Network boundary checker; the local hardening aggregate; and
`git diff --check`. The hardening aggregate explicitly skipped its optional
real-repository leg because no fixture was supplied. The changed npm publisher
workflow also parsed as YAML. A supplemental `dist generate --check` attempt could not
run because the `dist` executable is not installed in the current environment;
that command belongs to the later G4.2 preflight and is not a G4.0 acceptance
criterion. No crate/package identity was claimed, no secret or credential was
handled, no registry publication or tag push occurred, and no live target or
target-project write was used.

G4.0 is complete. G4.1's completed external bootstrap and acceptance checks are
recorded below.

## Track G4.1 bootstrap verification observed on 2026-07-19

The eight official crates.io package endpoints return 404 when queried with an
identifying user agent: `vibescan-types`, `vibescan-secrets`, `vibescan-git`,
`vibescan-report`, `vibescan-supabase`, `vibescan-registry`, `vibescan-core`,
and `vibescan-cli`. None currently resolves to a foreign owner, but all remain
unclaimed. The initial anonymous requests returned a uniform 403; those denials
were discarded as non-evidence and the identifying-user-agent results are the
recorded status.

The official npm registry endpoints for `@jiayanzeng/vibescan` and all five
`@jiayanzeng/vibescan-*` platform packages return 404. None currently resolves
to a foreign owner. The release owner confirms that the new npm username is
`jiayanzeng`; npm automatically assigns that user the personal `@jiayanzeng`
scope, so no organization creation or account conversion is required. The
packages remain unpublished and will be created by their first authorized
publication. The owner confirms that `npm whoami` returns `jiayanzeng`, account
two-factor authentication is enabled, and a short-lived `NPM_TOKEN` bootstrap
secret is present in the `vibescan` repository.

The public `https://github.com/jiayanzeng/homebrew-tap` repository and its
`Formula/` layout both return 200. The owner confirms that a least-privilege
`HOMEBREW_TAP_TOKEN` secret capable of writing formula commits to that tap is
present in the `vibescan` repository. The owner also confirms the earlier
crates.io email/account verification and presence of the one-time
`CARGO_REGISTRY_TOKEN` bootstrap secret. Secret values and secret-setting APIs
were not read, logged, or exercised.

The final acceptance check ran `git status --short --branch`, `git rev-parse
--short HEAD`, and anonymous read-only HTTPS status requests against the
official crates.io, npm, and GitHub endpoints. The initial crates.io requests
without identification returned 403 and were repeated with an identifying user
agent; only the resulting eight 404 responses are evidence. The six npm
requests returned 404, and the tap plus `Formula/` requests returned 200.

No crate, npm package, formula, or tag was published. The release owner created
the public tap and configured account controls/secrets as the explicitly
authorized G4.1 external mutations; Codex did not access credentials or perform
those mutations. None of the fourteen registry targets resolves to a third
party. G4.1 is **complete**. The next task is G4.2's fully reversible preflight;
G4.3's immutable version/tag/publication work must not begin until G4.2 passes.
After the first publication, configure trusted publishing for all eight crates
and six npm packages, then remove both registry bootstrap secrets.

The prior Track F baseline commits Tasks F1–F3 and CF1. F1 adds the
architecture-authorized eighth crate, `vibescan-registry`, with only the allowed
`vibescan-registry -> vibescan-types` edge. Core owns parsing and orchestration;
the CLI exposes `--registry-checks` only under its independent `registry`
feature. Repository configuration cannot confirm Registry egress, and registry
opt-in does not enable either RLS tier.

The registry crate's private transport feature is named `transport`, while the
public core/CLI feature is `registry`. This is intentional: Cargo applies a
workspace-wide `--features network` to every member with that feature name, so
calling the private feature `network` would wrongly activate registry transport
during a Supabase-only build. The boundary checker now validates default,
Supabase-only, registry-only, and combined graphs and rejects unauthorized
nearest transport parents.

F1 parses deterministic npm and Python dependency inputs and publishes
defaulted Registry scope/action/disclosure shapes. F2 matches exact resolved
versions locally against cached OSV ecosystem snapshots and checks public,
unscoped npm/PyPI names for existence. Scoped npm names, structurally invalid
dependencies, and ecosystems configured for alternate/private registries do not
drive the public-404 rule. Both public-data caches use a 24-hour TTL, and cache
hits issue no request. Tests use mocks and local cache fixtures only. No live
registry, OSV, database, or target-project Network action was run.

F3 materializes a public unscoped nonexistent-package fixture, drives F2 through
an injected 404 source, and keeps a scoped npm 404 in the same manifest as a
negative control. Its reviewed golden contains exactly one High confirmed
`NonexistentPackage` finding. The committed metrics baseline has
`corpus_version` `tier-f3-live-v1` and records 14 TP, 0 FP, 0 FN, precision 1.0,
recall 1.0, and coverage 0.75. No capability-gated corpus fixture remains;
remaining ignored tests are feature-off stubs.

All Phase 1–5, Tier D, Tier E, and Track F regressions are green in the default,
`network`, `registry`, and combined workspace matrices.

## Track G1 verification observed on 2026-07-18

G1 is release/distribution plumbing under architecture §13.1. It does not
change scan behavior, the crate DAG, the LocalStatic default, runtime Network
consent, or target-project access. Every intra-workspace dependency now carries
both its local path and matching `0.1.0` registry version. The workspace
repository URL now matches the checkout's actual `origin`,
`https://github.com/jiayanzeng/vibescan`, rather than the prior placeholder.

The checksum-verified official `dist` 0.32.0 binary initialized
`dist-workspace.toml` and generated `.github/workflows/release.yml`. The plan
contains exactly `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and
`x86_64-pc-windows-msvc`; no GNU/Linux artifact is planned. Shell and PowerShell
installers are enabled. At G1 closeout, npm and Homebrew remained G2/G3 work.
SHA-256 emits the unified `sha256.sum`, and GitHub Artifact Attestations are
enabled in the generated platform build jobs.

The generated workflow reaches a configured global-artifact job only after all
platform archives exist. That reusable job requires exactly two Linux musl
archives, extracts one `vibescan` binary from each, requires `file` to report
static/static-PIE linkage, and rejects an ELF interpreter or any `NEEDED`
shared-library entry with `readelf`. Its success is a prerequisite for hosting
the release. The generated workflow itself was not hand-edited; regenerating it
from `dist-workspace.toml` is clean.

Both Linux targets were also cross-built locally from the macOS arm64 host with
temporary `cargo-zigbuild` 0.23.0 and Zig 0.16.0 tooling. `file` reported both
ELFs as `statically linked`, and both archive SHA-256 files verified. `dist`
0.32.0 has removed the older cargo-zigbuild/cargo-auditable incompatibility
described in the G1 instruction note; G1 still deliberately leaves
`cargo-auditable = false` so embedded dependency metadata is not silently added
to this release-only task.

The first hosted branch-push run, GitHub Actions run `29646107632`, exposed an
existing fixture dependency on the runner's global Git default branch. The
all-ref history test ran `git init`, created `feature`, then assumed the initial
branch was named `main`; Ubuntu initialized `master`, so checkout failed and
poisoned the fixture's shared Git environment lock. The regression reproduces
locally by injecting `init.defaultBranch=master`. The fixture now uses
`git init --initial-branch=main`, making its branch contract explicit without
changing production code or adding a runtime Git dependency.

The following commands passed on this G1 worktree using pinned Rust 1.85.0:

```sh
cargo build --workspace --locked
dist generate
dist plan
dist build --artifacts=local --target=x86_64-unknown-linux-musl
dist build --artifacts=local --target=aarch64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/dist/vibescan \
  target/aarch64-unknown-linux-musl/dist/vibescan
shasum -a 256 -c vibescan-cli-x86_64-unknown-linux-musl.tar.xz.sha256
shasum -a 256 -c vibescan-cli-aarch64-unknown-linux-musl.tar.xz.sha256
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=init.defaultBranch \
  GIT_CONFIG_VALUE_0=master cargo test -p vibescan-git --locked \
  tests::history_scan_collects_changed_blobs_from_all_refs -- --exact
cargo test -p vibescan-git --locked
cargo test -p vibescan-core --test golden_corpus --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

Measured workspace results are **171 passed, 4 ignored** by default, **184
passed, 1 ignored** with `network`, **183 passed, 3 ignored** with `registry`,
and **196 passed, 0 ignored** with both features. The hardening aggregate passed
and emitted `real-repo leg skipped: no fixture`. Those local checks used no live
target, credential, registry lookup, package publication, or external Network
probe.

Pull request #1's final branch revision passed all 21 applicable GitHub Actions
checks; its five release-only jobs were correctly skipped before tagging. The
tagged [release run
29646459806](https://github.com/jiayanzeng/vibescan/actions/runs/29646459806)
then completed successfully. It built exactly the five planned platform
archives, passed the custom static-Linux job for both musl targets, generated
the global artifacts, hosted the release, and completed the announcement job.

The public [`v0.1.0`
release](https://github.com/jiayanzeng/vibescan/releases/tag/v0.1.0) contains
the five platform archives, one source archive, the shell and PowerShell
installers, `dist-manifest.json`, the unified `sha256.sum`, and the corresponding
per-archive checksum files. All six entries in the unified checksum file (the
source archive and five platform archives) verified after download with:

```sh
shasum -a 256 -c sha256.sum
```

GitHub published exactly five [artifact
attestations](https://github.com/jiayanzeng/vibescan/attestations), one for each
platform archive. Each public Sigstore bundle verified offline with a
checksum-verified temporary GitHub CLI 2.94.0 binary and this command shape:

```sh
gh attestation verify <archive> \
  --repo jiayanzeng/vibescan \
  --bundle <bundle> \
  --signer-workflow jiayanzeng/vibescan/.github/workflows/release.yml
```

All five verifications identified `release.yml@refs/tags/v0.1.0` as the signer
and `fba689c83a776a6a7bb025f04d9ce439683980b8` as the source repository digest.
The only external mutations were the approved branch push, pull request merge,
tag push, and GitHub-hosted release in the project's own repository. No live
target, credential, registry query, crates.io/npm/Homebrew publication, or
target-project write was used.

G1 is complete. G2 is complete. G3 is not started.
The Track G review must also flag architecture §13.1's `ships/downloads` wording
for the architecture owner to narrow to ships-only; neither G1 nor G2 edits the
architecture.

## Track G2 verification observed on 2026-07-18

G2 implements the npm distribution channel under architecture §§13.1 and
13.4. The official `dist` 0.32 npm installer was evaluated and rejected for
this task because its generated install path fetches a release binary. That
contradicts Track G's ships-only invariant. The implementation therefore uses
the instruction-set fallback: a small hand-rolled CommonJS shim in the
unscoped `vibescan` package plus five platform packages, integrated into the
existing `dist` release as a custom global-artifact job. The built-in `dist`
npm installer remains disabled.

The main `vibescan@0.1.0` manifest exposes `bin.vibescan` and names all five
platform packages as exact `0.1.0` `optionalDependencies`; no version range is
used. Each platform manifest declares its supported `os` and `cpu`, contains
only the corresponding release binary, and has no lifecycle script. The two
Linux packages deliberately omit npm's `libc` restriction because their musl
binaries are static and must install on glibc hosts as well as musl hosts.

At execution time the shim maps `process.platform` plus `process.arch` to the
matching installed package, resolves that package locally, and synchronously
spawns its binary with unchanged arguments and inherited standard streams. It
exits with the child's status. It contains no fetch implementation and has no
postinstall hook. When optional dependencies were skipped, it exits 1 without a
stack trace and explains cross-OS `node_modules` caches, stale lockfiles,
`npm ci`, `cargo install vibescan-cli`, and the shell-installer alternative while
stating that no replacement binary will be downloaded or executed
automatically.

The release workspace now lists `./package-npm` as a custom global artifact
job. The generated release workflow invokes the reusable npm packaging workflow
only after the five platform archives exist; hosting depends on the npm job as
well as the pre-existing static-Linux gate. The npm job extracts the five
release binaries, creates the unscoped package and all five platform tarballs,
verifies their packed contents, uploads them as release artifacts, and runs the
same five-platform smoke matrix used on pull requests. This is packaging only:
G2 did not publish to npm or query the live npm registry.

The source contract tests verify the exact platform set and versions, `os` /
`cpu` selectors, absence of lifecycle scripts and fetch primitives, shim exit
status propagation, and the missing-optional-package failure. A full local
six-tarball build used the five downloaded `v0.1.0` G1 archives. Packed-package
verification passed, and the macOS arm64 smoke installed the local tarballs
with `--ignore-scripts --offline`, ran `npx --no-install vibescan --version`,
proved scan exit 0 on the clean fixture and exit 1 on a High-trigger fixture,
then proved the actionable no-download error after `--omit=optional`.

The following local commands passed on the G2 worktree:

```sh
npm --prefix npm test
node npm/scripts/build-packages.mjs \
  --artifacts /private/tmp/vibescan-gh.N3e4g9 \
  --out /private/tmp/vibescan-g2-all-packages.7gtU3a
node npm/scripts/verify-packages.mjs \
  --packages /private/tmp/vibescan-g2-all-packages.7gtU3a
node npm/scripts/smoke-packages.mjs \
  --packages /private/tmp/vibescan-g2-all-packages.7gtU3a \
  --target aarch64-apple-darwin
dist generate
dist plan
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

`dist plan` retained exactly the five G1 targets. Regenerating
`.github/workflows/release.yml` from `dist-workspace.toml` was clean, all three
affected workflow files parsed as YAML, and every JavaScript file passed
`node --check`. The hardening aggregate reported its optional real-repository
leg as skipped; no user repository was supplied.

Pull request #3's final branch revision `69167a1` passed 27 applicable GitHub
Actions checks with six expected release-only skips. Its npm jobs passed the
source contract and native smoke tests on macOS arm64, macOS x64, static-musl
Linux arm64, static-musl Linux x64 on a glibc runner, and Windows x64. Each
native smoke built the target binary, packed only the local main/platform
tarballs, installed them offline with lifecycle scripts disabled, verified
`npx vibescan --version`, verified scan exit statuses 0 and 1, and exercised the
skipped-optional-dependency error.

No live target, credential, registry query, npm/crates.io/Homebrew publication,
or target-project write was used. G2 is complete. At G2 closeout, G3 remained
unstarted and owned npm publication/provenance plus the Homebrew formula.
Architecture §13.1 still needs the review-time one-line clarification from
`ships/downloads` to `ships`;
G2 deliberately does not edit the architecture.

## Track G3 implementation verification observed on 2026-07-18

G3 is deferred distribution work under architecture §13.1. It does not alter
the scanner pipeline, LocalStatic default, runtime Network consent, Registry
egress, secret handling, or target-project safety. The exact eight-crate DAG is
unchanged.

All eight Cargo packages now inherit the public homepage and package the root
README. `scripts/publish-crates.sh` encodes the documented dependency order:
types, secrets, git, report, supabase, registry, core, then CLI. Its default is
fail-closed: callers must choose `--dry-run` for deterministic local packaging
contract checks or `--publish` for a live registry mutation. The generated
release workflow invokes the live mode only after GitHub hosting succeeds. It
uses an optional first-release `CARGO_REGISTRY_TOKEN`, otherwise the official
crates.io trusted-publishing action supplies a short-lived token through OIDC;
the token remains in the environment and is not placed on a process command
line.

The Cargo package name remains `vibescan-cli`, as required by the exact package
DAG and boundary checker, while its binary remains `vibescan`. An offline local
`cargo install --path crates/vibescan-cli` installed and ran `vibescan 0.1.0`.
The Track G instruction's literal `cargo install vibescan` cannot resolve this
package name. Renaming the CLI package or adding a ninth alias crate would
contradict the current architecture and requires an explicit specification
decision; G3 does neither. The truthful registry command is
`cargo install vibescan-cli`, which installs the `vibescan` executable.

All six npm manifests request public provenance publication. The custom
publisher validates the packed manifest, publishes the five exact platform
packages first, then publishes unscoped `vibescan` last, and passes
`--provenance` explicitly. Like the Cargo publisher, it refuses an invocation
that does not choose exactly one of `--print-plan`, `--dry-run`, or `--publish`.
The reusable workflow uses Node 24, `id-token: write`, an optional bootstrap
`NPM_TOKEN`, and the packed artifacts already built and smoke-tested by G2. It
does not introduce an install-time fetch or enable cargo-dist's fetch-based npm
installer.

`dist` 0.32.0 now generates `vibescan.rb` and publishes it to the configured
`jiayanzeng/homebrew-tap` only after hosting. The formula selects four macOS /
Linux prebuilt archives, carries their SHA-256 values, and installs the shipped
`vibescan` binary without a Rust toolchain. The prior successful `v0.1.0` CI
platform artifacts were downloaded from GitHub Actions through the signed-in
project session; every artifact zip matched the digest reported by GitHub.
Replaying the global cargo-dist build with those four platform manifests
produced a checksum-bearing formula. A temporary local tap installed it,
`/opt/homebrew/bin/vibescan --version` returned `vibescan 0.1.0`, and the test
installation and tap were removed afterward.

Homebrew auto-updated itself while performing the functional check and installed
its audit gem bundle. The audit command also enabled Homebrew developer mode;
that mode was explicitly returned to off after the test. No `vibescan` formula
or `vibescan-test/tap` entry remains installed.

Current Homebrew rejects formula file paths for both audit and install, which
is why the functional check used a temporary tap. `brew audit --strict` ran by
tap name and reported cargo-dist-generated strict/style findings (including no
`test do` block and formatting rules). The generated publisher itself runs
`brew style --fix` with cargo-dist's documented exclusions before committing;
the stronger functional install still passed. No generated formula is checked
into this repository.

`RELEASING.md` documents immutable versioning, all eight Cargo and six npm
publisher identities, bootstrap tokens, trusted-publisher migration, the exact
publication orders, tap setup, tag behavior, checksums, GitHub attestation
verification, npm signature/provenance checks, and per-channel install checks.
README and npm fallback text now use the architecture-correct
`cargo install vibescan-cli` command and do not claim that registry packages or
the tap already exist.

The following G3-specific checks passed:

```sh
npm --prefix npm test
python3 scripts/verify-release-publishing.py
bash scripts/publish-crates.sh --dry-run
node npm/scripts/build-packages.mjs \
  --artifacts target/distrib --out target/npm-packages
node npm/scripts/verify-packages.mjs --packages target/npm-packages
node npm/scripts/publish-packages.mjs \
  --packages target/npm-packages --print-plan
dist generate --check
dist plan --output-format=json
dist build --tag=v0.1.0 --artifacts=global --allow-dirty
ruby -c target/distrib/vibescan.rb
cargo install --offline --locked --path crates/vibescan-cli \
  --root /private/tmp/vibescan-g3-install.zbayG1
/private/tmp/vibescan-g3-install.zbayG1/bin/vibescan --version
brew install vibescan-test/tap/vibescan
/opt/homebrew/bin/vibescan --version
```

All GitHub workflow files parsed as YAML. The full architecture gate also
passed on this worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The hardening aggregate's optional real-repository leg was skipped because no
fixture was supplied. No golden or report snapshot changed. No live npm or
crates.io query/publication was run, no public tap was created by this work, no credential
was handled, and no tag was pushed. A trial offline `cargo package --no-verify`
of a parent crate correctly failed because its versioned workspace dependencies
do not yet exist in the crates.io index; the deterministic `--dry-run` contract
therefore uses `cargo package --list` for every crate, while the hosted live job
will prove registry resolution after the one-time bootstrap.

G3's repository implementation is locally verified, but its external
acceptance remains partial until the release owner creates/controls the eight
crates.io names and six npm identities in the approved personal scope, creates
`jiayanzeng/homebrew-tap`, configures bootstrap secrets and then trusted
publishers, and cuts a new immutable version tag. Those are explicit external
mutations and were not inferred from approval to implement G3. After that tag,
the owner must verify all package pages show the intended provenance and all
three public install commands succeed. The `cargo install vibescan` naming
conflict remains an architecture-owner decision.

## Track F verification and close-out re-audit observed on 2026-07-18

The exact post-v1 eight-crate DAG is enforced across all declared dependency
kinds and resolved feature graphs. The default graph has no transport, the
Supabase-only graph cannot activate registry transport, the registry-only graph
cannot activate Supabase transport, and the combined graph permits only the two
architecture-authorized nearest parents. Synthetic negative controls reject a
registry-to-LocalStatic edge, LocalStatic transport leakage, an unauthorized
nearest parent, sibling/direct dependency drift, and OpenSSL/native-tls.

Types compatibility tests prove older serialized scope records default the new
Registry fields. Core and CLI tests pin deterministic npm/scoped-npm/PyPI input
shapes, exact lockfile versions, runtime opt-in, repository-config inertness,
feature-off failure, and independence from both RLS tiers. Registry tests pin
Critical confirmed OSV matches without name egress, High confirmed public 404s
with auditable name egress, resolvable controls, precision guards, nonfatal
failure taxonomy, duplicate coalescing, and zero-request cache hits. Report
tests and reviewed snapshots disclose Registry activity without secrets or
absolute paths. F3's shared mock helper proves the public name resolves once,
the scoped name is never queried, and the golden/metrics harnesses observe the
same single High finding.

CF1 now pins F2 acceptance criterion 4 clause 3 with a composed core regression:
all LocalStatic structural findings survive both a registry outage and an OSV
snapshot failure without manufacturing a `NonexistentPackage` finding.
The subsequent close-out re-audit found CF1–CF2 and F1–F3 complete against the
current implementation, fixtures, committed metrics, CI, and boundary policy;
no residual Tier F acceptance gap remains.

The following pass is green on the committed Track F/CF1 baseline:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-core --features registry registry_failure_tests --locked
cargo test -p vibescan-core --features network,registry registry_failure_tests --locked
cargo test -p vibescan-registry --features transport --locked
cargo test -p vibescan-core --test golden_corpus --features network,registry --locked
cargo test -p vibescan-core --test precision_recall --features registry --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
cargo test -p vibescan-report --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The snapshot update was run only after the additive Registry scope fields and
synthetic disclosure action were intentional, reviewed, and rerun without the
update guard. F3's golden and metrics updates were separately regenerated,
reviewed, and rerun without their update guards. The hardening helper emitted
`real-repo leg skipped: no fixture`.

## Tier E3 verification observed on 2026-07-18

Core unit tests prove rule 1 fires from standalone-Critical `RlsDisabled` and
`PermissivePolicy` evidence with no `RlsProbe` present. Negative controls prove
missing-operation, inferred-write, and known-different-project policy findings
cannot fire the read chain. A committed elevated-key case proves rule 2 includes
Tier 1 policy evidence.

Both promoted fixtures run `introspect_tier1_with_source` through a deterministic
mock and assert three catalog `SELECT` actions. RLS-off produces one absorbed
Critical composite. The permissive fixture produces the absorbed Critical
composite plus the three valid Medium default-deny operation advisories from E2.
Reviewed goldens contain only the environment-source sentinel and repo-relative
client path; they contain no DB URL, password, row data, timestamp, or absolute
host path. At that checkpoint, `hallucinated-dependency` was the only remaining
capability-gated fixture; Track F3 has since promoted it under `registry`.

The current committed metrics baseline includes both fixtures and Track F3. Its
`corpus_version` is `tier-f3-live-v1`, with **14 TP, 0 FP, 0 FN, precision 1.0,
recall 1.0, and coverage 0.75**. The clean-control FP gate remains zero, and the
negative recall/FP controls still fail when intentionally perturbed.

The following pass is green on the current Tier E3 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test golden_corpus --features network --locked
cargo test -p vibescan-core --test precision_recall --locked
cargo test -p vibescan-core --test precision_recall --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

Measured workspace results are **153 passed, 4 ignored** by default and **166
passed, 1 ignored** with `network`. The hardening helper's self-tests, workspace
tests, and boundary leg passed; its optional real-repository leg printed
`real-repo leg skipped: no fixture`. No live target or credential was used.

## Tier E2 verification observed on 2026-07-18

Mock-catalog tests pin each E2 finding independently: RLS disabled, normalized
literal `USING (true)`, one missing `SELECT` policy, and an `anon` `INSERT` grant
without an operation policy. Negative controls reject `is_active = true`,
`true_flag`, and `is_true(...)` as permissive policies; ignore catalog tables
outside the project-scoped LocalStatic candidate set; and suppress policy
conclusions when the policy query fails. A named test proves the metadata-keyed
heuristic is absent. The production query guard still accepts only catalog
`SELECT`s and rejects `SET`/DML controls.

Architecture §17.8's severity and wording contract is pinned directly: RLS
disabled and literal-true permissive policies are Critical standalone,
inferred-write exposure is High, and a missing-operation policy is a Medium
default-deny advisory for `anon`/`authenticated`, never described as an open or
exposed operation.

`Evidence::RlsPolicy` round-trips through JSON and carries project, table,
command, `USING`, `WITH CHECK`, `rowsecurity`, and exposure. Catalog actions omit
the inapplicable row-count field. Serialized mock output contains the intended
policy predicate but no DB password, mock row markers, application row values,
or count. The four report snapshots were regenerated under `UPDATE_GOLDEN=1`,
reviewed, and rerun without the variable; no absolute path or raw credential was
introduced.

The following pass is green on the current Tier E2 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-types --locked
cargo test -p vibescan-supabase --locked
cargo test -p vibescan-supabase --features network --locked
cargo test -p vibescan-report --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test precision_recall --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

No live Network action or credentialed database connection was run. At this E2
checkpoint, the Tier 1 goldens were still gated; Tier E3 has since promoted them
through the mock-catalog orchestration recorded above.

## Tier E1 verification observed on 2026-07-18

The production Postgres dependency is optional under `network`, nearest-parented
by `vibescan-supabase`, rustls-backed, and absent from the default graph. The
boundary checker rejects OpenSSL/native-tls and confirms the four production
`LocalStatic` libraries remain transport-free. Mock-catalog tests cover query
ordering, action serialization, early rejection of invalid hosts/schemes/ports,
project mismatch, query failures, secret-safe errors/debug output, and the
fixed-`SELECT` query guard. CLI regressions cover both opt-in directions,
repository-config inertness, and exit 2 when the Tier 1 credential is absent.

The following pass is green on the current Tier E1 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-supabase --locked
cargo test -p vibescan-supabase --features network --locked
cargo test -p vibescan-types --locked
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked
cargo test -p vibescan-cli --features network --locked
cargo test -p vibescan-report --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
python3 scripts/check-network-boundary.py --self-test
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

No golden manifest or report snapshot changed. No real credential was placed in
configuration, logs, tests, fixtures, actions, or persisted output. Architecture
§7.2 still describes a service-role key and a DB URL as interchangeable Tier 1
inputs; E1 follows the task's catalog-access rationale and implements only the
DB-URL path. The architecture owner should clarify that wording rather than
silently treating PostgREST service-role access as policy-catalog access.
The hardening aggregate passed and emitted the required explicit
`real-repo leg skipped: no fixture` note.

## Tier D4 verification observed on 2026-07-18

The new core integration test plants one synthetic `sb_secret_*` value in a
temporary Git repository, runs `scan_and_render` for JSON, SARIF, HTML, and TTY,
and proves that every format contains the redacted evidence but not the raw
body. It separately serializes the full `ScanResult` and proves the same
candidate-to-finding boundary. The report integration test pins presentation of
the supplied redacted evidence in all four formats. No production behavior or
snapshot changed.

At the Tier D4 checkpoint, the existing
`gitignored_env_fixture_has_exact_elevated_key_finding` test was the §17.1 pin:
a gitignored `.env` containing an elevated new-format key produces exactly one
`Critical` `SecretNew` finding. No duplicate assertion was added.
At that checkpoint, the gated RLS fixtures said `TODO(tier1)`; the
hallucinated-dependency fixture said
`TODO(registry)`, and the mocked exposed-public-key chain remains
`TODO(network)` in default builds.

The following pass is green on the current Tier D4 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-core --test redaction_boundary --locked
cargo test -p vibescan-report --test report_snapshots --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --lib \
  gitignored_env_fixture_has_exact_elevated_key_finding --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The default workspace matrix reports **132 passed, 4 intentionally ignored**;
the `network` matrix reports **137 passed, 3 intentionally ignored**. The
hardening aggregate reruns the default matrix and checker self-tests, confirms
the seven-crate/transport boundary, and emits the required loud
`real-repo leg skipped: no fixture` note. No live Network action was run.

## Tier D3 verification observed on 2026-07-15

`ScanStats` now publishes `paths_walked`, `blobs_read`, `unique_contents`,
`units_materialized`, and `truncated` as defaulted integer/boolean fields. The
collector owns the pre/post-dedup measurements; core copies them into the scan
result. Dedup ratio is derived from the exact counts at report time and is not
stored as a float. An older-shape `ScanResult` JSON fixture without the five
fields still deserializes and round-trips with zero/false defaults.

The generated fixture creates 40 byte-deterministic TypeScript files with 30
unique contents and 10 intentional duplicates. Two independent scans both
produce **40 paths, 40 blobs, 30 unique contents, 30 materialized units, and a
25.00% dedup ratio**. The pre-dedup negative control records 40 would-be unique
inputs and proves the production counter differs by exactly 10. Explicit
`--nocapture` runs recorded values from 12–33 ms; these values are logged only
and no test compares or gates wall time. Existing default/network workspace CI
jobs pick up the integration test automatically.

The following pass is green on the current Tier D3 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-types --locked
cargo test -p vibescan-git --locked
cargo test -p vibescan-report --locked
cargo test -p vibescan-core --test perf_counters --locked -- --nocapture
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh --offline-only
git diff --check
```

The default workspace matrix reports **130 passed, 4 intentionally ignored**;
the `network` matrix reports **135 passed, 3 intentionally ignored**. Golden
manifests are unchanged because their builder still canonicalizes findings
only. JSON, SARIF, TTY, and HTML report snapshots were intentionally regenerated
and reviewed to expose the counters and derived ratio; no raw secret or
absolute path was introduced. No live Network action was run.

## Tier D2 verification observed on 2026-07-15

The D2 harness shares the golden corpus's seven live repository fixtures and
adds the offline composite exposed-public-key chain. It reads the existing
`expected.json` manifests as truth, matches path-independent
`(rule_id, fingerprint, normalized_project)` identities, and excludes all three
ignored/gated fixtures from the metric. Explicit truth annotations supply
stable non-path subjects for the two dependency findings and the absorbed
composite finding without changing the existing golden assertions.

The committed `tier-d2-live-v1` baseline records **8 TP, 0 FP, 0 FN, precision
1.0, recall 1.0, and classification coverage 0.6**. Coverage is exactly 3/5:
the history-only `src/history.ts` and nested
`packages/nested/ignored-but-scanned/secret.ts` findings are legitimately
`Unknown`, while the other three eligible live findings are classified. The
in-memory bogus-truth control produces one FN and trips the recall gate; an
injected clean-control finding produces one FP and trips the independent clean
gate.

The following pass on the current combined D1/D2 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-core --test precision_recall --locked
cargo test -p vibescan-core --test precision_recall --features network --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test golden_corpus --features network --locked
UPDATE_METRICS=1 cargo test -p vibescan-core --test precision_recall --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The default workspace matrix reports **126 passed, 4 intentionally ignored**;
the `network` matrix reports **131 passed, 3 intentionally ignored**. The
baseline SHA-256 was
`3d5ef933fca6a00460b84904fadfe19a3d2fe947a7232fe961f5763ceeba106f` both
before and after `UPDATE_METRICS=1`, proving byte-identical regeneration on the
unchanged corpus. No live Network action was run.

## Tier D1 verification observed on 2026-07-15

The following pass on the current Tier D1 worktree:

```sh
python3 scripts/real-repo-invariants.py --self-test
python3 scripts/real-repo-invariants.py \
  tests/fixtures/offline-composite-exposed-public-key-chain/expected.json
bash -n scripts/verify-hardening-checks.sh
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci.yml")'
bash scripts/verify-hardening-checks.sh
bash scripts/verify-hardening-checks.sh --real-repo-only \
  /Users/yzjia/test/astroscout
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --features network --locked
git diff --check
```

The no-argument hardening command runs the default workspace matrix (**123
passed, 4 intentionally ignored**), the checker self-tests, and the Network
boundary, then emits `real-repo leg skipped: no fixture`. The Network workspace
matrix reports **128 passed, 3 intentionally ignored**. A synthetic Git-backed
smoke target exercised the real-only path, sanitized zero-finding control, and
planted positive control; its positive run emitted
`REALREPO_INVARIANTS ok coverage=100.00% findings=1 projects=0`.

The explicitly supplied AstroScout repository then passed the complete
LocalStatic real-repository leg, including both controls, and emitted
`REALREPO_INVARIANTS ok coverage=100.00% findings=3 projects=1`. This records a
genuine §17 coverage data point without changing the `src/api/` rule. No live
Supabase target was contacted. The private-fixture CI job requires
`VIBESCAN_REAL_REPO_REPOSITORY` plus `VIBESCAN_REAL_REPO_TOKEN` and reports a
loud skip when they are absent.

## Phase 5 verification observed on 2026-07-12

The following pass on the current Phase 5 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-secrets --locked
cargo test -p vibescan-core --locked
cargo test -p vibescan-cli --locked
cargo test -p vibescan-cli --features network --locked
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test golden_corpus --features network --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The default workspace matrix reports 123 passed and 4 intentionally ignored;
the `network` matrix reports 128 passed and 3 intentionally ignored. The CLI
real-binary suite passes 12/12 in both modes. The hardening aggregate passes and
skips its optional real-repository leg because no fixture was supplied. No live
Network action was run.

## Phase 4 verification observed on 2026-07-12

The following pass on the current Phase 4 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-git --locked
cargo test -p vibescan-supabase --locked
cargo test -p vibescan-core --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

The boundary checker confirms the exact seven-crate DAG in both metadata
graphs and runs synthetic positive/negative controls for a sibling
dev-dependency, an unauthorized direct/optional edge, and LocalStatic transport
leakage. The two unfiltered workspace commands were also run; both stop only at
the same three pre-existing Phase 5 CLI/baseline tests. The local hardening
aggregate was run and stops at those same tests before its boundary leg. No live
Network action was run.

## Phase 3C verification observed on 2026-07-12

The following pass on the current Phase 3C worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-types --locked
cargo test -p vibescan-supabase --features network --locked
cargo test -p vibescan-report --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
bash scripts/check-network-boundary.sh
git diff --check
```

The two unfiltered workspace commands were also run. In both default and
`network` modes, they stop only at the same three pre-existing Phase 5
CLI/baseline regressions named above; no Phase 3C test failed. No live Network
action was run.

## Phase 3B verification observed on 2026-07-12

The following pass on the current Phase 3B worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
bash scripts/check-network-boundary.sh
git diff --check
```

No live Network action was run. The remaining deliberate reds are exactly the
three Phase 5 CLI/baseline cases.

## Phase 3A verification observed on 2026-07-12

The following pass on the current Phase 3A worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-supabase --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error \
  --skip tier0_probe_inputs_keep_harvested_tables_project_local \
  --skip tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table
bash scripts/check-network-boundary.sh
git diff --check
```

No live Network action was run. The remaining deliberate reds are exactly two
Phase 3B table-scope cases and three Phase 5 CLI/baseline cases.

## Phase 2 verification observed on 2026-07-12

The following pass on the current Phase 2 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked -- \
  --skip tier0_probe_inputs_keep_harvested_tables_project_local \
  --skip tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

Default and network workspace matrices pass when only the later-phase known-red
tests are excluded. No golden or report snapshot changed, and no live Network
action was run. An unfiltered default `--no-fail-fast` audit confirms that the
remaining failures are exactly the three Phase 5 CLI/baseline cases and two
Phase 3 root-warning cases; the network matrix additionally retains the two
Phase 3 project-table-scope cases.

## Phase 1 verification observed on 2026-07-12

The following pass on the current Phase 1 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-types --locked
cargo test -p vibescan-git --locked
cargo test -p vibescan-secrets --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

The default and `network` workspace matrices also pass when only the remaining
known-red Phase 2–5 regression names are excluded. The Phase 1 regression
`identical_content_at_server_and_browser_paths_retains_both_locations` passes.
No live network action was run.

## Prior audit verification observed on 2026-07-12

The following passed against the clean `e7e9263` code baseline:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo clippy --workspace --all-targets --features network --locked --offline -- -D warnings
cargo test --workspace --locked --offline
cargo test --workspace --features network --locked --offline
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

Measured results:

- default feature set: **79 passed, 4 ignored**;
- `network` feature set: **81 passed, 3 ignored**;
- boundary check: default graph contained no transport crates; enabled
  transport was nearest-parented by `vibescan-supabase`; the four production
  `LocalStatic` libraries were transport-free;
- hardening helper: deterministic local checks passed; its optional sanitized
  real-repository leg was skipped because no fixture path was provided; and
- committed expected manifests/snapshots contained no detected absolute home
  paths or live scan-envelope fields.

These results prove the current covered behavior. They do not prove the missing
edge cases or deferred requirements described below. A live Supabase target was
not contacted and is not required for the default completion gate.

After the documentation changes, the closeout pass also reran and passed:

- `cargo fmt --all -- --check`;
- `bash scripts/check-network-boundary.sh`;
- the default golden corpus (**4 passed, 4 intentionally ignored**);
- the network golden corpus (**5 passed, 3 intentionally ignored**);
- report snapshots (**1 passed**); and
- `git diff --check`.

## Architecture completion matrix

| Architecture area | Status | Evidence and limitation |
|---|---|---|
| Design invariants | Partial / safety core verified | LocalStatic default, own-Supabase URL guard, read-only Tier 0, redacted per-action scope evidence, and no persisted writes are implemented. |
| Post-v1 eight-crate workspace | Phase 4 + F1 complete | The architecture-authorized `vibescan-registry` crate has only its types edge; core is its only application parent. The exact DAG holds across normal, build, dev, target, optional, and feature-activated dependencies. Synthetic controls reject horizontal/direct drift, unauthorized transport parents, OpenSSL/native-tls, and Supabase/Registry feature cross-activation. |
| Shared data model | Phase 1 identity complete | `ContentId`, `UnitLocation`, `ScannableUnit.locations`, and `UnitRef.locations` form one canonical occurrence model; singular competing fields were removed. |
| Content handling | Substantially implemented | Binary/size skips, ignore layers, forced real-env/client-bundle scanning, inline allow, and commit allowlists exist. Historical paths intentionally use current ignore state. |
| Scan pipeline | Partial | All five phases exist and exact `ContentId` lookup now binds enrichment to the candidate revision. Units/candidates/findings remain materialized rather than streamed. |
| Location classification | Verified for covered Tier C and Phase 1 cases | Whole-segment monorepo matching, server-first precedence, substring controls, and identical-content server/browser occurrence retention are tested. |
| Generic secret substrate | Phase 5 application contract verified | Keyword prefilter, regex, entropy, allowlists, attribution, and required provider families exist. Repository-configured custom rules now append to embedded rules/allowlists; duplicate IDs are rejected and mandatory defaults remain active. |
| Git walker | Partial | Discovery, all refs, budgets, changed blobs, working tree, edge warnings, and full SHA-256 `ContentId` grouping exist. Cross-path locations/classes and same-path provenance are retained deterministically; output remains a `Vec`, not a stream. |
| Supabase key classification | Partial | New/legacy classes, exact-revision project extraction, and conservative same-fingerprint project enrichment exist. Initial new-format project discovery remains same-unit only, and no user-supplied project/key pair exists. |
| Tier 0 RLS probe | Partial, Phase 3C verified | Feature/runtime gating, `apikey`, URL restriction, GET-only probing, no row retention, precise root fallback, typed references, exact/unambiguous project-scoped table sets, and one redacted scope record per attempted GET are tested. |
| Tier 1 RLS introspection | Tier E E1–E3 complete | The env-only rustls catalog path emits `Confirmed` Critical RLS-disabled/literal-true findings, a Medium default-deny missing-operation advisory, and High inferred-write findings with catalog-native evidence. The two read-exposure shapes drive same-project rule 1, all Tier 1 RLS findings participate in rule 2, and both mock fixtures are live under `network`; architecture §17.8 defers the metadata-keyed `Review` heuristic. |
| Correlation | Phase 2 + Tier E3 verified | Both declarative v1 rules honor primary/additional commit provenance, compare normalized projects, and produce deterministic unique location/related unions. Rule 1 accepts only evidence that proves reads; rule 2 includes both RLS evidence shapes. |
| Dependency integrity | v1 §11.0 + Track F complete | Offline npm/Python structural checks remain unchanged. F1 adds deterministic parsed inputs, the separate rustls Registry boundary, explicit consent, and scope vocabulary. F2 adds exact-version local OSV matching, guarded public existence resolution, a nonfatal failure taxonomy, and 24-hour public-data caches. F3 activates the mocked nonexistent-package golden and metrics coverage. The newcomer heuristic remains an explicitly separate deferred follow-up. |
| Reporting | Verified through F2 scope | JSON, SARIF, TTY, and HTML include redacted findings, Network action scope evidence, Registry name-egress disclosure, locations, history context, collection/dedup counters, a derived dedup ratio, exit gates, and deterministic snapshots. A full-pipeline integration test proves raw candidate material reaches neither any renderer nor serialized `ScanResult`; §17.3 permits no full-match mode. Protected actions do not affect finding statistics or gates. |
| CLI/config | Phase 5 + F1 complete | LocalStatic precedence remains defaults < repository TOML < explicitly supplied CLI values. The independent feature-gated `--registry-checks` runtime confirmation cannot be enabled by repository config and does not enable Tier 0 or Tier 1. Named paths retain repository-root handling and operational failures. |
| Security/nonfunctional | Partial; G1–G3 implemented, G4.0–G4.1 complete (rollout pending) | Pure-Rust/default transport boundaries remain enforced. The hosted `v0.1.0` release proves the exact five-target matrix, musl-only Linux artifacts, SHA-256 checksums, five verified GitHub Artifact Attestations, and blocking static-link verification. G2 adds the ships-only npm wrapper, exact optional platform packages, release integration, no-fetch/no-postinstall contracts, and a green five-platform `npx` matrix. G3's fail-closed Cargo/npm publishers, OIDC provenance wiring, and prebuilt Homebrew formula are implemented and merged to `main`. G4.0 replaces the unavailable unscoped and organization-scope npm targets with controlled `@jiayanzeng/vibescan` plus its five platform packages and proves the six-identity scoped publish plan. G4.1 verifies all fourteen registry identities remain free, records owner-confirmed bootstrap credentials/account controls, and verifies the public tap plus `Formula/` layout. G4.2 preflight, G4.3 publication, and G4.4 post-publish checks remain outstanding. |
| Testing strategy | v1 closeout + Tier E + Track F complete | Exact goldens, clean control, report snapshots, four-way boundary checks, mocked Tier 0/Tier 1/Registry fixtures, source/cache mocks, the Tier D1 scripted real-repository path, committed metrics, deterministic performance counters, and end-to-end redaction pins exist. AstroScout supplied the first genuine D1 coverage record (100.00%, 3 findings, 1 project); the Track F corpus records 14 TP, 0 FP, 0 FN, precision 1.0, recall 1.0, and classification coverage 0.75. No capability-gated corpus fixture remains. |
| Explicit non-goals | Preserved | No live writes, active DAST, BOLA, dashboard, accounts, billing, or client-auth heuristic scanner was found. |

## Tier C status

Tier C is implemented and covered for its named acceptance paths:

- **C1:** segment-aware monorepo classification with server-first precedence;
- **C2:** conservative same-secret coalescing and one Tier 0 input per normalized
  project; and
- **C3:** `apikey` on every mocked request, LocalStatic table/RPC harvesting,
  best-effort OpenAPI supplementation, distinct degraded warnings, read-only
  table probing, and the enabled mocked exposed-public-key-chain golden.

Phases 1–2 now cover the identity/linkage cases that Tier C did not: identical
content at different paths, commit membership stored in additional provenance,
two historical contents at one path, and a project URL split from a client key.
Tier D1 has one explicit local real-repository coverage record, Tier D2 has a
committed live-corpus metrics baseline, Tier D3 has the deterministic counter
gate, and Tier D4 pins the resolved architecture decisions. Architecture §15
step 9 is therefore complete. The private CI fixture remains optional and
secret-gated.

## Strict gaps and known risks

### P0 — headline false-negative risks

1. **Alternate paths during content dedup — resolved in Phase 1.**

   The collector now groups by full SHA-256 `ContentId` and retains a canonical,
   deterministic list of `UnitLocation`s. Identical server/browser content is
   scanned once while both paths, classes, and provenances reach candidates and
   findings.

2. **Committed predicates and additional provenance — resolved in Phase 2.**

   Both v1 rules now use one `location_has_commit` predicate covering the
   primary and every additional provenance.

3. **Historical project-context swaps — resolved in Phase 2.**

   Core now resolves enrichment content by the candidate's exact `ContentId`.

4. **Projectless/project-bearing copies — resolved conservatively in Phase 2.**

   Two-stage coalescing joins projectless evidence only when the base group has
   exactly one known normalized project. Multiple known projects remain
   separate and retain a separate projectless bucket rather than guessing.

### P1 — contract and configuration gaps

1. **Literal crate DAG — resolved in Phase 4.** Cross-crate integration tests
   now live in core, sibling dev-dependencies and the CLI-to-types edge are
   removed, and the checker validates every declared dependency kind plus both
   resolved feature graphs.

2. **CLI/config precedence — resolved in Phase 5.** LocalStatic clap values are
   applied only when explicit, paired scope flags override both directions, and
   repository Network configuration remains inert without runtime confirmation.

3. **Baseline/custom-rules paths — resolved in Phase 5.** Relative paths use
   the discovered repository root, absolute paths are preserved, missing named
   files fail operationally, and custom rules append without replacing embedded
   rules or safety allowlists.

4. Project-scoped table harvesting — resolved in Phase 3B. Exact `ContentId`
   association wins; otherwise deterministic app/package scope is used only
   when it resolves to one project. Missing/ambiguous tables are skipped with a
   coverage warning, and RPC references never become table reads.

5. **Tier 0 protected-action auditability — resolved in Phase 3C.** Every
   attempted root/table GET now produces redacted scope evidence even when no
   finding is emitted.

### P2 — assurance and product-depth gaps

- **Track G1–G3 implemented; G4.0–G4.1 complete, rollout pending:** the release workspace, exact five-target
  `cargo-dist` matrix, musl Linux cross-builds, checksums, attestations, and
  blocking static-link verification are locally validated and proven by the
  successful hosted `v0.1.0` release. The ships-only npm shim, five exact
  optional platform packages, release packaging job, and five-platform `npx`
  smoke matrix are also verified. G3 now has fail-closed Cargo/npm publishers,
  OIDC provenance wiring, a functional prebuilt Homebrew formula, and a release
  runbook. G4.0 selects controlled `@jiayanzeng/vibescan`, removes the unscoped
  and unavailable organization-scope npm targets, and pins the six personal-
  scope identities in tests. G4.1 verifies the free registry identities and
  completes the owner-controlled account/secret/tap bootstrap. G4.2 preflight,
  G4.3 publication, and G4.4 post-publish checks remain outstanding, as does the
  CLI Cargo package naming decision.
- **Track F complete:** F1 establishes Registry ownership, feature/runtime
  consent, parsing, transport isolation, and auditable output shapes; F2 adds
  the two confirmed checks and bounded privacy-aware caching; F3 activates the
  hallucinated-dependency golden and metrics baseline. The separate npm-only
  `Review` newcomer heuristic remains deferred and off by default; PyPI remains
  blocked on a download-signal decision.
- Tier D3 now provides the required deterministic counter gate and records wall
  time without asserting it. Longer-term timing trends and peak-memory growth
  for the materialized pipeline are not yet tracked.
- History-only remediation is present in general terms but should be tested for
  the architecture's explicit rewrite/force-push guidance.
- The default ruleset is deliberately conservative; provider precision and
  corpus licensing/attribution should receive a durable audit artifact before
  broad expansion.
- README documents the basic test and boundary commands, not the complete
  closeout matrix. `verify-hardening-checks.sh` now owns the default/offline and
  optional real-repository D1 legs, but it still omits fmt, clippy,
  network-feature workspace tests, and diff checks; it must not be treated as
  the full gate.

## Resolved architecture decisions

The former architecture ambiguities are resolved in architecture §17
(2026-07-13; §17.3 finalized 2026-07-18). The implementation follows those
decisions, including redaction in every output format.

## Detailed next-step plan

### Phase 1 — repair scan identity and correlation linkage

Do this before adding detection breadth or new Network features.

1. Add failing regression tests for:

   - identical content at server and client paths preserving two locations and
     `ClientReachable` precedence;
   - a working-tree key whose commit membership exists only in
     `additional_provenance` satisfying both committed predicates;
   - two historical blobs at the same path, each using its own project URL;
   - the same fingerprint in a projectless client file and an unambiguous
     project-bearing server/config file coalescing into one linkable fact;
   - known-different projects never merging; and
   - two projects receiving only their own harvested table candidates.

2. Change collection/data linkage so content dedup retains each path and
   location class. Prefer an explicit occurrence/location list or a stable
   unit/blob identifier over overloading provenance.
3. Pass exact unit content into classification rather than looking it up by
   path.
4. Centralize “has committed provenance” over primary plus additional
   provenance and use it in both v1 rules.
5. Reconcile a missing project with one unambiguous known project for the same
   fingerprint, while refusing known-project conflicts.
6. Associate harvested API names with the relevant source/project before
   generating probe inputs.

Acceptance: targeted crate tests, both golden feature modes, full default and
network clippy/tests, boundary script, reviewed golden diffs, and no decrease in
clean-control precision.

### Completed in Phase 4 — enforce the complete crate DAG

Cross-crate classifier/walker integration coverage now lives in core. The
sibling dev-dependencies and CLI-to-types edge are gone. The boundary checker
validates the exact workspace membership and edge set across every declared
dependency kind and both feature graphs while preserving separate transport
reachability assertions. Synthetic controls prove rejection of a sibling
dev-dependency, an unauthorized direct/optional edge, and LocalStatic transport
leakage.

### Completed in Phase 5 — make configuration truthful end to end

LocalStatic CLI overrides are explicit and paired where booleans require both
directions. Repository configuration sits between built-in defaults and
explicit CLI values. Relative baseline/custom-rule paths resolve from the
repository root; named missing files fail with exit 2; synthetic real baselines
suppress findings. Custom rules append to embedded defaults and duplicate IDs
are rejected. Repository configuration alone cannot confirm Network work.

### Completed in Phase 3C — Tier 0 observability without broader authority

Structured records now cover root enumeration/unavailability, exposed,
protected/empty, not-found, key-rejected, invalid-response, and transport-error
attempts. They record GET intent, normalized endpoint, optional table, status
when present, outcome, and an exposure-only row count. Mock tests prove that
keys, headers, response bodies, and rows are absent. Network failure remains
nonfatal, and no writes, arbitrary URLs, live CI, or registry egress were added.
Tier E1 subsequently added a separately gated catalog transport without changing
Tier 0 behavior.

### Next — continue measured assurance

1. **Tier D2 complete:** the deterministic live-corpus harness publishes a
   committed machine-readable baseline with corpus version, per-fixture counts,
   TP/FP/FN, precision, recall, and classification coverage. Clean-control FP
   and precision/recall regression checks are hard gates even during baseline
   regeneration.
2. **Tier D3 complete:** the generated fixture gates exact paths, blobs, unique
   contents, materialized units, truncation, and the derived dedup ratio while
   recording but never gating `duration_ms`.
3. **Tier D4 complete:** every output format and serialized `ScanResult` is
   pinned to redacted evidence; §17 status debt is retired; gated fixtures name
   their actual capability. The `src/api/` classification remains unchanged
   pending stronger real-repository evidence.
4. Add a canonical full-verification script or prominently document the exact
   root `AGENTS.md` matrix. Keep Tier D1's real-repository leg separate and
   explicitly fixture/Network-gated.
5. Extend CI only with deterministic offline checks.

### Post-v1 tracks

- Registry checks: Track F is complete—F1's crate/DAG/transport/opt-in/input
  plumbing, F2's two confirmed detections/guards/failure taxonomy/caches, and
  F3's golden plus committed metric activation are all verified. Newcomer
  checks remain a separate, explicitly consented npm-only `Review` mode and
  must not be inferred from `--registry-checks`; PyPI newcomer remains deferred
  pending a download-signal decision.
- Tier 1 introspection/policy analysis: E1 transport/input, E2's four
  mechanically decidable findings, and E3 correlation/fixtures are complete.
  Architecture §17.8 defers the metadata-keyed `Review` heuristic outside the
  confirmed set.
- Distribution: G1's five-target static-binary matrix, checksums, attestations,
  static-link gate, and release workflow are complete and proven by the hosted
  `v0.1.0` release. G2's ships-only npm shim, five exact optional platform
  packages, release packaging integration, and cross-platform smoke matrix are
  complete. G3's local publishers, npm provenance contract, Homebrew formula,
  and runbook are implemented and verified. G4.0 is complete with
  `@jiayanzeng/vibescan` as the controlled personal-scope entry point. G4.1's
  owner-controlled registry/account/tap bootstrap and read-only acceptance
  checks are complete. The next task is G4.2; run it before any new-version
  release tag, then run G4.3 and G4.4 in order. Do not add a ninth crate
  or rename `vibescan-cli` merely to satisfy the instruction's literal Cargo
  command without first amending the architecture.
- Active DAST/write probes: prohibited in v1, not merely postponed.

## Closeout gate for future milestone claims

Run, record, and reconcile at least:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test precision_recall --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

Use `UPDATE_GOLDEN=1` or `UPDATE_METRICS=1` only after an intentional result
change, inspect every artifact diff, then rerun without it. The D2 clean-control
and no-decrease precision/recall gates remain active during metrics updates. Do
not claim completion from this file's historical results; rerun the commands on
the current checkout.
