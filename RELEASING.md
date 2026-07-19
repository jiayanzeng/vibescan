# Releasing vibescan

Releases are tag-triggered and immutable. Prepare and review every registry and
tap change before pushing the tag; never reuse a version after any package has
been published.

## npm entry-point decision (G4.0)

The release owner selected the controlled personal-scope entry point on
2026-07-19: `@jiayanzeng/vibescan`, invoked as
`npx @jiayanzeng/vibescan`. The third-party-owned unscoped `vibescan` package
and the unavailable `@vibescan` organization scope are not publication targets.
The npm publisher must publish the five `@jiayanzeng/vibescan-*` platform
packages first and `@jiayanzeng/vibescan` last; its print plan must contain only
these six scoped identities.

## `v0.1.1` release decision (G4.3)

After the complete G4.2 preflight passed on 2026-07-19, the release owner
authorized the recommended `0.1.1` patch release. This is a distribution-only
release: it exercises the already-implemented crates.io, scoped npm, and
Homebrew publishers for the first time and does not change scanner behavior,
the eight-crate dependency graph, LocalStatic/Network boundaries, target-project
access, or detection output. Its release notes are therefore the first public
availability of the existing scanner through eight crates, six
`@jiayanzeng/vibescan*` npm packages, and the prebuilt Homebrew formula.

## One-time publisher setup

1. Confirm the eight crates.io names and all six scoped npm names are controlled
   by the release owner. Do not perform this live check from automated tests.
2. For the first crates.io release, add a short-lived repository secret named
   `CARGO_REGISTRY_TOKEN`. crates.io requires the first version to be published
   with a token. Afterward, configure trusted publishing for each crate against
   `jiayanzeng/vibescan` and `release.yml`, then delete the secret.
3. For the first npm release, use the existing `jiayanzeng` user account and
   its automatically owned personal scope, `@jiayanzeng`; do not create an
   organization and do not convert the user account into one. Confirm
   `npm whoami` returns `jiayanzeng`, enable two-factor authentication, and add
   an optional short-lived bootstrap secret named `NPM_TOKEN`. The first
   publication creates the six currently unpublished package identities. After
   all six packages exist, configure each package's trusted publisher for
   GitHub user `jiayanzeng`, repository `vibescan`, and workflow `release.yml`,
   then delete the bootstrap secret. The caller filename is `release.yml` even
   though publication runs in a reusable workflow.
4. Create the public `jiayanzeng/homebrew-tap` repository. Add a repository
   secret named `HOMEBREW_TAP_TOKEN` to `jiayanzeng/vibescan`; it must be able to
   write formula commits to the tap.
5. Protect release tags and, if desired, require an approval environment for
   publisher jobs before the first production tag.

## Cut a version

1. Start from a clean, fully verified `main`.
2. Bump the version in all eight Cargo manifests, the main npm package, and all
   five npm platform packages. Update the exact npm `optionalDependencies` and
   all version-bearing workspace dependencies together. Run `cargo update
   --workspace` so `Cargo.lock` records the new workspace versions.
3. Update release notes and review `git diff` for unintended generated or
   credential-bearing content.
4. Run the local preflight:

   ```sh
   npm --prefix npm test
   python3 scripts/verify-release-publishing.py
   bash scripts/publish-crates.sh --dry-run
   dist generate --check
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
   bash scripts/check-network-boundary.sh
   git diff --check
   ```

5. Merge the version change, create an annotated `v<version>` tag on that merge,
   and push only that tag. The release workflow builds and attests the five
   platform archives, verifies static Linux linkage, packages and smoke-tests
   the six npm tarballs, creates the GitHub release, then runs the package
   publishers.

## Publication order

The crates.io job publishes bottom-up so every registry dependency exists before
its parent:

1. `vibescan-types`
2. `vibescan-secrets`
3. `vibescan-git`
4. `vibescan-report`
5. `vibescan-supabase`
6. `vibescan-registry`
7. `vibescan-core`
8. `vibescan-cli`

The npm job publishes all five `@jiayanzeng/vibescan-*` platform packages
before the scoped `@jiayanzeng/vibescan` package. Every `npm publish` uses
`--provenance`; the main package stays last so users never receive a version
whose exact optional dependencies have not been published.

The Homebrew publisher writes the generated prebuilt-binary formula to
`jiayanzeng/homebrew-tap`. It never builds vibescan from source.

## Verify a release

Download `sha256.sum` and the release artifacts, then verify checksums and the
GitHub build provenance:

```sh
shasum -a 256 -c sha256.sum
gh attestation verify <archive> \
  --repo jiayanzeng/vibescan \
  --signer-workflow jiayanzeng/vibescan/.github/workflows/release.yml
```

Exercise every public channel:

```sh
npx @jiayanzeng/vibescan@<version> --version
npm audit signatures
cargo install vibescan-cli --version <version> --locked
vibescan --version
brew install jiayanzeng/tap/vibescan
vibescan --version
```

The Cargo package remains architecture-named `vibescan-cli`; it installs the
`vibescan` binary. The Track G instruction's literal `cargo install vibescan`
command conflicts with the repository's exact `vibescan-cli -> vibescan-core`
package-DAG contract. Renaming it requires an architecture change and is not
silently folded into G3.

Finally, confirm all six npm package pages show provenance linked to the tagged
`release.yml` run, all eight crates.io versions resolve, the tap contains the
new formula, and the release still contains `sha256.sum` plus five verifiable
GitHub Artifact Attestations.
