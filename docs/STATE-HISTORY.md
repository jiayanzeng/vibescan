# vibescan State — Verification History (Archive)

Append-only archive of dated, per-task verification records moved out of `STATE.md`
to keep that file focused on current state. Authority remains `vibescan-architecture.md`.
These records document observed status at the time noted; they do not override the
architecture or prove completion by themselves. Newest records are toward the top,
matching the order they were recorded in the original log.

---

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
party. G4.1 is **complete**. At its close, the next task was G4.2's fully
reversible preflight; G4.3's immutable version/tag/publication work could not
begin until G4.2 passed.
After the first publication, configure trusted publishing for all eight crates
and six npm packages, then remove both registry bootstrap secrets.

## Track G4.2 preflight verification observed on 2026-07-19

G4.2 ran against clean, synchronized commit `0781869`. It is release and
distribution assurance under architecture §13.1; it changes no scanner phase,
crate edge, LocalStatic/Network boundary, target-project behavior, package
version, or publication identity. The pinned official `dist` 0.32.0 Apple
Silicon archive was downloaded into an isolated temporary directory and matched
SHA-256 `aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7`.
The temporary executable reported `cargo-dist 0.32.0`.

The following prescribed commands passed on the release commit:

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
bash scripts/publish-crates.sh --dry-run
node npm/scripts/build-packages.mjs \
  --artifacts target/distrib --out target/npm-packages
node npm/scripts/verify-packages.mjs --packages target/npm-packages
node npm/scripts/publish-packages.mjs \
  --packages target/npm-packages --print-plan
npm --prefix npm test
python3 scripts/verify-release-publishing.py
<temporary-dist>/dist generate --check
<temporary-dist>/dist plan --output-format=json
ruby -c target/distrib/vibescan.rb
bash scripts/verify-hardening-checks.sh
git diff --check
```

The Cargo plan listed all eight crates in the required bottom-up order: types,
secrets, git, report, supabase, registry, core, then CLI. The npm print plan
listed exactly the five `@jiayanzeng/vibescan-*` platform packages first and
`@jiayanzeng/vibescan` last; it contained no unscoped `vibescan` publication.
Every entry requests public provenance publication. A machine assertion over
the `dist` JSON plan proved exactly the five architecture-approved executable
archives (macOS arm64/x64, musl Linux arm64/x64, Windows x64) plus the
`vibescan.rb` Homebrew installer. `dist generate --check` produced no workflow
diff, and the formula passed Ruby syntax validation.

The required negative control temporarily changed the Darwin-arm64 source
manifest CPU selector from `arm64` to `x64`. `verify-packages.mjs` exited 1 and
reported the exact `x64` versus `arm64` mismatch. The manifest was immediately
restored; the same verifier then exited 0, and `git diff` proved no residual
manifest change.

The first npm packed-output verification encountered six stale, pre-G4.0
tarballs in the ignored `target/npm-packages` directory and correctly rejected
the extra files. That generated directory was preserved outside the workspace,
the prescribed build/verify/print-plan sequence was rerun from an absent output
path, and every command passed. This was local ignored-state contamination, not
a release-source defect; the closeout instructions now explicitly require the
generated output path to begin absent or empty.

The hardening aggregate passed and explicitly skipped its optional real-repo
leg because no fixture was supplied. Tests used mocks and local fixtures only.
No registry credential was read or passed to a command; no live Supabase,
Registry, npm, crates.io, or Homebrew publication action ran. No package,
formula, version, tag, GitHub release, or target-project state was created or
modified. G4.2 is **complete**. At its close, G4.3 was the next task; its
release preparation is now recorded below, while its merge, annotated tag, and
owner-only tag push remain incomplete.

## Track G4.3 release preparation observed on 2026-07-19

The release owner authorized the closeout document's recommended `0.1.1` patch
release after G4.2 passed. Commit `be615a0` synchronizes all eight Cargo package
versions, the seven version-bearing workspace dependency constraints, all six
scoped npm package versions, the five exact npm optional dependencies, the npm
publish-plan fixture, and the eight workspace entries in `Cargo.lock`.
`RELEASING.md` records why this is distribution-only: it changes no scanner
phase, dependency edge, LocalStatic/Network boundary, finding, target-project
access, or public identity.

The following release and architecture checks passed on the `0.1.1` worktree:

```sh
cargo update --workspace
npm --prefix npm test
python3 scripts/verify-release-publishing.py
bash scripts/publish-crates.sh --dry-run
cargo run --locked -p vibescan-cli -- --version
<checksum-verified-dist-0.32.0>/dist --version
<checksum-verified-dist-0.32.0>/dist generate --check
<checksum-verified-dist-0.32.0>/dist plan --output-format=json
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

The CLI reports `vibescan 0.1.1`; the Cargo dry-run retains all eight crates in
bottom-up dependency order; npm tests retain the five controlled platform
packages before `@jiayanzeng/vibescan`; and the `dist` plan announces `v0.1.1`
with exactly the five approved executable targets and the Homebrew formula.
`dist` warned about and ignored old `v0.1.0` manifests in generated
`target/distrib` state; the emitted plan itself is consistently `0.1.1` and no
generated workflow diff exists. Hardening passed and explicitly skipped its
optional real-repository leg because no fixture was supplied.

No registry credential was read, no tag was created or pushed, and no package,
GitHub release, or formula was published. G4.3 is therefore **prepared but not
complete**. Per the closeout authorization boundary, the release owner must
merge the reviewed branch, create an annotated `v0.1.1` tag on that exact merge,
and push only the tag. The tagged workflow must then pass before G4.3 can be
called complete; G4.4 remains unstarted.

## Track G4.3 tagged-workflow startup recovery observed on 2026-07-19

Pull request #6 merged the verified `0.1.1` preparation to `main` as merge
commit `01f7f39c45a0016c952d5c1c8f276203dc73cf7f`; all 26 required pull-request
checks passed. The release owner created annotated tag `v0.1.1`, whose peeled
target is that exact merge. GitHub Actions Release run
`29673995181` reached the terminal `Startup failure` state before any job ran.
GitHub's workflow validator reported that the call to
`.github/workflows/publish-crates.yml` requested `contents: read` while the
caller granted `contents: none`. The npm reusable publisher had the same
caller/callee permission mismatch. Because validation failed before job
startup, no artifact, GitHub release, crate, npm package, or Homebrew formula
was created.

Implementation commit `bca901a` configures cargo-dist 0.32.0's supported
`github-custom-job-permissions` surface for both `publish-crates` and
`publish-npm`. Each generated caller now grants exactly `contents: read`,
`id-token: write`, and `packages: write`. The reusable workflows still request
only `contents: read` plus `id-token: write`; no broader permission, scanner
runtime behavior, crate dependency, egress capability, credential handling, or
target-project access was added. `scripts/verify-release-publishing.py` now
requires the source configuration and both generated job blocks to carry that
exact permission set. Before the repair, the new check failed on the missing
configuration; after regeneration, it passed.

The pinned official Apple Silicon cargo-dist 0.32.0 archive matched SHA-256
`aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7` and
reported `cargo-dist 0.32.0`. The following commands passed on implementation
commit `bca901a` (documentation-only status edits followed):

```sh
python3 scripts/verify-release-publishing.py
python3 -m py_compile scripts/verify-release-publishing.py
dist generate
dist generate --check
ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |path| YAML.load_file(path) }'
npm --prefix npm test
bash scripts/publish-crates.sh --dry-run
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

The hardening aggregate explicitly skipped its optional real-repository leg
because no fixture was supplied. All tests used local fixtures and mocks. No
credential was read, no live registry or target system was contacted, no
publication was retried, and no tag was created, moved, deleted, or pushed by
this repair. At that checkpoint, the ordered next steps were to merge the
repair, prepare the next patch version because `v0.1.1` is immutable evidence,
and require a new owner-pushed tagged workflow to pass. PR #7 and the `0.1.2`
preparation recorded below advance the first two steps. G4.3 and Track G remain
**partial**.

## Track G4.3 `v0.1.2` recovery preparation observed on 2026-07-19

Pull request #7 merged the reusable-publisher permission repair to `main` as
`66e5fa2c3bbcf3b8fec41b8b1c7bc17cb3850f7b`; all 36 hosted checks passed.
The release owner then authorized the next immutable patch preparation.
Implementation commit `0efdca0` synchronizes all eight Cargo package versions,
the seven version-bearing workspace dependency constraints, all six scoped npm
package versions, the five exact npm optional dependencies, the npm publish-plan
fixture, and the eight workspace entries in `Cargo.lock` to `0.1.2`.
`RELEASING.md` records that this is a distribution-only recovery for the failed
`v0.1.1` attempt and does not change scanner behavior, the crate DAG,
LocalStatic/Network boundaries, target-project access, findings, or package
identities.

The following release and architecture checks passed on implementation commit
`0efdca0` before this documentation-only status update:

```sh
cargo update --workspace
cargo metadata --no-deps --format-version 1
npm --prefix npm test
python3 scripts/verify-release-publishing.py
ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |file_name| YAML.load_file(file_name) }'
bash scripts/publish-crates.sh --dry-run
cargo run --locked -p vibescan-cli -- --version
<previously-checksum-verified-dist-0.32.0>/dist --version
<previously-checksum-verified-dist-0.32.0>/dist generate --check
<previously-checksum-verified-dist-0.32.0>/dist plan --output-format=json
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

The CLI reports `vibescan 0.1.2`; Cargo/npm metadata contains only the intended
`0.1.2` workspace/package identities; the Cargo dry-run retains all eight crates
in bottom-up dependency order; npm retains the five controlled platform
packages before `@jiayanzeng/vibescan`; and the `dist` plan announces `v0.1.2`
with exactly the five approved executable targets plus `vibescan.rb`.
`dist generate --check` produced no workflow diff. The hardening aggregate
passed and explicitly skipped its optional real-repository leg because no
fixture was supplied.

All tests used local fixtures and mocks. No credential was read, no live
registry or target system was contacted, no tag was created, moved, deleted,
or pushed, and no package, GitHub release, or formula was published. G4.3 is
**prepared but not complete**: the reviewed `0.1.2` branch must merge, then the
release owner must create and push a new annotated `v0.1.2` tag on that exact
merge. The tagged workflow must pass before G4.3 can close; G4.4 remains
unstarted.

## Track G4.3 `v0.1.3` recovery preparation observed on 2026-07-19

Pull request #8 merged `0.1.2` to `main` as
`1883d61fecc7c48e1ead5e69b47a7862561eb473`; annotated tag `v0.1.2` peels to
that exact merge. [Release run #13](https://github.com/jiayanzeng/vibescan/actions/runs/29675300081)
built all five platform archives, passed both static Linux checks, passed the
five-platform npm package smoke, completed all five `Attest` steps, and created
the GitHub release. It published the six approved scoped npm packages and the
Homebrew formula at `0.1.2`. crates.io accepted, in order,
`vibescan-types`, `vibescan-secrets`, `vibescan-git`, `vibescan-report`, and
`vibescan-supabase`, then returned HTTP 429 for `vibescan-registry` because too
many new crates had been published in a short period. No publisher returned
403. Public registry reads confirmed those five crates and all six npm packages
at `0.1.2`, the formula at `0.1.2`, and the remaining registry/core/CLI crate
identities still absent. Because published versions and tags are immutable,
neither `v0.1.2` nor any `0.1.2` package may be retried, replaced, or moved.

The release owner authorized synchronized patch `0.1.3` as a distribution-only
recovery. Implementation commit `a12499a` updates all eight Cargo packages, all
seven version-bearing workspace dependency constraints, all six npm packages,
all five exact npm optional dependencies, the publish-plan fixture, and the
lockfile. `scripts/publish-crates.sh` now retries only a Cargo error containing
both the registry-publication failure and explicit HTTP 429 markers; retry
delay and budget are bounded, while authentication, ownership, validation, and
other failures remain fail-closed. Its fake-Cargo regression test proves a
single 429 recovery, a fatal 403 with no retry, and bounded repeated-429
exhaustion.

cargo-dist 0.32.0 does not express dependencies among separate publish jobs, so
the generated `v0.1.2` workflow ran crates.io, npm, and Homebrew concurrently.
The recovery replaces those three publish entries with one reusable
`publish-all` workflow: Cargo must succeed before npm begins, and npm must
succeed before Homebrew begins. The generated release workflow invokes only
that chain after GitHub hosting succeeds. The contract checker rejects the old
parallel jobs, missing dependency markers, or missing retry regression in CI.

The following release and architecture checks passed on implementation commit
`a12499a` before this documentation-only status update:

```sh
cargo update --workspace
cargo metadata --no-deps --format-version 1
npm --prefix npm test
python3 scripts/verify-release-publishing.py
python3 -m py_compile scripts/verify-release-publishing.py
bash -n scripts/publish-crates.sh scripts/test-publish-crates.sh
bash scripts/test-publish-crates.sh
bash scripts/publish-crates.sh --dry-run
cargo run --locked -p vibescan-cli -- --version
<previously-checksum-verified-dist-0.32.0>/dist generate
<previously-checksum-verified-dist-0.32.0>/dist generate --check
<previously-checksum-verified-dist-0.32.0>/dist plan --output-format=json
ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |path| YAML.load_file(path) }'
ruby -c target/distrib/vibescan.rb
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

The CLI reports `vibescan 0.1.3`; Cargo/npm metadata contains only the intended
`0.1.3` package versions; the Cargo dry-run retains all eight crates in
bottom-up order; npm retains exactly five controlled platform packages before
the main package; and the cargo-dist plan announces `v0.1.3` with exactly five
approved executable archives plus `vibescan.rb`. `dist generate --check`
produced no workflow diff. cargo-dist warns that its built-in Homebrew publisher
is disabled; this is intentional because the ordered custom workflow publishes
the same generated formula. Hardening passed and explicitly skipped only its
optional real-repository leg because no fixture was supplied.

No credential was read during recovery preparation, no live target was probed,
and no target-project data or scanner behavior changed. G4.3 remains
**prepared but not complete** at this checkpoint: merge `a12499a` and this
status follow-up to `main`, create annotated `v0.1.3` on that exact merge, push
only the tag, require the tagged workflow to pass end to end, and prove that a
second push of the same tag is a no-op. G4.4 remains a separate follow-up.

## Track G4.3 `v0.1.3` release completion observed on 2026-07-19

Pull request #9 merged implementation `a12499a` and preparation record
`234981f` to `main` as `e788b1c139556f979a23fc6e97705bc54fce1cc7` after 27
hosted checks passed with seven expected release-only skips. The remote had no
`v0.1.3` tag before release. Annotated tag object
`45e6841294c37a843e17164d54cfc1fe9ee51620` peels to the exact PR merge. The
initial push sent only `refs/tags/v0.1.3` and triggered
[Release run #29676514551](https://github.com/jiayanzeng/vibescan/actions/runs/29676514551).

The run completed all 19 jobs successfully on tagged merge `e788b1c`. All five
platform build jobs passed, including one successful `Attest` step each. The
static Linux verifier, npm package job, all five platform smoke jobs, GitHub
host, crates.io publisher, npm publisher, Homebrew publisher, and announcement
also passed. Job timestamps and dependency state showed only crates.io active
after hosting; npm began only after crates.io completed; Homebrew began only
after npm completed. No publisher returned 403.

The [v0.1.3 GitHub release](https://github.com/jiayanzeng/vibescan/releases/tag/v0.1.3)
targets `e788b1c` and includes `source.tar.gz`, `sha256.sum`, and the exact five
architecture-approved platform archives:

- `vibescan-cli-aarch64-apple-darwin.tar.xz`;
- `vibescan-cli-x86_64-apple-darwin.tar.xz`;
- `vibescan-cli-aarch64-unknown-linux-musl.tar.xz`;
- `vibescan-cli-x86_64-unknown-linux-musl.tar.xz`; and
- `vibescan-cli-x86_64-pc-windows-msvc.zip`.

Each of those five SHA-256 digests returned exactly one record from GitHub's
public attestations API. Public crates.io API reads returned maximum version
`0.1.3` for all eight workspace crates, proving that each dependency resolved
at publish time. Public npm registry reads returned `latest = 0.1.3` for the
main package and all five platform packages. The public tap's
`Formula/vibescan.rb` declares `version "0.1.3"` and uses the release archive
URLs and matching digests.

The completion verification used these command forms against public endpoints;
the package and digest queries were repeated for every identity named above:

```sh
git ls-remote origin refs/tags/v0.1.3 refs/tags/v0.1.3^{}
curl -fsSL 'https://api.github.com/repos/jiayanzeng/vibescan/actions/runs/29676514551'
curl -fsSL 'https://api.github.com/repos/jiayanzeng/vibescan/actions/runs/29676514551/jobs?per_page=100'
curl -fsSL 'https://api.github.com/repos/jiayanzeng/vibescan/releases/tags/v0.1.3'
curl -fsSL 'https://github.com/jiayanzeng/vibescan/releases/download/v0.1.3/sha256.sum'
curl -fsSL 'https://api.github.com/repos/jiayanzeng/vibescan/attestations/sha256:<digest>'
curl -fsSL 'https://crates.io/api/v1/crates/<crate>'
curl -fsSL 'https://registry.npmjs.org/@jiayanzeng%2f<package>'
curl -fsSL 'https://raw.githubusercontent.com/jiayanzeng/homebrew-tap/main/Formula/vibescan.rb'
git push origin refs/tags/v0.1.3
```

The required negative control repeated `git push origin
refs/tags/v0.1.3`. Git returned `Everything up-to-date`; the remote annotated
tag object and peeled merge remained unchanged, and no duplicate workflow or
publication ran. G4.3 is therefore **complete**. G4.4 remains a distinct
post-publish install, signature/provenance, checksum, and tamper-control task;
this completion record does not claim it.

## Track G4.4 post-publish verification observed on 2026-07-19

G4.4 began from a clean `main` at `6441cc7`, which includes PR #10's G4.3
closeout. The task is release/distribution verification under architecture
§13.1 and G3 acceptance #1–#3. It changed no scanner code, dependency edge,
runtime Network capability, package version, registry publication, release
tag, or target-project state.

An isolated npm cache and install root ran
`npx @jiayanzeng/vibescan@0.1.3 --version` and received `vibescan 0.1.3`. A
second temporary project installed the main package plus all five platform
packages at the exact version. `npm audit signatures` reported six verified
registry signatures and six verified attestations. The Homebrew Node build's
bundled CA set did not initially trust Sigstore's current TUF certificate
chain; retrying with the host `/etc/ssl/cert.pem` retained TLS verification and
passed. Decoding each verified SLSA statement proved the exact subject and
named `https://github.com/jiayanzeng/vibescan`,
`.github/workflows/release.yml`, `refs/tags/v0.1.3`, source digest
`e788b1c139556f979a23fc6e97705bc54fce1cc7`, and Release run
#29676514551 attempt 1.

An isolated Cargo home/root ran
`cargo install vibescan-cli --version 0.1.3 --locked`; the installed binary
reported `vibescan 0.1.3` and downloaded the complete seven-crate default
graph from crates.io. A second install with `--features registry` resolved and
compiled `vibescan-registry` as well. The registry source directory therefore
contained all eight exact `vibescan-*` workspace crates at `0.1.3`, proving the
optional eighth crate and the default graph both resolve from the public
registry.

The machine had neither `vibescan` nor `jiayanzeng/tap` installed before the
Homebrew check. `brew install jiayanzeng/tap/vibescan` cloned the public tap,
fetched formula `0.1.3`, installed five files from the prebuilt arm64 archive
in one second, and produced `vibescan 0.1.3`. `brew deps` was empty; the live
formula has no Rust dependency or Cargo invocation and uses `bin.install` on
the release archive. The verification-only formula and tap were then removed,
restoring their absent state. Homebrew's automatic cleanup also removed its
stale cached `vibescan` `0.1.0` archive; no installed user package was removed.

The release's `sha256.sum` contains the source archive plus the exact five
platform archives. All six entries returned `OK` and `shasum` exited zero.
macOS `shasum` warns about one improperly formatted line because cargo-dist
emitted a trailing blank line; this is a non-blocking formatting note, not a
digest failure. GitHub CLI 2.94.0 was downloaded from its official release,
its macOS arm64 archive matched the official checksum, and it verified all
five platform archives against their one-record public Sigstore bundles.
Verification enforced signer workflow
`jiayanzeng/vibescan/.github/workflows/release.yml`, source ref
`refs/tags/v0.1.3`, source digest `e788b1c`, and the SLSA provenance predicate.

Both required rejection controls passed. Truncating a temporary archive copy
to one byte made `gh attestation verify` fail; changing the first checksum in a
temporary manifest made `shasum -c` fail while the other five entries remained
`OK`. The real release files were never modified.

The observed command forms were:

```sh
npx --yes @jiayanzeng/vibescan@0.1.3 --version
npm install --ignore-scripts --force --save-exact \
  @jiayanzeng/vibescan@0.1.3 \
  @jiayanzeng/vibescan-darwin-arm64@0.1.3 \
  @jiayanzeng/vibescan-darwin-x64@0.1.3 \
  @jiayanzeng/vibescan-linux-arm64-musl@0.1.3 \
  @jiayanzeng/vibescan-linux-x64-musl@0.1.3 \
  @jiayanzeng/vibescan-win32-x64-msvc@0.1.3
NODE_EXTRA_CA_CERTS=/etc/ssl/cert.pem npm audit signatures
cargo install vibescan-cli --version 0.1.3 --locked
cargo install vibescan-cli --version 0.1.3 --locked --features registry
brew install jiayanzeng/tap/vibescan
shasum -a 256 -c sha256.sum
gh attestation verify <archive> \
  --repo jiayanzeng/vibescan \
  --bundle <public-bundle> \
  --signer-workflow jiayanzeng/vibescan/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.3 \
  --source-digest e788b1c139556f979a23fc6e97705bc54fce1cc7
```

After the documentation update, `npm --prefix npm test`, the release
publishing contract verifier, format, all four clippy matrices, all four
workspace test matrices, the Network boundary checker, the hardening aggregate,
and `git diff --check` passed. The hardening aggregate explicitly skipped only
its optional real-repository leg because no fixture was supplied.

Closeout commit `517dfa2` records the verified release facts in the README,
runbook, Track G closeout, post-v1 roadmap, and this state file. The branch
started from clean `main` at `6441cc7`; no pre-existing user change was present
or modified, and the worktree was clean before this status-only follow-up.

All six G4.4 acceptance criteria are satisfied. G4.4 and Track G are
**complete**. The architecture-correct Cargo package remains `vibescan-cli` and
installs the `vibescan` binary; no ninth alias crate or package rename is
needed.

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

