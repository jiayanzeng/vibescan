# vibescan State

Reviewed: 2026-07-09
Updated: 2026-07-10

## Overall Status

Task B3 is implemented: the project now has an architecture-level golden
fixture corpus with canonical manifests, deterministic normalization, and
gated placeholders for Network-only §14 fixtures. Task A1 remains complete: the
LocalStatic/Network boundary is asserted by a fixture-free, feature-aware CI
check.

Implemented and verified:

- Added fixture-free, feature-aware network-boundary assertion in
  `scripts/check-network-boundary.sh`.
- Added `.github/workflows/ci.yml` with fmt, default/network clippy,
  default/network tests, and the boundary gate.
- Made `scripts/verify-hardening-checks.sh` skip the optional real-repo scan
  when no fixture is provided and removed personal path assumptions.
- Added `tests/fixtures/` golden corpus coverage for clean-control,
  history-only elevated key, publishable client key, vendor-chunks noise,
  nested `.gitignore`, malformed dependency, and offline composite correlation.
- Added `crates/vibescan-core/tests/golden_corpus.rs`, which normalizes each
  finding to stable fields and supports `UPDATE_GOLDEN=1` manifest refresh.
- Added deterministic report-format snapshots for JSON, SARIF, HTML, and TTY in
  `crates/vibescan-report/tests/report_snapshots.rs`.
- Added ignored Network fixture placeholders for exposed-public-key chain,
  RLS-off table, permissive `USING (true)` policy, and hallucinated dependency.
- Removed the stale `vibescan-hardening-instructions.md` reference from
  `README.md`.
- Fixed strict clippy failures in `vibescan-report` and the same pattern in
  `vibescan-core`.
- Preserved the seven-crate workspace and LocalStatic dependency boundary.
- Made elevated Supabase keys standalone Critical findings, matching the
  architecture's bypasses-RLS severity principle.
- Associated co-located Supabase project URLs with new-format secret keys as
  well as publishable keys.
- Moved config loading to the discovered repository root, so subdirectory scans
  still honor root `vibescan.toml`.
- Converted correlation execution to a small rule registry and added summary
  absorption for the exposed-public-key/RLS kill-chain.
- Added commit-id allowlists to the detector allowlist model.
- Surfaced all report locations and first-seen/last-seen commit context for
  deduplicated historical provenance.
- Expanded dependency integrity beyond root `package.json` to root-relative
  manifest discovery, `package-lock.json`, `pyproject.toml`, and
  `requirements.txt` structural checks.
- Added an explicit Gitleaks-compatible attribution note for the embedded
  generic ruleset while keeping Supabase rules project-owned.

Still intentionally not implemented:

- Online dependency registry and OSV/advisory lookups. The current dependency
  integrity implementation is offline-only and structural. Adding nonexistent
  package, suspicious newcomer, and known-malicious checks should happen behind
  an explicit Network opt-in so LocalStatic remains clean.
- Tier 1 Supabase introspection. This remains post-v1 per
  `vibescan-architecture.md`.
- npm wrapper/cross-compile distribution pipeline. This is also deferred by the
  architecture.

## Current Worktree Context

The worktree was already dirty before the original audit. Existing user-owned
modified/deleted files were left in place and worked with rather than reverted.
The current B3 changes add the corpus and integration harness. A1's docs,
scripts, and CI workflow plumbing remain in place from the previous step.

Files currently changed for B3:

- `STATE.md`
- `crates/vibescan-core/tests/golden_corpus.rs`
- `crates/vibescan-report/tests/report_snapshots.rs`
- `tests/fixtures/**`

Temporary negative-control edits to `crates/vibescan-git/Cargo.toml`,
`crates/vibescan-report/Cargo.toml`, and `Cargo.lock` were reverted.

## Verification Results

Passed:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo clippy --workspace --all-targets --features network --locked -- -D warnings`
- `cargo test --workspace --locked`
- `cargo test --workspace --features network --locked`
- `bash scripts/check-network-boundary.sh`
- `bash scripts/verify-hardening-checks.sh`
- `UPDATE_GOLDEN=1 cargo test -p vibescan-core --test golden_corpus`
- `cargo test -p vibescan-core --test golden_corpus`
- `UPDATE_GOLDEN=1 cargo test -p vibescan-report --test report_snapshots`
- `cargo test -p vibescan-report --test report_snapshots`
- `cargo test --workspace`

The hardening script now exits successfully with a skipped notice when no
real-repo fixture is supplied. The optional sanitized real-repo scan remains
available when a fixture path or `VIBESCAN_REAL_REPO` is provided.
`grep -rn '/Users/' scripts/` returned no matches.
The expected-manifest stability grep for absolute paths, timestamps,
`tool_version`, `duration`, and `started_at` returned no matches.

Negative controls were also run and reverted:

- Adding non-optional `reqwest` to `vibescan-git` made the boundary script fail
  and name `vibescan-git` and `reqwest`.
- Adding non-optional `reqwest` to `vibescan-report` made the network
  reachability check fail because transport became nearest-parented by
  `vibescan-report` as well as `vibescan-supabase`.
- Temporarily mutating the publishable-key fixture changed the normalized
  fingerprint/stable key and made the golden harness fail against
  `expected.json`; the mutation was reverted and the harness passed again.

History fixture mechanism: `history-only-elevated-key` ships a
`history.bundle` generated from pinned author/committer identity, dates,
messages, and file contents. The harness clones that bundle at test time, which
keeps SHAs stable while keeping runtime scanning on the LocalStatic gitoxide
path.

## Architecture Completion Matrix

### 1. Crate Architecture

Status: complete for v1.

The seven-crate workspace remains intact. The default/no-network dependency
tree keeps network and transport crates out of LocalStatic code paths. The
optional Tier 0 probe remains behind the `network` feature and explicit opt-in.
The invariant is asserted in CI via `scripts/check-network-boundary.sh`, using
exact resolved package names from Cargo metadata rather than substring matches
over rendered `cargo tree` output.

### 2. Data Model

Status: complete for current v1 needs.

The shared model continues to carry scan units, candidates, findings, evidence,
scope, network state, warnings, and provenance. Existing `additional_provenance`
is now surfaced in reports as first-seen/last-seen history context.

### 3. Content Handling

Status: complete for v1.

The scanner handles binary skips, size caps, `.gitignore`, `.vibescanignore`,
default skips, high-risk `.env` force-scan behavior, inline `vibescan:allow`,
and now commit-id allowlists.

Known approximation:

- Historical paths still use current ignore rules rather than replaying
  per-commit ignore state. This remains an intentional v1 tradeoff documented in
  code.

### 4. Generic Secret Detection

Status: substantially complete.

The detector has keyword prefiltering, regex matching, entropy gates, path,
regex, stopword, and commit allowlists. The embedded generic provider rules now
carry explicit Gitleaks-compatible attribution, while Supabase-shaped rules
remain project-owned and emit only `PossibleSupabaseKey` candidates.

### 5. Git Walker

Status: complete for v1.

Implemented and covered: repo discovery, all-ref history scan, commit budget
warnings, changed-blob collection, merge first-parent warnings, submodule skip
warnings, shallow-clone warning, working-tree scan, and content-hash dedup.

### 6. Supabase Key Classification

Status: complete for v1.

New and legacy keys are classified correctly. Elevated new/legacy keys are
Critical standalone `SecretExposure` findings. Low-privilege publishable/anon
keys remain Info unless correlated with RLS exposure. New-format secret keys now
retain co-located project URL context for same-project correlation.

### 7. Network Boundary and RLS Tier 0

Status: complete for v1 step 8.

Network probing is feature-gated and opt-in. The Tier 0 probe uses only GET
requests against normalized Supabase project URLs discovered from the user's
repository, records endpoint and row count, and never records returned row data.

### 8. Correlation Engine

Status: complete for v1 rules.

The two v1 rules are registered declaratively in a small rule table. The
exposed-public-key chain emits a Critical composite finding with reproduction
text and absorbs its key/RLS constituents in the final summary. The elevated-key
rule annotates same-project RLS findings as moot when an elevated committed key
is exposed.

### 9. Dependency Integrity

Status: offline v1 complete; online checks pending.

Implemented:

- Recursive root-relative discovery of supported manifests outside skipped
  directories.
- `package.json` dependency sections.
- `package-lock.json` dependencies/packages.
- `pyproject.toml` project and Poetry dependencies.
- `requirements.txt` structural parsing.
- Invalid package-name findings.
- Empty npm/Poetry version specifier findings.

Pending Network work:

- Registry lookups for nonexistent npm/Python packages.
- Suspicious-newcomer heuristics using publication/download metadata.
- OSV/advisory checks for known-malicious packages.

These pending checks must be explicitly opt-in Network actions.

### 10. Reporting

Status: complete for v1.

JSON, SARIF, TTY, and HTML renderers are present and now covered by deterministic
snapshot tests. Portable outputs use redacted evidence. TTY/HTML show all
locations for each finding and include first-seen/last-seen commit context when
deduplicated historical provenance is available. Correlated public-key chains
absorb their constituents in the final summary.

### 11. CLI

Status: complete for v1.

The CLI remains thin. Config loading now resolves the repository root before
loading `vibescan.toml`, so subdirectory targets inherit root config.

### 12. Golden Fixture Corpus

Status: complete for B3.

Committed fixtures now cover precision, history-only elevated-key
classification, publishable-key Info severity, vendor-chunk false-positive
suppression, nested `.gitignore` segment matching, malformed dependency
structure, and the exposed-public-key/RLS composite via an offline engine-level
golden. Network-dependent §14 fixture directories exist with TODO manifests and
ignored harness cases, so default `cargo test --workspace` remains LocalStatic.

## Suggested Next Steps

1. Add explicit Network-gated dependency-integrity lookups for registry
   existence and OSV/advisory data.
2. Promote the ignored Network fixture placeholders to live tests when Tier 0
   fixture/mocking support and registry lookup work land.
3. Add a release/distribution track for npm wrapper packages and cross-compiled
   binaries.
4. Consider documenting the historical-ignore approximation in user-facing
   docs, since it can affect history-only findings in old paths.
