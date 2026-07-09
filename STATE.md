# vibescan State

Reviewed: 2026-07-09
Updated: 2026-07-09

## Overall Status

The project now satisfies the local-first v1 architecture much more closely.
The release gates listed in the previous audit pass, including strict clippy in
both default and `network` feature builds.

Implemented and verified:

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

Files touched by this pass include:

- `README.md`
- `STATE.md`
- `crates/vibescan-core/src/lib.rs`
- `crates/vibescan-git/src/lib.rs`
- `crates/vibescan-report/src/lib.rs`
- `crates/vibescan-secrets/src/lib.rs`
- `crates/vibescan-secrets/src/rules/default-rules.toml`
- `crates/vibescan-supabase/src/lib.rs`

Pre-existing dirty files still present include:

- `Cargo.lock`
- `crates/vibescan-cli/Cargo.toml`
- `crates/vibescan-cli/src/main.rs`
- `crates/vibescan-core/Cargo.toml`
- `crates/vibescan-supabase/Cargo.toml`
- deleted: `vibescan-hardening-instructions.md`

## Verification Results

Passed:

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo test --workspace --features network`
- `cargo clippy --workspace --all-targets --no-default-features --locked --offline -- -D warnings`
- `cargo clippy --workspace --all-targets --features network --locked --offline -- -D warnings`
- `bash scripts/verify-hardening-checks.sh`

The hardening script also passed its sanitized real-repo scan and planted
gitignored `.env` Supabase secret check.

## Architecture Completion Matrix

### 1. Crate Architecture

Status: complete for v1.

The seven-crate workspace remains intact. The default/no-network dependency
tree keeps network and transport crates out of LocalStatic code paths. The
optional Tier 0 probe remains behind the `network` feature and explicit opt-in.

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

JSON, SARIF, TTY, and HTML renderers are present. Portable outputs use redacted
evidence. TTY/HTML now show all locations for each finding and include
first-seen/last-seen commit context when deduplicated historical provenance is
available. Correlated public-key chains absorb their constituents in the final
summary.

### 11. CLI

Status: complete for v1.

The CLI remains thin. Config loading now resolves the repository root before
loading `vibescan.toml`, so subdirectory targets inherit root config.

## Suggested Next Steps

1. Add explicit Network-gated dependency-integrity lookups for registry
   existence and OSV/advisory data.
2. Add a small fixture corpus directory for architecture-level golden tests
   instead of relying only on in-test temporary repositories.
3. Add a release/distribution track for npm wrapper packages and cross-compiled
   binaries.
4. Consider documenting the historical-ignore approximation in user-facing
   docs, since it can affect history-only findings in old paths.
