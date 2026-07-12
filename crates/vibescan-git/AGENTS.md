# `vibescan-git` contract

This file supplements the repository-root `AGENTS.md`. Architecture sections
5, 6.1–6.2, 8, and 13 are binding for this crate.

## Ownership and boundary

This crate is strictly `LocalStatic`. It owns repository discovery, working
tree and all-ref history traversal, changed-blob collection, ignore/content
policy, location classification, scan budgets, and provenance. It must not know
what a secret means and must never depend on a sibling library, even for tests.

Use pure-Rust gitoxide/gix APIs. Do not shell out to Git in production and do
not add libgit2, transport features, sockets, or C dependencies. Test fixture
setup may invoke a local `git` executable, but runtime behavior must be proven
to work without Git on `PATH`.

## Collection rules

- Enumerate commits reachable from all refs, not only `HEAD`.
- Diff changed blobs rather than rereading full trees. Use the first parent for
  merges and emit the specified warning.
- Enforce the commit budget and report truncation. Warn on shallow clones and
  skipped submodules; degrade cleanly for detached or empty repositories.
- Apply binary and size skips uniformly and emit scope warnings.
- Honor `.gitignore`, then `.vibescanignore`, then configured path exclusions,
  while preserving the architecture's forced scanning of real `.env` files and
  shipped client bundles.
- The current-history-ignore approximation may use today's ignore files, but
  it must stay documented as a coverage limitation.

## Paths, classification, and dedup

- Normalize repo-relative paths with `/` and compare whole segments at any
  monorepo depth.
- Evaluate server-only signals before client-reachable signals. Add positive
  and substring/anchoring negative controls for every new path rule.
- Content-hash dedup must not lose alternate paths, provenance, first/last
  commit context, or the most-client-reachable class. A duplicate blob in a
  server file and a browser bundle must remain reproducible at both locations.
- Collection order must not change security semantics. Downstream consumers
  must be able to see commit membership even when a working-tree occurrence is
  the primary provenance.
- The walker emits scannable units only. Detection and Supabase interpretation
  belong downstream.

## Verification

Run `cargo test -p vibescan-git --locked`, the core golden corpus, full default
and network workspace tests, and `scripts/check-network-boundary.sh` after any
collector, dependency, ignore, location, or provenance change.
