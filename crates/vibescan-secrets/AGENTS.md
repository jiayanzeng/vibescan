# `vibescan-secrets` contract

This file supplements the repository-root `AGENTS.md`. Architecture sections
5 and 9 govern this crate.

## Ownership and boundary

This crate is a `LocalStatic` generic detection substrate. It owns the pattern
registry, keyword prefilter, pure-Rust regex matching, entropy calculation, and
OR-semantics allowlists. It emits `SecretCandidate`s; it does not decide
Supabase privilege, severity, project identity, RLS exposure, or correlation.

Never depend on a sibling library or any network/transport crate. Supabase-
shaped patterns must emit `PossibleSupabaseKey` and stop there.

## Detection rules

Keep the processing order: keyword prefilter, regex/capture, entropy gate,
then per-rule/global allowlists. Preserve same-line `vibescan:allow`.

- Use the extracted capture for entropy and stopword checks.
- Keep path, regex, commit, and stopword allowlists OR-combined unless the
  architecture is explicitly changed.
- Use Rust `regex`; patterns must not require backtracking engines or native
  libraries.
- Keep the embedded ruleset zero-config and compile-tested.
- Attribute reused generic rules and respect their license. Do not expand
  generic breadth in place of the Supabase-specific product work.
- Synthetic examples and tests must use unmistakably fake credentials.
- Raw matches may remain in memory only long enough for classification and
  redaction. Never log, snapshot, or include them in an error.

The library may parse an extendable TOML ruleset, but application wiring belongs
in `vibescan-core`/`vibescan-cli`. Custom configuration must not silently remove
mandatory Supabase rules or safety allowlists.

## Verification

Add positive, placeholder, entropy-boundary, allowlist, inline-allow, path, and
false-positive tests for rule changes. Run `cargo test -p vibescan-secrets
--locked`, the golden corpus, full workspace tests, and the boundary script.
