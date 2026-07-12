# `vibescan-report` contract

This file supplements the repository-root `AGENTS.md`. Architecture sections
3, 13.3–13.4, and 14 govern this crate.

## Ownership

This crate deterministically renders an already-decided `ScanResult` as JSON,
SARIF, TTY, or self-contained HTML. It may expose a pure exit-code calculation
from a supplied gate, but it must not select policy, scan content, classify a
key, correlate findings, resolve config, or reach the network.

It may depend only on `vibescan-types` among workspace crates. Test convenience
does not permit sibling dependencies.

## Privacy and accuracy

- Treat every serialized format, including HTML, as shareable. Render only the
  redacted/fingerprinted evidence present in `Finding`.
- Never accept a raw secret merely to render it. Never include returned row
  data, public keys in request headers, credentials, or environment values.
- RLS reproduction is endpoint plus observed row count and must state read
  exposure only.
- Render every relevant location/provenance and all coverage warnings. Do not
  hide truncation or Network degradation.
- Escape all user/repository-derived HTML text and produce valid SARIF 2.1.0.
- Preserve deterministic ordering supplied by core; renderer code must not
  make finding decisions or silently filter content.

## Snapshots

Every format change requires focused tests and review of JSON, SARIF, TTY, and
HTML snapshots. Snapshots must use fixed synthetic timestamps/durations and
repo-relative paths. Update with `UPDATE_GOLDEN=1` only when intentional,
inspect the complete diff for leaks, then rerun without the variable.

Run `cargo test -p vibescan-report --locked`, the snapshot integration test,
full workspace tests in both feature modes, and `git diff --check`.
