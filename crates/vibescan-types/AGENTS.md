# `vibescan-types` contract

This file supplements the repository-root `AGENTS.md`. Read both plus
`vibescan-architecture.md` before editing this crate.

## Ownership

This crate is the stable shared vocabulary: serializable data shapes, enums,
identifiers, and lightweight sink traits. It must not scan, read files, access
Git, classify keys, hash secrets, correlate findings, render output, resolve
configuration, or make policy decisions.

It has no workspace dependencies. Keep it free of network, filesystem, CLI,
formatting, and domain-engine dependencies.

## Data rules

- `SecretCandidate` may carry a full raw match transiently between LocalStatic
  phases. `Finding` evidence must remain redacted and safe to serialize.
- Preserve every location and provenance needed to reproduce a finding.
- Keep serialized enum/tag names stable. Treat renames and field-shape changes
  as compatibility changes that require all consumers, goldens, and snapshots
  to be audited.
- Severity ordering, stable identifiers, scan-scope warnings, and evidence
  variants are cross-workspace contracts. Do not encode crate-specific logic
  in them.
- Add a shared shape only when at least two layers need the vocabulary. Keep
  orchestration and conversion logic in the owning higher crate.

## Verification

Run `cargo test -p vibescan-types --locked`, then all workspace default and
network tests for a public data-model change. Inspect JSON/SARIF/HTML/TTY
snapshots and baseline compatibility whenever serialization changes.
