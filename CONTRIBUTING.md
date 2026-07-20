# Contributing to vibescan

Thanks for your interest in contributing.

## License of contributions

vibescan is released under the [PolyForm Noncommercial License 1.0.0](LICENSE):
source-available, free for noncommercial use, with commercial use requiring a separate
license. By submitting a contribution (a pull request, patch, or similar), you agree that
your contribution is provided under the same PolyForm Noncommercial License that covers
the project, and that you have the right to submit it under those terms.

This is the standard "inbound=outbound" model: contributions come in under the same
license the project goes out under. There is no separate contributor agreement to sign at
this time.

If you are contributing as part of your job, please make sure you have your employer's
permission first, since many employment agreements assign work you create to your employer.

## Before you open a PR

- Discuss significant changes in an issue first, especially anything touching
  `vibescan-architecture.md` — that document is authoritative, and changes to it are
  treated as spec changes.
- Keep the safety invariants intact: no new network egress outside the sanctioned
  feature-gated transports, and nothing that weakens secret redaction or the
  own-assets-only boundary.
- Run `cargo test --workspace` and `bash scripts/check-network-boundary.sh` before
  submitting.
