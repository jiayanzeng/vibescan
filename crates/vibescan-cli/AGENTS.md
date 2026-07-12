# `vibescan-cli` contract

This file supplements the repository-root `AGENTS.md`. The CLI must remain a
thin shell over `vibescan-core`.

## Responsibilities

This crate owns clap definitions, user-facing help, config/argument handoff,
progress/process presentation, stdout/stderr selection, and process exit-code
conversion. It must not collect files, inspect Git, match secrets, classify
Supabase keys, correlate findings, render format internals, or implement HTTP.

## Argument behavior

- Load target-repository config first, then override only values corresponding
  to CLI arguments the user explicitly supplied. Boolean/default clap values
  must not erase TOML choices.
- Resolve relative config paths in core against the repository root; do not
  reinterpret them against the caller's current directory.
- Keep Network arguments compiled behind `network` and visibly opt-in. No
  config or CLI default may silently enable a request.
- Help text must distinguish default LocalStatic behavior from optional
  Network behavior and must not overclaim write exposure.
- Keep output clean: report on stdout, diagnostics on stderr. Never print raw
  secrets or row data.
- Preserve exit semantics: 0 below the configured gate, 1 when the gate is met,
  and 2 for operational/configuration failure.

Add CLI-level tests for precedence and feature-gated flag availability when
changing arguments. Run package/default/network workspace tests and the
boundary check.
