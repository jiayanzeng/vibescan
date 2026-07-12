# Verification-script contract

This file supplements the repository-root `AGENTS.md` and applies to scripts
that enforce architecture or hardening gates.

## Script behavior

- Use repo-relative discovery; never embed a developer home path or assume the
  caller's current directory.
- Start Bash scripts with `set -euo pipefail`. Quote paths and clean temporary
  files/directories with a trap.
- Keep the default path offline-safe and deterministic. Optional real-repo or
  live legs must require an explicit argument/environment value and must say
  clearly when they are skipped.
- Never copy real secrets into the repository or print them. Plant only
  synthetic values in isolated temporary copies.
- Distinguish a convenience smoke/hardening helper from the full closeout
  matrix in root `AGENTS.md`; do not imply that a partial script proves all CI
  gates.

## Boundary checker

`check-network-boundary.sh` is a security control. It must inspect exact Cargo
package identities and all relevant dependency kinds/features. The default
graph must contain no transport, and enabled transport must be nearest-parented
only by `vibescan-supabase`; LocalStatic siblings must remain transport-free.

Changes to the checker require positive and negative controls that prove it
accepts the intended graph and rejects transport leakage or horizontal
workspace dependencies. Do not weaken a denylist or skip a graph because a
new dependency makes the check inconvenient.

Run the changed script, both Cargo feature matrices, and `git diff --check`.
