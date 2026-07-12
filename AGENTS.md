# Codex operating contract for vibescan

## Scope and authority

This file applies to the entire repository. A more deeply nested `AGENTS.md`
adds rules for its subtree; it may not weaken this file or the architecture.

`vibescan-architecture.md` is the authoritative product and engineering
specification. Read it in full before changing code, tests, manifests, CI,
fixtures, or user-facing behavior. Treat it as the decision rubric, not as
background reading.

Use repository documents in this order:

1. The user's explicit request. If it would change or contradict the
   architecture, surface that fact and amend the architecture first only when
   the user explicitly wants a specification change.
2. `vibescan-architecture.md`.
3. This file and the nearest scoped `AGENTS.md`.
4. Current source, tests, manifests, and CI configuration.
5. `STATE.md`, `README.md`, and task instruction files as status/history only.

`STATE.md` is never proof that an item is complete. Re-check the current
checkout and run the relevant gates. `vibescan-tierC-instructions.md` records a
completed implementation tier; it does not supersede the architecture.
Existing code may predate this contract; known mismatches are recorded in
`STATE.md`. Do not treat their presence as permission to repeat or normalize
them. Fix them within the authorized task scope or report them explicitly.

## Required start-of-task protocol

Before editing:

1. Read `vibescan-architecture.md`, this file, and every scoped `AGENTS.md`
   governing the files in scope.
2. Read `STATE.md`, then verify any relevant status claim against the current
   commit and implementation.
3. Run `git status --short`. Preserve all pre-existing changes as user-owned;
   never discard, rewrite, or fold them into unrelated work.
4. Map the request to architecture sections, the owning crate, and one of these
   capability classes: `LocalStatic`, opt-in `Network`, or deferred/out of v1.
5. Identify acceptance tests before implementation. Use a failing regression
   test or deterministic fixture when fixing behavior.
6. Inspect dependency direction before adding or moving code. Test convenience
   does not justify an architecture-breaking dependency.

If the task is an audit, compare the implementation directly with every
relevant architecture requirement. Report complete, partial, missing,
deferred, and contradictory items separately.

## Non-negotiable invariants

- The default product is `LocalStatic`: filesystem plus local Git object store
  only. It must have no reachable transport client, DNS, socket, or network
  dependency.
- Network capability is compile-time feature-gated, runtime opt-in, visibly
  recorded in the scan scope, and limited to assets the user controls.
- Never turn vibescan into an arbitrary URL scanner.
- No v1 code path may create, modify, or delete target-project data. Never add
  insert, update, delete, RPC mutation, write-probe, active DAST, or BOLA
  behavior. Write exposure may only be inferred from authorized introspection.
- Tier 0 proves anonymous read exposure only. Never claim that Tier 0 proved
  modification or write access.
- Raw secret values stay on the machine. They may exist transiently in
  `SecretCandidate` and, for an explicitly credentialed future tier, in memory
  for a request to the user's own project. They must not enter logs, errors,
  fixtures, snapshots, persisted reports, or portable output.
- JSON, SARIF, and HTML are always treated as shareable and must be redacted.
  TTY is redacted by default too. A future full-value local view would require
  an explicit local-only design and tests proving it cannot be exported.
- RLS evidence contains the endpoint and observed row count, never returned row
  data.
- Every finding must have stable identity, reproducible evidence, accurate
  scope/provenance, confidence, and concrete remediation.
- Keep the seven-crate DAG. Do not add an eighth crate in v1.
- Use pure-Rust components: gitoxide/gix APIs, Rust `regex`, and rustls-backed
  transport. Do not introduce libgit2, C regex engines, OpenSSL-linked clients,
  or another C toolchain dependency.
- Do not broaden generic secret detection as a product moat. Reuse and
  attribute a compatible corpus; keep innovation in Supabase semantics and
  correlation.

## Crate graph and ownership

Allowed workspace edges are:

```text
vibescan-cli -> vibescan-core
vibescan-core -> vibescan-git
vibescan-core -> vibescan-secrets
vibescan-core -> vibescan-supabase
vibescan-core -> vibescan-report
vibescan-core -> vibescan-types
vibescan-git -> vibescan-types
vibescan-secrets -> vibescan-types
vibescan-supabase -> vibescan-types
vibescan-report -> vibescan-types
```

Arrows point downward only. The rule applies to normal, build, dev, target,
optional, and feature-activated dependencies. Sibling-library dev-dependencies
are not an exception; place cross-crate integration tests in `vibescan-core` or
another architecture-approved top-level harness.

- `vibescan-types`: shared data vocabulary and light traits only.
- `vibescan-git`: LocalStatic repository discovery, working-tree/history
  collection, content handling, location classification, and provenance.
- `vibescan-secrets`: generic matching substrate only.
- `vibescan-supabase`: Supabase key semantics and the only optional transport
  boundary.
- `vibescan-core`: configuration, orchestration, dependency checks,
  coalescing, correlation, baselines, and severity-gate policy.
- `vibescan-report`: deterministic rendering only.
- `vibescan-cli`: argument parsing and process presentation only.

Shared shapes belong in `vibescan-types`; cross-module wiring belongs in
`vibescan-core`. Do not make sibling crates call each other.

## Pipeline contract

Preserve this phase order:

1. Resolve target/config/baseline and collect LocalStatic units.
2. Detect generic candidates.
3. Enrich Supabase semantics and optionally run expressly enabled Network work.
4. Coalesce linkable facts and run declarative correlation rules.
5. Deduplicate, apply baselines, absorb summary constituents, sort, compute
   stats, render, and derive the severity-gate result.

Behavioral constraints:

- Content-hash dedup happens before detection, but it must retain every distinct
  path, provenance, and location class needed for reproducible findings.
- A location counts as committed when either its primary provenance or any
  additional provenance is a commit. Never make correlation depend only on the
  primary value chosen by deduplication.
- Candidate enrichment must use content from the candidate's exact unit/blob
  revision. A path-only map must not let one historical version supply project
  context for a different version at the same path.
- Path logic uses repo-relative `/`-separated whole components at any nesting
  depth. Never use root-only `starts_with` or raw substring matching.
- Server signals win over client signals. Coalescing carries the most
  client-reachable class across all locations.
- Same-secret coalescing is conservative and stable across location order.
  Never merge different fingerprints or known-different projects. When one
  copy has reliable project context and another has none, preserve the shared
  identity and enrich cautiously instead of leaving the client location unable
  to participate in same-project correlation.
- Correlation rules are declarative data in `vibescan-core`; v1 ships exactly
  the two rules in architecture section 12.
- Baseline-suppressed findings do not affect stats used for the final summary or
  the exit gate.
- Scope warnings must make truncation, skipped content, disabled history, and
  degraded Network coverage explicit. Never imply a complete scan when a
  budget or error reduced coverage.

## Configuration and CLI precedence

Resolve configuration as: built-in defaults, then target-repository
`vibescan.toml`, then only CLI options the user explicitly supplied. A clap
default must not erase a TOML value. Resolve config-referenced paths, including
baselines and custom rule files, relative to the discovered repository root
unless the user supplied an absolute path. Report the scope actually scanned.

The embedded ruleset must keep zero-config behavior. If the architecture's
custom ruleset surface is wired into the application, extend or merge it
deliberately; do not silently replace Supabase rules or safety allowlists.

## Network and external-service policy

The `network` feature may expose transport only through
`vibescan-supabase`. Both the feature and an explicit user action are required
to execute a request.

For Tier 0:

- Accept only normalized `https://<project-ref>.supabase.co` targets associated
  with a key found in the scanned repository.
- Use read-only `GET /rest/v1/<table>?select=*&limit=1`.
- Send the public key in `apikey` on every request. Bearer-only auth is invalid.
- Harvest candidate names locally. The OpenAPI root is optional supplementation
  and its failure must not erase offline findings.
- Distinguish key rejection, root-enumeration denial, no candidates, protected
  results, and transport failure.
- Record enough scope information to audit which read actions ran, including
  successful protected outcomes, without recording row content or keys.

Use mocks for automated Network tests. Do not run live probes, real registry
queries, or credentialed tests unless the user explicitly authorizes that
specific external action and target. Never use shared infrastructure.

Architecture sections 1–2 limit network actions to the user's Supabase assets,
while section 11 proposes optional registry/OSV lookups. Do not implement
third-party egress until the architecture explicitly resolves that conflict or
the user authorizes a specification update. Preserve the offline dependency
path in every case.

Tier 1 introspection, release/distribution work, active DAST, web accounts,
billing, and client-auth heuristics are deferred. Do not start deferred work
merely because nearby code makes it convenient.

## Test and fixture discipline

Prefer targeted tests while iterating. Before claiming a cross-crate,
architecture, milestone, dependency, feature, or release change complete, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
git diff --check
```

Use `bash scripts/verify-hardening-checks.sh` for the local hardening aggregate.
Its optional real-repository argument is not part of the default gate and must
not be pointed at user data without explicit approval.

For focused changes also run the owning tests:

- shared vocabulary: `cargo test -p vibescan-types --locked`
- collection/path/history: `cargo test -p vibescan-git --locked`
- detection/rules: `cargo test -p vibescan-secrets --locked`
- Supabase/network: default plus
  `cargo test -p vibescan-supabase --features network --locked`
- orchestration/correlation: `cargo test -p vibescan-core --locked` plus the
  network-feature variant when relevant
- renderers: `cargo test -p vibescan-report --locked` and report snapshots
- golden corpus: `cargo test -p vibescan-core --test golden_corpus --locked`

Golden updates are review operations, not formatting operations. Set
`UPDATE_GOLDEN=1` only after an intentional behavior change, inspect every
manifest/snapshot diff, then rerun without the variable. Expected artifacts
must contain no real credentials, row data, absolute local paths, live
timestamps, random IDs, or uncontrolled ordering.

Do not weaken, delete, ignore, or regenerate a failing test just to obtain a
green run. Temporary negative controls must be reverted immediately.

## Definition of done and status reporting

A change is complete only when:

- its architecture requirements and non-goals are named;
- the code lives in the correct crate and preserves the dependency boundary;
- regression tests cover success, negative, degraded, and safety cases in
  proportion to risk;
- affected golden manifests and report snapshots are intentionally reconciled;
- relevant default and `network` gates pass on the current checkout;
- documentation describes actual behavior and limitations; and
- `STATE.md` is updated for milestone/status work with the date, commit,
  worktree state, commands actually run, results, intentional gaps, and ordered
  next steps.

Never copy old pass counts or describe a previously dirty tree as current. Do
not call the full architecture complete when only build-order steps 1–8 are
complete; distinguish buildable-v1, full-spec, and deferred scope.

Stop and ask before changing the architecture, adding a crate, enabling new
external egress, running live tests, handling real credentials, or entering a
deferred track. Stop immediately if a proposed test or implementation could
write to a target project.
