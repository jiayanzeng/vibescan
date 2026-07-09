# vibescan — Codex Instructions: Tier A1 + Tier B3

Reviewed: 2026-07-09
Author: architecture review (Claude), for implementation by Codex

## How to consume this document

Two independent tasks. Each is self-contained with an explicit spec basis, file
targets, implementation guidance, and self-verifiable acceptance criteria. Do
not treat status notes in `STATE.md` as authority — the authority is
`vibescan-architecture.md`. Every finding below is tied to a spec section; if an
implementation choice conflicts with a cited section, the section wins and you
should surface the conflict rather than silently diverge.

Both tasks assume a committed `Cargo.lock` so that CI can run `--locked`
(Tier B item 2 in the review — reconcile the dirty worktree — is a prerequisite
for the CI job to be reproducible; if the lockfile is still uncommitted when you
start, commit it as the first step of Task A1).

---

## Task A1 — Feature-aware network-boundary assertion, wired into CI

### Spec basis

- **§1 (core principle 1):** the `LocalStatic` / `Network` split is
  "architectural, not a runtime flag: the crate dependency graph enforces that
  `LocalStatic` code paths cannot reach a network client."
- **§13.3:** "`LocalStatic` crates have **no** network dependency in their
  dependency tree — enforce by construction and **assert in CI**."
- **§14 (Testing strategy):** "**Boundary assertion:** an automated check that no
  `LocalStatic` crate transitively depends on a network crate."
- **§13.1:** the `Network` tiers are expected to use a **pure-Rust TLS stack**
  (rustls). This is the correctness constraint the current check gets wrong.

### Problem — why the current check is insufficient

`scripts/verify-hardening-checks.sh` conflates three concerns and fails its own
§13.3/§14 acceptance on all three:

1. **Not automated.** There is no `.github/workflows/` directory anywhere in the
   tree, so nothing runs this on push. It is a manually-invoked local script.
2. **Not runnable in a clean CI runner.** It hardcodes a personal fixture path
   (`/Users/yzjia/codexbuildapp/fintelcore/dashboard`) and requires an external
   Next.js/Supabase repo plus `rsync`, `python3`, and `rg`. A clean checkout
   cannot execute it.
3. **Brittle and feature-blind.** The boundary check is a text `rg` of a
   fixed denylist over `cargo tree --workspace --edges normal` **display
   output**, run only against the default feature set. Two concrete defects:
   - Substring matching over rendered text is not package identity — it can miss
     a renamed transport crate and can false-match on unrelated names.
   - The denylist includes `rustls`. Under `--features network`,
     `vibescan-supabase` pulls `reqwest` with `rustls-tls` **by design**
     (§13.1). If this same denylist were ever applied to the network build it
     would flag the sanctioned TLS stack. The check must be **feature-aware**:
     forbid *all* transport in the default build, but under `network` verify
     *reachability* (transport reachable only through `vibescan-supabase`), not
     mere presence.

### Crate classification (the invariant to assert)

From §3 and the crate table:

- **Pure `LocalStatic` (zero transport in any configuration):**
  `vibescan-types`, `vibescan-git`, `vibescan-secrets`, `vibescan-report`.
- **`vibescan-core`:** LocalStatic that *orchestrates* Network; its `network`
  feature only forwards (`network = ["vibescan-supabase/network"]`). No direct
  transport dep. Default build must be transport-free.
- **`vibescan-supabase`:** `LocalStatic + Network`. `default = []`;
  `network = ["dep:reqwest"]` where `reqwest` is `default-features = false,
  features = ["blocking", "json", "rustls-tls"], optional = true`. Transport is
  permitted **only** under `--features network`, and only here.
- **`vibescan-cli`:** thin shell; `network = ["vibescan-core/network"]`.

Feature propagation chain: `cli → core → supabase → dep:reqwest`.

### File targets

- **New:** `scripts/check-network-boundary.sh` — fixture-free, the only thing CI
  runs for the boundary. Replaces the boundary portion of
  `verify-hardening-checks.sh`.
- **New:** `.github/workflows/ci.yml` — runs fmt, clippy (default + network),
  test (default + network), and the boundary script on push/PR.
- **Edit:** `scripts/verify-hardening-checks.sh` — remove the hardcoded personal
  path; make the real-repo sanitized scan a *separate, opt-in* concern that
  cleanly skips (exit 0 with a "skipped: no fixture" notice) when neither
  `argv[1]` nor `VIBESCAN_REAL_REPO` is set. It stays a developer convenience,
  not a CI gate.
- **Edit (docs):** `README.md` and/or `STATE.md` — point the boundary invariant
  at the new script.

### Implementation guidance

Assert package **identity**, not text. Use exact resolved package-name set
membership. Prefer `cargo tree` with a machine-parseable format
(`--prefix none --format '{p}'` and normalize each line to its crate name) or
`cargo metadata --format-version 1` walked as a graph. Restrict to `--edges
normal` so dev-deps and build-deps do not count against the runtime tree
(supabase has a dev-dependency on `vibescan-secrets`; test-only deps must never
trip the check).

Define the transport denylist as a set of **exact crate names**, e.g.
`reqwest, hyper, h2, tokio, tokio-util, tokio-rustls, ureq, isahc, curl,
native-tls, openssl, openssl-sys, rustls, hyper-util`. (Keep it maintainable and
comment why each is here.)

Three assertions:

1. **Default build, whole workspace — presence check.**
   `cargo tree --workspace -e normal` (default features) must contain **none**
   of the denylist, matched by exact package name. This is the strict §13.3
   statement: with no feature flags, nothing network is in the tree at all
   (including `rustls`, which is correctly forbidden in the default build).

2. **Network build — reachability check (this is the feature-aware fix).**
   With `--features network`, transport crates *are* expected. Do **not**
   denylist them globally here. Instead, for each transport crate that appears,
   assert its only workspace-crate parent is `vibescan-supabase`:
   `cargo tree -i <crate> -e normal --features network` — the set of
   `vibescan-*` parents must equal `{vibescan-supabase}`. This proves no
   `LocalStatic` crate reaches a network client even when the feature is on,
   and it permits `rustls` because it is reached only through supabase.

3. **Per-crate belt-and-suspenders.** For each of `vibescan-types`,
   `vibescan-git`, `vibescan-secrets`, `vibescan-report`, assert its individual
   normal-edge subtree contains no denylisted crate, evaluated both with default
   features and with `--features network` passed at the workspace level (these
   crates do not propagate the feature, so their subtrees must stay clean
   regardless). `cargo tree -p <crate> -e normal [--features network]`.

CI workflow (`.github/workflows/ci.yml`) jobs, all `--locked`:
- `fmt`: `cargo fmt --all -- --check`
- `clippy-default`: `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `clippy-network`: `... --features network ...`
- `test-default`: `cargo test --workspace --locked`
- `test-network`: `cargo test --workspace --features network --locked`
- `network-boundary`: `bash scripts/check-network-boundary.sh`

Pin the toolchain to the workspace MSRV (`rust-version = "1.85"`, edition 2024,
resolver 3). Do not add the real-repo scan to any required CI job.

### Acceptance criteria (self-verifiable)

1. On a clean checkout, `bash scripts/check-network-boundary.sh` exits `0` and
   requires no external fixture, no personal path, and no network access.
2. **Negative control — default build:** temporarily add `reqwest` as a
   non-optional `[dependencies]` entry to `vibescan-git`; the script exits
   non-zero and names `vibescan-git` and `reqwest`. Revert; it passes again.
3. **Negative control — reachability:** temporarily add `reqwest` (non-optional)
   to `vibescan-report`; under the `--features network` reachability check the
   script exits non-zero because `reqwest` now has a `vibescan-*` parent other
   than `vibescan-supabase`. Revert; it passes.
4. **rustls is allowed under network, forbidden in default:** with no negative
   controls applied, assertion 1 confirms `rustls` is absent from the default
   tree, and assertion 2 passes with `rustls` present but parented only by
   `vibescan-supabase`. The script must not fail on the stock repo under
   `--features network`.
5. Matching is by exact resolved package name: introducing a dummy crate whose
   name merely *contains* a denylisted substring but is not itself a transport
   crate does not trip the check (document the match logic; a unit-level or
   inline comment demonstrating exact-name comparison suffices).
6. `grep -rn '/Users/' scripts/` returns nothing. `verify-hardening-checks.sh`
   exits `0` with a clear "skipped" message when no fixture is provided.
7. `.github/workflows/ci.yml` exists and runs all six jobs above; the real-repo
   scan is either absent from CI or a separate non-required step gated on
   `VIBESCAN_REAL_REPO`. All jobs use `--locked`.

---

## Task B3 — Architecture-level golden-fixture corpus

### Spec basis

- **§14 (Testing strategy):** mandates a **"Vulnerable-fixture corpus:** a set of
  deliberately-broken sample repos as golden inputs — the exposed-public-key
  chain, an elevated key committed then removed (history-only), an RLS-off
  table, a permissive `USING (true)` policy, a hallucinated dependency. Each
  fixture asserts the exact findings and severities produced." It further
  requires a **"Precision/recall harness"** including a **clean control repo
  which must produce zero findings**, and **snapshot tests** per report format.
- **§6.6 (finalize):** findings are deduped by `finding.id` and sorted by
  severity — the harness relies on a stable ordering plus a deterministic
  secondary key.

### Problem

Correctness today rests entirely on in-test temporary repositories built
programmatically inside `#[cfg(test)]` modules (e.g. `TestRepo` in
`vibescan-git`). There is no committed corpus of golden inputs asserting exact
findings and severities end-to-end through the pipeline, so the P0/P1 fixes
(nested-gitignore correctness, `.next/server/vendor-chunks` exclusion,
publishable-key handling, history-only elevated-key classification) are not
locked against regression at the architecture level. This is the §14
requirement, not new scope.

### Determinism constraints (must be designed for, not bolted on)

The scan result carries **nondeterministic fields** that a naive full-output
snapshot would thrash on. `started_at` is now a live `Timestamp::now()` RFC3339
value (verified in the current tree), `duration`/`duration_ms` is wall-clock,
`tool_version` changes across releases, and temp materialization paths are
absolute and per-run. The harness **must** project each finding to a canonical,
stable shape before diffing and must never assert on the run envelope.

### File targets

- **New:** `tests/fixtures/<name>/` corpus directories (workspace root), one per
  fixture, each containing the source tree plus an `expected.json` golden
  manifest. History-dependent fixtures additionally ship a committed
  `history.bundle`.
- **New:** a golden harness integration test. Recommended location:
  `crates/vibescan-core/tests/golden_corpus.rs`, driving the offline scan via
  the `vibescan-core` public API (fast, hermetic, and avoids spawning the
  binary — consistent with §13.1). Report-format snapshots (§14) may live
  alongside or in `vibescan-report/tests/`.
- **Do not** delete or weaken the existing in-test temp-repo unit tests; the
  corpus is additive coverage.

### Corpus contents

Offline, LocalStatic-testable in v1 (implement fully now):

1. **`clean-control/`** — a realistic small repo with zero real secrets.
   Expected: **no findings**. This is the §14 precision anchor; a false positive
   here fails CI.
2. **`history-only-elevated-key/`** — an `sb_secret_…` (or `service_role` legacy
   JWT) committed and then removed in a later commit; working tree is clean.
   Expected: a **Critical** standalone `SecretExposure` with provenance kind
   `Commit` and stable first-seen/last-seen SHAs. Requires `history.bundle`.
3. **`publishable-client-reachable/`** — an `sb_publishable_…` key plus a
   co-located `https://<ref>.supabase.co` URL in a client-reachable path (per
   §6.2 location heuristics). Expected: an **Info** standalone finding (it must
   *not* be Critical without an RLS correlation). Working-tree only.
4. **`vendor-chunks-noise/`** — a high-entropy vendored bundle under
   `.next/server/vendor-chunks/` (the exact P1 false-positive source) **and** a
   planted real secret in a scanned path. Expected: **zero findings from the
   vendored bundle**, plus the expected finding for the planted secret. This
   locks the P1 regression. Working-tree only.
5. **`nested-gitignore/`** — a nested `.gitignore` suppressing a subdirectory,
   with a look-alike sibling path that must still be scanned (the P0
   segment-vs-substring case). Expected asserts the suppressed path yields
   nothing and the sibling is scanned. Working-tree only.
6. **`malformed-dependency/`** — a manifest with an invalid package name and an
   empty version specifier (the offline structural checks that dependency
   integrity actually implements today). Expected: the corresponding structural
   findings. Working-tree only.

Network-dependent §14 fixtures — **structure now, gate the assertions.** The
exposed-public-key **chain**, the RLS-off table, the permissive `USING (true)`
policy, and a truly *nonexistent* ("hallucinated") dependency all require the
Tier 0 probe / registry lookups, which are Network and (registry lookups)
post-v1. Represent each as a fixture directory with an `expected.json` and a
harness case that is `#[ignore]`d or `#[cfg(feature = "network")]`-gated, with a
`TODO` referencing the network work. Additionally, add **one offline
engine-level golden** for the composite: feed the correlation engine a
synthetic publishable-key finding plus an RLS finding with matching project
URLs and assert the **Critical** composite plus constituent absorption — this
covers the chain deterministically without a live probe.

### Golden manifest + normalization

`expected.json` stores a **canonical finding list**: for each finding, a stable
subset — e.g. `{ stable_key, rule_id, category, severity, locations: [path…]
(sorted), provenance_kind, correlation_related?: [...] }`. Exclude
`started_at`, `duration`/`duration_ms`, `tool_version`, absolute paths, and any
identifier that embeds a timestamp or an absolute path. If `finding.id` embeds a
content hash that is path/timestamp-independent, it is stable and may be the
`stable_key`; otherwise derive a stable key (e.g. `rule_id` + sorted
repo-relative paths + provenance) and canonicalize it. Sort the canonical list
by `(severity, stable_key)` before diffing.

Provide an `UPDATE_GOLDEN=1` env switch that regenerates every `expected.json`
from the current run; CI runs with it unset and fails on any drift.

### History-fixture mechanism (decision point)

To keep SHAs stable, ship history fixtures as a committed `history.bundle` and
have the harness materialize it into a temp dir. Cloning a bundle uses the `git`
binary **at test time only** — this is an isolated test-environment convenience,
not a runtime violation of §13.1 (there is already a test proving the scanner
runs a history scan with an empty PATH). If you prefer to avoid the test-time
git dependency entirely, generate the history deterministically with pinned
`GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE`, identity, message, and file content so
the commit SHAs are reproducible, and record those SHAs in `expected.json`.
State which mechanism you chose and why in `STATE.md`.

### Acceptance criteria (self-verifiable)

1. `tests/fixtures/` contains, at minimum: `clean-control`,
   `history-only-elevated-key`, `publishable-client-reachable`,
   `vendor-chunks-noise`, `nested-gitignore`, `malformed-dependency`, each with
   an `expected.json`.
2. `cargo test --workspace` runs the golden harness; every non-gated fixture's
   normalized findings equal its `expected.json`.
3. **Determinism:** running the golden test twice in a row produces identical
   results, and `expected.json` contains no absolute paths, no timestamps, no
   `tool_version`, and no `duration`. (Grep the committed manifests to confirm.)
4. **Precision:** `clean-control` yields exactly zero findings.
5. **P1 regression lock:** `vendor-chunks-noise` yields no finding attributable
   to any file under `.next/server/vendor-chunks/`, and does yield the expected
   finding for the planted secret.
6. **History classification:** `history-only-elevated-key` yields a Critical
   standalone `SecretExposure` with provenance kind `Commit` and the recorded
   first-seen/last-seen SHAs.
7. **Publishable is Info, not Critical:** `publishable-client-reachable` yields
   an Info finding and no standalone Critical.
8. **Composite covered offline:** the engine-level composite golden asserts a
   Critical correlated finding with its key/RLS constituents absorbed from the
   summary.
9. **Drift detection:** mutating a rule's severity or a fixture's secret causes
   the corresponding golden case to fail; `UPDATE_GOLDEN=1 cargo test …`
   regenerates the manifests and the suite passes again.
10. Network-dependent §14 fixtures exist as directories with manifests and
    `#[ignore]`/feature-gated harness cases carrying TODOs; they do not block the
    default `cargo test --workspace`.
11. Existing in-test temp-repo unit tests still pass unchanged.

---

## Notes for review

- Task A1's reachability check (assertion 2) is the substantive correctness
  improvement over the current script — it is what makes the boundary invariant
  hold under `--features network` while still honoring §13.1's pure-Rust TLS
  requirement. Confirm the `cargo tree -i` inversion resolves the way this
  document assumes on your toolchain; if `-i` behaves unexpectedly under
  workspace feature unification, fall back to a `cargo metadata` graph walk and
  note the change.
- Task B3 deliberately scopes the network fixtures as gated placeholders so the
  corpus *shape* matches §14 in full while v1 does not block on a mocked
  PostgREST surface. When the Network dependency-integrity work lands (review
  Tier C), those placeholders become live and the mock is the natural home for
  the RLS/`USING (true)` fixtures.
