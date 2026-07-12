# vibescan State

Reviewed: 2026-07-12

Current implementation baseline: `36b0a1b` (`main`) plus the Phase 3A worktree
described below.

Prior architecture-audit baseline: `e7e9263`.

Authority: `vibescan-architecture.md`. This file records observed status; it
does not override the architecture or prove completion by itself.

## Executive verdict

vibescan is a substantial, runnable local-first Rust CLI. Every build-order
step in architecture section 15 (steps 1–8) has an implementation, Tier C has
landed, Phase 1 preserves exact content/source occurrences, and Phase 2 now
uses that identity for exact Supabase enrichment, conservative project-aware
coalescing, Tier 0 input preparation, and provenance-aware correlation. Phase
3A now distinguishes root-enumeration unavailability from table-level key
rejection.

The strict completion verdict is nevertheless **partial**, not complete.
Several later cross-phase linkage defects can still suppress the headline
public-key-plus-RLS correlation in realistic layouts. The literal crate DAG,
configuration contract, extendable ruleset surface, Network auditability,
dependency intelligence, performance/precision evidence, and distribution
requirements also have remaining work.

Use these three lenses when discussing completion:

- **Runnable v1 coverage:** all eight section-15 steps exist and the current
  automated gates are green.
- **Strict buildable-v1 conformance:** partial because some edge cases can lose
  locations, commit status, or project linkage, and two sibling dev-dependency
  edges violate the literal crate rule.
- **Entire architecture document:** partial. Online dependency intelligence,
  full section-14 assurance, performance proof, Tier 1, and distribution are
  missing or explicitly deferred.

No target-project write path was found. The production RLS transport exposes
GET only, validates Supabase-owned URLs, and discards returned row data after
counting. The default production dependency graph remains transport-free.

## Current worktree context

Phase 3A starts from `36b0a1b`, which contains Phases 0–2. The current worktree
changes the Supabase warning type/handling, the mocked network golden assertion,
and Phase 3A planning/status documentation. No report snapshot, transport
implementation, CLI behavior, live endpoint, or target-project data changed.

All Phase 1–3A regressions are green. The suite remains intentionally red only
for Phase 3B project-table scoping and Phase 4 CLI/baseline behavior.

## Phase 3A verification observed on 2026-07-12

The following pass on the current Phase 3A worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-supabase --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error \
  --skip tier0_probe_inputs_keep_harvested_tables_project_local \
  --skip tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table
bash scripts/check-network-boundary.sh
git diff --check
```

No live Network action was run. The remaining deliberate reds are exactly two
Phase 3B table-scope cases and three Phase 4 CLI/baseline cases.

## Phase 2 verification observed on 2026-07-12

The following pass on the current Phase 2 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked -- \
  --skip tier0_probe_inputs_keep_harvested_tables_project_local \
  --skip tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

Default and network workspace matrices pass when only the later-phase known-red
tests are excluded. No golden or report snapshot changed, and no live Network
action was run. An unfiltered default `--no-fail-fast` audit confirms that the
remaining failures are exactly the three Phase 4 CLI/baseline cases and two
Phase 3 root-warning cases; the network matrix additionally retains the two
Phase 3 project-table-scope cases.

## Phase 1 verification observed on 2026-07-12

The following pass on the current Phase 1 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-types --locked
cargo test -p vibescan-git --locked
cargo test -p vibescan-secrets --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

The default and `network` workspace matrices also pass when only the remaining
known-red Phase 2–5 regression names are excluded. The Phase 1 regression
`identical_content_at_server_and_browser_paths_retains_both_locations` passes.
No live network action was run.

## Prior audit verification observed on 2026-07-12

The following passed against the clean `e7e9263` code baseline:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo clippy --workspace --all-targets --features network --locked --offline -- -D warnings
cargo test --workspace --locked --offline
cargo test --workspace --features network --locked --offline
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

Measured results:

- default feature set: **79 passed, 4 ignored**;
- `network` feature set: **81 passed, 3 ignored**;
- boundary check: default graph contained no transport crates; enabled
  transport was nearest-parented by `vibescan-supabase`; the four production
  `LocalStatic` libraries were transport-free;
- hardening helper: deterministic local checks passed; its optional sanitized
  real-repository leg was skipped because no fixture path was provided; and
- committed expected manifests/snapshots contained no detected absolute home
  paths or live scan-envelope fields.

These results prove the current covered behavior. They do not prove the missing
edge cases or deferred requirements described below. A live Supabase target was
not contacted and is not required for the default completion gate.

After the documentation changes, the closeout pass also reran and passed:

- `cargo fmt --all -- --check`;
- `bash scripts/check-network-boundary.sh`;
- the default golden corpus (**4 passed, 4 intentionally ignored**);
- the network golden corpus (**5 passed, 3 intentionally ignored**);
- report snapshots (**1 passed**); and
- `git diff --check`.

## Architecture completion matrix

| Architecture area | Status | Evidence and limitation |
|---|---|---|
| Design invariants | Partial / safety core verified | LocalStatic default, own-Supabase URL guard, read-only Tier 0, redaction, and no persisted writes are implemented. Per-Network-action audit records are incomplete. |
| Seven-crate workspace | Partial under the literal rule | The production DAG is layered and acyclic, but `vibescan-git` and `vibescan-supabase` each dev-depend on sibling `vibescan-secrets`. The boundary script checks normal edges only. |
| Shared data model | Phase 1 identity complete | `ContentId`, `UnitLocation`, `ScannableUnit.locations`, and `UnitRef.locations` form one canonical occurrence model; singular competing fields were removed. |
| Content handling | Substantially implemented | Binary/size skips, ignore layers, forced real-env/client-bundle scanning, inline allow, and commit allowlists exist. Historical paths intentionally use current ignore state. |
| Scan pipeline | Partial | All five phases exist and exact `ContentId` lookup now binds enrichment to the candidate revision. Units/candidates/findings remain materialized rather than streamed. |
| Location classification | Verified for covered Tier C and Phase 1 cases | Whole-segment monorepo matching, server-first precedence, substring controls, and identical-content server/browser occurrence retention are tested. |
| Generic secret substrate | Partial application contract | Keyword prefilter, regex, entropy, allowlists, attribution, and the required provider families exist. `Detector::from_toml` is not wired through core/CLI, so the architecture's extendable ruleset is library-only. |
| Git walker | Partial | Discovery, all refs, budgets, changed blobs, working tree, edge warnings, and full SHA-256 `ContentId` grouping exist. Cross-path locations/classes and same-path provenance are retained deterministically; output remains a `Vec`, not a stream. |
| Supabase key classification | Partial | New/legacy classes, exact-revision project extraction, and conservative same-fingerprint project enrichment exist. Initial new-format project discovery remains same-unit only, and no user-supplied project/key pair exists. |
| Tier 0 RLS probe | Partial, Phase 3A verified | Feature/runtime gating, `apikey`, URL restriction, GET-only probing, no row retention, root 401/403 fallback, and table-only key rejection are mock-tested. Candidate tables remain global across projects pending 3B, and protected attempts lack durable action records pending 3C. |
| Correlation | Phase 2 linkage verified | Both declarative v1 rules honor primary/additional commit provenance, compare normalized projects, and produce deterministic unique location/related unions. Later Network coverage limitations still affect which RLS facts exist to correlate. |
| Dependency integrity | Partial | Offline npm/Python structural checks exist. Registry existence, newcomer heuristics, and OSV/advisory checks do not. Their proposed third-party egress conflicts with the current own-assets-only invariant and needs a spec decision first. |
| Reporting | Verified for current v1 | JSON, SARIF, TTY, and HTML exist with redacted evidence, locations, history context, exit gates, and deterministic snapshots. Current always-redacted HTML is the conservative interpretation of an ambiguous spec. |
| CLI/config | Partial | The CLI is thin and feature-gates the Tier 0 flag. Clap defaults currently overwrite TOML `working_tree`, `history`, `severity_gate`, and network choices; relative baseline resolution and CLI precedence need tests/fixes. |
| Security/nonfunctional | Partial | Pure-Rust/default transport boundary is enforced. No measured low-single-digit performance artifact, static cross-platform build matrix, npm wrapper, or Homebrew path exists. |
| Testing strategy | Strong but incomplete | Exact goldens, clean control, report snapshots, boundary checks, and a mocked Tier 0 exposed-chain test exist. There is no precision/recall metrics artifact or benchmark; three architecture cases remain ignored/deferred. |
| Explicit non-goals | Preserved | No live writes, active DAST, BOLA, dashboard, accounts, billing, or client-auth heuristic scanner was found. |

## Tier C status

Tier C is implemented and covered for its named acceptance paths:

- **C1:** segment-aware monorepo classification with server-first precedence;
- **C2:** conservative same-secret coalescing and one Tier 0 input per normalized
  project; and
- **C3:** `apikey` on every mocked request, LocalStatic table/RPC harvesting,
  best-effort OpenAPI supplementation, distinct degraded warnings, read-only
  table probing, and the enabled mocked exposed-public-key-chain golden.

Phases 1–2 now cover the identity/linkage cases that Tier C did not: identical
content at different paths, commit membership stored in additional provenance,
two historical contents at one path, and a project URL split from a client key.
The next correctness priority is Phase 3's warning semantics and project-scoped
table harvesting.

## Strict gaps and known risks

### P0 — headline false-negative risks

1. **Alternate paths during content dedup — resolved in Phase 1.**

   The collector now groups by full SHA-256 `ContentId` and retains a canonical,
   deterministic list of `UnitLocation`s. Identical server/browser content is
   scanned once while both paths, classes, and provenances reach candidates and
   findings.

2. **Committed predicates and additional provenance — resolved in Phase 2.**

   Both v1 rules now use one `location_has_commit` predicate covering the
   primary and every additional provenance.

3. **Historical project-context swaps — resolved in Phase 2.**

   Core now resolves enrichment content by the candidate's exact `ContentId`.

4. **Projectless/project-bearing copies — resolved conservatively in Phase 2.**

   Two-stage coalescing joins projectless evidence only when the base group has
   exactly one known normalized project. Multiple known projects remain
   separate and retain a separate projectless bucket rather than guessing.

### P1 — contract and configuration gaps

1. The literal no-horizontal-dependency rule is violated by these test-only
   edges:

   - `vibescan-git -> vibescan-secrets`;
   - `vibescan-supabase -> vibescan-secrets`.

   The current boundary check intentionally considers only normal dependencies,
   so it cannot detect this class of drift.

2. CLI defaults overwrite repository config even when the user did not supply
   an option. The affected fields include working-tree/history selection,
   severity gate, and the network config value in network builds.

3. Baseline/custom-rules paths need an explicit repository-root resolution
   contract. The detector can parse custom TOML, but the scan pipeline always
   constructs the embedded default detector.

4. New-format key/project association is limited to one unit, and table
   candidates are harvested once for the whole repo rather than associated with
   the relevant project/bundle. Multi-project monorepos can receive noisy or
   incorrect probe associations.

5. A successful protected/empty/404 Tier 0 attempt emits neither a finding nor
   a durable action record. This falls short of the invariant that every
   Network action is logged/auditable.

### P2 — assurance and product-depth gaps

- Exact goldens plus a clean control are good inputs, but there is no measured
  precision/recall report.
- No repeatable benchmark proves the low-single-digit local performance target
  or bounds memory growth from the materialized pipeline.
- History-only remediation is present in general terms but should be tested for
  the architecture's explicit rewrite/force-push guidance.
- The default ruleset is deliberately conservative; provider precision and
  corpus licensing/attribution should receive a durable audit artifact before
  broad expansion.
- README documents the basic test and boundary commands, not the complete
  closeout matrix. `verify-hardening-checks.sh` is a useful helper but omits
  fmt, clippy, network-feature tests, and diff checks; it must not be treated as
  the full gate.

## Architecture ambiguities requiring an explicit decision

Future agents must surface these conflicts instead of silently choosing new
behavior:

1. **Elevated key severity:** section 10.1 says a gitignored server-env elevated
   key is High, while the following mechanics say elevated keys are essentially
   always Critical. Current code uses Critical.
2. **Tier 0 wording:** Tier 0 demonstrates reads only, while one correlation
   sentence says “read/modify.” Current code correctly claims read exposure
   only.
3. **HTML disclosure:** hosted/shareable HTML must be redacted, but another
   sentence permits full matches in local HTML without defining a mode. Current
   HTML is always redacted.
4. **Finding identity:** the data-model text includes location in an ID, while
   coalescing requires one stable identity across several locations. Current
   coalesced secret IDs are path-independent.
5. **External egress:** own-assets-only networking conflicts with optional
   third-party registry/OSV lookups. Privacy, consent, caching, failure
   semantics, and crate ownership are unspecified.
6. **Tier 1 fixtures:** section 14 names RLS-off and permissive-policy fixtures,
   while section 15 defers Tier 1. Treat them as post-v1 verification gaps, not
   blockers for the current runnable build.

Conservative policy until the architecture is clarified: keep elevated keys
Critical, describe Tier 0 as read-only, redact all HTML, retain path-independent
coalesced identity, prohibit third-party egress, and keep Tier 1 cases deferred.

## Detailed next-step plan

### Phase 1 — repair scan identity and correlation linkage

Do this before adding detection breadth or new Network features.

1. Add failing regression tests for:

   - identical content at server and client paths preserving two locations and
     `ClientReachable` precedence;
   - a working-tree key whose commit membership exists only in
     `additional_provenance` satisfying both committed predicates;
   - two historical blobs at the same path, each using its own project URL;
   - the same fingerprint in a projectless client file and an unambiguous
     project-bearing server/config file coalescing into one linkable fact;
   - known-different projects never merging; and
   - two projects receiving only their own harvested table candidates.

2. Change collection/data linkage so content dedup retains each path and
   location class. Prefer an explicit occurrence/location list or a stable
   unit/blob identifier over overloading provenance.
3. Pass exact unit content into classification rather than looking it up by
   path.
4. Centralize “has committed provenance” over primary plus additional
   provenance and use it in both v1 rules.
5. Reconcile a missing project with one unambiguous known project for the same
   fingerprint, while refusing known-project conflicts.
6. Associate harvested API names with the relevant source/project before
   generating probe inputs.

Acceptance: targeted crate tests, both golden feature modes, full default and
network clippy/tests, boundary script, reviewed golden diffs, and no decrease in
clean-control precision.

### Phase 2 — enforce the complete crate DAG

1. Move cross-crate classifier/walker integration coverage to
   `vibescan-core` or another existing top-level integration harness.
2. Remove sibling dev-dependencies from `vibescan-git` and
   `vibescan-supabase`.
3. Extend the dependency guard to inspect normal/build/dev/target/optional
   workspace edges and reject all horizontal sibling edges, while still
   separately proving the feature-gated transport rule.
4. Add negative controls showing the guard fails for a sibling dev-dependency
   and for transport leakage.

Acceptance: the exact architecture DAG holds in every dependency kind and both
feature graphs.

### Phase 3 — make configuration truthful end to end

1. Represent CLI overrides as optional/explicit values so absent flags preserve
   TOML settings.
2. Test precedence: defaults < repository config < explicit CLI arguments.
3. Resolve baseline and custom-rules paths relative to the discovered repo
   root; preserve absolute paths.
4. Define and implement custom ruleset merge/replace behavior without removing
   mandatory Supabase rules or safety allowlists.
5. Add CLI integration tests for both feature modes and correct exit codes.
6. Update README examples only after the behavior is proven.

### Phase 4 — complete Tier 0 observability without broadening authority

1. Add structured, redacted per-action outcomes for exposed, protected/empty,
   not-found, key-rejected, root-unavailable, and transport-error attempts.
2. Record method-equivalent intent, normalized endpoint, table, and outcome;
   never record keys, headers, or rows.
3. Keep Network failure nonfatal to LocalStatic findings and keep all tests on
   the injected mock client.
4. Do not add writes, arbitrary URLs, live CI, registry egress, or Tier 1 as
   part of this phase.

### Phase 5 — add measured assurance

1. Build a deterministic precision/recall harness over the golden corpus and
   publish a machine-readable report with corpus version and expected totals.
2. Add a representative local performance fixture and measure wall time,
   scanned blobs, dedup ratio, peak/materialized unit counts, and truncation.
3. Add a canonical full-verification script or prominently document the exact
   root `AGENTS.md` matrix; keep the optional real-repo smoke leg separate.
4. Extend CI only with deterministic offline checks.

### Deferred tracks — require a separate architecture decision

- Registry existence/newcomer/OSV checks: first resolve third-party egress,
  consent, privacy, caching, and owning-crate policy.
- Tier 1 introspection/policy analysis: post-v1 and credentialed; no writes.
- Cross-platform static binaries, npm wrapper, Homebrew, signing, and release
  provenance: separate distribution track.
- Active DAST/write probes: prohibited in v1, not merely postponed.

## Closeout gate for future milestone claims

Run, record, and reconcile at least:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

Use `UPDATE_GOLDEN=1` only after an intentional result change, inspect every
artifact diff, then rerun without it. Do not claim completion from this file's
historical results; rerun the commands on the current checkout.
