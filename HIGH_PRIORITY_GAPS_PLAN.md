# High-Priority Gap Remediation Plan

Reviewed: 2026-07-12

Planning checkout: `1d6abbb` with a clean worktree before this file was added.

Authority: `vibescan-architecture.md`. This plan explains how to close the
highest-priority gaps recorded in `STATE.md`; it does not supersede the
architecture or authorize deferred work.

Evidence source: the user-supplied 2026-07-12 command transcript containing
workspace build/test output, hardening checks, LocalStatic scans of a real
repository, and an explicitly initiated Tier 0 read probe.

## Purpose and scope

The new results validate the ordinary end-to-end path, but they do not exercise
the four identity/linkage cases most likely to cause false negatives in the
headline Supabase correlation. This plan therefore keeps those four repairs
first, folds in three concrete defects newly revealed by the transcript, and
then addresses the related dependency-DAG and configuration gaps.

The intended order is:

```text
synthetic regression lock
  -> content/source identity
  -> project and provenance joins
  -> Tier 0 outcome accuracy and project scoping
  -> complete DAG enforcement
  -> CLI/config/baseline correctness
  -> full deterministic closeout
```

This is a planning artifact. Implementation should be delivered as small,
reviewable slices with the relevant tests passing after each slice.

## Immediate operational action outside this code plan

The supplied scan output reports live elevated/provider credentials and a
confirmed anonymous read exposure. The affected credentials should be rotated
and removed, and the affected RLS policy should be corrected independently of
vibescan development.

Do not copy the real values, project identifiers, fingerprints, endpoints, or
response data into this repository. No additional live probe is required to
implement or accept the changes below. Any future live rerun requires explicit
user authorization for that target.

## What the new results prove

- `cargo build --workspace` completed successfully.
- The default workspace test run passed with 79 tests passed and 4 ignored.
- The network-boundary and hardening scripts passed.
- The optional sanitized real-repository hardening leg passed, including its
  planted gitignored-env control.
- LocalStatic scanning completed in roughly 1 to 1.4 seconds for the supplied
  repository, with 25 history commits covered and no history truncation.
- TTY, JSON, and SARIF reports retained redacted evidence and consistent stable
  finding IDs.
- Ordinary same-secret coalescing worked when the same key appeared in two
  different files whose whole-file contents were different.
- The monorepo classifier correctly retained a server-only location and a
  client-reachable bundle location for one publishable key.
- The explicitly initiated Tier 0 run continued after root enumeration failed,
  used a harvested API reference, and produced the intended read-only Critical
  composite without displaying returned row contents.

The observed local runtime is encouraging but is one sample, not the repeatable
performance artifact required by architecture section 13.2.

## What the new results do not prove

- They do not cover identical whole-file content at two different paths. The
  successful two-path coalescing case therefore does not test blob-level path
  loss in `UnitCollector`.
- Every displayed location had primary working-tree provenance and an empty
  `additional_provenance`; the independent committed branch remains untested.
- They do not cover two different historical contents at the same path, so the
  path-keyed enrichment lookup remains untested.
- The public key already had project context. A projectless client copy plus a
  project-bearing server/config copy remains untested.
- Only one Supabase project was involved, so cross-project table-candidate
  isolation remains untested.
- Direct CLI flags worked, but no test showed that absent CLI flags preserve
  `vibescan.toml` values.
- The boundary script proved production transport isolation only; it did not
  validate the literal workspace DAG across dev/build/target/optional edges.
- The transcript did not contain the complete closeout matrix: there was no
  default/network clippy pair, no network-feature workspace test run, no
  locked-mode evidence, no `git diff --check`, and no commit/worktree evidence
  tying the test run to an exact revision.
- Output from a live run does not by itself prove HTTP method/header behavior
  or in-memory row disposal. Those remain code and mock-test assertions.

## Highest-priority findings and reasons to implement

### P0.1 — content deduplication loses alternate paths and location classes

Current root cause: `vibescan-git::UnitCollector` keys on content hash. When a
duplicate blob is found, it appends only the duplicate provenance to the first
unit and discards the duplicate path and `LocationClass`.

Why this must be fixed first:

- Reproducible evidence requires every real source location.
- A browser location can disappear when identical content was first seen at a
  server path.
- Losing `ClientReachable` can suppress the product's headline correlation.
- Later project/table association cannot be made reliable until source
  occurrences survive collection.

### P0.2 — committed correlation ignores `additional_provenance`

Current root cause: both v1 correlation rules inspect only
`Location.provenance`. Collection visits the working tree first, so an
identical committed blob is commonly stored only in `additional_provenance`.

Why this must be fixed:

- Architecture section 12 defines committed presence as an independent trigger.
- Collection order must not change security behavior.
- The current implementation can miss both the public-key chain and the
  elevated-key-remediation ordering rule.

### P0.3 — historical candidates can receive the wrong project context

Current root cause: core constructs a `path -> content` map for Supabase
enrichment. If multiple historical contents share a path, one overwrites the
other in that map.

Why this must be fixed:

- Project association must come from the exact blob that produced the key.
- A wrong association can create either a false negative or a cross-project
  false correlation.
- Project-scoped Tier 0 harvesting depends on exact blob identity.

### P0.4 — projectless and project-bearing copies of one key remain split

Current root cause: the coalescing key includes `Option<project_url>`. The same
fingerprint with `None` and `Some(project)` therefore lands in different
findings even when there is exactly one unambiguous project.

Why this must be fixed:

- A common repository layout stores the public key and project URL in different
  configuration or bundle locations.
- The project-bearing server copy may initiate a probe while the projectless
  browser copy cannot satisfy same-project correlation.
- The fix must remain conservative so known-different projects never merge.

### Newly observed — duplicate correlation location

The live composite printed the same client path/span twice. The RLS finding
uses the selected key location and core concatenates it with every key location
without canonicalization.

Why implement now: duplicate evidence is noisy, destabilizes snapshots, and
violates the requirement that findings be reproducible and actionable. This is
a small fix that naturally belongs in the P0 location-union work.

### Newly observed — root 401 is mislabeled as global key rejection

The OpenAPI root returned 401, but a harvested table read using the same probe
input succeeded. The key was therefore not globally rejected.

Why implement now: architecture section 7.1 treats root 401/403 as root
enumeration unavailable. A contradictory warning undermines confidence in a
confirmed finding and obscures the distinction between root behavior and a
table request that actually rejects a key.

### Newly observed — a missing baseline is silently ignored

An explicit `--baseline` path that existed in neither the scanner repository nor
the target repository was accepted as an empty baseline, and all findings were
reported without a warning or error.

Why implement: CI users can believe a named baseline was loaded when it was
not. Missing explicit/configured inputs should be operational errors, and path
resolution must be deterministic.

### P1 — table candidates are global rather than project-scoped

Core harvests one repository-wide `BTreeSet` and clones it into every project
probe input.

Why implement after exact blob identity: a multi-project monorepo can probe a
table referenced only by project A against project B. The requests remain
read-only, but the association and evidence are inaccurate.

### P1 — successful protected outcomes are not auditable

Protected, empty, and not-found table attempts produce neither findings nor
durable scope records.

Why implement: architecture section 1 requires every Network action to be
logged. Protected outcomes should remain non-findings, but they are still part
of the scan's reproducible coverage evidence.

### P1 — the literal crate DAG is not enforced

Known mismatches include sibling dev-dependencies from `vibescan-git` and
`vibescan-supabase` to `vibescan-secrets`, plus a direct CLI dependency on
`vibescan-types` that is absent from the authoritative graph.

Why implement: the crate graph is an architectural safety control. The current
boundary script validates transport reachability through normal dependencies,
not the complete workspace edge set.

### P1 — CLI defaults overwrite repository configuration

The CLI unconditionally writes default history, working-tree, severity, and
network values over the configuration loaded by core.

Why implement: the documented precedence contract is defaults, repository
configuration, then explicitly supplied CLI values. A default clap value is not
an explicit user override.

## Implementation plan

### Phase 0 — add synthetic regression tests before behavior changes

Place cross-crate regressions in `vibescan-core` integration tests rather than
adding sibling test dependencies.

Add cases for:

1. Identical content at a server path and browser path retains two locations
   and `ClientReachable` precedence.
2. A working-tree primary location with an additional commit satisfies the
   public-key committed predicate.
3. The same provenance arrangement satisfies the elevated-key rule.
4. A server-only key with no committed provenance still does not fire the
   browser/committed branch.
5. Two historical blobs at the same path each use their own project URL.
6. One projectless copy joins one known project for the same fingerprint.
7. Two known-different projects remain separate, and an ambiguous unknown copy
   is not assigned to either.
8. Correlation unions a server location, client location, and repeated RLS key
   location into exactly two unique locations in deterministic order.
9. Root 401 plus table 200/nonempty yields a root-unavailable warning and an
   exposed finding, with no key-rejected warning.
10. Root 401 plus table 401 yields distinct root-unavailable and table-key-
    rejected outcomes.
11. Root 403 continues to fall back to harvested candidates.
12. Two app/package scopes with two projects issue only project-local table
    requests.
13. Ambiguous table association performs no cross-project probe and emits a
    coverage warning.
14. A missing explicit or configured baseline returns an operational/config
    error.
15. Absent CLI values preserve TOML; explicit CLI values override it.

All credentials, URLs, repository contents, and HTTP responses in these tests
must be synthetic. Unexpected mock requests should fail the test.

Exit criterion: each new regression fails for the intended root cause before
its corresponding implementation slice lands.

#### Phase 0 status — regression lock installed (2026-07-12)

Phase 0 adds 16 synthetic tests without changing production behavior:

- 10 core tests lock content-occurrence identity, exact historical project
  context, conservative project joining, provenance-aware correlation,
  location deduplication, and project-scoped Tier 0 inputs.
- 2 Supabase mock-client tests distinguish root enumeration failure from a
  table-level key rejection. The fake client rejects every unexpected request
  and every observed request is checked for the synthetic `apikey` header.
- 4 real-binary CLI tests lock TOML/CLI precedence and missing-baseline error
  handling for both explicit and configured paths.

The focused baseline is intentionally red: 13 tests fail at the planned
behavior boundaries, while three negative/override controls pass. The existing
mocked root-403 fallback test also remains the control for item 11. All tests
compile in the default workspace, and the project-scope regressions compile and
run only with the existing `network` feature; no test performs live I/O.

The no-cross-project half of item 13 is now locked. Its separate coverage-
warning assertion must be added when Phase 4 introduces a project-association
result seam capable of returning both scoped tables and scope warnings; the
current `tier0_probe_inputs` function returns inputs only, so a warning test
cannot truthfully observe production output yet.

### Phase 1 — introduce exact content and source-occurrence identity

Preferred shared vocabulary in `vibescan-types`:

```text
ContentId
UnitLocation {
  path
  location_class
  provenance
  additional_provenance[]
}
ScannableUnit {
  content_id
  content
  locations[]
}
UnitRef {
  content_id
  locations[]
}
```

Implementation details:

1. Define `ContentId` as an opaque full-content SHA-256 identifier. Keep hashing
   outside `vibescan-types`; the types crate remains pure data.
2. Replace the singular internal unit path/provenance fields with one canonical
   list of source locations. Avoid retaining both singular fields and a new
   list as competing sources of truth.
3. In `vibescan-git`, group by `ContentId`, then merge occurrences at the same
   path by provenance. A different path always remains a different
   `UnitLocation`, even when content is identical.
4. Sort/deduplicate locations and provenances deterministically before units
   leave the collector.
5. In `vibescan-secrets`, scan the content once. Apply path and commit
   allowlists per `UnitLocation`, retaining only eligible locations on the
   candidate instead of suppressing unrelated occurrences.
6. Build every `Finding.locations` entry from the candidate's retained source
   locations, reusing the identical content-relative span.
7. Do not add `ContentId` to public finding IDs. It is an internal phase-linkage
   key, not user-facing identity.

Reasons for this design:

- It preserves the performance benefit of scanning identical content once.
- It represents all paths without misusing provenance as a path surrogate.
- It gives core a stable exact-blob lookup key.
- It avoids an `additional_locations` compatibility layer with two conflicting
  representations.
- It does not add a crate or weaken the LocalStatic boundary.

Exit criteria:

- Alternate paths/classes/provenances survive collection and detection.
- Same-path repeated commits still collapse to one source location with
  complete first/last provenance.
- Two historical contents at one path remain distinct content units.
- Existing finding IDs remain unchanged unless project evidence legitimately
  becomes more specific.

#### Phase 1 status — implemented (2026-07-12)

- `vibescan-types` now exposes opaque full-SHA-256 `ContentId` plus the single
  canonical `UnitLocation` list used by `ScannableUnit` and `UnitRef`; the old
  singular path/provenance/class fields were removed.
- `vibescan-git` groups by `ContentId`, keeps different paths distinct, merges
  same-path provenances, and normalizes both locations and provenances before
  returning units.
- `vibescan-secrets` scans each content body once and evaluates path/commit
  allowlists per occurrence, retaining unaffected locations on the candidate.
- Generic and Supabase finding builders copy every retained location with the
  same content-relative span. A regression proves `ContentId` is not part of a
  public Supabase finding ID.

The Phase 0 identical-content server/browser regression is green. The
historical same-path project-context regression deliberately remains red:
Phase 1 carries the exact `ContentId`, while Phase 2 is responsible for using
it instead of the legacy path-keyed enrichment map.

### Phase 2 — repair exact enrichment, coalescing, and correlation

1. Replace the current path-keyed unit-content map with
   `ContentId -> exact content`.
2. Pass only that exact content to Supabase project extraction.
3. Add a core helper equivalent to `location_has_commit` that checks both the
   primary and additional provenances; use it in both v1 rules.
4. Introduce an internal classified-key fact that retains:

   - the resolved `Finding`;
   - the transient raw public key needed for a request; and
   - exact unit/source context.

   Never put the raw key into `Finding`, `ScanResult`, logs, or snapshots.
5. Coalesce classified-key facts before building Tier 0 inputs.
6. Use a two-stage coalescer:

   - base group: category + rule/class + fingerprint + severity;
   - within the base group, partition by normalized known project.

7. If the base group has exactly one known project, merge projectless copies
   into it and retain all sorted locations.
8. If more than one known project exists, keep each project separate and keep
   projectless evidence separate rather than guessing.
9. Continue refusing merges across different fingerprints/classes/severities.
10. Build composite locations through the canonical sort/dedup helper. Preserve
    distinct paths, spans, provenances, and classes while removing exact
    duplicates.
11. Keep `related` IDs and correlation ID derivation deterministic.

Baseline consideration: a finding may receive a different stable ID when new
unambiguous project evidence changes it from projectless to project-bearing.
Review this intentionally in golden/baseline tests; do not conceal it as an
unexplained snapshot refresh.

Exit criteria: all four P0 regressions and the unique-location regression pass,
while known-different projects remain negative controls.

#### Phase 2 status — implemented (2026-07-12)

- Core enrichment now resolves source bytes exclusively by `ContentId`, so
  historical revisions at one path cannot exchange project context.
- An internal classified-key fact retains the resolved finding, transient raw
  key, and exact `UnitRef` context. Facts are coalesced before Tier 0 input
  selection; raw keys never enter findings, results, logs, or snapshots.
- Finding and classified-fact coalescing use the same two-stage policy:
  fingerprint/class/severity base groups are partitioned by normalized known
  project, projectless copies join only a single unambiguous project, and an
  ambiguous projectless copy remains separate.
- Both correlation rules use `location_has_commit`, including additional
  provenance. Composite locations use the canonical deterministic
  sort/deduplication helper, and related/correlation identities remain stable
  across input order.
- A baseline regression records the intentional identity transition when
  reliable project evidence enriches a formerly projectless finding. Existing
  golden manifests and report snapshots require no refresh.

All Phase 2 and known-different-project controls pass in default and network
core tests. The remaining deliberate red cases belong to Phase 3 warning/table
scope work and Phase 4 CLI/baseline behavior.

### Phase 3 — correct Tier 0 outcomes and project-scope candidate harvesting

#### 3A. Correct warning semantics

1. Replace root-specific 401/403 variants with a precise
   `RootEnumerationUnavailable { url, status }` outcome.
2. Reserve `KeyRejected` for a table/RPC request that returns 401.
3. Continue probing LocalStatic candidates after root 401 or 403.
4. Preserve both outcomes when the root is unavailable and a table request
   separately rejects the key.
5. Keep LocalStatic findings even when all Network requests degrade.

#### Phase 3A status — implemented (2026-07-12)

- Root HTTP 401 and 403 now emit
  `RootEnumerationUnavailable { url, status }` and continue with harvested
  LocalStatic candidates.
- `KeyRejected` is emitted only for a table request returning HTTP 401.
- Mocked cases prove root-401/table-200 produces an exposed finding plus only
  the root warning, while root-401/table-401 preserves both distinct outcomes.
- The root-403 fallback, no-candidate warning, exact `apikey` assertions, and
  read-only request behavior remain green. No live Network action is used.

The two Phase 3A regressions are green. Remaining deliberate reds are the two
Phase 3B project-table-scope cases and the three Phase 4 CLI/baseline cases.

#### 3B. Harvest typed, project-scoped API references

Replace the global string set with typed internal references:

```text
ApiReference {
  kind: Table | Rpc
  content_id
  source_scope
  name
}
```

Association rules:

1. An exact unit that identifies one project assigns its references directly.
2. References in separate units may join through a deterministic app/package
   scope only when that scope resolves to exactly one project.
3. A missing or ambiguous association must not fall back to the repository-wide
   union. Skip that probe and emit a coverage warning.
4. Build a stable normalized project URL -> table set map and give each probe
   only its own candidates.
5. Retain `.rpc()` references as `Rpc`; do not issue table reads such as
   `/rest/v1/<rpc>?select=...`. RPC probing remains optional/stretch work.
6. Normalize URL host case and trailing slashes before grouping.

Exit criteria:

- Two-project fixtures make no cross-project requests.
- Ambiguous references are reported as coverage limitations, not guessed.
- Historical versions never exchange project or API-reference context.
- The existing one-project harvested-table chain still passes.

#### Phase 3B status — implemented (2026-07-12)

- LocalStatic harvesting now emits typed `Table`/`Rpc` references carrying
  exact `ContentId`, deterministic app/package scope, and normalized name.
- Each classified source retains the project evidence established before fact
  coalescing. Table association prefers an exact content project and otherwise
  uses a scope only when that scope resolves to one project.
- Missing or ambiguous associations produce deterministic coverage warnings
  and no table candidate. Tier 0 receives a normalized per-project table map;
  the repository-wide union has been removed.
- RPC references remain typed but are excluded from table-read endpoints.
- Regressions cover two-project isolation, ambiguous and missing associations,
  exact historical revision context, RPC exclusion, and the existing
  one-project chain.

All Phase 3B default and network core tests pass. The only deliberate red tests
remaining are the three Phase 4 CLI/baseline cases.

#### 3C. Add redacted per-action audit records

Add shared pure-data vocabulary for Network actions and aggregate it into the
scan scope. Record one entry for every attempted root/table request:

- action kind and GET intent;
- normalized endpoint and optional table;
- HTTP status when present;
- outcome: root enumerated/unavailable, exposed, no rows observed, protected,
  not found, key rejected, invalid response, or transport error;
- observed row count only for an exposure.

Never record the public key, headers, response body, returned rows, or raw
transport material. Protected outcomes remain scope evidence, not findings;
they must not change finding statistics or the severity gate.

Update deterministic JSON/SARIF/TTY/HTML coverage and snapshots for the new
scope evidence.

Implemented on 2026-07-12:

- `vibescan-types` now owns the serializable `NetworkActionAudit` vocabulary.
  Older serialized scopes deserialize with an empty action list.
- Every attempted Tier 0 root or table GET emits exactly one record with its
  kind, GET intent, normalized endpoint, optional table, available status, and
  classified outcome. Only exposed reads carry an observed row count.
- Root enumeration/unavailability, exposed, empty, protected, not-found,
  key-rejected, invalid-response, and transport-error paths are covered by
  injected-client tests. Serialized-record negative controls reject public
  keys, `apikey` header material, response bodies, and returned row values.
- `vibescan-core` aggregates the records under `ScanScope.network.actions`.
  Scope-only protected evidence remains outside findings, statistics, and the
  severity exit gate.
- JSON and SARIF serialize the structured records; TTY and HTML render safe
  summaries. Fixed synthetic snapshots cover root, protected, and exposed
  outcomes in all four formats.

All Phase 3C-focused tests and both feature-mode workspace matrices pass when
the three pre-existing Phase 5 CLI/baseline regressions are excluded. The
unfiltered matrices fail only those same three known tests. No live Network
action was used.

### Phase 4 — enforce the complete workspace DAG

1. Move the git-to-detector integration test out of `vibescan-git` and into an
   existing `vibescan-core` integration harness.
2. Move the detector-to-Supabase classification integration test into core.
3. Remove the sibling dev-dependencies from `vibescan-git` and
   `vibescan-supabase`.
4. Remove the CLI's direct dependency on `vibescan-types`; expose/import the
   severity-gate vocabulary through `vibescan-core` so CLI depends only on core.
5. Extend `scripts/check-network-boundary.sh` to validate the exact allowed
   workspace edge set for normal, dev, build, target, optional, and
   feature-activated dependencies.
6. Preserve the existing transport checks as a separate assertion:

   - no default transport dependency;
   - enabled transport nearest-parented only by `vibescan-supabase`;
   - pure LocalStatic libraries transport-free in both graphs.

7. Add negative controls proving the checker rejects a sibling dev-dependency,
   an unauthorized direct workspace edge, and transport leakage.

Exit criterion: the authoritative seven-crate DAG holds across every dependency
kind and both feature graphs.

Implemented on 2026-07-12:

- The git-to-detector and detector-to-Supabase integration assertions now live
  in `vibescan-core`; lower crates retain only their owned behavioral tests.
- The `vibescan-git -> vibescan-secrets` and
  `vibescan-supabase -> vibescan-secrets` dev-dependencies were removed.
- `vibescan-cli` no longer depends on `vibescan-types`; core publicly exposes
  `Severity` for the thin CLI boundary.
- The checker validates exactly seven workspace members and the complete
  authoritative edge set from Cargo's declared dependencies, covering normal,
  build, dev, target, and optional edges independent of feature activation.
- Default and `network` resolved graphs retain separate transport assertions.
  In-process synthetic controls prove acceptance of the intended graph and
  rejection of a sibling dev-edge, an unauthorized direct/optional edge, and
  LocalStatic transport leakage.

All Phase 4-focused tests, clippy gates, goldens, snapshots, and both workspace
matrices pass when the three pre-existing Phase 5 CLI/baseline regressions are
excluded. Unfiltered matrices fail only those same tests.

### Phase 5 — make CLI, configuration, and baseline behavior truthful

1. Represent CLI overrides as optional/tri-state values. A clap default must
   not be applied as an explicit override.
2. For LocalStatic fields, implement and test:

   ```text
   built-in defaults < repository vibescan.toml < explicit CLI arguments
   ```

3. Add paired enable/disable CLI forms when a configured boolean must be
   explicitly overridable in either direction.
4. Preserve the safety rule that Network execution requires explicit runtime
   confirmation. Repository configuration alone must not silently cause a
   request. If config-alone Network opt-in is desired, resolve that as an
   architecture decision before implementation.
5. Resolve configured baseline/custom-rules paths relative to the discovered
   target repository root; preserve absolute paths.
6. Resolve the CLI baseline path under one documented rule and test it. The
   recommended rule for consistency is target-repository-relative unless the
   path is absolute.
7. Treat an explicitly supplied or configured missing baseline as a
   configuration/operational error and return process exit code 2.
8. Preserve `None` only for the case where the user supplied no baseline.
9. Add CLI integration tests using the built binary and standard library rather
   than introducing a broad testing dependency.
10. Wire custom detector rules only after merge-versus-replace semantics are
    explicit and tested; never remove mandatory Supabase rules or safety
    allowlists silently.

Exit criteria:

- Absent CLI flags preserve repository config.
- Explicit flags override it predictably.
- Config alone never triggers an unexpected Network request.
- Missing named baselines fail visibly.
- Baseline suppression is tested with a real synthetic baseline file.

## Suggested merge sequence

1. `test: lock identity, warning, location, and baseline regressions`
2. `refactor(types,git,secrets): preserve content source occurrences`
3. `fix(core,supabase): exact enrichment and conservative project joining`
4. `fix(core): committed predicates and canonical correlation locations`
5. `fix(core,supabase): project-scoped Tier 0 inputs and root warning taxonomy`
6. `feat(types,supabase,report): redacted Network action audit records`
7. `refactor(test,manifests): enforce the exact crate DAG`
8. `fix(cli,core): config precedence and strict baseline resolution`
9. `docs: reconcile README and STATE with measured final results`

Each merge should keep default tests offline and should pass its focused package
tests before the next dependent slice begins.

## Verification and acceptance gates

Use mocks and synthetic repositories only. A live target is not part of
acceptance.

Focused gates while iterating:

```sh
cargo test -p vibescan-types --locked
cargo test -p vibescan-git --locked
cargo test -p vibescan-secrets --locked
cargo test -p vibescan-supabase --locked
cargo test -p vibescan-supabase --features network --locked
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked
```

Full closeout gate:

```sh
cargo build --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test golden_corpus --features network --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
git status --short
```

`UPDATE_GOLDEN=1` is allowed only after an intentional output/identity change.
Inspect every changed ID, location, warning, scope action, and snapshot, then
rerun without the variable. Do not use a golden refresh to conceal a regression.

## Definition of done

The highest-priority remediation is complete only when:

- all four P0 false-negative regressions pass;
- correlation locations are unique and deterministic;
- root 401/403 messages describe root enumeration rather than falsely
  declaring a globally rejected key;
- table candidates are project-scoped with explicit ambiguity warnings;
- every Network request has a redacted action outcome and no row/key leakage;
- the literal workspace DAG holds across all dependency kinds;
- absent CLI values preserve TOML, missing baselines fail, and explicit
  overrides behave predictably;
- default and `network` feature matrices, clippy, formatting, goldens,
  snapshots, and boundary assertions pass on the same clean commit; and
- `STATE.md` and README record the exact measured results and remaining
  deferred work without claiming that a live run substitutes for mock/CI gates.

## Stop conditions and non-goals

Stop and request direction before:

- changing `vibescan-architecture.md`;
- adding an eighth crate;
- enabling third-party registry/advisory egress;
- running another live probe or handling real credentials;
- adding Tier 1 introspection, active DAST, write probes, or any mutating
  request; or
- changing the conservative rules for ambiguous project association.

This plan does not include generic rule breadth, distribution/npm packaging,
Tier 1 policy analysis, or active probing. Those tracks do not take precedence
over the false-negative and evidence-correctness work above.
