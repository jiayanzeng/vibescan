# vibescan — Codex Instructions: Track F (registry egress & `vibescan-registry`)

Reviewed: 2026-07-18
Author: architecture review (Claude), for implementation by Codex

## How to consume this document

This is the second post-v1 track (see `vibescan-postv1-roadmap.md`). It implements
the **Registry** egress class — architecture **§11.1 (contract)** and **§11.2
(mechanism, resolved 2026-07-18)** — and un-gates the **last** remaining corpus
fixture (`hallucinated-dependency`). It is decision-gated work: **§11.2 already
made the mechanism decisions** (which registries, how OSV is consumed, caching,
confidence tiering); this document turns that decision into a build. Do not
re-open the mechanism — if implementation surfaces a genuine conflict with §11.2,
flag it, don't diverge.

Three dependency-ordered tasks in the house format: spec basis with section
citations, root-caused problem with file evidence, file targets, implementation
guidance, self-verifiable acceptance criteria with negative controls. Authority is
`vibescan-architecture.md`, **not** `STATE.md`.

Build order (respect it — F1's crate + DAG is the substrate F2/F3 build on):

1. **F1 — `vibescan-registry` crate, DAG, transport, opt-in, parsed-dep plumbing** (P1; §11.1 clause 6, §13.1, §13.3)
2. **F2 — Known-malicious (OSV) + nonexistent-package detections** (P1; §11.2 Tiers 1–2, §11.1 clauses 1–5)
3. **F3 — Un-gate `hallucinated-dependency`; extend precision/recall; closeout** (P1; §14, §17.6)

**The suspicious-newcomer heuristic (§11.2 Tier 3) is deliberately out of Track F's
first pass** — it is `Review` confidence, off by default, npm-only, and §16 defers
noisy heuristics. It is named as a follow-up in F3, not built here.

Assume a committed `Cargo.lock`; CI jobs run `--locked`. Track F is additive except
where `hallucinated-dependency/expected.json` is populated and the D2 baseline is
regenerated under `UPDATE_*` guards (F3). Do not weaken or delete an existing test.

---

## Task F1 — The `vibescan-registry` crate, DAG, transport, opt-in, and plumbing

### Spec basis

- **§11.1 clause 6 (ownership):** the Registry checks live in their **own crate**,
  `vibescan-registry`, which is the **nearest parent of its HTTP transport** —
  exactly as `vibescan-supabase` is for the RLS probe. `vibescan-core` gains an
  **optional, feature-gated** edge to it; the §13.3 boundary assertion and the
  workspace-DAG checker are updated **in the same change**; `LocalStatic` crates
  stay transport-free.
- **§11.1 clause 1 (consent):** a `--registry-checks` opt-in **separate** from the
  Supabase network opt-in (enabling one must not enable the other); **repository
  config alone cannot enable it.**
- **§11.2 transport / §13.1:** sync, rustls-backed HTTP client (the Tier 0 choice —
  no OpenSSL, no C toolchain), independently feature-gated so a default build pulls
  no transport.
- **§11.1 clause 3 (privacy disclosure):** scan scope records that package names
  left the machine and to which hosts.

### Problem (root-caused)

Everything the Registry class needs to *hang off of* exists; the crate and its
seams do not:

- The workspace is exactly seven crates (root `Cargo.toml` members; the DAG checker
  `scripts/check-network-boundary.py` hard-codes `EXPECTED_WORKSPACE` = those seven
  and `ALLOWED_WORKSPACE_EDGES`). There is no `vibescan-registry`.
- The DAG checker permits transport under **one** parent: line ~213 asserts each
  transport crate's nearest workspace parents equal `{ALLOWED_NETWORK_PARENT}` where
  `ALLOWED_NETWORK_PARENT = "vibescan-supabase"` (a **single string**). A second
  transport-owning crate makes the nearest-parent set `{"vibescan-supabase",
  "vibescan-registry"}` and **fails this assertion**. This is the load-bearing edit
  — get it exactly right (see guidance), the same way C1's classifier and E3's
  correlation predicate were the load-bearing edits of their tiers.
- §11.0 dependency parsing lives in `vibescan-core`
  (`DependencyManifest`/`DependencyManifestKind`, `dependency_manifest_kind`, the
  per-manifest checks) and produces `Finding`s directly; it does not expose a
  parsed-dependency list a second consumer could reuse.
- `NetworkScope` (types) carries `enabled`, `tier0_read_probe`,
  `tier1_introspection`, `actions` — no registry opt-in flags and no name-egress
  disclosure. `NetworkActionKind` is `{ RootEnumeration, TableRead,
  CatalogIntrospection }` — no registry request kinds.

### File targets

- **New crate:** `crates/vibescan-registry/` (`Cargo.toml`, `src/lib.rs`,
  `AGENTS.md`). **Edit:** root `Cargo.toml` — add the workspace member and a
  `workspace.dependencies` entry.
- **Edit:** `scripts/check-network-boundary.py` — `EXPECTED_WORKSPACE`,
  `ALLOWED_WORKSPACE_EDGES`, generalize `ALLOWED_NETWORK_PARENT` → a set, add the
  registry feature graph.
- **Edit:** `crates/vibescan-core/{Cargo.toml,src/lib.rs}` — a `registry` cargo
  feature enabling the optional `vibescan-registry` edge; refactor §11.0 parsing to
  expose a `ParsedDependency` list; call the registry checks when `registry` +
  `--registry-checks` are on.
- **Edit:** `crates/vibescan-cli/{Cargo.toml,src/main.rs}` — the `registry` feature
  passthrough and the `--registry-checks` flag.
- **Edit:** `crates/vibescan-types/src/lib.rs` — extend `NetworkScope` (registry
  opt-in flags + name-egress disclosure) and `NetworkActionKind`
  (`RegistryExistence`, `RegistryAdvisory`) — additive, `#[serde(default)]`.
- **Edit:** `.github/workflows/ci.yml` — `clippy-registry` + `test-registry` jobs.

### Implementation guidance

**Crate shape mirrors `vibescan-supabase`** (injectable client trait + real impl
behind a feature + a function returning findings/warnings/audit), so review is
mechanical and tests are hermetic:

```
// vibescan-registry, default-feature = []
// feature "network" = ["dep:reqwest"]  (sync, rustls-tls, no OpenSSL — as Tier 0)
pub struct RegistryCheckInput { pub dependencies: Vec<ParsedDependency> }
pub struct RegistryCheckOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<RegistryWarning>,
    pub actions: Vec<NetworkActionAudit>,   // name-egress disclosure lives here
}
pub trait RegistrySource {                   // the mock seam
    fn resolves(&self, dep: &ParsedDependency) -> Result<bool, RegistryError>;      // existence
    fn advisories_for(&self, eco: Ecosystem) -> Result<AdvisorySet, RegistryError>; // OSV snapshot
}
pub fn run_registry_checks(
    source: &impl RegistrySource,
    input: &RegistryCheckInput,
) -> Result<RegistryCheckOutput, RegistryError> { /* F2 fills detections */ }
```

`vibescan-registry` depends only on `vibescan-types` (for `Finding`/`Evidence`)
plus its optional transport. It never touches the filesystem beyond its cache dir,
never scans, never classifies keys — same narrowness the other domain crates keep.

**The DAG-checker generalization (do this precisely).**
1. `EXPECTED_WORKSPACE`: add `"vibescan-registry"` (→ 8 crates).
2. `ALLOWED_WORKSPACE_EDGES`: add `("vibescan-core", "vibescan-registry")` and
   `("vibescan-registry", "vibescan-types")`. Add **nothing** else — no
   `vibescan-registry` edge to any `LocalStatic` crate.
3. Replace the single `ALLOWED_NETWORK_PARENT` with
   `ALLOWED_NETWORK_PARENTS = {"vibescan-supabase", "vibescan-registry"}`, and
   change the assertion (~L213) from `parents != {ALLOWED_NETWORK_PARENT}` to
   **`not parents or not parents.issubset(ALLOWED_NETWORK_PARENTS)`** — every
   transport crate's nearest workspace parent(s) must be non-empty and drawn only
   from the allowed set. Do **not** loosen it to "any parent"; a transport reachable
   from a `LocalStatic` crate must still fail.
4. `vibescan-registry` is **NOT** added to `PURE_LOCALSTATIC` (it owns transport).
5. Load and validate the **registry** feature graph too: the checker currently
   diffs the default and `--features network` metadata graphs; add the
   `--features registry` graph (and, if features compose, `network,registry`), and
   run both the workspace-edge and transport-boundary policies over it. In the
   **default** graph, no workspace root may reach any transport (registry's reqwest
   is optional/off) — assert this stays true.

**Feature gating.** A `registry` cargo feature on `vibescan-core` (and passthrough
on `vibescan-cli`) enables the optional `vibescan-registry` edge and its transport.
It is **independent** of the `network` (Supabase) feature — building with one must
not pull the other's transport. Provide synthetic DAG controls (as Phase 4 did for
the sibling-dev-dependency case): a rejected `vibescan-registry`→`LocalStatic` edge,
and a rejected transport reachable from a `PURE_LOCALSTATIC` crate.

**Opt-in.** `--registry-checks` is separate from `--rls-tier0-read-probe` /
`--rls-tier1-introspect`; enabling any one does not enable the others (assert all
directions). **Repository config alone cannot enable `--registry-checks`** (same
rule as all egress). With the `registry` feature absent, the flag is inert (or a
clear "built without registry support" error) — never a silent partial run.

**Parsed dependencies.** Refactor §11.0 so manifest parsing yields
`Vec<ParsedDependency> { name, version_req, ecosystem: Ecosystem (Npm|PyPI),
manifest_path, is_scoped }`. The existing structural checks consume it (behavior
unchanged — no golden churn). `is_scoped` (npm `@org/pkg`) is captured here because
F2's precision guard needs it.

**Disclosure & audit.** Extend `NetworkScope` with `registry_checks: bool`,
`registry_newcomer: bool`, and a name-egress disclosure the report renders (which
ecosystems' names left, to which hosts). Each name-leaking request is a
`NetworkActionAudit` with `kind: RegistryExistence` (or `RegistryAdvisory` for a
live OSV query), carrying the host and the package coordinate — **never** a secret.
Crucially, an **OSV-snapshot match emits no name-egress audit** (matching is local;
see F2) — only existence checks and the optional live-OSV path disclose names.

### Acceptance criteria (self-verifiable)

1. `vibescan-registry` exists, is a workspace member, depends only on
   `vibescan-types` + optional transport; `RegistrySource`, `run_registry_checks`,
   and the shapes above compile under default and `--features registry`; the real
   transport-backed source compiles only under the feature.
2. **DAG green with 8 crates:** `bash scripts/check-network-boundary.sh` passes with
   `vibescan-registry` present and the two new edges; transport is permitted under
   both `vibescan-supabase` **and** `vibescan-registry` and nowhere else; the
   default graph is still transport-free; the registry feature graph is validated.
3. **DAG negative controls:** a synthetic `vibescan-registry`→`LocalStatic` edge is
   rejected; a synthetic transport made reachable from a `PURE_LOCALSTATIC` crate is
   rejected; a transport whose nearest parent is neither allowed crate is rejected.
4. **Feature isolation:** building `--features registry` without `network` pulls no
   Supabase transport and vice versa (assert via the metadata graphs).
5. **Opt-in isolation:** `--registry-checks` does not enable either RLS tier and
   vice versa; repository config alone does not enable it; flag-without-feature is a
   clear error, not a silent skip.
6. **Zero live egress by default:** the full default and `--features registry` test
   suites make no network request; a `MockRegistry` implementing `RegistrySource`
   drives all tests. `NetworkScope` extension round-trips (older JSON without the
   fields deserializes via `#[serde(default)]`).
7. `cargo fmt` + `clippy -D warnings` clean across default / network / registry;
   `cargo test --workspace` and each feature graph green; CI gains the two registry
   jobs.

---

## Task F2 — Known-malicious (OSV) and nonexistent-package detections

### Spec basis

- **§11.2 Tier 1 (OSV ⇒ Critical, `Confirmed`, default & privacy-safe):** match
  dependencies against a **locally-cached OSV snapshot**
  (`https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`),
  24-hour TTL, keyed by ecosystem, no user data. Matching is local ⇒ **no package
  name egresses** for this check. The live `api.osv.dev` batch query is an optional
  supplement behind a further sub-opt-in, disclosed when used.
- **§11.2 Tier 2 (nonexistent ⇒ High, `Confirmed`, public unscoped names only):**
  resolve at `registry.npmjs.org/<pkg>` / `pypi.org/pypi/<pkg>/json`; a 404 ⇒ likely
  hallucinated. This leaks the queried names ⇒ disclosed. **Precision guard:** a 404
  on a scoped `@org/pkg`, or on a name in an ecosystem served by a configured
  private/alternate registry, is **excluded** from the High rule (at most a `Review`
  note) — a private package is not a hallucination.
- **§11.1 clauses 4–5:** cache with explicit TTL; a failure taxonomy that **never**
  conflates an unreachable registry with a nonexistent package.
- **§11.0 (existing):** structural checks already emit `InvalidPackageName` /
  `EmptyVersionSpecifier`; F2 must not double-report.

### Problem (root-caused)

`DependencyIntegrityReason` (types) already defines `NonexistentPackage`,
`KnownMalicious`, and `SuspiciousNewcomer` — **all unused**; nothing resolves a
package against a registry or an advisory feed. The `hallucinated-dependency`
fixture (a nonexistent package) is consequently a permanent stub. As with Tier E's
`RlsExposure` variants, the vocabulary was built ahead of the engine; F2 supplies
the engine for two of the three reasons.

### File targets

- **Edit:** `crates/vibescan-registry/src/lib.rs` — implement OSV-snapshot matching
  and existence resolution in `run_registry_checks`, the failure taxonomy, and the
  two caches; the real `RegistrySource` impl (snapshot download + registry GET)
  under the transport feature.
- **Edit:** `crates/vibescan-core/src/lib.rs` — thread `ParsedDependency` in; ensure
  a dependency already flagged structurally (`InvalidPackageName`) is **not** sent
  to the registry (malformed ⇒ skip lookup); merge/coalesce so one dependency yields
  at most one integrity finding, highest-severity wins.
- **Edit:** `crates/vibescan-report/src/lib.rs` — `evidence_summary` already handles
  `Evidence::Dependency`; confirm the two new reasons render (no code change if the
  reason is `Debug`-printed).

### Implementation guidance

**OSV (Tier 1 — the default, privacy-safe check).** The `RegistrySource::advisories_for`
seam returns the parsed advisory set for an ecosystem; the real impl downloads
`<ECOSYSTEM>/all.zip` over HTTPS **once**, caches it (24-hour TTL, keyed by
ecosystem, in the platform cache dir, holding no user data), and matches each
dependency's `name@version` locally. A match ⇒ **Critical** `Confirmed`
`Evidence::Dependency { reason: KnownMalicious }`. Because matching is local, this
check adds **no `NetworkActionAudit` name-egress record** — it downloads a public
DB and matches offline; assert that no package name appears in the actions for the
OSV path. The live `api.osv.dev` query is out of Track F's default; if built later
it goes behind a sub-opt-in and *does* disclose names.

**Existence (Tier 2).** For each dependency **not** already structurally flagged and
**not** excluded by the precision guard, `RegistrySource::resolves` returns whether
the registry has it (real impl: `GET registry.npmjs.org/<pkg>` / `pypi.org/pypi/<pkg>/json`,
404 ⇒ false). Unresolved ⇒ **High** `Confirmed` `NonexistentPackage`. Each existence
request is a name-egress `NetworkActionAudit` (`RegistryExistence`, host + coordinate)
and contributes to the scope disclosure.

**Precision guard (mandatory — the C1-shaped false-positive site).** Exclude from
the High "nonexistent" rule: any npm `is_scoped` name (`@org/pkg`), and any
dependency whose ecosystem is served by a configured private/alternate registry.
For those, emit at most a `Review` note, never `NonexistentPackage`. A structural
404 must not masquerade as a semantic hallucination — this is the same discipline
the ignore layer and C1's classifier had to learn.

**Failure taxonomy (§11.1 clause 5).** Distinct, non-fatal `RegistryWarning`s:
`OsvSnapshotUnavailable { ecosystem }` (bulk download failed ⇒ **no** OSV finding
for that ecosystem, never a false clean), `RegistryUnavailable { host }`,
`RateLimited { host }`, `InvalidResponse { host }`. **`NotFound` is the Tier-2
finding, not a warning.** A network outage must **never** manufacture a High
"nonexistent" finding — an unreachable registry is `RegistryUnavailable`,
categorically distinct from a 404. `LocalStatic` (§11.0) findings survive regardless
of any registry failure.

**Caching (§11.1 clause 4).** Two caches under the platform cache dir, both public
data only: the OSV snapshot zips (24-hour TTL, keyed by ecosystem) and per-package
existence results (24-hour TTL, keyed by `name+ecosystem`). A cache hit issues no
request; neither cache holds a secret, path, or repo identifier.

### Acceptance criteria (self-verifiable)

1. Against `MockRegistry`: a dependency present in the mocked OSV set →
   one **Critical** `KnownMalicious`; a dependency the mock does not resolve →
   one **High** `NonexistentPackage`; a resolvable, advisory-free dependency →
   no registry finding.
2. **Privacy invariant:** the OSV-match path produces **no** name-egress audit
   (matched locally); the existence path produces one `RegistryExistence` audit per
   queried name; the scope disclosure lists the ecosystems/hosts that received
   names. Assert no secret appears in any audit or the disclosure.
3. **Precision guard (negative controls):** a scoped `@org/pkg` that 404s does
   **not** produce `NonexistentPackage` (at most a `Review` note); a dependency in a
   configured private-registry ecosystem that 404s does not either. A structural
   `InvalidPackageName` dependency is **not** sent to the registry (no existence
   audit for it) and yields exactly one finding, not two.
4. **Failure taxonomy (negative controls):** a mocked registry outage yields
   `RegistryUnavailable`, **not** `NonexistentPackage`; a mocked OSV download failure
   yields `OsvSnapshotUnavailable` and **no** false clean; §11.0 structural findings
   still emit under both failures.
5. **Caching:** a second check over the same inputs issues zero requests against the
   mock (cache hit); the OSV snapshot is fetched at most once per ecosystem per TTL.
6. `clippy -D warnings` clean (default / network / registry); full workspace green
   across feature graphs.

---

## Task F3 — Un-gate `hallucinated-dependency`; extend precision/recall; closeout

### Spec basis

- **§14 / §17.6 (two-tier corpus):** `hallucinated-dependency` — the third and last
  gated fixture — moves from gated (`TODO(registry)` per Tier D's D4 relabel) to
  **live**, driven by a `MockRegistry` under `--features registry` (the pattern the
  Tier 0/Tier 1 network fixtures use). Precision/recall (D2) is computed over the
  live tier, so the newly-live fixture joins the baseline.

### Problem (root-caused)

`tests/fixtures/hallucinated-dependency/expected.json` is `{ "todo": …, "findings":
[] }` and its golden test `network_hallucinated_dependency_fixture`
(`crates/vibescan-core/tests/golden_corpus.rs` ~L219) is an `#[ignore]`d stub
calling `ignored_network_fixture`. With F1+F2 landed, the capability the TODO waits
on exists, so the fixture must go live and enter the metrics corpus — otherwise the
tool ships a nonexistent-package detector with no golden proving it, and the D2
metric never reflects it.

### File targets

- **Edit:** `crates/vibescan-core/tests/golden_corpus.rs` — implement
  `network_hallucinated_dependency_fixture` with a `MockRegistry` (mirror
  `network_exposed_public_key_chain_fixture_is_gated`), un-gate it, keep a
  `cfg(not(feature = "registry"))` `#[ignore]`d stub.
- **Edit:** `tests/fixtures/hallucinated-dependency/expected.json` — the real
  expected finding(s) (regenerate via `UPDATE_GOLDEN=1`, review the diff).
- **Edit:** `crates/vibescan-core/tests/precision_recall.rs` +
  `tests/fixtures/corpus-metrics-baseline.json` — add the now-live fixture; regen the
  baseline under `UPDATE_METRICS=1` (review).
- **Edit:** `STATE.md` — note Track F complete; no gated corpus fixtures remain.

### Implementation guidance

**Fixture.** `network_hallucinated_dependency_fixture` parses the fixture repo's
manifest (a declared dependency that does not resolve), drives
`run_registry_checks(&MockRegistry{ /* unresolved */ }, …)`, asserts one **High**
`NonexistentPackage` finding, and writes the golden. Mirror the Tier 0 fixture's
structure exactly, including the `cfg`-gated `#[ignore]` stub for the feature-off
build. The fixture must plant a plainly-hallucinated **unscoped public** name so the
precision guard does not (correctly) suppress it — and, ideally, a second dependency
that is scoped-and-404 to assert the guard *does* suppress that one (a live
negative control inside the golden).

**Precision/recall.** Add `hallucinated-dependency` to the live corpus set in
`precision_recall.rs` with ground truth = its `expected.json`. Regenerate
`corpus-metrics-baseline.json`: total precision and recall must **not** decrease,
clean-control FP must stay 0, coverage recomputed. Review the baseline diff as an
intentional change, not a silent drift.

**Newcomer stays deferred.** Do **not** implement §11.2 Tier 3 here. Record it in
`STATE.md`/PR as the named post-Track-F follow-up (`Review` confidence, off by
default, npm-only; PyPI newcomer pending a download-signal decision), per §16 and
§11.2. No `SuspiciousNewcomer` finding is emitted by Track F.

### Acceptance criteria (self-verifiable)

1. `network_hallucinated_dependency_fixture` is **un-gated** and green under
   `--features registry`; its `expected.json` carries a real **High**
   `NonexistentPackage` finding; the `cfg(not(feature = "registry"))` stub remains.
2. If the fixture includes a scoped-404 dependency as an in-golden negative control,
   the golden shows it produces **no** `NonexistentPackage` (guard holds end-to-end).
3. `corpus-metrics-baseline.json` includes `hallucinated-dependency` with correct
   expected/observed/TP/FP/FN; total precision and recall do not decrease;
   clean-control FP stays 0. Golden manifests free of absolute paths / timestamps.
4. **No gated corpus fixtures remain** — `rls-off-table` and
   `permissive-using-true-policy` were un-gated by Track E; `hallucinated-dependency`
   by Track F. Any remaining `#[ignore]` is a deliberate feature-off stub, not a
   capability gap.
5. `SuspiciousNewcomer` is **not** emitted anywhere; the newcomer follow-up is named
   in `STATE.md`/PR.
6. `cargo test --workspace` + each feature graph green; `check-network-boundary.sh`
   passes; `fmt` + `clippy -D warnings` clean.

---

## Completion status this track closes

Track F delivers the Registry egress class per §11.1/§11.2: a `vibescan-registry`
crate that is the nearest parent of its own sync/rustls transport, reachable from
`vibescan-core` only through an optional feature-gated edge with the DAG checker
updated to permit exactly that edge and a second transport parent (F1); the two
high-confidence detections — OSV known-malicious (Critical, matched locally so it
leaks no names) and nonexistent-package (High, with the scoped/private precision
guard) — plus the failure taxonomy and caching (F2); and the un-gating of
`hallucinated-dependency` into the live precision/recall corpus (F3). After Track F,
**no corpus fixture remains gated** and the v1+ detection surface is fully exercised.
The noisy newcomer heuristic remains deferred (§16), and the online dependency
intelligence stays post-v1 and **off by default** (§11.1 clause 1).

## Notes for review

- **The DAG-checker generalization is the load-bearing edit** — F1's
  `ALLOWED_NETWORK_PARENT` → set change and the registry-feature-graph validation.
  It is the C1/E3-shaped site: get the boundary policy exactly right, or the tool
  either fails CI for a legitimate second transport parent, or (worse) stops
  catching a real `LocalStatic`→transport leak. The negative controls in F1
  acceptance #3 are what prove it.
- **The scoped-name precision guard is the second such site** (F2). A private
  dependency name 404s exactly like a hallucinated one; without the guard, every
  private-scoped dep becomes a false High. The in-golden scoped-404 negative control
  (F3) pins it end-to-end.
- **OSV-snapshot-as-default is a privacy decision, not just a performance one.**
  Matching a downloaded DB locally leaks no package names; the existence check does.
  Assert the asymmetry (F2 #2) — it is the concrete form of §11.1 clause 3.
- **Newcomer is deferred on purpose** (§16, §11.2 Tier 3), and PyPI newcomer is
  double-blocked (no first-party download signal). Do not wire in a BigQuery or
  `pypistats.org` dependency to "finish" it — that is a separate decision.
- **No writes, no secrets in egress, ever.** Registry requests carry package names
  (public identifiers) at most; a secret, a path, or a repo identifier must never
  leave. This is §11.1 clause 2 and is the invariant most worth an explicit test.
