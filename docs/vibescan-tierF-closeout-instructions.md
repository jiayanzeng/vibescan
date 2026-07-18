# vibescan — Tier F Close-out Instructions

Reviewed: 2026-07-18
Status: **complete**. CF1 landed at `f215c6e`; CF2 refreshed `STATE.md` from the
actual committed baseline and metrics. A same-day re-audit found every CF1/CF2
acceptance criterion green. The problem statements below are retained as the
historical rationale for the completed work, not as open tasks.

Scope: the two residuals from the Tier F audit at `ca59d6e`. Tier F is
functionally complete and every build/test gate passes; this close-out pins one
unpinned acceptance criterion and refreshes stale status metadata. Authority is
`vibescan-architecture.md`; where an implementation choice conflicts with a
cited section, surface it rather than silently resolving it.

Priority / build order: **CF1** (P1 — spec conformance, an acceptance criterion
is unpinned) then **CF2** (P2 — hygiene; records CF1's landing).

---

## Task CF1 — Composed failure-taxonomy regression (F2 acceptance criterion 4, clause 3)

### Spec basis
- **§11.0 (`LocalStatic` structural checks, always on):** the two v1 dependency
  shapes (malformed/unresolvable specifier; structural risk signal) are *"the
  only dependency findings v1 emits,"* need no egress, and are independent of the
  registry.
- **§11.1 clause 5 (Failure semantics):** registry failures are *"non-fatal and
  distinguishable,"* a network outage *"must not manufacture a High finding,"*
  and an unreachable registry must never be conflated with a nonexistent package.
- **Tier F, F2 acceptance criterion 4** (`docs/vibescan-tierF-instructions.md`):
  a mocked registry outage yields `RegistryUnavailable`, **not**
  `NonexistentPackage`; a mocked OSV download failure yields
  `OsvSnapshotUnavailable` and **no** false clean; **§11.0 structural findings
  still emit under both failures.**

### Problem statement
Clauses 1–2 of AC4 are pinned by `outage_is_a_warning_never_a_nonexistent_finding`
and `osv_failure_is_explicit_and_does_not_erase_existence_results` in
`crates/vibescan-registry/src/lib.rs`. Both assert `output.findings.is_empty()`
with **no structural finding present** — they exercise the registry crate in
isolation. Clause 3 — that a §11.0 structural finding *survives* each failure —
is pinned by no single test:

- The registry crate has no structural findings to compose with:
  `run_registry_checks` only emits `KnownMalicious` / `NonexistentPackage`.
- The corpus helper `registry_fixture_findings`
  (`crates/vibescan-core/tests/common/mod.rs`) calls `run_registry_checks` with a
  **success** mock and returns only registry findings; it never runs the
  production ordering in which structural findings are extended *before* the
  registry append.

Production behavior is correct: in `scan()`
(`crates/vibescan-core/src/lib.rs`), `findings.extend(dependency_scan.findings)`
(structural §11.0) precedes the registry append, and `run_registry_checks`
returns `Ok` on both failure modes, so structural findings are never displaced.
This is a **test-coverage gap, not a behavior bug** — but it must be pinned so a
future regression (e.g. moving the registry step ahead of the structural extend,
or making a registry failure fatal via `?`) is caught.

### File targets
- `crates/vibescan-core/src/lib.rs` — extract the registry-merge block into a
  private helper so the test and production share the exact ordering; add a unit
  test module. **No public API change. Registry crate untouched.**

### Implementation guidance
1. **Behavior-preserving extraction.** Extract the body of the
   `#[cfg(feature = "registry")]` block currently inside
   `if config.registry_checks { … }` (from `let source = ReqwestRegistrySource::new()…`
   through the `warnings.extend(…)` that maps into `ScopeWarning::Other`) into one
   private generic helper, so `scan()` and the test drive the same code. Match the
   crate's real types — the local vecs are `Vec<NetworkActionAudit>` and
   `Vec<ScopeWarning>`, and warnings are wrapped as `ScopeWarning::Other { message: w.message() }`:

   ```rust
   #[cfg(feature = "registry")]
   fn apply_registry_findings<S: vibescan_registry::RegistrySource>(
       source: &S,
       input: vibescan_registry::RegistryCheckInput,
       findings: &mut Vec<Finding>,
       network_actions: &mut Vec<NetworkActionAudit>,
       registry_name_egress: &mut Vec<RegistryNameEgress>,
       warnings: &mut Vec<ScopeWarning>,
   ) -> Result<(), CoreError> {
       let mut output = run_registry_checks(source, &input).map_err(CoreError::Registry)?;
       findings.append(&mut output.findings);
       network_actions.append(&mut output.actions);
       registry_name_egress.append(&mut output.name_egress);
       warnings.extend(
           output.warnings.into_iter()
               .map(|w| ScopeWarning::Other { message: w.message() }),
       );
       Ok(())
   }
   ```

   `scan()` then builds `ReqwestRegistrySource::new()?` and calls the helper.
   Confirm the diff to `scan()` is limited to this substitution — no reordering,
   no signature change, identical merge order.

2. **Add `#[cfg(all(test, feature = "registry"))] mod registry_failure_tests`**
   inside core `lib.rs` (a *unit* test module, so it can call the private helper
   and, if used, the private `scan_dependency_integrity`). Define a socket-free
   mock:

   ```rust
   enum FailMode { Outage, OsvSnapshot }
   struct FailingRegistry { mode: FailMode }
   impl RegistrySource for FailingRegistry {
       fn resolves(&self, _dep: &ParsedDependency) -> Result<RegistryResolution, RegistryError> {
           match self.mode {
               FailMode::Outage => Err(RegistryError::RegistryUnavailable {
                   host: "registry.npmjs.org".to_owned(),
               }),
               FailMode::OsvSnapshot => Ok(RegistryResolution { exists: true, request_made: true }),
           }
       }
       fn advisories_for(&self, ecosystem: Ecosystem) -> Result<AdvisorySet, RegistryError> {
           match self.mode {
               FailMode::Outage => Ok(AdvisorySet::empty(ecosystem)),
               FailMode::OsvSnapshot => Err(RegistryError::OsvSnapshotUnavailable { ecosystem }),
           }
       }
   }
   ```

3. **Seed a real §11.0 structural finding.** Preferred: run the private
   `scan_dependency_integrity` against the committed
   `tests/fixtures/malformed-dependency/repo` (it yields
   `dependency:invalid_package_name` + `dependency:empty_version_specifier`), and
   take both its `findings` (structural baseline) and its `dependencies`
   (registry input, so the outage path also has something to resolve). If reaching
   that path from a unit test is awkward, synthesize one structural `Finding` with
   `rule_id = "dependency:invalid_package_name"`, category `dependency_integrity`
   — clause 3 concerns *survival across the registry step*, so a synthesized
   structural finding is acceptable; the fixture-backed form is stronger and
   preferred.

4. **The two cases.** For each of `FailMode::Outage` and `FailMode::OsvSnapshot`:
   - start `findings` = the structural finding(s) from step 3;
   - call `apply_registry_findings(&FailingRegistry { mode }, input, &mut findings, …)`;
   - assert it returns `Ok` (non-fatal — the load-bearing property);
   - assert every seeded structural finding is still present (match by `rule_id`
     + fingerprint);
   - assert the expected warning is present (`RegistryUnavailable` message for
     outage; `OsvSnapshotUnavailable` message for OSV);
   - **negative controls:** under outage, assert no finding with reason
     `NonexistentPackage` was manufactured; under OSV failure, assert the
     structural finding count did not drop (no false clean).

### Acceptance criteria (self-verifiable)
1. The new module runs under `--features registry` and
   `--features network,registry`; both cases green.
2. **Survival:** under both failure modes every seeded §11.0 structural finding
   remains in the merged `findings`. Negative control: if the merge is edited so
   the registry append precedes the structural extend, or the helper propagates
   the registry error as fatal, the survival assertion fails.
3. **Taxonomy in the composed setting:** outage → `RegistryUnavailable` warning
   and no `NonexistentPackage`; OSV failure → `OsvSnapshotUnavailable` warning and
   unchanged structural-finding count.
4. **Behavior-preserving refactor:** `git diff` shows `scan()`'s registry step
   reduced to constructing the source and calling `apply_registry_findings`, with
   identical ordering; no public item added; registry crate unchanged.
5. `cargo clippy -D warnings` clean for default / network / registry /
   network+registry; full workspace green across all four feature graphs;
   `cargo fmt --check` clean.

### Notes
- Do not weaken or relocate any existing registry-crate test; this task **adds**
  coverage.
- Keep the mock socket-free (it implements `RegistrySource` and opens nothing),
  per the trait's stated contract.

---

## Task CF2 — Refresh `STATE.md` to the committed F3 baseline

### Problem statement
`STATE.md` records a pre-commit view: baseline `aa0efdd` (Task F2) *"plus the
Track F3 worktree,"* and later *"the worktree remains intentionally dirty only
with the uncommitted F3 implementation,"* with a 13-TP metrics line. The
committed tree already contains F3 —
`tests/fixtures/corpus-metrics-baseline.json` is `corpus_version:
tier-f3-live-v1` with **14 TP / 0 FP / 0 FN** — and the checkout is clean at
`ca59d6e`. The prose metadata lags the code.

### File targets
- `STATE.md` only. Docs-only; no code, no fixtures, no metric files.

### Implementation guidance
Regenerate the status metadata **from the actual repository**, not from prior
prose (the repo is the source of truth; do not hardcode numbers from this
document):
- Set the baseline line to the current committed `HEAD`, dropping the "plus the
  F3 worktree" phrasing and the "worktree remains intentionally dirty /
  uncommitted F3" sentence.
- Update the metrics line to byte-match `tests/fixtures/corpus-metrics-baseline.json`
  — read the file: TP/FP/FN, precision, recall, coverage, and `corpus_version`.
- Update `Reviewed:` to the close-out date.
- If CF1 has landed, add one line under the Track F verification note recording
  that F2 AC4 clause 3 (structural findings survive registry outage and
  OSV-snapshot failure) is now pinned by a composed core regression.
- Leave the architecture-authority disclaimer and the three completion lenses
  intact.

### Acceptance criteria (self-verifiable)
1. `STATE.md` no longer references an uncommitted/dirty F3 worktree, nor
   `aa0efdd` as the *current* implementation baseline.
2. The metrics line byte-matches the totals in
   `tests/fixtures/corpus-metrics-baseline.json` (same TP/FP/FN/precision/recall/
   coverage and `corpus_version`).
3. After the edit, `git status` is clean except for `STATE.md` (plus CF1's files
   if landed together); `git diff --check` passes.
4. No code, fixture, or metric file changed by this task.

---

## Completion record

- **CF1 complete:** the private core merge helper is shared by production and
  socket-free composed regressions. Both registry outage and OSV-snapshot failure
  preserve every seeded §11.0 finding, remain non-fatal, retain their distinct
  warnings, and manufacture no `NonexistentPackage` finding.
- **CF2 complete:** `STATE.md` records the actual `f215c6e` baseline and the
  committed `tier-f3-live-v1` totals (14 TP, 0 FP, 0 FN, precision 1.0, recall
  1.0, coverage 0.75), with no stale dirty/uncommitted-F3 claim.
- Focused CF1 tests pass under `registry` and `network,registry`; the full
  default/network/registry/combined formatting, Clippy, test, boundary, and
  hardening gates are green. No live egress was used.
