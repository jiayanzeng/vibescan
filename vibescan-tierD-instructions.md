# vibescan — Codex Instructions: Tier D (v1 closeout / assurance)

Reviewed: 2026-07-13
Author: architecture review (Claude), for implementation by Codex

## How to consume this document

Tier C closed the correctness gaps the `astroscout` real-repo scan exposed.
Tier D closes the **assurance** gaps: the spec (`vibescan-architecture.md`)
names precision/recall, a performance target, and a corpus as v1-load-bearing,
and none of them is yet *measured*. These four tasks make the already-green
implementation *provable* rather than merely runnable.

Prerequisite already landed: **the architecture has been repatched** (§17
decision log added; §1.2, §1.5, §4, §10.1, §11, §12, §13.2, §13.3, §14, §15,
§16 amended). The six long-standing ambiguities `STATE.md` flagged are now
*resolved* in the spec — Tier D is where the code and tests catch up to those
resolutions. As always, the authority is `vibescan-architecture.md`, **not**
`STATE.md`. If an implementation choice conflicts with a cited section, the
section wins; surface the conflict rather than diverge.

Build order (respect it — D1 produces the real-repo signal D2's coverage metric
and the §17 open question both consume):

1. **D1 — Scripted real-repository validation** (P1; §14 "real-repository
   validation", §17 open question)
2. **D2 — Precision/recall + coverage harness with committed baseline** (P1;
   §14 "precision/recall harness")
3. **D3 — Deterministic performance fixture + counter gate** (P2; §13.2 "proof
   obligation")
4. **D4 — Retire the resolved-ambiguity debt; ratify §17 in code and tests**
   (P2; §17.1–17.6)

Registry-backed dependency intelligence (the hallucinated-dependency fixture)
is **explicitly out of Tier D.** §11.1 now specifies it fully, but it is
post-v1 and requires the separate `--registry-checks` egress class and a
`vibescan-registry` crate. Do not build it here; leave its fixture gated.

Assume a committed `Cargo.lock`; all CI jobs run `--locked`. Tier D is additive
and must not weaken or delete an existing test, except where a golden/baseline
manifest is regenerated under an explicit `UPDATE_*` env guard (called out per
task).

---

## Task D1 — Scripted real-repository validation

### Spec basis

- **Refined §14 "real-repository validation":** a scan against a real repo is a
  *required, scripted* step, not an optional convenience — flat fixtures have
  twice passed while the real behavior was broken (the §6.2 root-anchored
  classifier; the duplicate Tier 0 probe). The script asserts repo-agnostic
  invariants: one finding per fingerprint, one Tier 0 input per project, no
  `Unknown` class on a path §6.2 says is classifiable, no absolute paths or raw
  secrets in serialized output, plus a sanitized zero-finding control and a
  planted positive control.
- **§17 open question (`src/api/` → `ServerOnly`):** the coverage signal this
  produces is the evidence that question is waiting on. D1 must *record* the
  classification-coverage rate on the real target, not act on it.

### Problem (root-caused)

`scripts/verify-hardening-checks.sh` already contains a real-repo leg, but:

1. It **skips by default** — `real_repo="${1:-${VIBESCAN_REAL_REPO:-}}"`; with
   no argument it prints `skipped: …` and exits 0. The one check specifically
   designed to catch the Tier C class of defect runs only when a human
   remembers to pass a path.
2. It is **not in CI** — no job in `.github/workflows/ci.yml` invokes it, so
   even its offline `cargo test --workspace` + boundary leg is redundant with
   existing jobs and its unique value never runs automatically.
3. Its assertions are **coarse** — it checks zero-findings on a sanitized tree
   and a planted-`.env` positive, but not the Tier-C-specific invariants
   (no `Unknown` on classifiable nested paths; exactly one finding per
   fingerprint; one probe input per project; no absolute paths in JSON).

### File targets

- **Edit:** `scripts/verify-hardening-checks.sh` — split the offline leg from
  the real-repo leg; add the repo-agnostic invariant assertions; emit the
  coverage rate.
- **New (optional but preferred):** `scripts/real-repo-invariants.py` — the
  invariant checker the shell script pipes JSON into, so the logic is testable
  and not trapped in bash heredocs.
- **Edit:** `.github/workflows/ci.yml` — add a `hardening-offline` job that runs
  the offline leg unconditionally; keep the real-repo leg gated behind a
  repository variable/secret so forks without a fixture repo don't fail.

### Implementation guidance

**Separate the legs.** The offline leg (`cargo test --workspace` +
`check-network-boundary.sh`) must run with no fixture and be the CI job. The
real-repo leg stays argument/`VIBESCAN_REAL_REPO`-gated for local + a
CI-secret-gated optional job — a fork without a real repo must not fail, but the
skip must be **loud** (a distinct exit-note the CI log surfaces), never silent.

**Invariant checker** (`real-repo-invariants.py`) reads a `--format json` scan
and asserts, over `findings[]` and `scope`:

1. **Fingerprint uniqueness:** no two findings share the same
   `(rule_id, fingerprint, normalized_project)` identity — a violation is the
   coalescing/dedup bug regressing.
2. **Probe-input uniqueness:** at most one Tier 0 network action per normalized
   project URL in `scope.network` (only asserted under `--features network`).
3. **Classification coverage:** compute the share of secret/RLS findings whose
   `location_class != Unknown`. Assert it is **> 0** on a target known to have
   nested client bundles (a bare "no findings" repo is vacuously fine). Print
   the exact rate — this is the §17 open-question evidence.
4. **No absolute paths / no raw secrets:** no finding location or evidence
   string contains the scan root's absolute prefix, and no `evidence` field
   contains a full `sb_publishable_*` / `sb_secret_*` body (redaction holds in
   serialized output — §13.3).

Preserve the existing sanitized-zero-finding and planted-positive controls;
route both through the same invariant checker.

**Do not shell out to `git` from the scanner.** This is test/CI scaffolding, so
the *script* may use `git init` on the sanitized copy (as it already does) — the
single-binary invariant §13.1 constrains the shipped scanner, not the test
harness. Keep it that way; the scanner still uses `gix`.

### Acceptance criteria (self-verifiable)

1. `bash scripts/verify-hardening-checks.sh` with **no** argument runs the full
   offline leg (workspace tests + boundary) and exits 0 with an explicit
   "real-repo leg skipped: no fixture" note — not a silent success.
2. `bash scripts/verify-hardening-checks.sh /path/to/nextjs-supabase-repo` runs
   the invariant checker and fails loudly if any invariant is violated; on a
   healthy scan it prints the classification-coverage rate as a percentage.
3. `python3 scripts/real-repo-invariants.py <fixture.json>` has unit-style self
   checks: a crafted JSON with duplicate fingerprints fails invariant 1; one
   with an absolute path fails invariant 4; the offline-composite golden's JSON
   passes all applicable invariants. (Wire these as a `pytest`-free
   `if __name__ == "__main__"` self-test block or a tiny `bash` harness — no new
   Python deps.)
4. `.github/workflows/ci.yml` gains a `hardening-offline` job (unconditional)
   and an optional real-repo job gated on a repository secret; `cargo fmt` /
   `clippy -D warnings` unaffected (no Rust changed unless the checker is Rust).
5. The script emits, for any successful real scan, a one-line machine-greppable
   summary: `REALREPO_INVARIANTS ok coverage=<pct> findings=<n> projects=<n>`.

---

## Task D2 — Precision/recall + coverage harness with committed baseline

### Spec basis

- **Refined §14 "precision/recall harness":** measuring detection is itself a
  deliverable — a machine-readable JSON metrics report over the *live* corpus
  plus the clean control, containing corpus version, per-fixture expected vs
  observed counts, TP/FP/FN, precision, recall, and classification-coverage
  rate; compared against a **committed baseline**; any regression fails the
  build; zero FP on the clean control is a hard gate.
- **Refined §14 two-tier corpus (§17.6):** precision/recall is computed over the
  **live** tier only, never diluted by a gated fixture that cannot run.

### Problem (root-caused)

There is **no** precision/recall artifact anywhere in the tree (zero hits for
`precision`/`recall`/`bench` across `crates/`, `scripts/`, CI). The golden
corpus (`crates/vibescan-core/tests/golden_corpus.rs`) asserts exact per-fixture
manifests — which is necessary but is a *pass/fail* signal, not a *metric*. §14
calls the false-positive/negative rate "a security tool's credibility"; today
that rate is unmeasured, so a change that silently trades recall for fewer FPs
(or vice versa) passes CI as long as each individual golden is edited to match.

### File targets

- **New:** `crates/vibescan-core/tests/precision_recall.rs` — the harness as an
  integration test (reuses the fixture materialization already in
  `golden_corpus.rs`; factor shared helpers into a small module or duplicate
  minimally rather than making the test binaries depend on each other).
- **New:** `tests/fixtures/corpus-metrics-baseline.json` — the committed
  baseline the harness diffs against.
- **Edit:** each **live** fixture `expected.json` only if a `truth` annotation
  is needed (see guidance) — additive field, must not change existing manifest
  assertions.

### Implementation guidance

**Ground truth.** Each live fixture's `expected.json` already encodes the
findings that *should* be produced — treat that as ground truth. TP = an
expected finding observed; FN = expected but absent; FP = observed but not
expected. Match on the stable identity `(rule_id, fingerprint, project)`, **not**
on paths (identity is path-independent — §17.4). The clean control's ground
truth is the empty set, so any observed finding there is an FP.

**Live tier only.** Iterate the same `LIVE_FIXTURES` set the golden test uses
(clean-control, history-only-elevated-key, publishable-client-reachable,
vendor-chunks-noise, monorepo-layout, nested-gitignore, malformed-dependency)
plus the offline-composite exposed-public-key-chain. **Do not** include the
`#[ignore]`d gated fixtures (rls-off-table, permissive-using-true-policy,
hallucinated-dependency) — they cannot run and would corrupt the metric (§17.6).

**Metrics report shape** (serialize deterministically, `BTreeMap`-ordered):

```json
{
  "corpus_version": "<a constant bumped when the live set changes>",
  "totals": { "tp": N, "fp": N, "fn": N,
              "precision": 1.0, "recall": 1.0, "coverage": 1.0 },
  "per_fixture": {
    "<name>": { "expected": N, "observed": N, "tp": N, "fp": N, "fn": N }
  }
}
```

`coverage` = share of produced secret/RLS findings with `location_class !=
Unknown`, computed over the live corpus (the in-repo twin of D1's real-repo
coverage number).

**Baseline gate.** Compare the computed report to
`corpus-metrics-baseline.json`. On mismatch, fail with a readable diff. Provide
`UPDATE_METRICS=1` to rewrite the baseline (mirror the golden corpus's
`UPDATE_GOLDEN` ergonomics) so an *intended* change is a reviewed one-line diff,
never a silent drift. **Hard gate independent of the baseline:** clean-control
FP count must be exactly 0 and total precision/recall must not *decrease* vs
baseline even if `UPDATE_METRICS` is set without review — i.e. a downward move
requires deleting the assertion deliberately, which shows up in review.

### Acceptance criteria (self-verifiable)

1. `cargo test -p vibescan-core --test precision_recall` computes the report and
   asserts it equals `corpus-metrics-baseline.json`; green on the current tree.
2. The committed baseline records precision and recall on the current live
   corpus (expected: both 1.0 given exact goldens) and a coverage rate < 1.0 is
   permitted **only** if a fixture legitimately has `Unknown`-class findings —
   assert the exact number, don't hand-wave.
3. A deliberately broken run proves the gate bites: temporarily add a bogus
   expected finding to one fixture's ground truth → harness reports an FN and
   fails. (Provide this as a `#[test]` using an in-memory perturbed truth set,
   not by editing a committed fixture.)
4. Clean-control FP gate: a synthetic injected FP on the clean control fails the
   harness regardless of baseline state.
5. `UPDATE_METRICS=1 cargo test … precision_recall` regenerates the baseline;
   the regenerated file is byte-identical to the committed one on an unchanged
   tree (idempotent).
6. `clippy -D warnings` clean under default + network; `cargo test --workspace`
   and `--features network` both green.

---

## Task D3 — Deterministic performance fixture + counter gate

### Spec basis

- **Refined §13.2 "proof obligation":** the low-single-digit-seconds target is a
  claim until measured. The scan must emit deterministic counters in
  `ScanStats` — paths walked, blobs read, unique contents after dedup, dedup
  ratio, units materialized, budget/truncation flags — plus wall-clock
  `duration`. A deterministically generated performance fixture records both.
  **CI gates the counters, never wall time.** A counter regression is a build
  failure.

### Problem (root-caused)

`ScanStats` today carries only `by_severity`, `by_category`,
`skipped_large_files`, `skipped_binary_files`, `scan_budget_hit` (see
`crates/vibescan-types/src/lib.rs`). The dedup ratio — the single most
informative performance-correctness number, since content-hash dedup before
detection is the §13.2 mechanism — is not surfaced at all. There is no
performance fixture and no counter assertion, so a regression that (say) breaks
content dedup and rescans every blob would not fail any test; it would only be
"slower," which nothing measures.

### File targets

- **Edit:** `crates/vibescan-types/src/lib.rs` — extend `ScanStats` with the
  §13.2 counters (additive fields; keep `#[serde(default)]` so existing
  deserialization of older results doesn't break).
- **Edit:** `crates/vibescan-core/src/lib.rs` — populate the new counters in the
  collect/dedup/detect phases where the numbers already exist (the dedup step
  already groups by `ContentId`; expose the before/after counts).
- **New:** `crates/vibescan-core/tests/perf_counters.rs` — generates a fixture
  deterministically **in-test** (no vendored large files; write N files with a
  fixed seed so the tree is reproducible and the repo stays small), scans it,
  and asserts the counters.
- **Edit:** report snapshots only if the new `ScanStats` fields surface in a
  rendered format — regenerate under the existing snapshot update guard and
  review the diff.

### Implementation guidance

**New counters** (all `u64` unless noted; `#[serde(default)]`):
`paths_walked`, `blobs_read`, `unique_contents`, `units_materialized`,
`truncated` (bool/flag). Derive **dedup ratio** at report time
(`1 - unique_contents / blobs_read`) rather than storing a float, to keep the
serialized stats integer-exact and diff-stable.

**Determinism.** The fixture generator must produce a byte-identical tree every
run: fixed file count, fixed content templates seeded by index, a controlled
number of *intentional duplicates* so `unique_contents < blobs_read` is asserted
as an exact value, not a range. No timestamps, no randomness, no absolute paths
in anything asserted.

**Gate counters, not time.** Assert exact `blobs_read`, `unique_contents`,
`units_materialized`, and the derived dedup ratio. **Record** `duration_ms` (log
it, maybe print it) but never assert on it — a shared CI runner cannot support a
timing assertion, and a flaky perf test is worse than none. This split is the
whole point of §13.2's "gates the counters, never the wall time."

### Acceptance criteria (self-verifiable)

1. `ScanStats` gains the five counters; existing serialized `ScanResult`s
   (older JSON without the fields) still deserialize (`#[serde(default)]`
   proven by a round-trip test on a stored older-shape blob).
2. `cargo test -p vibescan-core --test perf_counters` builds the deterministic
   fixture, scans it, and asserts exact `blobs_read` / `unique_contents` /
   `units_materialized` and a dedup ratio matching the planted duplicate rate
   (e.g. 40 files, 10 duplicated → `unique_contents == 30`,
   `blobs_read == 40`).
3. Running the perf test twice yields identical counters
   (`golden_corpus_is_deterministic_across_runs`-style assertion).
4. A negative control proves the gate: a variant that disables content dedup
   (behind a test-only path or by asserting the *pre-dedup* number) shows
   `unique_contents == blobs_read`, demonstrating the counter actually reflects
   dedup. Keep this as an assertion of the real number, not a mutation of
   production code.
5. `duration_ms` is populated and non-asserted; no timing comparison exists in
   any test.
6. Golden manifests unaffected (stats are not part of the golden manifest —
   confirm the manifest builder still excludes volatile fields); report
   snapshots regenerated and reviewed only if the rendered output changed.
   `clippy -D warnings` clean default + network; full workspace green both
   modes.

---

## Task D4 — Retire resolved-ambiguity debt; ratify §17 in code and tests

### Spec basis

- **§17.1–17.6 (new decision log):** the six ambiguities are resolved. Most were
  resolved *in favor of what the code already did* — this task is about making
  that alignment **explicit and asserted**, and removing the now-obsolete
  "conservative policy until the architecture is clarified" paragraph from
  `STATE.md` so a future agent doesn't re-litigate a settled question.

### Problem (root-caused)

`STATE.md` still contains an "Architecture ambiguities requiring an explicit
decision" section and a "Conservative policy until the architecture is
clarified" paragraph. Those were correct *before* the §17 patch; they are now
stale and actively misleading — they tell a future agent that settled questions
are open. Several resolutions also lack a *pinning test*: e.g. §17.3 (all
serialized formats redacted) is currently true but not asserted per-format, so a
future "local HTML full-match" change could pass.

### File targets

- **Edit:** `STATE.md` — replace the "Architecture ambiguities" section with a
  short "Resolved in architecture §17 (2026-07-13)" pointer; delete the
  conservative-policy paragraph.
- **New/Edit:** `crates/vibescan-report/tests/report_snapshots.rs` — add a
  per-format redaction assertion (§17.3): scan a fixture with a known secret,
  render JSON / SARIF / HTML, assert none contains the raw secret body; the TTY
  full-match path is exercised separately and explicitly.
- **Edit (assertion only):** wherever elevated-key severity is tested, add an
  explicit gitignored-server-env case asserting **Critical** (§17.1) if one does
  not already exist.

### Implementation guidance

This is a documentation-truth + pinning-test task, **not** a behavior change. If
implementing any assertion reveals the code does *not* match the §17 resolution,
**stop and surface it** — that is a real bug the decision log exposed, not
something to quietly fix under a "docs" task.

For §17.3, the cleanest pin is a single table-driven test:
`for format in [Json, Sarif, Html] { assert!(!render(format).contains(raw)); }`
plus one `assert!(render_tty().contains(raw))` to prove the TTY exception is
real and intentional.

Leave §17.5 (registry egress) and §17.6 (gated fixtures) as *documentation*
only — their code lands with the post-v1 registry crate (out of Tier D scope).
Just ensure the three gated fixtures still carry accurate `TODO(<tier>)`
messages naming the capability, per §14.

### Acceptance criteria (self-verifiable)

1. `STATE.md` no longer contains the strings "requiring an explicit decision"
   or "Conservative policy until the architecture is clarified"; it points to
   architecture §17 instead.
2. A per-format redaction test asserts JSON, SARIF, and HTML omit the raw
   secret body while TTY includes it; green (proving §17.3 holds in code).
3. An elevated-key-in-gitignored-server-env test asserts `Critical` (§17.1).
4. The three gated fixtures (`rls-off-table`, `permissive-using-true-policy`,
   `hallucinated-dependency`) remain `#[ignore]`d with accurate,
   capability-naming `TODO` messages; no gated fixture was un-gated in Tier D.
5. `cargo test --workspace` + `--features network` green; `fmt` + `clippy -D
   warnings` clean.

---

## Completion status this tier closes

Prior tiers (A1, B3, C, Phases 1–5) are verified complete against their
acceptance criteria. Tier D adds no detection breadth; it discharges the three
v1-closeout obligations the repatched spec now names explicitly (§13.2 counters,
§14 precision/recall, §14 real-repo validation) and retires the resolved-
ambiguity debt (§17). After Tier D, "buildable v1" per §15 step 9 is *complete
and proven*, and the only remaining architecture work is the deferred post-v1
tracks: Tier 1 introspection, the §11.1 registry egress class, and the
distribution pipeline — each of which requires its own instruction set.

## Notes for review

- **D1 is load-bearing and should merge first.** It is the standing guard
  against the exact class of defect (flat fixture green, real repo broken) that
  produced all of Tier C. Its coverage number is also the input to the §17
  `src/api/` open question — merging it first starts accumulating that evidence
  immediately.
- **D2's ground truth is the existing goldens.** Do not invent a parallel truth
  format; the `expected.json` files already are the truth. The harness's job is
  to *aggregate* them into a metric and gate on drift, not to re-specify them.
- **D3's discipline is "counters not clocks."** The most common way to get this
  wrong is a wall-time assertion that flakes on CI. Assert integer counters that
  are exact and deterministic; log time, never gate on it.
- **D4 is the one task that might surface a real bug.** It is written as a
  docs/pinning task on the assumption the code already matches §17 (it appears
  to). If a pinning assertion fails, that is a genuine finding — escalate it,
  don't paper over it under the "documentation" framing.
- **Registry work stays out.** §11.1 is now fully specified precisely so it can
  be built *correctly later*, not so it can be rushed into v1. The
  hallucinated-dependency fixture stays gated until the `vibescan-registry`
  crate and `--registry-checks` opt-in exist.
