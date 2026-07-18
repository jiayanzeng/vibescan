# vibescan State

Reviewed: 2026-07-18

Current implementation baseline: `f1ef57e` (`main`, Task E2) plus the Tier E3
worktree described below.

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
rejection, and Phase 3B now scopes typed LocalStatic API references to exact or
unambiguous projects before Tier 0 probing. Phase 3C now records every attempted
Tier 0 root/table GET as redacted scan-scope evidence and renders it in JSON,
SARIF, TTY, and HTML. Phase 4 now enforces the authoritative seven-crate DAG
across normal, build, dev, target, optional, and feature-activated dependencies.
Phase 5 now enforces default < repository config < explicit CLI precedence,
strict repository-root path handling, named-baseline failures, and additive
custom rules without allowing repository config alone to enable Network work.

The strict **buildable-v1** verdict is now **complete and proven** through
architecture §15 step 9. Tier E1 added credentialed, read-only Postgres catalog
transport and input plumbing. Tier E2 added the four mechanically decidable
catalog detections and catalog-native evidence. Tier E3 now integrates the two
confirmed Tier 1 read-exposure shapes with both v1 correlation rules, activates
the RLS-off and permissive-policy mock goldens, and incorporates them into the
committed corpus metrics. Registry-backed dependency intelligence and
distribution remain incomplete post-v1 tracks. Architecture §17.8 explicitly
defers the noisy user-writable-metadata heuristic, so its absence is not an E2
gap. The verdict for the entire architecture document is therefore partial.

Use these three lenses when discussing completion:

- **Runnable v1 coverage:** all eight section-15 steps exist and the Phase
  1–5 regression matrix is green.
- **Strict buildable-v1 conformance:** complete. The previously identified
  identity, Network semantics, auditability, crate-DAG, CLI/config,
  real-repository, precision/recall, deterministic performance-counter, and
  resolved-decision ratification blockers are all covered by passing gates.
- **Entire architecture document:** partial. Tier E's E1–E3 implementation is
  complete, while online dependency intelligence and distribution remain
  incomplete.

No target-project write path was found. Tier 0 exposes GET only and discards
returned row data after counting. Tier E1's Postgres transport accepts only
validated Supabase DB hosts and ports and issues fixed, read-only catalog
`SELECT`s. E2 infers write exposure only from catalog grants plus policy absence
and never attempts a write. The default production dependency graph remains
transport-free.

## Current worktree context

The worktree started clean at `f1ef57e`, which commits Task E2. Tier E3 adds a
single read-exposure predicate in core: Tier 0 `Exposed`, Tier 1 `RlsDisabled`,
and Tier 1 `PermissivePolicy` may drive rule 1; `MissingOperationPolicy` and
`InferredWriteExposure` deliberately may not. Rule 2 now enumerates every
same-project `Category::Rls` finding across both evidence shapes.

The RLS-off and permissive-policy fixtures are live under `--features network`
through an injected read-only catalog. Default builds retain loud ignored stubs;
the network build now leaves only the registry-backed hallucinated-dependency
fixture ignored. The corpus baseline is `tier-e3-live-v1`: 13 TP, 0 FP, 0 FN,
1.0 precision, 1.0 recall, and 0.75 classification coverage. No live database or
Network action was run here.

All Phase 1–5, Tier D, and Tier E regressions and both unfiltered workspace
matrices remain green.

## Tier E3 verification observed on 2026-07-18

Core unit tests prove rule 1 fires from standalone-Critical `RlsDisabled` and
`PermissivePolicy` evidence with no `RlsProbe` present. Negative controls prove
missing-operation, inferred-write, and known-different-project policy findings
cannot fire the read chain. A committed elevated-key case proves rule 2 includes
Tier 1 policy evidence.

Both promoted fixtures run `introspect_tier1_with_source` through a deterministic
mock and assert three catalog `SELECT` actions. RLS-off produces one absorbed
Critical composite. The permissive fixture produces the absorbed Critical
composite plus the three valid Medium default-deny operation advisories from E2.
Reviewed goldens contain only the environment-source sentinel and repo-relative
client path; they contain no DB URL, password, row data, timestamp, or absolute
host path. Under `network`, only `hallucinated-dependency` remains ignored with
its accurate `TODO(registry)` capability label.

The committed metrics baseline now includes both fixtures: **13 TP, 0 FP, 0 FN,
precision 1.0, recall 1.0, coverage 0.75**. The clean-control FP gate remains
zero, and the negative recall/FP controls still fail when intentionally
perturbed.

The following pass is green on the current Tier E3 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test golden_corpus --features network --locked
cargo test -p vibescan-core --test precision_recall --locked
cargo test -p vibescan-core --test precision_recall --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

Measured workspace results are **153 passed, 4 ignored** by default and **166
passed, 1 ignored** with `network`. The hardening helper's self-tests, workspace
tests, and boundary leg passed; its optional real-repository leg printed
`real-repo leg skipped: no fixture`. No live target or credential was used.

## Tier E2 verification observed on 2026-07-18

Mock-catalog tests pin each E2 finding independently: RLS disabled, normalized
literal `USING (true)`, one missing `SELECT` policy, and an `anon` `INSERT` grant
without an operation policy. Negative controls reject `is_active = true`,
`true_flag`, and `is_true(...)` as permissive policies; ignore catalog tables
outside the project-scoped LocalStatic candidate set; and suppress policy
conclusions when the policy query fails. A named test proves the metadata-keyed
heuristic is absent. The production query guard still accepts only catalog
`SELECT`s and rejects `SET`/DML controls.

Architecture §17.8's severity and wording contract is pinned directly: RLS
disabled and literal-true permissive policies are Critical standalone,
inferred-write exposure is High, and a missing-operation policy is a Medium
default-deny advisory for `anon`/`authenticated`, never described as an open or
exposed operation.

`Evidence::RlsPolicy` round-trips through JSON and carries project, table,
command, `USING`, `WITH CHECK`, `rowsecurity`, and exposure. Catalog actions omit
the inapplicable row-count field. Serialized mock output contains the intended
policy predicate but no DB password, mock row markers, application row values,
or count. The four report snapshots were regenerated under `UPDATE_GOLDEN=1`,
reviewed, and rerun without the variable; no absolute path or raw credential was
introduced.

The following pass is green on the current Tier E2 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-types --locked
cargo test -p vibescan-supabase --locked
cargo test -p vibescan-supabase --features network --locked
cargo test -p vibescan-report --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test precision_recall --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

No live Network action or credentialed database connection was run. At this E2
checkpoint, the Tier 1 goldens were still gated; Tier E3 has since promoted them
through the mock-catalog orchestration recorded above.

## Tier E1 verification observed on 2026-07-18

The production Postgres dependency is optional under `network`, nearest-parented
by `vibescan-supabase`, rustls-backed, and absent from the default graph. The
boundary checker rejects OpenSSL/native-tls and confirms the four production
`LocalStatic` libraries remain transport-free. Mock-catalog tests cover query
ordering, action serialization, early rejection of invalid hosts/schemes/ports,
project mismatch, query failures, secret-safe errors/debug output, and the
fixed-`SELECT` query guard. CLI regressions cover both opt-in directions,
repository-config inertness, and exit 2 when the Tier 1 credential is absent.

The following pass is green on the current Tier E1 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-supabase --locked
cargo test -p vibescan-supabase --features network --locked
cargo test -p vibescan-types --locked
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked
cargo test -p vibescan-cli --features network --locked
cargo test -p vibescan-report --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
python3 scripts/check-network-boundary.py --self-test
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

No golden manifest or report snapshot changed. No real credential was placed in
configuration, logs, tests, fixtures, actions, or persisted output. Architecture
§7.2 still describes a service-role key and a DB URL as interchangeable Tier 1
inputs; E1 follows the task's catalog-access rationale and implements only the
DB-URL path. The architecture owner should clarify that wording rather than
silently treating PostgREST service-role access as policy-catalog access.
The hardening aggregate passed and emitted the required explicit
`real-repo leg skipped: no fixture` note.

## Tier D4 verification observed on 2026-07-18

The new core integration test plants one synthetic `sb_secret_*` value in a
temporary Git repository, runs `scan_and_render` for JSON, SARIF, HTML, and TTY,
and proves that every format contains the redacted evidence but not the raw
body. It separately serializes the full `ScanResult` and proves the same
candidate-to-finding boundary. The report integration test pins presentation of
the supplied redacted evidence in all four formats. No production behavior or
snapshot changed.

At the Tier D4 checkpoint, the existing
`gitignored_env_fixture_has_exact_elevated_key_finding` test was the §17.1 pin:
a gitignored `.env` containing an elevated new-format key produces exactly one
`Critical` `SecretNew` finding. No duplicate assertion was added.
At that checkpoint, the gated RLS fixtures said `TODO(tier1)`; the
hallucinated-dependency fixture said
`TODO(registry)`, and the mocked exposed-public-key chain remains
`TODO(network)` in default builds.

The following pass is green on the current Tier D4 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-core --test redaction_boundary --locked
cargo test -p vibescan-report --test report_snapshots --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --lib \
  gitignored_env_fixture_has_exact_elevated_key_finding --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The default workspace matrix reports **132 passed, 4 intentionally ignored**;
the `network` matrix reports **137 passed, 3 intentionally ignored**. The
hardening aggregate reruns the default matrix and checker self-tests, confirms
the seven-crate/transport boundary, and emits the required loud
`real-repo leg skipped: no fixture` note. No live Network action was run.

## Tier D3 verification observed on 2026-07-15

`ScanStats` now publishes `paths_walked`, `blobs_read`, `unique_contents`,
`units_materialized`, and `truncated` as defaulted integer/boolean fields. The
collector owns the pre/post-dedup measurements; core copies them into the scan
result. Dedup ratio is derived from the exact counts at report time and is not
stored as a float. An older-shape `ScanResult` JSON fixture without the five
fields still deserializes and round-trips with zero/false defaults.

The generated fixture creates 40 byte-deterministic TypeScript files with 30
unique contents and 10 intentional duplicates. Two independent scans both
produce **40 paths, 40 blobs, 30 unique contents, 30 materialized units, and a
25.00% dedup ratio**. The pre-dedup negative control records 40 would-be unique
inputs and proves the production counter differs by exactly 10. Explicit
`--nocapture` runs recorded values from 12–33 ms; these values are logged only
and no test compares or gates wall time. Existing default/network workspace CI
jobs pick up the integration test automatically.

The following pass is green on the current Tier D3 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-types --locked
cargo test -p vibescan-git --locked
cargo test -p vibescan-report --locked
cargo test -p vibescan-core --test perf_counters --locked -- --nocapture
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh --offline-only
git diff --check
```

The default workspace matrix reports **130 passed, 4 intentionally ignored**;
the `network` matrix reports **135 passed, 3 intentionally ignored**. Golden
manifests are unchanged because their builder still canonicalizes findings
only. JSON, SARIF, TTY, and HTML report snapshots were intentionally regenerated
and reviewed to expose the counters and derived ratio; no raw secret or
absolute path was introduced. No live Network action was run.

## Tier D2 verification observed on 2026-07-15

The D2 harness shares the golden corpus's seven live repository fixtures and
adds the offline composite exposed-public-key chain. It reads the existing
`expected.json` manifests as truth, matches path-independent
`(rule_id, fingerprint, normalized_project)` identities, and excludes all three
ignored/gated fixtures from the metric. Explicit truth annotations supply
stable non-path subjects for the two dependency findings and the absorbed
composite finding without changing the existing golden assertions.

The committed `tier-d2-live-v1` baseline records **8 TP, 0 FP, 0 FN, precision
1.0, recall 1.0, and classification coverage 0.6**. Coverage is exactly 3/5:
the history-only `src/history.ts` and nested
`packages/nested/ignored-but-scanned/secret.ts` findings are legitimately
`Unknown`, while the other three eligible live findings are classified. The
in-memory bogus-truth control produces one FN and trips the recall gate; an
injected clean-control finding produces one FP and trips the independent clean
gate.

The following pass on the current combined D1/D2 worktree:

```sh
cargo fmt --all -- --check
cargo test -p vibescan-core --test precision_recall --locked
cargo test -p vibescan-core --test precision_recall --features network --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test golden_corpus --features network --locked
UPDATE_METRICS=1 cargo test -p vibescan-core --test precision_recall --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The default workspace matrix reports **126 passed, 4 intentionally ignored**;
the `network` matrix reports **131 passed, 3 intentionally ignored**. The
baseline SHA-256 was
`3d5ef933fca6a00460b84904fadfe19a3d2fe947a7232fe961f5763ceeba106f` both
before and after `UPDATE_METRICS=1`, proving byte-identical regeneration on the
unchanged corpus. No live Network action was run.

## Tier D1 verification observed on 2026-07-15

The following pass on the current Tier D1 worktree:

```sh
python3 scripts/real-repo-invariants.py --self-test
python3 scripts/real-repo-invariants.py \
  tests/fixtures/offline-composite-exposed-public-key-chain/expected.json
bash -n scripts/verify-hardening-checks.sh
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci.yml")'
bash scripts/verify-hardening-checks.sh
bash scripts/verify-hardening-checks.sh --real-repo-only \
  /Users/yzjia/test/astroscout
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test --workspace --features network --locked
git diff --check
```

The no-argument hardening command runs the default workspace matrix (**123
passed, 4 intentionally ignored**), the checker self-tests, and the Network
boundary, then emits `real-repo leg skipped: no fixture`. The Network workspace
matrix reports **128 passed, 3 intentionally ignored**. A synthetic Git-backed
smoke target exercised the real-only path, sanitized zero-finding control, and
planted positive control; its positive run emitted
`REALREPO_INVARIANTS ok coverage=100.00% findings=1 projects=0`.

The explicitly supplied AstroScout repository then passed the complete
LocalStatic real-repository leg, including both controls, and emitted
`REALREPO_INVARIANTS ok coverage=100.00% findings=3 projects=1`. This records a
genuine §17 coverage data point without changing the `src/api/` rule. No live
Supabase target was contacted. The private-fixture CI job requires
`VIBESCAN_REAL_REPO_REPOSITORY` plus `VIBESCAN_REAL_REPO_TOKEN` and reports a
loud skip when they are absent.

## Phase 5 verification observed on 2026-07-12

The following pass on the current Phase 5 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-secrets --locked
cargo test -p vibescan-core --locked
cargo test -p vibescan-cli --locked
cargo test -p vibescan-cli --features network --locked
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-core --test golden_corpus --features network --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
bash scripts/verify-hardening-checks.sh
git diff --check
```

The default workspace matrix reports 123 passed and 4 intentionally ignored;
the `network` matrix reports 128 passed and 3 intentionally ignored. The CLI
real-binary suite passes 12/12 in both modes. The hardening aggregate passes and
skips its optional real-repository leg because no fixture was supplied. No live
Network action was run.

## Phase 4 verification observed on 2026-07-12

The following pass on the current Phase 4 worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-git --locked
cargo test -p vibescan-supabase --locked
cargo test -p vibescan-core --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test -p vibescan-core --test golden_corpus --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

The boundary checker confirms the exact seven-crate DAG in both metadata
graphs and runs synthetic positive/negative controls for a sibling
dev-dependency, an unauthorized direct/optional edge, and LocalStatic transport
leakage. The two unfiltered workspace commands were also run; both stop only at
the same three pre-existing Phase 5 CLI/baseline tests. The local hardening
aggregate was run and stops at those same tests before its boundary leg. No live
Network action was run.

## Phase 3C verification observed on 2026-07-12

The following pass on the current Phase 3C worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-types --locked
cargo test -p vibescan-supabase --features network --locked
cargo test -p vibescan-report --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
bash scripts/check-network-boundary.sh
git diff --check
```

The two unfiltered workspace commands were also run. In both default and
`network` modes, they stop only at the same three pre-existing Phase 5
CLI/baseline regressions named above; no Phase 3C test failed. No live Network
action was run.

## Phase 3B verification observed on 2026-07-12

The following pass on the current Phase 3B worktree:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo test -p vibescan-core --locked
cargo test -p vibescan-core --features network --locked
cargo test --workspace --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
cargo test --workspace --features network --locked -- \
  --skip absent_cli_scope_flags_preserve_toml_values \
  --skip missing_explicit_baseline_is_an_operational_error \
  --skip missing_configured_baseline_is_an_operational_error
bash scripts/check-network-boundary.sh
git diff --check
```

No live Network action was run. The remaining deliberate reds are exactly the
three Phase 5 CLI/baseline cases.

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
Phase 3B table-scope cases and three Phase 5 CLI/baseline cases.

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
remaining failures are exactly the three Phase 5 CLI/baseline cases and two
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
| Design invariants | Partial / safety core verified | LocalStatic default, own-Supabase URL guard, read-only Tier 0, redacted per-action scope evidence, and no persisted writes are implemented. |
| Seven-crate workspace | Phase 4 complete | The exact authoritative DAG holds across normal, build, dev, target, optional, and feature-activated dependencies. Cross-crate integration coverage lives in core, CLI depends only on core, and synthetic checker controls reject horizontal/direct drift and transport leakage. |
| Shared data model | Phase 1 identity complete | `ContentId`, `UnitLocation`, `ScannableUnit.locations`, and `UnitRef.locations` form one canonical occurrence model; singular competing fields were removed. |
| Content handling | Substantially implemented | Binary/size skips, ignore layers, forced real-env/client-bundle scanning, inline allow, and commit allowlists exist. Historical paths intentionally use current ignore state. |
| Scan pipeline | Partial | All five phases exist and exact `ContentId` lookup now binds enrichment to the candidate revision. Units/candidates/findings remain materialized rather than streamed. |
| Location classification | Verified for covered Tier C and Phase 1 cases | Whole-segment monorepo matching, server-first precedence, substring controls, and identical-content server/browser occurrence retention are tested. |
| Generic secret substrate | Phase 5 application contract verified | Keyword prefilter, regex, entropy, allowlists, attribution, and required provider families exist. Repository-configured custom rules now append to embedded rules/allowlists; duplicate IDs are rejected and mandatory defaults remain active. |
| Git walker | Partial | Discovery, all refs, budgets, changed blobs, working tree, edge warnings, and full SHA-256 `ContentId` grouping exist. Cross-path locations/classes and same-path provenance are retained deterministically; output remains a `Vec`, not a stream. |
| Supabase key classification | Partial | New/legacy classes, exact-revision project extraction, and conservative same-fingerprint project enrichment exist. Initial new-format project discovery remains same-unit only, and no user-supplied project/key pair exists. |
| Tier 0 RLS probe | Partial, Phase 3C verified | Feature/runtime gating, `apikey`, URL restriction, GET-only probing, no row retention, precise root fallback, typed references, exact/unambiguous project-scoped table sets, and one redacted scope record per attempted GET are tested. |
| Tier 1 RLS introspection | Tier E E1–E3 complete | The env-only rustls catalog path emits `Confirmed` Critical RLS-disabled/literal-true findings, a Medium default-deny missing-operation advisory, and High inferred-write findings with catalog-native evidence. The two read-exposure shapes drive same-project rule 1, all Tier 1 RLS findings participate in rule 2, and both mock fixtures are live under `network`; architecture §17.8 defers the metadata-keyed `Review` heuristic. |
| Correlation | Phase 2 + Tier E3 verified | Both declarative v1 rules honor primary/additional commit provenance, compare normalized projects, and produce deterministic unique location/related unions. Rule 1 accepts only evidence that proves reads; rule 2 includes both RLS evidence shapes. |
| Dependency integrity | v1 §11.0 complete; Registry deferred | Offline npm/Python structural checks exist. Registry existence, newcomer heuristics, and OSV/advisory checks remain post-v1; architecture §§11.1–11.2 now resolve their separate consent, privacy, caching, failure, mechanism, and ownership contract. |
| Reporting | Verified for current v1 | JSON, SARIF, TTY, and HTML include redacted findings and Network action scope evidence, locations, history context, collection/dedup counters, a derived dedup ratio, exit gates, and deterministic snapshots. A full-pipeline integration test proves raw candidate material reaches neither any renderer nor serialized `ScanResult`; §17.3 permits no full-match mode. Protected actions do not affect finding statistics or gates. |
| CLI/config | Phase 5 complete | LocalStatic precedence is defaults < repository TOML < explicitly supplied CLI values, with paired scope flags. CLI/config baseline and custom-rule paths are repository-root-relative unless absolute; named missing files exit 2; real baselines suppress findings. Repository config alone cannot enable Network work. |
| Security/nonfunctional | Partial | Pure-Rust/default transport boundary is enforced. Tier D3 now records deterministic collection/dedup counters and non-gated wall time. No static cross-platform build matrix, npm wrapper, or Homebrew path exists. |
| Testing strategy | v1 closeout + Tier E complete | Exact goldens, clean control, report snapshots, boundary checks, mocked Tier 0/Tier 1 correlation fixtures, the Tier D1 scripted real-repository invariant/CI path, the committed live-corpus metrics baseline, the Tier D3 deterministic performance-counter gate, and the Tier D4 end-to-end redaction pin exist. AstroScout supplied the first genuine D1 coverage record (100.00%, 3 findings, 1 project); the Tier E3 corpus records 1.0 precision, 1.0 recall, and 0.75 classification coverage over 13 live findings; D3 gates 40 blobs, 30 unique contents, 30 units, and 25.00% dedup. Only the registry-backed architecture case remains gated in the network matrix. |
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
Tier D1 has one explicit local real-repository coverage record, Tier D2 has a
committed live-corpus metrics baseline, Tier D3 has the deterministic counter
gate, and Tier D4 pins the resolved architecture decisions. Architecture §15
step 9 is therefore complete. The private CI fixture remains optional and
secret-gated.

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

1. **Literal crate DAG — resolved in Phase 4.** Cross-crate integration tests
   now live in core, sibling dev-dependencies and the CLI-to-types edge are
   removed, and the checker validates every declared dependency kind plus both
   resolved feature graphs.

2. **CLI/config precedence — resolved in Phase 5.** LocalStatic clap values are
   applied only when explicit, paired scope flags override both directions, and
   repository Network configuration remains inert without runtime confirmation.

3. **Baseline/custom-rules paths — resolved in Phase 5.** Relative paths use
   the discovered repository root, absolute paths are preserved, missing named
   files fail operationally, and custom rules append without replacing embedded
   rules or safety allowlists.

4. Project-scoped table harvesting — resolved in Phase 3B. Exact `ContentId`
   association wins; otherwise deterministic app/package scope is used only
   when it resolves to one project. Missing/ambiguous tables are skipped with a
   coverage warning, and RPC references never become table reads.

5. **Tier 0 protected-action auditability — resolved in Phase 3C.** Every
   attempted root/table GET now produces redacted scope evidence even when no
   finding is emitted.

### P2 — assurance and product-depth gaps

- Tier D3 now provides the required deterministic counter gate and records wall
  time without asserting it. Longer-term timing trends and peak-memory growth
  for the materialized pipeline are not yet tracked.
- History-only remediation is present in general terms but should be tested for
  the architecture's explicit rewrite/force-push guidance.
- The default ruleset is deliberately conservative; provider precision and
  corpus licensing/attribution should receive a durable audit artifact before
  broad expansion.
- README documents the basic test and boundary commands, not the complete
  closeout matrix. `verify-hardening-checks.sh` now owns the default/offline and
  optional real-repository D1 legs, but it still omits fmt, clippy,
  network-feature workspace tests, and diff checks; it must not be treated as
  the full gate.

## Resolved architecture decisions

The former architecture ambiguities are resolved in architecture §17
(2026-07-13; §17.3 finalized 2026-07-18). The implementation follows those
decisions, including redaction in every output format.

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

### Completed in Phase 4 — enforce the complete crate DAG

Cross-crate classifier/walker integration coverage now lives in core. The
sibling dev-dependencies and CLI-to-types edge are gone. The boundary checker
validates the exact workspace membership and edge set across every declared
dependency kind and both feature graphs while preserving separate transport
reachability assertions. Synthetic controls prove rejection of a sibling
dev-dependency, an unauthorized direct/optional edge, and LocalStatic transport
leakage.

### Completed in Phase 5 — make configuration truthful end to end

LocalStatic CLI overrides are explicit and paired where booleans require both
directions. Repository configuration sits between built-in defaults and
explicit CLI values. Relative baseline/custom-rule paths resolve from the
repository root; named missing files fail with exit 2; synthetic real baselines
suppress findings. Custom rules append to embedded defaults and duplicate IDs
are rejected. Repository configuration alone cannot confirm Network work.

### Completed in Phase 3C — Tier 0 observability without broader authority

Structured records now cover root enumeration/unavailability, exposed,
protected/empty, not-found, key-rejected, invalid-response, and transport-error
attempts. They record GET intent, normalized endpoint, optional table, status
when present, outcome, and an exposure-only row count. Mock tests prove that
keys, headers, response bodies, and rows are absent. Network failure remains
nonfatal, and no writes, arbitrary URLs, live CI, or registry egress were added.
Tier E1 subsequently added a separately gated catalog transport without changing
Tier 0 behavior.

### Next — continue measured assurance

1. **Tier D2 complete:** the deterministic live-corpus harness publishes a
   committed machine-readable baseline with corpus version, per-fixture counts,
   TP/FP/FN, precision, recall, and classification coverage. Clean-control FP
   and precision/recall regression checks are hard gates even during baseline
   regeneration.
2. **Tier D3 complete:** the generated fixture gates exact paths, blobs, unique
   contents, materialized units, truncation, and the derived dedup ratio while
   recording but never gating `duration_ms`.
3. **Tier D4 complete:** every output format and serialized `ScanResult` is
   pinned to redacted evidence; §17 status debt is retired; gated fixtures name
   their actual capability. The `src/api/` classification remains unchanged
   pending stronger real-repository evidence.
4. Add a canonical full-verification script or prominently document the exact
   root `AGENTS.md` matrix. Keep Tier D1's real-repository leg separate and
   explicitly fixture/Network-gated.
5. Extend CI only with deterministic offline checks.

### Deferred post-v1 tracks — require separate instruction sets

- Registry existence/newcomer/OSV checks: architecture §§11.1–11.2 resolve the
  contract and mechanism; implementation remains a post-v1 track with its own
  crate/feature work and verification instructions.
- Tier 1 introspection/policy analysis: E1 transport/input, E2's four
  mechanically decidable findings, and E3 correlation/fixtures are complete.
  Architecture §17.8 defers the metadata-keyed `Review` heuristic outside the
  confirmed set.
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
cargo test -p vibescan-core --test precision_recall --locked
cargo test -p vibescan-report --test report_snapshots --locked
bash scripts/check-network-boundary.sh
git diff --check
```

Use `UPDATE_GOLDEN=1` or `UPDATE_METRICS=1` only after an intentional result
change, inspect every artifact diff, then rerun without it. The D2 clean-control
and no-decrease precision/recall gates remain active during metrics updates. Do
not claim completion from this file's historical results; rerun the commands on
the current checkout.
