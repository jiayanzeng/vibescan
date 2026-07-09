# vibescan v1 — Hardening & Fix Instructions for Codex

These instructions correct deviations from `vibescan-architecture.md` found in review, fix the
false positive and false negatives observed in the trial run, and resolve the git-reads caveat.
Work top-down: **P0** items are correctness/safety (they cause missed real secrets or break a hard
invariant), **P1** are precision and spec conformance, **P2** are performance and hygiene.

## Ground rules (do not violate)

1. **Keep every existing test green.** Run `cargo test --workspace` after each task.
2. **Do not introduce any network crate into a LocalStatic crate** (`types`, `git`, `secrets`,
   `supabase`, `report`, `core`). If you add a dependency, confirm with `cargo tree` that no
   transport crate (reqwest/hyper/tokio/ureq/openssl/rustls/…) appears. Task P1-7 adds an automated
   check for exactly this.
3. **Preserve public contracts** (`WalkOutput`, `ScannableUnit`, `ScanResult`, `Finding`, CLI flags)
   unless a task explicitly changes them.
4. Add a regression test for every behavioral fix, in the crate that owns the behavior.

---

## P0-1 — Correct `.gitignore` / `.vibescanignore` semantics (keystone fix)

**Why:** The observed `.next/` false positive and the substring over-suppression both trace to the
hand-rolled matcher. Spec §5 requires honoring `.gitignore`; the current implementation reads only
the *repo-root* file, matches by substring, and ignores nested `.gitignore`, negation (`!`), and
anchoring. Honoring nested ignores alone would have excluded all of `dashboard/.next/**` in the
trial and removed the false positive.

**Files:** `crates/vibescan-git/src/lib.rs`, `crates/vibescan-core/src/lib.rs`,
`crates/vibescan-git/Cargo.toml`.

**Change:**
- Add the `ignore` crate (BurntSushi / ripgrep's walker — pure Rust, no network) to
  `vibescan-git`.
- Replace the manual `fs::read_dir` recursion in `collect_working_tree` / `walk_dir` with
  `ignore::WalkBuilder`, which applies nested `.gitignore`, `.ignore`, and global gitignore with
  correct semantics. Register `.vibescanignore` via `add_custom_ignore_filename(".vibescanignore")`.
- Delete `path_pattern_matches` and `should_skip_path`'s substring logic from `vibescan-git`, and
  delete `apply_path_allowlists` + `path_pattern_matches` from `vibescan-core`. Ignore handling now
  lives in one place (the walker). Config-level `path_allowlists` become extra override patterns fed
  to the walker (see P0-3), not a second post-filter.
- For **history** scanning (`collect_history` reads git objects, not the filesystem, so the walker
  doesn't apply): build one `ignore::gitignore::Gitignore` matcher from the repo's ignore files up
  front and test each historical path against it plus the P0-3 overrides. Note in a code comment
  that historical paths are matched against *current* ignore rules (a documented approximation).
- Remove `.vibescanignore` line-parsing from `read_ignore_patterns` in core; the walker consumes the
  file directly. `ScanConfig::load` should stop reading `.gitignore`/`.vibescanignore` itself.

**Acceptance:**
- A nested `dashboard/.gitignore` containing `.next/` excludes `dashboard/.next/**`.
- A `.gitignore` entry `dist` does **not** suppress `src/redistribute.ts` or `src/lib/distance.ts`.
- A negation entry (`build/` then `!build/keep.txt`) scans `build/keep.txt`.
- Existing `gitignore_suppresses_matching_paths` and `vibescanignore_suppresses_matching_paths`
  tests still pass.

## P0-2 — `.env` carve-out and shipped-bundle overrides (fix false negatives)

**Why:** Two spec requirements collide, and the current code resolves the collision the wrong way.
Spec §10.1 says a secret key in a **gitignored** `.env` must still be flagged ("it's in the tree").
Spec §6.2 says shipped client bundles (`dist/`, `build/`, `.next/static/`) are `ClientReachable` and
worth scanning. But those dirs and `.env` are exactly what real projects gitignore — so blindly
honoring gitignore (P0-1) would hide the most important targets. Resolve with an explicit override
layer that takes precedence over gitignore.

**Files:** `crates/vibescan-git/src/lib.rs`.

**Change:** Using `ignore::overrides::OverrideBuilder` (applied in both the working-tree walk and the
history matcher), implement a three-layer policy:

- **Always scan (override ignore):** `.env` and `.env.*` **except** `.env.example` / `.env.sample`;
  and shipped client-bundle roots `dist/`, `build/`, `out/`, `.next/static/`.
- **Always skip (regardless of gitignore):** dependency and cache/vendored code —
  `**/node_modules/**`, `**/vendor-chunks/**`, `**/.next/cache/**`, `**/.next/server/**`,
  `**/__pycache__/**`, `**/*.pyc`, `**/.DS_Store`, `**/.turbo/**`, `**/coverage/**`, `.git/**`,
  `target/**`.
- **Everything else:** honor `.gitignore` / `.vibescanignore` (P0-1).

Keep `.env.example` / `.env.sample` / `*.example` / `*.sample` skipped as before.

**Acceptance:**
- A gitignored root `.env` containing `sb_secret_…` produces a High/Critical finding.
- `dashboard/.next/server/vendor-chunks/prop-types.js` (the trial false positive) is **not**
  scanned; `dashboard/.next/static/**` still is.
- `.env.example` produces no finding.

## P0-3 — Feed config `path_allowlists` through the override layer

**Why:** Config-level allowlists (spec §5) must compose with the new ignore/override machinery
rather than being a separate broken matcher.

**Files:** `crates/vibescan-core/src/lib.rs`, `crates/vibescan-git/src/lib.rs`.

**Change:** Pass `config.path_allowlists` into `WalkOptions` (already present) and add them to the
`OverrideBuilder` as ignore patterns (lower precedence than the P0-2 always-scan set, so a user
allowlist can never hide `.env`). Remove the now-dead second-pass filter in core.

**Acceptance:** A `vibescan.toml` `[ignore] paths=["docs/**"]` suppresses `docs/**` but a
`paths=["**"]` still does **not** hide `.env`.

## P0-4 — Remove the runtime dependency on the `git` executable

**Why:** `vibescan-git` shells out to `git` for `rev-list`/`show`/`diff-tree`/`ls-tree`. This keeps
the dependency tree network-free but breaks the §13.1 hard invariant ("single static binary, no
runtime helper") — the binary now needs `git` on `PATH` — and adds real costs: parsing `git` stdout
is locale/`core.quotePath`-sensitive (non-ASCII paths in `--name-only` can break), and it spawns one
process per blob/commit (O(commits × files)), which scales poorly.

**Primary change (recommended): migrate object/history reads to `gix` in-process.**
- Add the top-level `gix` crate with **pure-Rust features only** (no `blocking-http-transport-*` or
  other network features). Pin the `gix` version whose bundled `gix-discover` matches the workspace's
  existing `0.52` line so you don't get two `gix-discover` versions; keep `default-features = false`
  and enable a local feature set (e.g. `max-performance-safe`).
- Reimplement, preserving the exact existing behavior and `WalkOutput` contract:
  - all-refs commit enumeration (replaces `rev-list --all --date-order`),
  - the commit budget + `max_commits + 1` truncation detection + `HistoryBudgetHit` warning,
  - first-parent diff for merges + `MergeCommitFirstParentOnly` warning,
  - changed-blob collection (`AM` filter) via tree diff,
  - `160000` submodule entries → `SubmoduleSkipped`,
  - blob byte reads via the object DB (replaces `git show sha:path`),
  - working-tree emission + content-hash dedup + `additional_provenance`.
- Delete `git_output`, `git_output_bytes`, and the `Command::new("git")` calls from
  `crates/vibescan-git/src/lib.rs` (test helpers may keep using the `git` CLI to *build* fixtures).
- Confirm via `cargo tree` that no network feature of `gix` was enabled (P1-7 will assert this).

**Alternative (only if you must ship before the migration): harden the subprocess path.**
If P0-4-primary is deferred, instead: check for `git` on startup and fail fast with a clear message;
and make output deterministic by invoking git with `-z` (NUL-delimited names), `-c
core.quotePath=false`, env `LC_ALL=C`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`; parse
NUL-delimited output. Document the `git` runtime dependency in the README and CLI `long_about`.
**Mark this as tech debt** — the gix migration remains required before broad `npx` distribution.

**Acceptance (primary):** history tests (`history_scan_collects_changed_blobs_from_all_refs`,
`history_budget_sets_scope_warning`) pass unchanged; the binary runs on a `PATH` with no `git`;
`cargo tree` shows no network crate.

---

## P1-5 — Calibrate generic-secret confidence and guard minified files (fix FP severity)

**Why:** `resolve_generic_candidates` emits **every** non-Supabase candidate at `High` / `Likely`.
The trial false positive was a generic-high-entropy hit surfaced as High, which under the default
`--severity-gate high` would fail CI on noise. Minified/bundled code is the main source of entropy
false positives.

**Files:** `crates/vibescan-core/src/lib.rs` (`generic_candidate_finding`),
`crates/vibescan-secrets/src/lib.rs`.

**Change:**
- Severity/confidence by candidate kind in `generic_candidate_finding`:
  `GenericHighEntropy` → `Medium` severity, `Review` confidence; `PrivateKey` and specific
  `ProviderSecret` prefixes (Stripe/AWS/GitHub/OpenAI/Anthropic) stay `High` / `Likely`.
- Add a minified-line guard in `vibescan-secrets`: for the `generic_high_entropy` kind only, skip
  matches on lines longer than a threshold (e.g. 500 chars) or in files that are effectively a
  single very long line. Keep provider-prefix rules active in such files (a real Stripe key in a
  shipped bundle should still fire).

**Acceptance:** the `prop-types.js`-style hit (long minified line, generic-entropy) produces no
finding; a genuine `sk_live_…` in a bundled file still fires at High.

## P1-6 — Fix dependency-integrity evidence and reasons

**Why:** `dependency_finding` always sets `DependencyIntegrityReason::NonexistentPackage` even for
"invalid name" or "empty version", mislabeling evidence. Spec §11 differentiates reasons/severities.
Offline structural-only checks are acceptable for the free tier, but the labels must be honest.

**Files:** `crates/vibescan-core/src/lib.rs`.

**Change:** Thread the real reason through to `Evidence::Dependency.reason`
(invalid-name / empty-version → an appropriate variant; keep `NonexistentPackage` only for genuine
nonexistence, which requires the deferred registry lookup). Keep severity `High` for structural
faults; leave registry/OSV/typosquat and Python-manifest parsing as documented deferred work
(comment referencing §11). Optionally add offline typosquat detection (edit-distance to a small
bundled list of popular packages) as `SuspiciousNewcomer` / `Medium` / `Review`.

**Acceptance:** `dependency_integrity_flags_invalid_package_names` still passes; the emitted
evidence's `reason` matches the detected fault.

## P1-7 — Add the LocalStatic network-boundary assertion (spec §13.3 / §14)

**Why:** The boundary currently holds only by manual `cargo tree`. Spec requires an automated check.

**Change:** Add a workspace test (or CI job) that parses `cargo metadata` and fails if any of
`types`, `git`, `secrets`, `supabase`, `report`, `core` has a transitive dependency on a known
network/transport crate (maintain a denylist: reqwest, hyper, tokio, ureq, isahc, curl, openssl,
native-tls, rustls, and gix's http transport crates). Run it in CI.

**Acceptance:** the test passes today and fails if someone enables a `gix` network feature or adds
`reqwest` to a LocalStatic crate.

## P1-8 — Add a precision/clean-control test and fixture corpus (spec §14)

**Why:** A "clean repo → zero findings" test would have caught the trial false positive.

**Change:** Add (a) a clean control fixture that must yield zero findings, and (b) golden fixtures
asserting exact findings/severities for: an elevated key committed then removed (history-only), a
gitignored `.env` with a secret key (must flag), a `.next/`-style build tree (must be clean after
P0), and a hallucinated/invalid dependency.

**Acceptance:** all fixtures assert their expected finding sets; the clean control yields `[]`.

## P1-9 — Shallow-clone warning (spec §8)

**Why:** `ScopeWarning::ShallowClone` exists and renders but is never emitted, so a shallow clone
under-reports history silently.

**Files:** `crates/vibescan-git/src/lib.rs`.

**Change:** After discovery, detect a shallow repo (presence of `<git_dir>/shallow`, or the gix
equivalent) and push `ScopeWarning::ShallowClone`.

**Acceptance:** a shallow test repo yields the warning.

## P1-10 — Real `started_at` timestamp and honest error message

**Files:** `crates/vibescan-core/src/lib.rs`.

**Change:** Set `started_at` to an RFC3339 UTC timestamp of scan start (use `jiff`, already in the
tree via gix, or format `std::time::SystemTime`) instead of the literal `"local-static"`. Rename the
`CoreError::Json` display text from "baseline JSON parse failed" to a generic "JSON parse failed"
since it also covers `package.json`.

**Acceptance:** `started_at` parses as a timestamp; message no longer misattributes a `package.json`
parse error to the baseline.

## P1-11 — Associate a project with new publishable keys (unblocks correlation rule 1)

**Why:** `sb_publishable_…` keys are opaque and carry no project ref, so
`correlate_exposed_public_key` (§12 rule 1 — the headline Moltbook chain) can never fire for the
modern key format. The project link is derivable locally from a co-located URL.

**Files:** `crates/vibescan-supabase/src/lib.rs` (or a core enrich step).

**Change:** When classifying a `PublishableNew` key, attempt to populate `project` by finding a
`https://<ref>.supabase.co` URL in the same unit/repo and using its `ref`. Leave `project = None` if
none is found. This is LocalStatic and readies the data before step 8 (RLS) lands.

**Acceptance:** a file containing both an `sb_publishable_…` key and a `…supabase.co` URL yields a
`PublishableNew` finding whose `project.url` matches the discovered project.

---

## P2-12 — Performance NFRs (spec §6, §13.2)

**Why:** Detection is single-threaded over a fully materialized `Vec`; §13.2 calls for parallel blob
scanning, and §6 for streaming. The trial run (6.8 s) exceeded the "low single-digit seconds" target,
partly from this and partly from the now-fixed build-artifact churn.

**Change:** Add `rayon` (pure Rust, no network) to `vibescan-secrets` or `core` and parallelize
`detect_units` across units. Replace the full-content `BTreeMap<Vec<u8>, usize>` dedup key in
`vibescan-git` with a content hash key to cut peak memory. Consider bounding peak memory by not
holding every blob's bytes simultaneously.

**Acceptance:** results are identical to the serial path (sort before comparing); a large fixture
scans faster; `cargo tree` still network-free.

## P2-13 — Layering and doc hygiene (low priority)

- The `git → secrets` and `supabase → secrets` **dev-dependency** edges violate the strict
  "these crates never depend on each other" rule in prose (no cycle, tests only). Either move the
  shared test helper into a tiny dev-only fixtures crate / behind `types`, or add a comment
  documenting the accepted test-only exception.
- Reconcile the architecture doc's "six crates" wording with the seven crates actually implemented
  (doc-only edit).

---

## Suggested order & verification

1. P0-1 → P0-2 → P0-3 (ignore/override rework; the biggest precision + false-negative wins).
2. P0-4 (gix migration; the binary-portability invariant).
3. P1-5, P1-6, P1-9, P1-10, P1-11 (precision + conformance).
4. P1-7, P1-8 (lock in the boundary and precision with tests).
5. P2 items last.

After each: `cargo test --workspace`, then `cargo tree --workspace --edges normal` to confirm no
network crate entered any LocalStatic crate. Re-run the tool against a real Next.js/Supabase repo and
confirm the clean tree produces zero findings and a planted gitignored `.env` secret is flagged.
