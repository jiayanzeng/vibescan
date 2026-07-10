# vibescan — Codex Instructions: Tier C (post-A1/B3)

Reviewed: 2026-07-10
Author: architecture review (Claude), for implementation by Codex

## How to consume this document

Three dependency-ordered tasks that close the gaps the `astroscout` real-repo
scan exposed after Tier A1 + Tier B3 landed. Each is self-contained: spec basis,
root-caused problem with file evidence, file targets, implementation guidance,
and self-verifiable acceptance criteria. As before, the authority is
`vibescan-architecture.md`, **not** `STATE.md`. Two of these tasks cite
*refined* section text — apply `vibescan-architecture-refinements.md` to the
architecture doc first (that patch is the authority for §6.2, §7.1, §10.2, and
the §12 rule‑1 note). If an implementation choice conflicts with a cited
section, the section wins; surface the conflict rather than diverge.

Build order (respect it — C1 unblocks the correlation predicate C2/C3 rely on):

1. **C1 — Monorepo-aware location classification** (P1; §6.2; unblocks §12 rule 1)
2. **C2 — Coalesce same-secret findings; dedup Tier 0 probe per project** (P2; §4, §8, §6.6)
3. **C3 — Tier 0 probe: apikey header + LocalStatic table enumeration** (P1; refined §7.1, §10.2)

Assume a committed `Cargo.lock`; all CI jobs run `--locked` (Task A1 is in
place). Do not weaken or delete existing tests; Tier C is additive except where
a golden manifest must be regenerated with `UPDATE_GOLDEN=1` (called out below).

---

## Task C1 — Monorepo-aware location classification

### Spec basis

- **Refined §6.2:** `LocationClass` is derived by **segment-boundary** path
  matching that holds at any nesting depth, with server signals overriding the
  client roots they can nest inside. Root-anchored `starts_with` and raw
  substring matching are both defects.
- **§12 rule 1:** the exposed-public-key chain fires only when a low-privilege
  key finding is `ClientReachable` (or committed). Classification is a hard
  dependency of the product's headline output.
- **Memory of the codebase:** substring/anchoring path bugs are a recurring
  pattern here; the ignore layer was already corrected to segment matching — the
  classifier is the site that was missed.

### Problem (root-caused)

`crates/vibescan-git/src/lib.rs::classify_location` (currently ~L621–646) tests
the path with root-anchored `starts_with`:

```rust
if lower.starts_with("public/") || … || lower.starts_with(".next/static/") { ClientReachable }
else if lower.starts_with(".env") || … || lower.starts_with("api/") { ServerOnly }
else { Unknown }
```

On the `astroscout` scan every finding came back `location_class: unknown`:

- `apps/web/.next/static/chunks/35xdx82k766q8.js` → `Unknown` (must be
  **`ClientReachable`** — it is browser-shipped and holds the publishable key).
- `apps/api/.env` and `apps/web/.env.local` → `Unknown` (must be
  **`ServerOnly`**).

Because the anchors are relative to the repo root, nothing nested under
`apps/*` / `packages/*` / `services/*` matches. The ignore layer already scans
these paths correctly (`shipped_static_bundle_is_scanned…` passes), so the
scanner *reads* `apps/web/.next/static/...` but then *mislabels* it — the two
path layers are inconsistent. Downstream, §12 rule 1 can never fire for a
bundle key in a monorepo, silently disabling the Moltbook chain end-to-end.

### File targets

- **Edit:** `crates/vibescan-git/src/lib.rs` — rewrite `classify_location`.
- **Reuse/extend:** if the ignore layer exposes a segment-boundary matcher,
  route classification through the same helper (single source of truth for
  "does this path contain segment sequence X"). If not, add a small private
  `fn path_has_segments(path, &[&str]) -> bool` and a `fn basename_is_env(path)`
  and use them in both places, or leave a `TODO` to unify in a follow-up.
- **New fixture:** `tests/fixtures/monorepo-layout/` (see C1 acceptance #5) — or
  extend `vendor-chunks-noise` — with an `expected.json` asserting the
  `ClientReachable` bundle classification.

### Implementation guidance

Split the path into `/`-delimited segments and match **whole segments** at any
depth. Evaluate in the order below (first match wins) so server signals win over
the client roots they nest inside:

1. `ServerOnly` if:
   - the final segment is `.env` or matches `.env.*` (basename check); or
   - segments contain `api/` **immediately under** an app/pages root
     (`app/api`, `pages/api`, `src/app/api`, `src/pages/api`); or
   - segments contain any of `server`, `.next/server`, `supabase/functions`,
     or a package-level `api` / `src/api` server root.
2. `ClientReachable` if segments contain any of `public`, `app`, `pages`,
   `src/app`, `src/pages`, `src/components`, `dist`, `build`, `out`,
   `.next/static`, `.svelte-kit`, a `client` segment, or a `.client.` infix in
   the basename.
3. else `Unknown`.

Lowercase for comparison as today. Keep the `.env.example`/`.env.sample`
allowlist in §5 (they never reach the classifier). Multi-segment keys like
`.next/static` and `app/api` must match as a **contiguous** segment pair, not as
two independent segments (so `app/foo/api` is not `app/api`).

### Acceptance criteria (self-verifiable)

1. Unit tests (`vibescan-git`) assert exactly:
   - `apps/web/.next/static/chunks/x.js` → `ClientReachable`
   - `apps/api/.env` → `ServerOnly`; `apps/web/.env.local` → `ServerOnly`
   - `packages/ui/src/components/Btn.tsx` → `ClientReachable`
   - `services/api/src/api/handler.ts` → `ServerOnly`
   - `apps/web/app/api/route.ts` → `ServerOnly` (not `ClientReachable`)
   - `apps/web/app/page.tsx` → `ClientReachable`
   - `apps/web/.next/server/vendor-chunks/x.js` → `ServerOnly` (belt-and-
     suspenders even though §5 skips it)
2. **Segment, not substring — negative controls:** `staticassets/x.js` does
   **not** classify as `ClientReachable`; a file whose basename is `myenv.ts`
   does **not** classify as `ServerOnly`; `apps/foo/api-docs/readme.md` does
   **not** trip the `api/` server rule.
3. Flat-repo behavior is unchanged: the existing classification tests still pass
   verbatim.
4. `cargo test --workspace` and `--features network` both green; `cargo fmt`
   and `clippy -D warnings` clean.
5. New/extended golden fixture asserts a publishable key under
   `.../.next/static/...` is classified `ClientReachable`, and — paired with a
   synthetic RLS `Exposed` finding on the same project via the existing
   engine-level composite harness — the §12 rule‑1 Critical composite fires.
   Regenerate manifests with `UPDATE_GOLDEN=1` and confirm they contain no
   absolute paths/timestamps.

---

## Task C2 — Coalesce same-secret findings; dedup Tier 0 probe per project

### Spec basis

- **§4:** a `Finding` carries a `Location` and "correlated findings may have
  several locations" — one logical secret is one finding with multiple
  locations, not N findings.
- **§8 dedup contract:** identical content collapses to one scanned unit
  carrying the set of provenances (first-seen/last-seen). The same secret across
  different paths is the analogous finding-level collapse.
- **§6.6 finalize:** dedup + stable ordering precede reporting.

### Problem (root-caused)

Two defects, both visible in the `astroscout` output:

1. **Duplicate findings for one key.** The publishable key
   `sb_pub…2CgS` (fingerprint `7e024d85…`) reports **twice** —
   `apps/web/.next/static/chunks/35xdx82k766q8.js:59` and
   `apps/web/.env.local:6` — as two separate Info findings with different ids
   (`supabase-key-369cfb…` vs `…855b56…`). `finding.id` embeds `location.path`
   (`generic_candidate_finding` hashes `location.path.0`; the supabase key
   finding id is analogous), and `dedup_findings` dedups by exact id only, so
   the two survive. The run reports "5 findings" for what is 4 distinct secrets.
2. **Probe runs per finding, not per project.** `tier0_probe_inputs`
   (`vibescan-core/src/lib.rs` ~L487) maps one `Tier0RlsProbeInput` per
   publishable/anon finding with no dedup on `project.url`. With two publishable
   findings for one project, the Tier 0 probe fired **twice** and emitted the
   identical `HTTP 401` warning twice.

### File targets

- **Edit:** `crates/vibescan-core/src/lib.rs`
  - add a coalescing pass in finalize (before correlation, so the correlated
    finding sees the merged, most-client-reachable key);
  - dedup `tier0_probe_inputs` by normalized `project.url`.
- Golden manifests will change (stable keys shift when locations merge):
  regenerate with `UPDATE_GOLDEN=1`.

### Implementation guidance

**Coalescing (conservative).** Merge two findings only when they share
`(category, rule_id-or-key-class, fingerprint, project_url, severity)`. On
merge: union the `locations` (sorted by path, then span) into one finding;
carry `location_class = max client-reachability` across locations
(`ClientReachable > ServerOnly > Unknown`); preserve per-location provenance
(do not flatten history). Derive the merged `finding.id`/stable key from the
path-independent parts (`rule_id`/class + fingerprint + project), **not** a
single path, so the id is stable regardless of which locations were found — this
is the §4-aligned stable key and it removes the path dependency that caused the
split. Do **not** merge across different fingerprints or different projects.
Leave §8's existing across-commits unit dedup intact; this is an additional,
finding-level, across-paths merge.

**Probe dedup.** Key `tier0_probe_inputs` output on normalized `project.url`
(lowercase host, strip trailing slash). Pick a representative input,
**preferring a location whose class is `ClientReachable`**, so the probe and any
resulting correlation reference the browser-exposed copy. One probe per unique
project.

### Acceptance criteria (self-verifiable)

1. A fixture/unit case with the same secret value at two paths yields **one**
   finding with two sorted locations; the total finding count drops accordingly.
2. The coalesced finding's `location_class` is `ClientReachable` when any
   constituent location is client-reachable (regression guard for §12 rule 1).
3. Coalescing never merges: (a) two different secrets sharing a path, (b) the
   same secret across two different project URLs — assert both as negatives.
4. `tier0_probe_inputs` returns exactly one input per unique project URL;
   feeding two same-project publishable findings produces a single probe and a
   single warning (assert on the produced input set, hermetically — no network).
5. Golden manifests regenerated and still free of absolute paths/timestamps/
   `tool_version`/`duration`; `golden_corpus_is_deterministic_across_runs` still
   passes.
6. All existing tests pass; `clippy -D warnings` clean under default + network.

---

## Task C3 — Tier 0 probe: `apikey` header + LocalStatic table enumeration

### Spec basis

- **Refined §7.1:** Tier 0 sends the public key in the **`apikey`** header (new
  keys are opaque, not JWTs; `Authorization: Bearer` alone is rejected), and
  derives candidate tables from a **LocalStatic** harvest of the bundle/source
  rather than the OpenAPI root (admin-gated; 403 for public keys under the
  current key model).
- **Refined §10.2:** enumeration source revised; warnings must distinguish
  401 / 403-root / no-candidates / protected.
- **§1, §7 invariants:** read-only, own-assets-only, redacted reproduction
  (endpoint + row count, never rows).

### Problem (root-caused)

`--features network … --rls-tier0-read-probe` on `astroscout` produced, twice:

```
Tier 0 RLS read probe failed …: RLS probe OpenAPI enumeration failed for
https://qwynjzgfztcknoetjbly.supabase.co/rest/v1/: HTTP 401
```

Two layered causes:

1. **401 (authentication).** Current Supabase requires the public key in the
   `apikey` header; opaque `sb_publishable_*` keys sent only as
   `Authorization: Bearer …` are rejected → 401. Confirm the probe sets
   `apikey` on **every** request.
2. **Enumeration strategy obsolete.** Even with a correct `apikey`, the
   PostgREST OpenAPI **root** `/rest/v1/` requires an admin-level key and
   returns **403** for publishable/anon keys under the new model. The current
   "enumerate from the OpenAPI description using the public key" cannot work at
   Tier 0. (The double warning is downstream of the C2 probe-dedup bug.)

### File targets

- **Edit:** `crates/vibescan-supabase/src/lib.rs` — `probe_tier0_read`: header
  construction; enumeration/fallback; warning taxonomy; per-table read.
- **Edit:** `crates/vibescan-core/src/lib.rs` — add a LocalStatic table-name
  harvester over the already-collected `ScannableUnit`s and thread the harvested
  candidates into `Tier0RlsProbeInput` (extend the input shape).
- **Tests:** a mocked PostgREST surface (no live services) under
  `vibescan-supabase` tests and/or the gated golden network fixtures.

### Implementation guidance

**Headers.** Set `apikey: <public_key>` on every request. Do not send the key
solely as `Authorization: Bearer`. (Sending it as `Bearer` in addition is
tolerated only if it exactly equals the `apikey` value; the `apikey` header is
the contract.) Keep the existing `refuses_non_supabase_urls` guard.

**Enumeration.** Add `fn harvest_table_names(units) -> BTreeSet<String>` that
extracts identifiers from the collected LocalStatic content: `supabase.from('X')`
/ `.from("X")`, `.rpc('fn')`, and literal `/rest/v1/<X>` path references. Feed
this set as the probe's candidate list. Attempt the OpenAPI root **best-effort**
only; on 401/403 there, do not abort — fall back to the harvested list and note
"root enumeration unavailable with public key." Probe each candidate with
`GET /rest/v1/<table>?select=*&limit=1`; rows ⇒ `Exposed` ⇒ Critical `Rls`
finding with reproduction (endpoint + observed row count, never rows); no rows /
`404` / filtered ⇒ `Protected` (no finding).

**Warning taxonomy (no conflation).** Distinct scope warnings for:
key-rejected (401), root-enumeration-forbidden (403 — informational, probe
continues on harvested list), no-candidate-tables (nothing to probe), and
transport/other errors. Keep graceful degradation: a probe failure never aborts
the offline findings (as today).

**Note on target variance.** Root-endpoint behavior can differ by deployment;
architect for the harvested-list default and verify the exact `/rest/v1/`
response against the target before relying on it. Do not hard-depend on the
root.

### Acceptance criteria (self-verifiable)

1. Against a **mocked** PostgREST surface (hermetic, no network): every request
   carries an `apikey` header equal to the public key; assert it explicitly.
2. Probing a mock table that returns a row yields one Critical `Rls` `Exposed`
   finding with reproduction metadata (endpoint + row count) and **no** row
   data in the finding; a table that returns `[]` / 404 yields nothing.
3. `harvest_table_names` extracts the table set from a fixture bundle containing
   `supabase.from('profiles')`, `.from("orders")`, `.rpc('do_x')`, and a
   `/rest/v1/widgets` reference; unit-tested independently of the network.
4. A mocked 403 on the OpenAPI root does **not** abort the probe: the probe
   proceeds using harvested names and emits the "root enumeration unavailable"
   note, not a generic failure. A mocked 401 emits the key-rejected warning.
5. Combined with C2, one same-project input set produces exactly one probe pass
   and at most one warning per distinct failure cause.
6. Wire the gated §14 network goldens (`network_rls_off_table_fixture`,
   `network_exposed_public_key_chain_fixture_is_gated`) to the mock and un-gate
   the ones the mock makes deterministic; any still-gated cases keep updated
   `TODO(network)` messages. `cargo test --workspace` (default) is unaffected by
   the gated cases.
7. Boundary invariant intact: `bash scripts/check-network-boundary.sh` still
   passes — transport only under `--features network`, still nearest-parented by
   `vibescan-supabase`.

---

## Completion status this tier closes

For reference, the prior tiers are verified complete against their acceptance
criteria (all workspace tests green; boundary script fixture-free and
feature-aware; golden corpus with drift detection; `started_at` now a live
RFC3339 timestamp). Tier C addresses only the *new* gaps the real-repo scan
surfaced — monorepo classification (C1), same-secret coalescing + probe dedup
(C2), and Tier‑0 probe correctness against the current Supabase key model (C3) —
none of which were exercised by the flat, root-anchored unit fixtures.

## Notes for review

- **C1 is the load-bearing fix.** Until location classification works on nested
  layouts, §12 rule 1 cannot fire for a bundle key in the exact class of repo
  this tool targets (Supabase + Next.js monorepos). It should merge first and be
  the one to scrutinize hardest.
- **C3 depends on an external, current-state API fact** (the `/rest/v1/`
  OpenAPI root is admin-gated; public keys 401 without `apikey` and 403 at the
  root). Verify against the live target during implementation; if the hosted
  platform behaves differently for a given project, keep the harvested-list
  default and treat root enumeration as the optional supplement regardless.
- The gated network goldens from Tier B3 are the natural home for the mocked
  PostgREST surface C3 introduces; landing C3 is what makes those placeholders
  live.
