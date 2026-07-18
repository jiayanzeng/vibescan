# vibescan — Codex Instructions: Tier E (Tier 1 credentialed introspection)

Reviewed: 2026-07-18
Author: architecture review (Claude), for implementation by Codex

## How to consume this document

This is the first **post-v1** capability track (see `vibescan-postv1-roadmap.md`).
It implements architecture **§7.2 Tier 1** — authoritative, credentialed RLS/policy
introspection — and un-gates two of the three remaining corpus fixtures
(`rls-off-table`, `permissive-using-true-policy`). It is the deepest part of the
Supabase moat: Tier 0 (shipped) proves a table is *readable*; Tier 1 proves *why*
RLS is broken, and catches the failures Tier 0 structurally cannot.

Three dependency-ordered tasks, in the house format: spec basis with section
citations, root-caused problem with file evidence, file targets, implementation
guidance, self-verifiable acceptance criteria with negative controls. The
authority is `vibescan-architecture.md`, **not** `STATE.md`. If an implementation
choice conflicts with a cited section, the section wins; surface the conflict
rather than diverge.

Build order (respect it — E3's correlation change is what makes the fixtures fire):

1. **E1 — Credentialed transport, opt-in, and input plumbing** (P1; §7.2, §7.4, §1.2, §13.1)
2. **E2 — The introspection detections + `Evidence::RlsPolicy`** (P1; §7.2, §7.3, §10.2)
3. **E3 — Correlation integration, un-gate fixtures, extend precision/recall** (P1; §12, §14)

Assume a committed `Cargo.lock`; all CI jobs run `--locked`. Tier E is additive
except where the two gated fixtures' `expected.json` are populated and the D2
precision/recall baseline is regenerated under an explicit `UPDATE_*` guard
(called out in E3). Do not weaken or delete an existing test.

---

## E0 — Transport decision (read before starting; one open item flagged for the spec)

§7.2 offers two credential inputs as if interchangeable: "a secret/service_role
key **or** a DB connection string." **They are not interchangeable for the specced
detections**, and this is the one architectural decision Tier E resolves:

- The Tier 1 detections require `rowsecurity` state and per-policy
  `USING`/`WITH CHECK` expressions (§10.2). Those live in `pg_catalog`
  (`pg_class.relrowsecurity`, `pg_policies`) and in `information_schema` (role
  grants). **PostgREST does not expose `pg_catalog` to a service_role key** — a
  service_role key over the REST surface can *read data bypassing RLS*, but cannot
  read the policy definitions the detections are about.
- Therefore **Tier 1 introspection uses the DB-connection-string input over a
  direct Postgres connection.** The service_role/PostgREST path is insufficient
  for policy-expression detection and is out of scope for Tier E (it would only
  duplicate Tier 0's data-readability signal).

**§13.1 single-binary constraint applies to the Postgres client:** it must be a
**sync, pure-Rust, rustls-backed** driver — no OpenSSL, no C toolchain (exactly
as Tier 0 chose blocking `reqwest` + `rustls-tls`). Recommended crate combo:
the sync `postgres` crate with a `rustls`/`tokio-postgres-rustls` TLS connector.
**Verify at build time** that the resolved dependency tree links no OpenSSL and
adds no C-toolchain requirement (the boundary/DAG checks in E1's acceptance cover
this); if the recommended combo has drifted, pick the current pure-Rust
rustls-backed equivalent and record the choice.

> **Spec item to surface (do not silently resolve):** §7.2 lists service_role and
> connection-string as equivalent Tier 1 inputs; per the above they are not, for
> the detections §7.2 itself names. This warrants a one-line §7.2 clarification
> ("Tier 1 policy introspection requires catalog access — the DB connection-string
> path; a service_role key over PostgREST reaches data but not `pg_policies`").
> Flag it in the PR; the architecture owner applies the note. Do not change §7.2
> from within an implementation change.

---

## Task E1 — Credentialed transport, opt-in, and input plumbing

### Spec basis

- **§7.2:** Tier 1 credential is read **from local env** and transmitted **only to
  the user's own Supabase**. `Confirmed` confidence.
- **§7.4:** Tier 0 read and Tier 1 introspection use **key possession as the
  authorization signal** — the ownership gate (DNS TXT / well-known file / OAuth)
  is reserved for *write-probes/DAST*, **not** Tier 1. Do not build an ownership
  gate here.
- **§1.2 (own-assets-only):** reject any host that is not a Supabase-owned DB
  host — the exact analog of Tier 0's `refuses_non_supabase_urls`
  (`InvalidProjectUrl`) guard.
- **§13.1:** sync, pure-Rust, rustls transport (see E0).
- **§3C precedent (shipped):** every Network action is recorded as a redacted
  `NetworkActionAudit` — Tier 1 must be equally auditable.

### Problem (root-caused)

The Tier 0 machinery is the template, and none of its Tier 1 analog exists:

- `crates/vibescan-supabase/src/lib.rs` has `Tier0RlsProbeInput`,
  `Tier0RlsProbeOutput`, `Tier0RlsProbeWarning`, the injectable `RlsHttpClient`
  trait, `probe_tier0_read_with_client(client, input)`, and the real
  `ReqwestRlsHttpClient` (network-gated). There is no `Tier1IntrospectInput`, no
  injectable catalog source, and no introspection entry point.
- `Cargo.toml [features] network = ["dep:reqwest"]` gates the only transport;
  there is no Postgres transport.
- `NetworkActionKind` (types) is `{ RootEnumeration, TableRead }` — REST-shaped;
  there is no `CatalogIntrospection` kind for the audit trail.
- The CLI has `--rls-tier0-read-probe`-style flags but no Tier 1 opt-in, and no
  env-credential read for a DB connection string.

### File targets

- **Edit:** `crates/vibescan-supabase/Cargo.toml` — add the sync rustls Postgres
  dependency under the `network` feature (optional; see E0).
- **Edit:** `crates/vibescan-supabase/src/lib.rs` — add `Tier1IntrospectInput`,
  `Tier1IntrospectOutput`, `Tier1IntrospectWarning` (with `message()`), an
  injectable `PgCatalogSource` trait, `introspect_tier1_with_source(source,
  input)`, and the real `PostgresPgCatalogSource` (network-gated) implementing the
  trait over a direct connection. Add a `refuses_non_supabase_db_host` guard.
- **Edit:** `crates/vibescan-types/src/lib.rs` — add
  `NetworkActionKind::CatalogIntrospection`; if the `NetworkActionAudit` REST
  fields don't fit a catalog query, keep them `Option` and add a `table` /
  normalized-host field as needed (additive; `#[serde(default)]`).
- **Edit:** `crates/vibescan-cli/src/main.rs` + core config — add
  `--rls-tier1-introspect` (distinct from the Tier 0 flag) and read the DB
  connection string **from env only** (e.g. `VIBESCAN_SUPABASE_DB_URL`), never
  from a CLI argument.
- **Edit:** `crates/vibescan-supabase/AGENTS.md` — extend the Tier 0 safety
  contract with a Tier 1 clause (credential from env, own-host-only, read-only
  catalog queries, no row data retained).

### Implementation guidance

**Mirror Tier 0's shapes exactly** so review is mechanical:

```
pub struct Tier1IntrospectInput {
    pub project: SupabaseProject,
    pub db_url: String,              // read from env by the caller, never argv
    pub credential_location: Location,
    pub candidate_tables: BTreeSet<String>, // harvested, project-scoped (§3B)
}
pub struct Tier1IntrospectOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<Tier1IntrospectWarning>,
    pub actions: Vec<NetworkActionAudit>,
}
pub trait PgCatalogSource {
    fn tables_with_rowsecurity(&self) -> Result<Vec<TableRls>, IntrospectError>;
    fn policies_for(&self, table: &str) -> Result<Vec<PolicyRow>, IntrospectError>;
    fn grants_for(&self, table: &str) -> Result<Vec<GrantRow>, IntrospectError>;
}
pub fn introspect_tier1_with_source(
    source: &impl PgCatalogSource,
    input: &Tier1IntrospectInput,
) -> Result<Tier1IntrospectOutput, IntrospectError> { /* E2 fills detections */ }
```

The trait is the seam that lets **every test run against a mock catalog with zero
DB connections** — the exact discipline `RlsHttpClient` + `MockPostgrest` gives
Tier 0. `PostgresPgCatalogSource` is the only impl that opens a socket, is
network-gated, and issues **only read-only catalog `SELECT`s** — no DDL, no DML,
no `SET`, no write of any kind (this is the §7.3/§1.3 no-writes invariant carried
into Tier 1).

**Host guard.** Mirror `refuses_non_supabase_urls`: parse the connection string's
host and reject anything that is not a Supabase-owned DB host (`db.<ref>.supabase.co`
and the Supabase pooler hosts). Arbitrary hosts, ports, and non-`postgres` schemes
are rejected before any connection is attempted.

**Opt-in.** `--rls-tier1-introspect` is a **separate** switch from the Tier 0
probe; enabling one must not enable the other. **Repository config alone cannot
enable it** (same rule as all Network work). The credential comes from env; if the
flag is set but the env var is absent, that is an operational error (exit 2), not
a silent skip.

**Audit.** Each catalog query produces a `NetworkActionAudit` with
`kind: CatalogIntrospection`, a read intent, the normalized DB host (never the
credential), the table, and the outcome — **never** a credential, a policy body in
the audit, or any row data.

### Acceptance criteria (self-verifiable)

1. `Tier1IntrospectInput/Output/Warning`, `PgCatalogSource`, and
   `introspect_tier1_with_source` compile under default + `--features network`;
   `PostgresPgCatalogSource` compiles only under `network`.
2. **Zero-connection default:** the full default test suite makes no DB
   connection; a `MockPgCatalog` implementing `PgCatalogSource` drives all Tier 1
   tests (assert, as Tier 0 does, that no credential and no row data appear in the
   serialized `actions`).
3. **Host guard (negative control):** a connection string pointing at a
   non-Supabase host (or a non-`postgres` scheme, or an arbitrary port) is rejected
   before any connection attempt, with a distinct error — mirror the
   `refuses_non_supabase_urls` test.
4. **Opt-in isolation:** enabling `--rls-tier1-introspect` does not enable the
   Tier 0 probe and vice versa; repository config alone does not enable Tier 1
   (assert both directions); flag-set-but-credential-absent exits 2.
5. **Transport constraint:** `bash scripts/check-network-boundary.sh` still passes
   — the new Postgres dep is optional, network-gated, rustls-backed, and
   nearest-parented by `vibescan-supabase`; `LocalStatic` crates remain
   transport-free across both feature graphs. Confirm no OpenSSL in the resolved
   `--features network` tree.
6. `cargo fmt` + `clippy -D warnings` clean (default + network); `cargo test
   --workspace` and `--features network` green.

---

## Task E2 — The introspection detections + `Evidence::RlsPolicy`

### Spec basis

- **§7.2 / §10.2:** Tier 1 emits **distinct, `Confirmed`** findings for: RLS
  disabled; RLS enabled with permissive `USING (true)`; missing-operation policy
  leaving an operation open; and inferred write-exposure. (The fifth §10.2 item,
  "policy keyed on user-writable metadata," is scoped out below.)
- **§7.3:** write-exposure is **inferred** from grants + absent restricting policy
  — **never demonstrated** by a write.
- **§4:** `Finding.evidence` is a redacted, serializable reproduction.

### Problem (root-caused)

The `RlsExposure` vocabulary is **already Tier 1-ready** — `crates/vibescan-types`
defines `RlsDisabled`, `PermissivePolicy`, `MissingOperationPolicy`,
`InferredWriteExposure` — but nothing emits them, and there is **no evidence
shape** to carry a policy fact. `Evidence::RlsProbe { table, endpoint,
observed_row_count, exposure }` is REST-shaped: `endpoint` and `observed_row_count`
are meaningless for a catalog-derived finding. Reusing it would force
`endpoint: "introspection"` / `observed_row_count: 0` placeholders — dishonest
evidence. A dedicated variant is required.

**Two vocabulary gaps to surface (do not silently paper over):**

1. **`Evidence::RlsPolicy` does not exist.** Add it (additive to the `Evidence`
   enum). It carries the policy reproduction: table, operation/command, the
   `USING`/`WITH CHECK` predicate text, and the `rowsecurity` flag. **Policy
   predicates are schema, not secrets** (§13.3 redaction governs *secret values*,
   not table/column identifiers), so the predicate text is the finding's
   reproduction and appears in full.
2. **No `RlsExposure` variant for "policy keyed on user-writable metadata."**
   Detecting it reliably requires predicate analysis (does the `USING` expression
   compare against a client-writable column?) — inherently heuristic and noisy.
   **§16 explicitly defers noisy `Review`-confidence heuristic scanners out of the
   first pass.** Scope it **out of Tier E**: implement the four mechanically-
   decidable Confirmed detections; leave the metadata-keyed heuristic as a named
   post-Tier-E follow-up (it would be `Review` confidence and needs its own
   `RlsExposure` variant when it lands). Record this scoping in the PR.

### File targets

- **Edit:** `crates/vibescan-types/src/lib.rs` — add the `Evidence::RlsPolicy`
  variant.
- **Edit:** `crates/vibescan-supabase/src/lib.rs` — implement the four detections
  in `introspect_tier1_with_source`, emitting `Confirmed` `Category::Rls` findings.
- **Edit:** `crates/vibescan-report/src/lib.rs` — extend `evidence_summary` with
  an `Evidence::RlsPolicy` arm (redacted-form discipline is automatic here — no
  secret is present).
- **Edit:** `crates/vibescan-report/tests/report_snapshots.rs` — snapshot the new
  evidence rendering per format.

### Implementation guidance

**The four detections** (all `Confirmed`, all read-only catalog queries via the
`PgCatalogSource` seam):

1. **RLS disabled** (`RlsExposure::RlsDisabled`): a table with `relrowsecurity =
   false` that is an API-exposed candidate. Severity per §10.2 (Critical in the
   correlation, but as a standalone Tier 1 finding follow §10.2's severity — do
   not overclaim; the *chain* is what's Critical, via E3).
2. **Permissive `USING (true)`** (`RlsExposure::PermissivePolicy`): RLS enabled but
   a policy whose `USING` predicate is a literal-true (`true`, `(true)`). Match the
   **normalized literal**, not a substring — `using (true)` and `USING (TRUE)` yes;
   `using (is_true(x))` no. This is the same segment/whole-token discipline the
   codebase already learned the hard way (C1, the ignore layer) — a substring
   match on `true` is a defect.
3. **Missing-operation policy** (`RlsExposure::MissingOperationPolicy`): RLS enabled
   with at least one policy, but a command (`SELECT`/`INSERT`/`UPDATE`/`DELETE`)
   has **no** policy covering it — under Postgres RLS, an operation with no
   permissive policy is denied, *except* the table owner / `BYPASSRLS` roles; the
   finding is "operation X has no policy; verify intended access," Confirmed on the
   catalog fact.
4. **Inferred write-exposure** (`RlsExposure::InferredWriteExposure`): a role grant
   (`information_schema.role_table_grants`) permitting `INSERT`/`UPDATE`/`DELETE`
   to `anon`/`authenticated` **combined with** the absence of a restricting policy
   for that operation ⇒ inferred openness. **Inferred only** — no write is
   attempted (§7.3). Detail must say "inferred from grants + absent policy," never
   claim a demonstrated write.

**Evidence.** Every emitted finding uses `Evidence::RlsPolicy { project, table,
command, using_expr, check_expr, rowsecurity }`. No row data, ever — catalog
queries return schema/metadata, and the detections must not `SELECT` table
*contents* (a `count(*)` is data too; if a detection needs "is the table
non-empty," obtain it from Tier 0's read probe, not here).

### Acceptance criteria (self-verifiable)

1. `Evidence::RlsPolicy` exists and serializes; `evidence_summary` renders it.
2. Against `MockPgCatalog`, each of the four detections produces exactly the
   expected `Confirmed` finding with the correct `RlsExposure` variant:
   - a `relrowsecurity=false` candidate → one `RlsDisabled`;
   - RLS-on + `USING (true)` policy → one `PermissivePolicy`;
   - RLS-on + policies present but no `SELECT` policy → one
     `MissingOperationPolicy` for `SELECT`;
   - `anon` `INSERT` grant + no INSERT policy → one `InferredWriteExposure`.
3. **Substring negative control:** a policy with `USING (is_active = true)` does
   **not** classify as `PermissivePolicy`; a policy `USING (true_flag)` does not
   either. Only a normalized literal-true predicate trips it.
4. **No-row-data invariant:** assert the serialized findings, warnings, and
   `actions` contain no table row values and no `count`; only schema identifiers
   and policy predicates.
5. **No-write invariant:** the mock records only read-category catalog queries; a
   test asserts no query the detections issue is a write/DDL/`SET`.
6. The metadata-keyed heuristic is **absent** (scoped out per §16) and named as a
   follow-up in the PR; `clippy -D warnings` clean; full workspace green both modes.

---

## Task E3 — Correlation integration, un-gate fixtures, extend precision/recall

### Spec basis

- **§12 rule 1:** the exposed-public-key chain fires on a low-privilege key
  (`ClientReachable`/committed) **AND at least one `Rls` `Exposed`/RLS-off finding
  on the same project.** "RLS-off" is precisely the Tier 1 `RlsDisabled` case;
  permissive `USING (true)` is read-equivalent. The chain claims **reads only**
  (§17.2).
- **§12 rule 2:** an exposed elevated key **moots all other RLS findings on that
  project** — Tier 1 adds RLS findings that rule 2 must also see.
- **§14 (§17.6 two-tier corpus):** `rls-off-table` and `permissive-using-true-
  policy` move from gated (`TODO(tier1)`) to **live**, driven by a mock catalog
  under `--features network` (the exact pattern the Tier 0 exposed-chain fixture
  uses). Precision/recall (D2) is computed over the live tier, so the newly-live
  fixtures join the baseline.

### Problem (root-caused)

`correlate_exposed_public_key` (`crates/vibescan-core/src/lib.rs:419`) selects its
RLS constituent with a hard `let Evidence::RlsProbe { table, endpoint,
observed_row_count, .. } = &rls_finding.evidence else { return None }`. A Tier 1
finding carrying `Evidence::RlsPolicy` returns `None` — **so the chain never fires
from introspection**, and un-gating `rls-off-table` would leave it not correlating.
This is the load-bearing integration, directly analogous to C1: the detection can
be perfect and the headline output still silent because the predicate doesn't
recognize the new evidence shape. `correlate_elevated_key_moots_rls` (:483) has the
same blind spot for rule 2.

The two fixtures are still stubs: `tests/fixtures/rls-off-table/expected.json` and
`.../permissive-using-true-policy/expected.json` are `{ "todo": ..., "findings":
[] }`, and their golden tests (`network_rls_off_table_fixture` :207,
`network_permissive_using_true_policy_fixture` :213) are `#[ignore]`d.

### File targets

- **Edit:** `crates/vibescan-core/src/lib.rs` — generalize the rule-1 RLS-
  constituent matcher (and rule 2's) to accept the Tier 1 read-exposure evidence.
- **Edit:** `crates/vibescan-core/tests/golden_corpus.rs` — implement the two
  network fixtures with a `MockPgCatalog` (mirror `network_exposed_public_key_
  chain_fixture_is_gated`), un-gate them, and relabel any residual `TODO` per D4.
- **Edit:** `tests/fixtures/rls-off-table/expected.json`,
  `tests/fixtures/permissive-using-true-policy/expected.json` — real expected
  findings (regenerate via `UPDATE_GOLDEN=1`, review the diff).
- **Edit:** `crates/vibescan-core/tests/precision_recall.rs` +
  `tests/fixtures/corpus-metrics-baseline.json` — add the two now-live fixtures to
  the corpus and regenerate the baseline under `UPDATE_METRICS=1` (review).

### Implementation guidance

**Rule-1 read-exposure set (the careful part).** Extend the matcher so the RLS
constituent is satisfied by **either**:
- `Evidence::RlsProbe { exposure: Exposed, .. }` (Tier 0, unchanged), **or**
- `Evidence::RlsPolicy { exposure: RlsDisabled | PermissivePolicy, .. }` (Tier 1).

Deliberately **exclude** `MissingOperationPolicy` and `InferredWriteExposure` from
rule 1's *read* chain: rule 1 claims reads (§17.2), and those two are operation-
/write-scoped. Excluding them is the conservative, non-overclaiming choice; note it
with a `TODO` to refine only if a *SELECT-specific* missing-operation case is later
shown to be a read exposure. Build the reproduction string from whichever evidence
matched (endpoint+rowcount for `RlsProbe`; "table X has RLS disabled" / "table X
has permissive USING (true)" for `RlsPolicy`) — do not fabricate REST fields for a
policy finding.

**Rule 2** must enumerate RLS findings by `Category::Rls` (both evidence shapes),
not by `RlsProbe` alone, so an exposed elevated key correctly moots Tier 1 findings
too.

**Fixtures.** `network_rls_off_table_fixture`: construct a `Tier1IntrospectInput`
for the fixture's project, drive `introspect_tier1_with_source(&MockPgCatalog{…}, …)`
returning a `relrowsecurity=false` candidate, assert one `Confirmed` `RlsDisabled`
finding, then `correlate_findings(&[key, rls_off])` and assert the Critical chain
fires **from the introspection finding** (this is the test that proves the rule-1
extension). `network_permissive_using_true_policy_fixture`: same, with an RLS-on +
`USING (true)` catalog, asserting `PermissivePolicy` and (if a client-reachable key
is present in the fixture) the chain. Both keep a `cfg(not(network))` `#[ignore]`d
stub, matching the Tier 0 fixture's structure.

### Acceptance criteria (self-verifiable)

1. **Chain fires from introspection:** a unit/integration test proves
   `correlate_findings` emits the Critical composite when given a
   `ClientReachable`/committed publishable key **and** a Tier 1 `RlsDisabled`
   finding on the same project — with **no** `Evidence::RlsProbe` present.
2. **Same for permissive:** the chain fires from a `PermissivePolicy` finding.
3. **Negative controls:** a `MissingOperationPolicy`-only or
   `InferredWriteExposure`-only finding does **not** by itself fire rule 1; a Tier 1
   finding on a *different* normalized project does not correlate with the key.
4. **Rule 2:** an exposed elevated key produces the "moots RLS" annotation over a
   Tier 1 `RlsPolicy` finding, not only over `RlsProbe`.
5. `network_rls_off_table_fixture` and `network_permissive_using_true_policy_
   fixture` are **un-gated** and green under `--features network`; their
   `expected.json` carry real findings; the `cfg(not(network))` stubs remain.
6. **Precision/recall extended:** `corpus-metrics-baseline.json` includes both
   fixtures with correct expected/observed/TP/FP/FN; total precision and recall do
   **not** decrease; clean-control FP stays 0; coverage recomputed. Golden manifests
   free of absolute paths / timestamps / row data.
7. Full workspace green (default + network); `check-network-boundary.sh` passes;
   `fmt` + `clippy -D warnings` clean. Only `hallucinated-dependency` remains gated
   (registry tier, Track F).

---

## Completion status this tier closes

Tier E delivers architecture §7.2 Tier 1 credentialed introspection: a sync,
rustls, own-host-only Postgres catalog reader (E1); the four mechanically-decidable
Confirmed detections with a proper `Evidence::RlsPolicy` reproduction (E2); and the
correlation-engine integration that lets the exposed-public-key chain fire from
introspection, with `rls-off-table` and `permissive-using-true-policy` un-gated and
folded into the precision/recall corpus (E3). After Tier E, two of the three
remaining gated fixtures are live; only `hallucinated-dependency` stays gated,
awaiting the registry track (F). The write-exposure story remains **inferred, never
demonstrated** — a live write-probe is still deferred behind the §7.4 ownership gate
(Track I).

## Notes for review

- **E3's rule-1 extension is the load-bearing change** — merge order puts it last,
  but scrutinize it hardest. It is the exact C1-shaped failure mode: a perfect
  detector whose output is silently dropped because the correlation predicate
  doesn't recognize the new evidence shape. The acceptance test #1 (chain fires
  with no `RlsProbe` present) is the one that proves it.
- **Two vocabulary gaps were surfaced, not resolved silently:** `Evidence::RlsPolicy`
  is added (E2, necessary and additive); the "user-writable-metadata policy"
  detection has no `RlsExposure` variant and is a noisy heuristic, so it is **scoped
  out** of Tier E citing §16, and named as a `Review`-confidence follow-up. Confirm
  the scoping is acceptable rather than assuming it.
- **One spec item needs the architecture owner:** §7.2 treats service_role and
  connection-string as equivalent Tier 1 inputs; they are not, for policy
  introspection (E0). The PR should flag a one-line §7.2 clarification; do not edit
  §7.2 from the implementation change.
- **No ownership gate here.** §7.4 reserves it for write-probes; Tier 1 authorizes
  on key/credential possession. Do not build DNS-TXT / well-known-file / OAuth in
  Tier E — that is Track I.
- **No writes, no row data, ever.** The detections are read-only catalog queries;
  policy predicates are schema (fine to show), table contents are not (never
  queried, never retained). This is §1.3/§7.3 carried into introspection and is
  the invariant most worth an explicit test.
