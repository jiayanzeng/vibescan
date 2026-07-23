# vibescan — Codex Instructions: Track H (resolve the §17 `src/api/` open question)

Reviewed: 2026-07-23
Author: architecture review (Claude), for implementation by Codex
Execution status: **Complete and verified in the current working tree (H1–H3)**
Integration status: **Uncommitted; not yet merged**

## Closure record

Track H is closed at the implementation/specification level:

- **H1 complete:** only `src/api/` is content-sensitive; the classifier truth
  table and coalescing regression pin both server and client directions.
- **H2 complete:** the live `src-api-client-wrapper` fixture, path-only Python
  oracle, mocked rule-1 classification branch, and harness-derived metrics
  baseline are synchronized. The corpus records 15 TP, 0 FP, 0 FN, precision
  1.0, recall 1.0, and classification coverage 7/9.
- **H3 complete:** architecture §6.2 contains the split rule and §17.9 records
  option 3 as resolved. The architecture change is exactly the two authorized
  hunks.

The required default, `network`, `registry`, and combined Clippy/test graphs,
the real-repository oracle self-tests, Network boundary checker, local
hardening aggregate, formatting, and `git diff --check` pass. No live request,
credentialed action, new dependency edge, or target-project write occurred.
Track I remains separate and security-design-first behind §7.4.

## How to consume this document

This is the evidence-gated fast-follow named in the post-v1 roadmap — architecture
**§17's one deliberately-open question** and the **§6.2** rule it concerns. It is a
single dependency-ordered task in the house format (spec basis → problem → file
targets → guidance → self-verifiable acceptance criteria with negative controls).
Authority is `vibescan-architecture.md`, **not** `STATE.md`.

It is small by design: a narrow §6.2 patch, a classifier signature change with one
production call site, a matching change to the Python D1 oracle, one new corpus
fixture, a truth-table of unit tests, and the §17 resolution note. It does **not**
touch the Network boundary, the crate DAG, correlation *rules*, or any transport.

Read the two framing notes below before writing code — they are the whole reason
this task was held back until now, and they determine the shape of the fix.

### Framing note 1 — why *now*, and why this is not "resolving on intuition"

§17 left exactly one question open **on purpose** and attached a standing
instruction: *"Do not change the rule on intuition. Measure it."* The measurement
apparatus (§14 real-repo validation + the coverage metric) had to exist and produce
a real-repo record first. That precondition is now met: the AstroScout D1 run is the
first genuine real-repository coverage record.

But AstroScout does **not**, by itself, settle the population question. Its three
findings sit in `.env` files (`apps/api/.env`, `apps/web/.env.local`) and a client
bundle — **none under a `src/api/` tree**. So AstroScout exercises the `.env` and
bundle paths, not the `src/api/` client-wrapper ambiguity. That means the two
"blanket flip" resolutions the roadmap listed —

  1. keep `src/api/` → `ServerOnly`, or
  2. flip `src/api/` → `ClientReachable`

— would *still* be an intuition call about how often real frontends put a
browser-shipped wrapper at `src/api/`. We do not have that frequency evidence, and
one repo will not produce it.

**Resolution: adopt roadmap option 3 — a disambiguating content signal.** Option 3
is the resolution that does *not* require the population-frequency evidence, because
it classifies each file by the server-runtime signals actually present in that file
rather than guessing which case is more common. It replaces *"guess the population"*
with *"measure each file,"* which is exactly what §17's "measure it" mandate asks
for. The disambiguation is then pinned by synthetic fixtures that model both
directions, and real repos keep flowing through the (updated) D1 harness so the
resolution stays evidence-anchored rather than frozen on one data point.

### Framing note 2 — the coverage metric cannot see this bug, so do not rely on it

This is a **wrong-class** defect, not an **Unknown** defect. A `src/api/` client
wrapper today classifies as `ServerOnly` — which *counts as classified*. Both the
Rust classifier (`classify_location`) and the Python D1 oracle
(`_expected_location_class` / `_has_package_server_root` in
`scripts/real-repo-invariants.py`) independently agree `src/api/` → `server_only`,
so they **mutually reinforce the same wrong answer**, and the classification-coverage
number stays at 100% while the reported class is wrong. The harm is real and
specific:

- the reported `location_class` is wrong on exactly the paths where a publishable
  key and a table name co-locate and ship to the browser; and
- **§12 rule 1** (the exposed-public-key chain) then fires only through its
  `(or committed)` branch. For a client wrapper that exists **only in the working
  tree** (uncommitted) alongside a same-project RLS-off table, the classification
  branch never fires — a genuine false negative for the headline chain.

So: **do not add a coverage assertion and call it done.** The acceptance criteria
below pin the class end-to-end and pin the rule-1 classification branch directly.

---

## Task H1 — Content-signal disambiguation for `src/api/` roots (P1; §6.2, §17, §12 rule 1)

### Spec basis

- **§6.2 Location classification.** Bullet 1 lists "a top-of-package `api/`/`src/api/`
  server root, at any depth" as a decisive `ServerOnly` signal. First-match-wins,
  server before client, segment-boundary matching (never root-anchored `starts_with`,
  never raw substring).
- **§17 Open question — `src/api/` → `ServerOnly`.** The rule is spec-conformant as
  written but misclassifies the common Vite/Next case where `src/api/` is a
  client-side wrapper that ships to the browser. Resolve by measurement, not intuition.
- **§12 rule 1.** The `location_class = ClientReachable` predicate is one of the two
  independent triggers for the exposed-public-key chain; the other is `(or committed)`.

### Problem statement

`classify_location(path: &str)` in `crates/vibescan-git/src/lib.rs` routes every
`src/api/`-shaped path to `ServerOnly` via `path_has_package_server_root`
(`path.starts_with(&["src", "api"])` and the `apps|packages|services/*/src/api`
window). It has no access to file content, so it cannot distinguish a server module
from a client fetch wrapper living at the same path.

### File targets

1. **`crates/vibescan-git/src/lib.rs`** — the classifier and its one production call site.
2. **`scripts/real-repo-invariants.py`** — the Python oracle that mirrors the classifier.
3. **`vibescan-architecture.md`** — §6.2 patch + §17 resolution note (Task H3 below;
   listed here so the code and spec move together in one PR).

### Implementation guidance

**(a) Thread content into the classifier.** Change the signature to
`classify_location(path: &str, content: &[u8]) -> LocationClass`. There is exactly
one production call site — `push_content` (currently `classify_location(&path.0)` at
the `UnitLocation` construction), where the `content: Vec<u8>` argument is already in
scope and has already passed the size and binary-NUL guards. Pass `&content`. Update
the three in-crate test call sites (`classify_location_*`).

**(b) Scope the signal narrowly — only the `src/api/` shape is ambiguous.** Do **not**
touch the unambiguous cases:

- **Keep unconditional `ServerOnly`:** Next.js route handlers (`app/api`, `pages/api`,
  `src/app/api`, `src/pages/api`); the `.env`/`server/`/`.next/server/`/`supabase/functions/`
  signals; and **bare top-of-package `api/` roots that are *not* under `src/`**
  (`api/…`, `apps|packages|services/<pkg>/api/…`). A directory literally named `api`
  at a package root — not under a frontend `src/` — is conventionally a backend
  package; §17's question is specifically about `src/api/`, so leave bare `api/`
  alone. Changing it is out of scope.
- **Make content-dependent:** only the `src/api/` shape —
  `src/api/…` and `apps|packages|services/<pkg>/src/api/…`.

Introduce two helpers to make the split explicit and testable, and stop overloading
`path_has_package_server_root`:

- `is_bare_api_package_root(segments)` → the non-`src` package roots only.
- `is_src_api_root(segments)` → `[src, api, …]` and `[apps|packages|services, <pkg>, src, api, …]`.

**(c) The server-runtime signal.** Add `has_server_runtime_signal(content: &[u8]) -> bool`.
Return true iff the (UTF-8-lossy) text contains any of:

- the directive `"use server"` or `'use server'` (the React/Next server directive);
- an import/require specifier `next/server`;
- an import/require specifier with a `node:` prefix (e.g. `node:fs`, `node:crypto`).

These are affirmative, low-false-positive markers of server-only runtime code. **Do
not** use `process.env` as a signal — it appears in client code via `NEXT_PUBLIC_`
and would re-introduce a false positive. Keep the set exactly these three; resist
drift.

**(d) Wire the branches so a no-signal `src/api/` lands `ClientReachable`, not `Unknown`.**
This is the load-bearing detail. Removing `src/api` from the server check is *not
sufficient* — a bare `[src, api, handler.ts]` matches **none** of the existing
`ClientReachable` patterns, so it would silently fall through to `Unknown`, quietly
breaking both the class and the rule-1 classification branch. Route it explicitly:

- In the `ServerOnly` block: `is_bare_api_package_root(segments)` unconditionally, and
  `is_src_api_root(segments) && has_server_runtime_signal(content)` conditionally.
- In the `ClientReachable` block: add `is_src_api_root(segments)`. Because `ServerOnly`
  is evaluated first and returns early, any `src/api/` path that reaches the
  `ClientReachable` block necessarily had **no** server signal — so this lands the
  client-wrapper case at `ClientReachable`, which is the whole point.

Result truth table (must hold):

| path | content | class |
|---|---|---|
| `src/api/supabase.ts` | plain client fetch wrapper (no signal) | `ClientReachable` |
| `src/api/handler.ts` | `import { NextRequest } from "next/server"` | `ServerOnly` |
| `src/api/db.ts` | `import "node:fs"` | `ServerOnly` |
| `src/api/actions.ts` | `"use server"` directive | `ServerOnly` |
| `packages/web/src/api/client.ts` | no signal | `ClientReachable` |
| `api/handler.ts` (bare, no `src`) | anything | `ServerOnly` |
| `apps/api/index.ts` (bare package) | anything | `ServerOnly` |
| `apps/web/app/api/route.ts` (route handler) | anything | `ServerOnly` |
| `apps/web/app/foo/api/route.ts` (not a route root) | — | `ClientReachable` (unchanged) |
| `staticassets/x.js`, `apps/web/src/myenv.ts`, `apps/foo/api-docs/readme.md` | — | `Unknown` (substring guard unchanged) |

**(e) The coalescing rule is unchanged.** §6.2's "most client-reachable class among
coalesced locations" and §4 identity are untouched. A publishable key present in both
a bundle (`ClientReachable`) and a signal-bearing `src/api/` server file (`ServerOnly`)
still coalesces to `ClientReachable` — no change needed, but add a test so it is pinned.

### Acceptance criteria (self-verifiable)

1. **Classifier truth table.** The `classify_location_*` unit tests in
   `crates/vibescan-git/src/lib.rs` cover every row of the table above, passing
   `(path, content)` pairs. Both `src/api/` directions are present; the bare-`api/`,
   route-handler, and substring/segment negative controls
   (`staticassets/`, `myenv.ts`, `api-docs/`, `app/foo/api/`) are unchanged.
2. **Coalescing pin.** A test asserts a key coalesced across a `ClientReachable`
   bundle and a signal-bearing `ServerOnly` `src/api/` file reports `ClientReachable`.
3. `fmt` + `clippy -D warnings` clean; the change compiles in default, `network`,
   `registry`, and combined graphs.

---

## Task H2 — New corpus fixture + oracle sync + metrics baseline (P1; §14, §12 rule 1)

### Spec basis

§14 two-tier corpus; §17.6 (precision/recall computed over the live tier);
§12 rule 1 (classification branch).

### File targets

- `tests/fixtures/src-api-client-wrapper/` (new fixture: `repo/…` + `expected.json`).
- `crates/vibescan-core/tests/common/mod.rs` (register in `LIVE_FIXTURES`).
- `tests/fixtures/corpus-metrics-baseline.json` (add the fixture row; recompute totals).
- `scripts/real-repo-invariants.py` (oracle sync).
- The `--features network` golden path in `crates/vibescan-core/tests/golden_corpus.rs`
  (rule-1 classification-branch assertion).

### Implementation guidance

**(a) The fixture — the exact §17 scenario, end to end.** Create a working-tree
(no history) fixture whose *only* secret-bearing file is a client wrapper at
`repo/src/api/supabase-client.ts` containing a **new publishable key**
(`sb_publishable_…`), the co-located project URL, and a table name, written as a
plain browser fetch wrapper with **no** server-runtime signal. Model it on
`tests/fixtures/publishable-client-reachable/` and `monorepo-layout/`. Expected
golden: exactly one **Info** `supabase-key:publishable_new` finding whose location is
the `src/api/…` path with `location_class = client_reachable`. Include the
`location_classes` array (as `monorepo-layout/expected.json` does) so the class is
asserted in the manifest. Manifest must be free of absolute paths and timestamps.

The **server-direction assertion and the negative/substring controls live in the H1
unit tests**, not this fixture — the golden only sees findings, and the unit tests
can assert class directly on `(path, content)` pairs. Keep the fixture minimal and
single-purpose: prove the pipeline surfaces `client_reachable` for the realistic
`src/api/` publishable-key case that §17 is about. Register it in `LIVE_FIXTURES`.

**(b) Oracle sync — the second site of the same truth.** In
`scripts/real-repo-invariants.py`, `_has_package_server_root` and
`_expected_location_class` currently mirror the *old* rule and cannot see content.
After H1 they would assert a class the checker can no longer determine from a path
alone. Change them so:

- `_has_package_server_root` covers only the **bare** `api` package roots — drop
  `segments[:2] == ["src", "api"]` and the `.../src/api` window.
- `_expected_location_class` returns **`None` (ambiguous — do not assert)** for
  `src/api/`-shaped paths, since the class is now content-dependent and the harness
  only sees serialized locations.

Net effect: the Unknown-where-classifiable check simply stops firing for `src/api/`
paths (correct — the checker can't know), while `.env`, route-handler, `server/`,
bare-`api/`, and all `ClientReachable` checks are unchanged. Update `run_self_tests`
and its printed `cases=N` count if you add a case; keep the golden-JSON self-test.

**(c) Metrics baseline.** Add the `src-api-client-wrapper` row (expected 1, observed 1,
tp 1, fp 0, fn 0) to `tests/fixtures/corpus-metrics-baseline.json`. **Recompute** the
totals and coverage from the harness output and record the recomputed values — do
**not** hand-edit a guessed coverage number. Total precision and recall must remain
1.0; clean-control FP must remain 0. Bump `corpus_version` (e.g. `tier-h2-live-v1`).

**(d) Rule-1 classification-branch assertion (`--features network`).** Add a golden
assertion that a `ClientReachable` `src/api/` low-privilege key plus a same-project
RLS-off/`Exposed` finding fires the **Critical** exposed-public-key composite **via
the classification branch** — i.e. the chain fires even when the key is *not*
committed, demonstrating it no longer depends solely on `(or committed)`. Reuse the
existing Tier-0/Tier-1 injected-catalog machinery in `golden_corpus.rs` and
`common/mod.rs`; do not contact a live endpoint.

### Acceptance criteria (self-verifiable)

1. `src-api-client-wrapper` produces **exactly one** Info `publishable_new` finding
   with `location_class = client_reachable` at the `src/api/…` path; golden manifest
   free of absolute paths/timestamps and registered in `LIVE_FIXTURES`.
2. **Negative control (unit, from H1):** a `src/api/` file bearing any of the three
   server signals classifies `ServerOnly`; a bare `api/` package root classifies
   `ServerOnly` regardless of content; the substring cases stay `Unknown`.
3. `corpus-metrics-baseline.json` updated with recomputed totals: precision 1.0,
   recall 1.0 unchanged; clean-control FP 0; coverage recorded from harness output.
4. `python3 scripts/real-repo-invariants.py --self-test` passes; the oracle returns
   ambiguous/`None` for `src/api/` paths and no longer asserts `server_only` for them;
   the Unknown-check does not fire for `src/api/` paths; `cases=N` updated.
5. The `--features network` golden asserts the rule-1 **classification branch** fires
   for an uncommitted `ClientReachable` `src/api/` key + same-project RLS-off, and the
   composite is Critical and absorbs its constituents.
6. `cargo test --workspace` and each feature graph green; `check-network-boundary.sh`
   passes (the DAG and transport boundary are untouched); `git diff --check`.

---

## Task H3 — Architecture patch: §6.2 + resolve §17 (P1; spec conformance)

### Spec basis / problem

The roadmap defines Track H's deliverable as "a small, evidence-gated §6.2 patch"
that resolves the §17 open question. The code (H1/H2) and the spec must move together
in one PR; the implementation must not silently diverge from a cited section.

### Implementation guidance

Apply two programmatic edits to `vibescan-architecture.md`, each with a
uniqueness-asserted anchor string, and verify with a unified diff showing exactly the
intended hunks and all other content byte-identical (the house patch discipline):

1. **§6.2, bullet 1.** Replace the phrase describing "a top-of-package `api/`/`src/api/`
   server root, at any depth" with the split rule:
   - a **bare** top-of-package `api/` root (`api/…`, `apps|packages|services/<pkg>/api/…`),
     at any depth, is a decisive `ServerOnly` signal; and
   - a **`src/api/`** root is `ServerOnly` **only when the file carries a server-runtime
     signal** — the `"use server"` directive, a `next/server` import, or a `node:`
     import — and is otherwise `ClientReachable`, because a `src/api/` module under a
     frontend `src/` tree with no server marker is a browser-shipped client wrapper
     (the §17 case). Note that this is the one classification rule that reads file
     content, not path alone, and that Next.js route handlers (`app/api`, `pages/api`,
     `src/app/api`, `src/pages/api`) remain unconditionally `ServerOnly`.

2. **§17 Open question → resolved (add 17.9; retitle/repoint the "Open question"
   block).** Record: the decision (option 3, content-signal disambiguation); the
   rationale (per-file measurement replaces population guessing, so it satisfies
   "measure it, don't guess"); the evidence framing (AstroScout is the first real-repo
   record but exercises `.env`/bundle paths, not `src/api/`, so a blanket flip would
   have been intuition; the disambiguation is pinned by the `src-api-client-wrapper`
   fixture + the classifier truth table, and real repos keep feeding D1); and the
   two-site nature of the change (Rust classifier + Python oracle move in lockstep).
   State that the coverage metric alone cannot detect the former mis-class (it is a
   wrong-class, not an Unknown), which is why the rule-1 classification-branch
   assertion exists.

### Acceptance criteria (self-verifiable)

1. `git diff -- vibescan-architecture.md` shows exactly the two intended hunks
   (§6.2 bullet 1; §17 resolution); every other line byte-identical.
2. The anchor strings used for each replacement are asserted unique before editing
   (grep count == 1), per the house patch method.
3. The resolved §17 text no longer frames `src/api/` as an *open* question and points
   to §6.2 and the fixture/tests as the evidence anchor.

---

## Track H closure

Track H is closed in the current working tree. The one deliberately-open
question in the architecture is resolved the way §17 required — by measurement,
not intuition — and in a form that does not hinge on a single real-repo sample:
`src/api/` classifies per the server-runtime signals actually present in each
file, the exposed-public-key chain fires through the classification branch for
an uncommitted browser-shipped `src/api/` wrapper (closing a real false
negative), the coverage oracle stops asserting a class it can no longer
determine, and the resolution is pinned end-to-end by a corpus fixture and a
classifier truth table. The post-v1 roadmap's only remaining item is then Track
I, which remains security-design-first behind the §7.4 ownership gate.
Repository integration remains pending until these working-tree changes are
committed and merged.

## Notes for review

- **The load-bearing edit is routing no-signal `src/api/` to `ClientReachable`, not
  `Unknown`.** This is the same segment-boundary/matching-discipline defect class as
  C1, E3, and F1 reappearing: get the branch wiring exactly right, or the class and
  the rule-1 classification branch silently regress while coverage looks fine. The
  truth-table unit tests and the network-golden rule-1 assertion are what prove it.
- **The Python oracle is a second copy of the same rule and must move in lockstep.**
  Leaving it asserting `src/api/ → server_only` makes the D1 harness claim a class it
  can no longer determine from a path.
- **Honest evidence caveat.** Option 3 is chosen precisely because it does not need
  the population-frequency data that one repo cannot supply. Keep running real
  Next.js/Supabase repos through `real-repo-invariants.py`; the disambiguation is
  baked into fixtures and unit tests, so the resolution is pinned regardless — but
  more real-repo coverage is the ongoing validation, exactly as §14 intends.
- **This is decision-first only in the sense that the decision *is* the evidence
  mechanism.** Surface the §6.2/§17 patch in the PR; do not let the implementation
  edit the architecture beyond the two cited hunks.
