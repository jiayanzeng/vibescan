# vibescan — Codex Instructions: Track L (adversarial corpus, precision measurement, real-repository sampling)

Reviewed: 2026-08-06
Author: architecture review (Claude), for implementation by Codex
Status: **Ready to execute.** Seven dependency-ordered tasks.

**Authority:** `vibescan-architecture.md`. This document is a task record, not a
status source; current state lives in `STATE.md`. Completion claims here were
true when recorded and must be re-verified against the current checkout.

## How this track differs from J and K

Tracks J and K were behavior-preserving. **Track L is not.** It is expected to
change detection behavior, regenerate goldens, and rewrite the metrics
baseline. The invariant is therefore not "nothing changes" but "every change is
individually justified against a cited architecture section and recorded."

Do not fail closed on a golden diff here. Fail closed on an *unexplained* one.

## Why this track exists

`corpus_precision: 1.0` and `corpus_recall: 1.0` are currently vanity numbers.
Twelve fixtures, 15 true positives, zero false positives — and the entire
false-positive population is one fixture, `clean-control`, consisting of a JSX
page that returns `<main>Clean control fixture</main>`, a one-line
`Deno.serve(() => new Response("ok"))`, and a `package.json`.

That corpus proves the scanner does not fire on an empty repository. It says
nothing about whether the scanner fires on code that *looks* like it contains
credentials and does not. Precision measured against a trivially-negative
control cannot move, cannot discriminate, and cannot detect a regression in the
direction that actually kills a scanner: noise.

Every gate built in Tracks J and K protects the implementation from drifting.
None of them tells you whether the detection is right on code you did not
write. That is what this track is for.

## Method note

All specific paths, line numbers, and behavioral claims below are **hypotheses
derived from reading source**, not verified observations. Reproduce each one
before acting on it. Where a hypothesis proves wrong, say so and record the
correct behavior — a disproved hypothesis is a useful result, not a failure.

Build order:

1. **L0** — Preflight
2. **L1** — Adversarial clean-control corpus
3. **L2** — Classifier precedence investigation
4. **L3** — Allowlist stopword investigation
5. **L4** — Metrics reform: separate the clean corpus and gate it
6. **L5** — Real-repository sampling with redacted triage
7. **L6** — Reconcile and record

---

## Task L0 — Preflight

### Spec basis
Root `AGENTS.md`, required start-of-task protocol.

### Implementation guidance
Confirm and report: `main` clean and synchronized with `origin/main`;
`bash scripts/verify-all.sh` green; `python3 scripts/check-public-api.py` and
`python3 scripts/check-status-consistency.py` both pass; the current corpus
baseline totals and `corpus_version`.

Then record, without editing: the full inventory of files under each fixture's
`repo/` directory, and which fixtures synthesize their repository
programmatically in the harness rather than from committed files. L1 needs to
know which construction path to follow.

### Fail-closed conditions
Any gate failing on a clean `main`. Stop and report; do not begin L1 on a
broken baseline.

---

## Task L1 — Adversarial clean-control corpus

### Spec basis
Architecture §14 (precision/recall harness). `tests/fixtures/AGENTS.md`:
synthetic repositories and unmistakably fake credentials only; keep clean
controls genuinely clean.

### Problem statement
There is one clean control and it exerts no false-positive pressure. The
detection ruleset has several rules whose shape makes them prone to firing on
non-secrets, and none of them is currently under test in the negative
direction:

- `generic-high-entropy-assignment` matches any
  `secret|token|api_key|apikey|password|passwd|credential` assignment of a
  24+ character string above 3.5 entropy. This is the classic noise generator:
  build hashes, base64 test payloads, content-addressed asset names, cache
  keys, and fixture data all match its shape.
- `supabase-legacy-jwt` matches any `eyJ`-prefixed three-segment dotted
  base64url string above 3.0 entropy. Every JWT in every README, every decoded
  example header, and every expired test token matches.
- `aws-access-key-id` has **no entropy gate** and matches `(AKIA|ASIA)` plus 16
  uppercase alphanumerics.
- `private-key-block` matches the PEM `BEGIN` header anywhere, including inside
  documentation explaining what not to commit.
- `stripe-secret-key` matches `sk_test_` keys, which are by construction not
  production credentials.

### Implementation guidance
Build an adversarial clean corpus of near-misses: files that a naive scanner
would flag and that must produce **zero findings**. Follow the existing fixture
construction pattern; use unmistakably synthetic values throughout and never
copy a real credential, project ref, endpoint, or private source fragment.

Cover at minimum, one file or case per line:

**Generic high-entropy assignments that must not fire**
- A webpack/Vite content hash assigned to a variable named `assetToken`.
- A base64-encoded fixture payload assigned to `testCredential`.
- A git commit SHA assigned to `buildToken`.
- A UUIDv4 assigned to `sessionToken`.
- A long low-entropy string (repeated characters) assigned to `password` —
  proves the entropy gate, not the keyword.
- `apiKey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY` — an environment
  reference with no literal.
- An empty-string assignment to `secret`.
- A minified single-line bundle containing an assignment above the generic
  line-length threshold — pins the existing suppression rather than leaving it
  untested.

**Provider-shaped strings that must not fire**
- The canonical AWS documentation access key ID (uppercase, contains the
  literal text `EXAMPLE`). See L3 — this one is expected to fail initially.
- A Stripe `sk_test_` key in a test file. Decide and record whether firing is
  correct; if it is, this belongs in the vulnerable corpus instead, at reduced
  severity.
- A structurally valid but semantically empty JWT in a README code fence
  documenting configuration.
- A PEM `BEGIN PRIVATE KEY` header quoted inside a markdown security policy.
- An OpenAI-shaped string that is actually a Storybook story ID.

**Allowlist boundary cases**
- A secret-shaped value inside `.env.example` — must not fire.
- The same value inside `.env.local` — **must** fire; this is a positive
  control proving the allowlist is not over-broad.
- A file whose path contains `node_modules` as a substring of a longer segment
  (for example `my-node_modules-notes.md`) — must fire, proving segment
  matching rather than substring matching.
- `deno.lock` and `bun.lock` integrity blocks. Neither is in the allowlist
  paths today and Supabase Edge Functions are Deno. Determine empirically
  whether they generate findings; if they do, add them to the allowlist and
  record the change.

**Classifier near-misses** — construct these regardless of whether they
currently produce findings, because L2 depends on them:
- `public/server/config.json`
- `app/server/page.tsx`
- `services/worker/dist/index.js`
- `app/api/(admin)/route.ts` — a Next.js route group under an API route
- `src/app/@modal/(.)photo/page.tsx` — parallel and intercepting route segments

Target: the clean corpus must contain **more files than the vulnerable corpus**
when this task completes. False-positive pressure is the missing quantity;
under-building here defeats the entire track.

For every file, record in a companion note: what a naive scanner would flag,
which rule it stresses, and why zero findings is correct. A near-miss without a
stated rationale is decoration.

### Acceptance criteria
1. Every clean-corpus file has a recorded rationale naming the rule it stresses.
2. The three positive controls embedded above (`.env.local`, the
   `my-node_modules-notes.md` path case, and the minified-line case) behave as
   specified — the clean corpus must be able to fail.
3. The clean corpus exceeds the vulnerable corpus in file count.
4. No file contains a real credential, endpoint, project ref, username, email,
   or absolute home path. State this explicitly.
5. Report the full list of findings the new corpus produces **before** any fix
   from L2 or L3 is applied. This is the track's primary measurement and must
   be recorded even where it is embarrassing.

---

## Task L2 — Classifier precedence investigation

### Spec basis
Architecture §6.2 (location classification and the enumerated roots).

### Problem statement (hypothesis — verify before acting)
In `crates/vibescan-git/src/location.rs`, `classify_location` evaluates the
`ServerOnly` branch before the `ClientReachable` branch, and that branch
contains `segments.contains("server")` — an **unanchored whole-path** test.
Every other rule in that branch is positional.

The consequence appears to be that any path containing a `server` segment
anywhere classifies `ServerOnly` regardless of position, including paths that
are unambiguously client-reachable:

- `public/server/config.json` — `public/` is the served web root. This
  classifies `ServerOnly` while being fetchable by any browser.
- `app/server/page.tsx` — a Next.js route literally named `server`.

Both are **severity deflation**: a client-exposed key reported as server-only.
That is the dangerous direction of error, and it is invisible to the current
corpus.

A second, milder hypothesis in the other direction: `segments.contains("dist")`
in the `ClientReachable` branch classifies server build output — for example
`services/worker/dist/index.js` — as client-reachable, inflating severity.

### Implementation guidance
1. Reproduce each case against the real classifier and report actual output.
   If a hypothesis is wrong, record the correct behavior and move on.
2. For each confirmed defect, determine the minimal correct fix against §6.2.
   The likely shape is anchoring or ordering: `public/` and route-root
   membership should take precedence over an unanchored `server` segment.
   Derive the rule yourself; do not pattern-match to this sentence.
3. If §6.2 does not determine the answer, that is an architecture gap. Propose
   the amendment, cite the section, and surface the conflict rather than
   resolving it silently.
4. Any behavior change requires regenerating the affected goldens under
   `UPDATE_GOLDEN=1`, reviewing every changed stable ID, severity, location,
   and ordering entry against the architecture, then rerunning without it.
5. Update `scripts/real-repo-invariants.py` if its independent classification
   reimplementation encodes the same defect. The oracle and the classifier must
   agree, and both must be right — if only one is fixed, the oracle stops being
   an independent check.

### Acceptance criteria
1. Each hypothesis is reported as confirmed or disproved, with observed output.
2. Every confirmed defect has a fix, a §6.2 citation, and a fixture pinning it.
3. Negative control: revert one fix, confirm the corresponding fixture fails,
   restore, prove a clean `git diff`.
4. The classifier and the oracle agree on the full clean and vulnerable corpora.
5. Every golden diff is enumerated with its justification. An unexplained diff
   is a failure.

---

## Task L3 — Allowlist stopword investigation

### Spec basis
Architecture §14. `crates/vibescan-secrets/src/rules/default-rules.toml`
allowlist semantics.

### Problem statement (hypothesis — verify before acting)
`CompiledAllowlist::matches` tests stopwords with
`context.secret.contains(stopword)`. Two properties follow:

- Matching is **case-sensitive**. The global stopword list is lowercase
  (`example`, `placeholder`, `changeme`, `your_key_here`, `test_key`), so the
  canonical AWS documentation access key ID — uppercase, ending in the literal
  text `EXAMPLE` — is not suppressed and fires as a provider secret. That
  string appears in a large fraction of AWS tutorials, READMEs, and test files.
- Matching is against **the captured secret only**, not the surrounding line.
  So `// example key follows` on the preceding line does not suppress, which is
  probably correct but is currently untested in either direction.

### Implementation guidance
1. Reproduce both properties and report actual behavior.
2. If case-sensitivity is confirmed as a defect, fix it — the natural form is
   ASCII-case-insensitive containment. Consider whether the stopword list
   should also grow (`EXAMPLE`, `dummy`, `sample`, `redacted`, `xxxxx`),
   and decide based on what the L1 corpus actually shows rather than on
   speculation.
3. Weigh the recall cost explicitly. A broader stopword list suppresses real
   secrets that happen to contain those substrings. State the tradeoff you
   chose and why, and add a vulnerable-corpus fixture proving the suppression
   does not swallow a genuine credential.
4. If line-context matching is judged desirable, that is a rule-schema change
   and belongs in its own track. Record the decision; do not implement it here.

### Acceptance criteria
1. Both properties reported as confirmed or disproved with observed output.
2. Any fix has a clean-corpus fixture proving suppression and a
   vulnerable-corpus fixture proving non-over-suppression.
3. Recall over the vulnerable corpus does not regress. If it does, the fix is
   wrong.
4. The recall/precision tradeoff is stated in one paragraph in the track record.

---

## Task L4 — Metrics reform: separate the clean corpus and gate it

### Spec basis
Architecture §14. Track H's coverage-ceiling pin, which established that a
metric must be able to fail in both directions.

### Problem statement
`corpus-metrics-baseline.json` reports one set of totals across all fixtures.
With one trivial clean control that was adequate; with a large adversarial
clean corpus it hides the number that matters. A single `fp: 0` across mixed
populations does not say how much noise pressure was actually applied.

### Implementation guidance
1. Extend the baseline schema to report the vulnerable and clean corpora
   separately: per-corpus totals, and for the clean corpus a false-positive
   count together with the size of the population it was measured against
   (file count and scanned-line count). A false-positive rate without its
   denominator is not a measurement.
2. Bump `corpus_version` to a Track L identifier.
3. Gate it: any increase in clean-corpus findings fails the harness. Zero is
   the expected value and the assertion must be exact, not a threshold.
4. Add the new fields to `STATE_FIELDS` in
   `scripts/check-status-consistency.py` and to the `STATE.md` current-state
   block, so the status gate validates them against the baseline artifact the
   way it already validates `corpus_tp` and the rest.
5. Update `docs/public-api-inventory.txt` if any of this changes a public
   surface. It should not; if it does, that is a finding.

### Acceptance criteria
1. The baseline distinguishes the two corpora, and the clean-corpus
   false-positive rate is reported with its denominator.
2. `python3 scripts/check-status-consistency.py --self-test` passes with the
   new fields, and the real check passes.
3. Negative control: introduce a deliberate false positive in the clean corpus;
   confirm both the harness and the status gate fail and name it; revert; prove
   a clean `git diff`.
4. `bash scripts/verify-all.sh` passes.

---

## Task L5 — Real-repository sampling with redacted triage

### Spec basis
Architecture §12 (LocalStatic scanning). `scripts/AGENTS.md`. Root `AGENTS.md`
on target-project access and network classes.

### Problem statement
Real-repository validation is `n=1`. `scripts/real-repo-invariants.py` checks
repo-agnostic invariants — redaction, path shape, classification consistency —
which is valuable but is **not** a precision measurement. There is no ground
truth for a repository you did not author, so the oracle cannot label a finding
true or false. Precision on real code therefore requires triage, and triage has
never been done at scale.

### Authorization and limits
You are authorized to clone **public** repositories over HTTPS from
`github.com` / `codeload.github.com` and to scan the resulting local working
trees. This is LocalStatic scanning of local files.

Prohibited without exception: any Tier 0 or Tier 1 Supabase probe against any
project referenced by a sampled repository; any Registry-class network call
beyond what the pinned offline fixtures provide; any credential use; any write
to a sampled repository; any publish. If a scan surfaces something that looks
like a live credential, **do not verify it, do not probe it, and do not record
its value** — record only the rule id, redacted path, and classification, and
note that a live-looking credential was suppressed.

### Implementation guidance
1. Select a sample of Next.js and Supabase repositories large enough to be
   informative — at minimum ten, spanning monorepo and single-app layouts,
   App Router and Pages Router, and at least two using Supabase Edge Functions.
   Choose by structural diversity, not popularity. Record the selection
   criteria and the exact commit SHA sampled for each.
2. Scan each, run the invariant oracle, and produce a **redacted triage
   worklist**: one row per finding with rule id, repo-relative path, location
   class, severity, and your TP/FP/uncertain label with a one-line rationale.
   Never record the matched secret text, a project ref, an endpoint, or any
   absolute path.
3. Label using a written decision procedure, committed alongside the worklist,
   so the labels are reproducible rather than personal. Where the procedure
   does not determine an answer, label `uncertain` and say what evidence would
   settle it. Do not force a binary.
4. Compute the real-corpus false-positive rate and compare it to the synthetic
   clean-corpus rate. A large divergence means the synthetic corpus is
   unrepresentative, which is itself the most valuable finding this track can
   produce — report it prominently rather than burying it.
5. Fold representative real-world false positives back into the synthetic clean
   corpus as new near-miss fixtures, **re-authored from scratch** with
   synthetic values. Never copy third-party source into the repository.
6. Do not commit any cloned repository, and do not add the sample to CI. The
   sampling harness may be committed; the sample must not be.

### Acceptance criteria
1. At least ten repositories sampled, each with its commit SHA and selection
   rationale recorded.
2. The triage worklist contains no secret values, project refs, endpoints, or
   absolute paths — verify mechanically, not by inspection.
3. The labeling decision procedure is committed and the labels follow it.
4. The real-corpus and synthetic-corpus false-positive rates are reported side
   by side, with the divergence discussed.
5. No prohibited network class was exercised. State this explicitly, naming
   what ran.
6. `git status` shows no cloned repository and no third-party source.

---

## Task L6 — Reconcile and record

### Implementation guidance
1. Append a dated Track L record to `docs/STATE-HISTORY.md`: what the corpus
   now contains, every behavior change with its architecture citation, the
   before-and-after metrics, the real-repository comparison, and every
   hypothesis that was disproved.
2. Write `docs/tracks/vibescan-trackL-instructions.md` recording the corpus
   design, the near-miss rationale table, and the triage decision procedure.
3. Re-derive the `STATE.md` current-state block from source, including the new
   metrics fields and `open_tracks`.
4. Record the remaining known limitations honestly. In particular: whether
   `classification_coverage` is still at its corpus ceiling, and what the
   sample size now supports claiming about real-world precision.

### Acceptance criteria
1. `bash scripts/verify-all.sh`, `dist generate --check`, `shellcheck`,
   `check-public-api.py`, and `check-status-consistency.py` all pass.
2. `git diff --check` passes.
3. Every golden and baseline diff across the whole track is enumerated with its
   justification.
4. Push, open one PR, report the URL. Merging remains the owner's action.

---

## Standing invariants for this track

- Synthetic values only. No real credential, project ref, endpoint, username,
  email, absolute home path, or third-party source enters the repository.
- `UPDATE_GOLDEN=1` is permitted here, and only here, for changes justified in
  L2 or L3. Every regenerated golden is reviewed field by field and enumerated
  in the track record.
- No fixture is deleted and no test is marked `#[ignore]` to make a gate pass.
- Crate DAG, network boundary, public API inventory, and release structure are
  untouched. If any of their gates fires, stop and report.
- Temporary mutation tests restore the exact prior state before the task ends.

## What this track does not do

- **Rule-schema changes** (line-context allowlists, per-rule severity
  overrides, confidence scoring). L3 may recommend them; implementing them
  belongs to a later track.
- **New detection capability.** Track L measures and corrects what exists.
- **Track I.** Gate 2 remains unmet.

---

## Track L execution record (2026-08-06)

Status: **implemented and verified on `codex/track-l-adversarial-precision`;
merge remains the repository owner's action.** This record was written in
dependency order so that the required unfixed L1 measurement could not be
replaced by the final result.

### L0 observed baseline

After `git fetch --prune origin`, `HEAD` and `origin/main` both resolved to
`59344707da92cd4bee8611334a8e54d1e3723fd5`. The only initial worktree item was
this user-authored, untracked instruction document; no pre-existing source or
fixture change existed. `bash scripts/verify-all.sh`,
`python3 scripts/check-public-api.py`, and
`python3 scripts/check-status-consistency.py` passed. The committed metrics
artifact reported `corpus_version: tier-h2-live-v1`, 15 TP, 0 FP, 0 FN,
precision 1.0, recall 1.0, and classification coverage 7/9.

Committed fixture repository inventory before L1:

- `clean-control`: `package.json`, `src/app/page.tsx`,
  `supabase/functions/ping/index.ts`.
- `hallucinated-dependency`: `package.json`.
- `malformed-dependency`: `package.json`.
- `monorepo-layout`: `apps/web/.next/static/chunks/x.js`.
- `nested-gitignore`: `packages/nested/.gitignore`,
  `packages/nested/ignored/secret.ts`, and
  `packages/nested/ignored-but-scanned/secret.ts`.
- `publishable-client-reachable`: `src/app/page.tsx`.
- `src-api-client-wrapper`: `src/api/supabase-client.ts`.
- `vendor-chunks-noise`: `.gitignore`,
  `dashboard/.next/server/vendor-chunks/prop-types.js`, and
  `src/server/secret.ts`.

`history-only-elevated-key` materializes by cloning its committed
`history.bundle`. `exposed-public-key-chain`,
`offline-composite-exposed-public-key-chain`, `rls-off-table`, and
`permissive-using-true-policy` synthesize findings and mocked read-only inputs
in the harness rather than materializing a committed `repo/` tree. The
Registry fixture uses its committed `repo/` tree plus an injected mock. All
other live working-tree fixtures are copied from committed `repo/` files and
initialized as temporary local Git repositories by the harness.

### L1 corpus decision and unfixed measurement

Decision: keep the clean truth population separate from positive controls.
`adversarial-clean-control` has 21 committed repository files and an explicit
per-file rationale table. `adversarial-positive-controls` has five files for
the `.env.local`, path-segment, Stripe test-key, AWS non-over-suppression, and
preceding-line-context controls. This preserves an exact zero-finding clean
gate while still proving that the corpus can fail. Counting the 21-file clean
fixture together with the original three-file clean control gives 24 clean
files, exceeding the 17 repository files in the vulnerable population after
the five positive-control files are added.

Before any L2 or L3 fix, a LocalStatic working-tree-only scan of the new clean
fixture produced **seven false positives across 20 scanned files** (the
`.env.example` template was correctly skipped):

| Rule | Redacted repository path | Class | Severity | L1 classification |
|---|---|---|---|---|
| `aws-access-key-id` | `docs/aws-example.md` | `Unknown` | High | FP: canonical documentation placeholder |
| `private-key-block` | `SECURITY.md` | `Unknown` | High | FP: backtick-quoted header only |
| `openai-api-key` | `stories/Auth.stories.ts` | `Unknown` | High | FP: Storybook identifier |
| `generic-high-entropy-assignment` | `assets/content-hash.ts` | `Unknown` | Medium | FP: content hash |
| `generic-high-entropy-assignment` | `sessions/example.ts` | `Unknown` | Medium | FP: UUIDv4 correlation identifier |
| `generic-high-entropy-assignment` | `fixtures/payload.ts` | `Unknown` | Medium | FP: base64 fixture payload |
| `generic-high-entropy-assignment` | `build/metadata.ts` | `ClientReachable` | Medium | FP: Git commit SHA |

The positive-control scan produced exactly five intended findings: two
`generic-high-entropy-assignment` findings at `.env.local` (`ServerOnly`) and
`docs/my-node_modules-notes.md` (`Unknown`), `stripe-secret-key` at
`tests/stripe.test.ts`, and `aws-access-key-id` at both
`src/aws-production-shape.ts` and `src/aws-preceding-comment.ts`. The minified
generic line, low-entropy password, environment reference, empty assignment,
empty-claims JWT, `.env.example`, `deno.lock`, and `bun.lock` produced no
finding before any fix. The Stripe test credential remains a positive because
it can authorize test-mode operations; Track L excludes the rule-schema change
needed for a reduced per-rule severity.

No fixture contains a real credential, endpoint, project reference, username,
email address, absolute home path, or third-party source.

### L2 and L3 hypothesis reproduction before fixes

The Rust classifier and independent Python oracle both produced:

- `public/server/config.json` → `ServerOnly`;
- `app/server/page.tsx` → `ServerOnly`;
- `services/worker/dist/index.js` → `ClientReachable`;
- `app/api/(admin)/route.ts` → `ServerOnly`;
- `src/app/@modal/(.)photo/page.tsx` → `ClientReachable`.

Thus the source-reading output hypotheses were confirmed. They are **not
implementation defects under the current architecture**: §6.2 explicitly
orders a whole `server/` segment before client roots and explicitly lists
`dist/` at any nesting depth as client-reachable. Track L does not authorize a
silent architecture reversal, so no classifier behavior change is justified;
the five-case Rust test and oracle self-test instead pin the observed contract.
The oracle was also strengthened to reject either wrong known class, not only
`Unknown`. It agreed with the classifier over all ten committed fixture
repository trees after each was materialized as its own temporary repository;
the remaining four vulnerable fixtures are harness-synthesized findings or
mocked inputs and do not invoke the filesystem classifier.

The L3 hypotheses were also confirmed before any fix. The lowercase `example`
stopword failed to suppress the uppercase `EXAMPLE` captured in the canonical
AWS documentation ID, while `example` on the preceding line did not suppress a
different AWS-shaped value on the next line. The former is a captured-value
case-sensitivity defect. The latter is the intended extracted-secret-only
boundary; widening it to line context would be a rule-schema change and is not
implemented in Track L.

### L5 sample selection and labeling procedure

Selection was structural rather than popularity-based: small and medium
single-apps, example collections and monorepos; both Next.js Pages and App
Routers; route groups and `src/app`; API-heavy Pages projects; a non-Next
client; and two repositories with `supabase/functions/`. Each shallow clone
was scanned as a LocalStatic working tree at the exact commit below. Shallow
history was intentionally not scanned because L5 measures working-tree noise.

| Repository | Commit | Structural reason | Scanned files | Findings |
|---|---|---|---:|---:|
| `supabase-community/nextjs-openai-doc-search` | `50d6bb71706b50a83c2a52dc4a7d3e426ac34adf` | Single-app Pages Router with a Supabase-backed search flow | 40 | 0 |
| `supabase-community/supabase-by-example` | `a40be7fe6e18c69764fdf8f4eb3422db636505c3` | Multi-example tree spanning Next.js App and Pages Routers plus other clients | 1,106 | 0 |
| `supabase-community/database-build` | `de2c18d36f7f256476e71b1dd372238c2ed2eeac` | `apps/` + `packages/` monorepo, App Router, and Supabase Edge Functions | 259 | 0 |
| `vercel/platforms` | `ec12e65709c8263dd3462c4d33261851b8a3157d` | Compact App Router multi-tenant example | 29 | 0 |
| `shadcn-ui/next-template` | `d117bd0fd897cfd3b0d14e8647d8fcd6341a511b` | Minimal App Router template control | 34 | 0 |
| `ixartz/Next-js-Boilerplate` | `2ed91c8ca6a89f49059388a690bcecb463ebe64b` | `src/app` with localization and nested route groups | 116 | 0 |
| `boxyhq/saas-starter-kit` | `abc9b686823cbfb4973c79bc36fea37a3244be6c` | Pages Router SaaS app with a large `pages/api` surface | 326 | 0 |
| `t3-oss/create-t3-app` | `4709861f7e67a15564c0460c13e7b4b6cfcae40d` | Multi-package generator/docs tree containing App and Pages templates | 541 | 1 |
| `supabase-community/flutter-stripe-payments-with-supabase-functions` | `6442c9e8a5836b6eaf1b12657abba1cd25ac8b52` | Non-Next client paired with several Supabase Edge Functions | 88 | 1 |
| `supabase-community/nextjs-subscription-payments` | `3aa0d956fb46dda45a6676f74ffa77eb0fe10a11` | Supabase subscription app on the Next.js App Router | 88 | 0 |

Labeling decision procedure:

1. Label `TP` only when local repository context establishes that the reported
   class is operationally accurate (for example, a private/elevated credential
   deliberately consumed by code). A public key classification is still a TP
   when the rule claims only public-key presence.
2. Label `FP` when local context establishes a non-secret semantic class such
   as build metadata, a public search-client credential, an integrity value,
   or an explicit placeholder, and the finding's rotate/remove claim is
   therefore inapplicable.
3. Label `uncertain` when distinguishing an active value from a placeholder or
   deciding privilege would require owner knowledge, credential use, or a
   network request. State the evidence that would settle it; never probe.
4. A comment or documentation location is not sufficient by itself for `FP`.
   It needs an explicit local placeholder/allow marker; otherwise a fully
   provider-shaped value remains `uncertain`.
5. Record only repository, exact commit, detector rule, repository-relative
   path, class, severity, label, and a one-line rationale. Suppress every
   matched value, project reference, endpoint, and absolute path.

The committed worklist is
`docs/tracks/vibescan-trackL-real-repo-triage.tsv`. It contains one row for each
of the two findings: one FP and one uncertain; there were no locally established
TPs. `python3 scripts/check-track-l-triage.py` mechanically verifies the path
shape and rejects endpoint, email, absolute-path, and credential-shaped
material.

Across 2,627 scanned real-repository files, the confirmed file-normalized FP
rate is `1 / 2627 = 0.00038066235249333843` (about 0.0381%). Treating the
uncertain row as an FP gives an upper bound of
`2 / 2627 = 0.0007613247049866769` (about 0.0761%). The final synthetic clean
corpus rate is `0 / 25 = 0.0`; the real sample is therefore nonzero where the
synthetic rate is zero. That divergence exposed two missing clean patterns,
both re-authored from scratch as `search/public-client.ts` and
`docs/commented-bearer.ts`. The latter uses the existing explicit inline allow
marker rather than weakening comment scanning. The sample supports a bounded
noise observation over these 2,627 files; with no established TP it does not
support a real-world recall claim.

Only GitHub HTTPS clones and LocalStatic working-tree scans ran. No scan used
`--network`, Tier 0, Tier 1, `--registry-checks`, a credential, or a write. No
sample repository was modified or committed, and no matched value was verified.

### L2/L3 decision, tradeoff, and negative control

The classifier behavior is unchanged because architecture §6.2 determines all
five L2 cases in exactly the direction observed. With no classifier fix, the
L2 “revert one fix” control is not applicable; inventing a classifier change
solely to revert it would contradict the architecture. The permanent Rust and
Python truth cases are the independent agreement proof, and the strict oracle
comparison over every repo-backed clean/vulnerable fixture found no mismatch.

L3 normalizes configured stopwords to ASCII lowercase and compares them with
an ASCII-lowercased captured secret. The default corpus adds only the measured
rule-local `storybook` stopword and narrow line allowlists for the four generic
binding/value pairs plus backtick-quoted private-key headers. After L5 it adds
one similarly narrow `publicSearchApiKey` binding. It does **not** add broad
`dummy`, `sample`, `redacted`, or `xxxxx` substrings because any can occur by
chance in a real opaque credential, and L1 produced no evidence that justified
that recall cost. The recall tradeoff is therefore deliberate: an actual
credential containing `example` or `storybook` in the captured body, or stored
in one of the exact near-miss binding/value shapes, can be suppressed; in
exchange, the measured high-volume documentation/build/test shapes stop
crying wolf. The five vulnerable positive controls—including two AWS values
without placeholder text, a Stripe test credential, `.env.local`, and the
longer `my-node_modules` path—preserve recall across the affected boundaries,
and vulnerable-corpus recall remains 1.0.

Negative control: temporarily restoring case-sensitive captured-secret
matching made
`track_l_stopwords_are_ascii_case_insensitive_and_secret_local` fail because
the canonical AWS documentation ID reappeared. Restoring the fix made the test
pass, and the detector source returned to its exact prior SHA-256.

### L4 metrics reform and negative control

`corpus_version` is now `track-l-adversarial-v1`. The baseline retains overall
totals and adds `corpora.vulnerable` and `corpora.clean`, each with fixture,
file, scanned-line, expected/observed, TP/FP/FN, precision/recall, and
file/line-normalized FP fields. The final values are:

| Population | Fixtures | Scanned files | Scanned lines | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Vulnerable | 12 | 17 | 46 | 20 | 0 | 0 | 1.0 | 1.0 |
| Clean | 2 | 25 | 50 | 0 | 0 | 0 | 1.0 | 1.0 |

Overall TP rises from 15 to 20 because the five positive controls are newly
labeled vulnerable cases. Overall FP/FN and precision/recall remain 0/0 and
1.0/1.0. Classification coverage changes from 7/9 to 8/14: `.env.local` adds
one classified finding while the other four new positive findings are
deliberately at framework-neutral paths. The exact six-member Unknown set is
pinned, so 8/14 remains the expanded corpus ceiling.

The hard gate checks the aggregate clean corpus, not one fixture, and requires
both `observed == 0` and `fp == 0`. The status schema mirrors vulnerable totals
and the clean population denominators/rates. Its self-test includes a nonzero
clean-FP rejection. For the required live negative control, a temporary
invalid dependency named `Bad Package` was inserted into the adversarial clean
fixture. The precision harness failed with
`clean-corpus false positives: expected 0, got 1`; with the temporary baseline
also claiming `corpora.clean.fp: 1`, the status gate independently rejected
`clean_corpus_fp`. Both files were restored byte-for-byte; their SHA-256 hashes
matched the pre-control values, and the clean harness plus status gate passed.

### Golden and baseline review

No pre-existing final golden changed. The first authorized regeneration also
removed the two hand-authored `truth` fields from
`malformed-dependency/expected.json` because that serializer does not carry
them. That was unexplained by L2/L3 and was immediately restored; its final
diff is empty.

The two new golden manifests were reviewed field by field:

- `adversarial-clean-control/expected.json`: empty findings, as required.
- `adversarial-positive-controls/expected.json`: five `generic-secret`
  findings in deterministic High-before-Medium order. The stable IDs are
  `secret-26961106447a5402d5e1ea4e`,
  `secret-43ede40a4493159a6321d217`,
  `secret-98ea6e22a38b72f6fcd4f0e1`,
  `secret-7ca635ef7f0c08b0feb38961`, and
  `secret-efb9f17c776b9c32f808069e`. Their paths respectively pin the AWS
  non-placeholder, Stripe test-key, preceding-line AWS, longer
  `my-node_modules`, and `.env.local` controls. The first four location classes
  are `Unknown`; `.env.local` is `ServerOnly`. All provenance is working-tree,
  evidence contains fingerprints only, there are no related IDs, and ordering
  is stable.

The metrics baseline is intentionally rewritten rather than treated as a
golden snapshot: it adds the two corpora, file/line denominators, and per-fixture
populations; bumps the corpus version; adds the two new fixtures; changes TP
15→20 and coverage 7/9→8/14; and leaves FP, FN, precision, and recall unchanged.
No report snapshot, public API inventory entry, crate edge, feature gate,
release artifact, or Network behavior changed.

The canonical per-file near-miss rationale table is committed at
`tests/fixtures/adversarial-clean-control/README.md`; the positive-control
rationale table is beside it at
`tests/fixtures/adversarial-positive-controls/README.md`. Together they name
every new repository file, stressed rule, naive signal, and truth-label reason.
