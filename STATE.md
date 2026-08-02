# vibescan State

```yaml
# vibescan:current-state
reviewed: 2026-08-02
head_commit: e899d4fb9b670bcd6fbe4b986d214b7776107a0b
branch: codex/track-j-assurance-hygiene
worktree: clean
workspace_version: 0.2.0
license: PolyForm-Noncommercial-1.0.0
released_version: 0.2.0
released_tag: v0.2.0
integration_status: committed-not-merged
corpus_version: tier-h2-live-v1
corpus_tp: 15
corpus_fp: 0
corpus_fn: 0
corpus_precision: 1.0
corpus_recall: 1.0
classification_coverage: 0.7777777777777778
open_tracks: none
```

`head_commit` records the commit at which status was last reconciled; because a
commit cannot contain its own SHA, the value is expected to be an ancestor of
current `HEAD`, not an equality guarantee.

Authority: `vibescan-architecture.md`. This file records observed current
status; it does not override the architecture or prove completion by itself.
Historical verification evidence is preserved in
[`docs/STATE-HISTORY.md`](docs/STATE-HISTORY.md).

The current repository checkpoint is `0.2.0`, tagged by the annotated
`v0.2.0` tag. Track H is merged to `main` at `e9390be`; Track J and its
J10–J12 addendum are committed through `e899d4f` on the branch named above but
are not merged. J0 refreshed `origin` and confirmed that local
`main`, `origin/main`, and the Track H closeout commit agree. The six npm
packages and all eight Cargo crates declare version `0.2.0`. Public release
channels were not queried during J0, so `released_version` uses the workspace
version and must not be read as fresh proof that every registry channel
currently resolves.

The workspace is licensed under SPDX identifier
`PolyForm-Noncommercial-1.0.0`. PolyForm Noncommercial is source-available,
not open source: its use restriction is incompatible with the Open Source
Definition. Historical releases `0.1.0`–`0.1.3` remain available under MIT to
anyone who already received them under that license.

No Track J task changes scanner behavior, a detection or correlation rule, a
crate edge, an egress path, credential handling, or target-project access.
Track J is repository hygiene and assurance infrastructure in the
`LocalStatic` capability class.

## Executive verdict

vibescan is a substantial, runnable local-first Rust CLI. Architecture §15
steps 1–9 are implemented and backed by the deterministic corpus,
performance-counter fixture, real-repository invariant harness, report
snapshots, and Network boundary checks. Tier 1 catalog introspection, the
separately gated Registry egress class, and the five-target distribution path
are implemented post-v1 additions. The default graph remains transport-free,
and no v1 path writes to a target project.

Track H resolved architecture §17.9: only `src/api/` is content-sensitive;
explicit server-runtime markers classify it as `ServerOnly`, while their
absence classifies it as `ClientReachable`. Bare top-of-package `api/` and
Next.js route-handler roots remain `ServerOnly`. The Rust classifier and the
independent real-repository oracle retain their distinct, tested contracts.

Use these three lenses when discussing completion:

- **Runnable v1 coverage:** all architecture §15 build-order steps exist.
- **Strict buildable-v1 conformance:** complete, subject to rerunning the
  current checkout's gates rather than trusting this status record.
- **Entire architecture document:** partial. Deferred active DAST/write
  probing, accounts, billing, and the noisy client-auth/newcomer heuristics
  remain outside the completed product surface.

## Current integration context

Track J began from `main` at `e9390beeb5bc8bbdb8550da3c58434d63d62faf7`,
which equals refreshed `origin/main`. J0 found one pre-existing change: the
user-supplied, untracked instruction document now preserved at
`docs/tracks/vibescan-trackJ-instructions.md`. It is the authorized input to
this track and remains user-owned content. The three documents whose
historical status was disputed are now preserved at
`content/moltbook-teardown.md`,
`docs/tracks/vibescan-trackH-instructions.md`, and
`docs/vibescan-trackI-security-design.md`; J0 confirmed all three were tracked
and not ignored before J4 reorganized them.

J0 derived, rather than copied, the repository facts in the current-state
block. The annotated `v0.2.0` tag peels to `c707ce6`; Track H is the following
merged commit. The corpus baseline is `tier-h2-live-v1` with 15 true positives,
zero false positives, zero false negatives, precision 1.0, recall 1.0, and
classification coverage 7/9. `.github/workflows/release.yml` carries dist's
generated-file marker. Track J pinned its action revisions through supported
cargo-dist configuration rather than hand-editing the generated workflow, and
`dist generate --check` passed with warnings only.

The 7/9 classification coverage is this corpus's pinned ceiling: the exact
Unknown remainder is `history-only-elevated-key` at `src/history.ts` and
`nested-gitignore` at `packages/nested/ignored-but-scanned/secret.ts`.

## Architecture completion matrix

| Architecture area | Status | Evidence and limitation |
|---|---|---|
| Design and privacy invariants | Safety core verified | LocalStatic is the default; raw secrets do not cross the candidate-to-finding boundary; Network actions are separately gated and read-only or catalog-read-only. |
| Crate graph | Verified eight-crate post-v1 graph | The only post-v1 crate is `vibescan-registry`; the exact dependency and transport-parent boundaries are machine-checked. |
| Collection and identity | Implemented | Full-content identity retains all distinct paths, provenances, and location classes; the pipeline remains materialized rather than streamed. |
| Location classification | Track H complete | Segment-aware precedence, monorepo depth, content-sensitive `src/api/`, and independent oracle behavior are pinned by fixtures and truth-table tests. |
| Detection and Supabase semantics | Implemented | The embedded generic substrate, exact-revision enrichment, new/legacy key classes, and conservative project-aware coalescing are covered. |
| Tier 0 read probing | Implemented, opt-in Network | Own-project URL validation, `apikey`, GET-only probing, local candidate harvesting, degraded outcomes, and redacted scope records are tested with mocks. |
| Tier 1 catalog introspection | Implemented, opt-in Network | Fixed read-only catalog queries emit confirmed evidence; write exposure is inferred and never demonstrated. |
| Correlation | Implemented | Exactly the two declarative v1 rules use same-project evidence and primary/additional commit provenance. |
| Dependency integrity | Offline plus Track F complete | LocalStatic structural checks remain available; Registry egress is independent, opt-in, cached, redacted, and failure-distinguishable. The noisy newcomer heuristic remains deferred. |
| Reporting and gates | Implemented | JSON, SARIF, TTY, and HTML are redacted and deterministic; baseline-suppressed findings do not affect stats or exit policy. |
| Configuration and CLI | Implemented | Defaults < repository TOML < explicit CLI precedence and repository-root relative paths are tested; repository config alone cannot enable Network work. |
| Distribution | Track G complete | The static five-target build, ships-only npm wrapper, crates.io/npm/Homebrew publishers, checksums, and attestations are implemented. Live channel state was not re-verified in Track J J0. |
| Assurance | Track J plus addendum committed, not merged | The corpus records 15 TP, 0 FP, 0 FN, precision/recall 1.0, and classification coverage 7/9. The exact two-member Unknown set is pinned; status consistency now verifies Repomix hygiene and Git truth, four-graph CI and release structure run on pull requests, immutable workflow actions remain enforced, and the canonical offline matrix covers these controls without changing scanner results. |
| Explicit non-goals | Preserved | No live writes, active DAST, BOLA, dashboard, accounts, billing, or client-auth heuristic scanner is authorized here. |

## Strict gaps and known risks

### P0 — scanner correctness

No open P0 scanner-correctness defect is recorded. Content identity,
committed-provenance predicates, exact historical revision enrichment, and
conservative project reconciliation are covered by regression tests.

### P1 — assurance infrastructure

No open P1 assurance-infrastructure gap is recorded. Track J added the
machine-readable current-state contract and offline consistency checker,
pinned the corpus's exact Unknown classification set, added explicit combined
`network,registry` clippy and test jobs, SHA-pinned every third-party workflow
action, and made `scripts/verify-all.sh` the canonical full offline matrix. The
J10–J12 addendum prevents Repomix bundles from being tracked, verifies branch
and integration claims against local Git state, and puts the release-channel
structural verifier on both the canonical matrix and pull-request CI path.

### P2 — measured product depth

- The live corpus is intentionally small and self-authored. Precision and
  recall are saturated; continued sanitized real-repository sampling is the
  appropriate expansion path.
- The materialized pipeline records deterministic counters and duration, but
  longer-term timing and peak-memory trends are not gated.
- Provider-corpus licensing and attribution should remain a durable review
  item before broad generic-rule expansion.
- Renaming `npm/platforms/cli-*` to mirror published identities is cosmetic and
  deferred because those paths are load-bearing release inputs.

## Detailed next steps

1. Review and merge the Track J pull request without squashing away the
   repository-history-preserving document moves.
2. Keep real-repository validation explicit and sanitized; never point the
   optional leg at user data without authorization.
3. Continue clean-control and planted-positive real-repository sampling before
   expanding generic detection breadth.
4. Keep Track I gated on explicit user demand, ownership-proof ratification,
   and a non-persisting design. No Track J work enters that deferred track.

## Closeout gate for future milestone claims

Run the canonical offline closeout matrix:

```sh
bash scripts/verify-all.sh
```

The optional sanitized real-repository leg requires
`--real-repo /absolute/path`; it is skipped by default. The default matrix is
offline and includes formatting, all four clippy graphs, all four test graphs,
the real-repository oracle self-test, Network-boundary checks, status
consistency, release-publishing structure, the offline hardening aggregate,
and `git diff --check`.

Use `UPDATE_GOLDEN=1` or `UPDATE_METRICS=1` only after an intentional result
change, inspect every artifact diff, then rerun without the variable. Do not
claim completion from historical pass counts.

## Track J verification observed on 2026-08-02

The complete default `bash scripts/verify-all.sh` matrix passed before the
Track J implementation commit `b08f693`. `dist generate --check`, the status
checker's self-test and repository check, workflow YAML parsing, immutable-
action and permission sweeps, Markdown relative-link validation,
`shellcheck scripts/verify-all.sh`, and `git diff --check` also passed.

Required negative controls were observed before being reverted byte-for-byte:
the exact Unknown-set test rejected both an extra member and a missing member;
the status checker rejected independent version, license, corpus-coverage,
terminology, and integration-token drift; and the canonical matrix reported
the exact failing step for both a format defect and a combined-feature-only
clippy warning. No live probe, public registry query, or user real-repository
scan was run. The optional real-repository leg was explicitly reported as
skipped because no fixture was supplied.

## Track J addendum verification observed on 2026-08-02

J10 generated a real Repomix bundle at the pinned `repomix-output.xml` path;
all root, Markdown, and nested variants matched the ignore rule, and generation
on committed checkout `e899d4f` left `git status --porcelain` empty. The
required force-stage negative control made the status checker fail with the
tracked bundle path, after which the bundle was removed from the index and
remained only as an ignored local artifact. JSON parsing confirmed that
`content/**` remains excluded and the security-check setting is unchanged.
Repomix v1.17.0 was fetched through `npx` solely to generate this local audit
artifact; that package fetch was not a vibescan scan or release-channel check.

J11's self-tests and real repository check passed. Independent negative
controls rejected a false `merged` claim and a wrong branch while printing the
claimed and observed Git facts; both edits were reverted byte-for-byte. A
depth-one local clone with no `origin/main` exited successfully and printed
explicit skip messages for the branch and integration truth checks.

J12's release-publishing verifier now runs in the canonical matrix and pull-
request CI. Its preflight exposed a stale mutable-tag assertion left by J8; the
user authorized replacing that assertion with a requirement for the same
action identity at an immutable 40-character SHA with its `v1.x.y` comment.
Negative controls proved that both a mutable action tag and a missing publish
permission fail with precise messages, then restored the source hashes. The
authorized correction is recorded in the
[Track J closure record](docs/tracks/vibescan-trackJ-instructions.md#track-j-closure-record).

On `e899d4f`, `bash scripts/verify-all.sh`, `dist generate --check`, and
`shellcheck scripts/verify-all.sh` passed. The optional real-repository leg was
skipped because no fixture was supplied. No live probe, credentialed test, or
target-project write was performed. No vibescan Registry-class or public
release-channel verification request ran.
