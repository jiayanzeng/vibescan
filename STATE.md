# vibescan State

Reviewed: 2026-07-19

Current released implementation checkpoint: `e788b1c` on `main`, with annotated
tag `v0.1.3` peeling to that exact merge (Tasks G4.0–G4.4 and Track G complete).
Release run #29676514551 passed all 19 jobs: five builds and
attestations, static Linux verification, five-platform npm smoke, GitHub
hosting, and the ordered crates.io → npm → Homebrew publishers. Public reads
resolve all eight crates and all six scoped npm identities at `0.1.3`; the tap
formula is `0.1.3`. An unchanged-tag re-push returned `Everything up-to-date`.
Documentation closeout checkpoint `a9507b2` is on
`codex/track-g4-release-0.1.3-closeout`; PR #10 merged that record to `main` as
`6441cc7`. G4.4 subsequently passed all three install paths, six npm provenance
checks, the eight-crate Cargo graph, six checksums, five Artifact Attestations,
and both rejection controls. No target-project state changed.

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
SARIF, TTY, and HTML. Phase 4 now enforces the authoritative post-v1
eight-crate DAG across normal, build, dev, target, optional, and
feature-activated dependencies.
Phase 5 now enforces default < repository config < explicit CLI precedence,
strict repository-root path handling, named-baseline failures, and additive
custom rules without allowing repository config alone to enable Network work.

The strict **buildable-v1** verdict is now **complete and proven** through
architecture §15 step 9. Tier E1 added credentialed, read-only Postgres catalog
transport and input plumbing. Tier E2 added the four mechanically decidable
catalog detections and catalog-native evidence. Tier E3 now integrates the two
confirmed Tier 1 read-exposure shapes with both v1 correlation rules, activates
the RLS-off and permissive-policy mock goldens, and incorporates them into the
committed corpus metrics. Track F1 provides the separately gated registry crate,
rustls transport boundary, dependency-input plumbing, explicit CLI opt-in, and
auditable scope shapes. Track F2 adds local OSV snapshot matching, public
package-existence checks, precision guards, failure taxonomy, and 24-hour
public-data caches. Track F3 activates the last gated corpus fixture through a
mock registry and adds it to the committed metrics baseline. Task G1 is
complete: the workspace is publish-ready, `dist` plans exactly the
architecture's five targets with musl-only Linux, the tagged `v0.1.0` release
run produced all five archives plus checksums, the blocking custom job proved
both Linux binaries are static, and all five GitHub Artifact Attestations
verified against the release workflow and merge commit. Task G2 is complete:
the npm shim selects one of five exact-version optional platform packages,
executes only the shipped binary, preserves its exit status, and has passed the
hosted five-platform `npx` smoke matrix. Task G3's local
implementation now wires bottom-up crates.io publication, platform-first npm
publication with OIDC provenance, and cargo-dist's prebuilt Homebrew formula
publisher, and provides an executable release runbook. Task G4.0 is complete:
the release owner selected the controlled personal-scope
`@jiayanzeng/vibescan` entry point, the publisher plans only the six approved
`@jiayanzeng/vibescan*` identities, and neither the third-party-owned unscoped
`vibescan` package nor an unavailable `@vibescan` organization scope is a
publication target.
Task G4.1 completed the original bootstrap: all fourteen registry identities
were free before publication, the release owner confirmed the crates.io and npm
bootstrap secrets plus npm two-factor authentication, and the public Homebrew
tap and its `Formula/` layout existed with workflow push credentials configured.
Task G4.2 is complete:
all engine, boundary, Cargo/npm packaging, `dist` plan/formula, negative-control,
and hardening gates pass on the current release commit. G4.3's `0.1.1`
preparation was merged and tagged, but Release run #10 failed validation before
jobs because the generated custom publisher calls omitted `contents: read`.
Repair commit `bca901a` uses cargo-dist's supported custom-job permission
configuration for both publishers and pins it in the release contract checker;
PR #7 merged it to `main` as `66e5fa2` with all 36 checks passing. PR #8 then
merged recovery `0.1.2` as `1883d61`. Its tagged run proved all five builds and
attestations, static Linux verification, npm packaging/smoke, GitHub hosting,
all six npm publications, the Homebrew update, and the first five crate
publications without any 403. crates.io returned HTTP 429 for the sixth new
crate, so `v0.1.2` remains partial immutable evidence. Preparation `a12499a`
synchronized `0.1.3`, retries only explicit crates.io 429 failures with a
bounded delay, sequences crates.io → npm → Homebrew, and passed the complete
local release and architecture matrix. PR #9 merged it as `e788b1c`; annotated
tag `v0.1.3` peels to that merge, and Release run #29676514551 passed all 19
jobs. All eight crates and all six npm identities now resolve publicly at
`0.1.3`, the formula is `0.1.3`, and the required same-tag push was a no-op.
G4.3 is complete. G4.4 then verified all three public install channels, all six
npm provenance statements, all eight crates, all six checksum entries, all
five platform attestations, and both tamper controls. The architecture-named
Cargo package remains `vibescan-cli`, which installs the `vibescan` binary.
Track G is complete.
Architecture §17.8 explicitly defers the noisy user-writable-metadata
heuristic, so its absence is not an E2 gap. The verdict for the entire
architecture document is therefore partial.

Use these three lenses when discussing completion:

- **Runnable v1 coverage:** all eight section-15 steps exist and the Phase
  1–5 regression matrix is green.
- **Strict buildable-v1 conformance:** complete. The previously identified
  identity, Network semantics, auditability, crate-DAG, CLI/config,
  real-repository, precision/recall, deterministic performance-counter, and
  resolved-decision ratification blockers are all covered by passing gates.
- **Entire architecture document:** partial. Tier E's E1–E3 implementation,
  Track F's registry intelligence/corpus activation, Track G1–G3's repository
  implementation, G4.0's npm identity decision, and G4.1's external bootstrap
  plus G4.2's reversible preflight are complete; G4.3's first tagged attempt
  failed before publication, and its `0.1.2` recovery partially published
  before crates.io rate-limited the sixth new identity. The `v0.1.3` recovery
  then passed end to end, and G4.4 verified every public channel and provenance
  path. Track G is complete; other deferred tracks keep the full architecture
  verdict partial.

No target-project write path was found. Tier 0 exposes GET only and discards
returned row data after counting. Tier E1's Postgres transport accepts only
validated Supabase DB hosts and ports and issues fixed, read-only catalog
`SELECT`s. E2 infers write exposure only from catalog grants plus policy absence
and never attempts a write. The default production dependency graph remains
transport-free.

## Current worktree context

The checkout was clean at `1dfa85c` when Task G1 began. Pull request
[#1](https://github.com/jiayanzeng/vibescan/pull/1) merged the initial G1
implementation (`1225975`) and its test-fixture portability correction
(`09eb065`) to `main` as `fba689c`. The correction was exposed by the first
hosted branch-push run; no production collection behavior changed. The
annotated `v0.1.0` tag points to that merge. No pre-existing user change was
present or modified.

Task G2 began from a clean `main` at `ac3757a`, after pull request #2 had landed
the G1 close-out record. Pull request
[#3](https://github.com/jiayanzeng/vibescan/pull/3) merged the G2 implementation
commit (`e0092ab`) and verification record (`69167a1`) to `main` as `1dbe6f2`.
No pre-existing user change was present or modified. G2 changes only packaging,
release workflow integration, tests, and documentation; it does not change a
crate, dependency edge, scanner phase, target-project access, or Network
capability.

Task G3 began from a clean `main` at `0ebca9b`, after pull request #4 landed the
G2 close-out record. Work is on `codex/track-g3-release-publishing`; no
pre-existing user change was present or modified. Before the G3 commit, the
worktree intentionally contains only release metadata, generated workflow,
publisher scripts/tests, npm manifest provenance, documentation, and this
status update. It does not change Rust scanner behavior, dependencies, the
eight-crate DAG, target-project access, or any runtime Network capability.

Pull request #5 merged G3 to `main` as `cb048b9` with 26/26 checks green. The
current branch then gained the user-authored documentation commit `4479cfb` and
the user-owned untracked
`docs/vibescan-trackG-closeout-instructions.md`. Task G4.0 began from that
checkout; the untracked instruction file was read and preserved without edits.
After the initial G4.0 commit, the release owner approved correcting the npm
identity to the personal `@jiayanzeng` scope; that correction updates the
instruction file as well. The current G4.0 worktree changes only npm package
identity, publisher/package contract tests, release documentation,
architecture §13.1's approved primary-channel wording, and this status record.
It does not change Rust scanner behavior, the eight-crate DAG, runtime Network
capability, or target-project access.

The corrected G4.0 implementation was committed as `4b5fb87`. The worktree was
clean and synchronized with `origin/codex/track-g3-release-publishing` when the
final G4.1 checks began. G4.1 changes no source, manifest, workflow, crate edge,
or architecture behavior; this status update records only the release owner's
external bootstrap actions and the corresponding read-only acceptance checks.

After G4.2 was committed as `d4daabd`, G4.3 preparation moved to
`codex/track-g4-release-0.1.1`. Commit `be615a0` contains only the synchronized
`0.1.1` Cargo/npm version surface, lockfile update, npm publish-plan fixture,
and release rationale. Pull request #6 merged that preparation to `main` as
`01f7f39`; the release owner then pushed annotated `v0.1.1` to that exact
merge. Release run #10 failed workflow validation before any job started, so
no GitHub release, registry package, or formula was created. The implementation
checkpoint `bca901a` on `codex/track-g4-release-permissions` repairs the caller
permissions and was clean before this status-only follow-up edit.

Pull request #7 merged the two permission-repair commits to `main` as
`66e5fa2c3bbcf3b8fec41b8b1c7bc17cb3850f7b`; GitHub reported 27 successful
checks, 9 expected skips, no failures, and no conflicts. Task G4.3 recovery
preparation then began from that clean merge on
`codex/track-g4-release-0.1.2`. Commit `0efdca0` contains only the synchronized
`0.1.2` Cargo/npm version surface, lockfile update, npm publish-plan fixture,
and immutable-recovery rationale. No pre-existing user change was present or
modified.

Pull request #8 merged that preparation to `main` as
`1883d61fecc7c48e1ead5e69b47a7862561eb473`; annotated tag `v0.1.2` peels to
that exact merge. Release run #13 failed only when crates.io rate-limited
`vibescan-registry` after accepting the preceding five new crate identities.
The same run had already published all six npm packages and the Homebrew
formula because cargo-dist generated the three channel publishers in parallel.
The release owner authorized the next immutable patch recovery. Branch
`codex/track-g4-release-0.1.3` began from a clean `origin/main` at `1883d61`;
implementation commit `a12499a` contains the synchronized `0.1.3` surfaces,
strict crates.io → npm → Homebrew workflow, bounded 429-only retry and its
negative controls, generated workflow, runbook, and closeout updates. No
pre-existing user change was present or modified.

Pull request #9 merged both reviewed recovery commits to `main` as
`e788b1c139556f979a23fc6e97705bc54fce1cc7`; GitHub reported 27 successful
checks and seven expected release-only skips. Annotated tag object `45e6841`
peels to that exact merge. The initial push named only `refs/tags/v0.1.3`.
Release run #29676514551 completed successfully, and the required unchanged-tag
re-push returned `Everything up-to-date`. The post-run documentation closeout
began from clean `origin/main` at `e788b1c` on
`codex/track-g4-release-0.1.3-closeout`; commit `a9507b2` records the runbook and
G4.3 completion evidence. No pre-existing user change was present or modified.

## Verification history

The detailed, dated per-task verification records (Phases 1–5, Tiers C–E, Tracks F
and G, and the prior-audit baselines) have been moved to
[`docs/STATE-HISTORY.md`](docs/STATE-HISTORY.md) to keep this file focused on current
state. That archive is append-only and preserves the full audit trail; the completion
matrix below summarizes it. New milestone verifications should be appended to the
history file, and this file's matrix, gaps, and next-step sections updated to match.

## Architecture completion matrix

| Architecture area | Status | Evidence and limitation |
|---|---|---|
| Design invariants | Partial / safety core verified | LocalStatic default, own-Supabase URL guard, read-only Tier 0, redacted per-action scope evidence, and no persisted writes are implemented. |
| Post-v1 eight-crate workspace | Phase 4 + F1 complete | The architecture-authorized `vibescan-registry` crate has only its types edge; core is its only application parent. The exact DAG holds across normal, build, dev, target, optional, and feature-activated dependencies. Synthetic controls reject horizontal/direct drift, unauthorized transport parents, OpenSSL/native-tls, and Supabase/Registry feature cross-activation. |
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
| Dependency integrity | v1 §11.0 + Track F complete | Offline npm/Python structural checks remain unchanged. F1 adds deterministic parsed inputs, the separate rustls Registry boundary, explicit consent, and scope vocabulary. F2 adds exact-version local OSV matching, guarded public existence resolution, a nonfatal failure taxonomy, and 24-hour public-data caches. F3 activates the mocked nonexistent-package golden and metrics coverage. The newcomer heuristic remains an explicitly separate deferred follow-up. |
| Reporting | Verified through F2 scope | JSON, SARIF, TTY, and HTML include redacted findings, Network action scope evidence, Registry name-egress disclosure, locations, history context, collection/dedup counters, a derived dedup ratio, exit gates, and deterministic snapshots. A full-pipeline integration test proves raw candidate material reaches neither any renderer nor serialized `ScanResult`; §17.3 permits no full-match mode. Protected actions do not affect finding statistics or gates. |
| CLI/config | Phase 5 + F1 complete | LocalStatic precedence remains defaults < repository TOML < explicitly supplied CLI values. The independent feature-gated `--registry-checks` runtime confirmation cannot be enabled by repository config and does not enable Tier 0 or Tier 1. Named paths retain repository-root handling and operational failures. |
| Security/nonfunctional | Partial overall; Track G complete | Pure-Rust/default transport boundaries remain enforced. The hosted `v0.1.0` release proves the exact five-target matrix, musl-only Linux artifacts, checksums, attestations, and static-link verification. G2 adds the ships-only npm wrapper and green five-platform `npx` matrix. G3 implements fail-closed Cargo/npm publishers, OIDC provenance, and the prebuilt formula. G4.0 selects controlled `@jiayanzeng/vibescan`; G4.1 records the owner-controlled bootstrap; G4.2 passes the reversible preflight. After immutable `v0.1.1` and partial `v0.1.2` evidence, PR #9's `v0.1.3` recovery passed all 19 jobs with strict crates.io → npm → Homebrew sequencing. G4.4 then verified all three installs, six npm provenance statements, all eight crates, six checksums, five attestations, and both rejection controls. Track G is complete. |
| Testing strategy | v1 closeout + Tier E + Track F complete | Exact goldens, clean control, report snapshots, four-way boundary checks, mocked Tier 0/Tier 1/Registry fixtures, source/cache mocks, the Tier D1 scripted real-repository path, committed metrics, deterministic performance counters, and end-to-end redaction pins exist. AstroScout supplied the first genuine D1 coverage record (100.00%, 3 findings, 1 project); the Track F corpus records 14 TP, 0 FP, 0 FN, precision 1.0, recall 1.0, and classification coverage 0.75. No capability-gated corpus fixture remains. |
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

- **Track G complete (G1–G3 and G4.0–G4.4):** the release workspace, exact five-target
  `cargo-dist` matrix, musl Linux cross-builds, checksums, attestations, and
  blocking static-link verification are locally validated and proven by the
  successful hosted `v0.1.0` release. The ships-only npm shim, five exact
  optional platform packages, release packaging job, and five-platform `npx`
  smoke matrix are also verified. G3 now has fail-closed Cargo/npm publishers,
  OIDC provenance wiring, a functional prebuilt Homebrew formula, and a release
  runbook. G4.0 selects controlled `@jiayanzeng/vibescan`, removes the unscoped
  and unavailable organization-scope npm targets, and pins the six personal-
  scope identities in tests. G4.1 verifies the free registry identities and
  completes the owner-controlled account/secret/tap bootstrap. G4.2 passes the
  complete reversible preflight. G4.3's synchronized `0.1.1` release commit was
  merged and tagged, but the workflow failed validation before publication.
  PR #7 merged the generated caller-permission repair. PR #8's `v0.1.2` run
  proved the build, attestation, static-link, npm package/smoke, hosting, npm,
  and Homebrew paths and published five crates before crates.io HTTP 429 stopped
  the sixth. PR #9 merged synchronized `0.1.3` as `e788b1c`, and annotated tag
  `v0.1.3` triggered green Release run #29676514551. All eight crates and all
  six npm packages resolve at `0.1.3`, the formula is current, all five archive
  digests have attestation records, and the unchanged-tag push was a no-op.
  G4.4 then passed all three public install paths, all six npm provenance
  statements, the complete eight-crate graph, all checksums and attestations,
  and both rejection controls. The architecture-named `vibescan-cli` package
  installs the `vibescan` binary; no alias crate or rename is required.
- **Track F complete:** F1 establishes Registry ownership, feature/runtime
  consent, parsing, transport isolation, and auditable output shapes; F2 adds
  the two confirmed checks and bounded privacy-aware caching; F3 activates the
  hallucinated-dependency golden and metrics baseline. The separate npm-only
  `Review` newcomer heuristic remains deferred and off by default; PyPI remains
  blocked on a download-signal decision.
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

### Post-v1 tracks

- Registry checks: Track F is complete—F1's crate/DAG/transport/opt-in/input
  plumbing, F2's two confirmed detections/guards/failure taxonomy/caches, and
  F3's golden plus committed metric activation are all verified. Newcomer
  checks remain a separate, explicitly consented npm-only `Review` mode and
  must not be inferred from `--registry-checks`; PyPI newcomer remains deferred
  pending a download-signal decision.
- Tier 1 introspection/policy analysis: E1 transport/input, E2's four
  mechanically decidable findings, and E3 correlation/fixtures are complete.
  Architecture §17.8 defers the metadata-keyed `Review` heuristic outside the
  confirmed set.
- Distribution: G1's five-target static-binary matrix, checksums, attestations,
  static-link gate, and release workflow are complete and proven by the hosted
  `v0.1.0` release. G2's ships-only npm shim, five exact optional platform
  packages, release packaging integration, and cross-platform smoke matrix are
  complete. G3's local publishers, npm provenance contract, Homebrew formula,
  and runbook are implemented and verified. G4.0 is complete with
  `@jiayanzeng/vibescan` as the controlled personal-scope entry point. G4.1's
  owner-controlled registry/account/tap bootstrap and read-only acceptance
  checks are complete. G4.2's complete reversible preflight is green. G4.3's
  `0.1.1` preparation was merged and correctly tagged, but Release run #10
  failed validation before any job or publication. PR #7 merged the permission
  repair. PR #8's `v0.1.2` run completed every release channel except the final
  three crates after crates.io rate-limited the sixth new identity. PR #9's
  `v0.1.3` recovery added bounded 429-only retry and ordered crates.io → npm →
  Homebrew publication, merged as `e788b1c`, and passed all 19 tagged release
  jobs. All registry identities and the formula are live at `0.1.3`; five
  attestation records exist; the unchanged-tag push was a no-op. G4.3 is
  complete. G4.4 then passed all three public installs, verified provenance for
  all six npm packages, resolved all eight crates, verified the checksum file
  and five attestations, and proved both tamper controls reject. Track G is
  complete. The architecture-named `vibescan-cli` remains the Cargo install
  package and exposes the `vibescan` binary; no ninth alias crate is needed.
- Active DAST/write probes: prohibited in v1, not merely postponed.

## Closeout gate for future milestone claims

Run, record, and reconcile at least:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
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
