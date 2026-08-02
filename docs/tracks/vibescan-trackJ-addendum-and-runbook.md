# vibescan — Track J Addendum (J10–J12) and Merge Runbook

Reviewed: 2026-08-02
Author: architecture review (Claude), for implementation by Codex
Status: **Three small tasks, then merge.** Track J itself is verified complete.

Authority is `vibescan-architecture.md`. This document is a task record, not a
status source; current state lives in `STATE.md`.

---

## Part 1 — Independent verification of Track J

Verified against the refreshed source bundle, not against the closeout prose.
All ten tasks land as specified:

| Task | Evidence checked |
|---|---|
| J0 | `STATE.md` records Track H merged to `main` at `e9390be`; the earlier dirty-tree/clean-tree contradiction is resolved |
| J1 | `# vibescan:current-state` block present, all 19 fields populated; `0.1.3` reduced from 18 references to 1 explicitly-historical; `0.2.0` ×7, `PolyForm` ×3; relicensing recorded as source-available, not open source |
| J2 | Original `routes/` sentence preserved byte-identical at `STATE-HISTORY.md:50`; dated errata at `:53`; preamble rule added at `:9` |
| J3 | No `routes/` outside the archive |
| J4 | `docs/tracks/` holds nine historical documents; `moltbook-teardown.md` gone from `docs/`; `repomix.config.json` ignores `content/**` |
| J5 | `classification_coverage_unknown_set_is_pinned` asserts an exact two-member set (`history-only-elevated-key`, `nested-gitignore`) with per-member rationale; `0.777_777_777_777_777_8` asserted separately |
| J6 | `check-status-consistency.py`, 464 lines, `--self-test`, banned-term list seeded with `routes/`, six check families |
| J7 | Four clippy graphs and four test graphs; `status-consistency` job added |
| J8 | Every workflow declares `permissions:`; **zero** unpinned third-party `uses:` references across all eight workflows, including the `dist`-generated `release.yml` |
| J9 | `verify-all.sh`, nine steps, real-repo leg opt-in and last |

One correction to my earlier reading: J8's `release.yml` fallback was not
needed — `dist` 0.32.0 supports pinned action commits natively, so the pinning
is complete rather than partially deferred. Better outcome than the instruction
anticipated.

**Three residual gaps found during this pass.** They are the tasks below.

---

## Task J10 — Repomix output hygiene

### Spec basis
Architecture §1.5 (all output redacted; nothing raw leaves the candidate
phase). Root `AGENTS.md`: never copy real secrets into the repository. J4's
untracked-file discipline.

### Problem statement
`.gitignore` contains no repomix entry, and `*.xml` is not otherwise ignored,
so `repomix-output.xml` — roughly 1.2 MB containing a verbatim copy of the
entire repository — is an untracked file that reappears on every audit bundle
and is one `git add -A` away from being committed.

The severity is raised by `repomix.config.json`, which sets
`security.enableSecurityCheck: false`. That setting is almost certainly correct
here (the fixtures and `default-rules.toml` are full of deliberately
credential-shaped synthetic strings that repomix would otherwise redact,
corrupting the bundle) — but it is undocumented, so the repository currently
reads as a security scanner shipping with its bundler's secret scanning turned
off and no stated reason.

Committing a security-check-disabled full-source dump would be a self-inflicted
instance of exactly the failure class vibescan exists to detect.

### File targets
- `.gitignore`
- `repomix.config.json`
- `scripts/check-status-consistency.py`
- `scripts/AGENTS.md`

### Implementation guidance
**(a)** Add to `.gitignore`, under a clearly labelled section:

```
# Repomix audit bundles (full-source dumps; never committed)
repomix-output.*
.repomix/
```

Use the unanchored pattern so a bundle generated from a subdirectory is also
caught.

**(b)** Pin the output path in `repomix.config.json` (`output.filePath`) so the
generated filename cannot drift away from the ignore pattern. Do not change
`enableSecurityCheck`; do not remove the existing `content/**` ignore.

**(c)** Add a seventh check to `check-status-consistency.py`: no tracked file
matches the repomix bundle pattern. Derive the tracked set from
`git ls-files`; skip with a clear message when git metadata is unavailable, in
the same style as the existing `head_commit` check. Extend `--self-test` with
both directions.

**(d)** Document in `scripts/AGENTS.md` why `enableSecurityCheck` is disabled —
that the repository intentionally contains synthetic credential-shaped strings
in fixtures and the default ruleset, that redaction would corrupt an audit
bundle, and that the compensating control is that bundles are never committed.
JSON cannot carry the comment, so this is where it lives.

### Acceptance criteria (self-verifiable)
1. `git check-ignore -v repomix-output.xml` names the new rule; the same holds
   for `repomix-output.md` and `sub/dir/repomix-output.xml`.
2. Generating a bundle leaves `git status --porcelain` empty.
3. `python3 scripts/check-status-consistency.py --self-test` passes with the
   new check's pass and fail cases.
4. **Negative control:** `git add -f repomix-output.xml`, confirm the checker
   exits 1 and names the tracked bundle path, then `git rm --cached` it and
   prove `git status --short` is clean.
5. `repomix.config.json` parses as JSON and still ignores `content/**`.

---

## Task J11 — Close the status-gate blind spot

### Spec basis
Root `AGENTS.md`, "Definition of done and status reporting." Task J6's purpose:
convert status drift from an audit finding into a machine gate.

### Problem statement
`check-status-consistency.py` validates `workspace_version`, `license`, the
corpus metrics, `head_commit` ancestry, banned terms, and that
`integration_status` is one of three permitted **tokens** — but it never checks
that the token is *true*.

That field motivated the gate. Today `STATE.md` says
`integration_status: committed-not-merged`; it becomes false the moment the
recorded commit merges, and every earlier check in the suite will still pass.
The gate has a hole at the post-merge transition it is meant to enforce.

The final Track J closeout removed J11's original `branch` assertion as an
authorized correction. A branch name is contextual checkout state rather than
durable status, and comparing it with the active checkout prevented this
reconciliation from passing on a pull-request branch. Git already exposes the
active branch; `integration_status` retains the durable ancestry assertion.

### File targets
- `scripts/check-status-consistency.py`

### Implementation guidance
Add an **`integration_status` truth** check, skipping cleanly when git metadata
or `origin` is unavailable:

- `merged` requires `git merge-base --is-ancestor <head_commit> origin/main`
  to succeed;
- `committed-not-merged` requires that same command to **fail** while
  `git cat-file -e <head_commit>` succeeds;
- `working-tree-only` requires `head_commit` not to resolve, or a dirty tree.

A token that contradicts the repository is an error naming both the claim and
the observed fact.

Extend `--self-test` with pass and fail cases. Keep the checker
offline: `git merge-base` reads local refs only; do not add a fetch.

### Acceptance criteria (self-verifiable)
1. `--self-test` passes, covering four new directions.
2. The real check passes on the current branch with
   `integration_status: committed-not-merged`.
3. **Negative control A:** set `integration_status: merged` while unmerged;
   the checker exits 1 and names the contradiction. Revert.
4. In a shallow checkout with no `origin/main`, the checker skips the new
   truth check with an explicit message and exits 0.
5. No network access is performed.

---

## Task J12 — Put the release-channel structural verifier on the PR path

### Spec basis
Architecture §13.1 (five-target matrix, publish order, provenance).
`scripts/AGENTS.md`: distinguish a smoke helper from the full closeout matrix.

### Problem statement
`scripts/verify-release-publishing.py` is an offline, deterministic verifier of
the release-channel contract — publish order across the eight crates, the npm
package identity, the tap, and the **required permissions on the publish
jobs**. It runs only in `npm-smoke.yml`, which is not on the pull-request path,
and it is absent from `verify-all.sh`.

J8 just edited permissions and action references across all eight workflows.
The one check that would catch a regression in that exact surface does not run
when those files change.

### File targets
- `scripts/verify-all.sh`
- `.github/workflows/ci.yml`

### Implementation guidance
Insert `python3 scripts/verify-release-publishing.py` into `verify-all.sh` as a
numbered step alongside the other offline structural gates — after the
Network-boundary matrix, before the status-consistency gate — preserving the
existing banner and fail-fast conventions. Add a matching CI job so the check
runs on every pull request, not only on the release path.

Do not modify the verifier itself. If it fails on the current checkout, that is
a finding about J8's workflow edits, not a reason to adjust the script — stop
and report.

> **Execution note (2026-08-02):** the preflight did stop here because the
> verifier still required the mutable `rust-lang/crates-io-auth-action@v1`
> spelling after J8 pinned that action to a commit SHA. The user explicitly
> authorized correcting the stale assertion. The verifier now requires the
> same action identity with an immutable 40-character SHA and its `v1.x.y`
> release comment; the workflow remains SHA-pinned.

### Acceptance criteria (self-verifiable)
1. `bash scripts/verify-all.sh` passes with the new step, offline.
2. The new CI job appears in `ci.yml` and the file parses as YAML.
3. **Negative control:** temporarily remove one required permission key from a
   publish job; confirm the verifier fails and names it; confirm
   `dist generate --check` behavior is unaffected by the revert. Restore and
   prove a clean `git diff`.
4. `shellcheck scripts/verify-all.sh` stays clean.

---

## Part 2 — Merge runbook

Ordered, with the human-intervention points marked. Everything unmarked is
Codex-executable.

### Step 1 — Land J10–J12 on the existing branch
Execute the three tasks above on `codex/track-j-assurance-hygiene`. Commit
separately from `b08f693` and `eccbee5` so the addendum is reviewable on its
own.

### Step 2 — Re-run the canonical matrix
```sh
bash scripts/verify-all.sh
dist generate --check
shellcheck scripts/verify-all.sh
```
J10 and J12 both touch inputs the matrix consumes, so a green run before Step 1
does not carry forward. Judge `dist` by exit code — a shasum warning in its
output is benign.

### Step 3 — Refresh the status block
`head_commit` in `STATE.md` still points at `b08f693`. Update it to the new tip
and re-run `check-status-consistency.py`. With J11 in place, a false
`integration_status` now fails the gate rather than passing quietly.

### Step 4 — Push and open the PR
```sh
git push -u origin codex/track-j-assurance-hygiene
gh pr create --fill
```
If `gh` is unavailable, print the compare URL and stop — the established
degradation path.

### Step 5 — Merge *(human)*
Review and merge through the GitHub UI. This is the one irreversible action in
the runbook and stays with the release owner.

### Step 6 — Post-merge status reconciliation
Set `integration_status: merged` and `head_commit` to the merge commit; re-run
`check-status-consistency.py`. J11 makes this step enforced rather than
remembered — the gate now fails if it is skipped.

### Step 7 — Convert one remaining assumption into evidence *(optional)*
`STATE.md` states plainly that `released_version: 0.2.0` was taken from the
workspace manifests because J0 did not query public channels. Resolve it with
read-only GETs against the eight crates.io endpoints and the six npm endpoints,
using an identifying user agent — anonymous crates.io requests return a uniform
403 that is not evidence, as G4.1 recorded. Under the Shadow Rocket proxy, any
npm-side leg needs `NODE_EXTRA_CA_CERTS=/etc/ssl/cert.pem`. Then either confirm
`released_version` or correct it.

### Step 8 — Re-bundle for the next audit
Regenerate the repomix bundle after merge so the next review reads the merged
tree. Post-J10 it will be ignored automatically rather than sitting untracked.

---

## Part 3 — What comes after Track J

No track is *open* after this merges. The three candidates, in the order I would
take them:

1. **Intra-crate module decomposition (proposed Track K).** Every crate remains
   a single `src/lib.rs`: core 4,882 lines, supabase 2,882, git 1,852, registry
   1,539. The crate DAG is the project's strongest structural asset and there
   is no structure at all inside it. This is now the largest remaining
   maintainability liability and the thing most likely to make a future
   contributor — or a future Codex session — reason wrongly about the code. It
   needs its own instruction document, must be behavior-preserving, and is
   pinned by the golden corpus, the report snapshots, and the metrics baseline.
   Do it before, not after, anything that adds behavior.

2. **Corpus false-positive pressure (proposed Track L).** Precision 1.0 and
   recall 1.0 across twelve self-authored fixtures is a saturated metric — it
   can only move down and no longer discriminates. J5 pinned the coverage
   ceiling honestly, which makes the saturation visible rather than fixing it.
   The remedy is a much larger clean-control population and continued D1
   real-repository sampling, currently n=1. This is design work needing
   decisions, not mechanical execution.

3. **Track I.** Unchanged: gate 1 (design ratification) is drafted, gate 2
   (concrete user demand) is not met. Nothing in Tracks H or J moves it, and it
   should stay unbuilt.

The honest ordering is K, then L, then nothing until real usage produces a
signal. Track J removed the excuses for status drift; Track K would remove the
excuses for structural drift.
