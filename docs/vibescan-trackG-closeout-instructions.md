# Track G closeout — rollout instructions (G4)

**Status basis:** PR #5 merged the G3 publishers, provenance wiring, Homebrew
formula, and `RELEASING.md` to `main` at `cb048b9` (26/26 checks green). Its
initial rollout was 0% because publishers fire only on a tag. G4.3 is now
complete through immutable tag `v0.1.3` and green Release run #29676514551.
G4.4's install, provenance, checksum, attestation, and negative-control
verification passed on 2026-07-19. Track G is **complete**.

This document specifies the remaining rollout as dependency-ordered tasks
(G4.0–G4.4). G4.0 is resolved to `@jiayanzeng/vibescan`. G4.1's explicitly
owner-controlled identity/credential/tap bootstrap and G4.2's reversible local
preflight are complete as of 2026-07-19. PR #6 merged the `0.1.1` preparation
to `main` as `01f7f39`, and the release owner pushed annotated tag `v0.1.1` to
that exact merge. Tagged Release run #10 failed workflow validation before any
job, artifact, GitHub release, registry publication, or formula update ran:
the generated caller denied `contents: read` to both reusable publisher
workflows. Pull request #7 merged commit `bca901a` plus its status record to
`main` as `66e5fa2`; all 36 hosted checks passed. PR #8 then merged the
synchronized `0.1.2` recovery and annotated tag `v0.1.2` points to merge
`1883d61`. Release run #13 built and hosted every artifact, published all six
npm packages and the Homebrew formula, and published the first five crates;
crates.io rate-limited the sixth new crate identity with HTTP 429. The tag is
immutable, so PR #9 prepared synchronized `0.1.3`, bounded 429-only Cargo retry,
and strict crates.io → npm → Homebrew sequencing. PR #9 merged as `e788b1c`;
annotated tag `v0.1.3` peels to that merge. Release run #29676514551 passed all
19 jobs end to end, and the unchanged-tag re-push was a no-op. G4.3 is complete;
G4.4 subsequently passed every post-publish acceptance check and closes Track G.

---

## Verified live ground truth (checked 2026-07-19)

| Channel | Expected after rollout | Observed now | Consequence |
|---|---|---|---|
| crates.io | 8 crates incl. `vibescan-types`, `vibescan-cli` | All eight resolve at `0.1.3` | Complete bottom-up publication proves registry dependency resolution |
| npm unscoped `vibescan` (excluded) | not published by vibescan | **Taken**: `vibescan@0.0.5`, maintainer `tanayvk`, Nuxt-scaffold placeholder, published 2025‑04‑16, `bin.vibescan → dist/cli.js` | Not in the approved publish plan; no longer a blocker |
| npm `@jiayanzeng/vibescan` + 5 platform packages | published, provenance | All six resolve at `0.1.3` | Published only after the complete crates.io job succeeded |
| `jiayanzeng/homebrew-tap` | tap repo + `Formula/vibescan.rb` | `Formula/vibescan.rb` is live at `0.1.3` | Updated only after npm succeeded |
| release tag exercising G3 publishers | new immutable `v0.1.x` | `v0.1.3` points to `e788b1c`; Release run #29676514551 passed all 19 jobs | G4.3 complete; retain `v0.1.1`/`v0.1.2` as immutable failure evidence |
| post-publish verification | all three installs, npm provenance, checksums, five attestations, two rejection controls | All passed for `v0.1.3` on 2026-07-19 | G4.4 and Track G complete |

**Exact identities the publishers target:**

- crates.io, publish bottom-up: `vibescan-types` → `vibescan-secrets` → `vibescan-git` →
  `vibescan-report` → `vibescan-supabase` → `vibescan-registry` → `vibescan-core` →
  `vibescan-cli`.
- npm, publish platform-first then the main package:
  `@jiayanzeng/vibescan-darwin-arm64`, `@jiayanzeng/vibescan-darwin-x64`,
  `@jiayanzeng/vibescan-linux-arm64-musl`,
  `@jiayanzeng/vibescan-linux-x64-musl`,
  `@jiayanzeng/vibescan-win32-x64-msvc`, then `@jiayanzeng/vibescan`.
- Homebrew: formula `vibescan.rb` published to `jiayanzeng/homebrew-tap`.

---

## Authorization & safety boundary

- **Read-only registry queries** (existence/ownership/provenance checks) are permitted and are
  the basis for the acceptance criteria below.
- **Registry-mutating actions** — claiming crate names, publishing the first npm
  package versions, creating the tap repo, configuring bootstrap secrets and
  trusted publishers, and pushing the release tag — require explicit,
  request-scoped authorization from the **release owner**. G4.3's user request
  supplied that authorization for the version merge and one exact tag push;
  secret/account mutations remain outside that authorization.
- **Immutability:** crates.io versions cannot be overwritten or (after 72h / once depended-on)
  unpublished; npm unpublish is likewise constrained. The ordering below front-loads the
  reversible dry-runs (G4.2) *before* the irreversible tag (G4.3) precisely because a partial
  release is expensive to undo.

---

## Task dependency order

```
G4.0 (DECISION: npm name)  ──►  G4.1 (identity bootstrap)  ──►  G4.2 (pre-flight dry-run gate)
                                                                        │
                                                                        ▼
                                                     G4.3 (version bump + tag)  ──►  G4.4 (post-publish verify)
```

Do not start G4.1 until G4.0 is decided; do not cut the tag in G4.3 until G4.2 is green.

---

## Task G4.0 — DECISION GATE: resolve the unscoped `vibescan` npm name

### Spec basis
§13.1 primary channel: the release-owner-controlled
`npx @jiayanzeng/vibescan` entry point for the JS-native audience. §13.4 npm
packaging.

### Problem
The unscoped `vibescan` npm name — the original target of `npx vibescan` — is
owned by a different account. Before G4.0 was corrected, a tagged release would
have published the five platform packages and then attempted the foreign
unscoped name, failing with 403 after scoped packages and crates were already
live and immutable. The approved personal-scope identity removes that failure
path before any tag is cut.

### Decision (release owner) — approved 2026-07-19
1. **Controlled personal-scope entry point (selected).** Make
   `@jiayanzeng/vibescan` the user entry point: `npx @jiayanzeng/vibescan`.
   The `jiayanzeng` user account automatically owns `@jiayanzeng`; do not create
   an organization and do not convert the user account into one. No third party
   is on the critical path.
   - Implies: promote the shim in `npm/vibescan/` to a scoped main package (e.g.
     `@jiayanzeng/vibescan`) that keeps the `bin.vibescan` and the exact-version `optionalDependencies`
     on the five platform packages; remove the unscoped `vibescan` publish step from
     `publish-packages.mjs`; update `README`, npm fallback text, `RELEASING.md`, and §13.1's
     `npx vibescan` wording to `npx @jiayanzeng/vibescan`.
   - Note: §13.1's `npx vibescan` phrasing is a **decision-gated** edit and is intentionally not
     touched by the P2 status-debt patch; apply it here only if this option is chosen.
2. **Acquire the unscoped name.** File an npm name dispute (the incumbent is a single `0.0.5`
   placeholder with a Nuxt-scaffold description, no repository, no homepage) and/or contact the
   maintainer for transfer. Keeps `npx vibescan`, but the timeline and outcome are outside your
   control; do not gate the release on it unless acquired.
3. **Alternate unscoped name.** Pick an available unscoped name and repoint the main package and
   all docs. Keeps a bare `npx <name>` UX at the cost of the `vibescan` brand on npm.

### Acceptance criteria
1. A written decision (1–3) is recorded in `RELEASING.md`.
2. If (1): `npm/` no longer publishes an unscoped `vibescan`; `publish-packages.mjs --print-plan`
   shows `@jiayanzeng/vibescan` last, five platform packages first; all
   user-facing docs say `npx @jiayanzeng/vibescan`; `npm --prefix npm test` and
   `node npm/scripts/verify-packages.mjs` pass.
3. If (2): ownership of `vibescan` is confirmed by a read-only query returning the owner as the
   release account **before** G4.3; otherwise fall back to (1)/(3).
4. Negative control: no code path publishes an unscoped name the release account does not own —
   demonstrated by `publish-packages.mjs --print-plan` naming only owned identities.

---

## Task G4.1 — External identity bootstrap (owner-authorized, dependency-ordered)

**Status:** complete on 2026-07-19; see `STATE.md` for the owner confirmations
and read-only acceptance evidence. No secret value was inspected or recorded.

### Spec basis
§13.1 secondary channels (`cargo install`, Homebrew); §13.4 npm; G3 acceptance #1–#3.

### Problem
No crate names, npm packages, or tap repo exist yet. The `jiayanzeng` npm user
and its personal `@jiayanzeng` scope exist, but the trusted-publishing /
bootstrap credentials are unset, so a tag would fail immediately.

### Actions (release owner, in this order)
1. **crates.io.** Reserve/own the 8 crate names (first publish in G4.3 claims them, but confirm no
   name is squatted). Configure either a one-time bootstrap `CARGO_REGISTRY_TOKEN` secret or the
   crates.io trusted-publisher (OIDC) binding to `release.yml`.
2. **npm.** Use the existing `jiayanzeng` user and its personal `@jiayanzeng`
   scope; do not create an organization or convert the user account. Confirm
   `npm whoami` returns `jiayanzeng`, enable two-factor authentication, and
   configure the existing `id-token: write` provenance path plus a short-lived
   bootstrap `NPM_TOKEN` if the first publication requires it. The first publish
   creates `@jiayanzeng/vibescan` and the five platform package identities;
   after they exist, configure trusted publishing for each package and remove
   the bootstrap token.
3. **Homebrew.** Create `jiayanzeng/homebrew-tap` (public), with the layout `dist` writes to
   (`Formula/`). Grant the release workflow push access (token/app) to that repo.

### Acceptance criteria (read-only, self-verifiable)
1. `GET https://crates.io/api/v1/crates/<name>` for all 8 either 404 (free to claim) or resolve
   to the release owner — none resolve to a foreign owner.
2. `npm whoami` returns `jiayanzeng`; before first publication, all six exact
   `GET https://registry.npmjs.org/@jiayanzeng%2F<vibescan-name>` requests
   return 404 rather than resolving to a foreign owner. After first publication,
   they resolve with `jiayanzeng` as a maintainer.
3. `GET https://github.com/jiayanzeng/homebrew-tap` returns 200 (repo exists).
4. Required secrets/OIDC bindings are present in repo settings (owner confirms; not logged).
5. Negative control: none of the target identities is owned by a third party at tag time.

---

## Task G4.2 — Pre-flight dry-run gate (reversible, before the immutable tag)

**Status:** complete on 2026-07-19 at commit `0781869`; see `STATE.md` for the
commands, negative-control result, and clean final worktree.

### Spec basis
G3 acceptance #1 (`--dry-run` / `cargo publish --dry-run` chain), #4 (runbook), #5 (engine green).

### Problem
The only irreversible step is the tag. Everything provable without mutating a registry must pass
first so a real release cannot fail halfway.

### Steps (run on the release commit, clean tree)
```sh
# engine + boundaries unchanged by distribution
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --features network --locked -- -D warnings
cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --features network --locked
cargo test --workspace --features registry --locked
cargo test --workspace --features network,registry --locked
bash scripts/check-network-boundary.sh

# publisher contracts, no mutation
bash scripts/publish-crates.sh --dry-run
# `target/npm-packages` is generated output; begin with it absent or empty so
# exact-file verification cannot mix prior versions or package identities.
node npm/scripts/build-packages.mjs --artifacts target/distrib --out target/npm-packages
node npm/scripts/verify-packages.mjs --packages target/npm-packages
node npm/scripts/publish-packages.mjs --packages target/npm-packages --print-plan
npm --prefix npm test
python3 scripts/verify-release-publishing.py
dist generate --check
dist plan --output-format=json
ruby -c target/distrib/vibescan.rb
```

### Acceptance criteria
1. Every command above exits 0.
2. `--print-plan` names only identities owned per G4.1 and reflects the G4.0 decision (unscoped
   `vibescan` absent unless owned).
3. Crate dry-run lists all 8 crates in dependency order with no unresolved-dependency error.
4. `dist plan` enumerates exactly the five platform archives + the tap formula.
5. Negative control: an intentionally malformed platform manifest makes `verify-packages.mjs`
   fail (proves the check is live), then is reverted.

---

## Task G4.3 — Version bump and tag (owner-authorized, irreversible)

**Status:** complete as of 2026-07-19. PR #6 merged the `0.1.1`
release preparation as `01f7f39`, and annotated tag `v0.1.1` points to that
exact merge. Release run #10 failed workflow validation before any job or
publication because both reusable publisher calls were denied
`contents: read`. PR #7 merged the supported cargo-dist permission repair to
`main` as `66e5fa2`, with all 36 checks passing. PR #8 merged `0.1.2` as
`1883d61`, and the annotated `v0.1.2` workflow published npm, Homebrew, and the
first five crates before crates.io returned HTTP 429 for `vibescan-registry`.
Do not move or reuse `v0.1.1` or `v0.1.2`. PR #9 merged synchronized `0.1.3`
with bounded crates.io 429 retry and strict crates.io → npm → Homebrew
sequencing as `e788b1c`. Annotated tag `v0.1.3` peels to that merge. Release run
[#29676514551](https://github.com/jiayanzeng/vibescan/actions/runs/29676514551)
passed all 19 jobs, and the required unchanged-tag re-push was a no-op.

### Spec basis
`RELEASING.md` runbook; G3 acceptance #1–#3.

### Problem
`v0.1.0` is consumed by the G1 release and its publishers never ran. `v0.1.1`
failed before jobs, while `v0.1.2` partially published before crates.io's
new-crate rate limit stopped the dependency chain. A new immutable tag is
required to complete all eight crates and prove the publishers end to end.

### Steps
1. **Version decision (owner):** after the partially published immutable
   `v0.1.2` attempt, bump the workspace to `0.1.3` (distribution-only recovery,
   no engine behavior change) and record the rationale in `RELEASING.md`. The
   five platform packages, all eight crates, all six npm identities, and the
   formula carry `0.1.3`.
2. Pin the observed failure mode: retry only an explicit crates.io HTTP 429 with
   a bounded delay, fail closed on every other publication error, and sequence
   crates.io → npm → Homebrew so downstream channels cannot publish after an
   upstream failure.
3. Merge the version bump to `main`, create an annotated `v<version>` tag on that merge, push
   **only** the tag.
4. The release workflow builds + attests the five platform archives, verifies static Linux
   linkage, packages and smoke-tests the npm tarballs, creates the GitHub release, then runs the
   crates.io → npm → Homebrew publishers in order.

### Acceptance criteria
1. The tagged workflow run is green end-to-end; the crates.io job resolves every dependency at
   publish time (this is the first real proof of registry resolution).
2. The GitHub release contains the five platform archives, source archive, `sha256.sum`, and five
   Artifact Attestations.
3. No publisher step 403s (validates G4.0/G4.1).
4. Negative control: re-pushing the same tag / re-running publish is rejected or no-ops (no
   duplicate/downgrade publish).

### Completion evidence

- PR #9's 27 hosted checks passed, with seven expected release-only skips, and
  merged as `e788b1c139556f979a23fc6e97705bc54fce1cc7`.
- Annotated tag object `45e6841` peels to that exact merge. The initial push
  sent only `refs/tags/v0.1.3`; repeating the same push returned
  `Everything up-to-date` and triggered no duplicate workflow.
- Release run #29676514551 completed all 19 jobs successfully. The Cargo job
  finished before npm began, and npm finished before Homebrew began. No
  publisher returned 403.
- The [GitHub release](https://github.com/jiayanzeng/vibescan/releases/tag/v0.1.3)
  contains `source.tar.gz`, `sha256.sum`, and exactly five platform archives.
  Each platform digest returns exactly one record from GitHub's public
  attestations API, and every build job's `Attest` step succeeded.
- Public registry reads resolve all eight crates and all six approved npm
  identities at `0.1.3`; `Formula/vibescan.rb` declares `version "0.1.3"`.

---

## Task G4.4 — Post-publish verification across all three channels

### Spec basis
G3 acceptance #1–#3; `RELEASING.md` "Verify a release".

### Steps (read-only, after G4.3)
```sh
# npm
npx @jiayanzeng/vibescan@<version> --version
npm audit signatures                           # provenance verified

# cargo (architecture-named package installs the `vibescan` binary)
cargo install vibescan-cli --version <version> --locked
vibescan --version

# homebrew
brew install jiayanzeng/tap/vibescan
vibescan --version

# artifacts
shasum -a 256 -c sha256.sum
gh attestation verify <archive> \
  --repo jiayanzeng/vibescan \
  --signer-workflow jiayanzeng/vibescan/.github/workflows/release.yml
```

### Acceptance criteria
1. All three install commands yield a working `vibescan <version>`.
2. All six npm package pages (or the scoped set per G4.0) show provenance linked to the tagged
   `release.yml` run; `npm audit signatures` reports verified signatures.
3. All eight crates.io versions resolve; `cargo install vibescan-cli` pulls the full graph.
4. The tap contains `Formula/vibescan.rb` at `<version>` and installs the prebuilt binary with no
   Rust toolchain.
5. `sha256.sum` verifies and all five attestations verify to `release.yml@refs/tags/v<version>`.
6. Negative controls: a tampered archive fails `gh attestation verify`; a wrong checksum fails
   `shasum -c`.

### Completion evidence (2026-07-19)

- An isolated `npx @jiayanzeng/vibescan@0.1.3 --version` returned
  `vibescan 0.1.3`. A temporary all-platform audit project installed the six
  exact scoped packages and `npm audit signatures` reported six verified
  registry signatures and six verified attestations. Each decoded SLSA
  statement names `jiayanzeng/vibescan`, `.github/workflows/release.yml`,
  `refs/tags/v0.1.3`, merge `e788b1c`, and Release run #29676514551.
- `cargo install vibescan-cli --version 0.1.3 --locked` in an isolated Cargo
  home/root produced `vibescan 0.1.3`. A second install with the optional
  `registry` feature resolved and compiled all eight `vibescan-*` crates at
  `0.1.3`, proving the complete published workspace graph.
- `brew install jiayanzeng/tap/vibescan` installed the prebuilt arm64 archive
  and returned `vibescan 0.1.3`. The live formula declares `version "0.1.3"`,
  has no dependencies, and installs the shipped binary without Cargo or a Rust
  toolchain. The verification-only local install and tap were removed afterward.
- All six entries in `sha256.sum` verified. macOS `shasum` also warned about
  cargo-dist's trailing blank line, but returned zero and marked every listed
  archive `OK`.
- A checksum-verified GitHub CLI verified all five platform archives against
  GitHub's public Sigstore bundles while enforcing `release.yml`,
  `refs/tags/v0.1.3`, and source digest `e788b1c`.
- The required negative controls passed: a one-byte temporary archive was
  rejected by `gh attestation verify`, and a deliberately wrong checksum was
  rejected by `shasum -c`.

---

## Fail-partial / rollback notes

- If a tagged workflow fails validation before any job starts, publish nothing,
  preserve the failed tag as immutable evidence, fix the workflow on `main`,
  and use the next patch version. Re-running the old workflow or moving its tag
  cannot incorporate the fixed workflow definition.
- If a publisher fails **after** some crates/packages are live, do **not** retry the same version.
  Diagnose, bump to the next patch version, and re-run — published immutable versions stay as-is.
  Release run #13 is the concrete example: its first five crates, six npm
  packages, Homebrew formula, release assets, and attestations remain at
  `0.1.2`, while the complete recovery moves to `0.1.3`.
- The single most likely failure is the unscoped `vibescan` publish; G4.0 removes that risk before
  the tag. Do not skip G4.0.
- Homebrew failures are the cheapest to recover (formula-only, no registry immutability); fix the
  tap and re-run the Homebrew publisher without re-publishing crates/npm.

---

## What closes Track G

Track G is fully closed for immutable tag `v0.1.3`: the engine matrices are
green, all eight crates.io versions resolve, `cargo install vibescan-cli`
works, the npm entry point installs via `npx` with six verified provenance
statements, `brew install jiayanzeng/tap/vibescan` works, and the release has a
verifying `sha256.sum` plus five verifying Artifact Attestations. The deferred
DAST/write-probe track (I) remains behind the §7.4 ownership gate.
