# Track G closeout — rollout instructions (G4)

**Status basis:** PR #5 merged to `main` at `cb048b9` (26/26 checks green). This landed the
G3 *publishers, provenance wiring, Homebrew formula, and `RELEASING.md`* onto `main` but
triggered **no publication** — the publishers only fire on a pushed tag, and none was cut.
Track G therefore remains **partially complete**: G1 and G2 are done; G3 is *implemented*
but its *rollout* is at 0%.

This document specifies the remaining rollout as dependency-ordered tasks
(G4.0–G4.4). G4.0 is resolved to `@jiayanzeng/vibescan`. **G4.1 requires the
release owner to perform registry-mutating actions under explicit
authorization** — those are external mutations that must not be inferred from
approval to implement code.

---

## Verified live ground truth (checked 2026-07-19)

| Channel | Expected after rollout | Observed now | Consequence |
|---|---|---|---|
| crates.io | 8 crates incl. `vibescan-types`, `vibescan-cli` | Neither exists (`does not exist`) | First-ever publish; names free to claim on first push |
| npm unscoped `vibescan` | ships-only shim `0.1.x` | **Taken**: `vibescan@0.0.5`, maintainer `tanayvk`, Nuxt-scaffold placeholder, published 2025‑04‑16, `bin.vibescan → dist/cli.js` | **Hard blocker** — the final publish step will 403 |
| npm `@jiayanzeng/vibescan` + 5 platform packages | published, provenance | All six return 404; npm user `jiayanzeng` owns the personal `@jiayanzeng` scope | First-ever publish creates the package identities; no organization is required |
| `jiayanzeng/homebrew-tap` | tap repo + `Formula/vibescan.rb` | Repo 404, formula 404 | Tap not created |
| release tag exercising G3 publishers | new immutable `v0.1.x` | None (`v0.1.0` predates G3) | Publishers have never run |

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
  trusted publishers, and pushing the release tag — are performed by the
  **release owner** only, with explicit authorization. Codex must not perform
  them and must not assume they were done.
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

### Spec basis
`RELEASING.md` runbook; G3 acceptance #1–#3.

### Problem
`v0.1.0` is consumed by the G1 release and its publishers never ran; a *new* immutable tag is
required to exercise the G3 publishers, and it will be the first published version on
crates.io/npm.

### Steps
1. **Version decision (owner):** bump the workspace to the next version. Recommended `0.1.1`
   (distribution-only change, no engine behavior change); record rationale in `RELEASING.md`.
   The five platform packages, six/eight registry identities, and the formula all carry this
   version.
2. Merge the version bump to `main`, create an annotated `v<version>` tag on that merge, push
   **only** the tag.
3. The release workflow builds + attests the five platform archives, verifies static Linux
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

---

## Fail-partial / rollback notes

- If a publisher fails **after** some crates/packages are live, do **not** retry the same version.
  Diagnose, bump to the next patch version, and re-run — published immutable versions stay as-is.
- The single most likely failure is the unscoped `vibescan` publish; G4.0 removes that risk before
  the tag. Do not skip G4.0.
- Homebrew failures are the cheapest to recover (formula-only, no registry immutability); fix the
  tap and re-run the Homebrew publisher without re-publishing crates/npm.

---

## What closes Track G

Track G is fully closed only when, for a single new immutable `v<version>` tag: the engine
matrices are green, all eight crates.io versions resolve and `cargo install vibescan-cli` works,
the npm entry point installs via `npx` with verified provenance, `brew install
jiayanzeng/tap/vibescan` works, and the release carries a verifying `sha256.sum` plus five
verifying Artifact Attestations. Until then, keep Track G marked **partial**. The deferred
DAST/write-probe track (I) remains the only post-v1 work after this, behind the §7.4 ownership
gate.
