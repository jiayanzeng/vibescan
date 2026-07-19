# vibescan — Post-v1 Roadmap (after Tier D)

Reviewed: 2026-07-18
Author: architecture review (Claude)

## Where this picks up

Tier D closed v1: **D1 (real-repo validation), D2 (precision/recall
harness), D3 (performance counters), and D4 (ratified §17 decisions) have all
landed.** Architecture §15 step 9 — "buildable v1, proven" — is complete.
Tier E has since landed the opt-in credentialed introspection track and its two
mock-catalog fixtures. Track F has also landed the independent Registry egress
class, its two confirmed detections, and the final corpus fixture. The remaining
tracks below are post-v1 work that was deferred on purpose (§15, §16).

This is a **roadmap, not a Codex instruction set.** Each track is large enough to
need its own dependency-ordered instruction document (the `vibescan-tierX-
instructions.md` format) before implementation. What this file does: name the
tracks, sequence them, state what each unblocks, and flag which need an
**architecture decision first** versus which are ready to spec directly. As
always, `vibescan-architecture.md` is the authority; where a track needs a
decision, that decision is a spec patch, reviewed before any code.

## The five tracks at a glance

| Track | What it is | Unblocks | Decision-first? | Depends on |
|---|---|---|---|---|
| **H** | Resolve §17 `src/api/` classification | Coverage-metric accuracy | No — *evidence-gated* | Tier D (D1+D2 coverage data) |
| **E (complete)** | Tier 1 credentialed introspection (§7.2) | `rls-off-table`, `permissive-using-true-policy` fixtures; the deep RLS moat | Resolved and implemented in Tier E | v1 proven |
| **F (complete)** | Registry egress + `vibescan-registry` (§11.1–§11.2) | `hallucinated-dependency` fixture; high-confidence OSV/nonexistent-package detection | Resolved and implemented in Track F | v1 proven |
| **G** | Distribution pipeline (§13.1) | `npx @jiayanzeng/vibescan`; the actual npm-native audience | Release-owner personal-scope entry point selected in G4.0; rollout remains dependency-gated | v1 proven (parallel) |
| **I** | DAST / write-probe (§7.3, §7.4) | Active write-exposure proof | Yes — security design + ownership gate | Everything; far future |

Original recommended order was **H (fast-follow) → E and G in parallel → F → I
(much later)**. Tiers E and F are now complete; H remains evidence-gated, while
G and I retain their ordering constraints below.

---

## Track H — Resolve the §17 `src/api/` open question (fast-follow)

**Why first, and why small.** §17 left exactly one question open on purpose:
`src/api/` classifies as `ServerOnly`, but in many Vite/Next frontends `src/api/`
is a *client-side* wrapper that ships to the browser with the publishable key and
table names in it. I refused to guess and said: measure it. Tier D produces the
measurement — D2's original baseline reported `coverage: 0.6`; Tier E3
recomputed the expanded corpus at `0.75` because it added three classified
policy advisories, while the original two `Unknown` paths remain. D1 emits a
real-repo coverage number. H is where that evidence is cashed in.

**The work.** After a handful of real Next.js/Supabase repos have been run
through D1's `real-repo-invariants.py`, inspect the paths that classify `Unknown`
or `ServerOnly` but ship to the browser. Then pick one of three resolutions and
patch §6.2 accordingly:
1. Keep `src/api/` → `ServerOnly` (if real repos rarely put client wrappers
   there);
2. Flip to `ClientReachable` (if they usually do);
3. Add a disambiguating signal — e.g. a server-runtime import (`next/server`,
   `node:*`) or a `"use server"` directive pushes `ServerOnly`, otherwise
   `ClientReachable`.

**Grain.** A small, evidence-gated §6.2 patch plus classifier tests and a
coverage-metric assertion — closer to a Tier C task than a full track. It can
remain an independent evidence-gated patch. It is listed first because it is
cheap, it directly sharpens the headline metric, and its input has existed since
Tier D landed.

**Decision-first?** No — the decision *is* the evidence. Do not resolve it on
intuition; that is the whole point of §17's open-question framing.

---

## Track E — Tier 1 credentialed introspection (§7.2) — complete

**Delivered value.** This is the deepest part of the moat. Tier 0 proves a table
is readable; Tier 1 proves *why* RLS is broken — and catches failures Tier 0
structurally cannot: RLS-theater (enabled but `USING (true)`), missing-operation
policies, and inferred write-exposure. The noisy user-writable-metadata heuristic
is intentionally deferred by §16/§17.8. Tier E un-gated the RLS-off and
permissive-policy fixtures, both now live.

**Implemented scope** (specified in §7.2 / §10.2):
- A credentialed transport in `vibescan-supabase` under `--features network` —
  the same rustls-backed, nearest-parented pattern the Tier 0 probe already uses.
  The Tier E implementation uses a DB connection string **from local env only**
  because the required `pg_catalog` policy definitions are not exposed through
  PostgREST; the broader §7.2 credential wording remains an architecture-owner
  clarification rather than an implementation-document override.
- Per-table `rowsecurity` introspection; per-policy `USING` / `WITH CHECK`
  extraction.
- Distinct `Confirmed` findings: RLS disabled; permissive `USING (true)`;
  missing-operation policy; and inferred write-exposure from grants plus an
  absent restricting policy — **inferred, never demonstrated**, per §7.3. The
  noisy user-writable-metadata heuristic remains deferred by §16/§17.8.
- The two Tier 1 fixtures were un-gated under the `network` feature, and the D2
  precision/recall corpus was extended to include them.

**Resolved implementation choices.** The Tier E instruction set selects a
direct, sync, pure-Rust/rustls PostgreSQL connection and a distinct
`--rls-tier1-introspect` runtime opt-in. Credentials remain env-only and the
transport rejects non-Supabase DB hosts before connecting.

**Status.** E1 transport/input plumbing, E2 catalog detections, and E3
correlation/fixture activation are complete. The two Tier 1 fixtures are live
under `--features network`, and the precision/recall baseline includes them.

---

## Track F — Registry egress and the `vibescan-registry` crate (§11.1) — complete

**Why after E.** It un-gates the *last* corpus fixture
(`hallucinated-dependency`) and adds high-signal dependency intelligence, but it
is lower value than Tier 1. Architecture §11.2 now resolves the mechanism that
§11.1 originally left open.

**The work** (§11.1 is the contract every clause of which is mandatory before any
of it ships):
- A new `vibescan-registry` crate that is the nearest parent of its HTTP
  transport (exactly as `vibescan-supabase` is for the RLS probe); an optional,
  feature-gated `vibescan-core` edge to it; the §13.3 boundary assertion and the
  workspace-DAG checker updated in the same change so `LocalStatic` stays
  transport-free.
- A `--registry-checks` opt-in **separate** from the Supabase network opt-in
  (enabling one must never enable the other); repository config alone cannot
  enable it.
- Payload discipline: package names and version requirements only — never a
  secret, path, file content, repo name, or remote URL; the request set
  reproducible from the manifests alone.
- Privacy disclosure in scan scope (an unlisted private dependency name *is* a
  disclosure); local cache with explicit TTL; a failure taxonomy that never
  conflates an unreachable registry with a nonexistent package.
- First-pass detections: local matching against 24-hour cached OSV ecosystem
  snapshots → Critical; public unscoped npm/PyPI package nonexistence → High,
  with scoped/private packages guarded out. Un-gate `hallucinated-dependency`.
- The noisy suspicious-newcomer heuristic remains a separate, off-by-default,
  npm-only follow-up; PyPI newcomer detection remains deferred pending a
  trustworthy download signal (§11.2, §16).

**Decision-first?** **No.** Architecture §11.2 made the registry, OSV, cache,
confidence, and privacy decisions on 2026-07-18; the Tier F instruction set now
implements them without reopening the mechanism.

**Status (2026-07-18): complete.** F1 established the crate, DAG, independent
opt-in, input plumbing, and disclosure shapes; F2 implemented the two confirmed
detections, guards, failure taxonomy, and 24-hour caches; F3 promoted
`hallucinated-dependency` into the golden and precision/recall corpus. The
newcomer heuristic remains the separate deferred follow-up described above.
The subsequent Tier F close-out is also complete: CF1 pins LocalStatic structural
findings through composed Registry/OSV failures, and CF2 reconciles the committed
F3 baseline and metrics in `STATE.md`. No Tier F acceptance residual remains.

---

## Track G — Distribution pipeline (§13.1) — runs in parallel

**Why parallel, why it matters.** This touches no scan logic, so it can proceed
alongside E/F with a different owner. It also has the highest *product* leverage
of anything here: §13.1 is explicit that the audience "lives in npm," and the
pure-Rust constraint (no OpenSSL, no libgit2) exists precisely to make per-target
prebuilds painless — the tool is architected for `npx @jiayanzeng/vibescan` but cannot yet be
installed that way.

**The work:**
- Cross-compile matrix: macOS arm64/x64, Linux x64/arm64, Windows x64 — a CI
  release workflow producing prebuilt binaries per target.
- The primary channel: the release-owner personal-scope `@jiayanzeng/vibescan`
  npm wrapper package ships the correct prebuilt per platform so
  `npx @jiayanzeng/vibescan` works. Secondary: `cargo install`,
  Homebrew.
- Release provenance/signing.

**Decisions to make first:**
- npm wrapper strategy: bundle all binaries vs download-on-install (download
  keeps the package small but adds a network step and a supply-chain surface —
  decide and document).
- Signing/provenance approach (e.g. sigstore) and the release-tag → build →
  publish flow.

**Decision-first?** **Yes**, but a *release-architecture* decision, independent of
the scan-engine spec — it can be written and reviewed in parallel with Track E.

---

## Track I — DAST / write-probe (§7.3, §7.4) — much later

**Why last and smallest-priority.** v1 infers write-exposure and never
demonstrates it, by invariant §1.3. A live write-probe is the one capability that
would *demonstrate* it — and it is deferred behind the §7.4 ownership gate for
good reason: it is the only feature that could touch a target's data.

**What it needs before it is even specced:**
- The §7.4 ownership-gate *mechanism*, which does not exist yet: DNS TXT record,
  a file at a well-known path, or OAuth into the user's Supabase/host. Tier 0/1
  rely on key-possession as authorization; active probing requires more.
- A non-persisting write-probe design (prove openness without leaving data) —
  itself a hard security-design problem.

**Decision-first?** **Emphatically yes** — a full security-design document for
the ownership gate and the non-persisting probe, reviewed on its own, before any
instruction doc. This is a distinct future project, named here only so the
roadmap is complete. Do not start it until E, F, and G are done and there is a
concrete user demand.

---

## Recommended sequencing

1. **Tier D is complete**, closing v1.
2. **Track H** as a fast-follow — cheap, evidence-gated on data Tier D already
   produced, directly improves the coverage metric. Resolve §6.2's `src/api/`
   question *from the evidence*.
3. **Tracks E (Tier 1) and G (distribution) are complete.** Track G touched no
   scan logic.
4. **Track F (registry) is complete:** the resolved §11.1–§11.2 mechanism is
   implemented and the last corpus fixture is live.
5. **Track I (DAST)** much later, security-design-first, only on real demand.

With F and G complete, the last gated corpus fixture is live, the
precision/recall corpus covers the full v1+ detection surface, and the tool
reaches its intended audience. That is the natural "v2" line.

## Available implementation documents

- `vibescan-tierE-instructions.md` covers Tier 1 introspection.
- `vibescan-tierF-instructions.md` covers the resolved registry track.
- `vibescan-trackG-instructions.md` covers distribution decisions and tasks.
- Track H remains evidence-gated on additional real-repository coverage data;
  Track I remains security-design-first and intentionally unspecced.
