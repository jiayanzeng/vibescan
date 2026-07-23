# vibescan — Track I Security Design: active write-exposure probe (DAST)

Reviewed: 2026-07-19
Author: architecture review (Claude)
Status: **DESIGN FOR RATIFICATION — not a Codex instruction set.**

## What this document is, and why it is not an instruction document

The post-v1 roadmap and the architecture are explicit and consistent that Track I —
the only capability that could ever *touch a target's data* — is **"emphatically
decision-first"**: it requires "a full security-design document for the ownership
gate and the non-persisting probe, reviewed on its own, before any instruction doc."
This is that document. It deliberately does **not** contain file targets, task
ordering, or Codex-executable acceptance criteria, because per §1.3 there is nothing
to implement yet: a Codex instruction set can only be written **after** the two gates
below are cleared.

Two gates, both currently open:

1. **Design ratification.** The mechanisms below (the §7.4 ownership gate; the
   non-persisting probe) do not exist in the spec as *mechanisms* — §7.4 names the
   candidates but specifies none. They must be chosen and written into the
   architecture as a reviewed spec patch (with an accompanying, carefully-scoped
   amendment to invariant §1.3) before any code.
2. **Concrete demand.** The roadmap says: *"Do not start it until E, F, and G are
   done and there is a concrete user demand."* E/F/G are now done — the first
   condition is met. The second is not established anywhere I can see. Active
   write-probing is the single feature most able to cause harm and most able to lose
   the tool's credibility if it goes wrong; it should stay unbuilt until a real user
   need justifies the risk. **This document is the artifact to have ready when that
   demand appears; it is not a signal to start building.**

The rest of this document exists to make gate 1 decidable and to surface the hard
problems honestly, so that if and when gate 2 arrives, the design review can move fast.

---

## 1. The invariant tension (read first)

Track I collides head-on with three invariants. Naming the collision precisely is the
point of the design.

- **§1.2 Own-assets-only** — the tool only ever interacts with the user's own project.
  Active probing raises the stakes on *proving* ownership, because a read probe that
  hits the wrong project leaks nothing new (the user already possesses the key), but a
  **write** probe that hits the wrong project could mutate a stranger's data. §7.4
  exists exactly for this escalation.
- **§1.3 Never persist writes** — *"No `Network` code path may create, modify, or
  delete data in the target project in v1. Write-exposure is inferred, never
  demonstrated by writing."* Track I is, by definition, the thing §1.3 forbids. It
  cannot ship without **amending §1.3** to carve out a narrowly-scoped, gated,
  non-persisting exception — and that amendment is the most consequential spec change
  in the project's history. It must not be done casually.
- **§7.3 Write exposure — inferred, never demonstrated** — v1 *infers* write-exposure
  from Tier-1 grants + absent policies. Track I would be the first path that
  *demonstrates* it. The design must preserve the honest distinction: a demonstrated
  result is a strictly stronger, and strictly more dangerous, claim than an inferred one.

**Design consequence:** Track I is not "Tier 2." It is a distinct egress class with a
distinct trust model (ownership proof, not mere key possession), a distinct consent
model (per-invocation, explicit, with a side-effect warning), and a distinct
confidence tier above "inferred."

---

## 2. The hard part first: there is no truly side-effect-free write probe

Before designing the gate, confront the uncomfortable core: **you cannot generally
prove write-exposure through a live API without risking a side effect.** This is not
a limitation to engineer around; it is why §1.3 forbids it and why the honest design
is conservative.

Two families of probe, from safest to least safe:

### 2a. Transactional probe (DB connection) — the only *near*-safe option

If the user supplies a direct Postgres connection string (the Tier-1 credential path,
`VIBESCAN_SUPABASE_DB_URL`, rustls, own-project host/port validated), a write can be
attempted inside a transaction and **unconditionally rolled back**:

```
BEGIN;
  -- attempt the write the RLS policy would gate
  INSERT INTO <schema>.<table> (...) VALUES (...);   -- or UPDATE/DELETE
  -- observe: did authz (RLS) permit the statement, or was it denied?
ROLLBACK;
```

Within the transaction, an INSERT/UPDATE/DELETE that reaches `ROLLBACK` persists **no
rows**. This is the closest thing to a safe active probe. **But it is still not fully
side-effect-free**, and the design must document and defend each residual:

- **Sequences are non-transactional.** A rolled-back INSERT that called `nextval` on a
  `SERIAL`/identity column **still advances the sequence** — a permanent, if usually
  harmless, gap. Mitigation: prefer UPDATE/DELETE probes (no sequence touch), or target
  a payload that fails before `nextval`, or accept and disclose the gap.
- **`BEFORE` triggers fire before the row is checked and are *not* undone by rollback
  if they have external effects.** A `BEFORE INSERT` trigger that sends an email, calls
  an HTTP endpoint, writes to another system, or `pg_notify`s a listener will have
  *already acted* by the time `ROLLBACK` runs. Rollback undoes database state, not the
  email that already left. **This is the dangerous residual.** Mitigation: **detect
  triggers via Tier-1 introspection first and refuse to probe any table that has a
  `BEFORE`/`INSTEAD OF` trigger** (see §5). This is a hard precondition, not a warning.
- **`NOTIFY`/`LISTEN`, `dblink`, `COPY ... PROGRAM`, FDW writes** — same class as
  triggers: effects that escape the transaction. Same mitigation: refuse if present.

**Verdict:** the transactional probe is the *primary* design, gated behind trigger
detection and preferring non-sequence-touching statements. It is strictly safer than
any PostgREST-based probe and is the only variant that should be considered first.

### 2b. Constraint-violation probe (public PostgREST API) — fallback, weaker safety

If only a publishable/anon key is available (no DB connection), there is **no
transaction boundary** exposed to the client — every PostgREST write commits. The
least-bad approximation is a **constraint-violation probe**: send a write whose
payload is *guaranteed to fail a data constraint* (e.g. omit a `NOT NULL` column, send
a type-invalid value, or violate a `CHECK`), and distinguish the responses:

- **`401/403` / RLS-permission error** ⇒ the policy denied the write ⇒ **not** exposed.
- **`4xx` constraint/validation error** (e.g. `23502 not_null_violation`,
  `23514 check_violation`, `22P02 invalid_text_representation`) ⇒ authz passed and the
  request reached data validation ⇒ **the policy would have allowed the write** ⇒
  exposed — *without persisting a row*, because a failed statement aborts atomically.

This is the "check whether the lock opens without walking through the door" probe. It
persists no rows, but it carries **the full `BEFORE`-trigger and sequence residual
from 2a with none of the rollback safety net** — a `BEFORE INSERT` trigger fires on
the way to the constraint check on a live, committing connection. **Therefore 2b is
acceptable only when 2a is unavailable, only after the same trigger-detection
precondition, and with the strongest consent + warning.** It should default **off**
even within Track I, and may reasonably be judged out of scope entirely.

**Honest conclusion for §2:** demonstrated write-exposure is achievable only
imperfectly. The design's job is to make the *safe* path (transactional, trigger-gated)
the default and to make the *unsafe* paths either heavily gated or excluded — not to
pretend a clean probe exists.

---

## 3. The §7.4 ownership gate (the mechanism that does not exist yet)

§7.4 names three candidate proofs — DNS TXT record, a file at a well-known path, or
OAuth into the user's Supabase/host — but specifies none. The design must pick, and
must specify the **binding, freshness, and verification** properties, not just the
mechanism.

### 3a. Requirements the gate must satisfy

- **Binds to the exact target.** The proof must attest ownership of the *specific*
  Supabase project ref / host being probed — not "some project." A proof for
  `project-A` must not authorize a probe against `project-B`.
- **Fresh.** Verified immediately before the probe run, with a short validity window.
  A months-old cached proof is not acceptable for an escalation this consequential.
- **Non-transferable and unforgeable by a third party.** The proof must be something
  only the project owner can produce.
- **Auditable.** The proof method, target, and timestamp are recorded in the same
  redacted scan-scope audit stream Tier 0/Tier 1 already use.

### 3b. Recommended mechanisms, by hosting model

- **Supabase-hosted projects → OAuth / Management-API ownership (primary).** Require
  the user to authenticate to Supabase and demonstrate that the target `project_ref`
  is one they own (e.g. it appears under their authenticated account's projects). This
  binds tightly to the exact project and is fresh by construction. It is the strongest
  option and should be the default for hosted projects.
- **Custom domain / self-hosted → DNS TXT challenge (secondary).** Publish a
  vibescan-issued nonce as a TXT record on the domain of the target host; verify it
  immediately before probing. Binds to the host, is standard (ACME-style), and needs
  no account integration. Good where OAuth is unavailable.
- **Self-hosted with filesystem/deploy control → well-known-path file (tertiary).**
  Serve a vibescan nonce at `/.well-known/vibescan-challenge/<nonce>` over the target's
  own origin. Weakest of the three (proves control of the web root, which is close to
  but not identical to ownership); acceptable as a fallback.

### 3c. What the gate explicitly is *not*

Key possession is **not** ownership proof for active probing. Tier 0 read and Tier 1
introspection lean on key possession because a read/introspection of the user's own
project, using the user's own key, mutates nothing. An active write raises the bar:
possession of a leaked key is exactly the attacker's position, so the gate must prove
ownership *independently of the key*.

---

## 4. Consent, disclosure, and kill-switch (product surface)

Even with ownership proven and triggers excluded, an active write-probe must be
un-missable to invoke and fully disclosed:

- **A dedicated, distinct opt-in flag** — not reusing `--rls-tier0-read-probe` or
  `--rls-tier1-introspect`. Something like `--rls-write-probe`, gated behind a build
  feature separate from `network` (mirroring the registry-feature isolation lesson:
  a workspace-wide `--features network` must **not** silently arm write-probing).
- **Per-invocation confirmation with an explicit side-effect warning** — state plainly
  that the probe issues real (rolled-back or constraint-failing) writes against the
  live project and that `BEFORE`-trigger side effects, if any slipped detection, cannot
  be undone. No "assume yes."
- **A plan/dry-run mode that prints exactly what would be attempted** (tables,
  statement kinds, payloads) and performs **no** network write — the default first step.
- **Full redacted audit** of every attempted write in JSON/SARIF/TTY/HTML, in the same
  never-leak style as Tier 0 (no keys, no payload secrets, no row data), plus the
  ownership-proof record.
- **Scope ceiling** — probe only tables surfaced by the user's own scan of their own
  project; never an arbitrary table list; never a table with a detected trigger.

---

## 5. Data-model, boundary, and correlation implications

- **A new egress sub-class, nearest-parented to its own transport.** Following the
  §11 / Track F precedent, active probing lives behind its own feature (e.g. a `dast`
  feature on `vibescan-supabase`), and the network-boundary checker
  (`check-network-boundary.sh` / `.py`) must be extended to permit **exactly** that
  transport parent and reject any `LocalStatic` leak — the same C1/E3/F1 "get the
  boundary policy exactly right" site. This is the load-bearing safety edit and must
  carry negative controls.
- **Trigger detection is a Tier-1 precondition, not an option.** The probe runner must
  first introspect `pg_trigger` (via the existing Tier-1 catalog path) for
  `BEFORE`/`INSTEAD OF` triggers, `NOTIFY`, and FDW/`dblink` usage on the target table,
  and **refuse** to probe if any are present. Wire this as a hard gate in the design.
- **A new confidence tier above "inferred."** A demonstrated write-exposure is
  `Confirmed`-and-stronger than the §7.3 inferred case. Severity still tracks blast
  radius (write-exposure on an API-reachable table is Critical), but the finding text
  must say *demonstrated by a rolled-back/constraint-failed probe* — never overclaim,
  and never blur the line §7.3/§17.2 drew between reads-demonstrated and
  writes-inferred. Correlation (§12) may add a new rule that annotates a demonstrated
  write-exposure, but must not silently escalate base severity (the §17.8 discipline).

---

## 6. Explicit non-goals (preserve the v1 line even inside Track I)

- No BOLA/IDOR enumeration, no auth bypass fuzzing, no destructive payloads, no
  data exfiltration — the probe answers exactly one question ("would a write be
  permitted?") and nothing more.
- No probing of any project without a fresh, target-bound ownership proof.
- No probing of any table with a detected trigger / external-effect construct.
- No reuse of the `network` feature or the read/introspect flags to arm writes.
- No persisted rows, ever; the transactional path rolls back unconditionally and the
  constraint path is designed to fail before commit.

---

## 7. What must be ratified before *any* Codex instruction document

A reviewer signing off on gate 1 must approve, as an architecture spec patch:

1. **A scoped amendment to §1.3** carving out the non-persisting, ownership-gated,
   trigger-excluded active probe as the single permitted exception, with the
   transactional path as primary and the constraint path off-by-default or excluded.
2. **A §7.4 mechanism spec** choosing OAuth-ownership (hosted) + DNS-TXT (custom/self)
   + well-known-path (fallback), with the binding/freshness/audit properties in §3.
3. **The trigger-detection precondition** written as a hard gate (§5).
4. **The new egress sub-class + boundary-checker extension** with negative controls (§5).
5. **The confidence/severity/correlation treatment** that keeps demonstrated ≠ inferred
   (§5, honoring §17.2/§17.8).

Only after all five are ratified — **and** concrete user demand exists — should a
`vibescan-trackI-instructions.md` be written in the house format.

## 8. Design-review exit criteria (for gate 1, not for code)

The design is ready to become an instruction document when a reviewer can answer *yes*
to each:

- Is the §1.3 amendment scoped so tightly that no reading of it permits a persisting
  write or an un-gated probe?
- Does the ownership gate bind to the exact target, refresh per run, and resist a
  third party holding a leaked key?
- Is there a probe path (the transactional one) whose only residual side effects are
  enumerated, defended, and either eliminated or disclosed — and is the trigger gate a
  hard refusal rather than a warning?
- Is the unsafe (constraint/PostgREST) path either excluded or gated strictly below the
  safe path and off by default?
- Does every finding preserve the demonstrated-vs-inferred distinction in its wording
  and confidence?
- Does the boundary checker prove `LocalStatic` still cannot reach the write transport,
  with negative controls?

Until then, Track I remains, correctly, the roadmap's last and most-gated item — named
so the plan is complete, and intentionally unbuilt.
