# `vibescan-supabase` contract

This file supplements the repository-root `AGENTS.md`. This is the product's
highest-risk crate; architecture sections 7 and 10 are mandatory reading.

## Ownership

The default build owns LocalStatic Supabase key classification and linkable
domain facts. Optional `network` code owns Tier 0 read probing. Generic secret
matching belongs in `vibescan-secrets`; final correlation belongs in
`vibescan-core`.

Do not depend on a sibling library, including through dev-dependencies. Put
cross-crate classification fixtures in the core integration harness.

## Key semantics

- `sb_publishable_*` and `sb_secret_*` are opaque. Classify by prefix; do not
  JWT-decode them, authenticate them, or depend on checksum validation.
- Legacy tokens are decoded only to label `role`, issuer, and project ref. Do
  not verify signatures or treat decoding as authentication.
- Publishable/anon keys are low privilege and Info in isolation. Elevated keys
  bypass RLS and require urgent remediation. Preserve explicit architecture
  tests for committed, client-reachable, and gitignored server-only locations;
  do not silently resolve the specification's severity ambiguity.
- Project/key association must be deterministic and must not attach a key to a
  different project merely because multiple projects occur in one file/repo.

## Tier 0 safety contract

Tier 0 exists only with the Cargo `network` feature and explicit runtime
opt-in. `reqwest` must remain optional, rustls-backed, and nearest-parented by
this crate.

- Accept only HTTPS Supabase project hosts associated with keys discovered in
  the scanned repository. Reject arbitrary hosts, paths, ports, and schemes.
- Send `apikey` on the OpenAPI supplement and every table read. Never use only
  `Authorization: Bearer` for an opaque public key.
- Only issue GET requests equivalent to
  `/rest/v1/<table>?select=*&limit=1`. Never add a write method, mutation RPC,
  or request body capable of changing target data.
- Candidate tables primarily come from LocalStatic source/bundle harvesting.
  Do not make the OpenAPI root a prerequisite.
- A 403 at the root is a distinct nonfatal fallback note. Keep 401 key
  rejection, no candidates, protected/no rows, 404, parse failures, and
  transport errors distinguishable.
- Returned rows may be counted in memory and then discarded. Do not retain,
  display, serialize, log, hash, or snapshot their contents.
- Evidence may include normalized project, table, endpoint, and observed count.
  It proves read exposure only.
- Log/record each attempted read outcome without keys or row data so Network
  activity is auditable even when no finding is emitted.

## Tests and future tiers

Use an injected/mock HTTP client and assert method-equivalent behavior, exact
`apikey` presence, URL validation, warning taxonomy, row-data absence, and
continued offline findings after Network failure. Default tests must make zero
requests. Do not run a live target without explicit user authorization.

Tier 1 introspection and all active probes are deferred. No ownership proof can
make writes acceptable in v1. Do not add external registry/OSV egress here
until the architecture resolves its own-assets-only conflict.

Run package tests in both feature modes, the network golden corpus, all
workspace gates, and `scripts/check-network-boundary.sh` for every change here.
