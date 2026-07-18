# vibescan

vibescan is a local-first Rust CLI for scanning Supabase + Next.js/TypeScript
apps for secret exposure, Supabase key semantics, dependency-integrity issues,
and offline correlations.

The current implementation defaults to the free local tier. It scans the working
tree and local git object store, classifies Supabase keys, renders local reports,
and keeps network probing disabled unless the binary is built with the `network`
feature and the user explicitly opts in.

## Safety Model

- LocalStatic crates do not use network clients.
- Secrets are redacted in report output.
- `.gitignore` and `.vibescanignore` are honored with explicit carve-outs for
  high-risk files such as real `.env` files.
- `.env.example`, `.env.sample`, dependency folders, caches, and server/vendor
  build output are skipped.
- Tier 0 RLS probing is read-only, feature-gated, and opt-in. It only talks to
  Supabase project URLs discovered from keys in the scanned repository.
- Every attempted Tier 0 GET is recorded as redacted scan-scope evidence in
  JSON, SARIF, TTY, and HTML. Records omit keys, headers, response bodies, and
  rows; protected outcomes do not become findings or affect the exit gate.
- Tier 1 catalog introspection has a separate runtime opt-in and reads its
  database URL only from `VIBESCAN_SUPABASE_DB_URL`. It rejects non-Supabase
  database/pooler hosts and nonstandard ports before connecting, uses rustls,
  and issues only catalog `SELECT`s. Audit records omit credentials, policy
  bodies, database errors, row data, and counts. Tier 1 findings reproduce the
  relevant `USING`/`WITH CHECK` policy predicate without retaining application
  rows.
- Generic secret rules use an attributed Gitleaks-compatible subset; Supabase
  key semantics and correlation remain vibescan-specific.

## Workspace

The project is a Cargo workspace with these crates:

- `vibescan-cli`: command-line entry point.
- `vibescan-core`: scan orchestration, config, baselines, correlation, and gates.
- `vibescan-git`: LocalStatic working-tree and git-history collection.
- `vibescan-secrets`: LocalStatic secret-detection substrate.
- `vibescan-supabase`: Supabase key classification and domain intelligence.
- `vibescan-report`: JSON, SARIF, TTY, and HTML rendering.
- `vibescan-types`: shared data contracts.

## Build

```sh
cargo build --workspace
```

## npm channel

The npm channel uses one unscoped `vibescan` shim package and five exact-version
platform packages under `@vibescan`. The platform packages carry the prebuilt
binary itself; the shim has no `postinstall` and never fetches or executes a
binary during installation. Linux packages carry the static musl builds without
a `libc` restriction, so npm can install them on both glibc and musl hosts.

Release CI locally packs and tests all five platform combinations with
`--ignore-scripts`, exercises `npx vibescan --version`, and proves that clean and
severity-gated scans preserve the Rust CLI's exit codes. Stable tags are wired to
publish the five platform packages first and the main package last with npm
provenance. Public availability still depends on the one-time registry ownership
and trusted-publisher setup in [RELEASING.md](RELEASING.md); this repository does
not claim publication until a tagged run proves it.

Run the source package and shim contract tests locally with:

```sh
npm --prefix npm test
```

If npm skips the matching optional package, the shim reports the usual cross-OS
`node_modules` cache or stale-lockfile causes and recommends a clean `npm ci`,
`cargo install vibescan-cli`, or the shell installer. The Cargo package installs
the `vibescan` binary. The shim never silently downloads a replacement.

## Secondary distribution channels

The release plan generates a prebuilt-binary Homebrew formula for
`jiayanzeng/tap/vibescan` and publishes the Cargo workspace bottom-up so
`cargo install vibescan-cli` installs the `vibescan` command. The exact publisher
order, bootstrap credentials, trusted-publisher setup, checksum and attestation
commands, and release gates are documented in [RELEASING.md](RELEASING.md).

## Test

```sh
cargo test --workspace
```

To run the hardening verification used during development:

```sh
bash scripts/verify-hardening-checks.sh
```

That script runs the workspace tests and the fixture-free network-boundary
assertion. The optional real-repo scan is a developer convenience only:

```sh
bash scripts/verify-hardening-checks.sh /path/to/nextjs-supabase-repo
```

When a fixture path is supplied, the script scans a sanitized clean copy of that
repo and verifies that a planted gitignored `.env` secret is reported. Without a
fixture path, it exits successfully with a skipped notice.

The CI boundary gate is:

```sh
bash scripts/check-network-boundary.sh
```

It validates the exact eight-crate post-v1 workspace DAG across normal, build,
dev, target, optional, and feature-activated dependencies. Separate assertions
keep default builds transport-free, allow `--features network` transport only
through `vibescan-supabase`, and allow the independent `--features registry`
transport only through `vibescan-registry`. Synthetic negative controls exercise
forbidden workspace edges, unauthorized transport parents, feature isolation,
and LocalStatic transport leakage on every run.

## Usage

Run a default local scan:

```sh
cargo run -p vibescan-cli -- /path/to/repo
```

Render JSON:

```sh
cargo run -p vibescan-cli -- /path/to/repo --format json
```

Render SARIF:

```sh
cargo run -p vibescan-cli -- /path/to/repo --format sarif
```

Disable history scanning:

```sh
cargo run -p vibescan-cli -- /path/to/repo --no-history
```

Scan all reachable history without the default commit cap:

```sh
cargo run -p vibescan-cli -- /path/to/repo --exhaustive-history
```

Use a baseline file:

```sh
cargo run -p vibescan-cli -- /path/to/repo --baseline baseline.json
```

Relative baseline paths are resolved from the discovered target repository,
not the caller's working directory. A named baseline must exist and parse; a
missing or invalid file is an operational error (exit code 2). Use `--history`
or `--no-history`, and `--working-tree` or `--no-working-tree`, to explicitly
override repository scan-scope settings in either direction.

Build with Tier 0 network probing support and opt in to read-only RLS probes:

```sh
cargo run -p vibescan-cli --features network -- /path/to/repo --rls-tier0-read-probe
```

To run Tier 1 introspection, set
`VIBESCAN_SUPABASE_DB_URL` locally (for example through a secret manager) and
use the distinct opt-in:

```sh
cargo run -p vibescan-cli --features network -- /path/to/repo --rls-tier1-introspect
```

The current Tier 1 pass emits `Confirmed` findings for Critical RLS-disabled and
literal-true permissive policies, a Medium default-deny missing-operation
advisory, and High write exposure inferred from role grants plus an absent
operation policy. It never attempts a write. Correlation and the gated Tier 1
fixtures are complete: RLS-disabled and permissive-policy evidence can drive
the same-project public-key read chain, while missing-operation advisories and
inferred-write findings cannot overclaim that reads were proven. The two Tier 1
goldens run through an injected catalog under `--features network` and never
contact a live database. Architecture §17.8 defers the noisy user-writable-
metadata policy heuristic; this pass does not infer it by substring matching.

Build with the independent Registry-class plumbing and explicitly opt in:

```sh
cargo run -p vibescan-cli --features registry -- /path/to/repo --registry-checks
```

Track F1 establishes the parsed-dependency flow, rustls transport boundary,
scope disclosure, and mockable registry source. Track F2 adds two confirmed
checks: exact resolved versions are matched locally against a 24-hour cached
OSV ecosystem snapshot (Critical, no package-name egress), and public unscoped
names are resolved against npm or PyPI (High on a real 404, with name egress
recorded in scan scope). Existence results are cached for 24 hours. Scoped npm
names and ecosystems configured for alternate/private registries are excluded
from the public-404 rule. Outages, rate limits, and invalid responses produce
coverage warnings, never nonexistent-package findings. The flag never enables
either Supabase RLS tier.

Track F3 activates the committed `hallucinated-dependency` golden through an
injected registry mock and includes it in the precision/recall baseline. The
fixture also carries a scoped-package 404 negative control, proving that private
package names do not become High nonexistent-package findings.

For confirmed OSV matching, vibescan uses exact versions from npm and supported
Python lockfiles, plus exact manifest pins. A loose version range is not called
known-malicious without a resolved version. The optional live OSV API and the
noisy newcomer heuristic remain disabled/deferred.

The process exit code is controlled by `--severity-gate`, which defaults to
`high`.

## Configuration

If present, `vibescan.toml` is loaded from the target repository:

```toml
[scan]
working_tree = true
history = true
max_commits = 2000
max_bytes = 2097152
severity_gate = "high"

[ignore]
paths = ["docs/**"]

[baseline]
path = "baseline.json"

[rules]
path = "config/custom-rules.toml"

[network]
tier0_read_probe = false
tier1_introspection = false
registry_checks = false
registry_newcomer = false
```

Config ignore paths are fed through the same override layer as git ignores. They
cannot hide real `.env` files from the local scanner.

Configuration precedence is built-in defaults, then repository
`vibescan.toml`, then CLI arguments the user explicitly supplied. Relative
baseline and custom-rule paths are repository-root-relative; absolute paths are
preserved. Custom rule files are additive: embedded rules and safety allowlists
remain active, custom rules and allowlists append, and duplicate rule IDs are
rejected instead of replacing a shipped rule.

Repository configuration cannot enable egress by itself. Even if a network
setting is `true`, the current process remains LocalStatic unless a feature-
enabled binary is invoked with the corresponding explicit
`--rls-tier0-read-probe`, `--rls-tier1-introspect`, or `--registry-checks` flag.
The newcomer setting remains inert because that heuristic is deferred.

## Repository Notes

- Keep `Cargo.lock` committed because this workspace builds a CLI binary.
- Do not commit `target/`, local reports, temporary fixtures, or real secrets.
- See `vibescan-architecture.md` for the architecture contract.
