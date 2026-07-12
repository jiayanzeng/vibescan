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

It validates the exact seven-crate workspace DAG across normal, build, dev,
target, optional, and feature-activated dependencies. Separate assertions keep
default builds transport-free and allow `--features network` transport only
through `vibescan-supabase`; synthetic negative controls exercise forbidden
workspace edges and LocalStatic transport leakage on every run.

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

Build with Tier 0 network probing support and opt in to read-only RLS probes:

```sh
cargo run -p vibescan-cli --features network -- /path/to/repo --rls-tier0-read-probe
```

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

[network]
tier0_read_probe = false
```

Config ignore paths are fed through the same override layer as git ignores. They
cannot hide real `.env` files from the local scanner.

## Repository Notes

- Keep `Cargo.lock` committed because this workspace builds a CLI binary.
- Do not commit `target/`, local reports, temporary fixtures, or real secrets.
- See `vibescan-architecture.md` for the architecture contract.
