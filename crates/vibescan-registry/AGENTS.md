# `vibescan-registry` contract

This file supplements the repository-root `AGENTS.md`. Architecture sections
11.1, 11.2, 13.1, and 13.3 govern this crate.

## Ownership

This crate owns the opt-in Registry egress class and is the nearest workspace
parent of its HTTP transport. It may depend only on `vibescan-types` plus an
optional rustls-backed transport. It must not scan repositories, inspect Git,
parse project configuration, classify secrets or Supabase keys, correlate
findings, or render reports.

## Privacy and transport

- Transport exists only under this crate's internal `transport` feature and must remain
  sync, rustls-backed, and free of OpenSSL/native-tls/C-toolchain dependencies.
- Requests may carry only package names and version requirements derived from
  manifests. Never transmit secrets, file contents, paths, repository names,
  or remote URLs.
- Record every package-name-leaking request as redacted scope evidence and
  disclose the ecosystem and destination host. Local OSV snapshot matching
  must not produce a package-name-egress action.
- Registry failures are non-fatal and distinct from a 404. An outage must
  never manufacture a nonexistent-package finding.
- Automated tests use an injected `RegistrySource`; never contact a live
  registry or OSV endpoint without explicit authorization for that action.

## Track boundaries

F1 establishes the crate, feature boundary, source seam, and plumbing only.
F2 owns OSV/existence detections, caching, and failure semantics. F3 owns the
golden/metrics activation. The noisy newcomer heuristic remains deferred.

Run this crate's default and `transport` tests, every workspace feature matrix,
and `scripts/check-network-boundary.sh` for changes here.
