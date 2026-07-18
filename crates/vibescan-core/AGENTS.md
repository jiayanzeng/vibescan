# `vibescan-core` contract

This file supplements the repository-root `AGENTS.md`. Architecture sections
6, 11, and 12 govern this crate.

## Ownership

Core owns orchestration, repository-root config resolution, baselines,
dependency-integrity orchestration, generic-candidate resolution, finding
coalescing, declarative correlation, finalization, stats, and severity-gate
policy. It may orchestrate optional Network behavior but must not implement a
transport. Low-level collection/detection and format-specific rendering stay in
their owning crates.

## Pipeline and identity

Preserve collect → detect → enrich → correlate → finalize. In particular:

- Harvest Network inputs only from already-collected LocalStatic units.
- Associate enrichment context with the exact scannable unit/blob, not merely
  a path that may have multiple historical contents.
- Coalesce same-secret facts before correlation so the rule sees every
  location and the most-client-reachable class.
- Keep project-specific inputs separated. Do not send a global union of table
  candidates to unrelated projects when project association is knowable.
- Correlation rules live in a small declarative registry. Do not replace them
  with scattered conditionals.
- v1 rule 1 requires same-project public-key and confirmed read exposure plus a
  client-reachable or committed key location. Rule 2 orders elevated-key
  remediation ahead of same-project RLS findings.
- Rule 1 accepts Tier 0 `Exposed` probes and Tier 1 `RlsDisabled` or
  `PermissivePolicy` evidence. It must not treat `MissingOperationPolicy` or
  `InferredWriteExposure` as proof of anonymous reads. Rule 2 sees all
  same-project `Category::Rls` evidence shapes.
- Treat primary and `additional_provenance` commit entries equivalently for the
  committed predicates in both rules.
- Tier 0 correlation may say anyone can read the observed table; it may not say
  writes were demonstrated.
- Stable IDs and baseline keys must not depend on discovery order or one
  arbitrary path. Preserve different fingerprints/projects and union sorted
  locations/provenance.
- If the same fingerprint has a trusted project on one location and no project
  on another, do not strand the unknown copy in a separate finding. Merge or
  enrich only when ambiguity checks prove there is no known-different project.
- Apply baselines before final stats and exit policy. Absorb constituents only
  in the summary representation while keeping `related` evidence reproducible.

## Configuration

Load `vibescan.toml` from the discovered repository root. Precedence is
defaults, file config, explicitly provided CLI values. Resolve relative
baseline/ruleset paths from that same root. Tests must prove that absent CLI
flags do not overwrite file values and that explicit flags do.

The architecture requires an extendable detector ruleset. When wiring it, keep
the embedded rules as the safe zero-config base and make merge/replace behavior
explicit and tested.

## Dependency integrity

Offline structural parsing must remain LocalStatic and deterministic. Track F1
may expose parsed dependencies and orchestrate the optional
`vibescan-registry` edge, but transport stays in that crate. F2 owns registry
existence/advisory detections, caching, precision guards, and failure semantics;
the newcomer heuristic remains deferred. Registry failure must never remove
offline findings.

## Verification

Use unit cases for rule predicates, cross-project negatives, stable IDs,
coalescing, config precedence, baseline behavior, degraded scope, and exit
codes. Use the golden corpus for end-to-end behavior. Run core tests in default,
network, and registry modes, all workspace matrices, report snapshots when
result shapes change, and the boundary script.
