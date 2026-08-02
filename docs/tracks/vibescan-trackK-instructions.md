# Track K — architecture-aligned module decomposition

> Status/history only. `vibescan-architecture.md` remains authoritative.
> This record describes a behavior-preserving source-layout refactor; it does
> not authorize or claim a capability change.

## Scope and baseline

Track K began from clean, up-to-date `origin/main` at
`e1acd83572411043242e0a374133ae51f4e4db68`, after Track J final closeout
merged. `python3 scripts/check-status-consistency.py` and the pre-refactor
`bash scripts/verify-all.sh` passed.

Actual pre-refactor `src/lib.rs` counts selected six crates:

| Order | Crate | Before `lib.rs` | After `lib.rs` | Largest after file |
|---:|---|---:|---:|---:|
| 1 | `vibescan-core` | 4,881 | 63 | 653 |
| 2 | `vibescan-supabase` | 2,881 | 46 | 658 |
| 3 | `vibescan-git` | 1,851 | 44 | 667 |
| 4 | `vibescan-registry` | 1,538 | 47 | 583 |
| 5 | `vibescan-report` | 993 | 25 | 305 |
| 6 | `vibescan-secrets` | 825 | 34 | 310 |

`vibescan-types/src/lib.rs` was 653 lines and therefore outside scope. No
scoped `lib.rs`, production module, or test source now exceeds 800 lines.

## Module layout and architecture ownership

### `vibescan-core`

| Module | Architecture basis | Ownership |
|---|---|---|
| `config.rs` | §§6.1 and 6.6 | Runtime/file configuration, precedence, and repository-relative path resolution. |
| `pipeline.rs` | §6 phases A–E | Scan orchestration, optional capability dispatch, rendering bridge, statistics assembly, and exit gate. |
| `correlation.rs` | §§6.4–6.5 and §12 | Candidate enrichment/coalescing, exact-revision API reference association, Tier 0 input construction, and the two declarative rules. |
| `dependencies.rs` | §§11 and 11.1 | Offline manifest discovery/parsing, structural dependency findings, and Registry-eligible inputs. |
| `findings.rs` | §6.6 and §13.3 | Finding coalescing, stable identity helpers, sorting, statistics, history scope, fingerprinting, and redaction. |
| `baseline.rs` | §§6.1 and 6.6 | Baseline loading/application and custom detector loading. |
| `error.rs` | §§3 and 6 | Crate-owned orchestration error boundary. |
| `registry_failure_tests.rs`, `tests/` | §14 | Existing root test modules and names, physically extracted from `lib.rs`. |

### `vibescan-supabase`

| Module | Architecture basis | Ownership |
|---|---|---|
| `classifier.rs` | §§6.4 and 10.1 | New/legacy key classification, project extraction, finding identity, fingerprint, and redaction. |
| `tier0.rs` | §§7.1 and 10.2 | Tier 0 input/output, read-only HTTP boundary, degraded outcomes, audit records, and RLS evidence. |
| `tier1.rs` | §§7.2–7.3 and 10.2 | Catalog vocabulary, validated Supabase DB targets, read-only introspection semantics, and inferred policy/grant evidence. |
| `catalog.rs` | §§7.2 and 10.2 | The rustls-backed PostgreSQL catalog source and fixed SELECT-only query construction. |
| `tests/` | §14 | Existing root test module split into include fragments without changing test paths. |

### `vibescan-git`

| Module | Architecture basis | Ownership |
|---|---|---|
| `repository.rs` | §§6.1 and 8 | Walk options/results, discovery, and top-level LocalStatic collection orchestration. |
| `working_tree.rs` | §§6.1 and 8 | Filesystem walk and working-tree content collection. |
| `history.rs` | §§6.2 and 8 | Ref traversal, commit/tree/blob decoding, history budgets, and commit provenance. |
| `location.rs` | §6.2 | Component-aware location classification and server-runtime content signals. |
| `ignore_policy.rs` | §§5, 6.1, and 8 | Config, Git, hard-skip, and force-scan policy. |
| `collector.rs` | §§5, 6.1, and 6.6 | Content-ID deduplication, location/provenance merging, and deterministic materialization counters. |
| `error.rs` | §§3 and 8 | Git/discovery/object/path error boundary. |
| `tests.rs` | §14 | Existing root test module extracted intact. |

### `vibescan-registry`

| Module | Architecture basis | Ownership |
|---|---|---|
| `model.rs` | §11.1 | Registry input/output, warning/error, source trait, resolution, and advisory vocabulary. |
| `checks.rs` | §11.1 | Name-egress precision guards, existence/advisory orchestration, auditing, and finding evidence. |
| `transport.rs` | §11.2 | Feature-gated rustls HTTP registry/OSV source. |
| `cache.rs` | §§11.1–11.2 | Existence and OSV snapshot caches, local snapshot parsing, expiry, and atomic cache writes. |
| `tests.rs` | §14 | Existing root test module extracted intact. |

### `vibescan-report`

| Module | Architecture basis | Ownership |
|---|---|---|
| `output.rs` | §§13.3–13.4 | Public format dispatch, JSON/TTY/HTML rendering, style, and exit policy. |
| `sarif.rs` | §§13.3–13.4 | Deterministic SARIF object and location construction. |
| `summaries.rs` | §13.3 | Redacted evidence, provenance, warning, Network action, and history summaries. |
| `presentation.rs` | §13.3 | Stable severity/category/confidence names and HTML escaping; deliberately named for its domain rather than as a catch-all utility module. |
| `tests.rs` | §14 | Existing root renderer tests extracted intact; integration snapshots remain under `tests/`. |

### `vibescan-secrets`

| Module | Architecture basis | Ownership |
|---|---|---|
| `detector.rs` | §§6.3 and 9 | Parallel/serial detector execution, compiled rules, keyword/entropy gates, and allowlist matching. |
| `config.rs` | §9 | TOML ruleset surface, additive merge, configured candidate kinds, and allowlist compilation. |
| `content.rs` | §§5 and 9 | Binary/size policy, entropy and span helpers, regex/keyword normalization, and working-tree test-unit construction. |
| `error.rs` | §§3 and 9 | Detector configuration/regex/TOML error boundary. |
| `tests.rs` | §14 | Existing root test module extracted intact. |

## Placement judgment calls

- Public definitions live in private implementation modules and are re-exported
  at each crate root. This keeps every pre-existing external path such as
  `vibescan_core::ScanConfig` while avoiding new public modules.
- Rustdoc JSON reports canonical definition paths after extraction. The public
  inventory therefore resolves each private-module crate-root glob re-export
  before comparison; otherwise a source-location change would be mistaken for
  an API-path change.
- Exact test names include their module path. Conventional nested
  `module::tests` moves would rename them, so the original root
  `tests::...` modules remain root declarations while their bodies live in
  adjacent `src/tests.rs` or size-bounded `src/tests/` include fragments.
  Integration tests under `tests/` did not move.
- Core API-reference harvesting stays with correlation because its output is
  project-associated enrichment used to construct same-project correlation
  and Tier 0 inputs, not generic filesystem collection.
- Core fingerprint/redaction helpers stay with finding finalization because
  they define portable finding identity and shareable evidence boundaries.
- `vibescan-git::push_content` remains adjacent to object materialization in
  `history.rs` even though working-tree collection also calls it; the shared
  parent-visible seam avoids inventing a context-free helper module.
- Supabase’s production PostgreSQL implementation is named `catalog.rs`, not
  `postgres.rs`, to express its architecture role and avoid shadowing the
  external `postgres` crate.
- Report naming and escaping are `presentation.rs`, not `util.rs`, because
  they implement the shareable presentation contract in §13.3.

Cross-module seams use the narrow parent visibility `pub(super)`. No item was
widened to `pub`. There were no pre-existing `pub(crate)` declarations and
Track K added none, so the required individual `pub(crate)` addition list is
empty.

## Public inventory

Method:

1. Run nightly rustdoc JSON without private items for each scoped crate:
   `cargo +nightly rustdoc -q -p <crate> --all-features -- -Z unstable-options --output-format json`.
2. Select local-crate entries from `target/doc/<crate>.json` where
   `crate_id == 0`.
3. Resolve private implementation-module crate-root glob re-exports, normalize
   each reachable item as `<kind>\t<public path>`, and sort.
4. Compare the captured baseline from `e1acd835` with the final checkout.

| Crate | Before items | After items | Added | Removed |
|---|---:|---:|---:|---:|
| `vibescan-core` | 31 | 31 | 0 | 0 |
| `vibescan-supabase` | 40 | 40 | 0 | 0 |
| `vibescan-git` | 18 | 18 | 0 | 0 |
| `vibescan-registry` | 20 | 20 | 0 | 0 |
| `vibescan-report` | 15 | 15 | 0 | 0 |
| `vibescan-secrets` | 20 | 20 | 0 | 0 |
| **Total** | **144** | **144** | **0** | **0** |

The normalized before and after inventories are byte-identical. Both have
SHA-256
`9ba9602c41ea530f3d32d91e5dd52bd5a0efd51b3198e95271c9cf3e831095b5`;
the unified diff is empty.

## Test inventory

The before and after commands were both:

```sh
cargo test --workspace --all-features -- --list \
  | sed -n 's/: test$//p' \
  | sort
```

| Inventory | Count | SHA-256 |
|---|---:|---|
| Before (`e1acd835`) | 199 | `fe8562e57b8259ff428d139960da52ff6450bcbef2b8efcf25dd9ecaf61c4173` |
| After (`5c2f296`) | 199 | `fe8562e57b8259ff428d139960da52ff6450bcbef2b8efcf25dd9ecaf61c4173` |

The byte comparison and unified diff are empty. This is the shared sorted list
for both captures:

<details>
<summary>199 identical test names</summary>

```text
absent_cli_scope_flags_preserve_toml_values
bogus_expected_identity_is_an_fn_and_trips_the_recall_gate
classification_coverage_unknown_set_is_pinned
configured_custom_rules_are_repo_relative_and_additive
configured_severity_is_preserved_and_explicit_cli_value_wins
deterministic_fixture_gates_collection_and_dedup_counters
every_format_renders_registry_name_egress_disclosure
every_format_renders_the_redacted_evidence
every_format_renders_the_rls_policy_reproduction
explicit_cli_scope_flag_overrides_toml_value
explicit_disable_flag_overrides_enabled_working_tree_config
explicit_enable_flags_override_disabled_toml_scopes
golden_corpus_is_deterministic_across_runs
golden_corpus_matches_expected_manifests
injected_clean_control_fp_fails_independently_of_baseline_rates
live_corpus_metrics_match_committed_baseline
missing_configured_baseline_is_an_operational_error
missing_configured_custom_rules_are_an_operational_error
missing_explicit_baseline_is_an_operational_error
monorepo_bundle_key_can_drive_exposed_public_key_chain
network_exposed_public_key_chain_fixture_is_gated
network_hallucinated_dependency_fixture
network_permissive_using_true_policy_fixture
network_rls_off_table_fixture
offline_composite_exposed_public_key_chain_golden
pre_dedup_negative_control_would_count_every_blob_as_unique
raw_secret_stops_at_the_candidate_to_finding_boundary
registry_failure_tests::structural_findings_survive_osv_snapshot_failure
registry_failure_tests::structural_findings_survive_registry_outage
registry_flag_does_not_enable_either_rls_tier
registry_tests::registry_runtime_opt_in_is_independent_of_both_rls_tiers
relative_cli_baseline_suppresses_a_real_synthetic_finding
relative_configured_baseline_suppresses_a_real_synthetic_finding
report_format_snapshots_match
repository_network_config_alone_never_enables_a_request
src_api_client_wrapper_drives_rule_one_without_commit_provenance
tests::additional_commit_provenance_qualifies_elevated_key_for_correlation
tests::additional_commit_provenance_qualifies_server_public_key_for_correlation
tests::ambiguous_projectless_copy_does_not_join_known_different_projects
tests::applies_entropy_gate_to_generic_assignments
tests::baseline_suppresses_existing_findings
tests::cache_hit_result_emits_no_name_egress_audit
tests::candidate_round_trips_through_json
tests::catalog_action_omits_and_defaults_the_inapplicable_row_count
tests::classifies_committed_secret_as_critical_even_when_server_only
tests::classifies_legacy_anon_jwt_and_project_ref
tests::classifies_legacy_service_role_as_elevated
tests::classifies_new_publishable_key_as_info
tests::classifies_new_publishable_key_with_colocated_project_url
tests::classifies_new_secret_key_as_critical_when_client_reachable
tests::classifies_new_secret_key_with_colocated_project_url
tests::classify_location_matches_monorepo_segment_rules
tests::classify_location_preserves_flat_repo_behavior
tests::classify_location_uses_segments_not_substrings
tests::clean_control_fixture_produces_zero_findings
tests::coalesced_projectless_client_copy_drives_known_project_probe
tests::coalesces_same_secret_across_paths
tests::coalescing_keeps_different_secrets_at_same_path_separate
tests::coalescing_keeps_same_secret_on_different_projects_separate
tests::coalescing_prefers_bundle_over_signal_bearing_src_api_copy
tests::collected_working_tree_units_feed_the_detector
tests::commit_allowlist_removes_only_the_matching_source_occurrence
tests::committed_elevated_key_moots_tier1_policy_finding
tests::config_loads_from_repo_root_when_target_is_subdirectory
tests::config_path_allowlists_skip_paths_but_cannot_hide_env
tests::config_path_allowlists_suppress_docs_but_cannot_hide_env
tests::config_preserves_all_localstatic_values_and_resolves_repo_relative_paths
tests::configured_allowlist_suppresses_commit_id
tests::configured_allowlist_suppresses_stopword
tests::content_dedup_retains_distinct_source_paths_and_classes
tests::content_id_does_not_change_public_finding_identity
tests::correlates_public_key_with_critical_permissive_policy_without_probe
tests::correlates_public_key_with_critical_rls_disabled_policy_without_probe
tests::correlates_public_key_with_rls_exposure_on_same_project
tests::correlation_locations_are_a_deterministic_unique_union
tests::credential_shaped_coordinate_never_reaches_audit_or_finding
tests::custom_rules_append_without_replacing_defaults_or_safety_allowlists
tests::custom_rules_cannot_override_an_embedded_rule_id
tests::default_rules_compile
tests::dependency_evidence_names_both_f2_reasons
tests::dependency_integrity_flags_invalid_package_names
tests::dependency_integrity_labels_empty_versions_honestly
tests::dependency_integrity_scans_package_lock
tests::dependency_integrity_scans_python_manifests
tests::detector_candidates_feed_supabase_classification
tests::detects_supabase_new_key_shapes
tests::different_historical_contents_at_one_path_remain_distinct_units
tests::duplicate_declarations_coalesce_into_one_finding_with_all_locations
tests::elevated_key_committed_then_removed_fixture_is_history_only_critical
tests::existence_cache_avoids_a_second_request
tests::exit_code_respects_severity_gate
tests::exit_code_uses_severity_gate
tests::expired_existence_cache_is_refreshed
tests::exposed_public_key_correlation_absorbs_constituents_in_summary
tests::finding_retains_every_candidate_source_location_with_the_same_span
tests::generic_entropy_skips_minified_lines_but_provider_rules_still_fire
tests::generic_finding_retains_all_candidate_source_locations
tests::generic_high_entropy_candidates_are_medium_review
tests::gitignore_negation_rescans_whitelisted_path
tests::gitignore_suppresses_matching_paths
tests::gitignored_env_fixture_has_exact_elevated_key_finding
tests::gitignored_env_is_scanned_but_examples_are_skipped
tests::gitignored_env_secret_is_still_reported
tests::harvest_api_references_retains_table_and_rpc_kinds
tests::historical_api_references_use_exact_content_project_context
tests::historical_versions_at_same_path_keep_their_own_project_context
tests::history_budget_sets_scope_warning
tests::history_paths_use_current_ignore_rules
tests::history_scan_collects_changed_blobs_from_all_refs
tests::history_scan_does_not_require_git_on_path_after_fixture_setup
tests::html_render_escapes_content
tests::identical_content_at_server_and_browser_paths_retains_both_locations
tests::ignores_non_supabase_candidate_kinds
tests::inline_allow_suppresses_line
tests::invalid_configured_severity_is_rejected
tests::invalid_dependency_fixture_has_exact_integrity_finding
tests::invalid_package_is_never_sent_and_remains_one_localstatic_finding
tests::json_error_message_is_not_baseline_specific
tests::json_render_is_valid_and_redacted
tests::known_malicious_is_critical_confirmed_and_has_no_name_egress
tests::localstatic_dependency_boundary_excludes_network_crates
tests::loose_version_ranges_are_not_misreported_as_confirmed_osv_matches
tests::nested_gitignore_suppresses_matching_paths_without_substrings
tests::network_scope_defaults_actions_when_reading_older_results
tests::next_build_tree_fixture_is_clean_after_ignore_overrides
tests::offline_pipeline_finds_supabase_and_generic_secrets
tests::operation_advisory_and_inferred_write_do_not_fire_read_chain
tests::osv_failure_is_explicit_and_does_not_erase_existence_results
tests::osv_snapshot_cache_fetches_once_and_matches_locally
tests::outage_is_a_warning_never_a_nonexistent_finding
tests::parallel_unit_detection_matches_serial_results
tests::parsed_dependencies_are_deterministic_and_registry_shaped
tests::parsed_dependencies_include_exact_npm_and_python_lock_versions
tests::parsed_dependency_and_registry_scope_round_trip
tests::path_allowlist_removes_only_the_matching_source_occurrence
tests::production_catalog_queries_are_select_only
tests::production_source_constructs_without_opening_a_connection
tests::project_enrichment_coalescing_is_independent_of_input_order
tests::projectless_copy_joins_single_known_project_for_same_fingerprint
tests::public_404_is_high_confirmed_and_disclosed_once
tests::registry_runtime_opt_in_is_auditable_and_does_not_enable_rls
tests::reports_one_based_spans
tests::repository_alternate_registry_configuration_activates_precision_guard
tests::repository_config_cannot_enable_network_without_runtime_confirmation
tests::repository_path_resolution_preserves_absolute_paths
tests::resolvable_advisory_free_dependency_has_no_finding
tests::rls_policy_evidence_round_trips_through_json
tests::root_unauthorized_and_table_unauthorized_report_distinct_outcomes
tests::root_unauthorized_but_table_readable_is_not_reported_as_key_rejection
tests::rpc_references_remain_typed_and_never_become_table_candidates
tests::same_path_repeated_commits_share_one_location_with_complete_provenance
tests::sarif_render_contains_results_and_locations
tests::scan_associates_new_publishable_key_with_colocated_project_url
tests::scan_result_started_at_is_rfc3339_timestamp
tests::scan_stats_carries_history_truncation
tests::scan_stats_defaults_performance_counters_when_reading_older_results
tests::scoped_and_private_registry_names_never_become_nonexistent_findings
tests::second_full_check_uses_both_caches_and_issues_zero_requests
tests::server_only_uncommitted_public_key_remains_outside_correlation
tests::severity_sorts_from_low_to_critical_by_rank
tests::shallow_repositories_emit_scope_warning
tests::shipped_static_bundle_is_scanned_but_server_vendor_chunks_are_skipped
tests::structurally_invalid_dependencies_are_excluded_from_registry_inputs
tests::tier0_and_tier1_runtime_opt_ins_are_independent
tests::tier0_probe_inputs_dedup_same_project_and_prefer_client_location
tests::tier0_probe_inputs_do_not_cross_probe_ambiguous_harvested_table
tests::tier0_probe_inputs_keep_harvested_tables_project_local
tests::tier0_read_probe_audits_invalid_responses_without_response_material
tests::tier0_read_probe_audits_transport_errors_for_each_attempt
tests::tier0_read_probe_continues_after_root_unavailable_with_harvested_tables
tests::tier0_read_probe_emits_exposed_table_without_row_data
tests::tier0_read_probe_omits_protected_or_empty_tables
tests::tier0_read_probe_refuses_non_supabase_urls
tests::tier0_read_probe_reserves_key_rejected_for_table_request
tests::tier0_read_probe_warns_when_there_are_no_candidate_tables
tests::tier1_accepts_supabase_direct_and_pooler_hosts_for_the_same_project
tests::tier1_catalog_failure_is_nonfatal_and_sanitized
tests::tier1_credential_location_is_the_env_source
tests::tier1_detects_literal_true_permissive_policy
tests::tier1_detects_one_missing_select_policy
tests::tier1_detects_rls_disabled_candidate
tests::tier1_ignores_catalog_tables_outside_the_local_api_candidates
tests::tier1_infers_write_exposure_from_anon_grant_without_policy
tests::tier1_literal_true_matching_rejects_substrings
tests::tier1_metadata_keyed_policy_heuristic_remains_out_of_e2
tests::tier1_mock_catalog_is_read_only_auditable_and_redacted
tests::tier1_output_contains_policy_reproduction_but_no_credentials_or_row_data
tests::tier1_read_exposure_on_different_project_does_not_correlate
tests::tier1_refuses_non_supabase_hosts_schemes_ports_and_overrides_before_queries
tests::tier1_rejects_database_project_mismatch_before_queries
tests::tier1_runtime_opt_in_requires_env_credential_value
tests::tty_render_is_human_readable
tests::tty_render_surfaces_all_locations_and_history_range
tests::unambiguous_project_enrichment_intentionally_changes_baseline_identity
tests::unassociated_table_reference_emits_coverage_warning
tests::vibescanignore_suppresses_matching_paths
tests::warning_messages_disclose_only_public_host_and_ecosystem
tier0_flag_does_not_require_or_enable_tier1
tier1_flag_without_env_credential_is_an_operational_error
```

</details>

## Verification record

Crates were committed largest first, with the complete offline matrix green
before advancing:

| Commit | Crate | Post-commit `bash scripts/verify-all.sh` |
|---|---|---|
| `bd219f4` | `vibescan-core` | PASS |
| `7d7a0bc` | `vibescan-supabase` | PASS |
| `5f5248d` | `vibescan-git` | PASS |
| `4d72959` | `vibescan-registry` | PASS |
| `2f6ecb3` | `vibescan-report` | PASS |
| `5c2f296` | `vibescan-secrets` | PASS |

The Supabase matrix first exposed default-feature unused imports and the Report
matrix first exposed a leading blank line. Each run stopped the track; the
same crate commit was amended, its full matrix passed, and only then did the
next crate begin.

Additional final evidence:

- all 32 tracked files under the fixture/snapshot/metrics paths have
  byte-identical before/after SHA-256 manifests;
- `git diff origin/main -- tests/fixtures
  tests/fixtures/report-format-snapshots
  tests/fixtures/corpus-metrics-baseline.json` is empty;
- `scripts/check-network-boundary.sh`, every Cargo manifest, and the crate DAG
  are unchanged;
- `UPDATE_GOLDEN` and `UPDATE_METRICS` were never set;
- no live request, credential, target-project scan, egress change, or
  target-project write was involved.

The negative control temporarily changed the moved rule-1 correlation severity
from `Critical` to `High` and ran:

```sh
cargo test -p vibescan-core --test golden_corpus \
  --features network,registry --locked
```

It exited 101: 6 of 9 tests failed and named the High-versus-Critical
contradiction across offline, mocked Network, monorepo-bundle, and
client-wrapper coverage. The edit was immediately restored; `git diff
--exit-code` and `git status --short` were empty, and the same 9-test command
then passed. No golden artifact was updated.
