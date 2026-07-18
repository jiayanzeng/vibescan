# Golden fixture contract

This file supplements the repository-root `AGENTS.md` and governs everything
under `tests/fixtures/`.

## Safety and determinism

- Use synthetic repositories and unmistakably fake credentials only. Never
  copy a real secret, project ref, endpoint, response row, username, email,
  home path, or private source fragment into a fixture.
- Fixture paths and expected locations are repo-relative. Expected artifacts
  contain no absolute home-directory paths, temp paths, live timestamps,
  durations, tool-version drift, random IDs, or nondeterministic map/order
  output.
- Keep clean controls genuinely clean and vulnerable fixtures minimal: one
  intended failure mode plus explicit negative controls wherever practical.
- Pin author, committer, dates, messages, and content when a history bundle is
  needed. Runtime scanning must still exercise the LocalStatic gitoxide path.
- Network fixtures use a local mock/injected client. They must not contact a
  live Supabase project, registry, advisory feed, or shared service.
- Never place returned row data in a mock expectation or golden. Assert that it
  is discarded.

## Updating expectations

Set `UPDATE_GOLDEN=1` only for an intentional behavior change. Review every
changed stable ID, severity, location, evidence field, warning, and ordering
entry against `vibescan-architecture.md`. Then rerun the same test without
`UPDATE_GOLDEN` and run `git diff --check`.

Do not bless a regression, delete a fixture, or add `#[ignore]` to make a gate
pass. Deferred placeholders must say exactly which architecture capability is
missing. Promote them only when a deterministic mock exercises the real
pipeline. The RLS-off and permissive-policy fixtures are live under the
`network` feature through an injected Tier 1 catalog; only the registry-backed
hallucinated-dependency fixture remains capability-gated.

Temporary mutation tests used to prove drift detection must restore the exact
fixture before the task ends.
