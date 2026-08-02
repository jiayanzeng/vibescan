#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
real_repo="${VIBESCAN_REAL_REPO:-}"
current_step="startup"
verify_tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/vibescan-verify-all.XXXXXX")"
matrix_started=0

usage() {
  cat <<'EOF'
usage: scripts/verify-all.sh [--real-repo REAL_REPO]

Run the complete deterministic offline closeout matrix. The optional
real-repository leg runs only when --real-repo or VIBESCAN_REAL_REPO supplies
an explicit fixture. No live Network leg is enabled by default.
EOF
}

finish() {
  local status=$?
  if [[ -d "$verify_tmp_dir" && "$verify_tmp_dir" == *vibescan-verify-all.* ]]; then
    rm -rf -- "$verify_tmp_dir"
  fi
  if (( matrix_started == 0 )); then
    return
  fi
  if (( status == 0 )); then
    echo
    echo "verify-all: PASS — complete offline closeout matrix succeeded"
  else
    echo
    echo "verify-all: FAIL — step '$current_step' exited with status $status" >&2
  fi
}
trap finish EXIT

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi
if [[ ${1:-} == "--real-repo" ]]; then
  if [[ $# -ne 2 || -z ${2:-} ]]; then
    usage >&2
    exit 2
  fi
  real_repo="$2"
  shift 2
fi
if (( $# != 0 )); then
  usage >&2
  exit 2
fi

cd "$repo_root"
matrix_started=1

run_step() {
  current_step="$1"
  shift
  echo
  echo "== $current_step =="
  "$@"
}

run_step "1. format" cargo fmt --all -- --check

run_step "2a. clippy (default)" \
  cargo clippy --workspace --all-targets --locked -- -D warnings
run_step "2b. clippy (network)" \
  cargo clippy --workspace --all-targets --features network --locked -- -D warnings
run_step "2c. clippy (registry)" \
  cargo clippy --workspace --all-targets --features registry --locked -- -D warnings
run_step "2d. clippy (network,registry)" \
  cargo clippy --workspace --all-targets --features network,registry --locked -- -D warnings

run_step "3a. tests (default)" cargo test --workspace --locked
run_step "3b. tests (network)" cargo test --workspace --features network --locked
run_step "3c. tests (registry)" cargo test --workspace --features registry --locked
run_step "3d. tests (network,registry)" \
  cargo test --workspace --features network,registry --locked

run_step "4. real-repository invariant self-tests" \
  python3 scripts/real-repo-invariants.py --self-test

run_step "5a. Network-boundary self-tests" \
  python3 scripts/check-network-boundary.py --self-test
echo "note: cargo-dist-style shasum warnings from the boundary leg are benign; judge the exit code"
run_step "5b. Network-boundary metadata matrix" \
  bash scripts/check-network-boundary.sh

run_step "6. release-publishing structure" \
  python3 scripts/verify-release-publishing.py

run_step "7a. status-consistency self-tests" \
  python3 scripts/check-status-consistency.py --self-test
run_step "7b. status-consistency repository gate" \
  python3 scripts/check-status-consistency.py

# This deliberately re-runs the oracle self-test, default workspace tests, and
# boundary checker. The legacy helper is itself a composed hardening contract;
# exercising it end to end proves that its public offline entry point remains
# operational in addition to proving each constituent above.
echo "note: step 8 deliberately re-runs the legacy hardening composition"
run_step "8. hardening helper (offline composition)" \
  bash scripts/verify-hardening-checks.sh --offline-only

run_step "9. whitespace errors" git diff --check

if [[ -z "$real_repo" ]]; then
  echo
  echo "real-repo leg skipped: no fixture supplied via --real-repo or VIBESCAN_REAL_REPO"
else
  if [[ ${VIBESCAN_REAL_REPO_NETWORK:-0} == "1" ]]; then
    echo "real-repo Network leg explicitly enabled by VIBESCAN_REAL_REPO_NETWORK=1"
  else
    echo "real-repo leg is LocalStatic; live Network work remains disabled"
  fi
  run_step "10. optional real-repository hardening leg" \
    bash scripts/verify-hardening-checks.sh --real-repo-only "$real_repo"
fi
