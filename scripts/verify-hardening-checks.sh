#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="all"
real_repo=""
tmp_dir=""
scan_status=0

usage() {
  cat <<'EOF'
usage: scripts/verify-hardening-checks.sh [--offline-only | --real-repo-only] [REAL_REPO]

With no mode, run the offline leg and then the optional real-repository leg.
REAL_REPO may also be supplied through VIBESCAN_REAL_REPO. Set
VIBESCAN_REAL_REPO_NETWORK=1 only to explicitly opt the real target into the
read-only, network-feature Tier 0 probe; controls remain LocalStatic.
EOF
}

cleanup() {
  if [[ -n "$tmp_dir" ]]; then
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT

if [[ ${1:-} == "--offline-only" || ${1:-} == "--real-repo-only" ]]; then
  mode="${1#--}"
  shift
elif [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

if (( $# > 1 )); then
  usage >&2
  exit 2
fi
if (( $# == 1 )); then
  real_repo="$1"
elif [[ "$mode" == "offline-only" ]]; then
  real_repo=""
else
  real_repo="${VIBESCAN_REAL_REPO:-}"
fi

if [[ "$mode" == "offline-only" && -n "$real_repo" ]]; then
  echo "--offline-only does not accept a real-repository path" >&2
  exit 2
fi

cd "$repo_root"

run_offline_leg() {
  echo "== real-repository invariant checker self-tests =="
  python3 scripts/real-repo-invariants.py --self-test

  echo "== cargo test --workspace --locked =="
  cargo test --workspace --locked

  echo "== network boundary =="
  bash scripts/check-network-boundary.sh

  echo "hardening offline verification passed"
}

run_scan() {
  local target="$1"
  local output="$2"
  local network_enabled="$3"
  local -a cargo_args=(run --quiet --locked -p vibescan-cli)
  local -a scan_args=("$target" --format json --no-history --severity-gate info)

  if [[ "$network_enabled" == "1" ]]; then
    cargo_args+=(--features network)
    scan_args+=(--rls-tier0-read-probe)
  fi

  set +e
  cargo "${cargo_args[@]}" -- "${scan_args[@]}" > "$output"
  scan_status=$?
  set -e

  if [[ ! -s "$output" ]]; then
    echo "vibescan produced no JSON for $target (status $scan_status)" >&2
    exit 1
  fi
}

run_real_repo_leg() {
  if [[ -z "$real_repo" ]]; then
    echo "real-repo leg skipped: no fixture"
    return
  fi
  if [[ ! -d "$real_repo" ]]; then
    echo "real repo not found: $real_repo" >&2
    echo "pass a Next.js/Supabase repo path or set VIBESCAN_REAL_REPO" >&2
    exit 2
  fi

  real_repo="$(cd "$real_repo" && pwd -P)"
  local network_enabled="${VIBESCAN_REAL_REPO_NETWORK:-0}"
  if [[ "$network_enabled" != "0" && "$network_enabled" != "1" ]]; then
    echo "VIBESCAN_REAL_REPO_NETWORK must be 0 or 1" >&2
    exit 2
  fi

  tmp_dir="$(mktemp -d)"
  local real_json="$tmp_dir/real.json"
  local clean_json="$tmp_dir/clean.json"
  local planted_json="$tmp_dir/planted.json"
  local copy_dir="$tmp_dir/repo"

  if [[ "$network_enabled" == "1" ]]; then
    echo "== real repository invariant scan (explicit read-only Network opt-in): $real_repo =="
  else
    echo "== real repository invariant scan (LocalStatic): $real_repo =="
  fi
  run_scan "$real_repo" "$real_json" "$network_enabled"
  local real_summary
  real_summary="$(python3 scripts/real-repo-invariants.py \
    --scan-root "$real_repo" \
    --require-classification-coverage \
    "$real_json")"

  mkdir -p "$copy_dir"
  rsync -a \
    --exclude '.git' \
    --exclude 'node_modules' \
    --exclude '.next' \
    "$real_repo"/ "$copy_dir"/
  find "$copy_dir" -type f \( -name '.env' -o -name '.env.*' \) -delete
  (
    cd "$copy_dir"
    git init --quiet
  )

  echo "== sanitized zero-finding control =="
  run_scan "$copy_dir" "$clean_json" 0
  python3 scripts/real-repo-invariants.py \
    --scan-root "$copy_dir" \
    --expect-findings 0 \
    --quiet \
    "$clean_json"

  echo "== planted gitignored .env positive control =="
  (
    cd "$copy_dir"
    printf '.env\n.env.*\n' > .gitignore
    printf 'SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n' > .env
  )
  run_scan "$copy_dir" "$planted_json" 0
  if [[ "$scan_status" == "0" ]]; then
    echo "expected planted secret scan to fail the info severity gate" >&2
    exit 1
  fi
  python3 scripts/real-repo-invariants.py \
    --scan-root "$copy_dir" \
    --require-supabase-location .env \
    --quiet \
    "$planted_json"

  printf '%s\n' "$real_summary"
  echo "hardening real-repo verification passed"
}

if [[ "$mode" != "real-repo-only" ]]; then
  run_offline_leg
fi
if [[ "$mode" != "offline-only" ]]; then
  run_real_repo_leg
fi
