#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

default_metadata="$(mktemp)"
network_metadata="$(mktemp)"
metadata_error="$(mktemp)"
trap 'rm -f "$default_metadata" "$network_metadata" "$metadata_error"' EXIT

host="$(rustc -vV | sed -n 's/^host: //p')"

metadata() {
  local output="$1"
  shift

  if cargo metadata --format-version 1 --locked --filter-platform "$host" "$@" > "$output" 2> "$metadata_error"; then
    return 0
  fi

  if grep -q "because --locked was passed" "$metadata_error"; then
    echo "network-boundary: locked metadata unavailable; retrying offline for boundary diagnostics" >&2
    cargo metadata --format-version 1 --offline --filter-platform "$host" "$@" > "$output"
    return 0
  fi

  cat "$metadata_error" >&2
  return 1
}

metadata "$default_metadata"
metadata "$network_metadata" --features network

python3 scripts/check-network-boundary.py --self-test
python3 scripts/check-network-boundary.py "$default_metadata" "$network_metadata"
