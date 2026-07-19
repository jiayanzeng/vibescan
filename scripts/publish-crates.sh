#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

publish_order=(
  vibescan-types
  vibescan-secrets
  vibescan-git
  vibescan-report
  vibescan-supabase
  vibescan-registry
  vibescan-core
  vibescan-cli
)

case "${1:-}" in
  --dry-run)
    for package in "${publish_order[@]}"; do
      cargo package --locked --allow-dirty --package "$package" --list >/dev/null
      printf 'packaging contract passed for %s\n' "$package"
    done
    exit 0
    ;;
  --publish)
    ;;
  *)
    printf 'usage: %s --dry-run|--publish\n' "$0" >&2
    exit 2
    ;;
esac

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
  printf 'CARGO_REGISTRY_TOKEN is required for live crates.io publication\n' >&2
  exit 1
fi

retry_seconds="${VIBESCAN_CRATES_IO_RETRY_SECONDS:-60}"
max_attempts="${VIBESCAN_CRATES_IO_MAX_ATTEMPTS:-12}"

if ! [[ "$retry_seconds" =~ ^[0-9]+$ ]]; then
  printf 'VIBESCAN_CRATES_IO_RETRY_SECONDS must be a non-negative integer\n' >&2
  exit 2
fi
if ! [[ "$max_attempts" =~ ^[1-9][0-9]*$ ]]; then
  printf 'VIBESCAN_CRATES_IO_MAX_ATTEMPTS must be a positive integer\n' >&2
  exit 2
fi

publish_log_dir="$(mktemp -d "${TMPDIR:-/tmp}/vibescan-publish-crates.XXXXXX")"
trap 'rm -rf "$publish_log_dir"' EXIT

publish_package() {
  local package="$1"
  local attempt=1
  local log_file="$publish_log_dir/$package.log"
  local cargo_status

  while true; do
    : >"$log_file"
    if cargo publish --locked --package "$package" 2>&1 | tee "$log_file"; then
      return 0
    else
      cargo_status="${PIPESTATUS[0]}"
    fi

    if ! grep -Fq 'failed to publish to registry' "$log_file" \
      || ! grep -Fq 'status 429 Too Many Requests' "$log_file"; then
      return "$cargo_status"
    fi

    if ((attempt >= max_attempts)); then
      printf 'crates.io rate-limit retry budget exhausted for %s after %s attempts\n' \
        "$package" "$attempt" >&2
      return "$cargo_status"
    fi

    printf 'crates.io rate-limited %s; retrying in %s seconds (%s/%s)\n' \
      "$package" "$retry_seconds" "$attempt" "$max_attempts" >&2
    sleep "$retry_seconds"
    attempt=$((attempt + 1))
  done
}

for package in "${publish_order[@]}"; do
  publish_package "$package"
done
