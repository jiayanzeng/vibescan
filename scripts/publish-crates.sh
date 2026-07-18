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

for package in "${publish_order[@]}"; do
  cargo publish --locked --package "$package"
done
