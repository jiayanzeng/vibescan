#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
real_repo="${1:-${VIBESCAN_REAL_REPO:-}}"

cd "$repo_root"

echo "== cargo test --workspace =="
cargo test --workspace

echo "== network boundary =="
bash scripts/check-network-boundary.sh

if [[ -z "$real_repo" ]]; then
  echo "skipped: no real-repo fixture provided via argv[1] or VIBESCAN_REAL_REPO"
  exit 0
fi

if [[ ! -d "$real_repo" ]]; then
  echo "real repo not found: $real_repo" >&2
  echo "pass a Next.js/Supabase repo path as argv[1] or VIBESCAN_REAL_REPO" >&2
  exit 2
fi

tmp_dir="$(mktemp -d)"
clean_json="$(mktemp)"
planted_json=""
trap 'rm -rf "$tmp_dir" "$clean_json" "${planted_json:-}"' EXIT

copy_dir="$tmp_dir/repo"
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

echo "== clean real repo scan: $real_repo (sanitized temp copy) =="
cargo run --quiet -p vibescan-cli -- "$copy_dir" --format json --no-history --severity-gate info > "$clean_json"
python3 - "$clean_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)

findings = result.get("findings", [])
if findings:
    print(f"expected zero findings in clean tree, got {len(findings)}", file=sys.stderr)
    for finding in findings:
        print(f"- {finding.get('id')}: {finding.get('title')}", file=sys.stderr)
    sys.exit(1)
PY

echo "== planted gitignored .env scan =="
(
  cd "$copy_dir"
  printf '.env\n.env.*\n' > .gitignore
  printf 'SUPABASE_SERVICE_ROLE_KEY=sb_secret_0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n' > .env
)

planted_json="$(mktemp)"
set +e
cargo run --quiet -p vibescan-cli -- "$copy_dir" --format json --no-history --severity-gate info > "$planted_json"
planted_status=$?
set -e
python3 - "$planted_json" "$planted_status" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)

status = int(sys.argv[2])
findings = result.get("findings", [])
if status == 0:
    print("expected planted secret scan to fail the info severity gate", file=sys.stderr)
    sys.exit(1)

if not any(
    any(location.get("path") == ".env" for location in finding.get("locations", []))
    and "Supabase" in finding.get("title", "")
    for finding in findings
):
    print("expected planted gitignored .env Supabase secret to be flagged", file=sys.stderr)
    print(json.dumps(findings, indent=2), file=sys.stderr)
    sys.exit(1)
PY

echo "hardening verification passed"
