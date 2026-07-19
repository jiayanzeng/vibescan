#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test_root="$(mktemp -d "${TMPDIR:-/tmp}/vibescan-publish-crates-test.XXXXXX")"
trap 'rm -rf "$test_root"' EXIT

fake_bin="$test_root/bin"
mkdir -p "$fake_bin"

cat >"$fake_bin/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
set -euo pipefail

package=""
while (($# > 0)); do
  if [[ "$1" == "--package" ]]; then
    package="$2"
    break
  fi
  shift
done

if [[ -z "$package" ]]; then
  printf 'fake cargo did not receive --package\n' >&2
  exit 2
fi

printf '%s\n' "$package" >>"$FAKE_CARGO_CALLS"

case "$FAKE_CARGO_MODE" in
  retry-once)
    if [[ "$package" == "vibescan-types" && ! -e "$FAKE_CARGO_STATE/retried" ]]; then
      touch "$FAKE_CARGO_STATE/retried"
      printf 'error: failed to publish to registry at https://crates.io\n' >&2
      printf 'status 429 Too Many Requests\n' >&2
      exit 101
    fi
    ;;
  fatal)
    printf 'error: failed to publish to registry at https://crates.io\n' >&2
    printf 'status 403 Forbidden\n' >&2
    exit 101
    ;;
  always-429)
    printf 'error: failed to publish to registry at https://crates.io\n' >&2
    printf 'status 429 Too Many Requests\n' >&2
    exit 101
    ;;
  *)
    printf 'unknown fake cargo mode: %s\n' "$FAKE_CARGO_MODE" >&2
    exit 2
    ;;
esac
FAKE_CARGO
chmod +x "$fake_bin/cargo"

run_publish() {
  local mode="$1"
  local attempts="$2"
  local output_file="$3"

  : >"$test_root/calls"
  rm -f "$test_root/retried"
  env \
    PATH="$fake_bin:$PATH" \
    CARGO_REGISTRY_TOKEN="synthetic-test-token" \
    VIBESCAN_CRATES_IO_RETRY_SECONDS=0 \
    VIBESCAN_CRATES_IO_MAX_ATTEMPTS="$attempts" \
    FAKE_CARGO_MODE="$mode" \
    FAKE_CARGO_CALLS="$test_root/calls" \
    FAKE_CARGO_STATE="$test_root" \
    bash scripts/publish-crates.sh --publish >"$output_file" 2>&1
}

run_publish retry-once 2 "$test_root/retry.log"
[[ "$(wc -l <"$test_root/calls" | tr -d ' ')" == "9" ]]
[[ "$(sed -n '1p' "$test_root/calls")" == "vibescan-types" ]]
[[ "$(sed -n '2p' "$test_root/calls")" == "vibescan-types" ]]
[[ "$(sed -n '9p' "$test_root/calls")" == "vibescan-cli" ]]
grep -Fq 'crates.io rate-limited vibescan-types' "$test_root/retry.log"

set +e
run_publish fatal 2 "$test_root/fatal.log"
fatal_exit=$?
set -e
[[ "$fatal_exit" != "0" ]]
[[ "$(wc -l <"$test_root/calls" | tr -d ' ')" == "1" ]]
if grep -Fq 'retrying' "$test_root/fatal.log"; then
  printf 'non-429 publication failure was retried\n' >&2
  exit 1
fi

set +e
run_publish always-429 2 "$test_root/exhausted.log"
exhausted_exit=$?
set -e
[[ "$exhausted_exit" != "0" ]]
[[ "$(wc -l <"$test_root/calls" | tr -d ' ')" == "2" ]]
grep -Fq 'retry budget exhausted' "$test_root/exhausted.log"

printf 'crates.io publication retry policy verified\n'
