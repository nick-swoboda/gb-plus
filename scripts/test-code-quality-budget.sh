#!/bin/sh
# A failed or absent Cargo graph must never become a zero-dependency pass.
set -eu
repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/gbplus-budget-test.XXXXXX")
cleanup() {
  rm -f -- "$fixture/cargo" "$fixture/output"
  rmdir -- "$fixture"
}
trap cleanup EXIT HUP INT TERM
refuses() {
  name=$1
  body=$2
  printf '#!/bin/sh\n%s\n' "$body" > "$fixture/cargo"
  chmod 0700 "$fixture/cargo"
  if PATH="$fixture:$PATH" sh "$repo_root/scripts/verify-code-quality-budget.sh" source > "$fixture/output" 2>&1; then
    printf 'FAIL %s: invalid graph was accepted\n' "$name" >&2
    exit 1
  fi
  if grep -q 'CODE-QUALITY BUDGET PASSED' "$fixture/output"; then
    printf 'FAIL %s: failure emitted a pass sentinel\n' "$name" >&2
    exit 1
  fi
  grep -q 'code-quality budget refused: dependency graph' "$fixture/output"
  printf 'PASS %s\n' "$name"
}
refuses failure-before-output 'exit 42'
refuses failure-after-partial-output 'printf "grok-build-tauri v0.2.1-plus\nserde v1.0.0\n"; exit 42'
refuses empty-success 'exit 0'
refuses root-only-success 'printf "grok-build-tauri v0.2.1-plus\n"'
