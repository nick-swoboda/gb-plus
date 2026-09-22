#!/bin/sh
# Dependency-free source/dependency and optional macOS artifact budget gate.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
baseline="$repo_root/scripts/code-quality-budget.txt"
mode=${1:-source}

fail() {
  /bin/echo "code-quality budget refused: $*" >&2
  exit 1
}

baseline_value() {
  key=$1
  value=$(/usr/bin/awk -v key="$key" '$1 == key { print $2; count += 1 } END { if (count != 1) exit 1 }' "$baseline") \
    || fail "baseline key $key is missing or duplicated"
  case "$value" in
    ''|*[!0-9]*) fail "baseline key $key is not a nonnegative integer" ;;
  esac
  /usr/bin/printf '%s\n' "$value"
}

assert_at_most() {
  label=$1
  actual=$2
  maximum=$3
  [ "$actual" -le "$maximum" ] \
    || fail "$label grew to $actual (maximum $maximum)"
  /usr/bin/printf '%s=%s (maximum %s)\n' "$label" "$actual" "$maximum"
}

sum_lines() {
  total=0
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    lines=$(/usr/bin/wc -l < "$repo_root/$path" | /usr/bin/tr -d ' ')
    total=$((total + lines))
  done
  /usr/bin/printf '%s\n' "$total"
}

production_rust_paths() {
  /usr/bin/find "$repo_root/crates" -type f -name '*.rs' -print \
    | /usr/bin/awk -v prefix="$repo_root/" '
      index($0, prefix) == 1 { $0 = substr($0, length(prefix) + 1) }
      !/(^|\/)(tests?|test_support)(\/|\.rs$)/ &&
      $0 !~ /daily_use_soak\.rs$/
    '
}

shipping_ui_paths() {
  /usr/bin/find "$repo_root/crates/grok-build-tauri/ui" -type f \
    \( -name '*.js' -o -name '*.css' -o -name '*.html' \) -print \
    | /usr/bin/awk -v prefix="$repo_root/" '
      index($0, prefix) == 1 { print substr($0, length(prefix) + 1) }
    '
}

assert_semantic_production_layout() {
  part_paths=$(production_rust_paths | /usr/bin/grep -E '(^|/)part_[0-9]+\.rs$' || true)
  [ -z "$part_paths" ] \
    || fail "production Rust still contains numbered part files: $part_paths"
  /usr/bin/printf 'production_numbered_part_files=0\n'
}

production_rust_lines=$(production_rust_paths | sum_lines)
shipping_ui_lines=$(shipping_ui_paths | sum_lines)
dependency_tree=$(
  cd "$repo_root"
  cargo tree -p grok-build-tauri --edges normal --locked --prefix none
) || fail "dependency graph command failed; no dependency count is available"
case "$dependency_tree" in
  'grok-build-tauri '*) ;;
  *) fail "dependency graph is empty or lacks the requested Tauri root" ;;
esac
external_dependencies=$(
  /usr/bin/printf '%s\n' "$dependency_tree" \
    | /usr/bin/sort -u \
    | /usr/bin/grep -v '^grok-build-' \
    | /usr/bin/awk 'END { print NR + 0 }'
)
[ "$external_dependencies" -gt 0 ] \
  || fail "dependency graph contains no external entries; measurement is unavailable"

assert_at_most production_rust_lines "$production_rust_lines" "$(baseline_value production_rust_lines)"
assert_at_most shipping_ui_lines "$shipping_ui_lines" "$(baseline_value shipping_ui_lines)"
assert_at_most tauri_external_dependency_entries "$external_dependencies" "$(baseline_value tauri_external_dependency_entries)"
assert_semantic_production_layout

case "$mode" in
  source) ;;
  artifacts)
    app_path="$repo_root/dist/GB Plus.app"
    tauri_path="$app_path/Contents/MacOS/grok-build-tauri"
    broker_path="$app_path/Contents/Helpers/grok-build-keychain-broker"
    zip_path="$repo_root/dist/gb-plus-macos-arm64.zip"
    [ -d "$app_path" ] || fail "missing $app_path"
    [ -f "$tauri_path" ] || fail "missing bundled Tauri executable"
    [ -f "$broker_path" ] || fail "missing bundled Keychain broker"
    [ -f "$zip_path" ] || fail "missing release zip"

    file_bytes() {
      if [ "$(/usr/bin/uname -s)" = Darwin ]; then
        /usr/bin/stat -f '%z' "$1"
      else
        /usr/bin/stat -c '%s' "$1"
      fi
    }

    app_payload_bytes=0
    while IFS= read -r file; do
      app_payload_bytes=$((app_payload_bytes + $(file_bytes "$file")))
    done <<EOF
$(/usr/bin/find "$app_path" -type f -print)
EOF

    assert_at_most bundled_tauri_bytes "$(file_bytes "$tauri_path")" "$(baseline_value bundled_tauri_bytes)"
    assert_at_most keychain_broker_bytes "$(file_bytes "$broker_path")" "$(baseline_value keychain_broker_bytes)"
    assert_at_most app_payload_bytes "$app_payload_bytes" "$(baseline_value app_payload_bytes)"
    assert_at_most release_zip_bytes "$(file_bytes "$zip_path")" "$(baseline_value release_zip_bytes)"
    /usr/bin/shasum -a 256 "$tauri_path" "$broker_path" "$zip_path"
    ;;
  *) fail "usage: $0 [source|artifacts]" ;;
esac

/bin/echo "CODE-QUALITY BUDGET PASSED"
