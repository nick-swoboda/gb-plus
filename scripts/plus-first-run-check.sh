#!/bin/sh
# Non-dev first-run check. Does not auto-install Colima.
# One step: grok-build --plus-prepare-guest (safe Colima start + verify
# install root + repair hints), then print the GUEST line from --plus-smoke.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
echo "GB Plus first-run check"
app_bin="${GROK_BUILD_TAURI_BIN:-$root/dist/GB Plus.app/Contents/MacOS/grok-build-tauri}"
[ -x "$app_bin" ] || { echo "GB Plus app is not built" >&2; exit 1; }
expected_version=$(python3 -c 'import json,sys; print("GB Plus " + json.load(open(sys.argv[1]))["version"])' "$root/crates/grok-build-tauri/tauri.conf.json")
[ "$("$app_bin" --version)" = "$expected_version" ] || { echo "GB Plus app version differs from the release source" >&2; exit 1; }
"$app_bin" --tauri-smoke
echo "See README.md for setup and SECURITY.md for containment limits."
echo "prepare guest / start Colima (if safe) / verify install root / repair hints"
bin="${GROK_BUILD_BIN:-$root/target/debug/grok-build}"
if [ -x "$bin" ]; then
  "$bin" --plus-prepare-guest
  "$bin" --plus-smoke | awk '/^GUEST /{print; found=1} END{if(!found) print "GUEST line missing from --plus-smoke"}'
else
  echo "service missing: grok-build is not built (cargo build --locked -p grok-build-desktop --bin grok-build)"
  if command -v colima >/dev/null 2>&1; then
    if colima status 2>&1 | grep -q "is running"; then
      echo "colima: running"
    else
      echo "guest down: colima is not running"
    fi
  else
    echo "guest down: colima is not on PATH"
  fi
fi
