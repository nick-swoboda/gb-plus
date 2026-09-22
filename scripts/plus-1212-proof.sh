#!/bin/sh
# Containment diagnostic; see SECURITY.md for qualification limits.
# Mac native is not 12/12. Nested Docker is not 12/12.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
bin="${GROK_BUILD_BIN:-$root/target/debug/grok-build}"
if [ ! -x "$bin" ]; then
  bin="$root/target/release/grok-build"
fi
if [ ! -x "$bin" ]; then
  echo "grok-build is not built; run: cargo build --locked -p grok-build-desktop --bin grok-build" >&2
  exit 2
fi
exec "$bin" --plus-1212-proof
