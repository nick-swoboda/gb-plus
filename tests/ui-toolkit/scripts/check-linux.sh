#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

test "$(uname -s)" = "Linux"
test "$(uname -m)" = "x86_64"
test "$(rustc +1.97.0 --version)" = "rustc 1.97.0 (2d8144b78 2026-07-07)"
test "$(cargo +1.97.0 --version)" = "cargo 1.97.0 (c980f4866 2026-06-30)"
cmp -s "$root/gpui-ce/src/main.rs" "$root/gpui-upstream/src/main.rs"

for candidate in gpui-ce gpui-upstream; do
  manifest="$root/$candidate/Cargo.toml"
  cargo +1.97.0 metadata --locked --format-version 1 --manifest-path "$manifest" >/dev/null
  cargo +1.97.0 fmt --manifest-path "$manifest" -- --check
  cargo +1.97.0 check --locked --all-targets --manifest-path "$manifest"
  cargo +1.97.0 test --locked --manifest-path "$manifest"
  cargo +1.97.0 clippy --locked --all-targets --manifest-path "$manifest" -- -D warnings
done

