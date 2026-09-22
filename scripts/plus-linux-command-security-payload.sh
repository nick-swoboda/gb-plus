#!/bin/sh
# Builds the exact ARM64 Linux payload consumed by the macOS release job.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$repo_root/scripts/release-paths.sh"
out=$repo_root/target/linux-command-security
build=$out/build
stage=$out/stage
payload=$out/GBPlusCommandSecurityLinuxArm64.tar.gz
source_bundle=$out/bubblewrap-source
zig=${GROK_BUILD_ZIG_BIN:-/opt/homebrew/bin/zig}
zigbuild=${GROK_BUILD_CARGO_ZIGBUILD_BIN:-$(command -v cargo-zigbuild || true)}
probe_source=$repo_root/crates/grok-build-plus-host/guest/plus-contained-probe.c
bwrap_deb=$build/bubblewrap_0.9.0-1ubuntu0.1_arm64.deb

fail() { echo "Linux payload refused: $*" >&2; exit 1; }
digest() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }
bytes() { /usr/bin/stat -f '%z' "$1"; }
verify() { test "$(bytes "$1")" = "$2" && test "$(digest "$1")" = "$3" || fail "$1 changed"; }
fetch() {
  path=$1 expected_bytes=$2 expected_sha=$3 url=$4
  if test ! -f "$path"; then
    /usr/bin/curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
      --max-filesize "$expected_bytes" --output "$path" "$url"
  fi
  verify "$path" "$expected_bytes" "$expected_sha"
}

test "$(/usr/bin/uname -s)" = Darwin || fail "macOS is required"
test "$(/usr/bin/uname -m)" = arm64 || fail "Apple Silicon is required"
test -x "$zig" && test "$($zig version)" = 0.16.0 || fail "Zig 0.16.0 is required"
test -x "$zigbuild" && test "$($zigbuild --version)" = 'cargo-zigbuild 0.22.3' || fail "cargo-zigbuild 0.22.3 is required"
rustup target list --installed --toolchain 1.97.1-aarch64-apple-darwin | /usr/bin/grep -Fxq aarch64-unknown-linux-gnu || fail "rust-std aarch64-unknown-linux-gnu is required"
/bin/mkdir -p "$build" "$out/downloads"
pool=https://ports.ubuntu.com/ubuntu-ports/pool/main/b/bubblewrap
fetch "$bwrap_deb" 49694 3fb4ca3a8d2060444836568ed49d6897a403467e4ba29c93440900093fb96a38 \
  "$pool/bubblewrap_0.9.0-1ubuntu0.1_arm64.deb"
fetch "$out/downloads/bubblewrap_0.9.0-1ubuntu0.1.dsc" 2684 \
  dc163940d29d2630b3ea8780429096ca397e46279afc72d02dfbe55c8f16d422 \
  "$pool/bubblewrap_0.9.0-1ubuntu0.1.dsc"
fetch "$out/downloads/bubblewrap_0.9.0.orig.tar.xz" 118984 \
  c6347eaced49ac0141996f46bba3b089e5e6ea4408bc1c43bab9f2d05dd094e1 \
  "$pool/bubblewrap_0.9.0.orig.tar.xz"
fetch "$out/downloads/bubblewrap_0.9.0.orig.tar.xz.asc" 833 \
  355568011016d6d5592c13830778a9b06365926f6478ae43e51b2ab5c3bc3c92 \
  "$pool/bubblewrap_0.9.0.orig.tar.xz.asc"
fetch "$out/downloads/bubblewrap_0.9.0-1ubuntu0.1.debian.tar.xz" 14080 \
  d253eccba8f6a8d636dd3df241c2d4d722785341c665c7817040aafa7ed3495e \
  "$pool/bubblewrap_0.9.0-1ubuntu0.1.debian.tar.xz"
/usr/bin/ar -p "$bwrap_deb" data.tar.zst > "$build/data.tar.zst"
/usr/bin/tar -xOf "$build/data.tar.zst" ./usr/bin/bwrap > "$build/bwrap"
verify "$build/bwrap" 67816 ae27935781511400c65ebcc0b4669775d602f46251b8707c947a1ac1b160c1c8
/bin/rm -rf -- "$source_bundle"
/bin/mkdir -m 0700 "$source_bundle"
/bin/cp "$out/downloads"/bubblewrap_0.9.0* "$source_bundle/"
/usr/bin/tar -xOf "$build/data.tar.zst" ./usr/share/doc/bubblewrap/copyright \
  > "$source_bundle/COPYRIGHT"
verify "$source_bundle/COPYRIGHT" 3388 229a402fddba5c81005950f28de162359383cba731f5b859b8f82a03c338bf01
test "$(/usr/bin/find "$source_bundle" -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 5 \
  || fail "Bubblewrap corresponding-source inventory changed"
/bin/chmod 0444 "$source_bundle"/*

RUSTUP_TOOLCHAIN=1.97.1-aarch64-apple-darwin \
RUSTUP_AUTO_INSTALL=0 \
CARGO_ZIGBUILD_ZIG_PATH=$zig \
CARGO_ZIGBUILD_CACHE_DIR=$build/zigbuild-cache \
ZIG_GLOBAL_CACHE_DIR=$build/zig-global \
ZIG_LOCAL_CACHE_DIR=$build/zig-local \
CARGO_TARGET_DIR=$build/cargo-target \
  "$zigbuild" zigbuild -p grok-build-plus-host --bin grok-build-linux-helper \
    --features linux-guest-helper --release --target aarch64-unknown-linux-gnu.2.17 \
    --locked --offline
helper=$build/cargo-target/aarch64-unknown-linux-gnu/release/grok-build-linux-helper
test -x "$helper" || fail "Linux helper was not produced"
/usr/bin/file "$helper" | /usr/bin/grep -q 'ELF 64-bit.*ARM aarch64' || fail "Linux helper target changed"

ZIG_GLOBAL_CACHE_DIR=$build/probe-zig-global ZIG_LOCAL_CACHE_DIR=$build/probe-zig-local \
  "$zig" cc -target aarch64-linux-musl -static -Oz -s \
    -o "$build/plus-contained-probe" "$probe_source"
verify "$build/plus-contained-probe" 3160 d36421faefab9a6acb9c141b5f4400126676eb8ff6c87a5faef8b9aed871178c

/bin/rm -rf -- "$stage"
/bin/mkdir -m 0700 "$stage"
/bin/cp "$build/bwrap" "$stage/bwrap"
/bin/cp "$helper" "$stage/grok-build-linux-helper"
/bin/cp "$build/plus-contained-probe" "$stage/plus-contained-probe"
/bin/chmod 0555 "$stage"/*
/usr/bin/touch -t 202601010000 "$stage"/*
COPYFILE_DISABLE=1 /usr/bin/tar --no-xattrs --uid 0 --gid 0 --uname root --gname root \
  -cf "$out/payload.tar" -C "$stage" bwrap grok-build-linux-helper plus-contained-probe
/usr/bin/gzip -9 -n -c "$out/payload.tar" > "$payload"
/bin/rm -f -- "$out/payload.tar"
test "$(bytes "$payload")" -le 5000000 || fail "compressed payload exceeded 5,000,000 bytes"
/usr/bin/printf 'payload=%s\npayload_bytes=%s\npayload_sha256=%s\nhelper_bytes=%s\nhelper_sha256=%s\nzig_sha256=%s\ncargo_zigbuild_sha256=%s\n' \
  "$payload" "$(bytes "$payload")" "$(digest "$payload")" \
  "$(bytes "$helper")" "$(digest "$helper")" "$(digest "$zig")" "$(digest "$zigbuild")"
