#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_svg="$repo_root/crates/grok-build-tauri/icons/icon.svg"
target_png="$repo_root/crates/grok-build-tauri/icons/icon.png"
target_icns="$repo_root/crates/grok-build-tauri/macos/GrokBuildPlus.icns"
work_root=$(/usr/bin/mktemp -d /private/tmp/grok-build-plus-icon.XXXXXX)
iconset="$work_root/GrokBuildPlus.iconset"
master_png="$work_root/GrokBuildPlus-1024.png"

cleanup() {
  /bin/rm -rf -- "$work_root"
}
trap cleanup EXIT HUP INT TERM

[ -f "$source_svg" ] || {
  echo "missing icon source: $source_svg" >&2
  exit 1
}

/bin/mkdir -m 700 "$iconset"
/usr/bin/swift -module-cache-path "$work_root/modules" \
  "$repo_root/scripts/render-macos-icon.swift" "$source_svg" "$master_png"
/bin/cp "$master_png" "$target_png"

render_icon() {
  pixels=$1
  output=$2
  /usr/bin/sips --resampleHeightWidth "$pixels" "$pixels" "$master_png" --out "$iconset/$output" >/dev/null
}

render_icon 16 icon_16x16.png
render_icon 32 icon_16x16@2x.png
render_icon 32 icon_32x32.png
render_icon 64 icon_32x32@2x.png
render_icon 128 icon_128x128.png
render_icon 256 icon_128x128@2x.png
render_icon 256 icon_256x256.png
render_icon 512 icon_256x256@2x.png
render_icon 512 icon_512x512.png
render_icon 1024 icon_512x512@2x.png

/usr/bin/iconutil -c icns "$iconset" -o "$target_icns"
/bin/mkdir -p "$repo_root/crates/grok-build-tauri/ui/assets"
/bin/cp "$source_svg" "$repo_root/crates/grok-build-tauri/ui/assets/gb-plus.svg"

actual_size=$(/usr/bin/sips -g pixelWidth -g pixelHeight "$iconset/icon_512x512@2x.png" | /usr/bin/awk '/pixelWidth|pixelHeight/ { print $2 }' | /usr/bin/paste -sd x -)
[ "$actual_size" = "1024x1024" ] || {
  echo "icon master has unexpected dimensions: $actual_size" >&2
  exit 1
}

echo "generated $target_icns"
