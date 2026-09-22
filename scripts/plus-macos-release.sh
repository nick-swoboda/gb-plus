#!/bin/sh
# Primary local macOS 15 arm64 bundle. Supports explicit ad-hoc or persistent
# local self-signed identity; never claims Developer ID, notarization, Gate 3,
# tagging, or publication.
set -eu
unset CONST_RANDOM_SEED

signing_mode=adhoc
case $# in
  0) ;;
  1)
    case "$1" in
      --local-signing) signing_mode=local ;;
      --adhoc) signing_mode=adhoc ;;
      *) /bin/echo "usage: $0 [--adhoc|--local-signing]" >&2; exit 2 ;;
    esac
    ;;
  *) /bin/echo "usage: $0 [--adhoc|--local-signing]" >&2; exit 2 ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
/bin/mkdir -p "$repo_root/.cache"
dist_root=$(/usr/bin/mktemp -d "$repo_root/.cache/gbplus-release.XXXXXX")
app_path="$dist_root/GB Plus.app"
previous_app_path="$dist_root/Grok Build+.app"
legacy_path="$dist_root/grok-build-macos"
zip_path="$dist_root/gb-plus-macos-arm64.zip"
previous_zip_path="$dist_root/grok-build-macos-arm64.zip"
checksum_path="$dist_root/SHA256SUMS"
binary_source="$repo_root/target/release/grok-build-tauri"
plist_source="$repo_root/crates/grok-build-tauri/macos/Info.plist"
icon_source="$repo_root/crates/grok-build-tauri/macos/GrokBuildPlus.icns"
entitlements_source="$repo_root/crates/grok-build-tauri/macos/GrokBuildPlus.entitlements"
bundle_binary="$app_path/Contents/MacOS/grok-build-tauri"
bundle_helpers="$app_path/Contents/Helpers"
bundle_broker="$bundle_helpers/grok-build-keychain-broker"
bundle_mcp_broker="$bundle_helpers/grok-build-mcp-keychain-broker"
bundle_resources="$app_path/Contents/Resources"
broker_binary_source="$repo_root/target/release/grok-build-keychain-broker"
broker_signed_stage="$repo_root/target/release/.grok-build-keychain-broker.signed"
broker_identifier="com.grokbuild.plus.credential-broker"
mcp_broker_identifier="com.grokbuild.plus.mcp-credential-broker"
mcp_broker_signed_stage="$repo_root/target/release/.grok-build-mcp-keychain-broker.signed"
release_receipt_source="$repo_root/target/release/grok-build-plus-release-receipt.json"
linux_payload_builder="$repo_root/scripts/plus-linux-command-security-payload.sh"
linux_payload_name="GBPlusCommandSecurityLinuxArm64.tar.gz"
linux_payload_source="$repo_root/target/linux-command-security/$linux_payload_name"
linux_helper_source="$repo_root/target/linux-command-security/build/cargo-target/aarch64-unknown-linux-gnu/release/grok-build-linux-helper"
bwrap_source_root="$repo_root/target/linux-command-security/bubblewrap-source"
verify_root=""
xterm_asset_root="$repo_root/crates/grok-build-tauri/ui/vendor/xterm"
whisper_sys_root="$repo_root/vendor/whisper-rs-sys-0.15.0-grok"
workflow_notice_root="$repo_root/vendor/workflow-notices"
websocket_notice_root="$repo_root/vendor/websocket-notices"
runtime_notice_root="$repo_root/vendor/runtime-notices"
local_signing_name="Grok Build+ Local Signing"
codesign_identity="-"
signing_identity_receipt="adhoc"
signature_posture="ad-hoc"

fail() {
  /bin/echo "release bundle refused: $*" >&2
  exit 1
}

verify_asset() {
  asset_path=$1
  expected_sha256=$2
  [ -f "$asset_path" ] || fail "missing admitted frontend asset $asset_path"
  actual_sha256=$(/usr/bin/shasum -a 256 "$asset_path" | /usr/bin/awk '{ print $1 }')
  [ "$actual_sha256" = "$expected_sha256" ] \
    || fail "frontend asset hash mismatch for $asset_path"
}

verify_workflow_notices() {
  workflow_notice_directory=$1
  verify_asset "$workflow_notice_directory/SHA256SUMS" "98d584a9728bc2a1b98b04455eaff8f9355a5303cb9fe20d53bfd8e18286fe91"
  while read -r notice_hash notice_name; do
    verify_asset "$workflow_notice_directory/$notice_name" "$notice_hash"
  done < "$workflow_notice_directory/SHA256SUMS"
}

verify_websocket_notices() {
  websocket_notice_directory=$1
  verify_asset "$websocket_notice_directory/SHA256SUMS" "2a6d87c73803d44f8e669f307c0d9ad21cfdbc422686f72a8fb07f03fda9b1fc"
  while read -r notice_hash notice_name; do
    verify_asset "$websocket_notice_directory/$notice_name" "$notice_hash"
  done < "$websocket_notice_directory/SHA256SUMS"
}

verify_bwrap_source() {
  root=$1
  verify_asset "$root/bubblewrap_0.9.0-1ubuntu0.1.dsc" dc163940d29d2630b3ea8780429096ca397e46279afc72d02dfbe55c8f16d422
  verify_asset "$root/bubblewrap_0.9.0.orig.tar.xz" c6347eaced49ac0141996f46bba3b089e5e6ea4408bc1c43bab9f2d05dd094e1
  verify_asset "$root/bubblewrap_0.9.0.orig.tar.xz.asc" 355568011016d6d5592c13830778a9b06365926f6478ae43e51b2ab5c3bc3c92
  verify_asset "$root/bubblewrap_0.9.0-1ubuntu0.1.debian.tar.xz" d253eccba8f6a8d636dd3df241c2d4d722785341c665c7817040aafa7ed3495e
  verify_asset "$root/COPYRIGHT" 229a402fddba5c81005950f28de162359383cba731f5b859b8f82a03c338bf01
  [ "$(/usr/bin/find "$root" -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 5 ] \
    || fail "Bubblewrap corresponding-source inventory changed"
}

cleanup() {
  case "$mcp_broker_signed_stage" in
    "$repo_root/target/release/.grok-build-mcp-keychain-broker.signed") /bin/rm -f -- "$mcp_broker_signed_stage" ;;
    *) /bin/echo "refusing unexpected MCP broker cleanup target" >&2 ;;
  esac
  case "$broker_signed_stage" in
    "$repo_root/target/release/.grok-build-keychain-broker.signed") /bin/rm -f -- "$broker_signed_stage" ;;
    *) /bin/echo "refusing unexpected broker staging cleanup target: $broker_signed_stage" >&2 ;;
  esac
  if [ -n "$verify_root" ]; then
    case "$verify_root" in
      /private/tmp/grok-build-plus-release.*) /bin/rm -rf -- "$verify_root" ;;
      *) /bin/echo "refusing unexpected temporary cleanup target: $verify_root" >&2 ;;
    esac
  fi
}
trap cleanup EXIT HUP INT TERM

[ "$(/usr/bin/uname -s)" = "Darwin" ] || fail "macOS is required"
[ "$(/usr/bin/uname -m)" = "arm64" ] || fail "Apple Silicon arm64 is required"
[ -f "$plist_source" ] || fail "missing checked-in Info.plist"
[ -f "$icon_source" ] || fail "missing checked-in GrokBuildPlus.icns"
[ -f "$entitlements_source" ] || fail "missing checked-in entitlements"

if [ "$signing_mode" = "local" ]; then
  login_keychains=$(
    /usr/bin/security list-keychains -d user 2>/dev/null \
      | /usr/bin/sed -n \
          -e 's/^[[:space:]]*"\(.*\/login\.keychain-db\)"[[:space:]]*$/\1/p' \
          -e 's/^[[:space:]]*"\(.*\/login\.keychain\)"[[:space:]]*$/\1/p'
  )
  login_keychain_count=$(/bin/echo "$login_keychains" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')
  [ "$login_keychain_count" = "1" ] \
    || fail "--local-signing requires exactly one login Keychain in the user search list (found $login_keychain_count)"
  login_keychain=$(/bin/echo "$login_keychains" | /usr/bin/awk 'NF { print; exit }')
  identity_matches=$(
    /usr/bin/security find-identity -v -p codesigning "$login_keychain" 2>/dev/null \
      | /usr/bin/awk -v name="\"$local_signing_name\"" 'index($0, name) > 0 { print $2 }'
  )
  identity_count=$(/bin/echo "$identity_matches" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')
  [ "$identity_count" = "1" ] \
    || fail "--local-signing requires exactly one valid '$local_signing_name' Code Signing identity in the login Keychain (found $identity_count)"
  codesign_identity=$(/bin/echo "$identity_matches" | /usr/bin/awk 'NF { print; exit }')
  [ "${#codesign_identity}" = "40" ] \
    || fail "local Code Signing identity fingerprint is not exactly 40 hexadecimal characters"
  case "$codesign_identity" in
    *[!0-9A-Fa-f]*) fail "local Code Signing identity fingerprint is not hexadecimal" ;;
  esac
  signing_identity_receipt=$(/bin/echo "$codesign_identity" | /usr/bin/tr '[:lower:]' '[:upper:]')
  signature_posture="local-self-signed"
fi

/usr/bin/plutil -lint "$plist_source"
/usr/bin/plutil -lint "$entitlements_source"
/usr/libexec/PlistBuddy -c 'Print :NSMicrophoneUsageDescription' "$plist_source" >/dev/null \
  || fail "real Voice requires NSMicrophoneUsageDescription"
[ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.security.device.audio-input' "$entitlements_source")" = "true" ] \
  || fail "real Voice requires the macOS audio-input entitlement"
verify_asset "$xterm_asset_root/xterm.mjs" "b336ec65a086c056d4804b3d4c2347da5663d3f23c3f25be866467bd8857ad59"
verify_asset "$xterm_asset_root/xterm.css" "854a7c0fb70e8b1a083c16797ab827299fb18744f5ad34f227b48337e33293c6"
verify_asset "$xterm_asset_root/addon-fit.mjs" "2d87e1bddc73be9111de8beee5370c3bb7aac9c94e18e6f245f02ca741ef1769"
verify_asset "$xterm_asset_root/LICENSE.xterm" "b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd"
verify_asset "$xterm_asset_root/LICENSE.addon-fit" "e256f01188af527e4d06d21d06fbf785ae9c50d4b328bf03cbe0ba7f0aa4228f"
verify_asset "$whisper_sys_root/build.rs" "80cf1db29b03709b6ec05b80245d4a8dd2311579a979279123b40fe749749888"
verify_asset "$whisper_sys_root/Cargo.toml" "1e843f8d6134abdd4e23f6ea09bba4ddb15d6f2ae455ee61d3560283152ce34a"
verify_asset "$whisper_sys_root/src/lib.rs" "65ce1b126fd0438ee4d604a121df5ee71558c905a17cede0b5ffc0ef36898224"
verify_asset "$whisper_sys_root/whisper.cpp/ggml/src/ggml.c" "1b90c2657076c0cd4c1004bd0c61b957f9997c998a608c12d823e461ae5a8205"
verify_asset "$whisper_sys_root/LICENSE-UNLICENSE" "6b0382b16279f26ff69014300541967a356a666eb0b91b422f6862f6b7dad17e"
whisper_file_count=$(/usr/bin/find "$whisper_sys_root" -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[ "$whisper_file_count" = "787" ] || fail "patched whisper-rs-sys source inventory changed"
whisper_manifest=$(
  cd "$whisper_sys_root"
  /usr/bin/find . -type f -print0 \
    | /usr/bin/sort -z \
    | /usr/bin/xargs -0 /usr/bin/shasum -a 256 \
    | /usr/bin/shasum -a 256 \
    | /usr/bin/awk '{ print $1 }'
)
[ "$whisper_manifest" = "c85d2ebf4bb673ebe033be1d6ea1236e62242e2c427f25a3fa91363a5f4889ed" ] \
  || fail "patched whisper-rs-sys relative source manifest changed"

cd "$repo_root"
verify_asset "$runtime_notice_root/SHA256SUMS" "44679ed71860125f9a067868ff8d39c05f26960b46b66c1753cfbacfadaa2bf2"
while read -r notice_hash notice_name; do
  verify_asset "$runtime_notice_root/$notice_name" "$notice_hash"
done < "$runtime_notice_root/SHA256SUMS"
python3 "$repo_root/scripts/verify-runtime-notices.py"
. "$repo_root/scripts/release-paths.sh"
prepare_native_release_cache
source_identity=$(python3 "$repo_root/scripts/release-source.py" identity) \
  || fail "could not resolve source provenance"
read -r build_revision bundle_build_number build_dirty <<EOF
$source_identity
EOF
case "$bundle_build_number" in
  ''|*[!0-9]*) fail "bundle build number is not a positive integer" ;;
esac
[ "$bundle_build_number" -gt 0 ] \
  || fail "bundle build number must be greater than zero"
/bin/rm -f -- "$broker_signed_stage"
GROK_BUILD_SIGNING_IDENTITY="$signing_identity_receipt" \
  MACOSX_DEPLOYMENT_TARGET=15.0 \
  cargo build --locked --release -p grok-build-keychain-broker \
    --bin grok-build-keychain-broker
[ -x "$broker_binary_source" ] || fail "release Keychain broker executable was not produced"
/bin/cp "$broker_binary_source" "$broker_signed_stage"
/bin/chmod 0755 "$broker_signed_stage"
/usr/bin/codesign --force --sign - --timestamp=none \
  --identifier "$broker_identifier" "$broker_signed_stage"
[ "$(/usr/bin/lipo -archs "$broker_signed_stage")" = "arm64" ] \
  || fail "Keychain broker executable is not thin arm64"
broker_minimum_os=$(/usr/bin/otool -l "$broker_signed_stage" \
  | /usr/bin/awk '$1 == "minos" { print $2; exit }')
[ "$broker_minimum_os" = "15.0" ] \
  || fail "Keychain broker minimum OS is $broker_minimum_os, expected 15.0"
/bin/chmod 0755 "$broker_signed_stage"
/usr/bin/codesign --verify --strict --verbose=4 "$broker_signed_stage"
broker_designated_requirement=$(/usr/bin/codesign -d -r- "$broker_signed_stage" 2>&1 \
  | /usr/bin/sed -n -e 's/^# designated => //p' -e 's/^designated => //p')
[ -n "$broker_designated_requirement" ] \
  || fail "signed Keychain broker has no designated requirement"
broker_sha256=$(/usr/bin/shasum -a 256 "$broker_signed_stage" | /usr/bin/awk '{ print $1 }')
broker_cdhash=$(/usr/bin/codesign -d --verbose=4 "$broker_signed_stage" 2>&1 \
  | /usr/bin/sed -n 's/^CDHash=//p' | /usr/bin/head -n 1)
[ "${#broker_cdhash}" = "40" ] || fail "Keychain broker has no exact SHA-1 CDHash"
broker_cdhash=$(/bin/echo "$broker_cdhash" | /usr/bin/tr '[:upper:]' '[:lower:]')
broker_observed_identifier=$(/usr/bin/codesign -d --verbose=4 "$broker_signed_stage" 2>&1 \
  | /usr/bin/sed -n 's/^Identifier=//p' | /usr/bin/head -n 1)
[ "$broker_observed_identifier" = "$broker_identifier" ] \
  || fail "Keychain broker code signature lost its exact identifier"
[ "$broker_designated_requirement" = "cdhash H\"$broker_cdhash\"" ] \
  || fail "stable Keychain broker designated requirement is not its exact CDHash"
broker_requirement_sha256=$(/usr/bin/printf '%s' "$broker_designated_requirement" \
  | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1 }')
/bin/rm -f -- "$mcp_broker_signed_stage"
GROK_BUILD_SIGNING_IDENTITY="$signing_identity_receipt" MACOSX_DEPLOYMENT_TARGET=15.0 \
  cargo build --locked --release -p grok-build-keychain-broker --bin grok-build-mcp-keychain-broker
/bin/cp "$repo_root/target/release/grok-build-mcp-keychain-broker" "$mcp_broker_signed_stage"
/bin/chmod 0755 "$mcp_broker_signed_stage"
/usr/bin/codesign --force --sign - --timestamp=none \
  --identifier "$mcp_broker_identifier" "$mcp_broker_signed_stage"
/usr/bin/codesign --verify --strict --verbose=4 "$mcp_broker_signed_stage"
[ "$(/usr/bin/lipo -archs "$mcp_broker_signed_stage")" = "arm64" ] \
  || fail "MCP Keychain helper is not thin arm64"
mcp_broker_sha256=$(/usr/bin/shasum -a 256 "$mcp_broker_signed_stage" | /usr/bin/awk '{ print $1 }')
mcp_broker_cdhash=$(/usr/bin/codesign -d --verbose=4 "$mcp_broker_signed_stage" 2>&1 \
  | /usr/bin/sed -n 's/^CDHash=//p' | /usr/bin/head -n 1)
mcp_broker_requirement=$(/usr/bin/codesign -d -r- "$mcp_broker_signed_stage" 2>&1 \
  | /usr/bin/sed -n -e 's/^# designated => //p' -e 's/^designated => //p')
[ "${#mcp_broker_cdhash}" = "40" ] \
  && [ "$mcp_broker_requirement" = "cdhash H\"$mcp_broker_cdhash\"" ] \
  || fail "MCP Keychain helper lacks its exact CDHash requirement"
[ -x "$linux_payload_builder" ] || fail "missing Linux Command security payload builder"
"$linux_payload_builder"
[ -f "$linux_payload_source" ] || fail "Linux Command security payload was not produced"
[ -x "$linux_helper_source" ] || fail "Linux Command security helper was not produced"
verify_bwrap_source "$bwrap_source_root"
linux_payload_bytes=$(/usr/bin/stat -f '%z' "$linux_payload_source")
linux_payload_sha256=$(/usr/bin/shasum -a 256 "$linux_payload_source" | /usr/bin/awk '{ print $1 }')
linux_helper_bytes=$(/usr/bin/stat -f '%z' "$linux_helper_source")
linux_helper_sha256=$(/usr/bin/shasum -a 256 "$linux_helper_source" | /usr/bin/awk '{ print $1 }')
bwrap_source_manifest_sha256=$(
  cd "$bwrap_source_root"
  /usr/bin/find . -type f -print0 | /usr/bin/sort -z \
    | /usr/bin/xargs -0 /usr/bin/shasum -a 256 \
    | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1 }'
)
[ "$bwrap_source_manifest_sha256" = d3efdf2d152b249ac31e8f2599dcfd43eb9bdc05008c2bfa78e94907cc31d50a ] \
  || fail "Bubblewrap corresponding-source manifest changed"
GROK_BUILD_REVISION="$build_revision" GROK_BUILD_DIRTY="$build_dirty" \
  GROK_BUILD_SIGNING_IDENTITY="$signing_identity_receipt" \
  GROK_BUILD_KEYCHAIN_BROKER_SHA256="$broker_sha256" \
  GROK_BUILD_KEYCHAIN_BROKER_CDHASH="$broker_cdhash" \
  GROK_BUILD_MCP_BROKER_SHA256="$mcp_broker_sha256" \
  GROK_BUILD_MCP_BROKER_CDHASH="$mcp_broker_cdhash" \
  GROK_BUILD_LINUX_PAYLOAD_SHA256="$linux_payload_sha256" \
  GROK_BUILD_LINUX_PAYLOAD_BYTES="$linux_payload_bytes" \
  GROK_BUILD_LINUX_HELPER_SHA256="$linux_helper_sha256" \
  GROK_BUILD_LINUX_HELPER_BYTES="$linux_helper_bytes" \
  MACOSX_DEPLOYMENT_TARGET=15.0 \
  cargo build --locked --release -p grok-build-tauri --features custom-protocol

[ -x "$binary_source" ] || fail "release Tauri executable was not produced"
[ "$(/usr/bin/lipo -archs "$binary_source")" = "arm64" ] || fail "release executable is not thin arm64"
minimum_os=$(/usr/bin/otool -l "$binary_source" | /usr/bin/awk '$1 == "minos" { print $2; exit }')
[ "$minimum_os" = "15.0" ] || fail "Mach-O minimum OS is $minimum_os, expected 15.0"
raw_version=$("$binary_source" --version) || fail "raw release version check failed"
[ "$raw_version" = "GB Plus 0.2.1-plus" ] \
  || fail "raw release version output was unexpected"
raw_smoke=$("$binary_source" --tauri-smoke) || fail "raw release smoke failed"
case "$raw_smoke" in
  "TAURI HOST SMOKE PASSED "*) ;;
  *) fail "raw release smoke did not emit its pass sentinel" ;;
esac
raw_binary_sha256=$(/usr/bin/shasum -a 256 "$binary_source" | /usr/bin/awk '{ print $1 }')
receipt_generated_at=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')
{
  /usr/bin/printf '%s\n' '{'
  /usr/bin/printf '  "schemaVersion": 7,\n'
  /usr/bin/printf '  "generatedAtUtc": "%s",\n' "$receipt_generated_at"
  /usr/bin/printf '  "buildRevision": "%s",\n' "$build_revision"
  /usr/bin/printf '  "buildDirty": %s,\n' "$build_dirty"
  /usr/bin/printf '  "rawBinarySha256": "%s",\n' "$raw_binary_sha256"
  /usr/bin/printf '  "rawVersionCheck": "passed",\n'
  /usr/bin/printf '  "rawSmoke": "passed",\n'
  /usr/bin/printf '  "minimumMacos": "15.0",\n'
  /usr/bin/printf '  "architecture": "arm64",\n'
  /usr/bin/printf '  "voiceEngine": "whisper.cpp-1.8.3-cpu-accelerate",\n'
  /usr/bin/printf '  "voiceModels": "lazy-sha256-pinned-base-small",\n'
  /usr/bin/printf '  "signaturePosture": "%s",\n' "$signature_posture"
  /usr/bin/printf '  "signingIdentity": "%s",\n' "$signing_identity_receipt"
  /usr/bin/printf '  "keychainBrokerProtocolVersion": 1,\n'
  /usr/bin/printf '  "keychainBrokerAccountVersion": 3,\n'
  /usr/bin/printf '  "keychainBrokerIdentifier": "%s",\n' "$broker_identifier"
  /usr/bin/printf '  "keychainBrokerSha256": "%s",\n' "$broker_sha256"
  /usr/bin/printf '  "keychainBrokerCdHash": "%s",\n' "$broker_cdhash"
  /usr/bin/printf '  "keychainBrokerExecution": "launchd-one-shot-private-unix-peer-validated",\n'
  /usr/bin/printf '  "keychainBrokerRequirementSha256": "%s",\n' "$broker_requirement_sha256"
  /usr/bin/printf '  "mcpBrokerIdentifier": "%s",\n' "$mcp_broker_identifier"
  /usr/bin/printf '  "mcpBrokerSha256": "%s",\n' "$mcp_broker_sha256"
  /usr/bin/printf '  "mcpBrokerCdHash": "%s",\n' "$mcp_broker_cdhash"
  /usr/bin/printf '  "linuxCommandSecurityPayloadBytes": %s,\n' "$linux_payload_bytes"
  /usr/bin/printf '  "linuxCommandSecurityPayloadSha256": "%s",\n' "$linux_payload_sha256"
  /usr/bin/printf '  "linuxCommandSecurityHelperBytes": %s,\n' "$linux_helper_bytes"
  /usr/bin/printf '  "linuxCommandSecurityHelperSha256": "%s",\n' "$linux_helper_sha256"
  /usr/bin/printf '  "bubblewrapCorrespondingSourceManifestSha256": "%s"\n' "$bwrap_source_manifest_sha256"
  /usr/bin/printf '%s\n' '}'
} > "$release_receipt_source"
/bin/chmod 0600 "$release_receipt_source"
/usr/bin/plutil -convert json -o /dev/null "$release_receipt_source"

case "$app_path" in
  "$dist_root/GB Plus.app") ;;
  *) fail "unexpected app replacement target" ;;
esac
case "$previous_app_path" in
  "$dist_root/Grok Build+.app") ;;
  *) fail "unexpected previous app cleanup target" ;;
esac
case "$legacy_path" in
  "$dist_root/grok-build-macos") ;;
  *) fail "unexpected legacy replacement target" ;;
esac
case "$zip_path" in
  "$dist_root/gb-plus-macos-arm64.zip") ;;
  *) fail "unexpected zip replacement target" ;;
esac
case "$previous_zip_path" in
  "$dist_root/grok-build-macos-arm64.zip") ;;
  *) fail "unexpected previous zip cleanup target" ;;
esac
case "$checksum_path" in
  "$dist_root/SHA256SUMS") ;;
  *) fail "unexpected checksum target" ;;
esac

/bin/rm -rf -- "$app_path"
/bin/rm -rf -- "$previous_app_path"
/bin/rm -rf -- "$legacy_path"
/bin/rm -f -- "$zip_path"
/bin/rm -f -- "$previous_zip_path"
/bin/rm -f -- "$checksum_path"
/bin/mkdir -p "$app_path/Contents/MacOS" "$bundle_helpers" "$bundle_resources"
/bin/cp "$plist_source" "$app_path/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $bundle_build_number" \
  "$app_path/Contents/Info.plist"
/bin/cp "$binary_source" "$bundle_binary"
/bin/chmod 0755 "$bundle_binary"
/bin/cp "$broker_signed_stage" "$bundle_broker"
/bin/chmod 0755 "$bundle_broker"
/bin/cp "$mcp_broker_signed_stage" "$bundle_mcp_broker"
/bin/chmod 0755 "$bundle_mcp_broker"
/bin/cp "$icon_source" "$bundle_resources/GrokBuildPlus.icns"
bundled_icon_name=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIconFile' \
  "$app_path/Contents/Info.plist")
[ "$bundled_icon_name" = "GrokBuildPlus.icns" ] \
  || fail "bundle icon reference is $bundled_icon_name, expected GrokBuildPlus.icns"
bundled_icon_file=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIconFiles:0' \
  "$app_path/Contents/Info.plist")
[ "$bundled_icon_file" = "GrokBuildPlus.icns" ] \
  || fail "bundle icon list does not name GrokBuildPlus.icns"
source_icon_sha256=$(/usr/bin/shasum -a 256 "$icon_source" | /usr/bin/awk '{ print $1 }')
bundled_icon_sha256=$(/usr/bin/shasum -a 256 \
  "$bundle_resources/GrokBuildPlus.icns" | /usr/bin/awk '{ print $1 }')
[ "$bundled_icon_sha256" = "$source_icon_sha256" ] \
  || fail "bundled Finder icon differs from the checked-in icon"
/bin/cp "$repo_root/LICENSE" "$bundle_resources/LICENSE.txt"
/bin/cp "$repo_root/ATTRIBUTION.md" "$bundle_resources/ATTRIBUTION.md"
/bin/cp "$runtime_notice_root/RuntimeNotices.tar.gz" "$bundle_resources/RuntimeNotices.tar.gz"
verify_asset "$bundle_resources/RuntimeNotices.tar.gz" "c26e3f85bc791cd936dac67c46f6a9f3f2a2ad4c6e31e295586cbe18d2e2e31e"
verify_workflow_notices "$workflow_notice_root"
/bin/mkdir "$bundle_resources/WorkflowNotices"
/bin/cp "$workflow_notice_root/SHA256SUMS" "$bundle_resources/WorkflowNotices/SHA256SUMS"
while read -r notice_hash notice_name; do
  /bin/cp "$workflow_notice_root/$notice_name" "$bundle_resources/WorkflowNotices/$notice_name"
done < "$workflow_notice_root/SHA256SUMS"
verify_workflow_notices "$bundle_resources/WorkflowNotices"
verify_websocket_notices "$websocket_notice_root"
/bin/mkdir "$bundle_resources/WebSocketNotices"
/bin/cp "$websocket_notice_root/SHA256SUMS" "$bundle_resources/WebSocketNotices/SHA256SUMS"
while read -r notice_hash notice_name; do
  /bin/cp "$websocket_notice_root/$notice_name" "$bundle_resources/WebSocketNotices/$notice_name"
done < "$websocket_notice_root/SHA256SUMS"
verify_websocket_notices "$bundle_resources/WebSocketNotices"
/bin/cp "$repo_root/dist/README.md" "$bundle_resources/README.md"
/bin/cp "$release_receipt_source" "$bundle_resources/GrokBuildReleaseReceipt.json"
/bin/cp "$linux_payload_source" "$bundle_resources/$linux_payload_name"
/bin/mkdir "$bundle_resources/BubblewrapSource"
/bin/cp "$bwrap_source_root"/* "$bundle_resources/BubblewrapSource/"
/bin/chmod 0644 "$bundle_resources/GrokBuildReleaseReceipt.json"
/bin/chmod 0444 "$bundle_resources/$linux_payload_name"
verify_bwrap_source "$bundle_resources/BubblewrapSource"
bundled_linux_payload_sha256=$(/usr/bin/shasum -a 256 \
  "$bundle_resources/$linux_payload_name" | /usr/bin/awk '{ print $1 }')
[ "$bundled_linux_payload_sha256" = "$linux_payload_sha256" ] \
  || fail "bundled Linux Command security payload changed"

resource_file_count=$(/usr/bin/find "$bundle_resources" -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[ "$resource_file_count" = "7" ] || fail "unexpected resource payload count $resource_file_count"
macos_file_count=$(/usr/bin/find "$app_path/Contents/MacOS" -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[ "$macos_file_count" = "1" ] || fail "unexpected executable/sidecar payload count $macos_file_count"
helper_file_count=$(/usr/bin/find "$bundle_helpers" -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')
[ "$helper_file_count" = "2" ] || fail "unexpected helper payload count $helper_file_count"
if /usr/bin/find "$app_path/Contents" -type f | /usr/bin/grep -Eiq '(^|/)(faster[-_]?whisper|ctranslate2|pyav|ffmpeg|x264|x265|voice[-_]?sidecar|ggml-(base|small)|models?)(/|\.|$)'; then
  fail "rejected Voice sidecar or lazy model payload entered the app bundle"
fi

/usr/bin/plutil -lint "$app_path/Contents/Info.plist"
/usr/bin/codesign --force --sign "$codesign_identity" --timestamp=none \
  --entitlements "$entitlements_source" "$app_path"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$app_path"
/usr/bin/codesign --verify --strict --verbose=4 "$bundle_broker"
/usr/bin/codesign --verify --strict --verbose=4 "$bundle_mcp_broker"
verify_asset "$bundle_mcp_broker" "$mcp_broker_sha256"
bundled_broker_sha256=$(/usr/bin/shasum -a 256 "$bundle_broker" | /usr/bin/awk '{ print $1 }')
[ "$bundled_broker_sha256" = "$broker_sha256" ] \
  || fail "outer app signing changed the exact Keychain broker bytes"
bundled_broker_cdhash=$(/usr/bin/codesign -d --verbose=4 "$bundle_broker" 2>&1 \
  | /usr/bin/sed -n 's/^CDHash=//p' | /usr/bin/head -n 1)
[ "$bundled_broker_cdhash" = "$broker_cdhash" ] \
  || fail "outer app signing changed the stable Keychain broker CDHash"
designated_requirement=$(/usr/bin/codesign -d -r- "$app_path" 2>&1 \
  | /usr/bin/sed -n -e 's/^# designated => //p' -e 's/^designated => //p')
[ -n "$designated_requirement" ] || fail "signed app has no designated requirement"
if [ "$signing_mode" = "local" ]; then
  case "$designated_requirement" in
    *'identifier "com.grokbuild.plus"'*) ;;
    *) fail "local-signed app designated requirement lost com.grokbuild.plus" ;;
  esac
  case "$designated_requirement" in
    *cdhash*) fail "local-signed app retained an ad-hoc cdhash-only designated requirement" ;;
  esac
  case "$designated_requirement" in
    *certificate*|*anchor*) ;;
    *) fail "local-signed app designated requirement is not certificate-based" ;;
  esac
else
  case "$designated_requirement" in
    *cdhash*) ;;
    *) fail "ad-hoc signed app did not expose its expected cdhash designated requirement" ;;
  esac
fi
designated_requirement_sha256=$(/usr/bin/printf '%s' "$designated_requirement" \
  | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1 }')
signed_entitlements=$(/usr/bin/codesign -d --entitlements :- "$app_path" 2>&1)
/bin/echo "$signed_entitlements" | /usr/bin/grep -q 'com.apple.security.device.audio-input' \
  || fail "signed app lost the admitted microphone entitlement"

"$bundle_binary" --version
"$bundle_binary" --tauri-smoke

COPYFILE_DISABLE=1 /usr/bin/ditto --norsrc --noextattr --noqtn --noacl \
  --zlibCompressionLevel 9 -c -k --keepParent "$app_path" "$zip_path"
zip_entries=$(/usr/bin/unzip -Z1 "$zip_path")
case "$zip_entries" in
  *"__MACOSX"*|*"/._"*) fail "zip contains AppleDouble/resource-fork entries" ;;
esac
/bin/echo "$zip_entries" | /usr/bin/grep -q '^GB Plus\.app/' \
  || fail "zip does not contain GB Plus.app as its root payload"
if /bin/echo "$zip_entries" | /usr/bin/grep -Eq '(^|/)grok-build$|^grok-build-macos/'; then
  fail "zip contains the legacy Slint front door"
fi
if /bin/echo "$zip_entries" | /usr/bin/grep -Eiq '(^|/)(faster[-_]?whisper|ctranslate2|pyav|ffmpeg|x264|x265|voice[-_]?sidecar|ggml-(base|small)|models?)(/|\.|$)'; then
  fail "zip contains a rejected Voice sidecar or lazy model payload"
fi

verify_root=$(/usr/bin/mktemp -d /private/tmp/grok-build-plus-release.XXXXXX)
/usr/bin/ditto --norsrc --noextattr --noqtn --noacl -x -k "$zip_path" "$verify_root"
extracted_app="$verify_root/GB Plus.app"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$extracted_app"
extracted_broker="$extracted_app/Contents/Helpers/grok-build-keychain-broker"
extracted_mcp_broker="$extracted_app/Contents/Helpers/grok-build-mcp-keychain-broker"
/usr/bin/codesign --verify --strict --verbose=4 "$extracted_mcp_broker"
verify_asset "$extracted_mcp_broker" "$mcp_broker_sha256"
/usr/bin/codesign --verify --strict --verbose=4 "$extracted_broker"
extracted_broker_sha256=$(/usr/bin/shasum -a 256 "$extracted_broker" | /usr/bin/awk '{ print $1 }')
[ "$extracted_broker_sha256" = "$broker_sha256" ] \
  || fail "zip extraction changed the exact Keychain broker bytes"
extracted_linux_payload_sha256=$(/usr/bin/shasum -a 256 \
  "$extracted_app/Contents/Resources/$linux_payload_name" | /usr/bin/awk '{ print $1 }')
[ "$extracted_linux_payload_sha256" = "$linux_payload_sha256" ] \
  || fail "zip extraction changed the Linux Command security payload"
verify_bwrap_source "$extracted_app/Contents/Resources/BubblewrapSource"
verify_workflow_notices "$extracted_app/Contents/Resources/WorkflowNotices"
verify_websocket_notices "$extracted_app/Contents/Resources/WebSocketNotices"
extracted_requirement=$(/usr/bin/codesign -d -r- "$extracted_app" 2>&1 \
  | /usr/bin/sed -n -e 's/^# designated => //p' -e 's/^designated => //p')
[ "$extracted_requirement" = "$designated_requirement" ] \
  || fail "extracted app designated requirement changed"
"$extracted_app/Contents/MacOS/grok-build-tauri" --version
"$extracted_app/Contents/MacOS/grok-build-tauri" --tauri-smoke

python3 "$repo_root/scripts/audit-release-payload.py" "$app_path" --zip "$zip_path" \
  --report "$dist_root/PAYLOAD-AUDIT.json"

zip_sha256=$(/usr/bin/shasum -a 256 "$zip_path" | /usr/bin/awk '{ print $1 }')
checksum_line="$zip_sha256  gb-plus-macos-arm64.zip"
/usr/bin/printf '%s\n' "$checksum_line" > "$checksum_path"
/bin/chmod 0644 "$checksum_path"
[ "$(/bin/cat "$checksum_path")" = "$checksum_line" ] \
  || fail "release checksum readback changed"

/bin/mkdir "$dist_root/previous"
for artifact_name in "GB Plus.app" "gb-plus-macos-arm64.zip" "SHA256SUMS" "PAYLOAD-AUDIT.json"; do
  if [ -e "$repo_root/dist/$artifact_name" ]; then
    /bin/mv "$repo_root/dist/$artifact_name" "$dist_root/previous/$artifact_name"
  fi
  /bin/mv "$dist_root/$artifact_name" "$repo_root/dist/$artifact_name"
done
app_path="$repo_root/dist/GB Plus.app"
zip_path="$repo_root/dist/gb-plus-macos-arm64.zip"
checksum_path="$repo_root/dist/SHA256SUMS"

/bin/echo "artifact=$app_path"
/bin/echo "zip=$zip_path"
/bin/echo "checksums=$checksum_path"
/bin/echo "signature=$signature_posture identity=$signing_identity_receipt; Developer ID and notarization not performed"
/bin/echo "designated-requirement-sha256=$designated_requirement_sha256"
/bin/echo "keychain-broker-sha256=$broker_sha256 cdhash=$broker_cdhash requirement-sha256=$broker_requirement_sha256"
/bin/echo "mcp-broker-sha256=$mcp_broker_sha256 cdhash=$mcp_broker_cdhash namespace=MCP-only"
/bin/echo "minimum-macos=$minimum_os architecture=arm64"
/bin/echo "voice=embedded whisper.cpp 1.8.3 CPU+Accelerate; models lazy and SHA-256 pinned; no rejected sidecar"
/bin/echo "linux-command-security-payload=$linux_payload_sha256 bytes=$linux_payload_bytes helper=$linux_helper_sha256"
/bin/echo "bubblewrap-corresponding-source=$bwrap_source_manifest_sha256"
