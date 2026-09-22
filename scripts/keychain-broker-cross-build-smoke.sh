#!/bin/sh
# Control-vs-enforced proof for the no-Developer-ID stable Keychain broker.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fixture_root=""
local_signing_name="Grok Build+ Local Signing"
fixture_namespace=provider
fixture_helper_identifier=com.grokbuild.plus.credential-broker
case $# in
  0) ;;
  1) [ "$1" = "--mcp" ] || { echo "usage: $0 [--mcp]" >&2; exit 2; }
     fixture_namespace=mcp
     fixture_helper_identifier=com.grokbuild.plus.mcp-credential-broker ;;
  *) echo "usage: $0 [--mcp]" >&2; exit 2 ;;
esac

fail() {
  /bin/echo "stable broker smoke refused: $*" >&2
  exit 1
}

launch_fixture_app() {
  fixture_label=$1
  fixture_launch_app=$2
  fixture_result=$3
  shift 3
  /usr/bin/open -W -n "$fixture_launch_app" --args "$@" "$fixture_result" \
    || fail "$fixture_label could not be launched through LaunchServices"
  [ -f "$fixture_result" ] \
    || fail "$fixture_label exited without a durable result"
  fixture_outcome=$(/bin/cat "$fixture_result")
  [ "$fixture_outcome" = "PASS" ] \
    || fail "$fixture_label reported: $fixture_outcome"
  /bin/echo "$fixture_label PASS"
}

cleanup() {
  if [ -n "$fixture_root" ]; then
    case "$fixture_root" in
      /private/tmp/grok-build-keychain-broker.*) /bin/rm -rf -- "$fixture_root" ;;
      *) /bin/echo "refusing unexpected fixture cleanup target: $fixture_root" >&2 ;;
    esac
  fi
}
trap cleanup EXIT HUP INT TERM

[ "$(/usr/bin/uname -s)" = "Darwin" ] || fail "macOS is required"
[ "$(/usr/bin/uname -m)" = "arm64" ] || fail "Apple Silicon arm64 is required"

identity_matches=$(
  /usr/bin/security find-identity -v -p codesigning 2>/dev/null \
    | /usr/bin/awk -v name="\"$local_signing_name\"" 'index($0, name) > 0 { print $2 }'
)
identity_count=$(/bin/echo "$identity_matches" \
  | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')
[ "$identity_count" = "1" ] \
  || fail "exactly one valid '$local_signing_name' identity is required"
identity=$(/bin/echo "$identity_matches" | /usr/bin/awk 'NF { print; exit }')
case "$identity" in
  *[!0-9A-Fa-f]*|'') fail "local signing fingerprint is invalid" ;;
esac
[ "${#identity}" = "40" ] || fail "local signing fingerprint length is invalid"
identity=$(/bin/echo "$identity" | /usr/bin/tr '[:lower:]' '[:upper:]')

cd "$repo_root"
GROK_BUILD_SIGNING_IDENTITY="$identity" MACOSX_DEPLOYMENT_TARGET=15.0 \
  cargo build --locked --release -p grok-build-keychain-broker \
    --features broker-fixture \
    --bin grok-build-keychain-broker-fixture \
    --bin grok-build-keychain-parent-fixture-a \
    --bin grok-build-keychain-parent-fixture-b \
    --bin grok-build-keychain-parent-fixture-unauthorized

fixture_root=$(/usr/bin/mktemp -d /private/tmp/grok-build-keychain-broker.XXXXXX)
fixture_app="$fixture_root/GB Plus Broker Fixture.app"
fixture_contents="$fixture_app/Contents"
helper="$fixture_contents/Helpers/grok-build-keychain-broker-fixture"
parent="$fixture_contents/MacOS/grok-build-keychain-parent-fixture"
parent_a_source="$repo_root/target/release/grok-build-keychain-parent-fixture-a"
parent_b_source="$repo_root/target/release/grok-build-keychain-parent-fixture-b"
unauthorized_source="$repo_root/target/release/grok-build-keychain-parent-fixture-unauthorized"
wrong_identifier_app="$fixture_root/GB Plus Wrong Identifier Fixture.app"
wrong_identifier_contents="$wrong_identifier_app/Contents"
wrong_identifier_parent="$wrong_identifier_contents/MacOS/grok-build-keychain-parent-fixture"
/bin/mkdir -p "$fixture_contents/Helpers" "$fixture_contents/MacOS"
/bin/mkdir -p "$wrong_identifier_contents/MacOS"
/bin/cp crates/grok-build-keychain-broker/tests/FixtureInfo.plist "$fixture_contents/Info.plist"
/bin/cp crates/grok-build-keychain-broker/tests/FixtureInfo.plist "$wrong_identifier_contents/Info.plist"
/usr/bin/plutil -replace CFBundleIdentifier -string com.grokbuild.plus.wrong \
  "$wrong_identifier_contents/Info.plist"
/bin/cp target/release/grok-build-keychain-broker-fixture "$helper"
/bin/cp "$unauthorized_source" "$wrong_identifier_parent"
/bin/cp "$parent_a_source" "$parent"
/bin/chmod 0755 "$helper" "$parent" "$wrong_identifier_parent"

/usr/bin/codesign --force --sign - --timestamp=none \
  --identifier "$fixture_helper_identifier" "$helper"
/usr/bin/codesign --force --sign "$identity" --timestamp=none "$fixture_app"
/usr/bin/codesign --force --sign "$identity" --timestamp=none "$wrong_identifier_app"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$fixture_app"
/usr/bin/codesign --verify --strict --verbose=4 "$helper"
/usr/bin/codesign --verify --strict --verbose=4 "$wrong_identifier_app"

helper_sha=$(/usr/bin/shasum -a 256 "$helper" | /usr/bin/awk '{ print $1 }')
helper_cdhash=$(/usr/bin/codesign -d --verbose=4 "$helper" 2>&1 \
  | /usr/bin/sed -n 's/^CDHash=//p' | /usr/bin/head -n 1)
parent_a_cdhash=$(/usr/bin/codesign -d --verbose=4 "$fixture_app" 2>&1 \
  | /usr/bin/sed -n 's/^CDHash=//p' | /usr/bin/head -n 1)
[ -n "$helper_cdhash" ] || fail "helper CDHash is absent"
[ -n "$parent_a_cdhash" ] || fail "parent A CDHash is absent"
[ "$helper_cdhash" != "$parent_a_cdhash" ] \
  || fail "helper and parent A unexpectedly share one CDHash"

unique=$(/bin/date -u '+%Y%m%d%H%M%S')-$$
service="org.grok-build.desktop.test.broker-$unique"
if [ "$fixture_namespace" = mcp ]; then service="org.grok-build.desktop.test.mcp-$unique"; fi
account="fixture:$unique:parent:$parent_a_cdhash"
target="$service,$account"
result_a="$fixture_root/result-authorized-a"
result_wrong_identifier="$fixture_root/result-wrong-identifier"
result_b="$fixture_root/result-authorized-b"

launch_fixture_app authorized-a "$fixture_app" "$result_a" \
  "$helper" "$helper_sha" "$identity" "$target" "$helper_cdhash"
launch_fixture_app wrong-identifier "$wrong_identifier_app" "$result_wrong_identifier" \
  "$helper" "$helper_sha" "$identity" "$target" "$helper_cdhash"
/bin/cp "$parent_b_source" "$parent"
/bin/chmod 0755 "$parent"
/usr/bin/codesign --force --sign "$identity" --timestamp=none "$fixture_app"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$fixture_app"
parent_b_cdhash=$(/usr/bin/codesign -d --verbose=4 "$fixture_app" 2>&1 \
  | /usr/bin/sed -n 's/^CDHash=//p' | /usr/bin/head -n 1)
[ -n "$parent_b_cdhash" ] || fail "parent B CDHash is absent"
[ "$helper_cdhash" != "$parent_b_cdhash" ] \
  || fail "helper and parent B unexpectedly share one CDHash"
[ "$parent_a_cdhash" != "$parent_b_cdhash" ] \
  || fail "changed-parent control did not produce different CDHashes"
launch_fixture_app authorized-b "$fixture_app" "$result_b" \
  "$helper" "$helper_sha" "$identity" "$target" "$helper_cdhash"

/bin/echo "stable_self_signed_broker_survives_changed_parent_cdhash PASS"
/bin/echo "helper-sha256=$helper_sha helper-cdhash=$helper_cdhash"
/bin/echo "parent-a-cdhash=$parent_a_cdhash parent-b-cdhash=$parent_b_cdhash launchd-helper=allowed exact-helper-partition=enforced"
/bin/echo "wrong-identifier-peer=refused helper-hash=refused helper-cdhash=refused helper-path=refused no-ui-unauthorized-read=bounded-refusal"

/bin/echo "credential-namespace=$fixture_namespace changed-parent=passed"
if [ "$fixture_namespace" = mcp ]; then /bin/echo "cross-namespace=refused unrelated-binding=absent deletion-readback=absent"; fi
