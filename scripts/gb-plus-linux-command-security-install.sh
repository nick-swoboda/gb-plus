#!/bin/sh
# Runs as root inside the Colima guest. Every input is passed as one argv item.
set -eu

archive_path=$1
archive_bytes=$2
archive_sha=$3
helper_bytes=$4
helper_sha=$5
runner_uid=$6
runner_gid=$7
runner_home=$8
phase_root=/opt/grok-build/phase1
release_root=$phase_root/releases/$helper_sha
binary_root=$release_root/bin
install_root=$release_root/install
stdio_install_root=$release_root/stdio-install
probe_root=$release_root/probe
state_root=/var/lib/grok-build/phase1/releases/$helper_sha/state
stdio_state_root=/var/lib/grok-build/phase1/releases/$helper_sha/stdio-state
cgroup_parent=/sys/fs/cgroup/gbd-phase1
service_cgroup=$cgroup_parent/service
stdio_releases=$cgroup_parent/stdio-releases
stdio_cgroup_parent=$stdio_releases/$helper_sha
delegation=svc-$helper_sha
stage=

fail() { echo "Command security setup refused: $*" >&2; exit 78; }
cleanup() {
  case "$stage" in /var/tmp/gb-plus-command-security.*) rm -rf -- "$stage" ;; esac
  case "$archive_path" in /tmp/gb-plus-command-security.*.tar.gz) rm -f -- "$archive_path" ;; esac
}
trap cleanup EXIT HUP INT TERM

case "$archive_bytes:$helper_bytes:$runner_uid:$runner_gid" in
  *[!0-9:]*) fail "numeric input was invalid" ;;
esac
test "${#archive_sha}" = 64 && test "${#helper_sha}" = 64 || fail "digest length was invalid"
case "$archive_sha$helper_sha" in *[!0-9a-f]*) fail "digest input was invalid" ;; esac
case "$archive_path" in /tmp/gb-plus-command-security.*.tar.gz) ;; *) fail "archive path was invalid" ;; esac
case "$runner_home" in /*) ;; *) fail "runner home was not absolute" ;; esac
test "$runner_uid" -ne 0 && test "$runner_gid" -ne 0 || fail "runner identity cannot be root"
test -f "$archive_path" && test ! -L "$archive_path" || fail "payload was not one regular file"

stage=$(mktemp -d /var/tmp/gb-plus-command-security.XXXXXX)
cp -- "$archive_path" "$stage/payload.tar.gz"
chmod 0400 "$stage/payload.tar.gz"
test "$(stat -c %s "$stage/payload.tar.gz")" = "$archive_bytes" || fail "payload length changed"
observed=$(sha256sum "$stage/payload.tar.gz"); observed=${observed%% *}
test "$observed" = "$archive_sha" || fail "payload checksum changed"
inventory=$(tar -tzf "$stage/payload.tar.gz")
test "$inventory" = "bwrap
grok-build-linux-helper
plus-contained-probe" || fail "payload inventory changed"
mkdir -m 0700 "$stage/files"
tar -xzf "$stage/payload.tar.gz" -C "$stage/files"

verify() {
  test -f "$1" && test ! -L "$1" || fail "$1 was not a regular file"
  test "$(stat -c %s "$1")" = "$2" || fail "$1 length changed"
  value=$(sha256sum "$1"); value=${value%% *}
  test "$value" = "$3" || fail "$1 checksum changed"
}
verify "$stage/files/grok-build-linux-helper" "$helper_bytes" "$helper_sha"
verify "$stage/files/bwrap" 67816 ae27935781511400c65ebcc0b4669775d602f46251b8707c947a1ac1b160c1c8
verify "$stage/files/plus-contained-probe" 3160 d36421faefab9a6acb9c141b5f4400126676eb8ff6c87a5faef8b9aed871178c
grep -a -q -- '--plus-guest-contained' "$stage/files/grok-build-linux-helper" || fail "helper protocol was missing"
grep -a -q -- '--plus-typed-outcome-v1' "$stage/files/grok-build-linux-helper" || fail "typed outcome protocol was missing"
grep -a -q -- '--gb-contained-service-v1' "$stage/files/grok-build-linux-helper" || fail "contained service protocol was missing"
grep -a -q -- '--gb-contained-service-profile-v1' "$stage/files/grok-build-linux-helper" || fail "contained service profile protocol was missing"

for path in "$phase_root" "$phase_root/releases" "$release_root" "$binary_root" "$install_root" \
  "$stdio_install_root" /var/lib/grok-build /var/lib/grok-build/phase1 \
  /var/lib/grok-build/phase1/releases /var/lib/grok-build/phase1/releases/"$helper_sha" \
  "$state_root" "$stdio_state_root"; do
  test ! -L "$path" || fail "$path was a symlink"
done
install -d -o root -g root -m 0755 "$phase_root" "$phase_root/releases" "$release_root" "$binary_root" "$install_root"
install -d -o root -g root -m 0755 "$stdio_install_root" /var/lib/grok-build \
  /var/lib/grok-build/phase1 /var/lib/grok-build/phase1/releases \
  /var/lib/grok-build/phase1/releases/"$helper_sha"
# Existing owner-private state must not be made world-readable during a repair.
for private_root in "$state_root" "$stdio_state_root"; do
  if test ! -d "$private_root"; then
    install -d -o root -g root -m 0700 "$private_root"
  fi
done
install -o root -g root -m 0555 "$stage/files/grok-build-linux-helper" "$binary_root/grok-build-linux-helper"
install -o "$runner_uid" -g "$runner_gid" -m 0500 "$stage/files/grok-build-linux-helper" "$binary_root/grok-build-runner"
install -d -o root -g root -m 0755 "$probe_root"
install -o root -g root -m 0555 "$stage/files/plus-contained-probe" "$probe_root/plus-contained-probe"

if test -e /usr/bin/bwrap; then
  verify /usr/bin/bwrap 67816 ae27935781511400c65ebcc0b4669775d602f46251b8707c947a1ac1b160c1c8
else
  install -o root -g root -m 0755 "$stage/files/bwrap" /usr/bin/bwrap
fi
bwrap_version=$(/usr/bin/bwrap --version)
test "$bwrap_version" = 'bubblewrap 0.9.0' || fail "Bubblewrap version changed"

test -f /sys/fs/cgroup/cgroup.controllers || fail "cgroup v2 was unavailable"
grep -qw memory /sys/fs/cgroup/cgroup.controllers || fail "memory controller was unavailable"
grep -qw pids /sys/fs/cgroup/cgroup.controllers || fail "pids controller was unavailable"
test ! -L "$cgroup_parent" && test ! -L "$service_cgroup" || fail "cgroup path was a symlink"
mkdir -p "$cgroup_parent" "$service_cgroup"
chown root:root "$cgroup_parent" && chmod 0755 "$cgroup_parent"
printf '+memory +pids\n' > "$cgroup_parent/cgroup.subtree_control"
chown "$runner_uid:$runner_gid" "$cgroup_parent/cgroup.procs"
chown "$runner_uid:$runner_gid" "$service_cgroup" "$service_cgroup/cgroup.procs"
chmod 0755 "$service_cgroup"

if test ! -f "$install_root/handoff-commitment.v1.json"; then
  "$binary_root/grok-build-linux-helper" --grok-build-install-linux-native-service \
    "$install_root" "$state_root" "$cgroup_parent" "$delegation" \
    "$runner_uid" "$runner_gid" 755 "$helper_sha"
fi
sh -c 'echo $$ > "$1"; shift; exec setpriv --reuid="$1" --regid="$2" --clear-groups --no-new-privs "$3" --grok-build-open-linux-native-service "$4"' \
  sh "$service_cgroup/cgroup.procs" "$runner_uid" "$runner_gid" "$binary_root/grok-build-runner" "$install_root"

# Long-lived descendants never occupy the Checks delegation. Each helper
# generation has a distinct anchor and state root, so upgrading cannot replace
# the authority retained by an active old service. This installs no LSM policy
# and does not mark an extension enabled or a service ready.
for parent in "$stdio_releases" "$stdio_cgroup_parent"; do
  test ! -L "$parent" || fail "stdio cgroup parent was a symlink"
  mkdir -p "$parent"
  chown root:root "$parent" && chmod 0755 "$parent"
  printf '+memory +pids\n' > "$parent/cgroup.subtree_control"
done
# One immutable ceiling spans helper generations; per-lease limits remain tighter.
# Trusted control/staging helpers retain their existing separate harness domain.
printf '1073741824\n' > "$stdio_releases/memory.max"
printf '0\n' > "$stdio_releases/memory.swap.max"
printf '128\n' > "$stdio_releases/pids.max"
test "$(cat "$stdio_releases/memory.max")" = 1073741824 || fail "stdio memory pool readback differed"
test "$(cat "$stdio_releases/memory.swap.max")" = 0 || fail "stdio swap pool readback differed"
test "$(cat "$stdio_releases/pids.max")" = 128 || fail "stdio process pool readback differed"
if test ! -f "$stdio_install_root/handoff-commitment.v1.json"; then
  "$binary_root/grok-build-linux-helper" --grok-build-install-linux-native-service \
    "$stdio_install_root" "$stdio_state_root" "$stdio_cgroup_parent" stdio \
    "$runner_uid" "$runner_gid" 755 "$helper_sha"
fi
sh -c 'echo $$ > "$1"; shift; exec setpriv --reuid="$1" --regid="$2" --clear-groups --no-new-privs "$3" --grok-build-open-linux-native-service "$4"' \
  sh "$service_cgroup/cgroup.procs" "$runner_uid" "$runner_gid" "$binary_root/grok-build-runner" "$stdio_install_root"

probe_output=$(sh -c '
  echo $$ > "$1"
  exec setpriv --reuid="$2" --regid="$3" --clear-groups --no-new-privs env \
    HOME="$4" TMPDIR=/tmp \
    GROK_BUILD_LINUX_NATIVE_SERVICE_INSTALL_ROOT="$5" \
    GROK_BUILD_RUNNER_BINARY="$6" \
    GROK_BUILD_PLUS_GUEST_HELPER="$7" \
    GROK_BUILD_PLUS_PROBE_DIR="$8" \
    GROK_BUILD_PLUS_PREBUILT_PROBE="$9" \
    "$7" --plus-guest-contained --plus-typed-outcome-v1
' sh "$service_cgroup/cgroup.procs" "$runner_uid" "$runner_gid" "$runner_home" \
  "$install_root" "$binary_root/grok-build-runner" "$binary_root/grok-build-linux-helper" \
  "$probe_root" "$probe_root/plus-contained-probe") \
  || fail "contained readiness test failed"
printf '%s\n' "$probe_output" | grep -q '^Command succeeded' \
  || fail "contained readiness result was not successful"

current_tmp=$phase_root/.current.$$
trap 'rm -f -- "$current_tmp"; cleanup' EXIT HUP INT TERM
(umask 077; printf '%s\n%s\n%s\n' "$install_root" "$binary_root/grok-build-linux-helper" "$binary_root/grok-build-runner" > "$current_tmp")
chown root:root "$current_tmp" && chmod 0444 "$current_tmp"
mv -f -- "$current_tmp" "$phase_root/current"
sync -f "$phase_root"
echo "Command security runner installed and verified."
