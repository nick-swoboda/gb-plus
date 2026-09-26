#!/bin/sh
# Route 1 increment 2 canary harness.
#
# Pass A runs as root: it prepares the delegated cgroup root, the install roots,
# and the runner's state root, then runs the installer pass and the refusal
# halves that require a privileged reader.
#
# Pass B runs as uid 1000 through setpriv: it consumes the anchor root wrote.
set -eu

RUNNER_UID=1000
RUNNER_GID=1000
INSTALL_ROOT=/opt/gbd-install
FORGE_ROOT=/opt/gbd-forge
STATE_ROOT=/var/lib/gbd-service/state
CGROUP_PARENT=/sys/fs/cgroup/gbd
DELEGATION=anchor-delegation
# A second, genuine, runner-owned cgroup-v2 delegation under the same parent.
# Nothing about it is invalid; it exists so the anchored-facts control half can
# cross the committed delegation with a real one instead of an invented name.
CONTROL_DELEGATION=anchor-delegation-control

echo "=== host identity"
uname -srm
id
cat /proc/self/status | grep -E '^(Uid|CapEff|CapPrm):'

echo "=== delegated cgroup root"
mount | grep -E 'cgroup2? on /sys/fs/cgroup' || true
cat /sys/fs/cgroup/cgroup.controllers
# cgroup v2's no-internal-process rule applies to the container's own root under
# `--cgroupns=private`, so every process must leave it before the root can
# delegate a controller downward.
mkdir -p /sys/fs/cgroup/init
for pid in $(cat /sys/fs/cgroup/cgroup.procs); do
    echo "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
done
echo '+memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
echo "root subtree     : $(cat /sys/fs/cgroup/cgroup.subtree_control)"
mkdir -p "$CGROUP_PARENT"
echo '+memory +pids' > "$CGROUP_PARENT/cgroup.subtree_control"
echo "gbd controllers  : $(cat "$CGROUP_PARENT/cgroup.controllers")"
echo "gbd subtree      : $(cat "$CGROUP_PARENT/cgroup.subtree_control")"
mkdir -p "$CGROUP_PARENT/$CONTROL_DELEGATION"
chown "$RUNNER_UID:$RUNNER_GID" "$CGROUP_PARENT/$CONTROL_DELEGATION"
chmod 755 "$CGROUP_PARENT/$CONTROL_DELEGATION"
ls -ld "$CGROUP_PARENT/$CONTROL_DELEGATION"
# cgroup-v2 delegation containment, measured rather than assumed. A process may
# move itself into a cgroup only if it can write BOTH the destination's
# `cgroup.procs` AND the `cgroup.procs` of the common ancestor of its own cgroup
# and the destination (Documentation/admin-guide/cgroup-v2.rst, "Delegation
# Containment"). A service sitting in the container's root cgroup therefore has
# `/` as that ancestor and cannot place anything in its own delegated leaf, no
# matter who owns the leaf. Measured in this image: it fails with EIO.
#
# So the installer has to do two more things, and neither of them hands the
# service anything the anchored-facts mint forbids:
#
#   * give the service a cgroup of its own *beneath the delegation's parent*,
#     not beneath the delegation, because `validate_for_prepare` requires the
#     delegation itself to have no children and no processes; and
#   * delegate the parent's `cgroup.procs`, the file, never the directory. The
#     parent DIRECTORY stays installer-owned and mode 755, which is what
#     `observe_anchored_plan_facts` re-reads, so the service still cannot create
#     a sibling delegation or rmdir its own.
SERVICE_CGROUP="$CGROUP_PARENT/service"
mkdir -p "$SERVICE_CGROUP"
chown "$RUNNER_UID:$RUNNER_GID" "$SERVICE_CGROUP" "$SERVICE_CGROUP/cgroup.procs"
chown "$RUNNER_UID:$RUNNER_GID" "$CGROUP_PARENT/cgroup.procs"
ls -ld "$SERVICE_CGROUP"
ls -l "$CGROUP_PARENT/cgroup.procs"
# Who owns the *parent* is the one fact the delegation arms differ in. Left
# unset, the parent stays installer-owned, which is how cgroup v2 delegation is
# documented: the delegator keeps the parent and chowns only the delegated
# subtree, and the production plan built from it validates. Set, the parent is
# chowned to the service, a parent the service can create siblings in and
# rmdir this delegation from, and the anchored-facts mint refuses it before any
# plan exists. Nothing else varies between the two runs.
SERVICE_OWNED_PARENT="${GBD_CANARY_SERVICE_OWNED_CGROUP_PARENT:-}"
if [ -n "$SERVICE_OWNED_PARENT" ]; then
    chown "$RUNNER_UID:$RUNNER_GID" "$CGROUP_PARENT"
fi
ls -ld "$CGROUP_PARENT"

echo "=== install roots"
rm -rf "$INSTALL_ROOT" "$FORGE_ROOT" "$STATE_ROOT"
mkdir -p "$INSTALL_ROOT" "$FORGE_ROOT" "$STATE_ROOT"
chown root:root "$INSTALL_ROOT"
chmod 755 "$INSTALL_ROOT"
chown "$RUNNER_UID:$RUNNER_GID" "$FORGE_ROOT"
chmod 755 "$FORGE_ROOT"
ls -ld / /opt "$INSTALL_ROOT" "$FORGE_ROOT" /var/lib/gbd-service "$STATE_ROOT"

echo "=== build the test binary"
cargo test -p grok-build-runner --lib --all-features --locked --no-run --message-format=json \
    > /tmp/testbuild.json 2>/tmp/testbuild.err || { tail -40 /tmp/testbuild.err; exit 1; }
TEST_BIN="$(tr ',' '\n' < /tmp/testbuild.json | grep '"executable":"' | grep 'grok_build_runner-' | tail -1 | sed 's/.*"executable":"//; s/"$//')"
echo "test binary      : $TEST_BIN"
[ -x "$TEST_BIN" ] || { echo "no test binary"; exit 1; }
ls -l "$TEST_BIN"
sha256sum "$TEST_BIN"

export GROK_BUILD_SERVICE_INSTALL_ROOT="$INSTALL_ROOT"
export GROK_BUILD_SERVICE_FORGE_ROOT="$FORGE_ROOT"
export GROK_BUILD_SERVICE_STATE_ROOT="$STATE_ROOT"
export GROK_BUILD_SERVICE_CGROUP_PARENT="$CGROUP_PARENT"
export GROK_BUILD_SERVICE_DELEGATION="$DELEGATION"
export GROK_BUILD_SERVICE_CONTROL_DELEGATION="$CONTROL_DELEGATION"
export GROK_BUILD_SERVICE_RUNNER_UID="$RUNNER_UID"
export GROK_BUILD_SERVICE_RUNNER_GID="$RUNNER_GID"

echo
echo "=== PASS A (installer identity, uid 0): install + privileged refusal halves"
"$TEST_BIN" --test-threads=1 --nocapture \
    linux_cgroup_io::tests::linux_native_service 2>&1 | tail -30
"$TEST_BIN" --test-threads=1 --nocapture \
    linux_cgroup_io::tests::live_installed 2>&1 | tail -30
"$TEST_BIN" --test-threads=1 --nocapture \
    linux_cgroup_io::tests::service_install 2>&1 | tail -20

echo
echo "=== installed anchor"
ls -l "$INSTALL_ROOT"
cat "$INSTALL_ROOT/handoff-commitment.v1.json"; echo
ls -ld "$STATE_ROOT" "$STATE_ROOT/linux-command-journal-v2" "$CGROUP_PARENT/$DELEGATION"
echo "delegation subtree: $(cat "$CGROUP_PARENT/$DELEGATION/cgroup.subtree_control")"

# Runs one pass with the service's identity, from the service's own cgroup.
#
# The move happens first and with the installer's privilege, exactly as a
# service manager would place a unit before it drops privilege; the test binary
# itself never has more than uid $RUNNER_UID. Being inside "$SERVICE_CGROUP" is
# what makes the delegation's parent the common ancestor of the service and any
# leaf it prepares, and therefore what makes an unprivileged self-attachment
# into that leaf legal at all.
service_pass() {
    sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$SERVICE_CGROUP/cgroup.procs" \
        setpriv --reuid="$RUNNER_UID" --regid="$RUNNER_GID" --clear-groups --no-new-privs \
        env HOME=/tmp TMPDIR=/tmp \
        GROK_BUILD_SERVICE_INSTALL_ROOT="$INSTALL_ROOT" \
        GROK_BUILD_SERVICE_FORGE_ROOT="$FORGE_ROOT" \
        GROK_BUILD_SERVICE_STATE_ROOT="$STATE_ROOT" \
        GROK_BUILD_SERVICE_CGROUP_PARENT="$CGROUP_PARENT" \
        GROK_BUILD_SERVICE_DELEGATION="$DELEGATION" \
        GROK_BUILD_SERVICE_CONTROL_DELEGATION="$CONTROL_DELEGATION" \
        GROK_BUILD_SERVICE_RUNNER_UID="$RUNNER_UID" \
        GROK_BUILD_SERVICE_RUNNER_GID="$RUNNER_GID" \
        GBD_CANARY_SERVICE_OWNED_CGROUP_PARENT="$SERVICE_OWNED_PARENT" \
        "$TEST_BIN" --test-threads=1 --nocapture "$@"
}

echo
echo "=== PASS B (runner identity, uid $RUNNER_UID, cgroup $SERVICE_CGROUP)"
chmod 777 /tmp
service_pass linux_cgroup_io::tests:: 2>&1 | tail -60

echo
echo "=== PASS B, anchored production plan facts (route 1 increment 3)"
service_pass linux_cgroup_io::tests::live_anchored_plan_facts 2>&1

echo "HARNESS COMPLETE"
