#!/bin/sh
# Guest-side supervisor for the Grok Build Virtualization.framework Linux guest.
#
# The host owns the guest's lifecycle; this script is the guest half of it. It
# does the setup a container runtime performs invisibly, publishes a liveness
# signal the host can read, and then serves one command at a time over the only
# bidirectional channel a guest with no network already has: the virtiofs share.
#
# Channel, all under <share>/control:
#
#   ready        written once, after the share is mounted and the command image
#                is staged into guest RAM; carries the staging cost in ms
#   hb           rewritten every poll turn: "<turn> <guest-uptime-seconds>"
#   req.<n>      host -> guest, renamed into place: verb on line 1, argv after
#   out.<n>      guest -> host, the command's merged stdout and stderr
#   res.<n>      guest -> host, renamed into place: "<exit-code> <duration-ms>"
#
# Every guest-to-host file is renamed into place from a temporary in the same
# directory, so the host can never read a half-written record.
#
# Two properties this script exists to provide:
#
#   * **Staging from guest RAM.** Increment 1 measured the 51 MB command image
#     costing ~30 ms to seal from the virtiofs share against ~13 ms from guest
#     tmpfs. The share is copied into /stage once per guest, so that cost is
#     paid per guest instead of per command.
#   * **Residue freedom between commands.** A persistent guest amortises the
#     boot but keeps state between commands. Each command runs in its own mount
#     namespace with its own private /tmp, under its own cgroup leaf, in its own
#     private scratch root, with a replaced environment — and the leaf is killed
#     and proved empty before the next command is served.

set -u

SHARE=/mnt/ws
CONTROL="$SHARE/control"
STAGE=/stage

log() { echo "gbd-guest: $*"; }

# Guest milliseconds since boot. `date +%s%N` is unusable here: a guest with no
# real-time clock starts at the epoch, so the concatenation carries a leading
# zero and the shell reads it as an illegal octal literal. /proc/uptime has no
# such ambiguity, and the leading zero of its centisecond field is stripped for
# the same reason.
guest_ms() {
    read -r uptime_field _ < /proc/uptime
    uptime_seconds=${uptime_field%.*}
    uptime_centiseconds=${uptime_field#*.}
    uptime_centiseconds=${uptime_centiseconds#0}
    [ -z "$uptime_centiseconds" ] && uptime_centiseconds=0
    echo $(( uptime_seconds * 1000 + uptime_centiseconds * 10 ))
}

publish() {
    # $1 = final name under $CONTROL, $2 = contents. Renamed into place so the
    # host never reads a partial record.
    printf '%s' "$2" > "$CONTROL/.publish.tmp"
    mv -f "$CONTROL/.publish.tmp" "$CONTROL/$1"
}

# ---------------------------------------------------------------- share mount
mkdir -p "$SHARE"
if ! mount -t virtiofs gbdws "$SHARE"; then
    log "virtiofs mount failed"
    exit 1
fi
mkdir -p "$CONTROL"

# --------------------------------------------------------- cgroup delegation
echo "+pids +memory" > /sys/fs/cgroup/cgroup.subtree_control
mkdir -p /sys/fs/cgroup/gbd-deleg
echo "+pids +memory" > /sys/fs/cgroup/gbd-deleg/cgroup.subtree_control
mkdir -p /sys/fs/cgroup/gbd-deleg/service
chown -R 1000:1000 /sys/fs/cgroup/gbd-deleg
echo $$ > /sys/fs/cgroup/gbd-deleg/service/cgroup.procs

# ------------------------------------------------- stage the image into RAM
# The command image is copied out of the share exactly once. Everything a
# command executes afterwards is read from guest memory, never across virtiofs.
mkdir -p "$STAGE"
mount -t tmpfs -o size=2g,mode=0755 tmpfs "$STAGE"
STAGE_START=$(guest_ms)
cp "$SHARE/grok-build-runner" "$STAGE/grok-build-runner"
mkdir -p "$STAGE/deps"
for image in "$SHARE"/deps/*; do
    [ -e "$image" ] || continue
    cp "$image" "$STAGE/deps/"
done
chmod -R a+rX "$STAGE"
STAGE_END=$(guest_ms)
STAGE_MS=$(( STAGE_END - STAGE_START ))

mkdir -p /scratch
mount -t tmpfs -o size=4g,mode=0755 tmpfs /scratch

publish ready "$STAGE_MS"
log "ready, staged in ${STAGE_MS}ms"

# ------------------------------------------------------------- command serving
#
# The host publishes `hostbeat` while it is waiting on this guest and on every
# health check. If it stops advancing for HOST_STALL_LIMIT idle turns (1,000 turns of ~10 ms, so about 10 s) the host
# is gone, and a guest whose owner is gone powers itself off rather than running
# unattended: a host killed mid-session must not leave a machine behind. The
# check is between commands, so a command already running finishes first — the
# host's own wall-clock budget is the outer bound on that.
TURN=0
HOST_SEEN=""
HOST_STALL=0
HOST_STALL_LIMIT=1000
while :; do
    TURN=$((TURN + 1))
    read -r UPTIME _ < /proc/uptime
    publish hb "$TURN $UPTIME"

    REQUEST=""
    for candidate in "$CONTROL"/req.*; do
        [ -e "$candidate" ] || continue
        REQUEST="$candidate"
        break
    done
    if [ -z "$REQUEST" ]; then
        HOST_NOW=$(cat "$CONTROL/hostbeat" 2>/dev/null || echo "")
        if [ "$HOST_NOW" = "$HOST_SEEN" ]; then
            HOST_STALL=$((HOST_STALL + 1))
            if [ "$HOST_STALL" -ge "$HOST_STALL_LIMIT" ]; then
                log "host heartbeat stalled at '$HOST_SEEN'; powering off"
                break
            fi
        else
            HOST_SEEN=$HOST_NOW
            HOST_STALL=0
        fi
        sleep 0.01
        continue
    fi
    HOST_STALL=0

    SEQUENCE=${REQUEST##*/req.}
    VERB=$(head -n 1 "$REQUEST")

    if [ "$VERB" = shutdown ]; then
        rm -f "$REQUEST"
        log "shutdown requested"
        publish "res.$SEQUENCE" "0 0"
        break
    fi

    # Read argv from a plain file rather than a pipeline: in a POSIX shell a
    # `while read` on the right of a pipe runs in a subshell and the positional
    # parameters it builds would be discarded.
    tail -n +2 "$REQUEST" > /argv.current
    rm -f "$REQUEST"
    set --
    while IFS= read -r line; do
        set -- "$@" "$line"
    done < /argv.current

    # One private scratch root and one private cgroup leaf per command.
    ROOT="/scratch/cmd-$SEQUENCE"
    LEAF="/sys/fs/cgroup/gbd-deleg/cmd-$SEQUENCE"
    mkdir -p "$ROOT/shadow/src" "$ROOT/home"
    chown -R 1000:1000 "$ROOT"
    mkdir -p "$LEAF"
    # The command's delegation root must publish the controllers its own leaves
    # need: a leaf created beneath a root without `+pids` has no `pids.max` at
    # all, and the two descendant controls then refuse rather than measure.
    echo "+pids +memory" > "$LEAF/cgroup.subtree_control"
    # cgroup v2 forbids a cgroup from holding processes and enabled subtree
    # controllers at once, so the command's own process lives one level down.
    # Without this the command would run in the supervisor's cgroup and the
    # kill below would empty a domain the command was never in — measured: a
    # detached `setsid sleep` planted by one command survived into the next.
    mkdir -p "$LEAF/self"
    chown -R 1000:1000 "$LEAF"

    START=$(guest_ms)
    GBD_ROOT="$ROOT" GBD_LEAF="$LEAF" unshare --mount -- /bin/sh -c '
        set -u
        mount --make-rprivate /
        mount -t tmpfs -o size=1g,mode=1777 tmpfs /tmp
        echo $$ > "$GBD_LEAF/self/cgroup.procs"
        exec setpriv --reuid=1000 --regid=1000 --clear-groups \
            env -i \
                PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
                HOME="$GBD_ROOT/home" \
                TMPDIR=/tmp \
                GROK_BUILD_CGROUP_ROOT="$GBD_LEAF" \
                GBD_COMMAND_ROOT="$GBD_ROOT" \
                "$@"
    ' _ "$@" > "$CONTROL/.out.$SEQUENCE" 2>&1
    STATUS=$?
    END=$(guest_ms)

    # Prove the leaf empty before the next command can be served: one kill, then
    # a bounded wait for `populated 0`, never an unbounded one.
    if [ -e "$LEAF/cgroup.kill" ]; then
        echo 1 > "$LEAF/cgroup.kill" 2>/dev/null
    fi
    SETTLE=0
    while [ "$SETTLE" -lt 200 ]; do
        POPULATED=$(sed -n 's/^populated //p' "$LEAF/cgroup.events" 2>/dev/null)
        if [ "${POPULATED:-0}" = 0 ]; then
            break
        fi
        SETTLE=$((SETTLE + 1))
        sleep 0.005
    done
    rmdir "$LEAF" 2>/dev/null
    rm -rf "$ROOT"

    mv -f "$CONTROL/.out.$SEQUENCE" "$CONTROL/out.$SEQUENCE"
    publish "res.$SEQUENCE" "$STATUS $(( END - START ))"
done

umount "$STAGE" 2>/dev/null
umount /scratch 2>/dev/null
umount "$SHARE" 2>/dev/null
log "supervisor exiting"
