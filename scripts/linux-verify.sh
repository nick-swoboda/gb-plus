#!/usr/bin/env bash
# Compile, lint, format and test the workspace on Linux. Linked binaries and
# harness results must satisfy the checked-in policies; incomplete runs fail.
#
# Usage: ./scripts/linux-verify.sh [--native|--container]
#
# Environment overrides (all optional):
#   GBD_LINUX_IMAGE     container image tag        (default immutable reviewed ARM64 image)
#   GBD_LINUX_TARGET    docker volume for target/  (default gbd-target-linux)
#   GBD_CARGO_REGISTRY  docker volume for registry (default gbd-cargo-registry)
#   GBD_LINUX_SOURCE_VOLUME  explicitly prepared source snapshot volume (optional)
#                       Use only with independently verified source readback.
#   COLIMA_HOME         colima state directory; auto-discovered when unset
#   GBD_KEEP_JSON       set to 1 to keep the raw JSON streams for inspection
#
# Exit status: 0 only when every assertion below passed. Non-zero otherwise.

set -euo pipefail

readonly GATE_NAME="LINUX VERIFICATION GATE"
readonly EXPECTED_RUSTC_PREFIX="rustc 1.97.1 "
readonly EXPECTED_CARGO_PREFIX="cargo 1.97.1 "
# GNU ld symbol-table caching exhausted the 2 GiB guest on the Slint test link.
readonly LINUX_MEMORY_RUSTFLAGS="-C link-arg=-Wl,--no-keep-memory"

GATE_COMPLETED=0
GATE_REPORTED=0
WORK_DIR=""

cleanup() {
    local status=$?
    if [ -n "$WORK_DIR" ] && [ "${GBD_KEEP_JSON:-0}" != "1" ]; then
        rm -rf "$WORK_DIR"
    elif [ -n "$WORK_DIR" ]; then
        printf 'raw JSON streams kept in %s\n' "$WORK_DIR"
    fi
    if [ "$GATE_COMPLETED" -ne 1 ] && [ "$GATE_REPORTED" -ne 1 ]; then
        # Reached only when the script died somewhere it did not expect to:
        # an unset variable, a killed container, a `set -e` trip. Silence here
        # would read as a pass to anything scraping the tail of the log.
        printf '\n%s: FAILURE (terminated before completing its checks)\n' "$GATE_NAME"
        if [ "$status" -eq 0 ]; then
            # Never let an early exit be mistaken for a pass.
            exit 70
        fi
    fi
    exit "$status"
}
trap cleanup EXIT

fail() {
    GATE_REPORTED=1
    printf '\n%s: FAILURE\n  %s\n' "$GATE_NAME" "$*"
    exit 1
}

step() {
    printf '\n== %s\n' "$*"
}

# ---------------------------------------------------------------------------
# Preflight. Every precondition is checked and named; none is assumed.
# ---------------------------------------------------------------------------

MODE="container"
case "${1:-}" in
    "") ;;
    --native) MODE="native" ;;
    --container) MODE="container" ;;
    *) fail "unknown argument '$1'; expected --native or --container" ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

[ -f "$REPO_ROOT/Cargo.toml" ] || fail "no Cargo.toml at inferred repository root $REPO_ROOT"
grep -q '^\[workspace\]' "$REPO_ROOT/Cargo.toml" \
    || fail "$REPO_ROOT/Cargo.toml is not a cargo workspace root"

IMAGE="${GBD_LINUX_IMAGE:-sha256:7c235e5f908f7451a70150cddf9c291677b53fc052e70013d1141727618cc43b}"
TARGET_VOLUME="${GBD_LINUX_TARGET:-gbd-target-linux}"
REGISTRY_VOLUME="${GBD_CARGO_REGISTRY:-gbd-cargo-registry}"
SOURCE_VOLUME="${GBD_LINUX_SOURCE_VOLUME:-}"
SOURCE_MOUNT="type=bind,source=$REPO_ROOT,target=/work"
if [ -n "$SOURCE_VOLUME" ]; then
    SOURCE_MOUNT="type=volume,source=$SOURCE_VOLUME,target=/work"
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is not on PATH; the gate cannot parse cargo JSON"

if [ "$MODE" = "container" ]; then
    command -v docker >/dev/null 2>&1 \
        || fail "docker is not on PATH; the gate cannot run a Linux compile (use --native on a Linux host)"

    # Discover an existing project-local Colima socket when no home is set.
    if [ -z "${COLIMA_HOME:-}" ]; then
        probe="$REPO_ROOT"
        while [ "$probe" != "/" ]; do
            if [ -S "$probe/.colima/default/docker.sock" ]; then
                export COLIMA_HOME="$probe/.colima"
                break
            fi
            probe="$(dirname -- "$probe")"
        done
    fi

    docker info >/dev/null 2>&1 \
        || fail "docker daemon is unreachable (COLIMA_HOME=${COLIMA_HOME:-<unset>}); start it and retry"

    docker image inspect "$IMAGE" >/dev/null 2>&1 \
        || fail "container image $IMAGE is not present locally. Check disk space and prepare the reviewed image before running this gate; see CONTRIBUTING.md."
    for volume in "$TARGET_VOLUME" "$REGISTRY_VOLUME"; do
        docker volume inspect "$volume" >/dev/null 2>&1 \
            || fail "required volume $volume is absent; the gate never creates volumes. Check free space and prepare reviewed inputs explicitly."
    done
    if [ -n "$SOURCE_VOLUME" ]; then
        docker volume inspect "$SOURCE_VOLUME" >/dev/null 2>&1 \
            || fail "source snapshot volume $SOURCE_VOLUME is absent; prepare and verify it explicitly"
    fi
else
    command -v cargo >/dev/null 2>&1 || fail "cargo is not on PATH"
    # Step 1 asserts this again from inside the build host, but refusing here
    # gives a reader the reason instead of a confusing toolchain mismatch.
    [ "$(uname -s)" = "Linux" ] \
        || fail "--native was requested on $(uname -s); this gate only certifies Linux"
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gbd-linux-verify.XXXXXX")"

# Serialize compilation and disable incremental output to bound memory and disk.
run_in_container() {
    if [ "$MODE" = "native" ]; then
        ( cd "$REPO_ROOT" && CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 RUSTFLAGS="$LINUX_MEMORY_RUSTFLAGS" "$@" )
        return
    fi
    docker run --rm --network none \
        --mount "$SOURCE_MOUNT" -w /work \
        -v "$TARGET_VOLUME":/target \
        -v "$REGISTRY_VOLUME":/usr/local/cargo/registry:ro \
        --tmpfs /tmp:exec \
        -e CARGO_TARGET_DIR=/target \
        -e CARGO_TERM_COLOR=never \
        -e CARGO_NET_OFFLINE=true \
        -e RUSTUP_AUTO_INSTALL=0 \
        -e LANG=C.UTF-8 \
        -e CARGO_BUILD_JOBS=1 \
        -e RUSTFLAGS="$LINUX_MEMORY_RUSTFLAGS" \
        -e CARGO_INCREMENTAL=0 \
        "$IMAGE" "$@"
}

# Refuse up front when the build filesystem cannot hold a run, so a resource
# problem is never mistaken for a result. This asserts and reports; it deletes
# nothing. Reclaiming a cache is the operator's decision, and the message says
# what to reclaim rather than doing it.
readonly MINIMUM_FREE_KIB=5242880 # 5 GiB
check_free_space() {
    space_probe="$WORK_DIR/free-space.txt"
    if [ "$MODE" = "native" ]; then
        df -Pk "$REPO_ROOT" >"$space_probe" 2>/dev/null \
            || fail "could not measure free space on $REPO_ROOT"
        space_where="$REPO_ROOT"
    else
        # Measured through the target volume, so this reports the filesystem the
        # build actually writes to rather than the container's own layer.
        run_in_container df -Pk /target >"$space_probe" 2>/dev/null \
            || fail "could not measure free space on the $TARGET_VOLUME volume"
        space_where="volume $TARGET_VOLUME"
    fi
    space_free_kib="$(awk 'NR==2 {print $4}' "$space_probe")"
    case "$space_free_kib" in
        '' | *[!0-9]*)
            fail "free space on $space_where did not parse as a number: '$space_free_kib'"
            ;;
    esac
    printf 'free space : %s MiB on %s (minimum %s MiB)\n' \
        "$((space_free_kib / 1024))" "$space_where" "$((MINIMUM_FREE_KIB / 1024))"
    if [ "$space_free_kib" -lt "$MINIMUM_FREE_KIB" ]; then
        fail "only $((space_free_kib / 1024)) MiB free on $space_where; this gate needs at least $((MINIMUM_FREE_KIB / 1024)) MiB. It does not delete anything on your behalf. The usual reclaim is the regenerable incremental cache inside the target volume ('cargo clean' there, or remove its debug/incremental directory); check what is actually large before removing anything."
    fi
}

printf '%s\n' "$GATE_NAME"
printf 'repository : %s\n' "$REPO_ROOT"
printf 'mode       : %s\n' "$MODE"
if [ "$MODE" = "container" ]; then
    printf 'image      : %s\n' "$IMAGE"
    printf 'target vol : %s\n' "$TARGET_VOLUME"
fi

check_free_space

# ---------------------------------------------------------------------------
# 1. Prove the compile really is happening on Linux, on the pinned toolchain.
#    A gate that quietly ran on the host would be worthless.
# ---------------------------------------------------------------------------

step "1/6 host identity and toolchain pin"

if ! run_in_container sh -c 'uname -s; uname -m; uname -r; rustc --version; cargo --version' \
        >"$WORK_DIR/identity.txt" 2>"$WORK_DIR/identity.err"; then
    cat "$WORK_DIR/identity.err" >&2
    fail "could not execute anything inside $IMAGE"
fi

IDENT_OS="$(sed -n 1p "$WORK_DIR/identity.txt")"
IDENT_ARCH="$(sed -n 2p "$WORK_DIR/identity.txt")"
IDENT_KERNEL="$(sed -n 3p "$WORK_DIR/identity.txt")"
IDENT_RUSTC="$(sed -n 4p "$WORK_DIR/identity.txt")"
IDENT_CARGO="$(sed -n 5p "$WORK_DIR/identity.txt")"

[ "$IDENT_OS" = "Linux" ] || fail "compile host reports '$IDENT_OS', not Linux"
case "$IDENT_RUSTC" in
    "$EXPECTED_RUSTC_PREFIX"*) ;;
    *) fail "rustc is '$IDENT_RUSTC', expected $EXPECTED_RUSTC_PREFIX(pinned by rust-toolchain.toml)" ;;
esac
case "$IDENT_CARGO" in
    "$EXPECTED_CARGO_PREFIX"*) ;;
    *) fail "cargo is '$IDENT_CARGO', expected $EXPECTED_CARGO_PREFIX(pinned by rust-toolchain.toml)" ;;
esac

printf 'os         : %s %s (kernel %s)\n' "$IDENT_OS" "$IDENT_ARCH" "$IDENT_KERNEL"
printf 'toolchain  : %s / %s\n' "$IDENT_RUSTC" "$IDENT_CARGO"

# ---------------------------------------------------------------------------
# 2. Ask cargo which binary targets this workspace declares, rather than
#    hard-coding a list that would rot the moment a bin is added.
# ---------------------------------------------------------------------------

step "2/6 workspace binary targets"

if ! run_in_container cargo metadata --format-version 1 --no-deps --locked --offline \
        >"$WORK_DIR/metadata.json" 2>"$WORK_DIR/metadata.err"; then
    cat "$WORK_DIR/metadata.err" >&2
    fail "cargo metadata failed inside the container"
fi

python3 - "$WORK_DIR/metadata.json" >"$WORK_DIR/expected-bins.txt" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    metadata = json.load(handle)

members = set(metadata.get("workspace_members", []))
names = set()
for package in metadata.get("packages", []):
    if package.get("id") not in members:
        continue
    for target in package.get("targets", []):
        if "bin" in target.get("kind", []):
            names.add(target["name"])

if not names:
    sys.exit("no binary targets found in workspace metadata")
for name in sorted(names):
    print(name)
PY

EXPECTED_BINS="$(cat "$WORK_DIR/expected-bins.txt")"
EXPECTED_BIN_COUNT="$(printf '%s\n' "$EXPECTED_BINS" | grep -c . || true)"
[ "$EXPECTED_BIN_COUNT" -ge 1 ] || fail "workspace declares no binary targets; nothing would be proven"
printf 'declared bins (%s): %s\n' "$EXPECTED_BIN_COUNT" "$(printf '%s' "$EXPECTED_BINS" | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# 3. THE COMPILE. Whole workspace, every target, every binary, linked for real.
#    Success is asserted twice and independently: cargo's own exit status, and
#    the presence of a linked executable artifact for every declared bin.
#    Neither assertion looks at a diagnostic count.
# ---------------------------------------------------------------------------

step "3/6 Linux compile: cargo build --workspace --all-targets --all-features --locked"

BUILD_STATUS=0
run_in_container cargo build --workspace --all-targets --all-features --locked --offline \
        --message-format=json \
        >"$WORK_DIR/build.json" 2>"$WORK_DIR/build.err" || BUILD_STATUS=$?

BUILD_CHECK=0
python3 - "$WORK_DIR/build.json" "$WORK_DIR/expected-bins.txt" "$BUILD_STATUS" <<'PY' || BUILD_CHECK=$?
import json
import sys

stream_path, bins_path, cargo_status = sys.argv[1], sys.argv[2], int(sys.argv[3])

with open(bins_path, encoding="utf-8") as handle:
    expected = {line.strip() for line in handle if line.strip()}

linked = set()
artifacts = 0
errors = []
records = 0

with open(stream_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        records += 1
        reason = record.get("reason")
        if reason == "compiler-artifact":
            artifacts += 1
            target = record.get("target") or {}
            if "bin" in (target.get("kind") or []) and record.get("executable"):
                linked.add(target.get("name"))
        elif reason == "compiler-message":
            message = record.get("message") or {}
            if message.get("level") == "error":
                errors.append(message.get("rendered") or message.get("message") or "")

print(f"cargo exit status      : {cargo_status}")
print(f"json records parsed    : {records}")
print(f"compiler artifacts     : {artifacts}")
print(f"bins linked on Linux   : {len(linked)} of {len(expected)}")

problems = []
if records == 0:
    problems.append("cargo emitted no JSON records at all -- the compile did not run")
if cargo_status != 0:
    problems.append(f"cargo build exited {cargo_status}: the workspace DID NOT COMPILE on Linux")
missing = sorted(expected - linked)
if missing:
    problems.append("no linked executable produced for binary target(s): " + ", ".join(missing))

if errors:
    print(f"\ncompile errors         : {len(errors)}")
    for rendered in errors[:20]:
        print("-" * 70)
        print(rendered.rstrip())
    if len(errors) > 20:
        print(f"... and {len(errors) - 20} more")

if problems:
    print("\nCOMPILE ASSERTION FAILED:")
    for problem in problems:
        print(f"  - {problem}")
    sys.exit(1)

print("compile assertion      : PASS (every declared bin linked; cargo exit 0)")
PY
if [ "$BUILD_CHECK" -ne 0 ]; then
    printf '\n--- cargo build stderr (tail) ---\n'
    tail -n 40 "$WORK_DIR/build.err" || true
    fail "the workspace did not compile on Linux (see the errors above)"
fi

# ---------------------------------------------------------------------------
# 4. Lints. Same flags the CI Linux lane uses. Errors are counted separately
#    from warnings and evaluated against a frozen, per-lint policy so that
#    drift in EITHER direction fails: a new diagnostic fails, and a frozen
#    entry that no longer fires fails too.
# ---------------------------------------------------------------------------

step "4/6 clippy: cargo clippy --workspace --all-targets --all-features --locked"

CLIPPY_STATUS=0
run_in_container cargo clippy --workspace --all-targets --all-features --locked --offline \
        --message-format=json \
        >"$WORK_DIR/clippy.json" 2>"$WORK_DIR/clippy.err" || CLIPPY_STATUS=$?

POLICY="$REPO_ROOT/scripts/linux-clippy-policy.json"
[ -f "$POLICY" ] || fail "clippy policy file is missing: $POLICY"

CLIPPY_CHECK=0
python3 - "$WORK_DIR/clippy.json" "$POLICY" "$CLIPPY_STATUS" <<'PY' || CLIPPY_CHECK=$?
import json
import re
import sys
from collections import Counter

stream_path, policy_path, cargo_status = sys.argv[1], sys.argv[2], int(sys.argv[3])

with open(policy_path, encoding="utf-8") as handle:
    policy = json.load(handle)

frozen = {entry["lint"]: entry for entry in policy.get("frozen", [])}

# Cargo appends per-crate roll-up messages ("N warnings emitted", "aborting due
# to N previous errors", "For more information about this error..."). They are
# summaries of diagnostics already counted, not diagnostics, and counting them
# is how a total drifts away from what a human sees.
SUMMARY = re.compile(
    r"^(aborting due to \d+ previous error|"
    r"\d+ warnings? emitted|"
    r"For more information about|"
    r"Some errors have detailed|"
    r"For more information about an error|"
    r"generated \d+ warnings?)"
)

errors = Counter()
warnings = Counter()
diagnostic_render = []
seen = set()
artifacts = 0
records = 0
targets = set()

with open(stream_path, encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        records += 1
        reason = record.get("reason")
        if reason == "compiler-artifact":
            artifacts += 1
            target = (record.get("target") or {}).get("name")
            if target:
                targets.add(target)
            continue
        if reason != "compiler-message":
            continue
        message = record.get("message") or {}
        level = message.get("level")
        if level not in ("error", "warning"):
            continue
        text = message.get("message") or ""
        code = (message.get("code") or {}).get("code")
        if code is None and SUMMARY.match(text):
            continue
        # `--all-targets` compiles the same source into several targets (lib,
        # test, bin), so the identical diagnostic is reported more than once.
        # De-duplicate on the diagnostic's own identity: what a reader means by
        # "a diagnostic" is a place in the source, not a compilation of it.
        spans = message.get("spans") or []
        primary = next((s for s in spans if s.get("is_primary")), spans[0] if spans else {})
        identity = (
            level,
            code,
            primary.get("file_name"),
            primary.get("line_start"),
            primary.get("column_start"),
            text,
        )
        if identity in seen:
            continue
        seen.add(identity)
        bucket = errors if level == "error" else warnings
        bucket[code or f"<uncoded: {text[:60]}>"] += 1
        if level == "error" or code not in frozen:
            diagnostic_render.append(message.get("rendered") or text)

error_total = sum(errors.values())
warning_total = sum(warnings.values())

print(f"cargo exit status      : {cargo_status}")
print(f"json records parsed    : {records}")
print(f"targets linted         : {len(targets)}")
print(f"compiler artifacts     : {artifacts}")
print(f"ERRORS   (level=error) : {error_total}")
print(f"WARNINGS (level=warning): {warning_total}")

if error_total:
    print("\nerrors by lint/code:")
    for code, count in sorted(errors.items()):
        print(f"  {count:4d}  {code}")
    for rendered in diagnostic_render[:10]:
        print("-" * 70)
        print(rendered.rstrip())

if warning_total:
    print("\nwarnings by lint:")
    for code, count in sorted(warnings.items()):
        print(f"  {count:4d}  {code}")

problems = []
if records == 0:
    problems.append("clippy emitted no JSON records at all -- the lint pass did not run")
if artifacts == 0:
    problems.append("clippy produced no artifacts -- it linted nothing")

max_errors = policy.get("max_errors", 0)
if error_total > max_errors:
    problems.append(
        f"{error_total} clippy error(s); policy allows {max_errors}. "
        "An error is a compile failure, not a strong warning."
    )

# Per-lint drift, in both directions.
observed = dict(warnings)
observed.update({k: observed.get(k, 0) + v for k, v in errors.items()})
for lint, count in sorted(observed.items()):
    allowed = frozen.get(lint, {}).get("count", 0)
    if count != allowed:
        if allowed == 0:
            problems.append(f"{count} unfrozen diagnostic(s) of {lint}")
        else:
            problems.append(
                f"{lint}: {count} observed, {allowed} frozen "
                "(the frozen baseline may only change deliberately)"
            )
for lint, entry in sorted(frozen.items()):
    if observed.get(lint, 0) == 0 and entry.get("count", 0) != 0:
        problems.append(
            f"{lint} is frozen at {entry['count']} but no longer fires; "
            "remove it from scripts/linux-clippy-policy.json"
        )

if problems:
    print("\nCLIPPY POLICY FAILED:")
    for problem in problems:
        print(f"  - {problem}")
    if not error_total:
        for rendered in diagnostic_render[:10]:
            print(rendered.rstrip())
    sys.exit(1)

print("clippy policy          : PASS")
PY
if [ "$CLIPPY_CHECK" -ne 0 ]; then
    printf '\n--- cargo clippy stderr (tail) ---\n'
    tail -n 20 "$WORK_DIR/clippy.err" || true
    fail "clippy policy not satisfied on Linux (see above)"
fi

# ---------------------------------------------------------------------------
# 5. Formatting, checked on the same tree in the same pass so the Linux lane
#    and the local gate cannot disagree about which tree they looked at.
# ---------------------------------------------------------------------------

step "5/6 formatting: cargo fmt --all -- --check"

if ! run_in_container cargo fmt --all -- --check >"$WORK_DIR/fmt.txt" 2>&1; then
    cat "$WORK_DIR/fmt.txt"
    fail "cargo fmt --all -- --check reported differences"
fi
printf 'formatting             : PASS\n'

# ---------------------------------------------------------------------------
# 6. THE TESTS. Steps 1-5 prove the tree compiles and lints on Linux, which is
#    necessary and not sufficient: they say nothing about Linux behaviour, and
#    for two months "Linux verified" meant exactly that much while the runner's
#    library suite had never once been green.
#
#    This step runs that suite under ONE pinned invocation and compares the
#    exact set of failing test NAMES against scripts/linux-test-policy.json.
#    Drift fails in both directions: an unlisted failure fails the gate, and a
#    listed test that starts passing fails it too, so the accepted list can
#    only shrink deliberately. The executed count is floored and the ignored
#    count is capped, so deleting a test or hiding one behind #[ignore] fails
#    instead of quietly shrinking what "the suite" means.
#
#    Everything that decides the outcome is pinned here rather than inherited:
#    the container flags below, the cgroup namespace, a guaranteed-empty tmpfs
#    /tmp (a persistent one carries leftover state that fails a different test
#    set), and the harness thread count, which comes from the policy file.
# ---------------------------------------------------------------------------

# Separate from `run_in_container` on purpose. Steps 1-5 must keep running
# exactly as they did; only the suite needs the cgroup namespace pinned, and a
# compile does not care about it either way.
run_suite_in_container() {
    if [ "$MODE" = "native" ]; then
        ( cd "$REPO_ROOT" && CARGO_TERM_COLOR=never CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 RUSTFLAGS="$LINUX_MEMORY_RUSTFLAGS" "$@" )
        return
    fi
    docker run --rm --network none --cgroupns=private \
        --mount "$SOURCE_MOUNT" -w /work \
        -v "$TARGET_VOLUME":/target \
        -v "$REGISTRY_VOLUME":/usr/local/cargo/registry:ro \
        --tmpfs /tmp:exec \
        -e CARGO_TARGET_DIR=/target \
        -e CARGO_TERM_COLOR=never \
        -e CARGO_NET_OFFLINE=true \
        -e RUSTUP_AUTO_INSTALL=0 \
        -e LANG=C.UTF-8 \
        -e CARGO_BUILD_JOBS=1 \
        -e RUSTFLAGS="$LINUX_MEMORY_RUSTFLAGS" \
        -e CARGO_INCREMENTAL=0 \
        "$IMAGE" "$@"
}

TEST_POLICY="$REPO_ROOT/scripts/linux-test-policy.json"
[ -f "$TEST_POLICY" ] || fail "test policy file is missing: $TEST_POLICY"

TEST_PACKAGE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["package"])' "$TEST_POLICY")" \
    || fail "could not read package from $TEST_POLICY"
TEST_THREADS="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["test_threads"]))' "$TEST_POLICY")" \
    || fail "could not read test_threads from $TEST_POLICY"
MAX_ATTEMPTS="$(python3 -c '
import json, sys
policy = json.load(open(sys.argv[1]))
print(max([1] + [int(entry["max_attempts"]) for entry in policy.get("remeasure_signatures", [])]))
' "$TEST_POLICY")" || fail "could not read remeasure_signatures from $TEST_POLICY"

step "6/6 Linux test suite: cargo test -p $TEST_PACKAGE --lib --all-features --locked -- --test-threads=$TEST_THREADS"

TEST_ATTEMPT=1
TEST_CHECK=0
while : ; do
    TEST_LOG="$WORK_DIR/test-attempt-$TEST_ATTEMPT.txt"
    printf 'attempt %s of at most %s\n' "$TEST_ATTEMPT" "$MAX_ATTEMPTS"
    # cargo exits non-zero whenever any test fails, and this suite has accepted
    # failures, so its status is deliberately NOT the signal here. What proves
    # the suite ran is the harness's own result line and executed count, both
    # asserted below -- the same discipline step 3 applies to the compile.
    run_suite_in_container cargo test -p "$TEST_PACKAGE" --lib --all-features --locked --offline \
        -- --test-threads="$TEST_THREADS" 2>&1 | tee "$TEST_LOG" || true

    TEST_CHECK=0
    python3 - "$TEST_LOG" "$TEST_POLICY" "$MODE" <<'PY' || TEST_CHECK=$?
import json
import re
import sys

log_path, policy_path, mode = sys.argv[1:]
if mode not in ("container", "native"):
    sys.exit("unknown Linux test environment")

with open(policy_path, encoding="utf-8") as handle:
    policy = json.load(handle)

# The recorded exceptions describe missing tools in the admitted container.
accepted = {
    entry["test"]: entry for entry in policy.get("accepted_failures", [])
} if mode == "container" else {}
signatures = policy.get("remeasure_signatures", [])
min_executed = int(policy.get("min_executed", 0))
max_ignored = int(policy.get("max_ignored", 0))

with open(log_path, encoding="utf-8", errors="replace") as handle:
    text = handle.read()

# A test binary that re-executes itself for an isolated child (this suite has
# one) prints its own summary line with everything else filtered out. Only the
# lines that filtered nothing are this suite's own result.
RESULT = re.compile(
    r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out",
    re.M,
)
passed = failed = ignored = 0
summaries = 0
for match in RESULT.finditer(text):
    counts = [int(value) for value in match.groups()]
    if counts[4] != 0:
        continue
    summaries += 1
    passed += counts[0]
    failed += counts[1]
    ignored += counts[2]

# `failures:` blocks list the failing test names, one per indented line. The
# rendered panic for each also appears above under `---- <name> stdout ----`,
# which is where a signature is looked for.
observed = set()
in_block = False
for line in text.splitlines():
    if line.strip() == "failures:":
        in_block = True
        continue
    if not in_block:
        continue
    if line.startswith("    ") and "::" in line and line.strip():
        observed.add(line.strip())
    elif line.strip():
        in_block = False

blocks = {}
current = None
for line in text.splitlines():
    header = re.match(r"^---- (\S+) stdout ----$", line)
    if header:
        current = header.group(1)
        blocks[current] = []
        continue
    if current is not None:
        if line.startswith("----") or line.strip() == "failures:":
            current = None
        else:
            blocks[current].append(line)

executed = passed + failed
print(f"test environment       : {mode}")
print(f"harness summaries      : {summaries}")
print(f"executed               : {executed} ({passed} passed, {failed} failed)")
print(f"ignored                : {ignored}")
print(f"failing tests          : {len(observed)}")

problems = []
if summaries == 0:
    problems.append(
        "no unfiltered `test result:` line -- the suite did not run. A gate that "
        "cannot tell 'green' from 'never executed' is the defect this step exists to end."
    )
if executed < min_executed:
    problems.append(
        f"{executed} tests executed; policy floors this at {min_executed}. "
        "Tests were removed, filtered, or failed to build."
    )
if ignored > max_ignored:
    problems.append(
        f"{ignored} ignored test(s); policy caps this at {max_ignored}. "
        "Hiding a test behind #[ignore] is not an accepted failure."
    )
if failed != len(observed):
    problems.append(
        f"the harness reported {failed} failure(s) but named {len(observed)}; "
        "the log is truncated or malformed and cannot be evaluated"
    )

missing = sorted(set(accepted) - observed)
unexpected = sorted(observed - set(accepted))

for name in missing:
    problems.append(
        f"ACCEPTED FAILURE NOW PASSES: {name}. Remove it from "
        "scripts/linux-test-policy.json in the commit that fixed it -- this list "
        "may only shrink deliberately."
    )

remeasure = []
if unexpected and not problems:
    for name in unexpected:
        body = "\n".join(blocks.get(name, []))
        hit = next(
            (entry for entry in signatures if entry["signature"] in body),
            None,
        )
        if hit is None:
            break
        remeasure.append((name, hit["signature"]))
    else:
        for name, signature in remeasure:
            print(f"\nspoiled measurement    : {name}")
            print(f"  matched signature    : {signature}")
        sys.exit(2)

for name in unexpected:
    problems.append(f"NEW FAILURE: {name}")
    body = "\n".join(blocks.get(name, [])).strip()
    if body:
        for line in body.splitlines()[:6]:
            problems.append(f"    {line}")

if problems:
    print("\nTEST POLICY FAILED:")
    for problem in problems:
        print(f"  - {problem}")
    sys.exit(1)

print(f"accepted failures      : {len(accepted)} of {len(accepted)}, exactly as listed")
for name in sorted(accepted):
    print(f"  {name}")
print("test policy            : PASS")
PY

    if [ "$TEST_CHECK" -eq 0 ]; then
        break
    fi
    if [ "$TEST_CHECK" -eq 2 ] && [ "$TEST_ATTEMPT" -lt "$MAX_ATTEMPTS" ]; then
        printf 'the measurement was spoiled by a listed environmental signature; re-measuring\n'
        TEST_ATTEMPT=$((TEST_ATTEMPT + 1))
        continue
    fi
    if [ "$TEST_CHECK" -eq 2 ]; then
        fail "every one of $MAX_ATTEMPTS attempts was spoiled by a listed environmental signature; this is now a result, not a spoiled measurement"
    fi
    printf '\n--- test log (tail) ---\n'
    tail -n 40 "$TEST_LOG" || true
    fail "the Linux test suite did not match scripts/linux-test-policy.json (see above)"
done

GATE_COMPLETED=1
printf '\n%s: PASS\n' "$GATE_NAME"
printf 'Verified on Linux (%s %s, kernel %s, %s):\n' \
    "$IDENT_OS" "$IDENT_ARCH" "$IDENT_KERNEL" "$IDENT_RUSTC"
printf '  workspace compiled with --all-targets and linked %s of %s declared binaries\n' \
    "$EXPECTED_BIN_COUNT" "$EXPECTED_BIN_COUNT"
printf '  clippy --workspace --all-targets --all-features --locked met scripts/linux-clippy-policy.json\n'
printf '  rustfmt clean\n'
printf '  %s --lib ran under --test-threads=%s and matched scripts/linux-test-policy.json exactly (attempt %s of %s)\n' \
    "$TEST_PACKAGE" "$TEST_THREADS" "$TEST_ATTEMPT" "$MAX_ATTEMPTS"
exit 0
