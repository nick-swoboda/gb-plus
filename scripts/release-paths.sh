#!/bin/sh
# Source before compiling distribution binaries.
release_path_separator=$(/usr/bin/printf '\037')
release_path_flags="--remap-path-prefix=$repo_root=/gb-plus${release_path_separator}--remap-path-prefix=${HOME:?}=/build-user"
if [ -n "${CARGO_HOME:-}" ]; then
  release_path_flags="$release_path_flags${release_path_separator}--remap-path-prefix=$CARGO_HOME=/cargo"
fi
[ -z "${RUSTFLAGS:-}" ] || { echo "release paths: inherited RUSTFLAGS require review" >&2; exit 1; }
[ -z "${CARGO_ENCODED_RUSTFLAGS:-}" ] || [ "$CARGO_ENCODED_RUSTFLAGS" = "$release_path_flags" ] \
  || { echo "release paths: inherited encoded Rust flags require review" >&2; exit 1; }
CARGO_ENCODED_RUSTFLAGS=$release_path_flags
export CARGO_ENCODED_RUSTFLAGS

release_native_path_flags=$(python3 - "$repo_root" "$HOME" "${CARGO_HOME:-}" <<'PY'
import hashlib, os, shlex, stat, sys
from pathlib import Path
pairs = zip(sys.argv[1:], ("/gb-plus", "/build-user", "/cargo"))
body = (shlex.join("-ffile-prefix-map=" + source + "=" + target for source, target in pairs if source) + "\n").encode()
directory = Path("/private/tmp") / ("gbplus-build-flags-" + hashlib.sha256(body).hexdigest())
directory.mkdir(mode=0o700, exist_ok=True)
info = directory.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
    raise SystemExit("release paths: unsafe response-file directory")
path = directory / "native.rsp"
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except FileExistsError:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or stream.read(len(body) + 1) != body:
            raise SystemExit("release paths: response file differs")
else:
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
print("@" + str(path))
PY
)
for release_native_flags in "${CFLAGS:-}" "${CXXFLAGS:-}"; do
  [ -z "$release_native_flags" ] || [ "$release_native_flags" = "$release_native_path_flags" ] \
    || { echo "release paths: inherited native compiler flags require review" >&2; exit 1; }
done
CFLAGS=$release_native_path_flags
CXXFLAGS=$release_native_path_flags
export CFLAGS CXXFLAGS

prepare_native_release_cache() {
  native_stamp="$repo_root/target/release/.gbplus-native-paths"
  [ ! -L "$native_stamp" ] || { echo "release paths: native cache stamp is a symlink" >&2; exit 1; }
  if [ ! -f "$native_stamp" ] || [ "$(/bin/cat "$native_stamp")" != "$CFLAGS" ]; then
    cargo clean --release -p whisper-rs-sys
    /bin/mkdir -p "$repo_root/target/release"
    /usr/bin/printf '%s\n' "$CFLAGS" > "$native_stamp"
  fi
}
