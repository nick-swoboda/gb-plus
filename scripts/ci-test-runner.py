#!/usr/bin/env python3
"""Launch CI test executables without inherited build-control handles."""
import os
from pathlib import Path
import subprocess
import sys


def main(argv):
    if not argv:
        raise SystemExit("A test executable is required.")
    environment = dict(os.environ)
    for name in ("CARGO_MAKEFLAGS", "MAKEFLAGS"):
        environment.pop(name, None)
    if Path(argv[0]).name.startswith(("grok_build_runner-", "grok_build_tauri-")):
        environment["RUST_TEST_THREADS"] = "1"
    result = subprocess.run(argv, env=environment, close_fds=True, check=False)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
