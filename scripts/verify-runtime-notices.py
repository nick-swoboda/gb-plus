#!/usr/bin/env python3
"""Refuse a release whose admitted notices no longer cover its dependency graph."""
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent
SCOPES = (
    ("grok-build-tauri", "aarch64-apple-darwin", ["--features", "custom-protocol"]),
    ("grok-build-keychain-broker", "aarch64-apple-darwin", []),
    ("grok-build-plus-host", "aarch64-unknown-linux-gnu", ["--features", "linux-guest-helper"]),
)


def package_graph():
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked", "--offline"],
        cwd=ROOT, text=True, timeout=120, env={**os.environ, "RUSTUP_AUTO_INSTALL": "0"},
    ))
    members = set(metadata["workspace_members"])
    first_party = {(p["name"], p["version"]) for p in metadata["packages"] if p["id"] in members}
    observed = set()
    for package, target, features in SCOPES:
        output = subprocess.check_output(
            ["cargo", "tree", "-p", package, "--edges", "normal", "--prefix", "none",
             "--target", target, "--locked", "--offline", *features],
            cwd=ROOT, text=True, timeout=120,
            env={**os.environ, "RUSTUP_AUTO_INSTALL": "0"},
        )
        for line in output.splitlines():
            match = re.match(r"^([A-Za-z0-9_-]+) v([^\s()]+)(?: |$)", line)
            if not match:
                raise ValueError("Unrecognized dependency inventory line")
            name, version = match.groups()
            if (name, version) not in first_party:
                observed.add((name, version))
    return observed


def validate(manifest, observed, locked, rust_version):
    if manifest.get("schemaVersion") != 1 or manifest.get("rustToolchain") != rust_version:
        raise ValueError("Runtime notice schema or Rust standard-library notices are stale")
    expected = {}
    for package in manifest["packages"]:
        key = (package["name"], package["version"])
        if key in expected or not package.get("license") or not package.get("noticeTexts"):
            raise ValueError("Duplicate package or missing license notice")
        if key not in locked or package.get("packageSha256") != locked[key]:
            raise ValueError("Runtime notice package checksum differs from Cargo.lock")
        expected[key] = package
    if set(expected) != observed:
        raise ValueError("Runtime notice coverage differs from the release dependency graph")


def main():
    path = ROOT / "vendor/runtime-notices/manifest.json"
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Runtime notice manifest exceeds its limit")
    manifest = json.loads(path.read_text())
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    locked = {(p["name"], p["version"]): p.get("checksum") for p in lock["package"]}
    rust = subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True, timeout=30).strip()
    observed = package_graph()
    validate(manifest, observed, locked, rust)
    print(f"RUNTIME NOTICE COVERAGE PASSED packages={len(observed)}")


if __name__ == "__main__":
    main()
