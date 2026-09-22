#!/usr/bin/env python3
"""Reproduce the immutable upstream inventory without executing upstream code."""

import argparse
import hashlib
import json
import pathlib
import urllib.request

BASELINE = "59d2a6610a3c876051107159ced2b99adf59c772"
UPSTREAM = "37949780c144e37df692e3d669051a21fec24f20"
PREVIOUS = "9fabadea800fa6e2ed8ec91c4f45f02b7e2504f4"
SOURCE_REV = "c4ea71cfdbcdb21e32e41bc25a0043d7d4836714"


def git_tree(revision):
    url = f"https://api.github.com/repos/xai-org/grok-build/git/trees/{revision}?recursive=1"
    request = urllib.request.Request(url, headers={"User-Agent": "GBPlus-upstream-inventory"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    if data.get("truncated"):
        raise ValueError("GitHub returned a truncated inventory")
    return {row["path"]: row for row in data["tree"] if row["type"] == "blob"}


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink in reference: {path}")
        if not path.is_file():
            continue
        contents = path.read_bytes()
        result[path.relative_to(root).as_posix()] = {
            "bytes": len(contents),
            "sha256": hashlib.sha256(contents).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest(),
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = args.reference.resolve(strict=True)
    if (root / "SOURCE_REV").read_text().strip() != SOURCE_REV:
        raise ValueError("reference SOURCE_REV differs from the admitted reference")
    files = inventory(root)
    expected = git_tree(UPSTREAM)
    if files.keys() != expected.keys():
        raise ValueError("reference path inventory differs from the public sync")
    for path, record in files.items():
        if record["git_blob"] != expected[path]["sha"]:
            raise ValueError(f"reference content differs from the public sync: {path}")
    previous = git_tree(PREVIOUS)
    changes = []
    for path in sorted(previous.keys() | expected.keys()):
        before, after = previous.get(path), expected.get(path)
        if before and after and before["sha"] == after["sha"]:
            continue
        changes.append({"path": path, "change": "added" if not before else "removed" if not after else "modified"})
    result = {"format": 1, "app_baseline": BASELINE, "upstream_sync": UPSTREAM,
              "source_rev": SOURCE_REV, "source_version": "1.0.24", "runtime_target": "1.0.25",
              "previous_sync": PREVIOUS, "file_count": len(files),
              "changed_paths_before_rename_pairing": len(changes), "files": files, "changes": changes}
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded)
    print(f"Verified {len(files)} files; {len(changes)} changed paths before rename pairing")
    print(f"manifest_sha256={hashlib.sha256(encoded).hexdigest()}")


if __name__ == "__main__":
    main()
