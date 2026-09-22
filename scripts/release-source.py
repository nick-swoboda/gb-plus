#!/usr/bin/env python3
"""Create a history-free source release and recover its build provenance."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile

MANIFEST = "SOURCE-MANIFEST.json"
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
BLOCKED = {".git", ".cache", ".agents", ".codex", "target", "node_modules", "__MACOSX", "__pycache__"}
PRIVATE_ROOTS = {"docs", "ui-evaluation", "GOAL.md", "BUILD_STATUS.md", "full_code_review.md", "AGENTS.md"}
SECRET = re.compile(rb"(?<![\w-])(?:xai-[A-Za-z0-9]{40,}|sk-(?:proj-|ant-api)?[A-Za-z0-9_-]{40,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/=]{32,})")
HOME_PATH = re.compile(rb"/Users/([A-Za-z0-9_.-]+)(?=[/\"\s\x00]|$)")
VOLUME_PATH = re.compile(rb"/Volumes/([A-Za-z0-9_ .-]+)(?=[/\"\x00]|$)")
PUBLIC_HOMES = {b"you", b"test", b"person", b"release-tester", b"_gbdrun1", b"_x"}
MEDIA = {
    "crates/grok-build-tauri/icons/icon.png",
    "crates/grok-build-tauri/icons/icon.svg",
    "crates/grok-build-tauri/macos/GrokBuildPlus.icns",
    "crates/grok-build-tauri/ui/assets/gb-plus.svg",
}


def safe_path(name):
    path = PurePosixPath(name)
    if (not path.parts or path.is_absolute() or ".." in path.parts or "\\" in name
            or path.parts[0] in PRIVATE_ROOTS
            or any(part in BLOCKED or part.startswith("._") for part in path.parts)
            or path.name == ".DS_Store" or str(path) != name):
        raise ValueError("Unsafe source path")
    return path


def record(data, mode):
    if mode not in ("100644", "100755") or len(data) > MAX_FILE:
        raise ValueError("Source must be a bounded regular file")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": mode}


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, timeout=120)


def source_identity(root):
    if (root / ".git").exists():
        top = Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve()
        if top != root.resolve():
            raise ValueError("Build repository root differs")
        dirty = bool(git(root, "status", "--porcelain", "--untracked-files=normal"))
        return {"revision": git(root, "rev-parse", "HEAD").decode().strip(),
                "buildNumber": int(git(root, "rev-list", "--count", "HEAD")), "dirty": dirty}
    manifest_path = root / MANIFEST
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Unsafe source manifest")
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("schemaVersion") != 1 or not re.fullmatch(r"[a-f0-9]{40}", manifest["revision"])
            or type(manifest["buildNumber"]) is not int or manifest["buildNumber"] < 1):
        raise ValueError("Invalid source provenance")
    dirty = False
    for name, expected in manifest["files"].items():
        relative = safe_path(name)
        path = root / relative
        if (name == MANIFEST or path.is_symlink() or not path.is_file()
                or any((root / parent).is_symlink() for parent in relative.parents)):
            raise ValueError("Source manifest file is unavailable")
        mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        dirty |= record(path.read_bytes(), mode) != expected
    for directory, folders, names in os.walk(root):
        folders[:] = [name for name in folders if name not in BLOCKED and name != "dist"]
        dirty |= any((Path(directory) / name).is_symlink() for name in folders)
        for name in names:
            relative = str((Path(directory) / name).relative_to(root))
            dirty |= relative != MANIFEST and relative not in manifest["files"]
    return {"revision": manifest["revision"], "buildNumber": manifest["buildNumber"], "dirty": dirty}


class Audit:
    def __init__(self, tokens=()):
        self.tokens = [token.lower().encode() for token in tokens if len(token) >= 4]
        self.entries = 0
        self.expanded = 0

    def check(self, name, data, depth=0):
        self.entries += 1
        self.expanded += len(data)
        if len(data) > MAX_FILE or self.expanded > MAX_TOTAL or self.entries > 10000 or depth > 4:
            raise ValueError("Source audit expansion limit exceeded")
        lower = data.lower() + b"\n" + name.lower().encode()
        if any(token in lower for token in self.tokens) or SECRET.search(data) or SECRET.search(name.encode()):
            raise ValueError(f"Private identifier or credential pattern in {name}")
        if any(value not in PUBLIC_HOMES for value in HOME_PATH.findall(data)):
            raise ValueError(f"Private home path in {name}")
        volumes = VOLUME_PATH.findall(data)
        if volumes and not (name == "scripts/test-release-payload.py" and set(volumes) == {b"Private Disk"}):
            raise ValueError(f"Private volume path in {name}")
        if name.endswith((".tar.gz", ".tar.xz", ".crate")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for member in archive:
                    path = PurePosixPath(member.name)
                    if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                        raise ValueError("Unsafe nested source archive")
                    if member.isfile():
                        if member.size > MAX_FILE:
                            raise ValueError("Oversized nested source file")
                        self.check(name + "!" + str(path), archive.extractfile(member).read(MAX_FILE + 1), depth + 1)


def export(root, output, tokens):
    if not (root / ".git").exists():
        raise ValueError("Export requires the reviewed Git repository root")
    identity = source_identity(root)
    if identity["dirty"]:
        raise ValueError("Commit the reviewed source before exporting")
    if output.exists():
        raise ValueError("Source archive already exists")
    audit = Audit(tokens)
    files = {}
    payloads = {}
    for line in git(root, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not line:
            continue
        metadata, raw_name = line.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        name = os.fsdecode(raw_name)
        path = safe_path(name)
        if kind != "blob" or name == MANIFEST:
            raise ValueError("Unexpected source object")
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".pdf", ".svg", ".icns", ".ico", ".mov", ".mp4", ".wav", ".mp3", ".zip"} and name not in MEDIA:
            raise ValueError(f"Unreviewed media or archive: {name}")
        if path.suffix in {".db", ".sqlite", ".sqlite3"} and name != "fixtures/ledger-schema/schema-v37-migrated-ledger.db":
            raise ValueError("Runtime database in source")
        data = git(root, "cat-file", "blob", oid)
        files[name] = record(data, mode)
        audit.check(name, data)
        payloads[name] = data
    manifest = {"schemaVersion": 1, **identity, "historyIncluded": False, "files": files}
    payloads[MANIFEST] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payloads.items()):
            entry = zipfile.ZipInfo("gb-plus-0.2.1-plus/" + name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (0o100755 if files.get(name, {}).get("mode") == "100755" else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compresslevel=9)
    with zipfile.ZipFile(output) as archive:
        if archive.comment or len(archive.infolist()) != len(payloads):
            raise ValueError("Source ZIP inventory differs")
        for entry in archive.infolist():
            name = entry.filename.removeprefix("gb-plus-0.2.1-plus/")
            if entry.extra or entry.comment or archive.read(entry) != payloads[name]:
                raise ValueError("Source ZIP readback differs")
    return {"schemaVersion": 1, **identity, "passed": True, "sourceFiles": len(files),
            "sourceBytes": sum(item["bytes"] for item in files.values()),
            "inspectedEntries": audit.entries, "expandedBytes": audit.expanded,
            "historyIncluded": False, "personalDenyTokensChecked": len(audit.tokens),
            "archive": output.name, "bytes": output.stat().st_size,
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "findings": []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("identity", "export"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--deny-tokens-file", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.command == "identity":
        result = source_identity(args.root)
        print(result["revision"], result["buildNumber"], str(result["dirty"]).lower())
        return
    if not args.output:
        parser.error("export requires --output")
    tokens = [str(Path.home())]
    if args.deny_tokens_file:
        tokens.extend(json.loads(args.deny_tokens_file.read_text()))
    result = export(args.root, args.output, tokens)
    if args.report:
        args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
