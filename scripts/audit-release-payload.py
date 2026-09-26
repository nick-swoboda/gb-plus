#!/usr/bin/env python3
"""Audit the distributable without opening user state or credential stores."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import zipfile

REPO = Path(__file__).resolve().parent.parent
MAX_FILE = 160 * 1024 * 1024
MAX_EXPANDED = 300 * 1024 * 1024
PRIVATE_PATH = re.compile(rb"/(?:Users/(?!you/)[^/\s\x00]{1,80}|Volumes/[^/\x00]{1,120})/")
SECRET = re.compile(rb"(?:xai-[A-Za-z0-9]{40,}|sk-(?:proj-)?[A-Za-z0-9_-]{40,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{32,})")
TEST_MARKERS = (b"worktree-proof.txt", b"GB Plus baseline ready", b"I think you\xe2\x80\x99re grok")


def expected_files():
    names = {
        "Contents/Info.plist", "Contents/MacOS/grok-build-tauri",
        "Contents/Helpers/grok-build-keychain-broker",
        "Contents/Helpers/grok-build-mcp-keychain-broker",
        "Contents/_CodeSignature/CodeResources",
    }
    resource = "Contents/Resources/"
    names.update(resource + name for name in (
        "GrokBuildPlus.icns", "LICENSE.txt", "ATTRIBUTION.md", "README.md",
        "GrokBuildReleaseReceipt.json", "GBPlusCommandSecurityLinuxArm64.tar.gz",
        "RuntimeNotices.tar.gz",
    ))
    for directory, vendor in (("WorkflowNotices", "workflow-notices"), ("WebSocketNotices", "websocket-notices")):
        names.add(resource + directory + "/SHA256SUMS")
        for line in (REPO / "vendor" / vendor / "SHA256SUMS").read_text().splitlines():
            _, name = line.split(None, 1)
            names.add(resource + directory + "/" + name)
    for name in ("COPYRIGHT", "bubblewrap_0.9.0-1ubuntu0.1.dsc", "bubblewrap_0.9.0.orig.tar.xz", "bubblewrap_0.9.0.orig.tar.xz.asc", "bubblewrap_0.9.0-1ubuntu0.1.debian.tar.xz"):
        names.add(resource + "BubblewrapSource/" + name)
    return names


class Audit:
    def __init__(self):
        self.expanded = 0
        self.inspected = 0
        self.failures = []
        self.markers = TEST_MARKERS + (Path.home().name.encode(),)

    def check(self, name, data, depth=0):
        self.expanded += len(data)
        self.inspected += 1
        if len(data) > MAX_FILE or self.expanded > MAX_EXPANDED or depth > 4:
            raise ValueError("payload inspection limit exceeded")
        if PRIVATE_PATH.search(data):
            self.failures.append({"file": name, "reason": "private build path"})
        if SECRET.search(data):
            self.failures.append({"file": name, "reason": "credential-shaped material"})
        if any(marker and marker.lower() in data.lower() for marker in self.markers):
            self.failures.append({"file": name, "reason": "personal or recorded test marker"})
        if name.endswith((".tar.gz", ".tar.xz", ".crate")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                members = archive.getmembers()
                if len(members) > 10000:
                    raise ValueError("archive entry limit exceeded")
                for member in members:
                    path = PurePosixPath(member.name)
                    if path.is_absolute() or ".." in path.parts or member.size > MAX_FILE:
                        raise ValueError("unsafe archive entry")
                    if member.isfile():
                        self.check(name + "!" + member.name, archive.extractfile(member).read(), depth + 1)
                if name.endswith("GBPlusCommandSecurityLinuxArm64.tar.gz"):
                    if {m.name for m in members} != {"bwrap", "grok-build-linux-helper", "plus-contained-probe"}:
                        raise ValueError("unexpected Linux runtime payload")
                    if any(not m.isfile() or m.uid or m.gid or m.uname != "root" or m.gname != "root" for m in members):
                        raise ValueError("Linux runtime includes local ownership metadata")


def verify_zip_metadata(archive, entry):
    if entry.extra:
        raise ValueError("ZIP contains extra metadata")
    archive.fp.seek(entry.header_offset)
    header = archive.fp.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ValueError("Invalid ZIP local header")
    if struct.unpack_from("<H", header, 28)[0]:
        raise ValueError("ZIP local header contains extra metadata")


def audit_app(app, archive_path=None):
    expected = expected_files()
    expected_dirs = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != "."}
    audit = Audit()
    files = {}
    directories = set()
    for path in sorted(app.rglob("*")):
        metadata = path.lstat()
        name = path.relative_to(app).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(name)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE:
            raise ValueError("unsupported bundle file type or size")
        data = path.read_bytes()
        files[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        audit.check(name, data)
    if set(files) != expected:
        audit.failures.append({"reason": "bundle inventory differs", "extra": sorted(set(files) - expected), "missing": sorted(expected - set(files))})
    if directories != expected_dirs:
        audit.failures.append({"reason": "bundle directory inventory differs", "extra": sorted(directories - expected_dirs), "missing": sorted(expected_dirs - directories)})
    if archive_path:
        with zipfile.ZipFile(archive_path) as archive:
            if archive.comment:
                raise ValueError("ZIP contains a comment")
            observed = set()
            observed_dirs = set()
            entries = archive.infolist()
            if len(entries) > 10000:
                raise ValueError("ZIP entry limit exceeded")
            for entry in entries:
                if not entry.filename.startswith("GB Plus.app/") or entry.comment:
                    raise ValueError("unexpected ZIP root or entry comment")
                verify_zip_metadata(archive, entry)
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise ValueError("ZIP contains a symlink")
                if entry.is_dir():
                    name = entry.filename.removeprefix("GB Plus.app/").removesuffix("/")
                    if name not in expected_dirs | {""} or name in observed_dirs or entry.file_size:
                        raise ValueError("unexpected or duplicate ZIP directory")
                    observed_dirs.add(name)
                    continue
                name = entry.filename.removeprefix("GB Plus.app/")
                if name not in files or name in observed or entry.file_size > MAX_FILE:
                    raise ValueError("unexpected or duplicate ZIP entry")
                if hashlib.sha256(archive.read(entry)).hexdigest() != files[name]["sha256"]:
                    raise ValueError("ZIP and app contents differ")
                observed.add(name)
            if observed != set(files):
                raise ValueError("ZIP is missing bundle entries")
    assets = {}
    ui = REPO / "crates/grok-build-tauri/ui"
    for path in sorted(ui.rglob("*")):
        if path.is_symlink():
            raise ValueError("frontend asset is a symlink")
        if path.is_dir():
            continue
        if path.suffix not in {".js", ".mjs", ".css", ".html", ".svg", ".woff2"} and not path.name.startswith("LICENSE"):
            raise ValueError("unexpected frontend asset")
        name = path.relative_to(ui).as_posix()
        data = path.read_bytes()
        audit.check("ui/" + name, data)
        assets[name] = hashlib.sha256(data).hexdigest()
    return {"passed": not audit.failures, "bundleFiles": len(files), "bundleDirectories": len(directories), "inspectedEntries": audit.inspected,
            "expandedBytes": audit.expanded, "failures": audit.failures, "files": files,
            "uiAssets": assets,
            "scope": "Allowlisted bundle, archives and frontend sources; known personal/test markers, credential patterns and build paths. User state and credentials were not accessed."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("--zip", dest="archive", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = audit_app(args.app, args.archive)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        result = {"passed": False, "error": str(error)}
    if args.report:
        args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in {"files", "uiAssets"}}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
