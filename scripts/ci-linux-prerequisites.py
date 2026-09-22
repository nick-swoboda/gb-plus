#!/usr/bin/env python3
"""Download verified Ubuntu CI build inputs; never install packages."""

import argparse
import hashlib
import json
import platform
import subprocess
import urllib.request
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent / "ci/ubuntu-native.json"


def check_host(manifest):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("CI prerequisites require Ubuntu 24.04 on x86_64")
    release = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    if release.get("ID", "").strip('"') != "ubuntu" or release.get(
        "VERSION_ID", ""
    ).strip('"') != "24.04":
        raise ValueError("CI prerequisites require Ubuntu 24.04")
    for name, version in manifest["installed_dependencies"].items():
        installed = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}", name],
            text=True,
        )
        if installed != f"ii \t{version}":
            raise ValueError(f"Review runner dependency drift: {name} requires {version}")
    for name, package in manifest["packages"].items():
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}", name],
            capture_output=True, text=True, check=False,
        )
        if result.returncode == 0 and result.stdout.startswith("ii "):
            if result.stdout != f"ii \t{package['Version']}":
                raise ValueError(f"Refusing to replace an unreviewed version of {name}")


def verify_archive(data, package):
    if len(data) != int(package["Size"]):
        raise ValueError(f"Size mismatch: {package['Package']}")
    if hashlib.sha256(data).hexdigest() != package["SHA256"]:
        raise ValueError(f"Checksum mismatch: {package['Package']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--download-only", action="store_true",
                        help="verify downloads without checking the installation host")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    if not args.download_only:
        check_host(manifest)
    args.destination.mkdir(mode=0o700)
    for package in manifest["packages"].values():
        url = "https://archive.ubuntu.com/ubuntu/" + package["Filename"]
        with urllib.request.urlopen(url, timeout=60) as response:
            if not response.url.startswith("https://archive.ubuntu.com/ubuntu/"):
                raise ValueError("Unexpected package download origin")
            data = response.read(int(package["Size"]) + 1)
        verify_archive(data, package)
        path = args.destination / Path(package["Filename"]).name
        with path.open("xb") as output:
            output.write(data)
        print(f"Verified {package['Package']} {package['Version']}", flush=True)


if __name__ == "__main__":
    main()
