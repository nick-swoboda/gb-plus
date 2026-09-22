#!/usr/bin/env python3
"""Regression checks for CI package integrity and host preflight."""

import hashlib
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "prerequisites", Path(__file__).with_name("ci-linux-prerequisites.py")
)
PREREQUISITES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREREQUISITES)


class PrerequisiteTests(unittest.TestCase):
    def test_corrupt_or_unbounded_archives_are_refused(self):
        package = {"Package": "fixture", "Size": "3",
                   "SHA256": hashlib.sha256(b"abc").hexdigest()}
        PREREQUISITES.verify_archive(b"abc", package)
        for data in (b"abd", b"ab", b"abcd"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                PREREQUISITES.verify_archive(data, package)

    def test_foreign_host_does_not_query_packages(self):
        with patch.object(PREREQUISITES.platform, "system", return_value="Darwin"), \
             patch.object(PREREQUISITES.subprocess, "check_output") as query:
            with self.assertRaisesRegex(ValueError, "Ubuntu"):
                PREREQUISITES.check_host({})
            query.assert_not_called()

    def test_runtime_drift_is_refused_before_package_download(self):
        manifest = {"installed_dependencies": {"fixture": "1.0"}, "packages": {}}
        with patch.object(PREREQUISITES.platform, "system", return_value="Linux"), \
             patch.object(PREREQUISITES.platform, "machine", return_value="x86_64"), \
             patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="24.04"'), \
             patch.object(PREREQUISITES.subprocess, "check_output", return_value="ii \t1.1"):
            with self.assertRaisesRegex(ValueError, "dependency drift"):
                PREREQUISITES.check_host(manifest)


if __name__ == "__main__":
    unittest.main()
