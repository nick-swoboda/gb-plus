import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

spec = importlib.util.spec_from_file_location("notices", Path(__file__).with_name("verify-runtime-notices.py"))
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class NoticeCoverageTests(unittest.TestCase):
    def test_packaged_notice_manifests_match_their_files_and_release_pins(self):
        root = Path(__file__).resolve().parent.parent
        script = (root / "scripts/plus-macos-release.sh").read_text()
        for group in ("workflow", "websocket"):
            with self.subTest(group=group):
                folder = root / "vendor" / (group + "-notices")
                sums = folder / "SHA256SUMS"
                pin = re.search(group + r'_notice_directory/SHA256SUMS" "([0-9a-f]{64})"', script)
                self.assertIsNotNone(pin)
                self.assertEqual(pin[1], hashlib.sha256(sums.read_bytes()).hexdigest())
                for line in sums.read_text().splitlines():
                    expected, name = line.split("  ", 1)
                    self.assertEqual(Path(name).name, name)
                    self.assertFalse((folder / name).is_symlink())
                    self.assertEqual(expected, hashlib.sha256((folder / name).read_bytes()).hexdigest())
                manifest = json.loads((folder / "manifest.json").read_text())
                for entry in manifest.get("files", manifest.get("packages", [])):
                    name = entry.get("path", entry.get("file"))
                    self.assertEqual(entry["sha256"], hashlib.sha256((folder / name).read_bytes()).hexdigest())

    def setUp(self):
        self.package = {"name": "library", "version": "1.0.0", "license": "MIT",
                        "packageSha256": "a" * 64, "noticeTexts": [{"sha256": "b" * 64}]}
        self.manifest = {"schemaVersion": 1, "rustToolchain": "rustc fixture",
                         "packages": [self.package]}
        self.graph = {("library", "1.0.0")}
        self.locked = {("library", "1.0.0"): "a" * 64}

    def test_exact_graph_checksum_and_toolchain_pass(self):
        notices.validate(self.manifest, self.graph, self.locked, "rustc fixture")

    def test_added_removed_and_changed_dependency_versions_refuse(self):
        for graph in (set(), self.graph | {("new", "1.0.0")}, {("library", "1.0.1")}):
            with self.subTest(graph=graph), self.assertRaisesRegex(ValueError, "coverage"):
                notices.validate(self.manifest, graph, self.locked, "rustc fixture")

    def test_changed_checksum_and_duplicate_records_refuse(self):
        with self.assertRaisesRegex(ValueError, "checksum"):
            notices.validate(self.manifest, self.graph, {("library", "1.0.0"): "c" * 64}, "rustc fixture")
        self.manifest["packages"].append(copy.deepcopy(self.package))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            notices.validate(self.manifest, self.graph, self.locked, "rustc fixture")

    def test_missing_notice_and_unknown_schema_or_toolchain_refuse(self):
        for field, value in (("license", ""), ("noticeTexts", [])):
            changed = copy.deepcopy(self.manifest)
            changed["packages"][0][field] = value
            with self.assertRaisesRegex(ValueError, "missing"):
                notices.validate(changed, self.graph, self.locked, "rustc fixture")
        with self.assertRaisesRegex(ValueError, "stale"):
            notices.validate(self.manifest, self.graph, self.locked, "rustc newer")
        self.manifest["schemaVersion"] = 2
        with self.assertRaisesRegex(ValueError, "stale"):
            notices.validate(self.manifest, self.graph, self.locked, "rustc fixture")


if __name__ == "__main__":
    unittest.main()
