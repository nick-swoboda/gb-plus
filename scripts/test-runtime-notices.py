import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("notices", Path(__file__).with_name("verify-runtime-notices.py"))
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class NoticeCoverageTests(unittest.TestCase):
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
