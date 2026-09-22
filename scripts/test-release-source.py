import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("source", Path(__file__).with_name("release-source.py"))
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class SourceReleaseTests(unittest.TestCase):
    def test_private_paths_identifiers_and_credentials_refuse(self):
        for data in (b"/Users/" + b"private-builder/project", b"/Volumes/" + b"Client Disk/project",
                     b"private-owner@example.test", b"xai-" + b"A" * 64):
            with self.subTest(data=data[:12]), self.assertRaises(ValueError):
                source.Audit(["private-owner@example.test"]).check("fixture", data)

    def test_synthetic_paths_are_retained(self):
        source.Audit().check("fixture", b"/Users/you/Projects /Users/test/work /Users/person/work")

    def test_nested_archive_is_inspected(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            item = tarfile.TarInfo("notes.txt")
            body = b"private-owner@example.test"
            item.size = len(body)
            archive.addfile(item, io.BytesIO(body))
        with self.assertRaises(ValueError):
            source.Audit([body.decode()]).check("source.tar.gz", data.getvalue())

    def test_history_and_links_cannot_enter_source(self):
        for name in (".git/config", "../secret", "/tmp/file", ".cache/chat", "file/../../secret"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.safe_path(name)
        with self.assertRaises(ValueError):
            source.record(b"target", "120000")

    def test_working_notes_refuse_without_excluding_public_docs_or_fixtures(self):
        for name in ("docs/plan.md", "ui-evaluation/RESULTS.md", "GOAL.md",
                     "BUILD_STATUS.md", "full_code_review.md", "AGENTS.md"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                source.safe_path(name)
        for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md",
                     "DCO", "LICENSE", "ATTRIBUTION.md", "vendor/library/NOTICE.md",
                     "crates/grok-build-plus-host/prompts/system.md",
                     "fixtures/project/AGENTS.md", "fixtures/project/docs/report.txt"):
            with self.subTest(name=name):
                self.assertEqual(str(source.safe_path(name)), name)

    def test_archive_provenance_marks_edits_and_rejects_missing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_bytes(b"public source")
            manifest = {"schemaVersion": 1, "revision": "a" * 40, "buildNumber": 10,
                        "files": {"README.md": source.record(b"public source", "100644")}}
            (root / source.MANIFEST).write_text(json.dumps(manifest))
            self.assertEqual(source.source_identity(root),
                             {"revision": "a" * 40, "buildNumber": 10, "dirty": False})
            (root / "extra.rs").write_bytes(b"additional source")
            self.assertTrue(source.source_identity(root)["dirty"])
            (root / "extra.rs").unlink()
            (root / "README.md").write_bytes(b"changed")
            self.assertTrue(source.source_identity(root)["dirty"])
            (root / "README.md").unlink()
            with self.assertRaises(ValueError):
                source.source_identity(root)

    def test_export_reads_only_reviewed_git_blobs_and_normalizes_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / "personal-notes.txt").write_bytes(b"private notes")
            identity = {"revision": "a" * 40, "buildNumber": 12, "dirty": False}
            responses = [b"100644 blob " + b"b" * 40 + b"\tREADME.md\0", b"public source"]
            with patch.object(source, "source_identity", return_value=identity), patch.object(source, "git", side_effect=responses):
                result = source.export(root, root / "source.zip", [])
            self.assertTrue(result["passed"])
            with zipfile.ZipFile(root / "source.zip") as archive:
                self.assertEqual(len(archive.namelist()), 2)
                self.assertTrue(all(entry.date_time == (1980, 1, 1, 0, 0, 0) for entry in archive.infolist()))
                self.assertFalse(any("personal" in name for name in archive.namelist()))

    def test_git_build_number_still_comes_from_revision_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            responses = [str(root.resolve()).encode(), b"", b"a" * 40, b"42\n"]
            with patch.object(source, "git", side_effect=responses) as git:
                self.assertEqual(source.source_identity(root),
                                 {"revision": "a" * 40, "buildNumber": 42, "dirty": False})
            self.assertEqual(git.call_args.args, (root, "rev-list", "--count", "HEAD"))

    def test_exported_build_number_must_be_a_positive_integer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number in (0, -1, True, "10", 1.5):
                manifest = {"schemaVersion": 1, "revision": "a" * 40,
                            "buildNumber": number, "files": {}}
                (root / source.MANIFEST).write_text(json.dumps(manifest))
                with self.subTest(number=number), self.assertRaises(ValueError):
                    source.source_identity(root)


if __name__ == "__main__":
    unittest.main()
