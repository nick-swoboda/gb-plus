import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("payload", Path(__file__).with_name("audit-release-payload.py"))
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


class PayloadTests(unittest.TestCase):
    def test_build_paths_test_records_and_credentials_refuse(self):
        for data in (b"/Users/release-tester/build/main.rs", b"/Volumes/Private Disk/project/lib.rs",
                     b"worktree-proof.txt", b"xai-" + b"A" * 64,
                     b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 64):
            with self.subTest(data=data[:12]):
                audit = payload.Audit()
                audit.check("fixture", data)
                self.assertTrue(audit.failures)

    def test_public_placeholders_and_redaction_patterns_are_not_credentials(self):
        audit = payload.Audit()
        audit.check("fixture", b"/Users/you/Projects/example\x00-----BEGIN PRIVATE KEY-----\x00")
        self.assertFalse(audit.failures)

    def test_nested_archive_is_inspected_and_traversal_refuses(self):
        for name in ("notes.txt", "../notes.txt"):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                info = tarfile.TarInfo(name)
                content = b"/Users/release-tester/private"
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            audit = payload.Audit()
            if name.startswith(".."):
                with self.assertRaisesRegex(ValueError, "unsafe archive"):
                    audit.check("fixture.tar.gz", data.getvalue())
            else:
                audit.check("fixture.tar.gz", data.getvalue())
                self.assertTrue(any("!notes.txt" in failure["file"] for failure in audit.failures))

    def test_archive_expansion_is_bounded(self):
        audit = payload.Audit()
        with patch.object(payload, "MAX_EXPANDED", 4):
            with self.assertRaisesRegex(ValueError, "limit exceeded"):
                audit.check("fixture", b"12345")

    def test_inventory_and_zip_are_verified_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "GB Plus.app"
            relative = "Contents/MacOS/grok-build-tauri"
            executable = app / relative
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"public app fixture")
            archive = root / "app.zip"
            with patch.object(payload, "expected_files", return_value={relative}):
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.write(executable, "GB Plus.app/" + relative)
                self.assertTrue(payload.audit_app(app, archive)["passed"])
                extra = app / "auth.json"
                extra.write_text("test-only sentinel")
                self.assertFalse(payload.audit_app(app)["passed"])
                extra.unlink()
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.write(executable, relative)
                with self.assertRaisesRegex(ValueError, "unexpected"):
                    payload.audit_app(app, archive)
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr("GB Plus.app/" + relative, b"changed")
                with self.assertRaisesRegex(ValueError, "differ"):
                    payload.audit_app(app, archive)

    def test_empty_directories_and_zip_directory_metadata_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "GB Plus.app"
            relative = "Contents/MacOS/grok-build-tauri"
            executable = app / relative
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"public app fixture")
            archive = root / "app.zip"
            with patch.object(payload, "expected_files", return_value={relative}):
                extra = app / "saved-project"
                extra.mkdir()
                self.assertFalse(payload.audit_app(app)["passed"])
                extra.rmdir()
                with zipfile.ZipFile(archive, "w") as bundle:
                    for name in ("GB Plus.app/", "GB Plus.app/Contents/", "GB Plus.app/Contents/MacOS/"):
                        bundle.writestr(name, b"")
                    bundle.write(executable, "GB Plus.app/" + relative)
                self.assertTrue(payload.audit_app(app, archive)["passed"])
                for name, comment, body in (
                    ("GB Plus.app/saved-project/", b"", b""),
                    ("GB Plus.app/Contents/", b"personal note", b""),
                    ("GB Plus.app/Contents/", b"", b"unexpected directory data"),
                ):
                    with self.subTest(name=name, comment=comment, body=body):
                        with zipfile.ZipFile(archive, "w") as bundle:
                            entry = zipfile.ZipInfo(name)
                            entry.comment = comment
                            bundle.writestr(entry, body)
                            bundle.write(executable, "GB Plus.app/" + relative)
                        with self.assertRaises(ValueError):
                            payload.audit_app(app, archive)


if __name__ == "__main__":
    unittest.main()
