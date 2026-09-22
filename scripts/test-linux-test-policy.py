"""Exercise the Linux gate's embedded result checker with bounded fixture logs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "scripts/linux-test-policy.json"
RECORD = json.loads(POLICY.read_text())
MARKER = '    python3 - "$TEST_LOG" "$TEST_POLICY" "$MODE" <<\'PY\' || TEST_CHECK=$?\n'
SCRIPT = (ROOT / "scripts/linux-verify.sh").read_text()
assert SCRIPT.count(MARKER) == 1
CHECKER = SCRIPT.split(MARKER, 1)[1].split("\nPY\n", 1)[0]
ACCEPTED = [entry["test"] for entry in RECORD["accepted_failures"]]


class LinuxTestPolicyTests(unittest.TestCase):
    def check_log(self, mode, failures=(), *, executed=None, ignored=0, body=""):
        executed = RECORD["min_executed"] if executed is None else executed
        log = body + "\nfailures:\n"
        log += "".join(f"    {name}\n" for name in failures)
        log += (
            f"\ntest result: {'FAILED' if failures else 'ok'}. "
            f"{executed - len(failures)} passed; {len(failures)} failed; "
            f"{ignored} ignored; 0 measured; 0 filtered out\n"
        )
        return self.run_checker(mode, log)

    def run_checker(self, mode, log):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.log"
            path.write_text(log)
            return subprocess.run(
                [sys.executable, "-", str(path), str(POLICY), mode],
                input=CHECKER, text=True, capture_output=True, timeout=10,
            )

    def test_native_accepts_complete_success(self):
        self.assertEqual(self.check_log("native").returncode, 0)

    def test_native_refuses_every_container_exception(self):
        for name in ACCEPTED:
            with self.subTest(name=name):
                result = self.check_log("native", [name])
                self.assertEqual(result.returncode, 1)
                self.assertIn("NEW FAILURE: " + name, result.stdout)

    def test_container_requires_its_exact_recorded_failure_set(self):
        self.assertEqual(self.check_log("container", ACCEPTED).returncode, 0)
        self.assertEqual(self.check_log("container", ACCEPTED[:-1]).returncode, 1)
        self.assertEqual(
            self.check_log("container", ACCEPTED + ["fixture::unexpected"]).returncode, 1,
        )

    def test_incomplete_or_weakened_measurements_refuse(self):
        for mode, failures in [("native", []), ("container", ACCEPTED)]:
            with self.subTest(mode=mode):
                self.assertEqual(self.run_checker(mode, "compile failed\n").returncode, 1)
                self.assertEqual(self.check_log(mode, failures, executed=10).returncode, 1)
                self.assertEqual(self.check_log(mode, failures, ignored=2).returncode, 1)

    def test_known_clock_failure_requests_remeasurement_without_passing(self):
        name = "fixture::clock_regression"
        body = f"---- {name} stdout ----\n{RECORD['remeasure_signatures'][0]['signature']}\n"
        for mode, failures in [("native", []), ("container", ACCEPTED)]:
            with self.subTest(mode=mode):
                self.assertEqual(self.check_log(mode, failures + [name], body=body).returncode, 2)

    def test_unknown_environment_refuses(self):
        self.assertNotEqual(self.check_log("unknown").returncode, 0)


class ClippyOutputTests(unittest.TestCase):
    def test_new_warning_refuses_and_retains_its_source_location(self):
        marker = 'python3 - "$WORK_DIR/clippy.json" "$POLICY" "$CLIPPY_STATUS" <<\'PY\' || CLIPPY_CHECK=$?\n'
        self.assertEqual(SCRIPT.count(marker), 1)
        checker = SCRIPT.split(marker, 1)[1].split("\nPY\n", 1)[0]
        location = "crates/fixture.rs:42:5"
        records = [
            {"reason": "compiler-artifact", "target": {"name": "fixture", "kind": ["lib"]}},
            {"reason": "compiler-message", "message": {
                "level": "warning", "code": {"code": "clippy::uninlined_format_args"},
                "message": "inline the format argument", "rendered": location + ": inline argument",
                "spans": [{"is_primary": True, "file_name": "crates/fixture.rs", "line_start": 42, "column_start": 5}],
            }},
        ]
        with tempfile.TemporaryDirectory() as directory:
            stream = Path(directory) / "clippy.json"
            stream.write_text("\n".join(json.dumps(record) for record in records))
            result = subprocess.run(
                [sys.executable, "-", str(stream), str(ROOT / "scripts/linux-clippy-policy.json"), "0"],
                input=checker, text=True, capture_output=True, timeout=10,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("CLIPPY POLICY FAILED", result.stdout)
        self.assertIn(location, result.stdout)
        self.assertNotIn("clippy policy          : PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
