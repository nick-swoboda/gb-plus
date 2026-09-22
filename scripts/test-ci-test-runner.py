import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


RUNNER = Path(__file__).with_name("ci-test-runner.py").resolve()


class TestRunnerTests(unittest.TestCase):
    def test_process_global_harnesses_default_to_serial(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, expected in [("grok_build_runner-0123456789abcdef", "1"),
                                   ("grok_build_tauri-0123456789abcdef", "1"),
                                   ("grok_build_plus_host-0123456789abcdef", "8"),
                                   ("grok-build-runner", "8")]:
                with self.subTest(executable=name):
                    executable = Path(directory) / name
                    executable.write_text('#!/bin/sh\nprintf "%s" "$RUST_TEST_THREADS"\n')
                    executable.chmod(0o700)
                    result = subprocess.run(
                        [sys.executable, str(RUNNER), str(executable)],
                        env={**os.environ, "RUST_TEST_THREADS": "8"},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, expected)

    def test_ambient_handles_and_jobserver_metadata_do_not_reach_tests(self):
        with tempfile.TemporaryFile() as file:
            handles = []
            try:
                for _ in range(2):
                    handle = fcntl.fcntl(file.fileno(), fcntl.F_DUPFD, 128)
                    handles.append(handle)
                environment = {**os.environ, "CARGO_MAKEFLAGS": "--jobserver-auth=128,129",
                               "MAKEFLAGS": "--jobserver-auth=128,129"}
                probe = """import os, sys
for value in sys.argv[1:]:
    try:
        os.fstat(int(value))
    except OSError:
        continue
    raise SystemExit(9)
assert 'CARGO_MAKEFLAGS' not in os.environ
assert 'MAKEFLAGS' not in os.environ
"""
                args = [sys.executable, "-c", probe, *map(str, handles)]
                control = subprocess.run(args, env=environment, pass_fds=handles, check=False)
                self.assertEqual(control.returncode, 9)
                result = subprocess.run([sys.executable, str(RUNNER), *args],
                                        env=environment, pass_fds=handles, check=False)
                self.assertEqual(result.returncode, 0)
            finally:
                for handle in handles:
                    os.close(handle)

    def test_arguments_stdio_directory_and_exit_status_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            probe = """import json, os, sys
print(json.dumps({'arguments':sys.argv[1:], 'input':sys.stdin.read(),
                  'directory':os.getcwd(), 'environment':os.environ['GB_PLUS_CI_TEST']}))
print('diagnostic', file=sys.stderr)
raise SystemExit(7)
"""
            result = subprocess.run(
                [sys.executable, str(RUNNER), sys.executable, "-c", probe,
                 "value with spaces", "--literal"], cwd=directory,
                env={**os.environ, "GB_PLUS_CI_TEST": "preserved"},
                input="fixture input", text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stderr, "diagnostic\n")
            self.assertEqual(json.loads(result.stdout), {
                "arguments": ["value with spaces", "--literal"], "input": "fixture input",
                "directory": str(Path(directory).resolve()), "environment": "preserved",
            })


if __name__ == "__main__":
    unittest.main()
