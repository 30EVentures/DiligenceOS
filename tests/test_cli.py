import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_REQUEST = REPO_ROOT / "fixtures" / "golden" / "sample_request.json"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CliTest(unittest.TestCase):
    def test_command_runs_and_prints_a_verdict(self):
        result = subprocess.run(
            [sys.executable, "-m", "diligenceos", str(SAMPLE_REQUEST)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        payload = json.loads(result.stdout)
        self.assertIn("verdict", payload)
        self.assertIn("trust_score", payload)
        self.assertIn("findings", payload)

    def test_too_many_arguments_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "diligenceos", "one", "two"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)


class ServeModeTest(unittest.TestCase):
    def test_no_argument_starts_a_real_http_server(self):
        port = _free_port()
        with tempfile.TemporaryDirectory() as tmpdir:
            # A real subprocess reads real env vars — without this override
            # it would read and write the actual ~/.diligenceos/store.json.
            data_path = str(Path(tmpdir) / "store.json")
            env = {**os.environ, "DILIGENCEOS_PORT": str(port), "DILIGENCEOS_DATA_PATH": data_path}
            proc = subprocess.Popen(
                [sys.executable, "-m", "diligenceos"],
                cwd=REPO_ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                body = None
                last_error = None
                while time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=0.5) as resp:
                            body = resp.read().decode("utf-8")
                            break
                    except (urllib.error.URLError, ConnectionError) as exc:
                        last_error = exc
                        time.sleep(0.1)
                self.assertIsNotNone(body, msg=f"server never came up: {last_error}")
                self.assertIn("DiligenceOS", body)
                self.assertIn('name="registration_id"', body)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    unittest.main()
