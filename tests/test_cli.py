import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_REQUEST = REPO_ROOT / "fixtures" / "golden" / "sample_request.json"


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

    def test_missing_argument_exits_nonzero(self):
        result = subprocess.run(
            [sys.executable, "-m", "diligenceos"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
