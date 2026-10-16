import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parents[2] / 'diligenceos' / 'flashy'
sys.path.insert(0, str(HERE))
import mesh_reporter as m  # noqa: E402

TOKEN = "agt_test_0123456789abcdef"
ENV = {"FLASHYOS_ORG_ID": "org_abc123", "FLASHYOS_AGENT_TOKEN": TOKEN, "FLASHYOS_AGENT_NAME": "demo-agent"}


class Opener:
    def __init__(self, exc=None):
        self.exc, self.calls = exc, 0

    def open(self, req, timeout=None):
        self.calls += 1
        raise self.exc


class Reporter(unittest.TestCase):
    def test_unconfigured_sends_nothing_and_says_why(self):
        for env in ({}, {"FLASHYOS_ORG_ID": "org_abc123"}, {**ENV, "FLASHYOS_AGENT_NAME": ""}, {**ENV, "FLASHYOS_AGENT_TOKEN": ""}):
            o = Opener(RuntimeError("must not be called"))
            self.assertEqual(m.heartbeat("IDLE", env=env, opener=o), {"sent": False, "reason": "NOT_CONFIGURED"})
            self.assertEqual(o.calls, 0)

    def test_config_refuses_unsafe_or_odd_values(self):
        cases = [("FLASHYOS_API_URL", "http://api.flashyos.com", "API_URL_NOT_HTTPS"), ("FLASHYOS_API_URL", "http://localhost:1", "API_URL_NOT_HTTPS"),
                 ("FLASHYOS_API_URL", "https://u:p@api.flashyos.com", "BAD_API_URL"), ("FLASHYOS_API_URL", "https://api.flashyos.com/?x=1", "BAD_API_URL"),
                 ("FLASHYOS_API_URL", "https://api.flashyos.com/evil", "BAD_API_URL"), ("FLASHYOS_API_URL", "nonsense", "BAD_API_URL"),
                 ("FLASHYOS_API_URL", "file:///etc/passwd", "BAD_API_URL"), ("FLASHYOS_ORG_ID", "a b", "BAD_ORG_ID"),
                 ("FLASHYOS_AGENT_NAME", "Has Caps", "BAD_AGENT_NAME"), ("FLASHYOS_AGENT_TOKEN", "short", "BAD_TOKEN_SHAPE"),
                 ("FLASHYOS_AGENT_TOKEN", "has space in it ok?", "BAD_TOKEN_SHAPE")]
        for k, v, why in cases:
            with self.subTest(k=k, v=v):
                self.assertEqual(m.read_config({**ENV, k: v})["reason"], why)
        self.assertTrue(m.read_config(ENV)["configured"])

    def test_bad_status_and_progress_never_reach_the_network(self):
        o = Opener(RuntimeError("must not be called"))
        for s in ("idle", "LIVE", "", None, "DROP TABLE"):
            self.assertEqual(m.heartbeat(s, env=ENV, opener=o)["reason"], "BAD_STATUS")
        for p in (-1, 101, 1.5, "5", True):
            self.assertEqual(m.heartbeat("IDLE", "", p, env=ENV, opener=o)["reason"], "BAD_PROGRESS")
        self.assertEqual(o.calls, 0)

    def test_failures_never_raise_and_never_leak_the_token(self):
        import urllib.error
        outs = [m.heartbeat("IDLE", env=ENV, opener=Opener(RuntimeError("boom " + TOKEN))),
                m.heartbeat("IDLE", env=ENV, opener=Opener(urllib.error.HTTPError("u", 401, "x", {}, None))),
                m.heartbeat("IDLE", env=ENV, opener=Opener(urllib.error.HTTPError("u", 503, "x", {}, None)))]
        self.assertEqual([o["reason"] for o in outs], ["NETWORK_ERROR", "HTTP_401", "HTTP_503"])
        for o in outs:
            self.assertNotIn(TOKEN, json.dumps(o))

    def test_describe_redacts_and_cleans(self):
        d = m.describe_heartbeat(m.read_config(ENV), "ACTIVE", "a\n\x00b" + "x" * 300, 5)
        self.assertNotIn(TOKEN, json.dumps(d))
        self.assertLessEqual(len(d["body"]["currentTask"]), 120)
        self.assertNotIn("\n", d["body"]["currentTask"])
        self.assertEqual(d["url"], "https://api.flashyos.com/api/v1/agents/heartbeat")


class Wire(unittest.TestCase):
    def setUp(self):
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.seen.append({"path": self.path, "ct": self.headers.get("Content-Type"), "body": json.loads(self.rfile.read(n))})
                self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.env = {**ENV, "FLASHYOS_API_URL": f"http://127.0.0.1:{self.srv.server_port}"}

    def tearDown(self):
        self.srv.shutdown()

    def test_exact_request_shape(self):
        out = m.heartbeat("TESTING", "running checks", 40, env=self.env)
        self.assertEqual((out["sent"], out["httpStatus"]), (True, 200))
        self.assertEqual(self.seen[0], {"path": "/api/v1/agents/heartbeat", "ct": "application/json",
                                        "body": {"orgId": "org_abc123", "token": TOKEN, "agentName": "demo-agent", "status": "TESTING", "currentTask": "running checks", "progress": 40}})

    def test_a_redirect_is_never_followed(self):
        landed = []

        class T(BaseHTTPRequestHandler):
            def do_POST(self):
                landed.append(1); self.send_response(200); self.end_headers()

            do_GET = do_POST

            def log_message(self, *a):
                pass
        tgt = HTTPServer(("127.0.0.1", 0), T)
        threading.Thread(target=tgt.serve_forever, daemon=True).start()

        class Hop(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{tgt.server_port}/steal"); self.end_headers()

            def log_message(self, *a):
                pass
        hop = HTTPServer(("127.0.0.1", 0), Hop)
        threading.Thread(target=hop.serve_forever, daemon=True).start()
        try:
            out = m.heartbeat("IDLE", env={**ENV, "FLASHYOS_API_URL": f"http://127.0.0.1:{hop.server_port}"})
            self.assertFalse(out["sent"]); self.assertEqual(landed, [])
        finally:
            hop.shutdown(); tgt.shutdown()

    def test_script_is_a_dry_run_by_default(self):
        run = lambda args, env: subprocess.run([sys.executable, str(HERE / "mesh_reporter.py"), *args], env=env, capture_output=True, text=True)
        env = {**os.environ, **self.env}
        dry = run([], env); self.assertEqual(dry.returncode, 0); self.assertIn("dry run", dry.stdout); self.assertNotIn(TOKEN, dry.stdout + dry.stderr); self.assertEqual(len(self.seen), 0)
        bad = run(["--send", "--every", "3"], env); self.assertEqual(bad.returncode, 2); self.assertEqual(len(self.seen), 0)
        sent = run(["--send"], env); self.assertEqual(sent.returncode, 0); self.assertIn("sent", sent.stdout); self.assertNotIn(TOKEN, sent.stdout + sent.stderr); self.assertEqual(len(self.seen), 1)
        none = run(["--send"], {"PATH": os.environ["PATH"]}); self.assertEqual(none.returncode, 2); self.assertIn("not configured", none.stderr)


if __name__ == "__main__":
    unittest.main()
