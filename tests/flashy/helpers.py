"""Shared helpers for the flashy demo tests. Node-backed tests skip LOUDLY (stderr + skip reason) if node
or the demo repo (~/FlashyDemo, override with FLASHYDEMO) is missing; they never pass silently."""

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from diligenceos.flashy.spine import DOMAIN_LOG_ENTRY, SpineKey, hash_of

HERE = Path(__file__).parent
DEMO = Path(os.environ.get("FLASHYDEMO", str(Path.home() / "FlashyDemo")))
VECTORS = json.loads((HERE / "fixtures" / "vectors.json").read_text())
NODE = shutil.which("node")


def need_node():
    if NODE is None or not (DEMO / "src" / "invoice.js").exists():
        msg = f"SKIPPED (needs node and the demo repo at {DEMO})"
        print("\n*** " + msg, file=sys.stderr)
        raise unittest.SkipTest(msg)


def node_json(script: str, payload) -> object:
    """Run an ES-module script in the demo repo with `payload` on stdin; parse its stdout as JSON."""
    need_node()
    prelude = f"import {{ pathToFileURL }} from 'node:url'; const D = (p) => import(pathToFileURL({json.dumps(str(DEMO))} + '/' + p).href); const IN = JSON.parse(await new Promise(r => {{ let s=''; process.stdin.on('data', d => s += d); process.stdin.on('end', () => r(s)) }}));\n"
    out = subprocess.run([NODE, "--input-type=module", "-e", prelude + script], input=json.dumps(payload),
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise AssertionError("node failed: " + out.stderr[-800:])
    return json.loads(out.stdout)


class MockChainProc:
    """`node scripts/mock-rpc.js` as a subprocess; first stdout line is the URL."""

    def __init__(self):
        need_node()
        self.proc = subprocess.Popen([NODE, str(DEMO / "scripts" / "mock-rpc.js")], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        self.url = self.proc.stdout.readline().strip()
        assert self.url.startswith("http://127.0.0.1:"), self.url
        self.token = "0x" + "ab" * 20

    def call(self, method, params=()):
        from diligenceos.flashy.seller import RpcClient
        return RpcClient(self.url)(method, list(params))

    def close(self):
        self.proc.terminate()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self.proc.stderr.close()


def make_log(key: SpineKey, items, ts="2026-10-14T09:00:00.000Z"):
    """Build a valid plane-style signed log from [(kind, data)] or [(kind, data, ts)]."""
    entries, prev = [], None
    for i, it in enumerate(items):
        kind, data = it[0], it[1]
        body = {"seq": i, "prev": prev, "ts": it[2] if len(it) > 2 else ts, "kind": kind, "data": data}
        h = hash_of(body)
        entries.append({**body, "hash": h, "sig": key.sign(DOMAIN_LOG_ENTRY, {"hash": h})})
        prev = h
    return entries


def seed(c: str) -> str:
    return (c * 64)[:64]
