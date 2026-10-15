"""One refusal corpus, two implementations. The JS spine and the Python adapter must give every case the same
answer; a known difference is recorded in the corpus as `gap.<impl>` and asserted exactly, so it cannot hide and
cannot silently persist once fixed."""

import json
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from diligenceos.flashy import seller

from .helpers import need_node, node_json

HERE = Path(__file__).parent
CORPUS_PATH = HERE / "fixtures" / "refusal-corpus.json"
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def cases():
    for s in CORPUS["sets"]:
        for c in s["cases"]:
            yield s["name"], c


def py_answer(kind, c):
    if kind == "invoice":
        now = datetime.fromtimestamp(c["now_ms"] / 1000, tz=timezone.utc)
        return {"valid": seller.invoice_refusal(c["invoice"], c["pinned"], now) is None}

    def rpc(method, params):
        if method in c["throws"]:
            raise seller.RpcError("rpc " + method)
        return c["rpc"].get(method)

    o = seller.tx_outcome(rpc, c["chain"], c["txHash"], c["minConfirmations"])
    return {"state": o["state"], "transfers": [{"token": t["token"], "from": t["from"], "to": t["to"], "amount": str(t["amount"])} for t in o["transfers"]]}


def wanted(c, impl):
    return c.get("gap", {}).get(impl, c["expect"])


class Corpus(unittest.TestCase):
    def test_it_is_what_the_builder_makes(self):
        done = subprocess.run([sys.executable, str(HERE / "build_refusal_corpus.py")], capture_output=True, text=True, cwd=HERE.parents[1])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(CORPUS_PATH.read_text(encoding="utf-8"), json.dumps(json.loads(CORPUS_PATH.read_text(encoding="utf-8")), indent=1, ensure_ascii=True) + "\n")
        fresh = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(fresh, CORPUS, "regenerate with tests/flashy/build_refusal_corpus.py and commit the result")

    def test_refusals_dominate_and_ids_are_unique(self):
        every = list(cases())
        ids = [c["id"] for _, c in every]
        self.assertEqual(len(ids), len(set(ids)))
        refusals = [c for kind, c in every if (c["expect"].get("valid") is False if kind == "invoice" else c["expect"]["state"] != "confirmed" or not c["expect"]["transfers"])]
        self.assertGreaterEqual(len(refusals) / len(every), 0.8)

    def test_every_gap_names_one_implementation_and_a_reason(self):
        for _, c in cases():
            if "gap" in c:
                self.assertEqual(len(set(c["gap"]) - {"why"}), 1, c["id"])
                self.assertTrue(set(c["gap"]) - {"why"} <= {"js", "py"}, c["id"])
                self.assertGreater(len(c["gap"]["why"]), 20, c["id"])
                impl = (set(c["gap"]) - {"why"}).pop()
                self.assertNotEqual(c["gap"][impl], c["expect"], f"{c['id']}: a gap equal to the expectation is not a gap")


class PythonAdapter(unittest.TestCase):
    def test_every_case_is_answered_as_required_or_as_the_recorded_gap(self):
        wrong = []
        for kind, c in cases():
            if py_answer(kind, c) != wanted(c, "py"):
                wrong.append((c["id"], py_answer(kind, c), wanted(c, "py")))
        self.assertEqual(wrong, [])


class JsSpine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_node()
        cls.answers = node_json((HERE / "parity_runner.mjs").read_text(encoding="utf-8"), CORPUS)

    def test_every_case_is_answered_as_required_or_as_the_recorded_gap(self):
        wrong = [(c["id"], self.answers.get(c["id"]), wanted(c, "js")) for _, c in cases() if self.answers.get(c["id"]) != wanted(c, "js")]
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
