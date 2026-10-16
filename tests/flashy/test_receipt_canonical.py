"""trust_score is an integer 0..100 in every receipt, so the spine (which refuses floats) can canonicalise a whole
receipt, and the three canonicalisers (receipt.canonical_json, spine.canonical, the JS canon.js) agree on it. The
note that said otherwise was wrong; these tests are why we know."""

import itertools
import json
import unittest

from diligenceos import api
from diligenceos.engine import assemble_verdict
from diligenceos.flashy import spine
from diligenceos.receipt import canonical_json, verify_receipt
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding

from .helpers import need_node, node_json

NAMES = ["Plain Ltd", "José Ramírez", "emoji 😀 Co", "tab\there", "ctl\u0001x", "del\u007f", "ls ps ", 'quote"back\\slash',
         "nul\u0000x", "高橋 商事", "a/b", "é", "퟿"]


def floats_in(v, path=""):
    if isinstance(v, float):
        yield path
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from floats_in(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from floats_in(x, f"{path}[{i}]")


class NoFloatsAnywhere(unittest.TestCase):
    def test_every_possible_score_is_an_int(self):
        categories = ["sanctions", "identity", "track_record", "document_scan"]
        for n in range(len(categories) + 1):
            for flagged in itertools.combinations(categories, n):
                findings = [Finding(c, CheckStatus.FLAG, detail="x") if c in flagged else Finding(c, CheckStatus.PASS) for c in categories]
                score = assemble_verdict(findings).trust_score
                self.assertIs(type(score), int, flagged)
                self.assertTrue(0 <= score <= 100)

    def test_no_endpoint_output_contains_a_float(self):
        store = Store.seeded_from_sample()
        _, _, out = api.handle("POST", "/v1/verdict", json.dumps({"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
                                                                  "transaction": {"amount_minor": 5, "currency": "USD"}}).encode(), store)
        receipt = json.loads(out)
        self.assertEqual(list(floats_in(receipt)), [])
        for method, path, body in (("POST", "/v1/verify", receipt), ("GET", "/v1/log/head", None), ("GET", "/v1/log/entries", None), ("GET", "/v1/capabilities", None)):
            _, _, o = api.handle(method, path, json.dumps(body).encode() if body is not None else b"", store)
            self.assertEqual(list(floats_in(json.loads(o))), [], path)


class AScoreThatIsNotAnIntegerIsRefused(unittest.TestCase):
    def setUp(self):
        _, _, out = api.handle("POST", "/v1/verdict", json.dumps({"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}}).encode(), Store.seeded_from_sample())
        self.receipt = json.loads(out)

    def test_the_verifier_refuses_every_non_int_spelling_of_the_score(self):
        score = self.receipt["trust_score"]
        for bad in (float(score), score + 0.5, str(score), True, None, [score], {"v": score}, float("nan"), float("inf"), 1e2, -0.0):
            check = verify_receipt({**self.receipt, "trust_score": bad})
            self.assertFalse(check.valid, repr(bad))

    def test_the_spine_refuses_a_float_where_the_receipt_verifier_would_too(self):
        for bad in (85.0, 85.5, 1e2, float("nan"), float("inf")):
            with self.assertRaises(spine.CanonError, msg=repr(bad)):
                spine.canonical({"trust_score": bad})
        self.assertEqual(spine.canonical({"trust_score": 85}), '{"trust_score":85}')

    def test_python_canonical_json_would_accept_a_float_which_is_why_the_verifier_must_not(self):
        # receipt.canonical_json does not refuse floats (the spine does); verify_receipt is what keeps them out of receipts.
        self.assertEqual(canonical_json({"x": 85.0}), b'{"x":85.0}')
        self.assertFalse(verify_receipt({**self.receipt, "trust_score": 85.0}).valid)


class ThreeCanonicalisersAgree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        store = Store.seeded_from_sample()
        cls.receipts = []
        for name in NAMES:
            status, _, out = api.handle("POST", "/v1/verdict", json.dumps({"subject": {"name": name, "registration_id": "R"},
                                                                         "transaction": {"amount_minor": 1, "currency": "USD"}}).encode(), store)
            assert status == 200, (name, out)
            cls.receipts.append(json.loads(out))

    def test_python_and_spine_agree_byte_for_byte_on_real_receipts(self):
        for name, r in zip(NAMES, self.receipts):
            self.assertEqual(canonical_json(r).decode("utf-8"), spine.canonical(r), repr(name))

    def test_js_agrees_too(self):
        need_node()
        js = node_json("const {canonical}=await D('src/canon.js'); console.log(JSON.stringify(IN.map(r=>canonical(r))))", self.receipts)
        for name, r, got in zip(NAMES, self.receipts, js):
            self.assertEqual(got, spine.canonical(r), repr(name))


if __name__ == "__main__":
    unittest.main()
