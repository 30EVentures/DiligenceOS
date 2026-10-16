"""What a stranger runs: one file, one pinned key, one clear answer. No server, no network."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from diligenceos import api, tools
from diligenceos.signing import Signer
from diligenceos.store import Store


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = tools.main(list(argv))
        except SystemExit as stop:
            code = stop.code
    return code, out.getvalue(), err.getvalue()


class VerifyReceiptCommand(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = Store.seeded_from_sample()
        _, _, out = api.handle("POST", "/v1/verdict", json.dumps({"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
                                                                  "transaction": {"amount_minor": 2400000, "currency": "USD"}}).encode(), cls.store)
        cls.receipt = json.loads(out)
        cls.pin = cls.store.signer.issuer_id

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def file(self, doc, name=None):
        self._n = getattr(self, "_n", 0) + 1                       # every call its own file: argument lists are built before any run
        p = self.dir / (name or f"r{self._n}.json")
        p.write_text(doc if isinstance(doc, str) else json.dumps(doc))
        return str(p)

    def test_a_genuine_receipt_with_the_right_pin_is_verified(self):
        code, out, _ = run("verify-receipt", self.file(self.receipt), "--pin", self.pin)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("VERIFIED"), out)

    def test_everything_else_is_not_verified_and_says_why(self):
        cases = {
            "amount edited": {**self.receipt, "transaction": {"amount_minor": 1, "currency": "USD"}},
            "verdict edited": {**self.receipt, "verdict": "PROCEED" if self.receipt["verdict"] != "PROCEED" else "HOLD"},
            "score edited": {**self.receipt, "trust_score": 99},
            "signature removed": {k: v for k, v in self.receipt.items() if k != "signature"},
            "signature flipped": {**self.receipt, "signature": self.receipt["signature"][:-1] + ("0" if self.receipt["signature"][-1] != "0" else "1")},
            "issuer swapped": {**self.receipt, "issuer": Signer.generate().issuer_id},
            "extra field": {**self.receipt, "note": "x"},
            "junk": [1, 2, 3],
        }
        for label, doc in cases.items():
            code, out, _ = run("verify-receipt", self.file(doc), "--pin", self.pin)
            self.assertEqual(code, 1, label)
            self.assertTrue(out.startswith("NOT VERIFIED"), (label, out))
            self.assertNotRegex(out.splitlines()[0], r"^VERIFIED", label)

    def test_the_wrong_pin_is_not_verified(self):
        code, out, _ = run("verify-receipt", self.file(self.receipt), "--pin", Signer.generate().issuer_id)
        self.assertEqual(code, 1)
        self.assertIn("not signed by the key you pinned", out)

    def test_an_expired_receipt_is_not_verified_at_a_later_time(self):
        code, out, _ = run("verify-receipt", self.file(self.receipt), "--pin", self.pin, "--now", "2099-01-01T00:00:00+00:00")
        self.assertEqual(code, 1)
        self.assertIn("expired", out)

    def test_a_receipt_with_no_expiry_is_not_verified(self):
        from diligenceos.engine import assemble_verdict
        from diligenceos.receipt import issue_receipt
        from diligenceos.types import CheckStatus, Finding
        signer = Signer.generate()
        r = issue_receipt(subject={"name": "A", "registration_id": "R"}, inputs={}, result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]), signer=signer)
        self.assertIsNone(r["expires"])
        code, out, _ = run("verify-receipt", self.file(r), "--pin", signer.issuer_id)
        self.assertEqual(code, 1)
        self.assertIn("no expiry", out)

    def test_it_always_says_what_it_cannot_know_offline(self):
        _, out, _ = run("verify-receipt", self.file(self.receipt), "--pin", self.pin)
        self.assertIn("revoked", out)

    def test_usage_problems_are_exit_2_and_never_a_verified(self):
        for argv in (["verify-receipt", str(self.dir / "absent.json"), "--pin", self.pin], ["verify-receipt", self.file("not json"), "--pin", self.pin],
                     ["verify-receipt", self.file(self.receipt), "--pin", "nope"], ["verify-receipt", self.file(self.receipt), "--pin", "ed25519:" + "AB" * 32],
                     ["verify-receipt", self.file(self.receipt), "--pin", self.pin, "--now", "yesterday"], ["verify-receipt", self.file(self.receipt)],
                     ["verify-receipt", self.file(self.receipt), "--pin", self.pin, "--now", "2026-10-16T00:00:00"]):
            code, out, _ = run(*argv)
            self.assertEqual(code, 2, argv)
            self.assertNotIn("VERIFIED", out.replace("NOT VERIFIED", ""))

    def test_a_pin_is_a_public_key_id_and_nothing_else_is_read_from_the_receipt(self):
        forged = {**self.receipt, "trusted_issuers": [Signer.generate().issuer_id]}
        code, out, _ = run("verify-receipt", self.file(forged), "--pin", Signer.generate().issuer_id)
        self.assertEqual(code, 1)


class VerifyEvidenceCommand(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from flashy.test_payment_evidence import OPERATOR, Flow
        cls.operator = OPERATOR
        cls.doc = Flow().build()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def file(self, doc):
        self._n = getattr(self, "_n", 0) + 1
        p = self.dir / f"e{self._n}.json"
        p.write_text(json.dumps(doc))
        return str(p)

    def test_genuine_evidence_with_the_right_pin_is_verified_and_summarised(self):
        code, out, _ = run("verify-evidence", self.file(self.doc), "--pin", self.operator.issuer_id)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("VERIFIED"), out)
        for needle in (self.doc["payer_address"], self.doc["payee_address"], self.doc["amount"], self.doc["tx_hash"], "simulated"):
            self.assertIn(needle, out)
        self.assertIn("does not approve", out)

    def test_edited_evidence_wrong_pin_and_junk_are_not_verified(self):
        for doc, pin in (({**self.doc, "amount": "1"}, self.operator.issuer_id), ({**self.doc, "approves_spend": True}, self.operator.issuer_id),
                         (self.doc, Signer.generate().issuer_id), ({**self.doc, "extra": 1}, self.operator.issuer_id), ({}, self.operator.issuer_id), ([], self.operator.issuer_id)):
            code, out, _ = run("verify-evidence", self.file(doc), "--pin", pin)
            self.assertEqual(code, 1)
            self.assertTrue(out.startswith("NOT VERIFIED"), out)

    def test_the_purpose_text_is_never_in_the_output(self):
        _, out, _ = run("verify-evidence", self.file(self.doc), "--pin", self.operator.issuer_id)
        self.assertNotIn("sealed snapshot", out)




class RecheckEvidenceCommand(unittest.TestCase):
    """The third party who has the underlying documents re-derives the record instead of trusting the signature alone."""

    @classmethod
    def setUpClass(cls):
        from flashy.test_payment_evidence import OPERATOR, Flow
        cls.operator, cls.flow = OPERATOR, Flow()
        cls.doc = cls.flow.build()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, doc):
        p = self.dir / name
        p.write_text(json.dumps(doc))
        return str(p)

    def args(self, flow=None, doc=None, pins=None, chain=None):
        f = flow or self.flow
        c = chain or {"chainId": f.chain_id, "blockNumber": f.tip, "receipt": f.receipt}
        return ["recheck-evidence", self.write("e.json", doc or self.doc), "--pin", self.operator.issuer_id, "--request", self.write("rq.json", f.request),
                "--authorization", self.write("au.json", f.authorization), "--plane-log", self.write("log.json", f.log), "--pins", self.write("pins.json", pins or f.pins),
                "--chain", self.write("chain.json", c)]

    def test_a_record_that_matches_its_documents_is_consistent(self):
        code, out, _ = run(*self.args())
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("CONSISTENT"), out)

    def test_the_documents_of_another_payment_are_not(self):
        from flashy.test_payment_evidence import Flow
        code, out, _ = run(*self.args(flow=Flow(amount="2000000"), doc=self.doc))
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("DIFFERS") or out.startswith("REFUSED"), out)

    def test_a_forged_record_signed_by_someone_else_is_not_trusted_even_if_it_matches(self):
        other = Signer.generate().issuer_id
        code, out, _ = run(*[a if a != self.operator.issuer_id else other for a in self.args()])
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("NOT VERIFIED"), out)

    def test_a_pin_the_documents_do_not_satisfy_is_refused_with_a_code(self):
        from flashy.test_payment_evidence import STRANGER
        code, out, _ = run(*self.args(pins={**self.flow.pins, "root_pubs": [STRANGER.pub_hex]}))
        self.assertEqual(code, 1)
        self.assertIn("GRANT_CHAIN_INVALID", out)

    def test_a_chain_that_does_not_show_the_payment_is_refused(self):
        code, out, _ = run(*self.args(chain={"chainId": self.flow.chain_id, "blockNumber": self.flow.tip, "receipt": None}))
        self.assertEqual(code, 1)
        self.assertIn("CHAIN_NOT_CONFIRMED", out)

    def test_missing_or_unreadable_files_are_exit_2(self):
        good = self.args()
        for i in range(len(good)):
            if good[i].startswith(str(self.dir)) and i > 0:
                bad = list(good)
                bad[i] = str(self.dir / "absent.json")
                self.assertEqual(run(*bad)[0], 2, good[i - 1])
        self.assertEqual(run("recheck-evidence", self.write("x.json", self.doc), "--pin", self.operator.issuer_id)[0], 2)


if __name__ == "__main__":
    unittest.main()
