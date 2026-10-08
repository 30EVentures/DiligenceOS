import copy
import unittest

from diligenceos.engine import assemble_verdict
from diligenceos.receipt import canonical_json, digest, issue_receipt, verify_receipt
from diligenceos.types import CheckStatus, Finding

SUBJECT = {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}
INPUTS = {"subject": SUBJECT, "document_text": "x"}
T = "2026-09-29T12:00:00+00:00"


def make(findings=None, **kw):
    findings = findings or [
        Finding("sanctions", CheckStatus.PASS),
        Finding("document_scan", CheckStatus.FLAG, detail="no indemnification clause"),
    ]
    return issue_receipt(
        subject=SUBJECT, inputs=INPUTS, result=assemble_verdict(findings),
        issued_at=T, **kw,
    )


def reseal(receipt):
    """Forge: edit fields, then recompute a matching id."""
    body = {k: v for k, v in receipt.items() if k != "id"}
    return {**body, "id": digest(body)}


class ReceiptTest(unittest.TestCase):
    def test_fresh_receipt_verifies(self):
        check = verify_receipt(make())
        self.assertTrue(check.valid, check.errors)

    def test_issue_is_deterministic(self):
        self.assertEqual(canonical_json(make()), canonical_json(make()))

    def test_canonical_json_ignores_key_order(self):
        self.assertEqual(canonical_json({"a": 1, "b": 2}), canonical_json({"b": 2, "a": 1}))

    def test_tampered_fields_fail(self):
        for mutate in (
            lambda r: r.update(verdict="PROCEED"),
            lambda r: r.update(trust_score=99),
            lambda r: r["subject"].update(name="Someone Else"),
            lambda r: r["findings"][1].update(detail="edited"),
        ):
            r = copy.deepcopy(make())
            mutate(r)
            self.assertFalse(verify_receipt(r).valid)

    def test_resealed_forgery_is_caught_by_replay(self):
        r = copy.deepcopy(make())
        r["verdict"] = "PROCEED"
        r["trust_score"] = 85
        check = verify_receipt(reseal(r))
        self.assertFalse(check.valid)
        self.assertTrue(any("does not follow" in e for e in check.errors))

    def test_trust_score_must_be_an_integer(self):
        # 85.0 == 85 and True == 1 in Python, but they canonicalize differently and other
        # languages disagree about them: only a real integer may match the replay.
        for bad in (85.0, True):
            r = copy.deepcopy(make(findings=[Finding("sanctions", CheckStatus.PASS)]))
            self.assertEqual(r["trust_score"], 85)
            r["trust_score"] = bad if bad is not True else 1
            check = verify_receipt(reseal(r))
            self.assertFalse(check.valid, bad)
        r = copy.deepcopy(make(findings=[Finding("sanctions", CheckStatus.PASS)]))
        r["trust_score"] = 85.0
        self.assertTrue(any("trust_score" in e for e in verify_receipt(reseal(r)).errors))

    def test_malformed_input_never_raises(self):
        for bad in (None, [], "x", {}, {"schema": "diligenceos.receipt/1", "findings": 3}):
            self.assertFalse(verify_receipt(bad).valid)

    def test_expiry_is_reported_separately(self):
        r = make()
        r = reseal({**{k: v for k, v in r.items() if k != "id"}, "expires": "2026-09-30T00:00:00+00:00"})
        self.assertFalse(verify_receipt(r, now="2026-09-29T13:00:00+00:00").expired)
        late = verify_receipt(r, now="2026-10-01T00:00:00+00:00")
        self.assertTrue(late.valid)
        self.assertTrue(late.expired)


if __name__ == "__main__":
    unittest.main()
