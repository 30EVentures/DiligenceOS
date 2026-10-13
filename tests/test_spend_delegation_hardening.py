"""Round 4 of the overnight review: a receipt pays once, and a delegation's own clock fields mean something."""

import json
import tempfile
import unittest
from pathlib import Path

from auth_helpers import as_operator
from diligenceos import api
from diligenceos.conformance import test_signer
from diligenceos.delegation import issue_delegation, verify_chain
from diligenceos.policy import Policy
from diligenceos.store import Store
from diligenceos.types import Money, Verdict

POLICY = Policy(Money(50_000_000, "USD"), frozenset({Verdict.PROCEED}), 70).to_dict()
SUBJECT = {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}


def call(store, method, path, payload=None):
    body = json.dumps(as_operator(store, path, payload) if payload is not None else None).encode() if payload is not None else b""
    status, _, out = api.handle(method, path, body, store)
    return status, json.loads(out)


def verdict(store, amount=24_000_000):
    status, receipt = call(store, "POST", "/v1/verdict",
                           {"subject": SUBJECT, "transaction": {"amount_minor": amount, "currency": "USD"}})
    assert status == 200 and receipt["verdict"] == "PROCEED", receipt
    return receipt


def spend(store, receipt, budget):
    return call(store, "POST", "/v1/spend", {"budget_id": budget, "receipt": receipt, "policy": POLICY})[1]


class OneReceiptPaysOnceTest(unittest.TestCase):
    def test_the_same_receipt_cannot_be_spent_under_a_second_budget(self):
        store = Store.seeded_from_sample()
        r = verdict(store)
        first = spend(store, r, "q4")
        self.assertEqual((first["decision"], first["spent_minor"]), ("ALLOW", 24_000_000))
        second = spend(store, r, "q4-copy")
        self.assertEqual(second["decision"], "DENY", second)
        self.assertEqual(second["spent_minor"], 0)
        self.assertFalse(second["already_committed"])
        self.assertNotIn("q4", " ".join(second["reasons"]), "must not reveal another budget's name")
        self.assertEqual(store.spent("q4-copy", "USD"), 0)
        self.assertEqual(store.spent("q4", "USD"), 24_000_000)

    def test_the_same_budget_is_still_idempotent(self):
        store = Store.seeded_from_sample()
        r = verdict(store)
        spend(store, r, "q4")
        again = spend(store, r, "q4")
        self.assertEqual((again["decision"], again["already_committed"], again["spent_minor"]), ("ALLOW", True, 24_000_000))

    def test_it_holds_across_a_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            store = Store.load_or_seed(path)
            r = verdict(store)
            spend(store, r, "a")
            restarted = Store.load_or_seed(path)
            self.assertEqual(spend(restarted, r, "b")["decision"], "DENY")
            self.assertEqual(spend(restarted, r, "a")["already_committed"], True)

    def test_a_denied_spend_does_not_consume_the_receipt(self):
        store = Store.seeded_from_sample()
        r = verdict(store, amount=60_000_000)          # over the 50M cap: escalates, commits nothing
        self.assertEqual(spend(store, r, "a")["decision"], "ESCALATE")
        self.assertEqual(spend(store, r, "b")["decision"], "ESCALATE")


NOW = "2026-10-13T12:00:00+00:00"
OP, AGENT = test_signer(1), test_signer(2)


def chain(**kw):
    kw.setdefault("issued_at", "2026-10-01T00:00:00+00:00")
    kw.setdefault("expires", "2026-12-01T00:00:00+00:00")
    return [issue_delegation(OP, delegate=AGENT.issuer_id, scopes=["spend"], **kw)]


def valid(links, now=NOW):
    return verify_chain(links, root_issuers=[OP.issuer_id], now=now)


class DelegationClockTest(unittest.TestCase):
    def test_a_normal_delegation_verifies(self):
        self.assertTrue(valid(chain()).valid)

    def test_issued_at_must_be_a_timezone_aware_timestamp(self):
        for bad in ("never", "", "2026-10-01T00:00:00", "2026-10-01", 5, None):
            result = valid(chain(issued_at=bad))
            self.assertFalse(result.valid, repr(bad))

    def test_a_delegation_from_the_future_is_not_valid_yet(self):
        self.assertFalse(valid(chain(issued_at="2031-01-01T00:00:00+00:00")).valid)
        self.assertFalse(valid(chain(issued_at="2026-10-13T12:10:00+00:00")).valid)      # beyond the skew allowance
        self.assertTrue(valid(chain(issued_at="2026-10-13T12:04:00+00:00")).valid)       # inside it: clocks differ a little

    def test_issued_after_it_expires_is_refused(self):
        self.assertFalse(valid(chain(issued_at="2026-12-02T00:00:00+00:00"), now="2026-12-02T00:00:00+00:00").valid)
        self.assertFalse(valid(chain(issued_at="2026-11-01T00:00:00+00:00", expires="2026-10-20T00:00:00+00:00")).valid)

    def test_a_child_cannot_predate_its_parent(self):
        parent = chain(issued_at="2026-10-05T00:00:00+00:00")[0]
        child = issue_delegation(AGENT, delegate=test_signer(3).issuer_id, scopes=["spend"],
                                 expires="2026-11-01T00:00:00+00:00", parent=parent["id"],
                                 issued_at="2026-10-01T00:00:00+00:00")
        self.assertFalse(valid([parent, child]).valid)
        ok_child = issue_delegation(AGENT, delegate=test_signer(3).issuer_id, scopes=["spend"],
                                    expires="2026-11-01T00:00:00+00:00", parent=parent["id"],
                                    issued_at="2026-10-06T00:00:00+00:00")
        self.assertTrue(valid([parent, ok_child]).valid)


if __name__ == "__main__":
    unittest.main()
