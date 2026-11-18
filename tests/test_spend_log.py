import json
import tempfile
import unittest
from pathlib import Path

from diligenceos import api
from diligenceos.policy import Policy
from diligenceos.receipt_log import LogCorruptError, ReceiptLog, verify_chain
from diligenceos.store import Store
from diligenceos.types import Money, Verdict
from tests.auth_helpers import as_operator

CAP = 30_000_000


def policy(cap=CAP):
    return Policy(Money(cap, "USD"), frozenset({Verdict.PROCEED, Verdict.HOLD}), 0).to_dict()


class SpendLogTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.seeded_from_sample(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def receipt(self, store=None, amount=24_000_000, name="Meridian Robotics Ltd.", reg="UK09456213"):
        store = store or self.store
        body = {"subject": {"name": name, "registration_id": reg}, "transaction": {"amount_minor": amount, "currency": "USD"}}
        status, _, out = api.handle("POST", "/v1/verdict", json.dumps(body).encode(), store)
        self.assertEqual(status, 200)
        return json.loads(out)

    def spend(self, receipt, store=None, budget="q4", cap=CAP):
        store = store or self.store
        body = as_operator(store, "/v1/spend", {"budget_id": budget, "receipt": receipt, "policy": policy(cap)})
        status, _, out = api.handle("POST", "/v1/spend", json.dumps(body).encode(), store)
        return status, json.loads(out)

    def spends_in_log(self, store=None):
        return (store or self.store).log.spend_entries()

    def test_a_committed_spend_is_a_signed_log_entry(self):
        receipt = self.receipt()
        status, out = self.spend(receipt)
        self.assertEqual((status, out["decision"]), (200, "ALLOW"))
        (entry,) = self.spends_in_log()
        self.assertEqual((entry["kind"], entry["budget_id"], entry["spent_receipt_id"]), ("spend", "q4", receipt["id"]))
        self.assertEqual((entry["amount_minor"], entry["currency"]), (24_000_000, "USD"))
        self.assertEqual(entry["caller"], self.store.signer.issuer_id)
        self.assertEqual(entry["issuer"], self.store.signer.issuer_id)
        self.assertEqual(verify_chain(self.store.log.entries, require_signed=True, trusted_issuers=[self.store.signer.issuer_id]), [])
        self.assertTrue(json.loads(api.handle("GET", "/v1/log/verify", b"", self.store)[2])["valid"])

    def test_the_same_receipt_twice_logs_one_spend(self):
        receipt = self.receipt()
        self.spend(receipt)
        status, out = self.spend(receipt)
        self.assertEqual((status, out["already_committed"]), (200, True))
        self.assertEqual(len(self.spends_in_log()), 1)

    def test_a_refused_spend_is_not_logged(self):
        status, out = self.spend(self.receipt(amount=31_000_000))
        self.assertEqual(out["decision"], "ESCALATE")
        self.assertEqual(self.spends_in_log(), [])

    def test_zeroing_the_index_cannot_reopen_a_budget(self):
        self.spend(self.receipt(amount=24_000_000))
        state = json.loads(self.path.read_text())
        state["spend"] = {}  # someone who can write store.json but does not hold the issuer key
        self.path.write_text(json.dumps(state))
        restarted = Store.load_or_seed(self.path)
        self.assertEqual(restarted.spent("q4", "USD"), 24_000_000)
        second = self.receipt(restarted, amount=24_000_000, name="Other Co", reg="UK1")
        status, out = self.spend(second, store=restarted)
        self.assertEqual(out["decision"], "ESCALATE")

    def test_a_crash_between_the_log_and_the_index_still_counts(self):
        receipt = self.receipt(amount=24_000_000)
        # the log append happened, the index save did not
        self.store.log.append_spend("q4", receipt["id"], {"amount_minor": 24_000_000, "currency": "USD"}, "someone",
                                    signer=self.store.signer)
        restarted = Store.load_or_seed(self.path)
        self.assertEqual(restarted.spent("q4", "USD"), 24_000_000)
        self.assertIsNotNone(restarted.spend_entry("q4", receipt["id"]))

    def test_an_unreadable_log_refuses_the_spend_with_503_and_commits_nothing(self):
        receipt = self.receipt()
        log_path = self.path.with_name("receipts.jsonl")
        lines = log_path.read_text().splitlines()
        lines[0] = lines[0].replace('"seq": 0', '"seq": 7')
        log_path.write_text("\n".join(lines) + "\n")
        broken = Store.load_or_seed(self.path)
        body = as_operator(broken, "/v1/spend", {"budget_id": "q4", "receipt": receipt, "policy": policy()})
        status, _, out = api.handle("POST", "/v1/spend", json.dumps(body).encode(), broken)
        self.assertEqual((status, json.loads(out)["error"]["code"]), (503, "log_unavailable"))
        self.assertEqual(json.loads(self.path.read_text()).get("spend"), {})

    def test_commit_spend_fails_closed_and_leaves_the_index_alone(self):
        store = Store.seeded_from_sample(self.path)
        receipt = self.receipt(store)
        self.path.with_name("receipts.jsonl").write_text("not json\n")
        broken = Store.load_or_seed(self.path)
        with self.assertRaises(LogCorruptError):
            broken.commit_spend("q4", receipt["id"], Money(5, "USD"), caller="x")
        self.assertEqual(broken._spend, {})

    def test_a_hash_valid_but_malformed_spend_entry_is_corruption(self):
        for label, extra in (("string amount", {"amount_minor": "5"}), ("negative", {"amount_minor": -5}),
                             ("bool", {"amount_minor": True}), ("no budget", {"budget_id": None})):
            with self.subTest(label):
                path = Path(self._tmp.name) / f"{label.replace(' ', '_')}.jsonl"
                log = ReceiptLog(path)
                log.append_spend("q4", "sha256:" + "0" * 64, {"amount_minor": 5, "currency": "USD"}, None, signer=self.store.signer)
                bad = dict(log.entries[0])
                bad.update(extra)
                for k in ("entry_hash", "signature"):
                    bad.pop(k)
                log2 = ReceiptLog(Path(self._tmp.name) / f"{label.replace(' ', '_')}-2.jsonl")
                log2._seal_and_write(bad, self.store.signer)
                with self.assertRaises(LogCorruptError):
                    ReceiptLog(log2.path)

    def test_an_independent_witness_accepts_a_log_that_holds_spends(self):
        from diligenceos import witness
        self.spend(self.receipt())
        head = json.loads(api.handle("GET", "/v1/log/head", b"", self.store)[2])
        entries = self.store.log.entries
        self.assertEqual([e["kind"] for e in entries], ["receipt", "spend"])
        result = witness.check_consistency(None, entries, head, pinned_issuer=self.store.signer.issuer_id)
        self.assertTrue(result.ok, result)

    def test_a_store_without_spends_is_unchanged(self):
        self.assertEqual(self.store.spent("q4", "USD"), 0)
        self.assertEqual(self.store.log.entries, [])


if __name__ == "__main__":
    unittest.main()
