"""Round 2 of the overnight review: the witness must not treat a damaged baseline as
'first sight', a hash-valid but odd log must fail closed (not KeyError), strict means strict."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from diligenceos import api
from diligenceos.engine import assemble_verdict
from diligenceos.receipt import issue_receipt
from diligenceos.receipt_log import GENESIS, LogCorruptError, ReceiptLog, _entry_hash
from diligenceos.signing import LOG_HEAD_DOMAIN, Signer, head_message
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding
from diligenceos.witness import check_consistency, run_witness

T = "2026-09-29T12:00:00+00:00"


def receipt(n):
    return issue_receipt(subject={"name": f"S{n}"}, inputs={"n": n},
                         result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]), issued_at=T)


def signed_log(signer, count):
    log = ReceiptLog(None)
    for n in range(count):
        log.append(receipt(n), now=T, signer=signer)
    return log


def head_doc(signer, log):
    length = len(log.entries)
    return {"length": length, "head_hash": log.head, "issuer": signer.issuer_id,
            "signature": signer.sign(LOG_HEAD_DOMAIN, head_message(length, log.head)), "cosignatures": []}


class DamagedBaselineTest(unittest.TestCase):
    """A witness's whole value is its memory. A baseline it cannot read is never 'the first time'."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "witness.json"
        self.op, self.w = Signer.generate(), Signer.generate()
        self.log = signed_log(self.op, 3)
        docs = {"/v1/log/head": head_doc(self.op, self.log), "/v1/log/entries": {"entries": self.log.entries}}
        self.fetch = lambda path: docs[path]

    def tearDown(self):
        self._tmp.cleanup()

    def round(self):
        return run_witness(self.fetch, self.state, self.w, self.op.issuer_id)

    def with_baseline(self, baseline):
        self.state.write_text(json.dumps({self.op.issuer_id: baseline}))

    def test_a_blank_baseline_is_not_first_sight(self):
        for baseline in ({}, [], "", 0, False, None):
            self.with_baseline(baseline)
            code, message, cosig = self.round()
            self.assertEqual(code, 3, baseline)
            self.assertIsNone(cosig, baseline)
            self.assertIn("baseline", message, baseline)

    def test_every_malformed_baseline_is_refused_not_a_crash(self):
        good_hash = self.log.head
        for baseline in ({"length": "3", "head_hash": good_hash}, {"length": -1, "head_hash": good_hash},
                         {"length": 1.5, "head_hash": good_hash}, {"length": True, "head_hash": good_hash},
                         {"length": None, "head_hash": good_hash}, {"length": 3}, {"head_hash": good_hash},
                         {"length": 3, "head_hash": 7}, [1, 2], 5, "x"):
            self.with_baseline(baseline)
            before = self.state.read_text()
            code, message, cosig = self.round()
            self.assertEqual(code, 3, baseline)
            self.assertIsNone(cosig)
            self.assertEqual(self.state.read_text(), before, "a refused round must not touch the state")

    def test_no_baseline_at_all_is_still_first_sight(self):
        self.assertEqual(self.round()[0], 0)
        self.state.write_text(json.dumps({"someone-else": {"length": 1, "head_hash": "x"}}))
        self.assertEqual(self.round()[0], 0)

    def test_a_good_baseline_still_works_and_check_consistency_never_raises(self):
        self.with_baseline({"length": 3, "head_hash": self.log.head})
        self.assertEqual(self.round()[0], 0)
        for previous in ({}, [], "x", 5, {"length": "3"}, {"length": -1, "head_hash": "h"}):
            r = check_consistency(previous, self.log.entries, head_doc(self.op, self.log), pinned_issuer=self.op.issuer_id)
            self.assertFalse(r.ok, previous)

    def test_an_unreadable_state_file_is_a_refusal_not_a_crash_and_is_kept(self):
        for text in ("", "{", "[]", "null", '"x"', "5"):
            self.state.write_text(text)
            code, message, cosig = self.round()
            self.assertEqual(code, 3, text)
            self.assertIsNone(cosig)
            self.assertEqual(self.state.read_text(), text)

    def test_the_state_file_is_replaced_atomically(self):
        self.assertEqual(self.round()[0], 0)
        before = self.state.read_text()
        bigger = signed_log(self.op, 4)
        docs = {"/v1/log/head": head_doc(self.op, bigger), "/v1/log/entries": {"entries": bigger.entries}}
        real = Path.write_text

        def dies_half_way(path, data, *a, **kw):
            real(path, data[: len(data) // 2], *a, **kw)
            raise OSError("disk full")

        with mock.patch.object(Path, "write_text", dies_half_way):
            with self.assertRaises(OSError):
                run_witness(lambda p: docs[p], self.state, self.w, self.op.issuer_id)
        self.assertEqual(self.state.read_text(), before, "a crash while saving must leave the old baseline intact")
        json.loads(self.state.read_text())


class OddLogTest(unittest.TestCase):
    def write(self, *entries):
        self.dir = tempfile.mkdtemp()
        path = Path(self.dir) / "receipts.jsonl"
        prev, lines = GENESIS, []
        for i, body in enumerate(entries):
            entry = {"seq": i, "prev_hash": prev, **body}
            entry["entry_hash"] = _entry_hash(entry)
            prev = entry["entry_hash"]
            lines.append(json.dumps(entry))
        path.write_text("\n".join(lines) + "\n")
        return path

    def test_a_hash_valid_entry_that_is_not_a_receipt_entry_fails_closed(self):
        for body in ({"kind": "receipt"}, {"kind": "receipt", "receipt_id": "sha256:" + "a" * 64},
                     {"kind": "receipt", "receipt_id": ["x"], "inputs_digest": "d"},
                     {"kind": "receipt", "receipt_id": "r", "inputs_digest": {"a": 1}}, {}):
            with self.assertRaises(LogCorruptError, msg=body):
                ReceiptLog(self.write(body))

    def test_the_api_says_503_not_500_for_such_a_log(self):
        path = self.write({"kind": "receipt"})
        store = Store.load_or_seed(Path(self.dir) / "store.json")
        status, _, body = api.handle("GET", "/v1/log/head", b"", store)
        self.assertEqual((status, json.loads(body)["error"]["code"]), (503, "log_unavailable"))
        self.assertIsNone(None if status == 503 else path)

    def test_a_revocation_entry_with_no_target_is_loaded_but_never_enforced(self):
        log = ReceiptLog(self.write({"kind": "revocation"}))
        store = Store.load_or_seed(Path(self.dir) / "store.json")
        self.assertEqual(store.revocations, {})
        self.assertEqual(len(log.revocation_entries()), 1)


class StrictQueryTest(unittest.TestCase):
    def get(self, query):
        return api.handle("GET", "/v1/log/entries", b"", Store(), query)[0]

    def test_a_trailing_newline_is_not_a_digit(self):
        for query in ("after_seq=5%0A", "limit=5%0A", "limit=5%0D%0A"):
            self.assertEqual(self.get(query), 400, query)
        self.assertEqual(self.get("limit=5"), 200)

    def test_a_receipt_id_may_not_end_in_a_newline(self):
        for rid in ("sha256:" + "a" * 64 + "\n", "sha256:" + "a" * 64 + "\n\n"):
            status, _, body = api.handle("POST", "/v1/log/lookup", json.dumps({"receipt_id": rid}).encode(), Store())
            self.assertEqual((status, json.loads(body)["error"]["code"]), (400, "invalid_request"))


if __name__ == "__main__":
    unittest.main()
