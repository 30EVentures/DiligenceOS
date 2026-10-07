import copy
import json
import tempfile
import unittest
from pathlib import Path

from diligenceos import api
from diligenceos.engine import assemble_verdict
from diligenceos.receipt import issue_receipt
from diligenceos.receipt_log import GENESIS, LogCorruptError, ReceiptLog, _entry_hash, verify_chain
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding

T = "2026-09-29T12:00:00+00:00"
CLEAN = [Finding("sanctions", CheckStatus.PASS)]
FLAGGED = [Finding("document_scan", CheckStatus.FLAG, detail="d")]


def receipt(n=0, findings=CLEAN, inputs=None, issued_at=T):
    return issue_receipt(
        subject={"name": f"S{n}"}, inputs=inputs if inputs is not None else {"n": n},
        result=assemble_verdict(findings), issued_at=issued_at,
    )


def filled(count=4):
    log = ReceiptLog()
    for n in range(count):
        log.append(receipt(n), now=T)
    return log


def reseal(entries, i):
    """Forge entry i then repair its own hash (but not later links)."""
    entries[i]["entry_hash"] = _entry_hash(entries[i])


class ChainTest(unittest.TestCase):
    def test_honest_log_verifies_and_links_from_genesis(self):
        log = filled()
        self.assertEqual(verify_chain(log.entries), [])
        self.assertEqual(log.entries[0]["prev_hash"], GENESIS)
        self.assertEqual(log.head, log.entries[-1]["entry_hash"])
        self.assertEqual(ReceiptLog().head, GENESIS)

    def test_edited_entry_fails(self):
        e = filled().entries
        e[1]["logged_at"] = "2020-01-01T00:00:00+00:00"
        self.assertTrue(any("own hash" in x for x in verify_chain(e)))

    def test_edited_and_rehashed_entry_breaks_the_next_link(self):
        e = filled().entries
        e[1]["receipt_id"] = "sha256:" + "f" * 64
        reseal(e, 1)
        self.assertTrue(any("does not link" in x for x in verify_chain(e)))

    def test_removed_middle_entry_fails(self):
        e = filled().entries
        del e[1]
        self.assertTrue(verify_chain(e))

    def test_reordered_entries_fail(self):
        e = filled().entries
        e[1], e[2] = e[2], e[1]
        self.assertTrue(verify_chain(e))

    def test_truncated_tail_is_caught_only_with_a_remembered_head(self):
        log = filled()
        head = log.head
        e = log.entries[:-1]
        self.assertEqual(verify_chain(e), [])  # an intact prefix looks fine on its own
        self.assertTrue(any("head" in x for x in verify_chain(e, expected_head=head)))
        self.assertEqual(verify_chain(log.entries, expected_head=head), [])

    def test_entries_must_be_a_list(self):
        # an empty non-list used to look like an empty log; a number or None raised TypeError
        for bad in (None, 5, True, "", "abc", {}, {"0": {}}, (), 0.5):
            errors = verify_chain(bad)
            self.assertEqual(errors, ["entries must be a list"], bad)

    def test_seq_must_be_an_integer_not_a_boolean_or_string(self):
        for bad_seq in (False, "0", 0.5):
            entry = {"seq": bad_seq, "kind": "receipt", "receipt_id": "sha256:" + "a" * 64,
                     "inputs_digest": "sha256:" + "b" * 64, "outcome_digest": "sha256:" + "c" * 64,
                     "logged_at": T, "conflict_with": None, "prev_hash": GENESIS}
            entry["entry_hash"] = _entry_hash(entry)  # self-consistent forgery: only seq is wrong
            self.assertTrue(any("seq" in e for e in verify_chain([entry])), bad_seq)
        self.assertEqual(verify_chain(filled().entries), [])

    def test_garbage_never_raises(self):
        for bad in ([1], [{"seq": 0}], [None], [{"seq": 0, "prev_hash": GENESIS, "x": {1, 2}}]):
            self.assertTrue(verify_chain(bad))


class AppendTest(unittest.TestCase):
    def test_same_receipt_twice_is_one_entry(self):
        log = ReceiptLog()
        r = receipt()
        a, b = log.append(r, now=T), log.append(r, now=T)
        self.assertEqual(a, b)
        self.assertEqual(len(log.entries), 1)

    def test_same_inputs_same_outcome_is_not_a_conflict(self):
        log = ReceiptLog()
        log.append(receipt(0, issued_at="2026-09-29T12:00:00+00:00"))
        second = log.append(receipt(0, issued_at="2026-09-29T12:00:05+00:00"))
        self.assertIsNone(second["conflict_with"])
        self.assertEqual(log.conflicts(), [])

    def test_same_inputs_different_outcome_is_a_permanent_conflict(self):
        log = ReceiptLog()
        first = log.append(receipt(0, CLEAN, issued_at="2026-09-29T12:00:00+00:00"))
        second = log.append(receipt(0, FLAGGED, issued_at="2026-09-29T12:00:05+00:00"))
        self.assertEqual(second["conflict_with"], first["seq"])
        self.assertEqual([c["seq"] for c in log.conflicts()], [1])
        # the flag is inside the hashed entry: removing it breaks the chain
        e = log.entries
        e[1]["conflict_with"] = None
        self.assertTrue(verify_chain(e))


class PersistenceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "receipts.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def test_reopen_continues_the_chain_and_keeps_conflict_detection(self):
        log = ReceiptLog(self.path)
        log.append(receipt(0, CLEAN, issued_at="2026-09-29T12:00:00+00:00"), now=T)
        head = log.head
        again = ReceiptLog(self.path)
        self.assertEqual(again.head, head)
        entry = again.append(receipt(0, FLAGGED, issued_at="2026-09-29T12:00:05+00:00"), now=T)
        self.assertEqual((entry["seq"], entry["prev_hash"], entry["conflict_with"]), (1, head, 0))
        self.assertEqual(len(self.path.read_text().splitlines()), 2)

    def test_hand_edited_file_fails_closed(self):
        log = ReceiptLog(self.path)
        log.append(receipt(0), now=T)
        log.append(receipt(1), now=T)
        lines = self.path.read_text().splitlines()
        edited = json.loads(lines[0])
        edited["logged_at"] = "1999-01-01T00:00:00+00:00"
        self.path.write_text("\n".join([json.dumps(edited), lines[1]]) + "\n")
        with self.assertRaises(LogCorruptError):
            ReceiptLog(self.path)

    def test_non_json_file_fails_closed(self):
        self.path.write_text("not json\n")
        with self.assertRaises(LogCorruptError):
            ReceiptLog(self.path)


class ApiLogTest(unittest.TestCase):
    REQ = {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def call(self, method, path, payload=None, store=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        status, headers, out = api.handle(method, path, body, store or self.store)
        return status, dict(headers), json.loads(out)

    def test_verdict_is_logged_with_headers_and_unchanged_body(self):
        status, headers, receipt = self.call("POST", "/v1/verdict", self.REQ)
        self.assertEqual(headers["X-DiligenceOS-Log-Seq"], "0")
        self.assertNotIn("X-DiligenceOS-Log-Conflict", headers)
        self.assertNotIn("log", receipt)
        self.assertTrue(self.call("POST", "/v1/verify", receipt)[2]["valid"])
        entry = self.call("POST", "/v1/log/lookup", {"receipt_id": receipt["id"]})[2]["entry"]
        self.assertEqual(entry["entry_hash"], headers["X-DiligenceOS-Log-Entry-Hash"])
        head = self.call("GET", "/v1/log/head")[2]
        self.assertEqual((head["length"], head["head_hash"]), (1, entry["entry_hash"]))
        self.assertEqual(self.call("GET", "/v1/log/verify")[2]["valid"], True)
        self.assertEqual(len(self.call("GET", "/v1/log/entries")[2]["entries"]), 1)
        self.assertEqual(self.call("GET", "/v1/log/conflicts")[2]["conflicts"], [])

    def test_lookup_errors(self):
        self.assertEqual(self.call("POST", "/v1/log/lookup", {"receipt_id": "x"})[0], 400)
        status, _, body = self.call("POST", "/v1/log/lookup", {"receipt_id": "sha256:" + "0" * 64})
        self.assertEqual((status, body["error"]["code"]), (404, "not_found"))
        self.assertEqual(self.call("GET", "/v1/log/lookup")[0], 405)

    def test_log_survives_a_restart_of_the_store(self):
        self.call("POST", "/v1/verdict", self.REQ)
        reopened = Store.load_or_seed(self.path)
        self.assertEqual(self.call("GET", "/v1/log/head", store=reopened)[2]["length"], 1)

    def test_corrupt_log_fails_closed_with_503_and_issues_nothing(self):
        self.call("POST", "/v1/verdict", self.REQ)
        log_path = self.path.with_name("receipts.jsonl")
        entry = json.loads(log_path.read_text().splitlines()[0])
        entry["logged_at"] = "1999-01-01T00:00:00+00:00"
        log_path.write_text(json.dumps(entry) + "\n")
        fresh = Store.load_or_seed(self.path)
        for method, path, payload in (("POST", "/v1/verdict", self.REQ), ("GET", "/v1/log/head", None)):
            status, _, body = self.call(method, path, payload, store=fresh)
            self.assertEqual((status, body["error"]["code"]), (503, "log_unavailable"))

    def test_conflict_header_when_the_same_request_yields_a_different_outcome(self):
        self.call("POST", "/v1/verdict", self.REQ)
        original = api.run_diligence
        api.run_diligence = lambda **kw: assemble_verdict(FLAGGED)  # engine "changed"
        try:
            _, headers, _ = self.call("POST", "/v1/verdict", self.REQ)
        finally:
            api.run_diligence = original
        self.assertEqual(headers["X-DiligenceOS-Log-Conflict"], "0")

    def test_conflict_is_headed_and_listed(self):
        first = self.call("POST", "/v1/verdict", self.REQ)[2]
        # same inputs, different outcome: simulate an engine change by hand-issuing
        forged = copy.deepcopy(first)
        forged["verdict"], forged["trust_score"] = "HOLD", 45
        forged["findings"][0].update(status="flag", detail="changed")
        forged["issued_at"] = "2099-01-01T00:00:00+00:00"
        forged["id"] = "sha256:" + "e" * 64
        entry = self.store.log.append(forged)
        self.assertEqual(entry["conflict_with"], 0)
        self.assertEqual(len(self.call("GET", "/v1/log/conflicts")[2]["conflicts"]), 1)


if __name__ == "__main__":
    unittest.main()
