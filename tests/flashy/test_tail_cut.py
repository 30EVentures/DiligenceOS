"""A hash chain cannot see a cut tail: a log with its last entries removed is still a valid chain. Only a
remembered head and count can. Every witnessing here pins them; a cut tail is refused, not signed."""

import json
import tempfile
import unittest
from pathlib import Path

from diligenceos.flashy import witness
from diligenceos.flashy.spine import SpineKey
from diligenceos.flashy.witness_ledger import WitnessLedger
from diligenceos.signing import Signer
from diligenceos.witness import check_consistency

from .helpers import make_log, seed

KEY = SpineKey.from_seed_hex(seed("c3"))
OTHER = SpineKey.from_seed_hex(seed("d4"))
AT = "2026-10-14T10:00:00.000Z"


def log_of(n, key=KEY, tag="a"):
    return make_log(key, [("decision", {"verdict": "ALLOW", "requestHash": f"{tag}{i}"}) for i in range(n)])


class PinnedVerification(unittest.TestCase):
    def setUp(self):
        self.full = log_of(6)
        self.pin = {"pinned_count": 6, "pinned_head": self.full[-1]["hash"]}

    def test_the_problem_a_cut_tail_is_a_valid_chain(self):
        self.assertTrue(witness.verify_plane_log(self.full[:4], KEY.pub_hex)["ok"])

    def test_with_a_pinned_head_and_count_every_cut_is_refused(self):
        for keep in (5, 4, 3, 1):
            r = witness.verify_plane_log(self.full[:keep], KEY.pub_hex, **self.pin)
            self.assertEqual((r["ok"], r["code"]), (False, "TAIL_CUT"), keep)

    def test_an_empty_log_is_refused_even_when_empties_are_allowed_if_something_was_pinned(self):
        r = witness.verify_plane_log([], KEY.pub_hex, allow_empty=True, **self.pin)
        self.assertEqual((r["ok"], r["code"]), (False, "TAIL_CUT"))

    def test_a_different_history_of_the_same_length_or_longer_is_refused(self):
        for forked in (log_of(6, tag="b"), log_of(9, tag="b")):
            r = witness.verify_plane_log(forked, KEY.pub_hex, **self.pin)
            self.assertEqual((r["ok"], r["code"]), (False, "HISTORY_REWRITTEN"))

    def test_the_pinned_log_itself_and_an_extension_pass(self):
        self.assertTrue(witness.verify_plane_log(self.full, KEY.pub_hex, **self.pin)["ok"])
        extended = make_log(KEY, [("decision", {"verdict": "ALLOW", "requestHash": f"a{i}"}) for i in range(6)] + [("decision", {"verdict": "DENY"})])
        self.assertEqual(extended[:6], self.full)
        r = witness.verify_plane_log(extended, KEY.pub_hex, **self.pin)
        self.assertEqual((r["ok"], r["count"]), (True, 7))

    def test_a_malformed_pin_is_a_refusal_not_a_pass(self):
        for pin in ({"pinned_count": 6}, {"pinned_head": self.full[-1]["hash"]}, {"pinned_count": "6", "pinned_head": self.full[-1]["hash"]},
                    {"pinned_count": True, "pinned_head": self.full[-1]["hash"]}, {"pinned_count": -1, "pinned_head": self.full[-1]["hash"]},
                    {"pinned_count": 0, "pinned_head": self.full[-1]["hash"]}, {"pinned_count": 6.0, "pinned_head": self.full[-1]["hash"]},
                    {"pinned_count": 6, "pinned_head": "nope"}, {"pinned_count": 6, "pinned_head": None}, {"pinned_count": 6, "pinned_head": self.full[-1]["hash"].upper()}):
            r = witness.verify_plane_log(self.full, KEY.pub_hex, **pin)
            self.assertEqual((r["ok"], r["code"]), (False, "BAD_PIN"), pin)

    def test_without_a_pin_nothing_changes(self):
        self.assertEqual(witness.verify_plane_log(self.full, KEY.pub_hex)["count"], 6)

    def test_other_refusals_still_come_first(self):
        tampered = json.loads(json.dumps(self.full))
        tampered[2]["data"]["verdict"] = "DENY"
        self.assertEqual(witness.verify_plane_log(tampered, KEY.pub_hex, **self.pin)["code"], "HASH_MISMATCH")
        self.assertEqual(witness.verify_plane_log(self.full, "zz", **self.pin)["code"], "UNPINNED_KEY")


class LedgerRemembersHeads(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "ledger.jsonl"
        self.signer = Signer.generate()
        self.ledger = WitnessLedger(self.path, self.signer)

    def tearDown(self):
        self._tmp.cleanup()

    def witness(self, entries, key=KEY, ledger=None, **kw):
        return (ledger or self.ledger).witness(entries, key.pub_hex, issued_at=AT, **kw)

    def test_a_cut_tail_is_refused_signed_nothing_and_recorded(self):
        full = log_of(6)
        self.assertIsNotNone(self.witness(full)[0])
        receipt, entry = self.witness(full[:4])
        self.assertIsNone(receipt)
        self.assertEqual((entry["outcome"], entry["code"]), ("REFUSED", "TAIL_CUT"))

    def test_a_rewritten_history_is_refused(self):
        self.witness(log_of(4))
        receipt, entry = self.witness(log_of(7, tag="b"))
        self.assertEqual((receipt, entry["code"]), (None, "HISTORY_REWRITTEN"))

    def test_an_honest_extension_is_witnessed_and_moves_the_memory(self):
        self.witness(log_of(4))
        self.assertIsNotNone(self.witness(log_of(6))[0])
        self.assertEqual(self.witness(log_of(5))[1]["code"], "TAIL_CUT")      # 5 < 6 now
        self.assertIsNotNone(self.witness(log_of(6))[0])                      # the same log again is fine

    def test_a_refusal_does_not_move_the_memory(self):
        self.witness(log_of(6))
        self.witness(log_of(2))                                               # refused
        self.assertEqual(self.witness(log_of(4))[1]["code"], "TAIL_CUT")      # still compared with 6, not 2

    def test_the_memory_is_per_plane_key(self):
        self.witness(log_of(6))
        self.assertIsNotNone(self.witness(log_of(2, key=OTHER), key=OTHER)[0])
        self.assertEqual(self.witness(log_of(3))[1]["code"], "TAIL_CUT")

    def test_the_memory_survives_a_restart(self):
        self.witness(log_of(6))
        reopened = WitnessLedger(self.path, self.signer)
        self.assertEqual(self.witness(log_of(3), ledger=reopened)[1]["code"], "TAIL_CUT")

    def test_a_caller_cannot_relax_the_memory_by_pinning_less(self):
        self.witness(log_of(6))
        receipt, entry = self.witness(log_of(3), pinned_count=3, pinned_head=log_of(3)[-1]["hash"])
        self.assertEqual((receipt, entry["code"]), (None, "TAIL_CUT"))

    def test_a_caller_pin_that_is_stricter_than_the_memory_is_enforced_too(self):
        self.witness(log_of(3))
        full = log_of(6)
        self.assertEqual(self.witness(full, pinned_count=6, pinned_head="0" * 64)[1]["code"], "HISTORY_REWRITTEN")
        self.assertIsNotNone(self.witness(full, pinned_count=6, pinned_head=full[-1]["hash"])[0])
        self.assertEqual(self.witness(log_of(4), pinned_count=6, pinned_head=full[-1]["hash"])[1]["code"], "TAIL_CUT")

    def test_the_first_sight_of_a_key_has_nothing_to_compare_with_and_says_so(self):
        receipt, entry = self.witness(log_of(3))
        self.assertEqual(entry["outcome"], "WITNESSED")
        self.assertEqual(entry["plane_log_key"], KEY.pub_hex)

    def test_an_invalid_log_is_refused_by_the_old_codes_and_an_emptied_one_is_a_cut(self):
        self.assertEqual(self.witness([])[1]["code"], "EMPTY_LOG")             # first sight: nothing was ever remembered
        self.witness(log_of(6))
        self.assertEqual(self.witness([])[1]["code"], "TAIL_CUT")              # a log that had 6 entries and now has none
        tampered = json.loads(json.dumps(log_of(6)))
        tampered[1]["data"]["verdict"] = "DENY"
        self.assertEqual(self.witness(tampered)[1]["code"], "HASH_MISMATCH")

    def test_the_receipt_records_head_and_count_so_the_next_check_can_pin_them(self):
        full = log_of(5)
        receipt, _ = self.witness(full)
        self.assertEqual((receipt["entry_count"], receipt["head_hash"]), (5, full[-1]["hash"]))


class TheMainLogsWitnessAlreadyRemembersAndRefuses(unittest.TestCase):
    """The DiligenceOS log's own witness (diligenceos.witness) has head memory; pin that behaviour for the cut-tail case."""

    def test_a_log_cut_by_one_entry_with_a_freshly_signed_shorter_head_is_refused(self):
        from diligenceos.receipt_log import ReceiptLog
        from diligenceos.signing import LOG_HEAD_DOMAIN, head_message
        from diligenceos.engine import assemble_verdict
        from diligenceos.receipt import issue_receipt
        from diligenceos.types import CheckStatus, Finding
        op = Signer.generate()
        log = ReceiptLog(None)
        for n in range(5):
            log.append(issue_receipt(subject={"name": f"S{n}"}, inputs={"n": n}, result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]),
                                     issued_at="2026-10-14T09:00:00+00:00"), now="2026-10-14T09:00:00+00:00", signer=op)

        def head(entries):
            h = entries[-1]["entry_hash"]
            return {"length": len(entries), "head_hash": h, "issuer": op.issuer_id, "cosignatures": [],
                    "signature": op.sign(LOG_HEAD_DOMAIN, head_message(len(entries), h))}

        seen = {"length": 5, "head_hash": log.entries[-1]["entry_hash"]}
        cut = log.entries[:4]
        for keep in (4, 3, 1):
            result = check_consistency(seen, log.entries[:keep], head(log.entries[:keep]), pinned_issuer=op.issuer_id)
            self.assertFalse(result.ok, keep)
        self.assertTrue(any("shorter" in e for e in check_consistency(seen, cut, head(cut), pinned_issuer=op.issuer_id).errors))
        self.assertTrue(check_consistency(seen, log.entries, head(log.entries), pinned_issuer=op.issuer_id).ok)


if __name__ == "__main__":
    unittest.main()
