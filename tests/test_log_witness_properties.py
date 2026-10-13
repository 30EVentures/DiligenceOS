"""Round 8 of the overnight review: properties of the log and the witness, tried on many random
logs rather than the few examples a person thinks of. An honest append-only history is accepted from
every earlier point; every single way of rewriting it that this code claims to detect is detected."""

import copy
import random
import unittest

from diligenceos.conformance import test_signer
from diligenceos.engine import assemble_verdict
from diligenceos.receipt import issue_receipt
from diligenceos.receipt_log import GENESIS, ReceiptLog, verify_chain
from diligenceos.signing import LOG_HEAD_DOMAIN, head_message
from diligenceos.types import CheckStatus, Finding
from diligenceos.witness import check_consistency

OP, OTHER = test_signer(1), test_signer(2)
T = "2026-10-13T11:00:00+00:00"


def receipt(tag):
    return issue_receipt(subject={"name": f"S{tag}", "registration_id": "R"}, inputs={"tag": tag},
                         result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]), issued_at=T)


def random_log(rnd, signer=OP, tag="a", length=None):
    log = ReceiptLog(None)
    made = []
    for i in range(length if length is not None else rnd.randint(1, 9)):
        if made and rnd.random() < 0.25:
            log.append_revocation(rnd.choice(made)["id"], f"reason {i}", signer.issuer_id, now=T, signer=signer)
        else:
            made.append(receipt(f"{tag}{i}-{rnd.random()}"))
            log.append(made[-1], now=T, signer=signer)
    return log


def head_of(entries, signer=OP):
    head_hash = entries[-1]["entry_hash"] if entries else GENESIS
    return {"length": len(entries), "head_hash": head_hash, "issuer": signer.issuer_id, "cosignatures": [],
            "signature": signer.sign(LOG_HEAD_DOMAIN, head_message(len(entries), head_hash))}


def judge(previous, entries, head=None, signer=OP):
    return check_consistency(previous, entries, head or head_of(entries, signer), pinned_issuer=signer.issuer_id)


class HonestHistoryTest(unittest.TestCase):
    def test_every_honest_extension_is_accepted_from_every_earlier_point(self):
        rnd = random.Random(11)
        for _ in range(40):
            log = random_log(rnd)
            entries = log.entries
            self.assertEqual(verify_chain(entries, trusted_issuers=[OP.issuer_id], require_signed=True), [])
            for k in range(len(entries) + 1):
                previous = {"length": k, "head_hash": entries[k - 1]["entry_hash"] if k else GENESIS}
                result = judge(previous, entries)
                self.assertTrue(result.ok, (k, len(entries), result.errors))
                self.assertEqual(result.appended, len(entries) - k)
            self.assertTrue(judge(None, entries).ok)


class RewrittenHistoryTest(unittest.TestCase):
    """Each rewrite below is internally consistent where it can be (re-hashed and re-signed by the
    operator's own key, which the operator has), so only the witness's memory can catch it."""

    def rewrite_and_judge(self, entries, rewritten, seen):
        previous = {"length": seen, "head_hash": entries[seen - 1]["entry_hash"] if seen else GENESIS}
        return judge(previous, rewritten, head_of(rewritten))

    def test_truncation_below_what_was_seen(self):
        rnd = random.Random(12)
        for _ in range(40):
            entries = random_log(rnd, length=rnd.randint(2, 9)).entries
            seen = rnd.randint(2, len(entries))
            cut = rnd.randint(0, seen - 1)
            self.assertFalse(self.rewrite_and_judge(entries, entries[:cut], seen).ok)

    def test_a_different_history_of_the_same_or_greater_length(self):
        rnd = random.Random(13)
        for _ in range(40):
            entries = random_log(rnd, tag="x", length=rnd.randint(2, 9)).entries
            seen = rnd.randint(1, len(entries))
            forked = random_log(rnd, tag="y", length=len(entries) + rnd.randint(0, 3)).entries
            self.assertFalse(self.rewrite_and_judge(entries, forked, seen).ok)

    def test_one_entry_replaced_before_the_seen_point(self):
        rnd = random.Random(14)
        for _ in range(40):
            base = random_log(rnd, tag="x", length=rnd.randint(3, 9))
            entries = base.entries
            seen = len(entries)
            at = rnd.randrange(seen)
            # the operator rebuilds the log with one receipt different, re-hashing and re-signing everything after it
            rebuilt = ReceiptLog(None)
            for i, entry in enumerate(entries):
                if i == at:
                    rebuilt.append(receipt(f"swapped-{rnd.random()}"), now=T, signer=OP)
                elif entry["kind"] == "receipt":
                    rebuilt.append(receipt(f"copy{i}-{rnd.random()}"), now=T, signer=OP)
                else:
                    rebuilt.append_revocation("sha256:" + "0" * 64, "r", OP.issuer_id, now=T, signer=OP)
            self.assertTrue(verify_chain(rebuilt.entries, require_signed=True) == [], "the rewrite is internally valid")
            self.assertFalse(self.rewrite_and_judge(entries, rebuilt.entries, seen).ok)

    def test_reordered_duplicated_and_dropped_entries_break_the_chain(self):
        rnd = random.Random(15)
        for _ in range(60):
            entries = random_log(rnd, length=rnd.randint(3, 9)).entries
            mutated = copy.deepcopy(entries)
            how = rnd.choice(["swap", "duplicate", "drop", "reseq"])
            i, j = rnd.sample(range(len(mutated)), 2)
            if how == "swap":
                mutated[i], mutated[j] = mutated[j], mutated[i]
            elif how == "duplicate":
                mutated.insert(i, copy.deepcopy(mutated[j]))
            elif how == "drop" and i < len(mutated) - 1:
                del mutated[i]
            else:
                mutated[i]["seq"] = mutated[j]["seq"] + 1000
            self.assertNotEqual(verify_chain(mutated, trusted_issuers=[OP.issuer_id], require_signed=True), [], how)
            self.assertFalse(judge(None, mutated, head_of(entries)).ok, how)

    def test_every_single_field_edit_of_a_signed_entry_is_caught(self):
        rnd = random.Random(16)
        for _ in range(30):
            entries = random_log(rnd, length=rnd.randint(2, 6)).entries
            for index, entry in enumerate(entries):
                for field in list(entry):
                    mutated = copy.deepcopy(entries)
                    mutated[index][field] = "tampered" if isinstance(entry[field], str) else 12345
                    self.assertNotEqual(verify_chain(mutated, trusted_issuers=[OP.issuer_id]), [], (index, field))

    def test_entries_signed_by_another_key_are_not_the_pinned_issuers(self):
        rnd = random.Random(17)
        foreign = random_log(rnd, signer=OTHER, length=4).entries
        result = check_consistency(None, foreign, head_of(foreign, OP), pinned_issuer=OP.issuer_id)
        self.assertFalse(result.ok)
        self.assertFalse(check_consistency(None, foreign, head_of(foreign, OTHER), pinned_issuer=OP.issuer_id).ok)

    def test_a_head_whose_signature_is_not_the_pinned_issuers_is_refused(self):
        rnd = random.Random(19)
        entries = random_log(rnd, length=4).entries
        good = head_of(entries)
        self.assertTrue(judge(None, entries, good).ok)
        stranger = head_of(entries, OTHER)
        for label, head in (
            ("signed by another key, claiming the pinned issuer", {**good, "signature": stranger["signature"]}),
            ("another issuer entirely", stranger),
            ("signature for a different length", {**good, "signature": head_of(entries[:-1])["signature"]}),
            ("signature removed", {k: v for k, v in good.items() if k != "signature"}),
            ("signature garbage", {**good, "signature": "ed25519:" + "0" * 128}),
            ("length as a string", {**good, "length": str(good["length"])}),
        ):
            self.assertFalse(judge(None, entries, head).ok, label)

    def test_a_head_that_describes_a_different_log_than_the_entries_served(self):
        rnd = random.Random(18)
        for _ in range(30):
            entries = random_log(rnd, length=rnd.randint(2, 8)).entries
            other = random_log(rnd, tag="z", length=len(entries)).entries
            self.assertFalse(judge(None, entries, head_of(other)).ok)
            self.assertFalse(judge(None, entries, head_of(entries[:-1])).ok)
            self.assertFalse(judge(None, entries[:-1], head_of(entries)).ok)


if __name__ == "__main__":
    unittest.main()
