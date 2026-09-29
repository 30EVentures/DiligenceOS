import copy
import io
import json
import os
import contextlib
import tempfile
import threading
import unittest
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

from auth_helpers import as_operator
from diligenceos import api, tools, webapp
from diligenceos.engine import assemble_verdict
from diligenceos.receipt import issue_receipt
from diligenceos.receipt_log import (
    GENESIS, LOG_ENTRY_DOMAIN, LogCorruptError, ReceiptLog, _entry_hash, verify_chain,
)
from diligenceos.signing import LOG_HEAD_DOMAIN, Signer, head_message
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding
from diligenceos.witness import (
    check_consistency, cosign_head, run_witness, verify_cosignature,
)

T = "2026-09-29T12:00:00+00:00"
CLEAN = [Finding("sanctions", CheckStatus.PASS)]
RID = "sha256:" + "a" * 64


def receipt(n, signer=None):
    return issue_receipt(subject={"name": f"S{n}"}, inputs={"n": n},
                         result=assemble_verdict(CLEAN), issued_at=T, signer=signer)


def signed_log(signer, count, path=None, offset=0):
    log = ReceiptLog(path)
    for n in range(offset, offset + count):
        log.append(receipt(n), now=T, signer=signer)
    return log


def head_doc(signer, log):
    length = len(log.entries)
    return {"length": length, "head_hash": log.head, "issuer": signer.issuer_id,
            "signature": signer.sign(LOG_HEAD_DOMAIN, head_message(length, log.head)),
            "cosignatures": []}


class SignedEntriesTest(unittest.TestCase):
    def setUp(self):
        self.key = Signer.generate()
        self.log = signed_log(self.key, 3)

    def test_entries_are_kinded_attributed_and_signed(self):
        e = self.log.entries[0]
        self.assertEqual((e["kind"], e["issuer"]), ("receipt", self.key.issuer_id))
        self.assertNotIn("signature", {k for k in e if k == "entry_hash"})
        self.assertEqual(verify_chain(self.log.entries, trusted_issuers=[self.key.issuer_id],
                                      require_signed=True), [])

    def test_signature_edits_and_swaps_are_caught(self):
        e = self.log.entries
        e[1]["signature"] = self.key.sign(LOG_ENTRY_DOMAIN, "sha256:" + "0" * 64)
        self.assertTrue(any("signature" in x for x in verify_chain(e)))
        e = self.log.entries
        e[1]["issuer"] = Signer.generate().issuer_id
        self.assertTrue(verify_chain(e))  # hash mismatch and signature both fail

    def test_a_resealed_forgery_by_another_key_is_untrusted(self):
        other = Signer.generate()
        forged = signed_log(other, 2).entries
        self.assertEqual(verify_chain(forged), [])  # internally fine
        errs = verify_chain(forged, trusted_issuers=[self.key.issuer_id])
        self.assertTrue(any("not trusted" in x for x in errs))

    def test_legacy_unsigned_entries_still_load_and_verify(self):
        legacy, prev = [], GENESIS
        for n in range(2):
            e = {"seq": n, "receipt_id": f"sha256:{n:064x}", "inputs_digest": f"sha256:{n + 9:064x}",
                 "outcome_digest": "sha256:" + "1" * 64, "logged_at": T, "conflict_with": None,
                 "prev_hash": prev}
            e["entry_hash"] = _entry_hash(e)
            legacy.append(e)
            prev = e["entry_hash"]
        self.assertEqual(verify_chain(legacy), [])
        self.assertTrue(any("not signed" in x for x in verify_chain(legacy, require_signed=True)))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "receipts.jsonl"
            p.write_text("\n".join(json.dumps(e) for e in legacy) + "\n")
            log = ReceiptLog(p)
            self.assertEqual(len(log.entries), 2)
            entry = log.append(receipt(50), now=T, signer=self.key)   # new signed entries extend it
            self.assertEqual(verify_chain(log.entries, trusted_issuers=[self.key.issuer_id]), [])
            self.assertEqual(entry["seq"], 2)

    def test_bad_signature_in_the_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "receipts.jsonl"
            signed_log(self.key, 2, p)
            lines = p.read_text().splitlines()
            e = json.loads(lines[0])
            e["signature"] = "ed25519:" + "0" * 128
            p.write_text("\n".join([json.dumps(e), lines[1]]) + "\n")
            with self.assertRaises(LogCorruptError):
                ReceiptLog(p)

    def test_head_at(self):
        self.assertEqual(self.log.head_at(0), GENESIS)
        self.assertEqual(self.log.head_at(3), self.log.head)
        self.assertEqual(self.log.head_at(2), self.log.entries[1]["entry_hash"])
        self.assertIsNone(self.log.head_at(4))


class RevocationLogTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_revocation_is_a_signed_attributed_log_entry(self):
        info = self.store.revoke(RID, "compromised", by="ed25519:" + "b" * 64)
        entry = self.store.log.revocation_entries()[0]
        self.assertEqual((entry["kind"], entry["target_id"], entry["reason"], entry["revoked_by"]),
                         ("revocation", RID, "compromised", "ed25519:" + "b" * 64))
        self.assertEqual((info["log_seq"], info["revoked_by"]), (entry["seq"], entry["revoked_by"]))
        self.assertEqual(verify_chain(self.store.log.entries,
                                      trusted_issuers=[self.store.signer.issuer_id], require_signed=True), [])

    def test_idempotent_and_survives_restart(self):
        self.store.revoke(RID, "first")
        self.store.revoke(RID, "second")
        self.assertEqual(len(self.store.log.revocation_entries()), 1)
        again = Store.load_or_seed(self.path)
        self.assertEqual(again.revocations[RID]["reason"], "first")
        self.assertEqual(len(again.log.revocation_entries()), 1)

    def test_revocations_do_not_disturb_receipt_indexing_or_conflicts(self):
        r = receipt(1)
        self.store.log.append(r, signer=self.store.signer)
        self.store.revoke(RID, "x")
        self.assertIsNotNone(self.store.log.lookup(r["id"]))
        self.assertEqual(self.store.log.conflicts(), [])
        self.assertEqual(len(Store.load_or_seed(self.path).log.entries), 2)

    def test_revoke_fails_closed_when_the_log_is_corrupt(self):
        self.store.revoke(RID, "x")
        log_path = self.path.with_name("receipts.jsonl")
        e = json.loads(log_path.read_text().splitlines()[0])
        e["reason"] = "rewritten"
        log_path.write_text(json.dumps(e) + "\n")
        fresh = Store.load_or_seed(self.path)
        with self.assertRaises(LogCorruptError):
            fresh.revoke("sha256:" + "c" * 64, "y")
        self.assertNotIn("sha256:" + "c" * 64, fresh.revocations)

    def test_api_revoke_records_the_caller_and_lists_signed_entries(self):
        def call(method, path, payload=None):
            payload = as_operator(self.store, path, payload)
            body = json.dumps(payload).encode() if payload is not None else b""
            status, _, out = api.handle(method, path, body, self.store)
            return status, json.loads(out)
        status, out = call("POST", "/v1/revoke", {"receipt_id": RID, "reason": "test"})
        self.assertEqual(status, 200)
        listing = call("GET", "/v1/revocations")[1]
        self.assertEqual(listing["revocations"][RID]["revoked_by"], self.store.signer.issuer_id)
        (entry,) = listing["entries"]
        self.assertEqual(entry["target_id"], RID)
        self.assertEqual(entry["issuer"], self.store.signer.issuer_id)
        self.assertEqual(verify_chain(self.store.log.entries, trusted_issuers=[entry["issuer"]]), [])
        log_path = self.path.with_name("receipts.jsonl")
        e = json.loads(log_path.read_text().splitlines()[0])
        e["logged_at"] = "1999-01-01T00:00:00+00:00"
        log_path.write_text(json.dumps(e) + "\n")
        fresh = Store.load_or_seed(self.path)
        self.assertEqual(call_with(fresh, "POST", "/v1/revoke", {"receipt_id": "sha256:" + "d" * 64, "reason": "z"})[0], 503)
        self.assertEqual(call_with(fresh, "GET", "/v1/revocations")[0], 503)


def call_with(store, method, path, payload=None):
    payload = as_operator(store, path, payload)
    body = json.dumps(payload).encode() if payload is not None else b""
    status, _, out = api.handle(method, path, body, store)
    return status, json.loads(out)


class ConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.op = Signer.generate()
        self.log = signed_log(self.op, 3)
        self.head = head_doc(self.op, self.log)
        self.seen = {"length": 3, "head_hash": self.log.head}

    def check(self, previous, entries=None, head=None):
        return check_consistency(previous, entries if entries is not None else self.log.entries,
                                 head or self.head, pinned_issuer=self.op.issuer_id)

    def test_first_sight_and_genuine_extension_are_accepted(self):
        first = self.check(None)
        self.assertEqual((first.ok, first.appended, first.length), (True, 3, 3))
        self.log.append(receipt(9), now=T, signer=self.op)
        r = self.check(self.seen, head=head_doc(self.op, self.log))
        self.assertEqual((r.ok, r.appended, r.length), (True, 1, 4))
        unchanged = signed_log(self.op, 3)
        same = check_consistency({"length": 3, "head_hash": unchanged.head}, unchanged.entries,
                                 head_doc(self.op, unchanged), pinned_issuer=self.op.issuer_id)
        self.assertEqual((same.ok, same.appended), (True, 0))
        empty = signed_log(self.op, 0)
        self.assertTrue(check_consistency(None, empty.entries, head_doc(self.op, empty),
                                          pinned_issuer=self.op.issuer_id).ok)

    def test_rewritten_history_is_refused_even_though_it_is_internally_valid(self):
        # the operator rebuilds a different, fully signed, longer log with the same key
        rewritten = signed_log(self.op, 4, offset=100)
        r = self.check(self.seen, rewritten.entries, head_doc(self.op, rewritten))
        self.assertFalse(r.ok)
        self.assertTrue(any("rewritten" in e for e in r.errors), r.errors)
        # ...yet a witness meeting it for the first time cannot tell (documented limit)
        self.assertTrue(self.check(None, rewritten.entries, head_doc(self.op, rewritten)).ok)

    def test_truncation_is_refused(self):
        short = ReceiptLog()  # same content, tail dropped
        for e in self.log.entries[:2]:
            short._entries.append(e)
        r = self.check(self.seen, short.entries, head_doc(self.op, short))
        self.assertFalse(r.ok)
        self.assertTrue(any("shorter" in e for e in r.errors), r.errors)

    def test_forged_or_foreign_or_mismatched_heads_are_refused(self):
        bad_sig = {**self.head, "signature": "ed25519:" + "0" * 128}
        self.assertFalse(self.check(None, head=bad_sig).ok)
        other = Signer.generate()
        self.assertFalse(check_consistency(None, self.log.entries, head_doc(other, self.log),
                                           pinned_issuer=self.op.issuer_id).ok)
        wrong_len = head_doc(self.op, self.log)
        wrong_len.update(length=2, signature=self.op.sign(LOG_HEAD_DOMAIN, head_message(2, self.log.head)))
        self.assertTrue(any("does not match the entries" in e for e in self.check(None, head=wrong_len).errors))

    def test_tampered_entries_are_refused(self):
        entries = self.log.entries
        entries[1]["logged_at"] = "1999-01-01T00:00:00+00:00"
        self.assertFalse(self.check(None, entries).ok)

    def test_garbage_never_raises(self):
        for entries, head in (([], None), (None, self.head), ("x", self.head), ([1], self.head), ([], {})):
            r = check_consistency(None, entries, head, pinned_issuer=self.op.issuer_id)
            self.assertFalse(r.ok)


class RunWitnessTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state = Path(self._tmp.name) / "witness.json"
        self.op, self.w = Signer.generate(), Signer.generate()
        self.log = signed_log(self.op, 2)

    def tearDown(self):
        self._tmp.cleanup()

    def fetch(self, log=None):
        log = log or self.log
        docs = {"/v1/log/head": head_doc(self.op, log), "/v1/log/entries": {"entries": log.entries}}
        return lambda path: docs[path]

    def run_w(self, log=None, submit=None):
        return run_witness(self.fetch(log), self.state, self.w, self.op.issuer_id, submit=submit)

    def test_cosigns_advances_state_and_verifies_offline(self):
        code, msg, cosig = self.run_w()
        self.assertEqual(code, 0, msg)
        self.assertTrue(verify_cosignature(cosig))
        self.assertEqual((cosig["witness"], cosig["length"], cosig["head_hash"]),
                         (self.w.issuer_id, 2, self.log.head))
        self.assertEqual(json.loads(self.state.read_text())[self.op.issuer_id]["length"], 2)
        for field, value in (("length", 9), ("head_hash", "sha256:" + "1" * 64), ("issuer", "x")):
            self.assertFalse(verify_cosignature({**cosig, field: value}), field)
        self.assertFalse(verify_cosignature({}))

    def test_a_failed_round_leaves_state_untouched(self):
        self.run_w()
        before = self.state.read_text()
        rewritten = signed_log(self.op, 3, offset=500)
        code, msg, cosig = self.run_w(rewritten)
        self.assertEqual(code, 3)
        self.assertTrue(msg.startswith("INCONSISTENT"))
        self.assertIsNone(cosig)
        self.assertEqual(self.state.read_text(), before)

    def test_first_round_failure_writes_no_state(self):
        bad = signed_log(self.op, 2)
        bad.entries  # noqa
        docs = {"/v1/log/head": {**head_doc(self.op, bad), "signature": "ed25519:" + "0" * 128},
                "/v1/log/entries": {"entries": bad.entries}}
        code, _, _ = run_witness(lambda p: docs[p], self.state, self.w, self.op.issuer_id)
        self.assertEqual(code, 3)
        self.assertFalse(self.state.exists())

    def test_submit_hook_is_reported(self):
        code, msg, _ = self.run_w(submit=lambda c: "stored")
        self.assertEqual(code, 0)
        self.assertIn("stored", msg)


class CosignApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)
        self.w = Signer.generate()
        self._old = os.environ.pop("DILIGENCEOS_WITNESSES", None)
        api.handle("POST", "/v1/verdict", json.dumps(
            {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}}).encode(), self.store)

    def tearDown(self):
        os.environ.pop("DILIGENCEOS_WITNESSES", None)
        if self._old is not None:
            os.environ["DILIGENCEOS_WITNESSES"] = self._old
        self._tmp.cleanup()

    def call(self, method, path, payload=None, store=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        status, _, out = api.handle(method, path, body, store or self.store)
        return status, json.loads(out)

    def cosig(self, **over):
        head = self.call("GET", "/v1/log/head")[1]
        return {**cosign_head(self.w, head["issuer"], head["length"], head["head_hash"]), **over}

    def test_nothing_is_accepted_until_witnesses_are_configured(self):
        status, out = self.call("POST", "/v1/log/cosign", self.cosig())
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))

    def test_listed_witness_is_stored_shown_and_persisted(self):
        os.environ["DILIGENCEOS_WITNESSES"] = f"{self.w.issuer_id}, {Signer.generate().issuer_id}"
        c = self.cosig()
        self.assertEqual(self.call("POST", "/v1/log/cosign", c), (200, {"accepted": True}))
        head = self.call("GET", "/v1/log/head")[1]
        self.assertEqual(head["cosignatures"], [c])
        self.assertTrue(all(verify_cosignature(x) for x in head["cosignatures"]))
        reopened = Store.load_or_seed(self.path)
        self.assertEqual(self.call("GET", "/v1/log/head", store=reopened)[1]["cosignatures"], [c])

    def test_rejections(self):
        os.environ["DILIGENCEOS_WITNESSES"] = self.w.issuer_id
        stranger = Signer.generate()
        head = self.call("GET", "/v1/log/head")[1]
        cases = {
            "unlisted witness": cosign_head(stranger, head["issuer"], head["length"], head["head_hash"]),
            "bad signature": self.cosig(signature="ed25519:" + "0" * 128),
            "head the log never had": cosign_head(self.w, head["issuer"], head["length"], "sha256:" + "9" * 64),
            "length the log never had": cosign_head(self.w, head["issuer"], 99, head["head_hash"]),
            "other issuer": cosign_head(self.w, "ed25519:" + "e" * 64, head["length"], head["head_hash"]),
        }
        for label, doc in cases.items():
            status, out = self.call("POST", "/v1/log/cosign", doc)
            self.assertEqual((status, out["error"]["code"]), (400, "invalid_request"), label)
        self.assertEqual(self.call("POST", "/v1/log/cosign", [1])[0], 400)
        self.assertEqual(self.call("GET", "/v1/log/head")[1]["cosignatures"], [])

    def test_a_cosignature_is_for_its_head_only(self):
        os.environ["DILIGENCEOS_WITNESSES"] = self.w.issuer_id
        self.call("POST", "/v1/log/cosign", self.cosig())
        self.call("POST", "/v1/verdict", {"subject": {"name": "Other", "registration_id": "X"}})
        self.assertEqual(self.call("GET", "/v1/log/head")[1]["cosignatures"], [])  # head moved on


class WitnessCliTest(unittest.TestCase):
    """A real server on a real socket, the real CLI over real HTTP."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self._old = os.environ.get("DILIGENCEOS_DATA_PATH")
        os.environ["DILIGENCEOS_DATA_PATH"] = str(self.dir / "store.json")
        os.environ["DILIGENCEOS_WITNESSES"] = ""
        webapp._store = None

        class Quiet(WSGIRequestHandler):
            def log_message(self, *a):
                pass

        self.server = make_server("127.0.0.1", 0, webapp.app, handler_class=Quiet)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        os.environ.pop("DILIGENCEOS_WITNESSES", None)
        if self._old is None:
            os.environ.pop("DILIGENCEOS_DATA_PATH", None)
        else:
            os.environ["DILIGENCEOS_DATA_PATH"] = self._old
        webapp._store = None
        self._tmp.cleanup()

    def witness(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        store = webapp._get_store()
        argv = ["witness", "--url", self.url, "--issuer", store.signer.issuer_id,
                "--key", str(self.dir / "w.key"), "--state", str(self.dir / "w.json"), *extra]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tools.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_witness_over_http_cosigns_and_submits(self):
        store = webapp._get_store()
        store.log.append(receipt(1), now=T, signer=store.signer)
        w_id = Signer.load_or_create(self.dir / "w.key").issuer_id
        os.environ["DILIGENCEOS_WITNESSES"] = w_id
        code, out, _ = self.witness("--submit")
        self.assertEqual(code, 0, out)
        doc = json.loads(out)
        self.assertTrue(doc["ok"] and verify_cosignature(doc["cosignature"]))
        self.assertIn("accepted", doc["message"])
        head = api.handle("GET", "/v1/log/head", b"", store)
        self.assertEqual(json.loads(head[2])["cosignatures"], [doc["cosignature"]])
        store.log.append(receipt(2), now=T, signer=store.signer)      # log grows: still consistent
        code, out, _ = self.witness()
        self.assertEqual((code, json.loads(out)["ok"]), (0, True))

    def test_wrong_pinned_issuer_and_unreachable_server_are_reported(self):
        out, err = io.StringIO(), io.StringIO()
        base = ["witness", "--key", str(self.dir / "w.key"), "--state", str(self.dir / "w.json")]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tools.main([*base, "--url", self.url, "--issuer", "ed25519:" + "a" * 64])
        self.assertEqual(code, 3)
        self.assertIn("not from the issuer", out.getvalue())
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tools.main([*base, "--url", "http://127.0.0.1:1", "--issuer", "ed25519:" + "a" * 64])
        self.assertEqual(code, 2)
        self.assertIn("could not reach", err.getvalue())


if __name__ == "__main__":
    unittest.main()
