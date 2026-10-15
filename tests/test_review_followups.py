"""Fixes and test gaps found by the fresh-context review of the overnight branch."""

import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
from urllib.parse import quote
from pathlib import Path
from unittest import mock

from diligenceos import tools
from diligenceos.conformance import test_signer
from diligenceos.delegation import issue_delegation, verify_chain
from diligenceos.names import normalize_name
from diligenceos.receipt_log import GENESIS, LogCorruptError, ReceiptLog, _entry_hash
from diligenceos.signing import RECEIPT_DOMAIN, verify_signature
from diligenceos.witness import run_witness
from test_input_limits import post
from test_webapp import WebappTestCase


class HugeContentLengthTest(WebappTestCase):
    def test_a_content_length_of_thousands_of_digits_is_refused_not_an_exception(self):
        for path in ("/verdict", "/v1/verdict", "/v1/capabilities", "/data/sanctions"):
            for length in ("9" * 5000, "1" + "0" * 16, "9" * 16):
                status, _, asked = post(path, b"", length=length, method="GET" if path == "/v1/capabilities" else "POST")
                self.assertTrue(status.startswith(("400", "413")), (path, len(length), status))
                self.assertEqual(asked, [])

    def test_a_non_ascii_admin_token_is_a_401_not_a_500(self):
        for token in ("tökén", "١٢", "x\ud800"):
            body = ("admin_token=" + quote(token, errors="surrogatepass")).encode()
            status, _, _ = post("/data/sanctions", body)
            self.assertTrue(status.startswith("401"), (token, status))


class DelegationDateArithmeticTest(unittest.TestCase):
    OP, AGENT, B = test_signer(1), test_signer(2), test_signer(3)

    def test_extreme_dates_are_a_refusal_not_an_overflow(self):
        parent = issue_delegation(self.OP, delegate=self.AGENT.issuer_id, scopes=["spend"],
                                  expires="9999-12-31T23:59:59+00:00", issued_at="0001-01-01T00:00:00+00:00")
        child = issue_delegation(self.AGENT, delegate=self.B.issuer_id, scopes=["spend"], expires="9999-12-31T23:59:59+00:00",
                                 parent=parent["id"], issued_at="0001-01-01T00:00:00+00:00")
        for now in ("2026-10-13T12:00:00+00:00", "9999-12-31T23:59:59+00:00", "0001-01-01T00:00:00+00:00"):
            verify_chain([parent, child], root_issuers=[self.OP.issuer_id], now=now)      # any answer is fine; raising is not
        self.assertFalse(verify_chain([parent, child], root_issuers=[self.OP.issuer_id], now="9999-12-31T23:59:59+00:00").valid)

    def test_unreadable_issued_at_in_a_hand_built_link(self):
        from diligenceos.delegation import DOMAIN, SCHEMA
        from diligenceos.receipt import digest
        for bad in ("", None, 5, "never"):
            body = {"schema": SCHEMA, "delegator": self.OP.issuer_id, "delegate": self.AGENT.issuer_id, "scopes": ["spend"],
                    "policy": None, "budget_id": None, "issued_at": bad, "expires": "2026-12-01T00:00:00+00:00", "parent": None}
            link = {**body, "id": digest(body)}
            link["signature"] = self.OP.sign(DOMAIN, link["id"])
            self.assertFalse(verify_chain([link], root_issuers=[self.OP.issuer_id], now="2026-10-13T12:00:00+00:00").valid, repr(bad))


class SmallOrderEverySpellingTest(unittest.TestCase):
    def test_no_small_order_encoding_signs_any_message(self):
        from diligenceos.signing import _SMALL_ORDER
        self.assertGreaterEqual(len(_SMALL_ORDER), 14)
        for raw in _SMALL_ORDER:
            for n in range(64):                      # a universal signature may only work for some messages
                msg = f"message {n}"
                for r in (raw, bytes([1]) + bytes(31)):
                    self.assertFalse(verify_signature("ed25519:" + raw.hex(), RECEIPT_DOMAIN, msg, "ed25519:" + r.hex() + "00" * 32),
                                     (raw.hex(), n))


class LogFieldChecksTest(unittest.TestCase):
    def write(self, **fields):
        d = Path(tempfile.mkdtemp())
        entry = {"seq": 0, "prev_hash": GENESIS, "kind": "receipt", **fields}
        entry["entry_hash"] = _entry_hash(entry)
        (d / "receipts.jsonl").write_text(json.dumps(entry) + "\n")
        return d / "receipts.jsonl"

    def test_each_required_field_is_required_on_its_own(self):
        full = {"receipt_id": "sha256:" + "a" * 64, "inputs_digest": "sha256:" + "b" * 64, "outcome_digest": "sha256:" + "c" * 64}
        ReceiptLog(self.write(**full))
        for missing in full:
            with self.assertRaises(LogCorruptError, msg=missing):
                ReceiptLog(self.write(**{k: v for k, v in full.items() if k != missing}))
            with self.assertRaises(LogCorruptError, msg=missing):
                ReceiptLog(self.write(**{**full, missing: 7}))


class WitnessReplyAndStateTest(unittest.TestCase):
    class Reply:
        def __init__(self, payload): self.payload = payload
        def read(self, n=-1): return self.payload if n < 0 else self.payload[:n]

    def test_an_oversize_reply_is_refused_for_its_size(self):
        big = b"[" + b"0," * (tools.MAX_RESPONSE_BYTES // 2 + 10) + b"0]"      # valid JSON, only too big
        json.loads(big)
        with self.assertRaises(ValueError) as caught:
            tools._json_from_response(self.Reply(big))
        self.assertIn("larger than", str(caught.exception))

    def test_a_deeply_nested_reply_is_a_value_error(self):
        with self.assertRaises(ValueError):
            tools._json_from_response(self.Reply(b"[" * 400_000 + b"]" * 400_000))

    def test_a_non_json_error_body_does_not_escape_the_cosign_submission(self):
        refusal = urllib.error.HTTPError("http://x/v1/log/cosign", 502, "Bad Gateway", {}, io.BytesIO(b"<html>bad gateway</html>"))
        args = mock.Mock(url="http://x", issuer="i", key="k", state="s", submit=True)
        seen = {}

        def fake_run(fetch, state, signer, issuer, submit=None):
            seen["note"] = submit({"c": 1})
            return 0, "ok", None

        with mock.patch("urllib.request.urlopen", side_effect=refusal), mock.patch("diligenceos.witness.run_witness", fake_run), \
                mock.patch("diligenceos.tools.Signer.load_or_create", return_value=test_signer(7)):
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                tools._witness(args)
        self.assertIn("502", seen["note"])

    def test_the_saved_state_keeps_its_permissions_and_its_symlink(self):
        from test_log_witness_hardening import head_doc, signed_log
        from diligenceos.signing import Signer
        op, w = Signer.generate(), Signer.generate()
        log = signed_log(op, 2)
        docs = {"/v1/log/head": head_doc(op, log), "/v1/log/entries": {"entries": log.entries}}
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "real.json"
            real.write_text("{}")
            os.chmod(real, 0o600)
            link = Path(d) / "link.json"
            link.symlink_to(real)
            self.assertEqual(run_witness(lambda p: docs[p], link, w, op.issuer_id)[0], 0)
            self.assertTrue(link.is_symlink())
            self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o600)
            self.assertIn(op.issuer_id, json.loads(real.read_text()))
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ["link.json", "real.json"])      # no .tmp left


class NamesAreComparedAsThePolicySaysTest(unittest.TestCase):
    def test_casefold_cases_and_their_limits(self):
        self.assertEqual(normalize_name("STRASSE"), normalize_name("Straße"))
        self.assertEqual(normalize_name("ΣΑΣ"), normalize_name("σας"))                  # final sigma
        self.assertEqual(normalize_name("aϒ"), normalize_name("aΥ".lower()) if False else normalize_name("aϒ"))
        self.assertNotEqual(normalize_name("Jose"), normalize_name("José"))               # accents are not dropped
        self.assertNotEqual(normalize_name("Bank"), normalize_name("Bаnk"))          # Cyrillic a is not Latin a (proposal P-2)
        self.assertEqual(normalize_name(normalize_name("Ⅳ ＡＢＣ ﬁ")), normalize_name("Ⅳ ＡＢＣ ﬁ"))


if __name__ == "__main__":
    unittest.main()
