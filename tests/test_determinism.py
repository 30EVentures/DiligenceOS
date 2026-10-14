"""Round 3 of the overnight review: same input, same bytes, on any machine; and one subject,
one spelling, whatever Unicode form or invisible character the caller used."""

import json
import os
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path

from diligenceos.identity import RegistryRecord, check_identity
from diligenceos.sanctions import SanctionsEntry, SanctionsList, screen_subject
from diligenceos.track_record import DeliveryRecord, Ledger, check_track_record
from diligenceos.types import CheckStatus

ROOT = Path(__file__).resolve().parent.parent


def run_python(args, env_extra, **kw):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONUTF8", "LC_ALL", "LANG", "PYTHONHASHSEED")}
    env.update(env_extra)
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run([sys.executable, *args], capture_output=True, env=env, cwd=ROOT, timeout=60, **kw)


ASCII_LOCALE = {"LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
UTF8 = {"PYTHONUTF8": "1"}
NAME = "Банк Тест Ltd"          # Cyrillic: not representable in an ASCII or Latin-1 locale


class FilesAreUtf8OnEveryMachineTest(unittest.TestCase):
    """A file the user hands us is UTF-8. Reading it with the machine's locale encoding made the
    screening depend on where it ran (an error under C, silent mojibake under cp1252)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.sanctions = self.dir / "sanctions.json"
        self.sanctions.write_text(json.dumps([{"name": NAME, "program": "TEST", "aliases": ["Тест"]}], ensure_ascii=False),
                                  encoding="utf-8")
        self.request = self.dir / "request.json"
        self.request.write_text(json.dumps({
            "subject": {"name": NAME, "registration_id": "R1"}, "sanctions_list_path": str(self.sanctions),
            "registry": {"R1": {"name": NAME, "status": "active", "jurisdiction": "XX"}},
        }, ensure_ascii=False), encoding="utf-8")

    def test_sanctions_file_loads_the_same_under_any_locale(self):
        code = ("import sys; from diligenceos.sanctions import load_sanctions_list as l; "
                "e = l(sys.argv[1]).entries[0]; print(ascii((e.name, e.aliases)))")
        out = {}
        for label, env in (("ascii", ASCII_LOCALE), ("utf8", UTF8)):
            done = run_python(["-c", code, str(self.sanctions)], env, text=True)
            self.assertEqual(done.returncode, 0, (label, done.stderr[-300:]))
            out[label] = done.stdout
        self.assertEqual(out["ascii"], out["utf8"])
        self.assertIn("\\u0411", out["ascii"])

    def test_batch_mode_prints_the_same_bytes_under_any_locale(self):
        out = {}
        for label, env in (("ascii", ASCII_LOCALE), ("utf8", UTF8)):
            done = run_python(["-m", "diligenceos", str(self.request)], env)
            self.assertEqual(done.returncode, 0, (label, done.stderr[-300:]))
            out[label] = done.stdout
        self.assertEqual(out["ascii"], out["utf8"])
        self.assertIn(b"RED_FLAG", out["ascii"])             # the Cyrillic name really was screened

    def test_the_cli_reads_json_files_as_utf8_under_any_locale(self):
        code = ("import sys; from diligenceos import tools; print(ascii(tools._read_json(sys.argv[1])))")
        out = {label: run_python(["-c", code, str(self.request)], env, text=True) for label, env in
               (("ascii", ASCII_LOCALE), ("utf8", UTF8))}
        for label, done in out.items():
            self.assertEqual(done.returncode, 0, (label, done.stderr[-300:]))
        self.assertEqual(out["ascii"].stdout, out["utf8"].stdout)


class SameBytesOnEveryRunTest(unittest.TestCase):
    SCRIPT = """
import json
from diligenceos.conformance import test_signer
from diligenceos.engine import assemble_verdict
from diligenceos.policy import Policy, narrow, effective_policy
from diligenceos.receipt import issue_receipt
from diligenceos.types import CheckStatus, Finding, Money, Verdict
r = issue_receipt(subject={"name": "S", "registration_id": "R"}, inputs={"a": 1, "z": [3, 2, 1]},
                  result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]),
                  transaction={"amount_minor": 5, "currency": "USD"}, issued_at="2026-10-01T00:00:00+00:00",
                  ttl_seconds=60, signer=test_signer(1))
p = Policy(Money(100, "USD"), frozenset({Verdict.PROCEED, Verdict.HOLD}), 50)
q = Policy(Money(50, "USD"), frozenset({Verdict.HOLD, Verdict.PROCEED}), 60)
print(json.dumps([r, p.to_dict(), narrow(p, q).to_dict(), effective_policy([p, q]).to_dict()], sort_keys=True))
"""

    def test_receipts_and_policies_do_not_depend_on_the_hash_seed(self):
        outs = {run_python(["-c", self.SCRIPT], {"PYTHONHASHSEED": str(seed)}, text=True).stdout for seed in (0, 1, 7, 12345)}
        self.assertEqual(len(outs), 1)
        self.assertIn("diligenceos.receipt/1", next(iter(outs)))


class OneSubjectOneSpellingTest(unittest.TestCase):
    """Screening compares names. Two spellings of one name (composed/decomposed accents, a
    full-width letter, an invisible character, a stray tab) must not be two different subjects."""

    BASE = "José Ramírez Holdings"

    def listed(self, name=BASE):
        return SanctionsList((SanctionsEntry(name, "TEST", ("Los Hermanos",)),))

    def variants(self):
        nfd = unicodedata.normalize("NFD", self.BASE)
        self.assertNotEqual(nfd, self.BASE)
        return {
            "decomposed accents": nfd,
            "full-width letters": "Ｊosé Ramírez Holdings",
            "zero-width space": "Jo​sé Ramírez Holdings",
            "soft hyphen": "José Ramí­rez Holdings",
            "no-break space": "José Ramírez Holdings",
            "tab and double space": "José\tRamírez  Holdings",
            "word joiner and BOM": "﻿José Ramírez⁠ Holdings",
            "case": "JOSÉ RAMÍREZ HOLDINGS",
        }

    def test_sanctions_catch_every_spelling_of_a_listed_name_and_alias(self):
        for label, name in self.variants().items():
            self.assertIs(screen_subject(name, self.listed()).status, CheckStatus.FLAG, label)
            self.assertIs(screen_subject(name, self.listed(name)).status, CheckStatus.FLAG, label)   # and as the listed form
        self.assertIs(screen_subject("Los Hermanos", self.listed()).status, CheckStatus.FLAG)

    def test_different_names_still_do_not_match(self):
        for other in ("José Ramírez Holding", "Jose Ramirez Holdings", "Ramírez José Holdings", ""):
            self.assertIs(screen_subject(other, self.listed()).status, CheckStatus.PASS, other)

    def test_the_cited_quote_still_comes_from_the_source_text(self):
        from diligenceos.evidence import verify_evidence
        sl = self.listed()
        finding = screen_subject(unicodedata.normalize("NFD", self.BASE), sl)
        self.assertEqual(verify_evidence(finding.evidence[0], sl.source_text()), [])

    def test_identity_compares_names_the_same_way(self):
        rec = RegistryRecord(self.BASE, "R1", "active", "XX")
        for label, name in self.variants().items():
            self.assertIs(check_identity(name, "R1", lambda _: rec).status, CheckStatus.PASS, label)

    def test_track_record_is_found_under_every_spelling(self):
        ledger = Ledger()
        for _ in range(3):
            ledger.record(DeliveryRecord(self.BASE, on_time=False))
        for label, name in self.variants().items():
            self.assertIs(check_track_record(name, ledger).status, CheckStatus.FLAG, label)
        self.assertIs(check_track_record("Someone Else", ledger).status, CheckStatus.PASS)


if __name__ == "__main__":
    unittest.main()
