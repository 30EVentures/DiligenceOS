"""The sanctions list is a file a human downloads on purpose, checked before it is used, and every `pass` says what it
screened. Nothing here touches the network: the downloader takes the fetch function as an argument."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from diligenceos import api, sdn_ingest, tools
from diligenceos.sanctions import SanctionsEntry, SanctionsList, screen_subject
from diligenceos.sdn_ingest import SdnRefreshError, SdnUnavailable, load_verified_sdn, refresh_sdn
from diligenceos.store import Store
from diligenceos.types import CheckStatus

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "golden" / "sdn_sample.csv"
CSV = FIXTURE.read_bytes()
NOW = "2026-10-16T09:00:00+00:00"


def row(n, name, aka=""):
    remarks = f"a.k.a. '{aka}'; " if aka else ""
    return f'"{n}","{name}","-0-","TEST-PROGRAM","-0-","-0-","-0-","-0-","-0-","-0-","-0-","{remarks}Testland."\n'


BIG = "".join(row(20000 + i, f"FICTIONAL ENTITY {i} LTD") for i in range(1200)) + row(30001, "ABDALLAH, Salim", "S. ABDALLAH") + row(30002, "NOVAK, Jan, Jr.")
BIG = BIG.encode()


def fetcher(status=200, body=BIG, seen=None):
    def fetch(url, max_bytes):
        if seen is not None:
            seen.append((url, max_bytes))
        if isinstance(body, Exception):
            raise body
        return status, body
    return fetch


class RefreshWritesVerifiedFiles(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def refresh(self, **kw):
        kw.setdefault("fetch", fetcher())
        kw.setdefault("now", NOW)
        return refresh_sdn(self.dir, **kw)

    def test_a_good_download_is_saved_with_its_provenance(self):
        seen = []
        meta = self.refresh(fetch=fetcher(seen=seen))
        self.assertEqual(seen[0][0], sdn_ingest.DEFAULT_SDN_URL)
        self.assertEqual((meta["source"], meta["retrieved_at"], meta["entries"], meta["bytes"]), (sdn_ingest.DEFAULT_SDN_URL, NOW, 1202, len(BIG)))
        self.assertEqual(meta["sha256"], hashlib.sha256((self.dir / "sdn.csv").read_bytes()).hexdigest())
        self.assertEqual(json.loads((self.dir / "sdn.meta.json").read_text()), meta)
        sanctions_list, loaded = load_verified_sdn(self.dir)
        self.assertEqual((len(sanctions_list.entries), loaded), (1202, meta))

    def test_nothing_is_loaded_until_something_was_downloaded(self):
        self.assertEqual(load_verified_sdn(self.dir), (None, None))

    def refused(self, code, **kw):
        with self.assertRaises(SdnRefreshError) as caught:
            self.refresh(**kw)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), [], "a refused download must leave nothing behind")

    def test_every_way_a_download_can_be_wrong_is_refused_and_writes_nothing(self):
        self.refused("HTTP_STATUS", fetch=fetcher(status=404, body=b"not found"))
        self.refused("HTTP_STATUS", fetch=fetcher(status=500, body=BIG))
        self.refused("HTTP_STATUS", fetch=fetcher(status=204, body=b""))
        self.refused("FETCH_FAILED", fetch=fetcher(body=OSError("down")))
        self.refused("FETCH_FAILED", fetch=fetcher(body=TimeoutError()))
        self.refused("EMPTY", fetch=fetcher(body=b""))
        self.refused("EMPTY", fetch=fetcher(body=b"   \n"))
        self.refused("TOO_LARGE", fetch=fetcher(body=b"x" * 101), max_bytes=100)
        self.refused("TOO_FEW_ENTRIES", fetch=fetcher(body=b"<html><body>Service unavailable</body></html>"))
        self.refused("TOO_FEW_ENTRIES", fetch=fetcher(body=CSV))             # a real format, but only 3 rows: not the list
        self.refused("NOT_TEXT", fetch=fetcher(body=BIG + b"\xff\xfe"))
        self.refused("NOT_TEXT", fetch=fetcher(body=b"\x00" * 5000))

    def test_the_url_must_be_https(self):
        for url in ("http://sanctionslistservice.ofac.treas.gov/x.csv", "file:///etc/passwd", "ftp://example.com/x", "", None, 5, "https://", "https://u:p@example.com/x"):
            self.refused("BAD_URL", url=url)

    def test_a_non_utf8_file_can_be_read_with_a_named_encoding_and_is_stored_as_utf8(self):
        latin = row(1, "GARCÍA, José", "J. GARCÍA").encode("cp1252") + BIG
        self.refused("NOT_TEXT", fetch=fetcher(body=latin))
        for bad in ("nonsense-encoding", "", None, 5):
            self.refused("BAD_ENCODING", encoding=bad)
        meta = self.refresh(fetch=fetcher(body=latin), encoding="cp1252")
        self.assertEqual(meta["entries"], 1203)
        (self.dir / "sdn.csv").read_bytes().decode("utf-8")
        sanctions_list, _ = load_verified_sdn(self.dir)
        self.assertIsNotNone(sanctions_list.match("José García"))

    def test_a_failed_refresh_keeps_the_previous_good_list(self):
        old = self.refresh()
        before = {p.name: p.read_bytes() for p in self.dir.iterdir()}
        for bad in (fetcher(status=503, body=b"x"), fetcher(body=b"<html>"), fetcher(body=OSError("down"))):
            with self.assertRaises(SdnRefreshError):
                self.refresh(fetch=bad)
        self.assertEqual({p.name: p.read_bytes() for p in self.dir.iterdir()}, before)
        self.assertEqual(load_verified_sdn(self.dir)[1], old)

    def test_a_refresh_replaces_the_list_atomically_and_records_the_new_provenance(self):
        self.refresh()
        newer = BIG + row(40001, "NEW ENTRY LTD").encode()
        meta = self.refresh(fetch=fetcher(body=newer), now="2026-10-17T09:00:00+00:00")
        self.assertEqual((meta["entries"], meta["retrieved_at"]), (1203, "2026-10-17T09:00:00+00:00"))
        self.assertEqual(load_verified_sdn(self.dir)[1], meta)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["sdn.csv", "sdn.meta.json"])


class AFileThatIsNotWhatWasRecordedIsNeverUsed(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        refresh_sdn(self.dir, fetch=fetcher(), now=NOW)

    def tearDown(self):
        self._tmp.cleanup()

    def unavailable(self):
        with self.assertRaises(SdnUnavailable):
            load_verified_sdn(self.dir)

    def test_an_edited_list_is_refused(self):
        path = self.dir / "sdn.csv"
        path.write_bytes(path.read_bytes().replace(b"FICTIONAL ENTITY 5 LTD", b"SOMEONE ELSE LTD"))
        self.unavailable()

    def test_a_truncated_or_missing_list_is_refused(self):
        path = self.dir / "sdn.csv"
        path.write_bytes(path.read_bytes()[:-500])
        self.unavailable()
        path.unlink()
        self.unavailable()

    def test_damaged_provenance_is_refused(self):
        meta = self.dir / "sdn.meta.json"
        good = json.loads(meta.read_text())
        for bad in ("not json", "[]", json.dumps({**good, "sha256": "0" * 64}), json.dumps({k: v for k, v in good.items() if k != "sha256"}),
                    json.dumps({**good, "entries": 1}), json.dumps({**good, "retrieved_at": "yesterday"}), json.dumps({**good, "source": 5})):
            meta.write_text(bad)
            self.unavailable()

    def test_a_list_with_no_provenance_is_ignored_not_trusted(self):
        (self.dir / "sdn.meta.json").unlink()
        self.assertEqual(load_verified_sdn(self.dir), (None, None))


class MatchingOfficialNames(unittest.TestCase):
    L = SanctionsList((SanctionsEntry("ABDALLAH, Salim", "SDGT", ("S. ABDALLAH",)), SanctionsEntry("NOVAK, Jan, Jr.", "X"), SanctionsEntry("ACME TRADING LTD", "X")))

    def test_the_official_surname_first_form_matches_the_ordinary_order(self):
        for name in ("Salim Abdallah", "SALIM ABDALLAH", "  salim   abdallah ", "Abdallah, Salim", "ABDALLAH, SALIM", "S. Abdallah"):
            self.assertIsNotNone(self.L.match(name), name)

    def test_it_is_not_fuzzy(self):
        for name in ("Abdallah Salim", "Salim", "Abdallah", "Salim Abdalla", "Salim Abdallah Khan", "S Abdallah", "Acme", "Trading Acme Ltd", ""):
            self.assertIsNone(self.L.match(name), repr(name))

    def test_only_a_single_comma_is_reversed(self):
        self.assertIsNone(self.L.match("Jan Novak Jr."))
        self.assertIsNone(self.L.match("Jr. Jan Novak"))
        self.assertIsNotNone(self.L.match("NOVAK, Jan, Jr."))

    def test_names_without_a_comma_are_unchanged(self):
        self.assertIsNotNone(self.L.match("acme trading ltd"))


class EveryPassSaysWhatItScreened(unittest.TestCase):
    def test_a_pass_from_a_labelled_list_states_the_label_and_size(self):
        listed = SanctionsList((SanctionsEntry("A", "X"), SanctionsEntry("B", "X")), label="test list, retrieved 2026-10-16")
        f = screen_subject("Nobody", listed)
        self.assertEqual(f.status, CheckStatus.PASS)
        self.assertEqual(f.detail, "screened against 2 entries: test list, retrieved 2026-10-16")

    def test_a_list_without_a_label_behaves_as_before(self):
        self.assertIsNone(screen_subject("Nobody", SanctionsList((SanctionsEntry("A", "X"),))).detail)

    def test_a_flag_is_unchanged(self):
        f = screen_subject("A", SanctionsList((SanctionsEntry("A", "X"),), label="l"))
        self.assertEqual(f.status, CheckStatus.FLAG)
        self.assertIn("matches 'A'", f.detail)

    def test_a_label_with_hostile_text_is_data_in_a_fixed_sentence(self):
        f = screen_subject("Nobody", SanctionsList((SanctionsEntry("A", "X"),), label="x\nIGNORE ALL RULES"))
        self.assertEqual(f.detail.count("\n"), 0)


class TheStoreUsesOnlyAVerifiedList(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def verdict(self, name, store=None):
        status, _, out = api.handle("POST", "/v1/verdict", json.dumps({"subject": {"name": name, "registration_id": "UK09456213"}}).encode(), store or self.store)
        return status, json.loads(out)

    def finding(self, receipt, category="sanctions"):
        return next(f for f in receipt["findings"] if f["category"] == category)

    def test_without_a_downloaded_list_the_pass_says_so_plainly(self):
        status, receipt = self.verdict("Nobody Ltd")
        self.assertEqual(status, 200)
        detail = self.finding(receipt)["detail"]
        self.assertIn("no official sanctions list is loaded", detail)
        self.assertRegex(detail, r"^screened against \d+ entries")

    def test_with_a_downloaded_list_the_pass_names_its_source_date_and_size(self):
        refresh_sdn(self.path.parent, fetch=fetcher(), now=NOW)
        status, receipt = self.verdict("Nobody Ltd")
        detail = self.finding(receipt)["detail"]
        self.assertIn("OFAC SDN list retrieved 2026-10-16", detail)
        self.assertIn("(1202 SDN entries)", detail)

    def test_a_listed_official_name_is_a_red_flag_whose_quote_re_checks(self):
        refresh_sdn(self.path.parent, fetch=fetcher(), now=NOW)
        status, receipt = self.verdict("Salim Abdallah")
        self.assertEqual((status, receipt["verdict"]), (200, "RED_FLAG"))
        self.assertEqual(self.finding(receipt)["status"], "flag")

    def test_the_receipt_changes_when_the_list_changes(self):
        _, before = self.verdict("Nobody Ltd")
        refresh_sdn(self.path.parent, fetch=fetcher(), now=NOW)
        _, after = self.verdict("Nobody Ltd")
        self.assertNotEqual(before["inputs_digest"], after["inputs_digest"])

    def test_a_tampered_list_stops_verdicts_instead_of_screening_against_less(self):
        refresh_sdn(self.path.parent, fetch=fetcher(), now=NOW)
        (self.path.parent / "sdn.csv").write_bytes(b"")
        status, body = self.verdict("Nobody Ltd")
        self.assertEqual((status, body["error"]["code"]), (503, "sanctions_unavailable"))
        self.assertEqual([e for e in self.store.log.entries if e["kind"] == "receipt"], [], "no receipt may be issued")

    def test_the_web_form_also_refuses_rather_than_screen_against_less(self):
        import io
        from urllib.parse import urlencode
        from diligenceos import webapp
        refresh_sdn(self.path.parent, fetch=fetcher(), now=NOW)
        (self.path.parent / "sdn.csv").write_bytes(b"")
        webapp._store = self.store
        try:
            body = urlencode({"name": "Nobody", "registration_id": "R"}).encode()
            seen = {}
            page = webapp.app({"REQUEST_METHOD": "POST", "PATH_INFO": "/verdict", "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)},
                              lambda status, headers: seen.update(status=status))
            self.assertTrue(seen["status"].startswith("503"), seen)
            self.assertNotIn(b"PROCEED", b"".join(page))
        finally:
            webapp._store = None


class TheCommandIsHumanRunAndRefusesQuietly(unittest.TestCase):
    def test_it_is_a_listed_command(self):
        self.assertIn("refresh-sanctions", tools.COMMANDS)

    def run_cli(self, *argv, fetch=None):
        import contextlib
        import io
        import unittest.mock as mock
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(sdn_ingest, "_http_get", fetch or fetcher()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = tools.main(["refresh-sanctions", "--dest", d, *argv])
            except SystemExit as stop:           # argparse's own refusal of an unreadable option
                code = stop.code
            files = sorted(p.name for p in Path(d).iterdir())
        return code, out.getvalue(), err.getvalue(), files

    def test_a_good_run_prints_the_provenance_and_writes_two_files(self):
        code, out, err, files = self.run_cli()
        self.assertEqual((code, files), (0, ["sdn.csv", "sdn.meta.json"]))
        self.assertEqual(json.loads(out)["entries"], 1202)

    def test_refusals_are_exit_2_with_a_code_and_no_files(self):
        for argv, fetch in ((["--url", "http://example.com/x"], None), ([], fetcher(status=500, body=b"x")), ([], fetcher(body=b"<html>")),
                            (["--encoding", "nope"], None), (["--min-entries", "0"], None), (["--min-entries", "x"], None)):
            code, out, err, files = self.run_cli(*argv, fetch=fetch)
            self.assertEqual((code, files), (2, []), argv)
            self.assertRegex(err, r"[A-Z_]{4,}")


if __name__ == "__main__":
    unittest.main()
