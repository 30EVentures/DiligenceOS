"""Slice-less hardening D1: GET /v1/log/entries is paginated, the witness follows
the pages, and a non-loopback bind warns that there is no TLS."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from diligenceos import api, manifest, webapp
from diligenceos.engine import assemble_verdict
from diligenceos.receipt import issue_receipt
from diligenceos.signing import Signer
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding
from diligenceos.witness import download_entries, run_witness

T = "2026-09-29T12:00:00+00:00"
CLEAN = [Finding("sanctions", CheckStatus.PASS)]


def make_receipt(n):
    return issue_receipt(subject={"name": f"S{n}"}, inputs={"n": n}, result=assemble_verdict(CLEAN), issued_at=T)


class PagedLogCase(unittest.TestCase):
    PAGE = 3  # tiny default page so boundaries are cheap to reach

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Store.load_or_seed(Path(self._tmp.name) / "store.json")
        patcher = mock.patch.object(api, "DEFAULT_LOG_PAGE", self.PAGE)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def grow(self, count):
        for _ in range(count):
            n = len(self.store.log.entries)
            self.store.log.append(make_receipt(n), now=T, signer=self.store.signer)

    def get(self, query=""):
        status, _, body = api.handle("GET", "/v1/log/entries", b"", self.store, query)
        return status, json.loads(body)


class PaginationTest(PagedLogCase):
    def test_empty_log(self):
        status, doc = self.get()
        self.assertEqual(status, 200)
        self.assertEqual((doc["entries"], doc["length"], doc["has_more"], doc["next_after_seq"]), ([], 0, False, None))
        self.assertEqual(doc["head_hash"], self.store.log.head)

    def test_exactly_one_page(self):
        self.grow(self.PAGE)
        _, doc = self.get()
        self.assertEqual([e["seq"] for e in doc["entries"]], [0, 1, 2])
        self.assertEqual((doc["has_more"], doc["next_after_seq"], doc["length"]), (False, None, 3))

    def test_one_more_than_a_page_and_following_the_cursor(self):
        self.grow(self.PAGE + 1)
        _, first = self.get()
        self.assertEqual((len(first["entries"]), first["has_more"], first["next_after_seq"]), (3, True, 2))
        self.assertEqual(first["head_hash"], self.store.log.head)  # the head of the whole log, not the page
        _, second = self.get(f"after_seq={first['next_after_seq']}")
        self.assertEqual(([e["seq"] for e in second["entries"]], second["has_more"], second["next_after_seq"]), ([3], False, None))
        self.assertEqual(first["entries"] + second["entries"], self.store.log.entries)

    def test_explicit_limit_and_cursor_are_stable_under_appends(self):
        self.grow(5)
        _, a = self.get("limit=2")
        self.assertEqual([e["seq"] for e in a["entries"]], [0, 1])
        self.grow(2)  # the log grows between pages: the cursor is a seq, nothing shifts
        _, b = self.get(f"after_seq={a['next_after_seq']}&limit=2")
        self.assertEqual([e["seq"] for e in b["entries"]], [2, 3])
        self.assertEqual(b["length"], 7)

    def test_cursor_at_or_past_the_end_is_an_empty_page_not_an_error(self):
        self.grow(4)
        for cursor in (3, 4, 10_000, 10 ** 14):
            status, doc = self.get(f"after_seq={cursor}")
            self.assertEqual((status, doc["entries"], doc["has_more"], doc["next_after_seq"]), (200, [], False, None), cursor)

    def test_limit_bounds(self):
        self.grow(2)
        self.assertEqual(len(self.get(f"limit={api.MAX_LOG_PAGE}")[1]["entries"]), 2)
        self.assertEqual(len(self.get("limit=1")[1]["entries"]), 1)

    def test_invalid_parameters_are_400_naming_the_field(self):
        self.grow(2)
        cases = {
            "limit=0": "limit", "limit=-1": "limit", f"limit={api.MAX_LOG_PAGE + 1}": "limit",
            "limit=abc": "limit", "limit=1.5": "limit", "limit=": "limit", "limit=+2": "limit",
            "limit=%D9%A3": "limit",  # an Arabic-Indic digit is not an ASCII integer
            "limit=1&limit=2": "limit", "after_seq=-1": "after_seq", "after_seq=x": "after_seq",
            "after_seq=": "after_seq", "after_seq=1e2": "after_seq", "after_seq=1&after_seq=2": "after_seq",
            "offset=1": "offset",
        }
        for query, field in cases.items():
            status, doc = self.get(query)
            self.assertEqual((status, doc["error"]["code"], doc["error"].get("field")), (400, "invalid_request", field), query)
        status, doc = self.get("limit")  # no '=' at all
        self.assertEqual((status, doc["error"]["code"]), (400, "invalid_request"))

    def test_other_log_endpoints_ignore_pagination(self):
        self.grow(5)
        status, _, body = api.handle("GET", "/v1/log/verify", b"", self.store, "limit=1")
        self.assertEqual((status, json.loads(body)["length"]), (200, 5))
        status, _, body = api.handle("GET", "/v1/log/head", b"", self.store)
        self.assertEqual(json.loads(body)["length"], 5)

    def test_query_string_reaches_the_api_through_wsgi(self):
        self.grow(5)
        webapp._store = self.store
        self.addCleanup(setattr, webapp, "_store", None)
        captured = {}
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/v1/log/entries", "QUERY_STRING": "limit=2&after_seq=0",
                   "CONTENT_LENGTH": "0", "wsgi.input": io.BytesIO(b"")}
        out = webapp.app(environ, lambda status, headers: captured.update(status=status))
        doc = json.loads(b"".join(out))
        self.assertEqual((captured["status"], [e["seq"] for e in doc["entries"]]), ("200 OK", [1, 2]))


class DocumentedLimitsTest(PagedLogCase):
    def test_manifest_limits_equal_the_enforcing_constants(self):
        m = json.loads(api.handle("GET", "/v1/manifest", b"", self.store)[2])["manifest"]
        self.assertEqual(m["limits"]["max_log_entries_page"], api.MAX_LOG_PAGE)
        self.assertEqual(m["limits"]["default_log_entries_page"], api.DEFAULT_LOG_PAGE)

    def test_capabilities_documents_the_parameters_and_limits(self):
        caps = json.loads(api.handle("GET", "/v1/capabilities", b"", self.store)[2])
        ep = caps["endpoints"]["GET /v1/log/entries"]
        self.assertEqual(set(ep["request"]), {"after_seq", "limit"})
        self.assertIn(str(api.MAX_LOG_PAGE), ep["request"]["limit"])
        self.assertIn("next_after_seq", ep["response"])


class WitnessAcrossPagesTest(PagedLogCase):
    def setUp(self):
        super().setUp()
        self.state = Path(self._tmp.name) / "witness.json"
        self.w = Signer.generate()
        self.requests = []

    def fetch(self, path):
        self.requests.append(path)
        route, _, query = path.partition("?")
        status, _, body = api.handle("GET", route, b"", self.store, query)
        assert status == 200, body
        return json.loads(body)

    def witness(self, fetch=None):
        return run_witness(fetch or self.fetch, self.state, self.w, self.store.signer.issuer_id)

    def test_a_log_longer_than_a_page_is_downloaded_and_accepted(self):
        self.grow(8)  # 3 pages
        code, msg, cosig = self.witness()
        self.assertEqual(code, 0, msg)
        self.assertEqual((cosig["length"], cosig["head_hash"]), (8, self.store.log.head))
        self.assertIn("8 new entries", msg)
        self.assertEqual(len([r for r in self.requests if r.startswith("/v1/log/entries")]), 3)

    def test_growth_across_pages_is_an_append_only_extension(self):
        self.grow(4)
        self.assertEqual(self.witness()[0], 0)
        self.grow(6)
        code, msg, _ = self.witness()
        self.assertEqual(code, 0, msg)
        self.assertIn("6 new entries", msg)

    def test_shortening_is_detected_even_when_the_head_is_honest(self):
        self.grow(7)
        self.assertEqual(self.witness()[0], 0)
        before = self.state.read_text()
        real = self.fetch

        def truncated(path):  # the server quietly serves only the first 5 entries, on any page
            doc = real(path)
            if path.startswith("/v1/log/entries"):
                doc = {**doc, "entries": [e for e in doc["entries"] if e["seq"] < 5], "has_more": False}
            return doc

        code, msg, cosig = self.witness(truncated)
        self.assertEqual(code, 3)
        self.assertTrue(msg.startswith("INCONSISTENT"), msg)
        self.assertIsNone(cosig)
        self.assertEqual(self.state.read_text(), before)

    def test_rewriting_an_entry_on_a_later_page_is_detected(self):
        self.grow(7)
        real = self.fetch

        def tampered(path):
            doc = real(path)
            if "after_seq=2" in path:
                doc = {**doc, "entries": [{**doc["entries"][0], "logged_at": "1999-01-01T00:00:00+00:00"}, *doc["entries"][1:]]}
            return doc

        code, msg, _ = self.witness(tampered)
        self.assertEqual(code, 3)
        self.assertFalse(self.state.exists())

    def test_history_rewritten_before_the_last_seen_head_is_detected(self):
        self.grow(7)
        self.assertEqual(self.witness()[0], 0)
        other_dir = Path(self._tmp.name) / "other"
        other_dir.mkdir()
        (other_dir / "issuer.key").write_bytes((Path(self._tmp.name) / "issuer.key").read_bytes())
        other = Store.load_or_seed(other_dir / "store.json")  # same operator key, a different (longer) history
        self.assertEqual(other.signer.issuer_id, self.store.signer.issuer_id)
        for n in range(100, 109):
            other.log.append(make_receipt(n), now=T, signer=self.store.signer)
        self.store = other
        code, msg, _ = self.witness()
        self.assertEqual(code, 3)
        self.assertIn("rewritten", msg)

    def test_a_server_whose_cursor_does_not_advance_cannot_loop_the_witness(self):
        self.grow(8)
        real = self.fetch

        def stuck(path):
            doc = real("/v1/log/entries")  # always the first page, always has_more
            return doc if path.startswith("/v1/log/entries") else real(path)

        code, msg, _ = self.witness(stuck)
        self.assertEqual(code, 3)
        self.assertIn("entries must be a list", msg)

    def test_malformed_pages_are_inconsistent_not_a_crash(self):
        self.grow(2)
        real = self.fetch
        for bad in ({}, {"entries": "x"}, [], None):
            code, _, _ = self.witness(lambda p, bad=bad: bad if p.startswith("/v1/log/entries") else real(p))
            self.assertEqual(code, 3)

    def test_download_stops_at_the_signed_length_and_ignores_later_growth(self):
        self.grow(7)
        entries = download_entries(self.fetch, 4)
        self.assertEqual([e["seq"] for e in entries], [0, 1, 2, 3])
        self.assertEqual(download_entries(self.fetch, "x"), [])
        self.assertEqual(download_entries(self.fetch, True), [])


class TlsWarningTest(unittest.TestCase):
    def test_loopback_never_warns(self):
        for host in ("127.0.0.1", "::1", "[::1]", "localhost", "LOCALHOST", "127.0.0.2"):
            self.assertIsNone(webapp.tls_warning(host, {}), host)

    def test_non_loopback_warns_and_says_what_to_do(self):
        for host in ("0.0.0.0", "::", "", "10.1.2.3", "192.168.0.5", "example.org", "localhost.example.org"):
            warning = webapp.tls_warning(host, {})
            self.assertIsNotNone(warning, host)
            self.assertIn("no TLS", warning)
            self.assertIn("reverse proxy", warning)
            self.assertIn("DILIGENCEOS_BEHIND_TLS_PROXY=1", warning)

    def test_explicit_acknowledgement_silences_it_and_only_exactly(self):
        self.assertIsNone(webapp.tls_warning("0.0.0.0", {"DILIGENCEOS_BEHIND_TLS_PROXY": "1"}))
        for value in ("", "0", "no", "true", "yes"):
            self.assertIsNotNone(webapp.tls_warning("0.0.0.0", {"DILIGENCEOS_BEHIND_TLS_PROXY": value}), value)

    def test_serve_prints_the_warning_but_still_starts(self):
        class Boom(Exception):
            pass

        stderr = io.StringIO()
        with mock.patch.dict("os.environ", {}, clear=False) as env, \
                mock.patch("sys.stderr", stderr), \
                mock.patch.object(webapp, "make_server", side_effect=Boom):
            env.pop("DILIGENCEOS_BEHIND_TLS_PROXY", None)
            with self.assertRaises(Boom):  # reached make_server: the warning did not stop startup
                webapp.serve("0.0.0.0", 0)
        self.assertIn("no TLS", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
