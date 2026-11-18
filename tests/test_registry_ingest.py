import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from diligenceos import api, registry_ingest as ri, tools
from diligenceos.identity import RegistryRecord, check_identity
from diligenceos.store import Store
from diligenceos.types import CheckStatus

KEY = "test-key-not-a-real-credential"
NOW = "2026-11-18T12:00:00+00:00"
# A synthetic profile shaped like the register's response. Not recorded from the live service.
PROFILE = {
    "company_number": "09456213", "company_name": "MERIDIAN ROBOTICS LTD", "company_status": "active",
    "jurisdiction": "england-wales", "type": "ltd",
}


def body(**changes):
    return json.dumps({**PROFILE, **changes}, indent=2).encode("utf-8")


class FakeFetch:
    def __init__(self, status=200, payload=None, exc=None):
        self.status, self.payload, self.exc, self.calls = status, payload if payload is not None else body(), exc, []

    def __call__(self, url, headers, max_bytes):
        self.calls.append((url, headers, max_bytes))
        if self.exc:
            raise self.exc
        return self.status, self.payload


class RefreshTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def refresh(self, fetch=None, number="09456213", **kw):
        return ri.refresh_company(self.dir, number, api_key=KEY, fetch=fetch or FakeFetch(), now=NOW, **kw)

    def test_saves_raw_bytes_and_provenance_and_never_the_key(self):
        fetch = FakeFetch()
        meta = self.refresh(fetch)
        url, headers, _ = fetch.calls[0]
        self.assertEqual(url, "https://api.company-information.service.gov.uk/company/09456213")
        self.assertEqual(headers["Authorization"], "Basic " + base64.b64encode(f"{KEY}:".encode()).decode())
        self.assertEqual(meta["retrieved_at"], NOW)
        saved = {p.name: p.read_bytes() for p in (self.dir / "registry").iterdir()}
        self.assertEqual(set(saved), {"09456213.json", "09456213.meta.json"})
        self.assertEqual(saved["09456213.json"], body())
        for blob in saved.values():
            self.assertNotIn(KEY.encode(), blob)
            self.assertNotIn(base64.b64encode(f"{KEY}:".encode()), blob)

    def test_refusals_change_nothing_and_never_name_the_key(self):
        cases = {
            "BAD_NUMBER": dict(number="../etc/pw"),
            "BAD_NUMBER ": dict(number="0945621"),
            "BAD_NUMBER  ": dict(number="09456213\n"),
            "BAD_NUMBER   ": dict(number="sc123456"),
            "BAD_URL": dict(base_url="http://api.company-information.service.gov.uk"),
            "NOT_FOUND": dict(fetch=FakeFetch(status=404, payload=b"")),
            "HTTP_STATUS": dict(fetch=FakeFetch(status=500, payload=b"x")),
            "EMPTY": dict(fetch=FakeFetch(payload=b"  ")),
            "TOO_LARGE": dict(fetch=FakeFetch(payload=b" " * (ri.MAX_BYTES + 1) + b"{}")),
            "BAD_PROFILE": dict(fetch=FakeFetch(payload=b"not json")),
            "BAD_PROFILE ": dict(fetch=FakeFetch(payload=body(company_number="00000006"))),
            "BAD_PROFILE  ": dict(fetch=FakeFetch(payload=body(company_name=""))),
            "BAD_PROFILE   ": dict(fetch=FakeFetch(payload=b'{"company_number":"09456213","company_number":"09456213"}')),
            "FETCH_FAILED": dict(fetch=FakeFetch(exc=OSError(KEY))),
        }
        for code, kwargs in cases.items():
            with self.subTest(code):
                with self.assertRaises(ri.RegistryRefreshError) as ctx:
                    self.refresh(**kwargs)
                self.assertEqual(ctx.exception.code, code.strip())
                self.assertNotIn(KEY, str(ctx.exception))
                self.assertFalse((self.dir / "registry").exists())

    def test_no_key_is_refused(self):
        for key in (None, "", "   ", 5):
            with self.subTest(key=key):
                with self.assertRaises(ri.RegistryRefreshError) as ctx:
                    ri.refresh_company(self.dir, "09456213", api_key=key, fetch=FakeFetch())
                self.assertEqual(ctx.exception.code, "NO_KEY")

    def test_a_failed_refresh_keeps_the_previous_snapshot(self):
        self.refresh()
        with self.assertRaises(ri.RegistryRefreshError):
            self.refresh(FakeFetch(payload=b"garbage"))
        self.assertEqual((self.dir / "registry" / "09456213.json").read_bytes(), body())


class LoadTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        ri.refresh_company(self.dir, "09456213", api_key=KEY, fetch=FakeFetch(), now=NOW)
        self.snap = self.dir / "registry"

    def tearDown(self):
        self._tmp.cleanup()

    def load(self, **kw):
        return ri.load_verified_record(self.dir, "09456213", now=NOW, **kw)

    def test_a_good_snapshot_loads_with_provenance(self):
        record = self.load()
        self.assertEqual((record.name, record.status, record.jurisdiction), ("MERIDIAN ROBOTICS LTD", "active", "england-wales"))
        self.assertFalse(record.stale)
        self.assertIn("retrieved 2026-11-18", record.provenance)
        self.assertIn("api.company-information.service.gov.uk/company/09456213", record.provenance)

    def test_no_snapshot_is_none_not_an_error(self):
        self.assertIsNone(ri.load_verified_record(self.dir, "00000006", now=NOW))
        self.assertIsNone(ri.load_verified_record(self.dir, "../x", now=NOW))
        self.assertIsNone(ri.load_verified_record(self.dir, None, now=NOW))

    def test_every_kind_of_damage_is_unavailable_never_none(self):
        data, meta = self.snap / "09456213.json", self.snap / "09456213.meta.json"
        good_data, good_meta = data.read_bytes(), meta.read_bytes()
        original = json.loads(good_meta)
        damages = {
            "edited": lambda: data.write_bytes(good_data.replace(b"active", b"dissolved")),
            "truncated": lambda: data.write_bytes(good_data[:20]),
            "emptied": lambda: data.write_bytes(b""),
            "data deleted": lambda: data.unlink(),
            "meta deleted": lambda: meta.unlink(),
            "meta not json": lambda: meta.write_bytes(b"{"),
            "meta wrong schema": lambda: meta.write_text(json.dumps({**original, "schema": "x"})),
            "meta wrong number": lambda: meta.write_text(json.dumps({**original, "number": "00000006"})),
            "meta bad sha": lambda: meta.write_text(json.dumps({**original, "sha256": "ABC"})),
            "meta wrong sha": lambda: meta.write_text(json.dumps({**original, "sha256": "0" * 64})),
            "meta naive time": lambda: meta.write_text(json.dumps({**original, "retrieved_at": "2026-11-18T12:00:00"})),
            "meta time missing": lambda: meta.write_text(json.dumps({k: v for k, v in original.items() if k != "retrieved_at"})),
            "meta bytes lie": lambda: meta.write_text(json.dumps({**original, "bytes": 1})),
            "meta duplicate key": lambda: meta.write_bytes(good_meta.replace(b'"bytes"', b'"number": "09456213", "bytes"', 1)),
        }
        for label, damage in damages.items():
            with self.subTest(label):
                data.write_bytes(good_data)
                meta.write_bytes(good_meta)
                damage()
                with self.assertRaises(ri.RegistryUnavailable):
                    self.load()

    def test_old_snapshot_is_stale(self):
        record = ri.load_verified_record(self.dir, "09456213", now="2026-12-31T00:00:00+00:00")
        self.assertTrue(record.stale)
        self.assertFalse(ri.load_verified_record(self.dir, "09456213", now="2026-12-17T12:00:00+00:00").stale)

    def test_snapshot_identities_list_provenance_only(self):
        self.assertEqual([s["number"] for s in ri.snapshot_identities(self.dir)], ["09456213"])
        self.assertEqual(ri.snapshot_identities(self.dir / "nowhere"), [])


class IdentityFindingTest(unittest.TestCase):
    def finding(self, record, name="MERIDIAN ROBOTICS LTD"):
        return check_identity(name, "09456213", lambda _: record)

    def record(self, **kw):
        return RegistryRecord(name="MERIDIAN ROBOTICS LTD", registration_id="09456213", status="active",
                              jurisdiction="england-wales", provenance="src retrieved 2026-11-18 (sha256 abc)", **kw)

    def test_pass_names_its_source(self):
        f = self.finding(self.record())
        self.assertEqual(f.status, CheckStatus.PASS)
        self.assertIn("src retrieved 2026-11-18", f.detail)

    def test_an_operator_record_is_unchanged(self):
        f = self.finding(RegistryRecord("MERIDIAN ROBOTICS LTD", "09456213", "active", "uk"))
        self.assertEqual((f.status, f.detail), (CheckStatus.PASS, None))

    def test_flags_carry_the_source(self):
        for record, name in ((self.record(stale=True, age_note="retrieved 2026-01-01"), None),
                             (RegistryRecord("MERIDIAN ROBOTICS LTD", "09456213", "dissolved", "x", provenance="P"), None),
                             (self.record(), "SOMEONE ELSE LTD")):
            f = self.finding(record, **({"name": name} if name else {}))
            self.assertEqual(f.status, CheckStatus.FLAG)
            self.assertIn(record.provenance, f.detail)
        self.assertIn("too old", self.finding(self.record(stale=True, age_note="retrieved 2026-01-01")).detail)


class StoreAndApiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.store = Store(persist_path=self.dir / "store.json")

    def tearDown(self):
        self._tmp.cleanup()

    def verdict(self, name="MERIDIAN ROBOTICS LTD", reg="09456213"):
        status, _, out = api.handle("POST", "/v1/verdict", json.dumps(
            {"subject": {"name": name, "registration_id": reg}}).encode(), self.store)
        return status, json.loads(out)

    def identity(self, receipt):
        return next(f for f in receipt["findings"] if f["category"] == "identity")

    def test_no_snapshot_means_unchanged_digest_and_a_flag(self):
        self.assertNotIn("registry_snapshots", self.store.digest_input())
        status, receipt = self.verdict()
        self.assertEqual((status, self.identity(receipt)["status"]), (200, "flag"))

    def test_a_snapshot_passes_identity_and_is_in_the_digest(self):
        before = api.digest(self.store.digest_input())
        ri.refresh_company(self.dir, "09456213", api_key=KEY, fetch=FakeFetch())
        status, receipt = self.verdict()
        self.assertEqual(status, 200)
        found = self.identity(receipt)
        self.assertEqual(found["status"], "pass")
        self.assertIn("sha256", found["detail"])
        self.assertEqual([s["number"] for s in self.store.digest_input()["registry_snapshots"]], ["09456213"])
        self.assertNotEqual(api.digest(self.store.digest_input()), before)

    def test_a_damaged_snapshot_stops_the_verdict_with_503(self):
        ri.refresh_company(self.dir, "09456213", api_key=KEY, fetch=FakeFetch())
        (self.dir / "registry" / "09456213.json").write_bytes(body(company_status="dissolved"))
        status, out = self.verdict()
        self.assertEqual((status, out["error"]["code"]), (503, "registry_unavailable"))
        self.assertEqual(len(self.store.log.entries), 0, "no receipt, no log entry")
        # another subject is unaffected
        self.assertEqual(self.verdict(reg="UK0000001")[0], 200)

    def test_an_operator_record_wins_over_a_snapshot(self):
        ri.refresh_company(self.dir, "09456213", api_key=KEY, fetch=FakeFetch())
        self.store.add_registry_record("09456213", "Meridian Robotics Ltd.", "active", "uk")
        found = self.identity(self.verdict(name="Meridian Robotics Ltd.")[1])
        self.assertEqual(found["status"], "pass")
        self.assertNotIn("sha256", found["detail"] or "")

    def test_in_memory_store_has_no_snapshots(self):
        self.assertIsNone(Store().registry_lookup()("09456213"))


class CliTest(unittest.TestCase):
    def test_no_key_refuses_without_touching_anything(self):
        with tempfile.TemporaryDirectory() as tmp:
            err = io.StringIO()
            saved = os.environ.pop(ri.KEY_VAR, None)
            try:
                with contextlib.redirect_stderr(err):
                    code = tools.main(["refresh-registry", "09456213", "--dest", tmp])
            finally:
                if saved is not None:
                    os.environ[ri.KEY_VAR] = saved
            self.assertEqual(code, 2)
            self.assertIn("NO_KEY", err.getvalue())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_the_key_is_not_a_command_line_argument(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                tools.main(["refresh-registry", "09456213", "--api-key", KEY])


if __name__ == "__main__":
    unittest.main()
