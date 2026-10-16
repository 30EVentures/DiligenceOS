"""An open verdict endpoint is fine on 127.0.0.1 and wrong on a public address: every request appends to the signed log.
So the default follows the bind address, and an explicit choice always wins."""

import json
import unittest
from unittest import mock

from diligenceos import api, webapp
from diligenceos.store import Store

GOOD = {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}}


def verdict(store):
    status, _, out = api.handle("POST", "/v1/verdict", json.dumps(GOOD).encode(), store)
    return status, json.loads(out)


class TheDefaultFollowsTheBindAddress(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()
        patcher = mock.patch.dict("os.environ")
        patcher.start()
        self.addCleanup(patcher.stop)
        import os
        os.environ.pop("DILIGENCEOS_VERDICT_AUTH", None)
        self.addCleanup(api.set_exposed, False)

    def test_on_loopback_the_default_stays_open(self):
        webapp.configure_exposure("127.0.0.1")
        self.assertEqual(api.verdict_auth_mode(), "open")
        self.assertEqual(verdict(self.store)[0], 200)

    def test_on_any_other_address_the_default_is_signed_and_an_unsigned_request_is_refused(self):
        for host in ("0.0.0.0", "10.0.0.5", "example.com", "", "::", "192.168.1.9", "localhost.evil.com"):
            webapp.configure_exposure(host)
            self.assertEqual(api.verdict_auth_mode(), "signed", host)
            status, body = verdict(self.store)
            self.assertEqual((status, body["error"]["code"]), (401, "unauthenticated"), host)
        self.assertEqual([e for e in self.store.log.entries if e["kind"] == "receipt"], [])

    def test_loopback_spellings_are_all_loopback(self):
        for host in ("127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.5"):
            webapp.configure_exposure(host)
            self.assertEqual(api.verdict_auth_mode(), "open", host)

    def test_an_explicit_setting_always_wins_in_both_directions(self):
        import os
        webapp.configure_exposure("0.0.0.0")
        os.environ["DILIGENCEOS_VERDICT_AUTH"] = "open"
        self.assertEqual(api.verdict_auth_mode(), "open")
        webapp.configure_exposure("127.0.0.1")
        os.environ["DILIGENCEOS_VERDICT_AUTH"] = "signed"
        self.assertEqual(api.verdict_auth_mode(), "signed")
        os.environ["DILIGENCEOS_VERDICT_AUTH"] = "typo"
        self.assertEqual(api.verdict_auth_mode(), "signed")

    def test_what_the_server_says_at_startup(self):
        import os
        self.assertEqual(webapp.configure_exposure("127.0.0.1"), [])
        notes = webapp.configure_exposure("0.0.0.0")
        self.assertTrue(any("signed" in n for n in notes), notes)
        os.environ["DILIGENCEOS_VERDICT_AUTH"] = "open"
        warnings = webapp.configure_exposure("0.0.0.0")
        self.assertTrue(any("OPEN" in w and "log" in w for w in warnings), warnings)

    def test_capabilities_and_manifest_report_the_mode_in_force(self):
        webapp.configure_exposure("0.0.0.0")
        _, _, out = api.handle("GET", "/v1/capabilities", b"", self.store)
        self.assertEqual(json.loads(out)["verdict_auth"], "signed")
        _, _, out = api.handle("GET", "/v1/manifest", b"", self.store)
        routes = {(r["method"], r["path"]): r for r in json.loads(out)["manifest"]["api"]["routes"]}
        self.assertTrue(routes[("POST", "/v1/verdict")]["authenticated"])

    def test_junk_is_not_a_bind_address_and_is_treated_as_exposed(self):
        for host in (None, 5, "http://127.0.0.1", "127.0.0.1:8000", "127.0.0.1 "):
            webapp.configure_exposure(host)
            self.assertEqual(api.verdict_auth_mode(), "signed", repr(host))


if __name__ == "__main__":
    unittest.main()
