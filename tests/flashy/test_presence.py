"""Real heartbeats from real verdict activity, with a closed vocabulary and no way to break a verdict."""

import json
import threading
import time
import unittest
from unittest import mock

from diligenceos import api
from diligenceos.flashy import presence
from diligenceos.flashy.presence import EVENTS, Presence
from diligenceos.store import Store

TOKEN = "agt_test_0123456789abcdef"
ENV = {"FLASHYOS_ORG_ID": "org_abc123", "FLASHYOS_AGENT_TOKEN": TOKEN, "FLASHYOS_AGENT_NAME": "demo-agent"}
SECRET_NAME = "ZEBRA-SECRET-COUNTERPARTY Ltd"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make(env=ENV, send=None, clock=None, **kw):
    sent = []
    p = Presence(send=send or (lambda status, task: sent.append((status, task))), clock=clock or Clock(),
                 env=env, start_thread=False, **kw)
    return p, sent


class NothingIsSentUnlessConfigured(unittest.TestCase):
    def test_unconfigured_never_sends_and_never_starts_a_thread(self):
        before = threading.active_count()
        for env in ({}, {"FLASHYOS_ORG_ID": "org_abc123"}, {**ENV, "FLASHYOS_AGENT_NAME": ""}, {**ENV, "FLASHYOS_AGENT_TOKEN": "short"},
                    {**ENV, "FLASHYOS_API_URL": "http://api.flashyos.com"}):
            p = Presence(send=lambda *a: self.fail("sent while unconfigured"), env=env)
            self.assertFalse(p.configured)
            for event in EVENTS:
                p.note(event)
            self.assertIsNone(p.step())
        self.assertEqual(threading.active_count(), before)

    def test_the_module_default_is_inert_without_the_three_variables(self):
        presence.reset()
        with mock.patch.dict("os.environ", {}, clear=True):
            presence.note("issuing")
            self.assertFalse(presence.default().configured)


class ClosedVocabulary(unittest.TestCase):
    def test_only_the_five_known_events_are_accepted(self):
        for bad in (None, "", "issuing ", "ISSUING", f"verdict for {SECRET_NAME}", {"event": "issuing"}, ["verifying"], 5, True, b"idle",
                    "received", "gathering", "issued", "BUILDING", "INCIDENT"):
            p, sent = make()
            p.step()                       # the initial idle heartbeat
            sent.clear()
            p.note(bad)
            p.clock.t += 5
            self.assertIsNone(p.step(), bad)
            self.assertEqual(sent, [], bad)
            self.assertEqual(p._seen_events, [], bad)

    def test_every_label_is_a_fixed_ascii_string_from_the_table(self):
        self.assertEqual(set(EVENTS), {"issuing", "verifying", "witnessing", "incident", "idle"})
        self.assertEqual({k: v[0] for k, v in EVENTS.items()},
                         {"issuing": "BUILDING", "verifying": "TESTING", "witnessing": "REVIEWING", "incident": "INCIDENT", "idle": "IDLE"})
        for status, task in EVENTS.values():
            self.assertIn(status, presence.mesh_reporter.STATUSES)
            self.assertTrue(task.isascii() and len(task) <= 40)

    def test_what_is_sent_is_exactly_a_table_row(self):
        p, sent = make(clock=Clock())
        for event in ("issuing", "verifying", "witnessing", "incident"):
            p.note(event)
            p.clock.t += 5
            p.step()
        self.assertEqual(sent, [EVENTS["issuing"], EVENTS["verifying"], EVENTS["witnessing"], EVENTS["incident"]])


class Throttling(unittest.TestCase):
    def test_a_burst_sends_one_heartbeat_not_one_per_event(self):
        p, sent = make()
        p.step()                                  # the initial idle
        for _ in range(500):
            p.note("issuing")
            p.note("verifying")
            p.note("witnessing")
        for _ in range(5):
            p.step()
        self.assertLessEqual(len(sent), 2, sent)

    def test_nothing_is_sent_twice_for_the_same_state_inside_the_refresh_interval(self):
        p, sent = make(refresh=60.0)
        p.note("issuing")
        p.step()
        for _ in range(30):
            p.clock.t += 1
            p.step()
        self.assertEqual([s for s in sent if s == EVENTS["issuing"]].__len__(), 1)

    def test_a_quiet_server_still_sends_a_heartbeat_every_refresh_interval(self):
        p, sent = make(refresh=60.0, idle_after=10.0)
        p.step()
        for _ in range(130):
            p.clock.t += 1
            p.step()
        self.assertGreaterEqual(len(sent), 3)
        self.assertEqual({s for s in sent}, {EVENTS["idle"]})

    def test_activity_decays_to_idle(self):
        p, sent = make(idle_after=15.0, min_gap=2.0)
        p.note("issuing")
        p.step()
        p.clock.t += 14
        p.step()
        self.assertEqual(sent[-1], EVENTS["issuing"])
        p.clock.t += 3
        p.step()
        self.assertEqual(sent[-1], EVENTS["idle"])


class MinimumGapAndInertness(unittest.TestCase):
    def test_two_different_states_inside_the_minimum_gap_are_one_heartbeat(self):
        p, sent = make(min_gap=2.0)
        p.note("issuing")
        self.assertEqual(p.step(), "issuing")
        p.clock.t += 0.5
        p.note("verifying")
        self.assertIsNone(p.step())               # too soon: waits
        self.assertEqual(sent, [EVENTS["issuing"]])
        p.clock.t += 2.0
        self.assertEqual(p.step(), "verifying")   # and then the latest state goes out
        self.assertEqual(sent, [EVENTS["issuing"], EVENTS["verifying"]])

    def test_an_unconfigured_reporter_records_and_starts_nothing(self):
        for env in ({}, {"FLASHYOS_ORG_ID": "org_abc123"}):
            p = Presence(send=lambda *a: self.fail("sent"), env=env)
            for event in EVENTS:
                p.note(event)
            self.assertEqual(p._seen_events, [])
            self.assertIsNone(p._thread)
            self.assertFalse(p._wake_event.is_set())
            self.assertIsNone(p._last_activity)


class NeverBreaksAVerdict(unittest.TestCase):
    def test_a_sender_that_raises_is_swallowed(self):
        def boom(status, task):
            raise RuntimeError("boom " + TOKEN)
        p, _ = make(send=boom)
        p.note("issuing")
        p.step()
        p.step()

    def test_a_note_that_raises_internally_is_swallowed(self):
        p, _ = make()
        with mock.patch.object(p, "_wake", side_effect=RuntimeError("x")):
            p.note("issuing")

    def test_a_blocked_sender_does_not_block_the_verdict(self):
        gate = threading.Event()
        called = threading.Event()

        def stuck(status, task):
            called.set()
            gate.wait(10)

        p = Presence(send=stuck, env=ENV, min_gap=0.0, tick=0.01)
        presence.set_default(p)
        try:
            started = time.monotonic()
            status, _, out = api.handle("POST", "/v1/verdict", json.dumps(
                {"subject": {"name": SECRET_NAME, "registration_id": "R1"}}).encode(), Store.seeded_from_sample())
            elapsed = time.monotonic() - started
            self.assertEqual(status, 200)
            self.assertTrue(called.wait(2), "the worker thread never tried to send")
            self.assertLess(elapsed, 1.0)
        finally:
            gate.set()
            p.stop()
            presence.reset()

    def test_a_broken_reporter_does_not_break_the_endpoint(self):
        class Broken:
            def note(self, event):
                raise RuntimeError("reporter exploded")
        presence.set_default(Broken())
        try:
            status, _, _ = api.handle("POST", "/v1/verdict", json.dumps(
                {"subject": {"name": "A", "registration_id": "R1"}}).encode(), Store.seeded_from_sample())
            self.assertEqual(status, 200)
        finally:
            presence.reset()


class FollowsRealActivity(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()

    def run_api(self, method, path, payload=None, store=None):
        p, sent = make(clock=Clock(), min_gap=0.0)
        presence.set_default(p)
        try:
            body = json.dumps(payload).encode() if payload is not None else b""
            status, _, out = api.handle(method, path, body, store or self.store)
        finally:
            presence.reset()
        return p, sent, status, out

    def verdict(self, name=SECRET_NAME, body=None):
        payload = body if body is not None else {"subject": {"name": name, "registration_id": "R1"}, "document_text": "ZEBRA-DOC-TEXT"}
        return self.run_api("POST", "/v1/verdict", payload)

    def test_issuing_a_receipt_is_building(self):
        p, sent, status, _ = self.verdict()
        self.assertEqual((status, p._seen_events), (200, ["issuing"]))
        p.step()
        self.assertEqual(sent[-1], ("BUILDING", "Issuing a receipt"))

    def test_verifying_is_testing(self):
        _, _, _, receipt = self.verdict()
        for method, path, payload in (("POST", "/v1/verify", json.loads(receipt)), ("GET", "/v1/log/verify", None),
                                      ("POST", "/v1/decide", {"receipt": json.loads(receipt), "policy": {"max_amount": {"amount_minor": 1, "currency": "USD"},
                                                                                                  "acceptable_verdicts": ["PROCEED"], "min_trust_score": 50}})):
            p, sent, status, _ = self.run_api(method, path, payload)
            self.assertEqual((status, p._seen_events[:1]), (200, ["verifying"]), path)
            p.step()
            self.assertEqual(sent[-1][0], "TESTING", path)

    def test_a_refused_request_shows_no_activity_at_all(self):
        for body in ({"subject": "nope"}, {"subject": {"name": "", "registration_id": "R"}}, {"subject": {"name": "A", "registration_id": "R"}, "extra": 1}):
            p, sent, status, _ = self.verdict(body=body)
            self.assertEqual(status, 400, body)
            self.assertEqual(p._seen_events, [], body)
            p.step()
            self.assertEqual(sent, [EVENTS["idle"]], body)           # only the idle heartbeat

    def test_a_broken_log_is_an_incident_and_no_receipt_is_issued(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            store = Store.load_or_seed(path)
            api.handle("POST", "/v1/verdict", json.dumps({"subject": {"name": "A", "registration_id": "R"}}).encode(), store)
            log = path.with_name("receipts.jsonl")
            log.write_text(log.read_text()[:-30])
            broken = Store.load_or_seed(path)
            for method, route, payload in (("POST", "/v1/verdict", {"subject": {"name": "B", "registration_id": "R"}}), ("GET", "/v1/log/head", None),
                                           ("GET", "/v1/log/verify", None)):
                p, sent, status, _ = self.run_api(method, route, payload, store=broken)
                self.assertEqual(status, 503, route)
                self.assertIn("incident", p._seen_events, route)
                p.step()
                self.assertEqual(sent[-1], ("INCIDENT", "Chain refused or broken"), route)

    def test_a_chain_that_does_not_verify_is_an_incident(self):
        import copy
        store = Store.seeded_from_sample()
        for n in "AB":
            api.handle("POST", "/v1/verdict", json.dumps({"subject": {"name": n, "registration_id": "R"}}).encode(), store)
        store.log._entries[0] = {**store.log._entries[0], "logged_at": "1999-01-01T00:00:00+00:00"}        # tamper in memory
        p, sent, status, out = self.run_api("GET", "/v1/log/verify", store=store)
        self.assertEqual((status, json.loads(out)["valid"]), (200, False))
        self.assertEqual(p._seen_events[-1], "incident")

    def test_an_incident_lingers_longer_than_ordinary_activity(self):
        p, sent = make(idle_after=15.0, min_gap=0.0)
        p.note("incident")
        p.step()
        p.clock.t += 30
        p.step()
        self.assertEqual(sent[-1], EVENTS["incident"])             # still shown at 30 s ...
        p.clock.t += 120
        p.step()
        self.assertEqual(sent[-1], EVENTS["idle"])                 # ... and gone after two minutes

    def test_witnessing_is_review_and_a_refused_chain_is_an_incident(self):
        import tempfile
        from pathlib import Path
        from diligenceos.flashy.spine import SpineKey
        from diligenceos.flashy.witness_ledger import WitnessLedger
        from diligenceos.signing import Signer
        from .helpers import make_log, seed
        key = SpineKey.from_seed_hex(seed("c3"))
        good = make_log(key, [("decision", {"verdict": "ALLOW"})])
        with tempfile.TemporaryDirectory() as d:
            ledger = WitnessLedger(Path(d) / "l.jsonl", Signer.generate())
            p, sent = make(clock=Clock(), min_gap=0.0)
            presence.set_default(p)
            try:
                ledger.witness(good, key.pub_hex, issued_at="2026-10-14T10:00:00.000Z")
                self.assertEqual(p._seen_events, ["witnessing"])
                ledger.witness([], key.pub_hex, issued_at="2026-10-14T10:00:00.000Z")        # empty log: refused
                ledger.witness(good[1:] or [{"x": 1}], key.pub_hex, issued_at="2026-10-14T10:00:00.000Z")
                self.assertEqual(p._seen_events, ["witnessing", "witnessing", "incident", "witnessing", "incident"])
            finally:
                presence.reset()

    def test_nothing_about_the_subject_ever_reaches_the_sender(self):
        p, sent, status, out = self.verdict()
        self.assertEqual(status, 200)
        p.step()
        blob = json.dumps(sent) + repr(p._want) + repr(p._seen_events)
        for fragment in (SECRET_NAME, "ZEBRA", "UK", "PROCEED", "HOLD", "RED_FLAG", "sanction", TOKEN, "R1"):
            self.assertNotIn(fragment, blob)

    def test_the_form_route_reports_too(self):
        import io
        from urllib.parse import urlencode
        from diligenceos import webapp
        p, sent = make(clock=Clock(), min_gap=0.0)
        presence.set_default(p)
        try:
            body = urlencode({"name": SECRET_NAME, "registration_id": "R1"}).encode()
            seen = {}
            webapp.app({"REQUEST_METHOD": "POST", "PATH_INFO": "/verdict", "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)},
                       lambda status, headers: seen.update(status=status))
            self.assertTrue(seen["status"].startswith("200"))
            self.assertEqual(p._seen_events, ["issuing"])
            p.step()
            self.assertNotIn(SECRET_NAME, json.dumps(sent))
        finally:
            presence.reset()


if __name__ == "__main__":
    unittest.main()
