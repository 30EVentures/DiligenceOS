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
            presence.note("received")
            self.assertFalse(presence.default().configured)


class ClosedVocabulary(unittest.TestCase):
    def test_only_the_four_known_events_are_accepted(self):
        for bad in (None, "", "received ", "RECEIVED", f"verdict for {SECRET_NAME}", {"event": "received"}, ["issued"], 5, True, b"idle"):
            p, sent = make()
            p.step()                       # the initial idle heartbeat
            sent.clear()
            p.note(bad)
            p.clock.t += 5
            self.assertIsNone(p.step(), bad)
            self.assertEqual(sent, [], bad)
            self.assertEqual(p._seen_events, [], bad)

    def test_every_label_is_a_fixed_ascii_string_from_the_table(self):
        self.assertEqual(set(EVENTS), {"received", "gathering", "issued", "idle"})
        for status, task in EVENTS.values():
            self.assertIn(status, presence.mesh_reporter.STATUSES)
            self.assertTrue(task.isascii() and len(task) <= 40)

    def test_what_is_sent_is_exactly_a_table_row(self):
        p, sent = make(clock=Clock())
        for event in ("received", "gathering", "issued"):
            p.note(event)
            p.clock.t += 5
            p.step()
        self.assertEqual(sent, [EVENTS["received"], EVENTS["gathering"], EVENTS["issued"]])


class Throttling(unittest.TestCase):
    def test_a_burst_sends_one_heartbeat_not_one_per_event(self):
        p, sent = make()
        p.step()                                  # the initial idle
        for _ in range(500):
            p.note("received")
            p.note("gathering")
            p.note("issued")
        for _ in range(5):
            p.step()
        self.assertLessEqual(len(sent), 2, sent)

    def test_nothing_is_sent_twice_for_the_same_state_inside_the_refresh_interval(self):
        p, sent = make(refresh=60.0)
        p.note("issued")
        p.step()
        for _ in range(30):
            p.clock.t += 1
            p.step()
        self.assertEqual([s for s in sent if s == EVENTS["issued"]].__len__(), 1)

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
        p.note("issued")
        p.step()
        p.clock.t += 14
        p.step()
        self.assertEqual(sent[-1], EVENTS["issued"])
        p.clock.t += 3
        p.step()
        self.assertEqual(sent[-1], EVENTS["idle"])


class MinimumGapAndInertness(unittest.TestCase):
    def test_two_different_states_inside_the_minimum_gap_are_one_heartbeat(self):
        p, sent = make(min_gap=2.0)
        p.note("received")
        self.assertEqual(p.step(), "received")
        p.clock.t += 0.5
        p.note("issued")
        self.assertIsNone(p.step())               # too soon: waits
        self.assertEqual(sent, [EVENTS["received"]])
        p.clock.t += 2.0
        self.assertEqual(p.step(), "issued")      # and then the latest state goes out
        self.assertEqual(sent, [EVENTS["received"], EVENTS["issued"]])

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
        p.note("received")
        p.step()
        p.step()

    def test_a_note_that_raises_internally_is_swallowed(self):
        p, _ = make()
        with mock.patch.object(p, "_wake", side_effect=RuntimeError("x")):
            p.note("received")

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
    def run_verdict(self, name=SECRET_NAME, body=None):
        p, sent = make(clock=Clock(), min_gap=0.0)
        presence.set_default(p)
        try:
            payload = body if body is not None else {"subject": {"name": name, "registration_id": "R1"}, "document_text": "ZEBRA-DOC-TEXT"}
            status, _, out = api.handle("POST", "/v1/verdict", json.dumps(payload).encode(), Store.seeded_from_sample())
        finally:
            presence.reset()
        return p, sent, status, out

    def test_a_verdict_walks_through_received_gathering_issued(self):
        p, sent, status, _ = self.run_verdict()
        self.assertEqual(status, 200)
        self.assertEqual(p._seen_events, ["received", "gathering", "issued"])

    def test_a_refused_request_is_received_but_never_reported_as_issued(self):
        for body in ({"subject": "nope"}, {"subject": {"name": "", "registration_id": "R"}}, {"subject": {"name": "A", "registration_id": "R"}, "extra": 1}):
            p, _, status, _ = self.run_verdict(body=body)
            self.assertEqual(status, 400, body)
            self.assertEqual(p._seen_events, ["received"], body)

    def test_nothing_about_the_subject_ever_reaches_the_sender(self):
        p, sent, status, out = self.run_verdict()
        self.assertEqual(status, 200)
        p.step()
        blob = json.dumps(sent) + repr(p.__dict__.get("_want")) + repr(p._seen_events)
        for fragment in (SECRET_NAME, "ZEBRA", "UK", "PROCEED", "HOLD", "RED_FLAG", "sanction", TOKEN):
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
            self.assertEqual(p._seen_events, ["received", "gathering", "issued"])
            p.step()
            self.assertNotIn(SECRET_NAME, json.dumps(sent))
        finally:
            presence.reset()


if __name__ == "__main__":
    unittest.main()
