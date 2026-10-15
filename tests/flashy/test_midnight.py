"""The daily cap across UTC midnight.

The stand-in plane once released a reservation against the day it was released on, so an authorization issued late
on day N and given back after midnight decremented day N+1. That is fixed upstream (it stores the issue day) and
the JS suite pins it; the first test here re-runs that JS test so a regression upstream fails here too.

The witness must agree with the fixed plane: a release credits the day the authorization was issued, never the day
it was released, and the cap is judged at the moment of each issuance, not after the fact. Judging it after the fact
(netting every release out of the day's total) hides an overspend that a later release happens to repay."""

import subprocess
import unittest

from diligenceos.flashy import witness
from diligenceos.flashy.spine import SpineKey

from .helpers import DEMO, NODE, make_log, need_node, seed

KEY = SpineKey.from_seed_hex(seed("c3"))
AG = "11" * 32
CAP = 100


def issue(req, auth, amount, ts, agent=AG):
    return [("request_received", {"requestId": req[:4], "requestHash": req, "agent": agent, "spend": {"chain": "evm:31337", "amount": str(amount)}, "purpose": "p"}, ts),
            ("authorization_issued", {"authId": auth, "requestHash": req, "amount": str(amount)}, ts)]


def release(auth, ts, how="expired_unused"):
    if how == "expired_unused":
        return [("expired_unused", {"authId": auth}, ts)]
    return [("outcome", {"authId": auth, "state": "failed", "reservation": "released"}, ts)]


def caps(items, cap=CAP):
    return witness.check_daily_caps(make_log(KEY, items), cap)


N = "2026-10-14T23:58:00.000Z"
LATE = "2026-10-14T23:59:30.000Z"
AFTER = "2026-10-15T00:01:00.000Z"
LATER = "2026-10-15T00:03:00.000Z"


class UpstreamPlaneStillReleasesToTheIssueDay(unittest.TestCase):
    def test_the_plane_s_own_midnight_test_passes(self):
        need_node()
        done = subprocess.run([NODE, "--test", "--test-name-pattern", "released against YESTERDAY", str(DEMO / "test" / "phase4.test.js")],
                              capture_output=True, text=True, cwd=DEMO, timeout=60)
        self.assertEqual(done.returncode, 0, done.stdout[-600:] + done.stderr[-300:])
        self.assertIn("pass 1", done.stdout)


class WitnessAgreesWithTheFixedPlane(unittest.TestCase):
    def test_a_release_after_midnight_is_credited_to_the_day_it_was_issued(self):
        r = caps(issue("r1", "a1", 100, N) + release("a1", AFTER) + issue("r2", "a2", 100, LATER))
        self.assertTrue(r["ok"], r)        # day N+1 holds only its own 100, not 100 minus a1

    def test_the_symptom_of_the_old_plane_bug_is_flagged_on_the_day_it_overspends(self):
        # a plane that credited the release to day N+1 would let N+1 reach 200 against a cap of 100
        r = caps(issue("r1", "a1", 100, N) + release("a1", AFTER) + issue("r2", "a2", 100, LATER) + issue("r3", "a3", 100, "2026-10-15T00:04:00.000Z"))
        self.assertFalse(r["ok"])
        self.assertEqual([(v["day"], v["total_base_units"]) for v in r["violations"]], [("2026-10-15", "200")])

    def test_an_overspend_that_a_later_release_repays_is_still_an_overspend(self):
        # day N: a1 (100) is reserved, then a2 (100) is issued on top of it: 200 reserved at 23:59:30. a1 is given back after midnight.
        r = caps(issue("r1", "a1", 100, N) + issue("r2", "a2", 100, LATE) + release("a1", AFTER))
        self.assertFalse(r["ok"], "netting the release after the fact would hide the moment the cap was broken")
        self.assertEqual([(v["day"], v["total_base_units"]) for v in r["violations"]], [("2026-10-14", "200")])

    def test_the_same_overspend_repaid_by_each_kind_of_release(self):
        for how in ("expired_unused", "outcome"):
            r = caps(issue("r1", "a1", 100, N) + issue("r2", "a2", 100, LATE) + release("a1", AFTER, how))
            self.assertFalse(r["ok"], how)

    def test_a_release_then_a_reissue_the_same_day_is_fine(self):
        r = caps(issue("r1", "a1", 100, "2026-10-14T10:00:00.000Z") + release("a1", "2026-10-14T10:30:00.000Z") + issue("r2", "a2", 100, "2026-10-14T11:00:00.000Z"))
        self.assertTrue(r["ok"], r)

    def test_a_release_cannot_be_counted_twice(self):
        r = caps(issue("r1", "a1", 100, N) + release("a1", LATE) + release("a1", AFTER, "outcome") + issue("r2", "a2", 100, AFTER) + issue("r3", "a3", 100, LATER), cap=150)
        self.assertFalse(r["ok"], r)
        self.assertEqual([(v["day"], v["total_base_units"]) for v in r["violations"]], [("2026-10-15", "200")])

    def test_a_release_that_comes_before_its_issuance_credits_nothing(self):
        r = caps(release("a1", N) + issue("r1", "a1", 100, LATE) + issue("r2", "a2", 100, LATE), cap=150)
        self.assertFalse(r["ok"])

    def test_a_release_for_an_authorization_nobody_issued_changes_nothing(self):
        r = caps(release("ghost", N) + issue("r1", "a1", 100, LATE) + issue("r2", "a2", 100, LATE), cap=150)
        self.assertEqual([v["total_base_units"] for v in r["violations"]], ["200"])

    def test_a_settled_authorization_stays_counted_all_day(self):
        settle = [("outcome", {"authId": "a1", "state": "confirmed", "reservation": "settled"}, LATE)]
        r = caps(issue("r1", "a1", 100, N) + settle + issue("r2", "a2", 100, AFTER) + issue("r3", "a3", 100, LATER), cap=150)
        self.assertEqual([(v["day"], v["total_base_units"]) for v in r["violations"]], [("2026-10-15", "200")])      # N+1: a2 + a3; a1 belongs to N

    def test_each_agent_and_chain_has_its_own_day(self):
        other = issue("r2", "a2", 100, LATE, agent="22" * 32)
        self.assertTrue(caps(issue("r1", "a1", 100, N) + other)["ok"])

    def test_the_peak_not_the_final_total_is_what_is_reported(self):
        r = caps(issue("r1", "a1", 100, N) + issue("r2", "a2", 60, LATE) + release("a1", AFTER) + release("a2", LATER))
        self.assertEqual([v["total_base_units"] for v in r["violations"]], ["160"])

    def test_an_authorization_id_issued_twice_fails_closed(self):
        r = caps(issue("r1", "a1", 10, N) + issue("r2", "a1", 10, LATE))
        self.assertFalse(r["ok"])
        self.assertEqual([p["code"] for p in r["problems"]], ["DUPLICATE_AUTHORIZATION"])

    def test_without_releases_nothing_changes(self):
        self.assertTrue(caps(issue("r1", "a1", 60, N) + issue("r2", "a2", 40, LATE))["ok"])
        self.assertEqual([v["total_base_units"] for v in caps(issue("r1", "a1", 60, N) + issue("r2", "a2", 41, LATE))["violations"]], ["101"])


if __name__ == "__main__":
    unittest.main()
