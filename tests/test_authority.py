import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from diligenceos import api, tools
from diligenceos.auth import authenticate, sign_request
from diligenceos.delegation import extend_chain, issue_delegation, verify_chain
from diligenceos.policy import Policy
from diligenceos.receipt import digest, issue_receipt
from diligenceos.signing import Signer
from diligenceos.store import Store
from diligenceos.types import Money, Verdict, VerdictResult

NOW = "2026-09-29T12:00:00+00:00"
LATER = "2026-09-30T12:00:00+00:00"
SOON = "2026-09-29T18:00:00+00:00"


def pol(cap=50_000_000, cur="USD", verdicts=("PROCEED",), floor=70):
    return Policy(Money(cap, cur), frozenset(Verdict(v) for v in verdicts), floor)


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.op, self.a, self.b = Signer.generate(), Signer.generate(), Signer.generate()
        self.root = [self.op.issuer_id]

    def verify(self, chain, now=NOW, revocations=None, root=None):
        return verify_chain(chain, root_issuers=root or self.root, now=now, revocations=revocations)

    def link(self, signer, delegate, chain=(), **kw):
        kw = {"scopes": ["spend"], "expires": LATER, "issued_at": NOW, **kw}
        return [*chain, issue_delegation(signer, delegate=delegate.issuer_id,
                                         parent=chain[-1]["id"] if chain else None, **kw)]

    def test_two_link_chain_verifies_and_reports_the_leaf(self):
        c = self.link(self.op, self.a, scopes=["spend", "revoke"], policy=pol(), budget_id="q4")
        c = self.link(self.a, self.b, c, scopes=["spend"], policy=pol(cap=1000, floor=90), budget_id="q4",
                      expires=SOON)
        r = self.verify(c)
        self.assertTrue(r.valid, r.errors)
        self.assertEqual((r.delegate, r.scopes, r.budget_id, r.root),
                         (self.b.issuer_id, frozenset({"spend"}), "q4", self.op.issuer_id))
        self.assertEqual(r.policy.max_amount.amount_minor, 1000)

    def test_every_widening_is_refused(self):
        parent = self.link(self.op, self.a, scopes=["spend"], policy=pol(), budget_id="q4", expires=SOON)
        cases = {
            "scopes": dict(scopes=["spend", "revoke"], policy=pol(), budget_id="q4", expires=SOON),
            "expiry": dict(scopes=["spend"], policy=pol(), budget_id="q4", expires=LATER),
            "budget changed": dict(scopes=["spend"], policy=pol(), budget_id="other", expires=SOON),
            "budget dropped": dict(scopes=["spend"], policy=pol(), budget_id=None, expires=SOON),
            "policy dropped": dict(scopes=["spend"], policy=None, budget_id="q4", expires=SOON),
            "bigger cap": dict(scopes=["spend"], policy=pol(cap=99_000_000), budget_id="q4", expires=SOON),
            "more verdicts": dict(scopes=["spend"], policy=pol(verdicts=("PROCEED", "HOLD")), budget_id="q4", expires=SOON),
            "lower floor": dict(scopes=["spend"], policy=pol(floor=10), budget_id="q4", expires=SOON),
            "other currency": dict(scopes=["spend"], policy=pol(cur="EUR"), budget_id="q4", expires=SOON),
        }
        for label, kw in cases.items():
            r = self.verify(self.link(self.a, self.b, parent, **kw))
            self.assertFalse(r.valid, label)
        ok = self.link(self.a, self.b, parent, scopes=["spend"], policy=pol(cap=5), budget_id="q4", expires=SOON)
        self.assertTrue(self.verify(ok).valid)

    def test_extend_chain_refuses_a_widening_child_at_creation(self):
        first = extend_chain([], self.op, delegate=self.a.issuer_id, scopes=["spend"],
                             expires=LATER, policy=pol(), issued_at=NOW)
        with self.assertRaises(ValueError) as cm:
            extend_chain(first, self.a, delegate=self.b.issuer_id, scopes=["spend"],
                         expires=LATER, policy=pol(cap=99_000_000), issued_at=NOW)
        self.assertIn("cap", str(cm.exception))
        self.assertEqual(len(extend_chain(first, self.a, delegate=self.b.issuer_id, scopes=["spend"],
                                          expires=LATER, policy=pol(cap=5), issued_at=NOW)), 2)

    def test_failures_that_are_not_widening(self):
        good = self.link(self.op, self.a)
        self.assertFalse(self.verify(good, now=LATER).valid)                       # expired
        self.assertFalse(self.verify(good, revocations={good[0]["id"]: {}}).valid)  # revoked
        self.assertFalse(self.verify(good, root=[self.a.issuer_id]).valid)         # foreign root
        forged = json.loads(json.dumps(good)); forged[0]["scopes"] = ["spend", "revoke"]
        self.assertFalse(self.verify(forged).valid)                                # edited
        stolen = json.loads(json.dumps(good)); stolen[0]["signature"] = self.a.sign("diligenceos.delegation/1", stolen[0]["id"])
        self.assertFalse(self.verify(stolen).valid)                                # wrong signer
        stranger = self.link(self.b, self.a, self.link(self.op, self.a))           # b is not a's delegate
        self.assertFalse(self.verify(stranger).valid)
        long = self.link(self.op, self.a)
        signers = [self.a, self.b, self.a, self.b]
        for s, d in zip(signers, [self.b, self.a, self.b, self.a]):
            long = self.link(s, d, long)
        self.assertFalse(self.verify(long).valid)                                  # too deep

    def test_malformed_input_never_raises(self):
        for bad in (None, [], "x", [None], [{}], [{"schema": "diligenceos.delegation/1"}], [1, 2]):
            self.assertFalse(self.verify(bad).valid, bad)
        self.assertFalse(self.verify(self.link(self.op, self.a), now="not a time").valid)

    def test_issue_validates_scopes_and_expiry(self):
        for kw in ({"scopes": []}, {"scopes": ["root"]}, {"scopes": ["spend"], "expires": "soon"}):
            with self.assertRaises(ValueError):
                issue_delegation(self.op, delegate=self.a.issuer_id, **{"expires": LATER, **kw})


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.op, self.agent = Signer.generate(), Signer.generate()
        self.body = {"budget_id": "q4", "n": 1}
        self.chain = [issue_delegation(self.op, delegate=self.agent.issuer_id, scopes=["spend"],
                                       expires=LATER, issued_at=NOW)]

    def auth(self, signer, chain, path="/v1/spend", body=None, **kw):
        return sign_request(signer, chain, path, body if body is not None else self.body, now=NOW, **kw)

    def run_auth(self, auth, path="/v1/spend", body=None, now=NOW, seen=None):
        return authenticate(path, body if body is not None else self.body, auth,
                            root_issuers=[self.op.issuer_id], now=now, remember_nonce=seen)

    def test_operator_and_delegate_authenticate(self):
        r = self.run_auth(self.auth(self.op, []))
        self.assertTrue(r.ok and r.is_root, r.errors)
        r = self.run_auth(self.auth(self.agent, self.chain))
        self.assertEqual((r.ok, r.is_root, r.scopes), (True, False, frozenset({"spend"})))

    def test_what_is_signed_cannot_change(self):
        a = self.auth(self.agent, self.chain)
        self.assertFalse(self.run_auth(a, body={**self.body, "n": 2}).ok)
        self.assertFalse(self.run_auth(a, path="/v1/revoke").ok)
        self.assertFalse(self.run_auth({**a, "nonce": "other"}).ok)
        self.assertFalse(self.run_auth({**a, "issued_at": "2026-09-29T12:00:01+00:00"}).ok)
        self.assertFalse(self.run_auth(a, now="2026-09-29T12:10:00+00:00").ok)  # stale
        self.assertTrue(self.run_auth(a, now="2026-09-29T12:04:00+00:00").ok)   # inside the window

    def test_request_key_must_be_the_credentials_delegate(self):
        thief = Signer.generate()
        self.assertFalse(self.run_auth(self.auth(thief, self.chain)).ok)   # stolen credential, wrong key
        self.assertFalse(self.run_auth(self.auth(thief, [])).ok)           # not the operator either

    def test_replayed_nonce_is_rejected(self):
        store = Store()
        a = self.auth(self.agent, self.chain)
        self.assertTrue(self.run_auth(a, seen=store.remember_nonce).ok)
        r = self.run_auth(a, seen=store.remember_nonce)
        self.assertFalse(r.ok)
        self.assertIn("replay", r.errors[0])

    def test_bad_envelopes_never_raise(self):
        for bad in (None, {}, [], {"signer": 1}, {"signer": "x", "chain": "no", "issued_at": NOW,
                                                  "nonce": "n", "signature": "s"}):
            self.assertFalse(self.run_auth(bad).ok)


class ApiAuthTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Store.load_or_seed(Path(self._tmp.name) / "store.json")
        self.op = self.store.signer
        self.agent, self.sub = Signer.generate(), Signer.generate()
        req = {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
               "transaction": {"amount_minor": 24_000_000, "currency": "USD"}}
        self.receipt = self.raw("POST", "/v1/verdict", req)[1]

    def tearDown(self):
        self._tmp.cleanup()

    def raw(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        status, _, out = api.handle(method, path, body, self.store)
        return status, json.loads(out)

    def signed(self, signer, chain, path, body):
        return {**body, "auth": sign_request(signer, chain, path, body)}

    def cred(self, signer=None, scopes=("spend",), hours=6, **kw):
        exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).replace(microsecond=0).isoformat()
        return extend_chain([], self.op, delegate=(signer or self.agent).issuer_id,
                            scopes=list(scopes), expires=exp, **kw)

    def spend_body(self, **kw):
        return {"budget_id": "q4", "receipt": self.receipt, **kw}

    def spend(self, signer, chain, **kw):
        return self.raw("POST", "/v1/spend", self.signed(signer, chain, "/v1/spend", self.spend_body(**kw)))

    def test_unauthenticated_calls_are_401(self):
        for path, body in (("/v1/spend", self.spend_body(policy=pol().to_dict())),
                           ("/v1/revoke", {"receipt_id": self.receipt["id"], "reason": "x"})):
            status, out = self.raw("POST", path, body)
            self.assertEqual((status, out["error"]["code"]), (401, "unauthenticated"), path)
        self.assertEqual(self.raw("POST", "/v1/revoke", {"auth": "nope"})[0], 401)

    def test_authentication_comes_before_validation(self):
        # an unauthenticated caller must learn nothing about what a valid body looks like
        for path in ("/v1/spend", "/v1/revoke"):
            for body in ({}, {"budget_id": ""}, {"receipt": 5}, {"reason": 1}):
                status, out = self.raw("POST", path, body)
                self.assertEqual((status, out["error"]["code"]), (401, "unauthenticated"), (path, body))
        status, out = self.raw("POST", "/v1/spend", [1])  # not even an object: still not a validation answer we vary
        self.assertEqual(status, 400)

    def test_operator_can_revoke_and_spend(self):
        p = pol().to_dict()
        self.assertEqual(self.spend(self.op, [], policy=p)[1]["decision"], "ALLOW")
        body = {"receipt_id": self.receipt["id"], "reason": "test"}
        self.assertEqual(self.raw("POST", "/v1/revoke", self.signed(self.op, [], "/v1/revoke", body))[0], 200)

    def test_a_signed_request_cannot_be_replayed(self):
        wire = self.signed(self.op, [], "/v1/spend", self.spend_body(policy=pol().to_dict()))
        self.assertEqual(self.raw("POST", "/v1/spend", wire)[0], 200)
        status, out = self.raw("POST", "/v1/spend", wire)
        self.assertEqual(status, 401)
        self.assertIn("replay", out["error"]["message"])

    def test_scope_is_enforced(self):
        chain = self.cred(scopes=("spend",))
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, chain, "/v1/revoke", {"receipt_id": self.receipt["id"], "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))
        rev = self.cred(scopes=("revoke",))
        self.assertEqual(self.spend(self.agent, rev, policy=pol().to_dict())[0], 403)
        # Holding the "revoke" scope is necessary but not sufficient: fixed
        # 2026-10-01, this receipt was issued by the operator, not self.agent,
        # so self.agent may not revoke it even with the right scope — see
        # test_revoke_scope_is_restricted_to_what_was_actually_created below.
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, rev, "/v1/revoke", {"receipt_id": self.receipt["id"], "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))

    def test_credential_policy_is_the_policy_and_the_caller_is_recorded(self):
        chain = self.cred(policy=pol(cap=30_000_000))
        status, out = self.spend(self.agent, chain)               # no request policy at all
        self.assertEqual((status, out["decision"], out["effective_policy"]["max_amount"]["amount_minor"]),
                         (200, "ALLOW", 30_000_000))
        self.assertEqual(self.store.spend_entry("q4", self.receipt["id"]).amount_minor, 24_000_000)
        recorded = json.loads(json.dumps(self.store._spend))["q4"][self.receipt["id"]]
        self.assertEqual(recorded["caller"], self.agent.issuer_id)

    def test_request_policy_may_narrow_but_never_widen_the_credential(self):
        chain = self.cred(policy=pol(cap=30_000_000))
        status, out = self.spend(self.agent, chain, policy=pol(cap=99_000_000).to_dict())
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))
        status, out = self.spend(self.agent, chain, policy=pol(cap=10_000_000).to_dict())
        self.assertEqual((status, out["decision"]), (200, "ESCALATE"))  # 24M > the narrowed 10M cap

    def test_policyless_credential_needs_a_request_policy(self):
        chain = self.cred()
        self.assertEqual(self.spend(self.agent, chain)[0], 400)
        self.assertEqual(self.spend(self.agent, chain, policy=pol().to_dict())[0], 200)

    def test_budget_binding(self):
        chain = self.cred(budget_id="q4")
        self.assertEqual(self.spend(self.agent, chain, policy=pol().to_dict())[0], 200)
        status, out = self.raw("POST", "/v1/spend", self.signed(
            self.agent, chain, "/v1/spend", {**self.spend_body(policy=pol().to_dict()), "budget_id": "q1"}))
        self.assertEqual((status, out["error"]["field"]), (403, "budget_id"))

    def test_subdelegation_end_to_end_and_widening_child_is_useless(self):
        chain = self.cred(policy=pol(cap=30_000_000))
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()
        sub = extend_chain(chain, self.agent, delegate=self.sub.issuer_id, scopes=["spend"],
                           expires=exp, policy=pol(cap=25_000_000))
        self.assertEqual(self.spend(self.sub, sub)[1]["effective_policy"]["max_amount"]["amount_minor"], 25_000_000)
        wide = [*chain, issue_delegation(self.agent, delegate=self.sub.issuer_id, scopes=["spend"],
                                         expires=exp, policy=pol(cap=99_000_000), parent=chain[-1]["id"])]
        status, out = self.spend(self.sub, wide)
        self.assertEqual((status, out["error"]["code"]), (401, "unauthenticated"))
        self.assertIn("widens", out["error"]["message"])

    def test_revoking_a_delegation_cuts_off_everything_below_it(self):
        chain = self.cred()
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()
        sub = extend_chain(chain, self.agent, delegate=self.sub.issuer_id, scopes=["spend"], expires=exp)
        self.assertEqual(self.spend(self.sub, sub, policy=pol().to_dict())[0], 200)
        body = {"delegation_id": chain[0]["id"], "reason": "agent compromised"}
        status, out = self.raw("POST", "/v1/revoke", self.signed(self.op, [], "/v1/revoke", body))
        self.assertEqual((status, out["delegation_id"]), (200, chain[0]["id"]))
        for who, c in ((self.agent, chain), (self.sub, sub)):
            status, out = self.spend(who, c, policy=pol().to_dict())
            self.assertEqual(status, 401)
            self.assertIn("revoked", out["error"]["message"])

    # --- Regressions for the 2026-10-01 security hardening pass ---------------

    def test_spend_ignores_a_self_supplied_trusted_issuers(self):
        # Before the fix: a delegate could submit a receipt it signed ITSELF
        # (empty findings replay to PROCEED/85, expires stays null) and list
        # its own key in `trusted_issuers` in the request body — the server
        # honored that and allowed the spend. trusted_issuers for /v1/spend
        # must come from server config only now.
        forged = issue_receipt(
            subject={"name": "Meridian Robotics Ltd."}, inputs={},
            result=VerdictResult(verdict=Verdict.PROCEED, trust_score=85, findings=()),
            transaction=Money(24_000_000, "USD").to_dict(), issued_at=NOW, signer=self.agent,
        )
        self.assertIsNone(forged["expires"])
        chain = self.cred(scopes=("spend",))
        body = {
            "budget_id": "q4", "receipt": forged, "policy": pol().to_dict(),
            "trusted_issuers": [self.agent.issuer_id],
        }
        status, out = self.raw("POST", "/v1/spend", self.signed(self.agent, chain, "/v1/spend", body))
        self.assertEqual(status, 200)  # a well-formed request; the *decision* must deny
        self.assertEqual(out["decision"], "DENY")
        self.assertIn("not validly signed by a trusted issuer", out["reasons"][0])

    def test_verify_does_not_trust_a_receipt_that_names_itself_trusted(self):
        # Before the fix: a bare (unwrapped) receipt could carry its own
        # trusted_issuers field and certify itself. trusted_issuers may only
        # come from the verifying caller's own envelope, never the object
        # being verified.
        forged = issue_receipt(
            subject={"name": "Shadow Co."}, inputs={},
            result=VerdictResult(verdict=Verdict.PROCEED, trust_score=85, findings=()),
            issued_at=NOW, signer=self.agent,
        )
        forged["trusted_issuers"] = [self.agent.issuer_id]  # the attacker's own addition
        status, out = self.raw("POST", "/v1/verify", forged)  # posted bare, no envelope
        self.assertEqual(status, 200)
        self.assertTrue(out["signed"])    # the agent's own signature is genuine
        self.assertFalse(out["valid"])    # id no longer matches the (now tampered) contents
        self.assertFalse(out["trusted"])  # must not trust the receipt's own say-so

    def test_delegate_cannot_revoke_a_receipt_it_did_not_issue(self):
        # Receipts are always issued with the operator's own key; holding
        # "revoke" never makes a delegate the issuer of one.
        rev = self.cred(scopes=("revoke",))
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, rev, "/v1/revoke", {"receipt_id": self.receipt["id"], "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))

    def test_delegate_can_revoke_a_delegation_it_issued_itself(self):
        chain = self.cred(scopes=("spend", "revoke"))
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()
        sub = extend_chain(chain, self.agent, delegate=self.sub.issuer_id, scopes=["spend"], expires=exp)
        issued = sub[-1]  # the agent -> sub link; delegator == self.agent
        body = {"delegation": issued, "reason": "sub-agent retired"}
        status, out = self.raw("POST", "/v1/revoke", self.signed(self.agent, chain, "/v1/revoke", body))
        self.assertEqual((status, out["delegation_id"]), (200, issued["id"]))
        status, out = self.spend(self.sub, sub, policy=pol().to_dict())
        self.assertEqual(status, 401)
        self.assertIn("revoked", out["error"]["message"])

    def test_delegate_cannot_revoke_a_delegation_it_did_not_issue(self):
        chain = self.cred(scopes=("revoke",))  # operator -> agent
        # by id alone: only the operator may revoke by id without proving authorship
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, chain, "/v1/revoke", {"delegation_id": chain[0]["id"], "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))
        # by submitting the object: the agent is this link's *delegate*, not its delegator
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, chain, "/v1/revoke", {"delegation": chain[0], "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))

    def test_delegate_cannot_revoke_a_siblings_delegation(self):
        mine = self.cred(scopes=("revoke",), signer=self.agent)
        theirs = self.cred(scopes=("spend",), signer=self.sub)  # operator -> sub; agent had no part in it
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, mine, "/v1/revoke", {"delegation": theirs[0], "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (403, "forbidden"))

    def test_revoke_rejects_a_tampered_delegation_object(self):
        chain = self.cred(scopes=("spend", "revoke"))
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0).isoformat()
        sub = extend_chain(chain, self.agent, delegate=self.sub.issuer_id, scopes=["spend"], expires=exp)
        issued = sub[-1]

        edited_field_stale_id = {**issued, "scopes": ["spend", "revoke"]}  # id/signature now stale
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, chain, "/v1/revoke", {"delegation": edited_field_stale_id, "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (400, "invalid_request"))

        # id recomputed to match the edit, but the signature is still the
        # original one (over the old delegator/body) — must not verify
        relinked = {k: v for k, v in issued.items() if k not in ("id", "signature")}
        relinked["delegator"] = self.op.issuer_id
        forged_signature = {**relinked, "id": digest(relinked), "signature": issued["signature"]}
        status, out = self.raw("POST", "/v1/revoke", self.signed(
            self.agent, chain, "/v1/revoke", {"delegation": forged_signature, "reason": "x"}))
        self.assertEqual((status, out["error"]["code"]), (400, "invalid_request"))

    def test_expired_credential_is_rejected(self):
        chain = [issue_delegation(self.op, delegate=self.agent.issuer_id, scopes=["spend"],
                                  expires="2020-01-01T00:00:00+00:00", issued_at="2019-01-01T00:00:00+00:00")]
        self.assertEqual(self.spend(self.agent, chain, policy=pol().to_dict())[0], 401)

    def test_open_endpoints_stay_open(self):
        for method, path in (("GET", "/v1/revocations"), ("GET", "/v1/log/head"), ("GET", "/v1/issuer")):
            self.assertEqual(self.raw(method, path)[0], 200, path)
        self.assertEqual(self.raw("POST", "/v1/decide", {"receipt": self.receipt, "policy": pol().to_dict()})[0], 200)


class ToolsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def run_tool(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tools.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_full_flow_through_the_cli_and_api(self):
        store = Store.load_or_seed(self.dir / "store.json")
        store.signer  # the server creates the operator key on first use
        op_key = str(self.dir / "issuer.key")
        agent_key = str(self.dir / "agent.key")
        code, out, _ = self.run_tool("keygen", agent_key)
        agent_id = json.loads(out)["issuer"]
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["issuer"], Signer.load_or_create(Path(agent_key)).issuer_id)

        chain_file = self.dir / "chain.json"
        code, out, _ = self.run_tool("delegate", "--key", op_key, "--subject", agent_id, "--scopes", "spend",
                                     "--max-amount", "30000000", "--currency", "USD", "--min-trust", "70",
                                     "--budget", "q4")
        self.assertEqual(code, 0)
        chain_file.write_text(out)
        chain = json.loads(out)
        self.assertEqual((chain[0]["scopes"], chain[0]["budget_id"]), (["spend"], "q4"))

        # widening onward delegation is refused by the tool itself
        sub_id = Signer.generate().issuer_id
        code, _, err = self.run_tool("delegate", "--key", agent_key, "--chain", str(chain_file),
                                     "--subject", sub_id, "--scopes", "spend", "--max-amount", "99000000",
                                     "--currency", "USD", "--min-trust", "70", "--budget", "q4")
        self.assertEqual(code, 2)
        self.assertIn("cap", err)

        req = {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
               "transaction": {"amount_minor": 24_000_000, "currency": "USD"}}
        _, _, out_ = api.handle("POST", "/v1/verdict", json.dumps(req).encode(), store)
        body_file = self.dir / "body.json"
        body_file.write_text(json.dumps({"budget_id": "q4", "receipt": json.loads(out_)}))
        code, out, _ = self.run_tool("sign-request", "--key", agent_key, "--chain", str(chain_file),
                                     "--path", "/v1/spend", str(body_file))
        self.assertEqual(code, 0)
        status, _, resp = api.handle("POST", "/v1/spend", out.encode(), store)
        self.assertEqual((status, json.loads(resp)["decision"]), (200, "ALLOW"))

    def test_bad_inputs_exit_2_without_a_traceback(self):
        cases = (
            ("delegate", "--key", str(self.dir / "missing.key"), "--subject", "x", "--scopes", "spend"),
            ("sign-request", "--key", str(self.dir / "k"), "--path", "/v1/spend", str(self.dir / "nope.json")),
        )
        for argv in cases:
            code, _, err = self.run_tool(*argv)
            self.assertEqual(code, 2, argv)
            self.assertTrue(err.startswith("error:"), err)
        Signer.load_or_create(self.dir / "k")
        (self.dir / "auth.json").write_text('{"auth": {}}')
        self.assertEqual(self.run_tool("sign-request", "--key", str(self.dir / "k"), "--path", "/p",
                                       str(self.dir / "auth.json"))[0], 2)
        code, _, err = self.run_tool("delegate", "--key", str(self.dir / "k"), "--subject", "x",
                                     "--scopes", "spend", "--max-amount", "5")
        self.assertEqual(code, 2)
        self.assertIn("policy needs all", err)


if __name__ == "__main__":
    unittest.main()
