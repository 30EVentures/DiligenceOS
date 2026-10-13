"""Round 6 of the overnight review: every verifier and endpoint, given a document an attacker has
mangled, answers (usually 'no') and never raises. Deterministic: fixed seeds, fixed caller arguments;
only the attacker-controlled document is mutated."""

import copy
import json
import random
import unittest

from auth_helpers import as_operator
from diligenceos import api
from diligenceos.auth import authenticate, sign_request
from diligenceos.conformance import test_signer
from diligenceos.delegation import issue_delegation, verify_chain
from diligenceos.engine import assemble_verdict
from diligenceos.policy import Policy, decide
from diligenceos.receipt import issue_receipt, verify_receipt
from diligenceos.receipt_log import ReceiptLog, verify_chain as verify_log
from diligenceos.signing import LOG_HEAD_DOMAIN, head_message, verify_head
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding, Money, Verdict
from diligenceos.witness import check_consistency, cosign_head, verify_cosignature

NOW = "2026-10-13T12:00:00+00:00"
OP, AGENT, WITNESS = test_signer(1), test_signer(2), test_signer(3)
POLICY = Policy(Money(100, "USD"), frozenset({Verdict.PROCEED}), 50)
JUNK = (None, True, False, 0, -1, 1, 2**63, 2**64, 1.5, "", "x", "sha256:" + "0" * 64, "\u0000", [], [1], {}, {"a": 1}, [[]],
        "2026-01-01T00:00:00+00:00", "ed25519:" + "0" * 64, "ed25519:" + "0" * 128, [{"a": [1]}], {"k": {"k": {}}})


def mutate(rnd, obj):
    """A deep copy with one randomly chosen node replaced, deleted, or given a stray sibling."""
    obj = copy.deepcopy(obj)
    node, trail = obj, []
    for _ in range(rnd.randint(1, 4)):
        if isinstance(node, dict) and node:
            key = rnd.choice(list(node))
        elif isinstance(node, list) and node:
            key = rnd.randrange(len(node))
        else:
            break
        trail.append((node, key))
        node = node[key]
    if not trail:
        return copy.deepcopy(rnd.choice(JUNK))
    parent, key = trail[-1]
    roll = rnd.random()
    if roll < 0.2:
        del parent[key]
    elif roll < 0.3 and isinstance(parent, dict):
        parent[rnd.choice(["extra", "x"])] = copy.deepcopy(rnd.choice(JUNK))
    else:
        parent[key] = copy.deepcopy(rnd.choice(JUNK))
    return obj


def fixtures():
    receipt = issue_receipt(
        subject={"name": "S", "registration_id": "R"}, inputs={"n": 1},
        result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]),
        transaction={"amount_minor": 5, "currency": "USD"}, issued_at="2026-10-13T11:00:00+00:00",
        ttl_seconds=7200, signer=OP)
    link = issue_delegation(OP, delegate=AGENT.issuer_id, scopes=["spend"], expires="2026-12-01T00:00:00+00:00",
                            policy=POLICY, budget_id="b", issued_at="2026-10-01T00:00:00+00:00")
    log = ReceiptLog(None)
    for n in range(3):
        log.append(issue_receipt(subject={"name": f"S{n}"}, inputs={"n": n}, result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]),
                                 issued_at="2026-10-13T11:00:00+00:00"), now=NOW, signer=OP)
    head = {"length": 3, "head_hash": log.head, "issuer": OP.issuer_id, "cosignatures": [],
            "signature": OP.sign(LOG_HEAD_DOMAIN, head_message(3, log.head))}
    return receipt, link, log, head


class HostileDocumentsTest(unittest.TestCase):
    ROUNDS = 400

    @classmethod
    def setUpClass(cls):
        cls.receipt, cls.link, cls.log, cls.head = fixtures()
        cls.cosig = cosign_head(WITNESS, OP.issuer_id, 3, cls.log.head)
        cls.body = {"budget_id": "b", "receipt": cls.receipt, "policy": POLICY.to_dict()}
        cls.env = sign_request(AGENT, [cls.link], "/v1/spend", cls.body, now=NOW)

    def each(self, seed, fn):
        rnd = random.Random(seed)
        for i in range(self.ROUNDS):
            try:
                fn(rnd)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"round {i} of seed {seed}: {type(exc).__name__}: {exc}")

    def test_verify_receipt_and_decide_never_raise(self):
        self.each(1, lambda rnd: verify_receipt(mutate(rnd, self.receipt), now=NOW, revocations={}, trusted_issuers=[OP.issuer_id]))
        self.each(2, lambda rnd: decide(mutate(rnd, self.receipt), POLICY, now=NOW, revocations={}, trusted_issuers=[OP.issuer_id]))

    def test_a_receipt_whose_id_is_a_list_or_object_is_invalid_not_a_crash(self):
        for bad in ([], {}, [1], {"a": 1}, 5, None, True):
            check = verify_receipt({**self.receipt, "id": bad}, now=NOW, revocations={"x": {}}, trusted_issuers=[OP.issuer_id])
            self.assertFalse(check.valid, repr(bad))
            self.assertFalse(check.revoked)

    def test_delegation_chains_never_raise(self):
        self.each(3, lambda rnd: verify_chain(mutate(rnd, [self.link]), root_issuers=[OP.issuer_id], now=NOW, revocations={}))

    def test_a_verifier_given_an_unreadable_clock_answers_no(self):
        for now in (None, 5, [], {}, "", "yesterday", "2026-10-13T12:00:00"):
            self.assertFalse(verify_chain([self.link], root_issuers=[OP.issuer_id], now=now).valid, repr(now))

    def test_authentication_never_raises_on_a_mangled_envelope(self):
        self.each(4, lambda rnd: authenticate(
            "/v1/spend", copy.deepcopy(self.body), mutate(rnd, self.env), root_issuers=[OP.issuer_id],
            now=NOW, revocations={}, remember_nonce=lambda n, t: False))
        # An envelope with nothing wrong must still be accepted, or "never raises" proves nothing.
        ok = authenticate("/v1/spend", copy.deepcopy(self.body), copy.deepcopy(self.env), root_issuers=[OP.issuer_id], now=NOW, revocations={})
        self.assertTrue(ok.ok, ok.errors)

    def test_log_and_witness_checks_never_raise(self):
        self.each(5, lambda rnd: verify_log(mutate(rnd, self.log.entries), expected_head=self.log.head, trusted_issuers=[OP.issuer_id]))
        self.each(6, lambda rnd: check_consistency(
            rnd.choice([None, {"length": 1, "head_hash": self.log.head}]), mutate(rnd, self.log.entries), mutate(rnd, self.head),
            pinned_issuer=OP.issuer_id))
        self.each(7, lambda rnd: verify_head(mutate(rnd, self.head)))
        self.each(8, lambda rnd: verify_cosignature(mutate(rnd, self.cosig)))

    def test_no_endpoint_answers_5xx_to_a_mangled_document(self):
        store = Store.seeded_from_sample()
        bases = {
            "/v1/verdict": {"subject": {"name": "A", "registration_id": "X"}, "transaction": {"amount_minor": 5, "currency": "USD"}, "document_text": "t"},
            "/v1/verify": {"receipt": self.receipt, "trusted_issuers": [OP.issuer_id], "sources": {"a": "b"}},
            "/v1/decide": {"receipt": self.receipt, "policy": POLICY.to_dict(), "trusted_issuers": [OP.issuer_id]},
            "/v1/revoke": {"receipt_id": self.receipt["id"], "reason": "x"},
            "/v1/spend": {"budget_id": "b", "receipt": self.receipt, "policy": POLICY.to_dict()},
            "/v1/log/lookup": {"receipt_id": self.receipt["id"]},
            "/v1/log/cosign": self.cosig,
        }

        def attempt(rnd):
            path = rnd.choice(list(bases))
            payload = mutate(rnd, bases[path])
            if path in ("/v1/revoke", "/v1/spend") and isinstance(payload, dict) and rnd.random() < 0.7:
                try:
                    payload = as_operator(store, path, payload)
                except (ValueError, TypeError):
                    return                                  # the test's own signing refused the mangled body
            try:
                raw = json.dumps(payload, allow_nan=False).encode()
            except ValueError:
                return
            status, _, out = api.handle("POST", path, raw, store)
            self.assertLess(status, 500, (path, out[:120]))
            json.loads(out)
        # An authenticated body holding a lone surrogate is the known, owner-deferred case
        # (decisions.md 2026-10-07): the test's own signing step skips those, so it is not asserted here.
        self.each(9, attempt)


if __name__ == "__main__":
    unittest.main()
