"""Regenerates conformance/diligenceos-1.json. Run from the repo root:

    .venv/bin/python conformance/build_diligenceos_1.py

The corpus is generated because its signed fixtures cannot be written by hand,
but every EXPECTATION below is written by hand from what the verifier is meant
to do, never read back from running it. Keys come from fixed seeds and times
are fixed, so the output is byte-for-byte reproducible (a test checks that).
The test keys protect nothing and appear nowhere except this corpus.
"""

from __future__ import annotations

import copy
import json
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from diligenceos.conformance import test_signer  # noqa: E402
from diligenceos.delegation import DOMAIN as DELEGATION_DOMAIN, issue_delegation  # noqa: E402
from diligenceos.engine import assemble_verdict  # noqa: E402
from diligenceos.evidence import text_digest  # noqa: E402
from diligenceos.receipt import digest, issue_receipt  # noqa: E402
from diligenceos.receipt_log import GENESIS, LOG_ENTRY_DOMAIN, ReceiptLog, _entry_hash  # noqa: E402
from diligenceos.signing import RECEIPT_DOMAIN  # noqa: E402
from diligenceos.types import CheckStatus, Evidence, Finding  # noqa: E402

OUT = ROOT / "conformance" / "diligenceos-1.json"

OP, ATT, W = test_signer(1), test_signer(2), test_signer(3)
KA, KB, KC, KD = (test_signer(n) for n in (4, 5, 6, 7))

ISSUED = "2026-05-01T00:00:00+00:00"
EXPIRES = "2026-07-01T00:00:00+00:00"
NOW = "2026-06-01T00:00:00+00:00"
LATE = "2026-08-01T00:00:00+00:00"
FAR = "2999-01-01T00:00:00+00:00"  # for the HTTP-shaped sets, which read the wall clock
LOGT = "2026-05-02T00:00:00+00:00"

DOC = "Acme Ltd holds public liability cover. The warranty is void after 12 months."
CLEAN = [Finding("sanctions", CheckStatus.PASS)]
FLAGGED = [Finding("identity", CheckStatus.FLAG, detail="Registration not found")]
SANCTIONED = [Finding("sanctions", CheckStatus.FLAG, detail="Matches a listed entity")]
EVIDENCED = [Finding("document_scan", CheckStatus.FLAG, detail="Cover is not as claimed",
                     evidence=(Evidence(source="doc", source_digest=text_digest(DOC), quote="public liability cover"),))]
UNQUOTED = [Finding("document_scan", CheckStatus.FLAG, detail="Cover is not as claimed",
                    evidence=(Evidence(source="doc", source_digest=text_digest(DOC), quote="fully insured"),))]
TX = {"amount_minor": 50_000, "currency": "USD"}


def pol(cap=100_000, cur="USD", verdicts=("PROCEED",), floor=70):
    return {"max_amount": {"amount_minor": cap, "currency": cur},
            "acceptable_verdicts": list(verdicts), "min_trust_score": floor}


# ── fixtures ────────────────────────────────────────────────────────────────

def mk(signer=OP, findings=CLEAN, tx=None, n=1, expires=EXPIRES, name=None):
    result = replace(assemble_verdict(findings), expires=expires)
    return issue_receipt(
        subject={"name": name if name is not None else f"Subject {n}", "registration_id": f"REG{n}"},
        inputs={"n": n}, result=result, transaction=tx, issued_at=ISSUED, signer=signer,
    )


def reseal(receipt, signer, **changes):
    """Edit a receipt and re-id it, then sign with `signer` (an attacker's own key)."""
    body = {k: v for k, v in receipt.items() if k not in ("id", "signature")}
    body.update(changes)
    if "issuer" not in changes:
        body["issuer"] = signer.issuer_id if signer else None
    rid = digest(body)
    out = {**body, "id": rid}
    if signer:
        out["signature"] = signer.sign(RECEIPT_DOMAIN, rid)
    return out


def edit(obj, **changes):
    out = copy.deepcopy(obj)
    out.update(changes)
    return out


def without(obj, *keys):
    return {k: v for k, v in obj.items() if k not in keys}


def dl(signer, delegate, parent=None, scopes=("spend",), expires="2026-12-01T00:00:00+00:00", policy=None, budget=None):
    from diligenceos.policy import Policy
    return issue_delegation(
        signer, delegate=delegate.issuer_id, scopes=scopes, expires=expires,
        policy=Policy.from_dict(policy) if policy else None, budget_id=budget, parent=parent, issued_at=ISSUED,
    )


def dl_rewrite(link, signer, **changes):
    """A delegation edited and correctly re-id'd and re-signed, so only the edit is wrong."""
    body = {k: v for k, v in link.items() if k not in ("id", "signature")}
    body.update(changes)
    did = digest(body)
    return {**body, "id": did, "signature": signer.sign(DELEGATION_DOMAIN, did)}


def log_of(signer, count=3, revoke=False, offset=0):
    log = ReceiptLog(None)
    for n in range(offset + 1, offset + count + 1):
        log.append(mk(OP, CLEAN, n=n), now=LOGT, signer=signer)
    if revoke:
        log.append_revocation(mk(OP, CLEAN, n=offset + 1)["id"], "issued in error", OP.issuer_id, now=LOGT, signer=signer)
    return log


def rehash(entry):
    entry = copy.deepcopy(entry)
    entry["entry_hash"] = _entry_hash(entry)
    return entry


# ── cases ───────────────────────────────────────────────────────────────────

BOUND = (
    "Money has no upper bound: amounts beyond 64 bits are accepted, so an amount that no int64 system can hold "
    "passes. Open design decision (which bound: 2^53-1 for JSON interop, or 2^63-1), not a clear-cut bug; see decisions.md 2026-10-07."
)
SURROGATE_AUTH = (
    "A lone surrogate in an authenticated route's body raises before the signature is checked (a 500, not a 401). "
    "Inside the auth path, which this work was told not to touch; see decisions.md 2026-10-07."
)

SETS: list[dict] = []


def add_set(name, kind, about, **extra):
    s = {"name": name, "kind": kind, "about": about, **extra, "cases": []}
    SETS.append(s)
    return s


def case(s, cid, note, input, expect, context=None, known_failure=None):
    c = {"id": cid, "set": s["name"], "note": note, "input": input}
    if context is not None:
        c["context"] = context
    c["expect"] = expect
    if known_failure:
        c["known_failure"] = known_failure
    s["cases"].append(c)


def ok(*codes):
    return {"valid": True, **({"codes": list(codes)} if codes else {})}


def no(*codes):
    return {"valid": False, **({"codes": list(codes)} if codes else {})}


def verdict(v, *codes):
    return {"verdict": v, **({"codes": list(codes)} if codes else {})}


# receipt ────────────────────────────────────────────────────────────────────
s = add_set("receipt", "validate",
            "Verify a verdict receipt. valid = intact, signature checks (if signed), not expired, not revoked, "
            "and signed by a trusted issuer when `trusted_issuers` is given. Context: now, trusted_issuers, revocations, sources.")
T = {"now": NOW, "trusted_issuers": [OP.issuer_id]}
good, held = mk(OP), mk(OP, FLAGGED, n=2)
case(s, "rc-signed-trusted", "A receipt signed by a trusted issuer.", good, ok(), T)
case(s, "rc-signed-hold", "A HOLD receipt is still a valid receipt.", held, ok(), T)
case(s, "rc-unsigned-offline", "Unsigned, no trust list: integrity only.", mk(None), ok(), {"now": NOW})
case(s, "rc-unsigned-with-trust-list", "Unsigned cannot satisfy a trust list.", mk(None), no("untrusted-issuer"), T)
case(s, "rc-signature-removed", "Names an issuer but the signature was stripped.", without(good, "signature"), no("unsigned-but-names-issuer"), T)
case(s, "rc-forged-id", "id replaced with an unrelated digest.", edit(good, id="sha256:" + "0" * 64), no("id-mismatch"), T)
case(s, "rc-verdict-edited", "HOLD edited to PROCEED, id left stale.", edit(held, verdict="PROCEED"), no("id-mismatch"), T)
case(s, "rc-verdict-replay-mismatch", "Attacker re-ids and re-signs HOLD as PROCEED; the findings still replay to HOLD.",
     reseal(held, ATT, verdict="PROCEED"), no("verdict-replay-mismatch"), {"now": NOW})
case(s, "rc-score-replay-mismatch", "Attacker raises trust_score to 99; findings replay to 70.",
     reseal(held, ATT, trust_score=99), no("score-replay-mismatch"), {"now": NOW})
case(s, "rc-redflag-relabelled", "A sanctions RED_FLAG relabelled PROCEED/85.",
     reseal(mk(OP, SANCTIONED, n=3), ATT, verdict="PROCEED", trust_score=85), no("verdict-replay-mismatch", "score-replay-mismatch"), {"now": NOW})
case(s, "rc-findings-dropped", "Findings emptied but verdict left RED_FLAG.",
     reseal(mk(OP, SANCTIONED, n=3), ATT, findings=[]), no("verdict-replay-mismatch"), {"now": NOW})
case(s, "rc-wrong-issuer", "Validly signed by a key the verifier does not trust.", mk(ATT), no("untrusted-issuer"), T)
case(s, "rc-extra-trusted-issuer", "Valid when the verifier's own list names the signer.", mk(ATT), ok(),
     {"now": NOW, "trusted_issuers": [OP.issuer_id, ATT.issuer_id]})
case(s, "rc-signature-of-another", "Another receipt's signature grafted on.", edit(good, signature=held["signature"]), no("bad-signature"), T)
case(s, "rc-issuer-swapped", "Issuer field swapped to another key.", edit(good, issuer=ATT.issuer_id), no("bad-signature", "id-mismatch"), T)
case(s, "rc-expired", "Past its expiry.", good, no("expired"), {**T, "now": LATE})
case(s, "rc-revoked", "Listed in the verifier's revocations.", good, no("revoked"),
     {**T, "revocations": {good["id"]: {"reason": "issued in error"}}})
case(s, "rc-unknown-schema", "Signed, but a schema this verifier does not know.", reseal(good, OP, schema="diligenceos.receipt/2"), no("unknown-schema"), T)
case(s, "rc-unknown-rules", "Signed, but verdict rules this verifier does not know.", reseal(good, OP, rules="verdict-rules/2"), no("unknown-rules"), T)
case(s, "rc-evidence-holds", "Quote found in the named source.", mk(OP, EVIDENCED, n=4), ok(), {**T, "sources": {"doc": DOC}})
case(s, "rc-evidence-source-edited", "The source changed since the claim was made.", mk(OP, EVIDENCED, n=4), no("evidence-digest-mismatch"),
     {**T, "sources": {"doc": DOC + " Edited."}})
case(s, "rc-evidence-quote-missing", "Digest matches but the quote is not in the source.", mk(OP, UNQUOTED, n=5), no("evidence-quote-missing"),
     {**T, "sources": {"doc": DOC}})
case(s, "rc-expires-not-a-timestamp", "Signed with expires='tomorrow'.", reseal(good, OP, expires="tomorrow"), no("bad-timestamp"), T)
case(s, "rc-now-not-a-timestamp", "The verifier's own clock value is unreadable.", good, no("bad-timestamp"), {**T, "now": "yesterday"})

# policy narrowing ───────────────────────────────────────────────────────────
s = add_set("policy-narrowing", "validate",
            "May `child` stand in a delegation below `parent`? valid = child only narrows: cap, verdicts, trust floor, currency.")
wide = pol(1000, verdicts=("PROCEED", "HOLD"), floor=50)
case(s, "pn-identical", "A policy narrows itself.", {"parent": pol(), "child": pol()}, ok())
case(s, "pn-narrower-everywhere", "Lower cap, fewer verdicts, higher floor.", {"parent": wide, "child": pol(999, floor=51)}, ok())
case(s, "pn-accepts-nothing", "No acceptable verdicts is narrower, not malformed.", {"parent": pol(), "child": pol(verdicts=())}, ok())
case(s, "pn-cap-widened-by-one", "One minor unit over the parent's cap.", {"parent": pol(1000), "child": pol(1001)}, no("widens-cap"))
case(s, "pn-verdicts-widened", "Child accepts HOLD, parent does not.", {"parent": pol(), "child": pol(verdicts=("PROCEED", "HOLD"))}, no("widens-verdicts"))
case(s, "pn-floor-lowered", "Child's trust floor is below the parent's.", {"parent": pol(floor=70), "child": pol(floor=69)}, no("lowers-floor"))
case(s, "pn-currency-changed", "Same cap, different currency.", {"parent": pol(), "child": pol(cur="EUR")}, no("currency-change"))
case(s, "pn-red-flag-acceptable", "RED_FLAG can never be acceptable.", {"parent": pol(), "child": pol(verdicts=("RED_FLAG",))}, no("policy-malformed"))
case(s, "pn-floor-over-100", "Trust floor above 100.", {"parent": pol(), "child": pol(floor=101)}, no("policy-malformed"))
case(s, "pn-cap-float", "Float money in the cap.", {"parent": pol(), "child": pol(99999.5)}, no("policy-malformed"))
case(s, "pn-cap-negative", "Negative cap.", {"parent": pol(), "child": pol(-1)}, no("policy-malformed"))
case(s, "pn-floor-missing", "Child has no trust floor.", {"parent": pol(), "child": without(pol(), "min_trust_score")}, no("policy-malformed"))
case(s, "pn-floor-string", "Trust floor as the string '70'.", {"parent": pol(), "child": edit(pol(), min_trust_score="70")}, no("policy-malformed"))
case(s, "pn-floor-boolean", "Trust floor as true (a bool is not an int).", {"parent": pol(floor=0), "child": edit(pol(), min_trust_score=True)}, no("policy-malformed"))
case(s, "pn-unknown-verdict", "A verdict name that does not exist.", {"parent": pol(), "child": pol(verdicts=("MAYBE",))}, no("policy-malformed"))
case(s, "pn-parent-not-an-object", "Parent is a string.", {"parent": "policy", "child": pol()}, no("policy-malformed"))
case(s, "pn-child-is-null", "Child is null.", {"parent": pol(), "child": None}, no("policy-malformed"))

# decide ─────────────────────────────────────────────────────────────────────
s = add_set("decide", "decide",
            "What may be done with a receipt under a policy: ALLOW, ESCALATE (ask a human) or DENY. "
            "Context: now, trusted_issuers, revocations, sources. The trust list is the verifier's own and is never read from the receipt.",
            outcomes=["ALLOW", "ESCALATE", "DENY"])
D = {"now": NOW, "trusted_issuers": [OP.issuer_id]}
tx = lambda amount=50_000, cur="USD": {"amount_minor": amount, "currency": cur}  # noqa: E731
rd = mk(OP, CLEAN, tx(), n=10)
case(s, "dc-allow", "Clean receipt, trusted, within the cap.", {"receipt": rd, "policy": pol()}, verdict("ALLOW"), D)
case(s, "dc-allow-at-cap", "Exactly the cap is allowed.", {"receipt": mk(OP, CLEAN, tx(100_000), n=11), "policy": pol()}, verdict("ALLOW"), D)
case(s, "dc-escalate-over-cap-by-one", "One minor unit over the cap.", {"receipt": mk(OP, CLEAN, tx(100_001), n=12), "policy": pol()}, verdict("ESCALATE", "over-cap"), D)
case(s, "dc-escalate-hold-verdict", "HOLD under a PROCEED-only policy.", {"receipt": mk(OP, FLAGGED, tx(), n=13), "policy": pol()}, verdict("ESCALATE", "verdict-not-acceptable"), D)
case(s, "dc-escalate-low-score", "Score 85 under a floor of 90.", {"receipt": rd, "policy": pol(floor=90)}, verdict("ESCALATE", "score-below-floor"), D)
case(s, "dc-escalate-currency", "EUR transaction under a USD cap.", {"receipt": mk(OP, CLEAN, tx(5, "EUR"), n=14), "policy": pol()}, verdict("ESCALATE", "currency-mismatch"), D)
case(s, "dc-escalate-no-transaction", "No amount to check.", {"receipt": mk(OP, CLEAN, None, n=15), "policy": pol()}, verdict("ESCALATE", "no-transaction"), D)
case(s, "dc-escalate-expired", "Valid but expired: run a fresh check.", {"receipt": rd, "policy": pol()}, verdict("ESCALATE", "expired"), {**D, "now": LATE})
case(s, "dc-deny-red-flag", "RED_FLAG is never allowed.", {"receipt": mk(OP, SANCTIONED, tx(), n=16), "policy": pol()}, verdict("DENY", "red-flag"), D)
case(s, "dc-deny-forged-id", "Tampered receipt.", {"receipt": edit(rd, id="sha256:" + "0" * 64), "policy": pol()}, verdict("DENY", "receipt-invalid", "id-mismatch"), D)
case(s, "dc-deny-verdict-relabelled", "Attacker relabels HOLD as PROCEED.",
     {"receipt": reseal(mk(OP, FLAGGED, tx(), n=13), ATT, verdict="PROCEED"), "policy": pol()}, verdict("DENY", "receipt-invalid", "verdict-replay-mismatch"), D)
case(s, "dc-deny-untrusted-issuer", "Valid receipt from a key the verifier does not trust.", {"receipt": mk(ATT, CLEAN, tx(), n=17), "policy": pol()}, verdict("DENY", "untrusted-issuer"), D)
case(s, "dc-deny-unsigned-with-trust-list", "Unsigned cannot satisfy a trust list.", {"receipt": mk(None, CLEAN, tx(), n=18), "policy": pol()}, verdict("DENY", "untrusted-issuer"), D)
case(s, "dc-deny-revoked", "Revoked by the verifier.", {"receipt": rd, "policy": pol()}, verdict("DENY", "revoked"),
     {**D, "revocations": {rd["id"]: {"reason": "issued in error"}}})
selfcert = reseal(mk(ATT, CLEAN, tx(), n=19), ATT, trusted_issuers=[ATT.issuer_id], issuer_is_trusted=True)
case(s, "dc-deny-self-certification", "The receipt carries its own trusted_issuers naming its signer. The verifier's list wins.",
     {"receipt": selfcert, "policy": pol()}, verdict("DENY", "untrusted-issuer"), D)
case(s, "dc-deny-evidence-source-edited", "Evidence no longer matches its source.", {"receipt": mk(OP, EVIDENCED, tx(), n=20), "policy": pol(verdicts=("PROCEED", "HOLD"))},
     verdict("DENY", "receipt-invalid", "evidence-digest-mismatch"), {**D, "sources": {"doc": DOC + " Edited."}})
atk = lambda **kw: reseal(mk(ATT, CLEAN, tx(), n=21), ATT, **kw)  # noqa: E731
DA = {"now": NOW, "trusted_issuers": [ATT.issuer_id]}  # a verifier that trusts a sloppy issuer
for cid, note, bad in (
    ("transaction-missing-currency", "transaction without a currency", {"amount_minor": 5}),
    ("transaction-float-amount", "float amount_minor", {"amount_minor": 12.5, "currency": "USD"}),
    ("transaction-string-amount", "string amount_minor", {"amount_minor": "5", "currency": "USD"}),
    ("transaction-negative-amount", "negative amount_minor would pass any cap", {"amount_minor": -5, "currency": "USD"}),
    ("transaction-boolean-amount", "true as an amount", {"amount_minor": True, "currency": "USD"}),
    ("transaction-lowercase-currency", "lowercase currency", {"amount_minor": 5, "currency": "usd"}),
    ("transaction-is-a-list", "transaction is a list", [5, "USD"]),
    ("transaction-is-a-string", "transaction is a string", "5 USD"),
    ("transaction-nul-currency", "NUL inside the currency code", {"amount_minor": 5, "currency": "U\u0000D"}),
):
    case(s, "dc-deny-" + cid, f"Signed by a trusted issuer, but with a malformed transaction ({note}). Never ALLOW, never crash.",
         {"receipt": atk(transaction=bad), "policy": pol()}, verdict("DENY", "malformed-transaction"), DA)

# decide-api ─────────────────────────────────────────────────────────────────
s = add_set("decide-api", "decide",
            "The same questions through this implementation's HTTP handlers (/v1/decide, or /v1/spend as the operator). "
            "The server's own key is the first test key; its default trust is that key alone. Specific to this implementation.",
            outcomes=["ALLOW", "ESCALATE", "DENY"])
mkf = lambda signer=OP, findings=CLEAN, t=None, **kw: mk(signer, findings, t if t is not None else tx(), expires=FAR, **kw)  # noqa: E731
case(s, "api-decide-operator-receipt", "Receipt from the server's own key, no trust list given.", {"receipt": mkf(), "policy": pol()}, verdict("ALLOW"))
case(s, "api-decide-stranger-receipt-default-trust", "A stranger's receipt: the default trust is the server alone.", {"receipt": mkf(ATT), "policy": pol()},
     verdict("DENY", "untrusted-issuer"))
case(s, "api-decide-receipt-certifies-itself", "A receipt carrying its own trusted_issuers is not trusted by it.",
     {"receipt": reseal(mkf(ATT), ATT, trusted_issuers=[ATT.issuer_id]), "policy": pol()}, verdict("DENY", "untrusted-issuer"))
case(s, "api-decide-caller-names-trust", "The caller's own trust list is honoured (the caller chose it, not the receipt).",
     {"receipt": mkf(ATT), "policy": pol(), "trusted_issuers": [ATT.issuer_id]}, verdict("ALLOW"))
case(s, "api-decide-trust-list-wrong-type", "trusted_issuers as a bare string.", {"receipt": mkf(), "policy": pol(), "trusted_issuers": OP.issuer_id},
     verdict("DENY", "invalid_request"))
case(s, "api-decide-no-policy", "No policy.", {"receipt": mkf()}, verdict("DENY", "invalid_request"))
case(s, "api-decide-chain-widens", "A policy chain whose second link widens the cap.",
     {"receipt": mkf(), "policy_chain": [pol(1000), pol(2000)]}, verdict("DENY", "policy_widening"))
case(s, "api-decide-malformed-transaction", "A trusted-by-caller issuer signed a negative amount.",
     {"receipt": reseal(mkf(ATT), ATT, transaction={"amount_minor": -5, "currency": "USD"}), "policy": pol(), "trusted_issuers": [ATT.issuer_id]},
     verdict("DENY", "malformed-transaction"))
case(s, "api-decide-receipt-not-an-object", "receipt is a string.", {"receipt": "receipt", "policy": pol()}, verdict("DENY", "receipt-invalid", "not-an-object"))
sp = {"endpoint": "spend"}
case(s, "api-spend-operator-receipt", "Operator-signed receipt within the cap.", {"budget_id": "b1", "receipt": mkf(), "policy": pol()}, verdict("ALLOW"), sp)
case(s, "api-spend-body-names-stranger-trusted", "A body-supplied trusted_issuers is ignored by /v1/spend: trust is server config.",
     {"budget_id": "b1", "receipt": mkf(ATT), "policy": pol(), "trusted_issuers": [ATT.issuer_id]}, verdict("DENY", "untrusted-issuer"), sp)
case(s, "api-spend-self-certifying-receipt", "A stranger's receipt that certifies itself.",
     {"budget_id": "b1", "receipt": reseal(mkf(ATT), ATT, trusted_issuers=[ATT.issuer_id]), "policy": pol()}, verdict("DENY", "untrusted-issuer"), sp)
case(s, "api-spend-over-cap", "Over the cap: ask a human.", {"budget_id": "b1", "receipt": mkf(t=tx(100_001)), "policy": pol()}, verdict("ESCALATE", "over-cap"), sp)
case(s, "api-spend-red-flag", "RED_FLAG is never spent against.", {"budget_id": "b1", "receipt": mkf(findings=SANCTIONED), "policy": pol()}, verdict("DENY", "red-flag"), sp)
case(s, "api-spend-no-budget", "A spend names no budget.", {"receipt": mkf(), "policy": pol()}, verdict("DENY", "invalid_request"), sp)

case(s, "api-spend-lone-surrogate-unauthenticated", "An unsigned request whose body holds a lone surrogate must be a 401, not a crash.",
     {"budget_id": "b\ud800", "receipt": mkf(), "policy": pol()}, verdict("DENY", "unauthenticated"), {"endpoint": "spend", "auth": "bogus"})
case(s, "api-spend-unsigned", "An unsigned spend is refused.", {"budget_id": "b1", "receipt": mkf(), "policy": pol()},
     verdict("DENY", "unauthenticated"), {"endpoint": "spend", "auth": "bogus"})

# delegation chains ──────────────────────────────────────────────────────────
s = add_set("delegation-chain", "validate",
            "Is this credential chain valid from a trusted root at `now`? Each link may only narrow the one above. "
            "Context: root_issuers, now, revocations.")
C = {"root_issuers": [OP.issuer_id], "now": NOW}
P_WIDE, P_MID = pol(1000, verdicts=("PROCEED", "HOLD"), floor=50), pol(500, verdicts=("PROCEED",), floor=60)
l0 = dl(OP, KA, scopes=("spend", "revoke"), policy=P_WIDE, budget="b1")
l1 = dl(KA, KB, parent=l0["id"], scopes=("spend",), expires="2026-11-01T00:00:00+00:00", policy=P_MID, budget="b1")
case(s, "dg-one-link", "The operator delegates to one key.", [dl(OP, KA)], ok(), C)
case(s, "dg-two-links-narrowing", "Narrower scopes, earlier expiry, tighter policy.", [l0, l1], ok(), C)
chain4 = [dl(OP, KA)]
for signer, delegate in ((KA, KB), (KB, KC), (KC, KD)):
    chain4.append(dl(signer, delegate, parent=chain4[-1]["id"]))
case(s, "dg-four-links-at-the-limit", "The longest chain allowed.", chain4, ok(), C)
chain5 = [*chain4, dl(KD, OP, parent=chain4[-1]["id"])]
case(s, "dg-five-links", "One longer than the limit.", chain5, no("chain-too-long"), C)
case(s, "dg-empty-chain", "No links.", [], no("chain-empty"), C)
case(s, "dg-chain-is-an-object", "A chain that is not a list.", {"0": l0}, no("chain-empty"), C)
case(s, "dg-chain-is-null", "A null chain.", None, no("chain-empty"), C)
case(s, "dg-untrusted-root", "Starts at a key the verifier does not trust.", [dl(ATT, KA)], no("untrusted-root"), C)
case(s, "dg-scope-widened", "Child grants revoke, the parent only spend.",
     [dl(OP, KA), dl(KA, KB, parent=dl(OP, KA)["id"], scopes=("spend", "revoke"))], no("widens-scopes"), C)
case(s, "dg-expiry-beyond-parent", "Child outlives its parent.",
     [dl(OP, KA, expires="2026-09-01T00:00:00+00:00"), dl(KA, KB, parent=dl(OP, KA, expires="2026-09-01T00:00:00+00:00")["id"], expires="2026-10-01T00:00:00+00:00")],
     no("expires-after-parent"), C)
case(s, "dg-signature-removed", "An unsigned link.", [without(dl(OP, KA), "signature")], no("bad-signature"), C)
case(s, "dg-signature-by-wrong-key", "Signed by a key that is not the delegator.",
     [edit(dl(OP, KA), signature=ATT.sign(DELEGATION_DOMAIN, dl(OP, KA)["id"]))], no("bad-signature"), C)
case(s, "dg-contents-edited", "Scopes edited after signing.", [edit(dl(OP, KA), scopes=["spend", "revoke"])], no("bad-id"), C)
case(s, "dg-link-expired", "Past its expiry.", [dl(OP, KA, expires="2026-05-15T00:00:00+00:00")], no("expired"), C)
case(s, "dg-link-revoked", "Listed in the verifier's revocations.", [dl(OP, KA)], no("revoked"), {**C, "revocations": {dl(OP, KA)["id"]: {"reason": "x"}}})
case(s, "dg-first-link-names-parent", "Link 0 claims a parent.", [dl(OP, KA, parent="sha256:" + "1" * 64)], no("bad-parent"), C)
case(s, "dg-wrong-delegator", "Link 1 is signed by a key that was not delegated to.",
     [dl(OP, KA), dl(KC, KB, parent=dl(OP, KA)["id"])], no("delegator-mismatch"), C)
case(s, "dg-wrong-parent", "Link 1 names a parent that is not link 0.", [dl(OP, KA), dl(KA, KB, parent="sha256:" + "2" * 64)], no("parent-mismatch"), C)
case(s, "dg-policy-cap-widened", "Child policy raises the cap.",
     [l0, dl(KA, KB, parent=l0["id"], policy=pol(1001, verdicts=("PROCEED", "HOLD"), floor=50), budget="b1")], no("widens-policy"), C)
case(s, "dg-policy-floor-lowered", "Child policy lowers the trust floor.",
     [l0, dl(KA, KB, parent=l0["id"], policy=pol(1000, verdicts=("PROCEED", "HOLD"), floor=49), budget="b1")], no("widens-policy"), C)
case(s, "dg-policy-verdicts-widened", "Child policy accepts a verdict the parent does not.",
     [dl(OP, KA, policy=pol()), dl(KA, KB, parent=dl(OP, KA, policy=pol())["id"], policy=pol(verdicts=("PROCEED", "HOLD")))], no("widens-policy"), C)
case(s, "dg-policy-dropped", "Child carries no policy under a parent that does.",
     [l0, dl(KA, KB, parent=l0["id"], budget="b1")], no("drops-policy"), C)
case(s, "dg-budget-changed", "Child rebinds to another budget.", [l0, dl(KA, KB, parent=l0["id"], policy=P_MID, budget="b2")], no("budget-changed"), C)
case(s, "dg-budget-dropped", "Child drops the budget binding.", [l0, dl(KA, KB, parent=l0["id"], policy=P_MID)], no("budget-changed"), C)
case(s, "dg-unknown-scope", "A scope that does not exist, validly signed.", [dl_rewrite(dl(OP, KA), OP, scopes=["admin"])], no("malformed-link"), C)
case(s, "dg-empty-scopes", "No scopes at all.", [dl_rewrite(dl(OP, KA), OP, scopes=[])], no("malformed-link"), C)
case(s, "dg-scopes-as-string", "Scopes as one string.", [dl_rewrite(dl(OP, KA), OP, scopes="spend")], no("malformed-link"), C)
case(s, "dg-expiry-without-timezone", "A naive expiry.", [dl_rewrite(dl(OP, KA), OP, expires="2026-12-01T00:00:00")], no("malformed-link"), C)
case(s, "dg-delegate-not-a-string", "Delegate is a number.", [dl_rewrite(dl(OP, KA), OP, delegate=5)], no("malformed-link"), C)
case(s, "dg-policy-malformed", "Embedded policy has a float cap.", [dl_rewrite(dl(OP, KA), OP, policy=pol(99.5))], no("malformed-link"), C)
case(s, "dg-clock-unreadable", "The verifier's now is not a timestamp.", [dl(OP, KA)], no("bad-now"), {**C, "now": "soon"})
case(s, "dg-link-is-a-number", "A link that is not an object.", [5], no("malformed-link"), C)

# receipt log ────────────────────────────────────────────────────────────────
s = add_set("log-chain", "validate",
            "Is this hash-chained, signed receipt log intact? Context: trusted_issuers, require_signed, expected_head.")
L3, L4, LU = log_of(OP, 3), log_of(OP, 3, revoke=True), log_of(None, 3)
LC = {"trusted_issuers": [OP.issuer_id], "require_signed": True}
e3 = L3.entries
case(s, "lg-valid-signed", "Three signed entries.", e3, ok(), LC)
case(s, "lg-valid-empty", "An empty log is a valid log.", [], ok(), LC)
case(s, "lg-valid-with-revocation", "A revocation entry in the chain.", L4.entries, ok(), LC)
case(s, "lg-valid-legacy-unsigned", "Unsigned entries are fine when signing is not required.", LU.entries, ok(), {})
case(s, "lg-valid-expected-head", "The head the verifier already holds.", e3, ok(), {**LC, "expected_head": L3.head})
case(s, "lg-entry-edited", "A field edited, hash left stale.", [e3[0], edit(e3[1], inputs_digest="sha256:" + "f" * 64), e3[2]], no("entry-hash-mismatch"), LC)
case(s, "lg-entry-edited-and-rehashed", "Edited and re-hashed without the key: signature fails and the next link breaks.",
     [e3[0], rehash(edit(e3[1], inputs_digest="sha256:" + "f" * 64)), e3[2]], no("bad-signature", "broken-link"), LC)
case(s, "lg-reordered", "Entries 1 and 2 swapped.", [e3[0], e3[2], e3[1]], no("bad-seq", "broken-link"), LC)
case(s, "lg-middle-deleted", "Entry 1 removed.", [e3[0], e3[2]], no("bad-seq", "broken-link"), LC)
case(s, "lg-first-deleted", "Entry 0 removed.", [e3[1], e3[2]], no("bad-seq", "broken-link"), LC)
case(s, "lg-entry-duplicated", "Entry 0 repeated.", [e3[0], e3[0]], no("bad-seq", "broken-link"), LC)
case(s, "lg-tail-truncated", "The newest entry dropped; the verifier holds the old head.", e3[:2], no("head-mismatch"), {**LC, "expected_head": L3.head})
case(s, "lg-empty-but-head-expected", "An empty log where the verifier holds a head.", [], no("head-mismatch"), {**LC, "expected_head": L3.head})
case(s, "lg-wrong-prev-hash", "Entry 2's prev_hash rewritten and the entry re-hashed.",
     [e3[0], e3[1], rehash(edit(e3[2], prev_hash=GENESIS))], no("broken-link"), LC)
case(s, "lg-unsigned-when-required", "Legacy unsigned log under require_signed.", LU.entries, no("unsigned-entry"), LC)
case(s, "lg-one-signature-removed", "A single entry's signature stripped under require_signed.", [e3[0], without(e3[1], "signature"), e3[2]], no("unsigned-entry"), LC)
case(s, "lg-untrusted-issuer", "A complete, signed log by a key the verifier does not trust.", log_of(ATT, 3).entries, no("untrusted-issuer"), LC)
case(s, "lg-signature-forged", "Entry 1 carries another key's signature.",
     [e3[0], edit(e3[1], signature=ATT.sign(LOG_ENTRY_DOMAIN, e3[1]["entry_hash"])), e3[2]], no("bad-signature"), LC)
case(s, "lg-entry-not-an-object", "An entry that is a number.", [e3[0], 5, e3[2]], no("not-an-object"), LC)
case(s, "lg-entry-is-null", "An entry that is null.", [None], no("not-an-object"), LC)
seq_false = {"seq": False, "kind": "receipt", "receipt_id": "sha256:" + "a" * 64, "inputs_digest": "sha256:" + "b" * 64,
             "outcome_digest": "sha256:" + "c" * 64, "logged_at": LOGT, "conflict_with": None, "prev_hash": GENESIS}
seq_false["entry_hash"] = _entry_hash(seq_false)
case(s, "lg-seq-is-false", "A forged, self-consistent entry whose seq is the boolean false, not 0.", [seq_false], no("bad-seq"), {})
seq_str = {**seq_false, "seq": "0"}
seq_str["entry_hash"] = _entry_hash(seq_str)
case(s, "lg-seq-is-a-string", "seq as the string '0'.", [seq_str], no("bad-seq"), {})

# malformed ──────────────────────────────────────────────────────────────────
s = add_set("malformed", "validate",
            "Hostile and ill-typed input. Every one must come back as a clean refusal (or, for verbatim text, a clean acceptance), "
            "never a crash. Context.op names the verifier: receipt, money, policy, delegation-chain, log-chain, verdict-request.")
R = lambda extra=None: {"op": "receipt", **T, **(extra or {})}  # noqa: E731
for cid, note, value in (
    ("array", "a JSON array", []), ("string", "a string", "receipt"), ("null", "null", None), ("number", "a number", 5),
    ("boolean", "true", True),
):
    case(s, "mf-receipt-" + cid, f"A receipt that is {note}.", value, no("not-an-object"), R())
case(s, "mf-receipt-empty-object", "{}", {}, no("unknown-schema"), R())
case(s, "mf-receipt-findings-string", "findings is a string.", reseal(good, OP, findings="abc"), no("findings-unreadable"), R())
case(s, "mf-receipt-findings-null-item", "findings holds null.", reseal(good, OP, findings=[None]), no("findings-unreadable"), R())
case(s, "mf-receipt-finding-status-unknown", "finding status 'maybe'.", reseal(good, OP, findings=[{"category": "x", "status": "maybe"}]), no("findings-unreadable"), R())
case(s, "mf-receipt-flag-without-detail", "A FLAG with no detail.", reseal(good, OP, findings=[{"category": "x", "status": "flag"}]), no("findings-unreadable"), R())
case(s, "mf-receipt-evidence-both-quote-and-absent", "Evidence with quote and absent.",
     reseal(good, OP, findings=[{"category": "x", "status": "flag", "detail": "d", "evidence": [
         {"source": "s", "source_digest": "sha256:" + "0" * 64, "quote": "a", "absent": "b"}]}]), no("findings-unreadable"), R())
case(s, "mf-receipt-score-fractional", "trust_score 85.5.", reseal(good, OP, trust_score=85.5), no("score-replay-mismatch"), R())
case(s, "mf-receipt-score-integral-float", "trust_score as the float 85.0 where the integer 85 is required.", reseal(good, OP, trust_score=85.0), no(), R(),
     )
case(s, "mf-receipt-score-boolean", "trust_score true.", reseal(good, OP, trust_score=True), no("score-replay-mismatch"), R())
case(s, "mf-receipt-verdict-list", "verdict as a list.", reseal(good, OP, verdict=["PROCEED"]), no("verdict-replay-mismatch"), R())
case(s, "mf-receipt-id-number", "id as a number.", edit(good, id=5), no("id-mismatch"), R())
case(s, "mf-receipt-id-nul", "id with a NUL.", edit(good, id="sha256:\u0000"), no("id-mismatch"), R())
case(s, "mf-receipt-signature-object", "signature as an object.", edit(good, signature={"a": 1}), no("bad-signature"), R())
case(s, "mf-receipt-signature-nul", "signature with a NUL.", edit(good, signature="ed25519:\u0000"), no("bad-signature"), R())
case(s, "mf-receipt-issuer-number", "issuer as a number.", edit(good, issuer=5), no("bad-signature"), R())
case(s, "mf-receipt-issuer-nul", "issuer with a NUL.", edit(good, issuer="ed25519:\u0000"), no("bad-signature"), R())
case(s, "mf-receipt-expires-number", "expires as a number.", reseal(good, OP, expires=5), no("bad-timestamp"), R())
case(s, "mf-receipt-subject-nul", "A NUL in the subject name is recorded and signed verbatim: valid, not safe.", mk(OP, CLEAN, name="A\u0000B"), ok(), R())
case(s, "mf-receipt-subject-bell", "A control character in the subject name, verbatim.", mk(OP, CLEAN, name="A\u0007B"), ok(), R())
case(s, "mf-receipt-subject-bidi", "A right-to-left override in the subject name, verbatim.", mk(OP, CLEAN, name="A‮B"), ok(), R())
case(s, "mf-receipt-subject-edited-nul", "A NUL slipped into a signed name afterwards.", edit(good, subject={"name": "Subject 1\u0000", "registration_id": "REG1"}), no("id-mismatch"), R())

M = lambda amount, cur="USD": {"amount_minor": amount, "currency": cur}  # noqa: E731
mo = {"op": "money"}
case(s, "mf-money-ok", "Plain integer minor units.", M(100), ok(), mo)
case(s, "mf-money-zero", "Zero.", M(0), ok(), mo)
case(s, "mf-money-largest-safe-integer", "2^53-1, the largest integer every JSON implementation reads exactly.", M(9007199254740991), ok(), mo)
for cid, note, value in (
    ("float", "a fractional amount", M(100.5)), ("boolean", "true as an amount", M(True)), ("string", "'100' as an amount", M("100")),
    ("null", "null amount", M(None)), ("negative", "a negative amount", M(-1)), ("list", "a list as an amount", M([1])),
    ("beyond-int64", "2^64: beyond any 64-bit integer", M(18446744073709551616)),
    ("astronomical", "2^200", M(2 ** 200)),
    ("currency-lowercase", "usd", M(1, "usd")), ("currency-short", "US", M(1, "US")), ("currency-long", "USDX", M(1, "USDX")),
    ("currency-nul", "a NUL in the code", M(1, "U\u0000D")), ("currency-fullwidth", "fullwidth letters", M(1, "ＵＳＤ")),
    ("currency-digits", "digits in the code", M(1, "U5D")), ("currency-number", "840", M(1, 840)), ("currency-null", "null", M(1, None)),
):
    case(s, "mf-money-" + cid, f"Money with {note}.", value, no("malformed-money"), mo)

po = {"op": "policy"}
case(s, "mf-policy-ok", "A well-formed policy.", pol(), ok(), po)
for cid, note, value in (
    ("verdicts-string", "acceptable_verdicts as a string", edit(pol(), acceptable_verdicts="PROCEED")),
    ("verdicts-number", "a number among the verdicts", edit(pol(), acceptable_verdicts=[5])),
    ("verdicts-null", "null among the verdicts", edit(pol(), acceptable_verdicts=[None])),
    ("verdicts-nested", "a list among the verdicts", edit(pol(), acceptable_verdicts=[["PROCEED"]])),
    ("verdicts-unknown", "an unknown verdict", edit(pol(), acceptable_verdicts=["MAYBE"])),
    ("verdicts-red-flag", "RED_FLAG as acceptable", edit(pol(), acceptable_verdicts=["RED_FLAG"])),
    ("floor-float", "a fractional floor", edit(pol(), min_trust_score=70.5)),
    ("floor-null", "a null floor", edit(pol(), min_trust_score=None)),
    ("floor-negative", "a negative floor", edit(pol(), min_trust_score=-1)),
    ("cap-missing", "no cap", without(pol(), "max_amount")),
    ("cap-list", "cap as a list", edit(pol(), max_amount=[1, "USD"])),
    ("cap-null", "null cap", edit(pol(), max_amount=None)),
    ("cap-string", "cap as a string", edit(pol(), max_amount="100 USD")),
    ("policy-list", "the policy itself a list", []), ("policy-null", "the policy itself null", None), ("policy-string", "the policy itself a string", "policy"),
):
    case(s, "mf-policy-" + cid, f"Policy with {note}.", value, no("policy-malformed"), po)

dgc = {"op": "delegation-chain", **C}
for cid, note, value in (
    ("link-null", "a null link", [None]), ("link-array", "an array as a link", [[]]), ("link-empty-object", "an empty object as a link", [{}]),
    ("link-wrong-schema", "a link of another schema", [edit(dl(OP, KA), schema="x")]),
    ("chain-number", "the chain a number", 5), ("chain-string", "the chain a string", "abc"), ("chain-boolean", "the chain true", True),
):
    case(s, "mf-delegation-" + cid, f"A delegation chain with {note}.", value, no("chain-empty" if "chain" in cid else "malformed-link"), dgc)

lgc = {"op": "log-chain", "require_signed": True}
for cid, note, value in (
    ("number", "a number", 5), ("null", "null", None), ("string", "a string", "abc"), ("empty-object", "an empty object", {}),
    ("object", "an object keyed by seq", {"0": e3[0]}), ("empty-string", "the empty string", ""), ("boolean", "true", True),
):
    case(s, "mf-log-entries-" + cid, f"A log whose entries value is {note}, not a list.", value, no("entries-not-a-list"), lgc)
case(s, "mf-log-entry-list", "An entry that is a list.", [[]], no("not-an-object"), lgc)
case(s, "mf-log-hash-number", "entry_hash as a number.", [edit(e3[0], entry_hash=5)], no("entry-hash-mismatch"), lgc)
case(s, "mf-log-hash-null", "entry_hash null.", [edit(e3[0], entry_hash=None)], no("entry-hash-mismatch"), lgc)
case(s, "mf-log-signature-number", "signature as a number.", [edit(e3[0], signature=5)], no("bad-signature"), lgc)
case(s, "mf-log-issuer-nul", "issuer with a NUL.", [edit(e3[0], issuer="ed25519:\u0000")], no("bad-signature"), lgc)

vr = {"op": "verdict-request"}
sub = lambda **kw: {"subject": {"name": "Acme Ltd", "registration_id": "R1", **kw}}  # noqa: E731
case(s, "mf-request-ok", "A minimal request.", sub(), ok(), vr)
case(s, "mf-request-with-transaction", "With a well-formed transaction.", {**sub(), "transaction": M(100)}, ok(), vr)
case(s, "mf-request-name-nul", "A NUL in the name is recorded verbatim.", sub(name="A\u0000B"), ok(), vr)
case(s, "mf-request-name-bidi", "A right-to-left override in the name, verbatim.", sub(name="A‮B"), ok(), vr)
case(s, "mf-request-name-emoji", "Astral characters survive.", sub(name="Acme \U0001F680 Ltd"), ok(), vr)
for cid, note, value, field in (
    ("name-list", "name as a list", sub(name=["Acme"]), "subject.name"),
    ("name-number", "name as a number", sub(name=5), "subject.name"),
    ("name-blank", "a blank name", sub(name="   "), "subject.name"),
    ("name-lone-surrogate", "a lone surrogate in the name (cannot be encoded as UTF-8)", sub(name="Acme \ud800"), "subject.name"),
    ("registration-number", "registration_id as a number", sub(registration_id=7), "subject.registration_id"),
    ("registration-lone-surrogate", "a lone surrogate in registration_id", sub(registration_id="R\udfff"), "subject.registration_id"),
    ("subject-string", "subject as a string", {"subject": "Acme"}, "subject"),
    ("subject-missing", "no subject", {}, "subject"),
    ("document-text-number", "document_text as a number", {**sub(), "document_text": 5}, "document_text"),
    ("transaction-string", "transaction as a string", {**sub(), "transaction": "100 USD"}, "transaction"),
    ("transaction-float", "float money", {**sub(), "transaction": M(12.5)}, "transaction.amount_minor"),
    ("transaction-boolean", "true as an amount", {**sub(), "transaction": M(True)}, "transaction.amount_minor"),
    ("transaction-string-amount", "'5' as an amount", {**sub(), "transaction": M("5")}, "transaction.amount_minor"),
    ("transaction-negative", "a negative amount", {**sub(), "transaction": M(-1)}, "transaction.amount_minor"),
    ("transaction-amount-missing", "no amount", {**sub(), "transaction": {"currency": "USD"}}, "transaction.amount_minor"),
    ("transaction-currency-lowercase", "lowercase currency", {**sub(), "transaction": M(1, "usd")}, "transaction.currency"),
    ("transaction-currency-nul", "a NUL in the currency", {**sub(), "transaction": M(1, "U\u0000D")}, "transaction.currency"),
    ("transaction-currency-null", "null currency", {**sub(), "transaction": M(1, None)}, "transaction.currency"),
    ("transaction-beyond-int64", "an amount beyond 64 bits", {**sub(), "transaction": M(18446744073709551616)}, "transaction.amount_minor"),
):
    case(s, "mf-request-" + cid, f"A verdict request with {note}.", value, no("invalid_request", field), vr)
for cid, note, value in (("array", "a JSON array", []), ("null", "null", None), ("number", "a number", 5), ("string", "a string", "x")):
    case(s, "mf-request-body-" + cid, f"A verdict request body that is {note}.", value, no("invalid_request"), vr)


KNOWN_FAILURES = {
    "mf-money-beyond-int64": BOUND,
    "mf-money-astronomical": BOUND,
    "mf-request-transaction-beyond-int64": BOUND,
    "api-spend-lone-surrogate-unauthenticated": SURROGATE_AUTH,
}


def build() -> dict:
    for set_ in SETS:
        for c in set_["cases"]:
            if c["id"] in KNOWN_FAILURES:
                c["known_failure"] = KNOWN_FAILURES[c["id"]]
    missing = set(KNOWN_FAILURES) - {c["id"] for x in SETS for c in x["cases"]}
    assert not missing, missing
    return {
        "contract": "conformance/1",
        "profile": "diligenceos/1",
        "version": "1.0.0",
        "license": "Proprietary, 30E Ventures; test vectors only",
        "about": (
            "DiligenceOS's own refusal-first conformance corpus. `valid` means no errors; on `decide` sets the answer is a `verdict`. "
            "The refusals are the substance. Expected codes are compared only where a case names them, and extra codes are allowed. "
            "Generated by conformance/build_diligenceos_1.py: regenerate, never hand-edit. All keys are fixed-seed test keys that "
            "protect nothing. Some sets are specific to this implementation's HTTP handlers (decide-api)."
        ),
        "protocol": {
            "about": "One JSON object per line in, one per line out.",
            "stdin": {"id": "string", "set": "string", "input": "the document to judge", "context": "optional"},
            "stdout": {"id": "string", "valid": "boolean", "verdict": "decide sets only", "codes": "string[], optional"},
        },
        "sets": SETS,
    }


if __name__ == "__main__":
    text = json.dumps(build(), indent=1, ensure_ascii=True) + "\n"
    OUT.write_text(text, encoding="utf-8")
    n = sum(len(x["cases"]) for x in SETS)
    print(f"wrote {OUT.relative_to(ROOT)}: {n} cases in {len(SETS)} sets")
