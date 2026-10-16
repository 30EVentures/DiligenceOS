"""A signed record that a payment was AUTHORIZED and MADE, that a third party can check against keys it pinned.

DiligenceOS looks at the pieces a payment leaves behind, checks every one against a key the CALLER pinned (never a key
carried in the piece), and only if they all agree signs one document that binds:

    who paid         the payer address read from the chain, and (when you hold a registry) checked against it
    who was paid     the payee address, the asset, the exact amount, the chain, the transaction hash, how many confirmations
    why              the purpose, by digest (the text is data and is never copied)
    under what authority   the agent's signed request, the whole chain of grants from a pinned root to the agent (each link
                     signed, each only narrowing, each valid when it was used), and the leaf's envelope allowing THIS payment
    who authorized   the plane's signed authorization, and the exact entries in the plane's signed log (request, authorization,
                     outcome, and a human approval if there was one), with the log's head and length so a witness can pin them
    optionally       a fresh PROCEED receipt for the counterparty, and a signed invoice naming the same payee and amount

It approves nothing and authorizes nothing: it witnesses that a payment which another system authorized was also made. It
does not prove the money was well spent, that the payee is who they say, that the plane applied its own rules correctly
(it checks the plane's records agree with each other, not the plane's judgment), that a grant was not revoked afterwards
(revocation lives in the plane), or that the agent key and the wallet are the same party (unless you pass `expected_payer`).
The chain is read through `rpc`; with the demo spine that is a mock chain, and the document says `finality: simulated`.

Every refusal is a closed code (PaymentEvidenceRefused.code) and never repeats text from the artifacts.
"""

from __future__ import annotations

import re
from datetime import datetime

from diligenceos.flashy.seller import ALLOWED_CHAINS, invoice_refusal, parse_iso, tx_outcome
from diligenceos.flashy.spine import ADDR, AMOUNT, HEX32, HEX64, TXHASH, CanonError, hash_of, verify_doc
from diligenceos.flashy.witness import verify_plane_log
from diligenceos.receipt import digest, verify_receipt
from diligenceos.signing import Signer, verify_signature

SCHEMA = "diligenceos.payment-evidence/1"
EVIDENCE_DOMAIN = "diligenceos.payment-evidence/1"
GRANT_DOMAIN, REQ_DOMAIN, AUTH_DOMAIN = "30e-demo/grant/1", "30e-demo/spend-request/1", "30e-demo/spend-auth/1"
MAX_DEPTH = 5
MAX_PURPOSE = 200
HOW = ("auto-approved", "human-approved")

STATEMENT = (
    "This record says a payment that another system authorized was also made. Every piece named in it was checked against keys "
    "the verifier pinned: the agent's signed request, the chain of grants from a pinned root, the plane's signed authorization and "
    "log, and the transaction as read from the chain. It does NOT approve or authorize any spend (DiligenceOS holds no spending "
    "authority; spend envelope: 0), does not judge the plane's decision, does not know whether a grant was later revoked, and does "
    "not show that the payee is who they claim. The purpose is bound by digest only."
)

FIELDS = frozenset((
    "schema statement approves_spend witness_spend_envelope_base_units plane finality chain asset amount payer_address payer_registry_checked "
    "payee_address agent_key authorized_how approver_key purpose_digest purpose_length request_hash grant_chain_digest grant_depth grant_root_key "
    "grant_leaf_id authorization_id authorization_digest plane_key plane_log_key log_seq_request log_seq_authorization log_seq_outcome "
    "log_head_hash log_entry_count tx_hash confirmations min_confirmations reference_time invoice_id invoice_digest diligence_receipt_id "
    "issued_at issuer id signature"
).split())

_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}\Z")
_LABEL = re.compile(r"^[A-Za-z0-9_.-]{1,32}\Z")
REQ_KEYS = frozenset("ver requestId agent grantChain spend purpose issuedAt sig".split())
SPEND_KEYS = frozenset("kind chain asset amount destination".split())
AUTH_KEYS = frozenset("ver authId requestHash agent chain kind asset amount destination decisionId plane issuedAt expiresAt sig".split())
GRANT_KEYS = frozenset("ver grantId parentId issuer subject envelope notBefore notAfter depth sig".split())
ENV_REQUIRED = frozenset("chain kinds assets destinations perTxMax dailyMax autoApproveMax".split())


class PaymentEvidenceRefused(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _no(code):
    raise PaymentEvidenceRefused(code)


def _lc(s):
    return s.lower() if isinstance(s, str) else s


def _closed(o, keys, required=None) -> bool:
    return isinstance(o, dict) and set(o) <= set(keys) and set(o) >= set(required if required is not None else keys)


def _hex32(v) -> bool:
    return isinstance(v, str) and bool(HEX32.match(v))


def _check_inputs(pins, rpc, signer, issued_at, min_confirmations, expected_payer, log_pin):
    if not isinstance(pins, dict) or not _hex32(pins.get("plane_pub")) or not _hex32(pins.get("log_pub")):
        _no("BAD_INPUT")
    roots = pins.get("root_pubs")
    if not isinstance(roots, list) or not all(_hex32(r) for r in roots):
        _no("BAD_INPUT")
    for key in ("approver_pubs",):
        if key in pins and not (isinstance(pins[key], list) and all(_hex32(r) for r in pins[key])):
            _no("BAD_INPUT")
    if "seller_pub" in pins and not _hex32(pins["seller_pub"]):
        _no("BAD_INPUT")
    if not callable(rpc) or not isinstance(signer, Signer) or parse_iso(issued_at) is None:
        _no("BAD_INPUT")
    if type(min_confirmations) is not int or min_confirmations < 1:
        _no("BAD_INPUT")
    if expected_payer is not None and not (isinstance(expected_payer, str) and ADDR.match(expected_payer)):
        _no("BAD_INPUT")
    if log_pin is not None and not (isinstance(log_pin, (tuple, list)) and len(log_pin) == 2):
        _no("BAD_INPUT")


def _check_request(req):
    try:
        if not _closed(req, REQ_KEYS) or req["ver"] != "30e-demo-spend/1" or not (isinstance(req["requestId"], str) and _ID.match(req["requestId"])):
            _no("REQUEST_INVALID")
        if not _hex32(req["agent"]) or not isinstance(req["purpose"], str) or len(req["purpose"]) > MAX_PURPOSE or parse_iso(req["issuedAt"]) is None:
            _no("REQUEST_INVALID")
        sp = req["spend"]
        if not _closed(sp, SPEND_KEYS) or not all(isinstance(sp[k], str) for k in SPEND_KEYS):
            _no("REQUEST_INVALID")
        if not (AMOUNT.match(sp["amount"]) and ADDR.match(sp["asset"]) and ADDR.match(sp["destination"])) or not isinstance(req["grantChain"], list):
            _no("REQUEST_INVALID")
        body = {k: v for k, v in req.items() if k != "sig"}
        if not verify_doc(req["agent"], REQ_DOMAIN, body, req["sig"]):
            _no("REQUEST_INVALID")
        return hash_of(req)
    except (KeyError, TypeError, CanonError):
        _no("REQUEST_INVALID")


def _check_authorization(auth, req, request_hash, plane_pub):
    try:
        if not _closed(auth, AUTH_KEYS) or auth["ver"] != "30e-demo-auth/1":
            _no("AUTHORIZATION_INVALID")
        if not (isinstance(auth["authId"], str) and _ID.match(auth["authId"])) or not isinstance(auth["plane"], str) or not _LABEL.match(auth["plane"]):
            _no("AUTHORIZATION_INVALID")
        if auth["decisionId"] not in HOW or parse_iso(auth["issuedAt"]) is None or parse_iso(auth["expiresAt"]) is None:
            _no("AUTHORIZATION_INVALID")
        body = {k: v for k, v in auth.items() if k != "sig"}
        if not verify_doc(plane_pub, AUTH_DOMAIN, body, auth["sig"]):
            _no("AUTHORIZATION_INVALID")
        sp = req["spend"]
        same = (auth["requestHash"] == request_hash and auth["agent"] == req["agent"] and auth["chain"] == sp["chain"] and auth["kind"] == sp["kind"]
                and _lc(auth["asset"]) == _lc(sp["asset"]) and auth["amount"] == sp["amount"] and _lc(auth["destination"]) == _lc(sp["destination"]))
        if not same:
            _no("AUTH_REQUEST_MISMATCH")
    except (KeyError, TypeError, CanonError):
        _no("AUTHORIZATION_INVALID")


def _subset(a, b) -> bool:
    return {_lc(x) for x in a} <= {_lc(x) for x in b}


def _envelope_ok(e) -> bool:
    if not _closed(e, ENV_REQUIRED | {"alwaysEscalate"}, ENV_REQUIRED) or e["chain"] not in ALLOWED_CHAINS:
        return False
    if not all(isinstance(e[k], str) and AMOUNT.match(e[k]) for k in ("perTxMax", "dailyMax", "autoApproveMax")):
        return False
    if not all(isinstance(e[k], list) and all(isinstance(x, str) for x in e[k]) for k in ("kinds", "assets", "destinations")):
        return False
    if not all(ADDR.match(_lc(x)) for x in e["assets"] + e["destinations"]):
        return False
    return e.get("alwaysEscalate") is None or isinstance(e["alwaysEscalate"], bool)


def _narrows(parent, child) -> bool:
    p, c = parent["envelope"], child["envelope"]
    if c["chain"] != p["chain"] or not (_subset(c["kinds"], p["kinds"]) and _subset(c["assets"], p["assets"]) and _subset(c["destinations"], p["destinations"])):
        return False
    if any(int(c[k]) > int(p[k]) for k in ("perTxMax", "dailyMax", "autoApproveMax")):
        return False
    if p.get("alwaysEscalate") is True and c.get("alwaysEscalate") is not True:
        return False
    return parse_iso(child["notBefore"]) >= parse_iso(parent["notBefore"]) and parse_iso(child["notAfter"]) <= parse_iso(parent["notAfter"])


def _check_grants(req, root_pubs, at: datetime):
    chain = req["grantChain"]
    if not chain or len(chain) > MAX_DEPTH + 1:
        _no("GRANT_CHAIN_INVALID")
    prev = None
    try:
        for i, g in enumerate(chain):
            if not _closed(g, GRANT_KEYS) or g["ver"] != "30e-demo-grant/1" or not _closed(g["envelope"], ENV_REQUIRED | {"alwaysEscalate"}, ENV_REQUIRED):
                _no("GRANT_CHAIN_INVALID")
            if not _envelope_ok(g["envelope"]) or not (_hex32(g["issuer"]) and _hex32(g["subject"])) or not isinstance(g["grantId"], str):
                _no("GRANT_CHAIN_INVALID")
            if not verify_doc(g["issuer"], GRANT_DOMAIN, {k: v for k, v in g.items() if k != "sig"}, g["sig"]) or g["depth"] != i or type(g["depth"]) is not int:
                _no("GRANT_CHAIN_INVALID")
            if i == 0:
                if g["parentId"] is not None or g["issuer"] not in root_pubs:
                    _no("GRANT_CHAIN_INVALID")
            elif g["parentId"] != prev["grantId"] or g["issuer"] != prev["subject"] or not _narrows(prev, g):
                _no("GRANT_CHAIN_INVALID")
            nb, na = parse_iso(g["notBefore"]), parse_iso(g["notAfter"])
            if nb is None or na is None or not nb <= at < na:
                _no("GRANT_CHAIN_INVALID")
            prev = g
        if prev["subject"] != req["agent"]:
            _no("GRANT_CHAIN_INVALID")
    except (KeyError, TypeError, ValueError, CanonError):
        _no("GRANT_CHAIN_INVALID")
    leaf, sp = prev["envelope"], req["spend"]
    if not (leaf["chain"] == sp["chain"] and sp["kind"] in leaf["kinds"] and _lc(sp["asset"]) in [_lc(x) for x in leaf["assets"]]
            and _lc(sp["destination"]) in [_lc(x) for x in leaf["destinations"]] and int(sp["amount"]) <= int(leaf["perTxMax"])):
        _no("GRANT_DOES_NOT_ALLOW")
    return chain[0]["issuer"], len(chain) - 1, prev["grantId"]


def _only(entries, predicate):
    return [(i, e) for i, e in enumerate(entries) if predicate(e)]


def _check_log(entries, pins, req, request_hash, auth, log_pin):
    pin_kw = {}
    if log_pin is not None:
        pin_kw = {"pinned_count": log_pin[0], "pinned_head": log_pin[1]}
    checked = verify_plane_log(entries, pins["log_pub"], **pin_kw)
    if not checked["ok"]:
        _no("LOG_INVALID")
    sp, auth_id = req["spend"], auth["authId"]
    requests = _only(entries, lambda e: e["kind"] == "request_received" and isinstance(e["data"], dict) and e["data"].get("requestId") == req["requestId"])
    if not requests:
        _no("LOG_ENTRY_MISSING")
    auths = _only(entries, lambda e: e["kind"] == "authorization_issued" and isinstance(e["data"], dict)
                  and (e["data"].get("authId") == auth_id or e["data"].get("requestHash") == request_hash))
    if not auths:
        _no("LOG_ENTRY_MISSING")
    outcomes = _only(entries, lambda e: e["kind"] == "outcome" and isinstance(e["data"], dict) and e["data"].get("authId") == auth_id)
    if not outcomes:
        _no("LOG_ENTRY_MISSING")
    if len(requests) != 1 or len(auths) != 1 or len(outcomes) != 1:
        _no("LOG_MISMATCH")
    (qi, q), (ai, a), (oi, o) = requests[0], auths[0], outcomes[0]
    qd, ad, od = q["data"], a["data"], o["data"]
    if not (qd.get("requestHash") == request_hash and qd.get("agent") == req["agent"] and qd.get("spend") == sp and qd.get("purpose") == req["purpose"]):
        _no("LOG_MISMATCH")
    if not (ad.get("authId") == auth_id and ad.get("requestHash") == request_hash and ad.get("amount") == auth["amount"]
            and _lc(ad.get("destination")) == _lc(auth["destination"]) and ad.get("how") == auth["decisionId"]):
        _no("LOG_MISMATCH")
    if not qi < ai < oi:
        _no("LOG_MISMATCH")
    if od.get("state") != "confirmed" or od.get("reservation") != "settled" or not (isinstance(od.get("txHash"), str) and TXHASH.match(od["txHash"])):
        _no("OUTCOME_NOT_CONFIRMED")
    approver = None
    if auth["decisionId"] == "human-approved":
        approvals = _only(entries, lambda e: e["kind"] == "approval" and isinstance(e["data"], dict) and e["data"].get("requestHash") == request_hash
                          and e["data"].get("decision") == "approve" and e["data"].get("approver") in pins.get("approver_pubs", []) and qi < entries.index(e) < ai)
        if len(approvals) != 1:
            _no("APPROVAL_INVALID")
        approver = approvals[0][1]["data"]["approver"]
    return {"seq_request": qi, "seq_authorization": ai, "seq_outcome": oi, "tx_hash": od["txHash"], "approver": approver,
            "head": entries[-1]["hash"], "count": len(entries)}


def _check_chain(rpc, auth, tx_hash, min_confirmations, expected_payer):
    try:
        out = tx_outcome(rpc, auth["chain"], tx_hash, min_confirmations)
    except Exception:  # noqa: BLE001 - an unreadable chain is "not confirmed", never a pass
        _no("CHAIN_NOT_CONFIRMED")
    if out["state"] == "refused":
        _no("CHAIN_REFUSED")
    if out["state"] != "confirmed":
        _no("CHAIN_NOT_CONFIRMED")
    want = int(auth["amount"])
    hits = [t for t in out["transfers"] if t["token"] == _lc(auth["asset"]) and t["to"] == _lc(auth["destination"]) and t["amount"] == want]
    if len(hits) != 1:
        _no("TRANSFER_MISMATCH")
    payer = hits[0]["from"]
    if expected_payer is not None and payer != expected_payer:
        _no("PAYER_MISMATCH")
    return payer, out["confirmations"]


def _check_receipt(receipt, trusted, at: datetime, amount_minor):
    try:
        check = verify_receipt(receipt, now=at.isoformat(), trusted_issuers=list(trusted) if isinstance(trusted, (list, tuple)) and trusted else ["none"])
        ok = (check.valid and check.trusted is True and not check.expired and not check.revoked and isinstance(trusted, (list, tuple)) and bool(trusted)
              and receipt["verdict"] == "PROCEED" and isinstance(receipt.get("transaction"), dict) and receipt["transaction"].get("amount_minor") == amount_minor
              and datetime.fromisoformat(receipt["issued_at"]) <= at)
    except (KeyError, TypeError, ValueError, AttributeError):
        ok = False
    if not ok:
        _no("DILIGENCE_RECEIPT_REFUSED")
    return receipt["id"]


def _check_invoice(invoice, seller_pub, at: datetime, auth):
    if seller_pub is None or invoice_refusal(invoice, seller_pub, at) is not None:
        _no("INVOICE_REFUSED")
    same = (_lc(invoice["payee"]) == _lc(auth["destination"]) and _lc(invoice["asset"]) == _lc(auth["asset"]) and invoice["chain"] == auth["chain"]
            and invoice["amount"] == auth["amount"])
    if not same:
        _no("INVOICE_REFUSED")
    return invoice["invoiceId"], hash_of(invoice)


def _body(request, authorization, plane_log, *, pins, rpc, issuer, issued_at, min_confirmations=1, expected_payer=None, log_pin=None,
          diligence_receipt=None, diligence_trusted_issuers=None, diligence_amount_minor=None, invoice=None) -> dict:
    request_hash = _check_request(request)
    _check_authorization(authorization, request, request_hash, pins["plane_pub"])
    at = parse_iso(authorization["issuedAt"])
    root_key, depth, leaf_id = _check_grants(request, pins["root_pubs"], at)
    log = _check_log(plane_log, pins, request, request_hash, authorization, log_pin)
    payer, confirmations = _check_chain(rpc, authorization, log["tx_hash"], min_confirmations, expected_payer)
    receipt_id = None
    if diligence_receipt is not None:
        receipt_id = _check_receipt(diligence_receipt, diligence_trusted_issuers, at, diligence_amount_minor if diligence_amount_minor is not None else int(authorization["amount"]))
    invoice_id = invoice_digest = None
    if invoice is not None:
        invoice_id, invoice_digest = _check_invoice(invoice, pins.get("seller_pub"), at, authorization)
    return {
        "schema": SCHEMA, "statement": STATEMENT, "approves_spend": False, "witness_spend_envelope_base_units": "0",
        "plane": authorization["plane"], "finality": "simulated" if authorization["chain"] == "evm:31337" else "testnet",
        "chain": authorization["chain"], "asset": _lc(authorization["asset"]), "amount": authorization["amount"],
        "payer_address": payer, "payer_registry_checked": expected_payer is not None, "payee_address": _lc(authorization["destination"]),
        "agent_key": request["agent"], "authorized_how": authorization["decisionId"], "approver_key": log["approver"],
        "purpose_digest": hash_of({"purpose": request["purpose"]}), "purpose_length": len(request["purpose"]),
        "request_hash": request_hash, "grant_chain_digest": hash_of(request["grantChain"]), "grant_depth": depth, "grant_root_key": root_key, "grant_leaf_id": leaf_id,
        "authorization_id": authorization["authId"], "authorization_digest": hash_of(authorization), "plane_key": pins["plane_pub"], "plane_log_key": pins["log_pub"],
        "log_seq_request": log["seq_request"], "log_seq_authorization": log["seq_authorization"], "log_seq_outcome": log["seq_outcome"],
        "log_head_hash": log["head"], "log_entry_count": log["count"], "tx_hash": log["tx_hash"], "confirmations": confirmations,
        "min_confirmations": min_confirmations, "reference_time": authorization["issuedAt"],
        "invoice_id": invoice_id, "invoice_digest": invoice_digest, "diligence_receipt_id": receipt_id,
        "issued_at": issued_at, "issuer": issuer,
    }


def build_payment_evidence(request, authorization, plane_log, *, pins, rpc, signer, issued_at, min_confirmations=1, expected_payer=None, log_pin=None,
                           diligence_receipt=None, diligence_trusted_issuers=None, diligence_amount_minor=None, invoice=None) -> dict:
    """The signed document, or PaymentEvidenceRefused(code). Never signs on a doubt."""
    _check_inputs(pins, rpc, signer, issued_at, min_confirmations, expected_payer, log_pin)
    body = _body(request, authorization, plane_log, pins=pins, rpc=rpc, issuer=signer.issuer_id, issued_at=issued_at, min_confirmations=min_confirmations,
                 expected_payer=expected_payer, log_pin=log_pin, diligence_receipt=diligence_receipt, diligence_trusted_issuers=diligence_trusted_issuers,
                 diligence_amount_minor=diligence_amount_minor, invoice=invoice)
    rid = digest(body)
    return {**body, "id": rid, "signature": signer.sign(EVIDENCE_DOMAIN, rid)}


def verify_payment_evidence(doc, pinned_issuer) -> bool:
    """Offline: the document is exactly the closed shape, says it approves nothing, and is signed by the PINNED issuer."""
    try:
        if not isinstance(doc, dict) or set(doc) != FIELDS or doc["schema"] != SCHEMA or doc["issuer"] != pinned_issuer:
            return False
        if doc["approves_spend"] is not False or doc["witness_spend_envelope_base_units"] != "0":
            return False
        body = {k: v for k, v in doc.items() if k not in ("id", "signature")}
        return doc["id"] == digest(body) and verify_signature(pinned_issuer, EVIDENCE_DOMAIN, doc["id"], doc["signature"])
    except (KeyError, TypeError, ValueError):
        return False


def recheck_payment_evidence(doc, request, authorization, plane_log, *, pins, rpc, **kw) -> list[str]:
    """Rebuild the document from the artifacts and say which fields differ ([] = the document is what the artifacts show).
    Does not need the issuer's key. A refusal comes back as ['refused:CODE']."""
    try:
        _check_inputs(pins, rpc, Signer.generate(), doc["issued_at"], kw.get("min_confirmations", 1), kw.get("expected_payer"), kw.get("log_pin"))
        fresh = _body(request, authorization, plane_log, pins=pins, rpc=rpc, issuer=doc["issuer"], issued_at=doc["issued_at"], **kw)
    except PaymentEvidenceRefused as exc:
        return [f"refused:{exc.code}"]
    except (KeyError, TypeError):
        return ["refused:BAD_INPUT"]
    return sorted(k for k in fresh if doc.get(k) != fresh[k])
