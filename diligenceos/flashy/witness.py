"""DiligenceOS as WITNESS of a spend-authorization plane's signed log.

It verifies the log's integrity (contiguous seq, prev chain, hash, signature under a PINNED key; an
empty log fails) and signs a receipt about what the log says. It does NOT approve or authorize any
spend: DiligenceOS's own spend envelope is $0 and it is read-only. The signing uses the existing
diligenceos.signing.Signer, so a witness receipt verifies with the same offline checker as other
DiligenceOS signatures (diligenceos.signing.verify_signature, domain below).
"""

from __future__ import annotations

import re
from datetime import timezone

from diligenceos.flashy.seller import parse_iso
from diligenceos.flashy.spine import (
    AMOUNT, DOMAIN_LOG_ENTRY, HEX32, CanonError, hash_of, verify_doc,
)
from diligenceos.receipt import digest
from diligenceos.signing import Signer, verify_signature

SCHEMA = "diligenceos.flashy-witness-receipt/1"
WITNESS_RECEIPT_DOMAIN = "diligenceos.flashy-witness-receipt/1"
ENTRY_KEYS = frozenset("seq prev ts kind data hash sig".split())
TOKEN = re.compile(r"^[A-Za-z0-9_]{1,64}$")
HEX_ID = re.compile(r"^[0-9a-f]{64}$")

STATEMENT = (
    "This receipt witnesses the integrity and contents of a spend-authorization plane's signed log: "
    "the hash chain and every signature were checked against the pinned plane log key. It does NOT "
    "approve or authorize any spend, and DiligenceOS holds no spending authority (spend envelope: 0, read-only). "
    "Counts are of values recorded in the log, not a judgment that any of them were correct."
)


class PlaneLogInvalid(Exception):
    def __init__(self, code: str, at=None) -> None:
        super().__init__(f"plane log refused: {code}" + (f" at {at}" if at is not None else ""))
        self.code, self.at = code, at


def verify_plane_log(entries, pinned_pub, *, allow_empty: bool = False, pinned_count=None, pinned_head=None) -> dict:
    """Pure; never raises. {ok, count, head} or {ok:False, code[, at]}. An EMPTY log fails.

    A hash chain cannot see a cut tail: a log with its last entries removed is still a valid chain. If you
    remember an earlier head, pass it (`pinned_count`, `pinned_head`, both or neither): a log shorter than
    that is TAIL_CUT, and one whose entry at that count is not that head is HISTORY_REWRITTEN. A pin that
    is not a positive int and a lowercase 64-hex hash is BAD_PIN, never ignored."""
    def bad(code, at=None):
        r = {"ok": False, "code": code}
        if at is not None:
            r["at"] = at
        return r

    if not (isinstance(pinned_pub, str) and HEX32.match(pinned_pub)):
        return bad("UNPINNED_KEY")
    pinned = pinned_count is not None or pinned_head is not None
    if pinned and not (type(pinned_count) is int and pinned_count >= 1 and isinstance(pinned_head, str) and HEX32.match(pinned_head)):
        return bad("BAD_PIN")
    if not isinstance(entries, list):
        return bad("NOT_A_LOG")
    if not entries:
        if pinned:
            return bad("TAIL_CUT")
        return {"ok": True, "count": 0, "head": None} if allow_empty else bad("EMPTY_LOG")
    prev = None
    for i, e in enumerate(entries):
        try:
            if not isinstance(e, dict) or set(e) != ENTRY_KEYS:
                return bad("MALFORMED", i)
            body = {k: v for k, v in e.items() if k not in ("hash", "sig")}
            if type(e["seq"]) is not int or e["seq"] != i:
                return bad("SEQ_GAP", i)
            if e["prev"] != prev:
                return bad("BROKEN_CHAIN", i)
            if hash_of(body) != e["hash"]:
                return bad("HASH_MISMATCH", i)
            if not verify_doc(pinned_pub, DOMAIN_LOG_ENTRY, {"hash": e["hash"]}, e["sig"]):
                return bad("BAD_SIGNATURE", i)
        except (CanonError, KeyError, TypeError):
            return bad("MALFORMED", i)
        prev = e["hash"]
    if pinned:
        if len(entries) < pinned_count:
            return bad("TAIL_CUT")
        if entries[pinned_count - 1]["hash"] != pinned_head:
            return bad("HISTORY_REWRITTEN")
    return {"ok": True, "count": len(entries), "head": prev}


def _tok(v, fallback):
    return v if isinstance(v, str) and TOKEN.match(v) else fallback


def summarize(entries) -> dict:
    """Counts only. Free text from the log is data: values that are not short identifiers are
    bucketed as INVALID rather than copied into the receipt."""
    by_kind: dict = {}
    verdicts: dict = {}
    for e in entries:
        k = _tok(e["kind"], "INVALID_KIND")
        by_kind[k] = by_kind.get(k, 0) + 1
        d = e["data"] if isinstance(e["data"], dict) else {}
        if "verdict" in d:
            v = _tok(d["verdict"], "INVALID")
            c = _tok(d.get("code"), "NONE" if d.get("code") is None else "INVALID")
            verdicts.setdefault(v, {})
            verdicts[v][c] = verdicts[v].get(c, 0) + 1
    return {"by_kind": by_kind, "verdicts": verdicts}


def check_daily_caps(entries, cap_base_units: int) -> dict:
    """Cross-check that no agent's authorizations in one UTC day exceed `cap_base_units`.

    Assumes `entries` already passed verify_plane_log. Integers only. Attribution: an
    `authorization_issued` entry carries no agent, so it is joined to the `request_received` entry
    with the same requestHash (the plane's own record of who asked). Grouped per (agent, chain)
    because base units of different chains are not comparable. Netting: an authorization the plane
    itself logged as released (`expired_unused`, or `outcome` with reservation `released`) is not
    counted, matching the plane's ledger. Any authorization this check cannot attribute or read
    fails the check (fail closed). Returns {ok, violations, problems}.
    """
    if type(cap_base_units) is not int or cap_base_units < 0:
        raise ValueError("cap_base_units must be a non-negative integer of base units")
    requests: dict = {}
    released: set = set()
    for e in entries:
        d = e.get("data") if isinstance(e.get("data"), dict) else {}
        if e.get("kind") == "request_received" and isinstance(d.get("requestHash"), str):
            sp = d.get("spend") if isinstance(d.get("spend"), dict) else {}
            requests.setdefault(d["requestHash"], (d.get("agent"), sp.get("chain")))
        elif e.get("kind") == "expired_unused" and isinstance(d.get("authId"), str):
            released.add(d["authId"])
        elif e.get("kind") == "outcome" and d.get("reservation") == "released" and isinstance(d.get("authId"), str):
            released.add(d["authId"])
    totals: dict = {}
    problems: list = []
    for e in entries:
        if e.get("kind") != "authorization_issued":
            continue
        d = e["data"] if isinstance(e.get("data"), dict) else {}
        auth_id = d.get("authId")
        label = auth_id if isinstance(auth_id, str) and TOKEN.match(auth_id.replace("-", "_")) else f"seq:{e.get('seq')}"
        who = requests.get(d.get("requestHash"))
        if not (who and isinstance(who[0], str) and HEX_ID.match(who[0]) and isinstance(who[1], str) and TOKEN.match(who[1].replace(":", "_"))):
            problems.append({"code": "UNATTRIBUTED_AUTHORIZATION", "auth": label})
            continue
        if not (isinstance(d.get("amount"), str) and AMOUNT.match(d["amount"])):
            problems.append({"code": "BAD_AMOUNT", "auth": label})
            continue
        ts = parse_iso(e.get("ts"))
        if ts is None:
            problems.append({"code": "BAD_TS", "auth": label})
            continue
        if auth_id in released:
            continue
        key = (who[0], who[1], ts.astimezone(timezone.utc).date().isoformat())
        totals[key] = totals.get(key, 0) + int(d["amount"])
    violations = [
        {"agent": a, "chain": c, "day": day, "total_base_units": str(t), "cap_base_units": str(cap_base_units)}
        for (a, c, day), t in sorted(totals.items()) if t > cap_base_units
    ]
    return {"ok": not violations and not problems, "violations": violations, "problems": problems}


def witness_receipt(entries, pinned_pub, signer: Signer, *, issued_at: str, cap_base_units: int | None = None) -> dict:
    """Signed DiligenceOS receipt about a plane log. Raises PlaneLogInvalid if the log does not verify
    (including empty): a witness never signs for a log it could not check."""
    chk = verify_plane_log(entries, pinned_pub)
    if not chk["ok"]:
        raise PlaneLogInvalid(chk["code"], chk.get("at"))
    if parse_iso(issued_at) is None:
        raise ValueError("issued_at must be an ISO-8601 UTC 'Z' timestamp")
    for e in entries:
        if parse_iso(e["ts"]) is None:
            raise PlaneLogInvalid("BAD_TS", e["seq"])
    body = {
        "schema": SCHEMA,
        "statement": STATEMENT,
        "approves_spend": False,
        "witness_spend_envelope_base_units": "0",
        "plane_log_key": pinned_pub,
        "head_hash": chk["head"],
        "entry_count": chk["count"],
        "counts": summarize(entries),
        "first_ts": entries[0]["ts"],
        "last_ts": entries[-1]["ts"],
        "daily_cap_check": None,
        "issued_at": issued_at,
        "issuer": signer.issuer_id,
    }
    if cap_base_units is not None:
        res = check_daily_caps(entries, cap_base_units)
        body["daily_cap_check"] = {"cap_base_units": str(cap_base_units), "ok": res["ok"],
                                   "violations": res["violations"], "problems": res["problems"]}
    rid = digest(body)
    return {**body, "id": rid, "signature": signer.sign(WITNESS_RECEIPT_DOMAIN, rid)}


def verify_witness_receipt(r, pinned_issuer: str) -> bool:
    """Offline check against a PINNED DiligenceOS issuer id (never the key the receipt names)."""
    try:
        if not isinstance(r, dict) or r.get("schema") != SCHEMA or r.get("issuer") != pinned_issuer:
            return False
        if r.get("approves_spend") is not False:
            return False
        body = {k: v for k, v in r.items() if k not in ("id", "signature")}
        if r.get("id") != digest(body):
            return False
        return verify_signature(pinned_issuer, WITNESS_RECEIPT_DOMAIN, r["id"], r.get("signature"))
    except (KeyError, TypeError, ValueError):
        return False
