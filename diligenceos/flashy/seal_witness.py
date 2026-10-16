"""DiligenceOS as WITNESS of another product's sealed snapshots: integrity and contents, nothing more.

A sealed snapshot (`mtos-seal/1`) is a signed document saying "these data points came from these HTTP responses
at these times". This module checks, against a key the CALLER pinned (never one carried in the document), what can
be checked without trusting the producer: the envelope is the closed schema it claims to be, the signature verifies,
the payload is the one the signature covers, every data point's hash binds it to the response hashes it names, the
named responses exist and succeeded, and the times are in order. It then signs a receipt of COUNTS about what it saw.

What it does not do, and the receipt says so: it does not judge whether the data is true, whether the producer's
clock is right, or whether values are well formed and consistent (the producer's own verifier re-derives those; this
is deliberately a smaller claim). It approves nothing and authorizes no spend. Free text in a seal (a headline, a
producer name) is data: it is never copied into the receipt; only counts and fixed kind names are.

Strictness follows the producer's own verifier (and tests/flashy/test_seal_witness.py runs that verifier as the oracle):
no floats, no duplicate keys, no byte-order mark, no trailing data, no unknown fields, no depth bombs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime  # noqa: F401  (kept for callers that format issued_at)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from diligenceos.flashy.seller import parse_iso
from diligenceos.flashy.spine import CanonError, canonical
from diligenceos.receipt import digest
from diligenceos.signing import _SMALL_ORDER, Signer, verify_signature

SEAL_SCHEMA = "mtos-seal/1"
SNAPSHOT_SCHEMA = "mtos-snapshot/1"
HEADER_DOMAIN = "MTOS-SEAL-V1\n"
KINDS = ("price", "change", "headline", "sentiment", "futures", "cross")
RECEIPT_SCHEMA = "diligenceos.flashy-seal-witness-receipt/1"
RECEIPT_DOMAIN = "diligenceos.flashy-seal-witness-receipt/1"
MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 32
SKEW_MS = 5 * 60_000
CAPTURE_SPAN_MS = 60 * 60_000
MAX_SAFE = 2**53 - 1
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_B64URL = re.compile(r"^[A-Za-z0-9_-]{86}\Z")           # 64 bytes, unpadded
_STORE_NAME = re.compile(r"^([0-9a-f]{64})\.json\Z")

STATEMENT = (
    "This receipt witnesses the integrity and contents of sealed snapshots: each was checked against a pinned public key "
    "(signature, payload hash, per-data-point hashes, provenance and time order). It does NOT say the data is true, that "
    "the producer's clock is right, or that any value is well formed; and it does NOT approve or authorize any spend "
    "(DiligenceOS holds no spending authority; spend envelope: 0, read-only). Counts are of what the seals contain."
)


class _Refuse(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _refuse(code):
    raise _Refuse(code)


def _int_hook(s: str) -> int:
    n = int(s)
    if s.startswith("-0") or abs(n) > MAX_SAFE:
        _refuse("non_integer")
    return n


def _no_dups(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        _refuse("unreadable")
    return dict(pairs)


def _depth_ok(v, depth=0) -> bool:
    if depth > MAX_DEPTH:
        return False
    if isinstance(v, dict):
        return all(_depth_ok(x, depth + 1) for x in v.values())
    if isinstance(v, list):
        return all(_depth_ok(x, depth + 1) for x in v)
    return True


def _parse(text):
    if isinstance(text, (bytes, bytearray)):
        if len(text) > MAX_BYTES:
            _refuse("too_large")
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            _refuse("unreadable")
    if not isinstance(text, str):
        _refuse("unreadable")
    if len(text) > MAX_BYTES:
        _refuse("too_large")
    if text.strip() == "":
        _refuse("empty")
    if text[0] == "﻿":
        _refuse("unreadable")
    try:
        value = json.loads(text, object_pairs_hook=_no_dups, parse_int=_int_hook,
                           parse_float=lambda s: _refuse("non_integer"), parse_constant=lambda s: _refuse("unreadable"))
    except RecursionError:
        _refuse("too_deep")
    except _Refuse:
        raise
    except ValueError:
        _refuse("unreadable")
    if not _depth_ok(value):
        _refuse("too_deep")
    return value


def _keys_exactly(o, keys, what=""):
    if not isinstance(o, dict) or set(o) != set(keys):
        _refuse("bad_shape")


def _int(v, minimum=0):
    if type(v) is not int or v < minimum:
        _refuse("bad_value")
    return v


def _str(v, maximum):
    if not isinstance(v, str) or not v or len(v) > maximum:
        _refuse("bad_value")
    return v


def _https(v):
    _str(v, 600)
    if not re.match(r"^https://[^\s/?#]+", v):
        _refuse("bad_value")


def _canon(v) -> str:
    try:
        return canonical(v)
    except (CanonError, TypeError, ValueError):
        _refuse("non_integer")


def _pins(pinned_pubs) -> dict:
    if not isinstance(pinned_pubs, (list, tuple)) or not pinned_pubs:
        _refuse("no_pinned_key")
    keys = {}
    for p in pinned_pubs:
        if not (isinstance(p, str) and _HEX64.match(p)) or bytes.fromhex(p) in _SMALL_ORDER:
            _refuse("bad_pinned_key")
        keys[hashlib.sha256(SPKI_PREFIX + bytes.fromhex(p)).hexdigest()] = p
    return keys


def _datapoint_hash(d, sources) -> str:
    return hashlib.sha256(_canon({"id": d["id"], "kind": d["kind"], "value": d["value"], "inputs": [sources[i]["bodySha256"] for i in d["inputs"]]}).encode()).hexdigest()


def _check_payload(p, now, sealed_at):
    _keys_exactly(p, ["schema", "createdAt", "producer", "sources", "datapoints", "omitted"])
    if p["schema"] != SNAPSHOT_SCHEMA:
        _refuse("bad_schema")
    _int(p["createdAt"], 1)
    _keys_exactly(p["producer"], ["name", "version"])
    _str(p["producer"]["name"], 60)
    _str(p["producer"]["version"], 30)
    if not isinstance(p["sources"], list) or not p["sources"] or not isinstance(p["datapoints"], list) or not p["datapoints"]:
        _refuse("empty")
    if not isinstance(p["omitted"], list):
        _refuse("bad_shape")
    if len(p["sources"]) > 2000 or len(p["datapoints"]) > 5000 or len(p["omitted"]) > 2000:
        _refuse("too_large")
    if p["createdAt"] > sealed_at:
        _refuse("time_order")
    if now - p["createdAt"] < -SKEW_MS:
        _refuse("future")
    for s in p["sources"]:
        _keys_exactly(s, ["url", "retrievedAt", "status", "bodySha256", "bytes"])
        _https(s["url"])
        _int(s["retrievedAt"], 1)
        _int(s["status"])
        if not (isinstance(s["bodySha256"], str) and _HEX64.match(s["bodySha256"])):
            _refuse("bad_value")
        _int(s["bytes"], 1 if s["status"] == 200 else 0)
        if s["retrievedAt"] > p["createdAt"]:
            _refuse("time_order")
        if p["createdAt"] - s["retrievedAt"] > CAPTURE_SPAN_MS:
            _refuse("stale_source")
    ids, by_kind = set(), {}
    for d in p["datapoints"]:
        _keys_exactly(d, ["id", "kind", "value", "inputs", "sha256"])
        _str(d["id"], 80)
        if d["id"] in ids:
            _refuse("duplicate_id")
        ids.add(d["id"])
        if not isinstance(d["kind"], str) or d["kind"] not in KINDS:
            _refuse("bad_kind")
        if not isinstance(d["inputs"], list) or not d["inputs"]:
            _refuse("no_provenance")
        for j in d["inputs"]:
            if type(j) is not int or not 0 <= j < len(p["sources"]) or p["sources"][j]["status"] != 200:
                _refuse("bad_provenance")
        if len(set(d["inputs"])) != len(d["inputs"]):
            _refuse("bad_provenance")
        if not (isinstance(d["sha256"], str) and _HEX64.match(d["sha256"])) or _datapoint_hash(d, p["sources"]) != d["sha256"]:
            _refuse("hash_mismatch")
        by_kind[d["kind"]] = by_kind.get(d["kind"], 0) + 1
    for o in p["omitted"]:
        _keys_exactly(o, ["id", "reason"])
        _str(o["id"], 80)
        _str(o["reason"], 120)
    return {"datapoints_by_kind": dict(sorted(by_kind.items())), "sources": len(p["sources"]), "omitted": len(p["omitted"])}


def verify_seal(text, pinned_pubs, *, now) -> dict:
    """{ok: True, key_id, sealed_at, created_at, payload_sha256, counts} or {ok: False, code}. Pure; never raises.
    `pinned_pubs`: raw Ed25519 public keys, 64 lowercase hex. `now`: epoch milliseconds, required."""
    try:
        if type(now) is not int or now <= 0:
            _refuse("no_clock")
        keys = _pins(pinned_pubs)
        env = _parse(text)
        _keys_exactly(env, ["schema", "alg", "keyId", "sealedAt", "payloadSha256", "signature", "payload"])
        if env["schema"] != SEAL_SCHEMA:
            _refuse("bad_schema")
        if env["alg"] != "Ed25519":
            _refuse("bad_alg")
        if not (isinstance(env["keyId"], str) and _HEX64.match(env["keyId"])):
            _refuse("bad_value")
        pub = keys.get(env["keyId"])
        if pub is None:
            _refuse("unpinned_key")                    # the seal cannot supply its own key
        _int(env["sealedAt"], 1)
        if not (isinstance(env["payloadSha256"], str) and _HEX64.match(env["payloadSha256"])):
            _refuse("bad_value")
        if not (isinstance(env["signature"], str) and _B64URL.match(env["signature"])):
            _refuse("bad_signature")
        sig = base64.urlsafe_b64decode(env["signature"] + "==")
        if len(sig) != 64 or base64.urlsafe_b64encode(sig).rstrip(b"=").decode() != env["signature"]:
            _refuse("bad_signature")
        if hashlib.sha256(_canon(env["payload"]).encode()).hexdigest() != env["payloadSha256"]:
            _refuse("payload_tampered")
        header = {k: env[k] for k in ("schema", "alg", "keyId", "sealedAt", "payloadSha256")}
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(sig, (HEADER_DOMAIN + _canon(header)).encode("utf-8"))
        except (InvalidSignature, ValueError):
            _refuse("bad_signature")
        if now - env["sealedAt"] < -SKEW_MS:
            _refuse("future")
        counts = _check_payload(env["payload"], now, env["sealedAt"])
        return {"ok": True, "key_id": env["keyId"], "sealed_at": env["sealedAt"], "created_at": env["payload"]["createdAt"],
                "payload_sha256": env["payloadSha256"], "counts": counts}
    except _Refuse as r:
        return {"ok": False, "code": r.code}
    except (KeyError, TypeError, ValueError, binascii.Error, RecursionError):
        return {"ok": False, "code": "internal"}


class SealStoreInvalid(Exception):
    """A store this witness will not sign for. `failures` are [{name, code}] with names that are 64-hex ids or '?'."""

    def __init__(self, code: str, failures=()) -> None:
        super().__init__(f"seal store refused: {code}")
        self.code, self.failures = code, list(failures)


def witness_seal_store(seals, pinned_pubs, signer: Signer, *, issued_at: str, now: int, pinned_count=None) -> dict:
    """Signed receipt of counts about a store of sealed snapshots (`seals`: {file name: text}, names `<payloadSha256>.json`).

    All or nothing: one seal that does not verify, or whose file name is not its own payload hash, and nothing is signed.
    `pinned_count`: the number of seals you saw last time; fewer now is `store_shrank` (a store only grows)."""
    if parse_iso(issued_at) is None:
        raise ValueError("issued_at must be an ISO-8601 UTC 'Z' timestamp")
    if not isinstance(seals, dict) or not seals:
        raise SealStoreInvalid("empty_store")
    if pinned_count is not None and (type(pinned_count) is not int or pinned_count < 0):
        raise SealStoreInvalid("bad_pin")
    if pinned_count is not None and len(seals) < pinned_count:
        raise SealStoreInvalid("store_shrank")
    failures, ok_results = [], []
    for name in sorted(seals, key=str):
        m = _STORE_NAME.match(name) if isinstance(name, str) else None
        shown = m.group(1) if m else "?"
        if not m:
            failures.append({"name": shown, "code": "bad_name"})
            continue
        r = verify_seal(seals[name], pinned_pubs, now=now)
        if not r["ok"]:
            failures.append({"name": shown, "code": r["code"]})
        elif r["payload_sha256"] != m.group(1):
            failures.append({"name": shown, "code": "name_mismatch"})     # filed under another seal's name
        else:
            ok_results.append(r)
    if failures:
        raise SealStoreInvalid(failures[0]["code"], failures)
    by_kind: dict = {}
    for r in ok_results:
        for k, n in r["counts"]["datapoints_by_kind"].items():
            by_kind[k] = by_kind.get(k, 0) + n
    ids = sorted(r["payload_sha256"] for r in ok_results)
    body = {
        "schema": RECEIPT_SCHEMA, "statement": STATEMENT, "approves_spend": False, "witness_spend_envelope_base_units": "0",
        "seal_key_ids": sorted({r["key_id"] for r in ok_results}), "seal_count": len(ok_results),
        "datapoints_by_kind": dict(sorted(by_kind.items())), "sources_total": sum(r["counts"]["sources"] for r in ok_results),
        "omitted_total": sum(r["counts"]["omitted"] for r in ok_results),
        "earliest_sealed_at": min(r["sealed_at"] for r in ok_results), "latest_sealed_at": max(r["sealed_at"] for r in ok_results),
        "store_digest": digest(ids), "issued_at": issued_at, "issuer": signer.issuer_id,
    }
    rid = digest(body)
    return {**body, "id": rid, "signature": signer.sign(RECEIPT_DOMAIN, rid)}


def verify_seal_witness_receipt(r, pinned_issuer: str) -> bool:
    """Offline, against a PINNED DiligenceOS issuer id."""
    try:
        if not isinstance(r, dict) or r.get("schema") != RECEIPT_SCHEMA or r.get("issuer") != pinned_issuer:
            return False
        if r.get("approves_spend") is not False or r.get("witness_spend_envelope_base_units") != "0":
            return False
        body = {k: v for k, v in r.items() if k not in ("id", "signature")}
        return r.get("id") == digest(body) and verify_signature(pinned_issuer, RECEIPT_DOMAIN, r["id"], r.get("signature"))
    except (KeyError, TypeError, ValueError):
        return False
