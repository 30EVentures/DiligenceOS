"""Witnessing: an outside party that remembers log heads and refuses a rewritten history."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from diligenceos.receipt_log import GENESIS, verify_chain
from diligenceos.signing import Signer, verify_head, verify_signature

COSIGN_DOMAIN = "diligenceos.log-cosign/1"


def cosign_message(issuer: str, length: int, head_hash: str) -> str:
    return f"{issuer}:{length}:{head_hash}"


def cosign_head(signer: Signer, issuer: str, length: int, head_hash: str) -> dict:
    return {
        "issuer": issuer,
        "length": length,
        "head_hash": head_hash,
        "witness": signer.issuer_id,
        "signature": signer.sign(COSIGN_DOMAIN, cosign_message(issuer, length, head_hash)),
    }


def verify_cosignature(doc) -> bool:
    """Pure; anything malformed is False. Checks the witness's signature only —
    whether that witness is one you trust is your call."""
    try:
        return verify_signature(
            doc["witness"], COSIGN_DOMAIN,
            cosign_message(doc["issuer"], doc["length"], doc["head_hash"]), doc["signature"],
        )
    except (KeyError, TypeError):
        return False


@dataclass(frozen=True)
class WitnessResult:
    ok: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    length: int = 0
    head_hash: str = GENESIS
    appended: int = 0


def check_consistency(previous, entries, head_doc, *, pinned_issuer: str) -> WitnessResult:
    """Is (`entries`, `head_doc`) a genuine, append-only extension of `previous`
    (this witness's last accepted {length, head_hash}, or None on first sight)?
    Pure; never raises."""
    errors: list[str] = []
    try:
        if head_doc.get("issuer") != pinned_issuer:
            errors.append("head is not from the issuer this witness is pinned to")
        if not verify_head(head_doc):
            errors.append("head signature does not verify")
        length, head_hash = head_doc["length"], head_doc["head_hash"]
    except (AttributeError, KeyError, TypeError):
        return WitnessResult(False, ("head document is malformed",))

    if not isinstance(entries, list):
        return WitnessResult(False, ("entries must be a list",))
    errors.extend(verify_chain(entries, trusted_issuers=[pinned_issuer]))
    if not all(isinstance(e, dict) for e in entries):
        return WitnessResult(False, tuple(errors))  # verify_chain already said why
    actual_head = entries[-1].get("entry_hash") if entries else GENESIS
    if length != len(entries) or head_hash != actual_head:
        errors.append("the signed head does not match the entries served with it")

    appended = 0
    if previous:
        seen_len, seen_hash = previous["length"], previous["head_hash"]
        if len(entries) < seen_len:
            errors.append(
                f"log is shorter than at last sight ({len(entries)} < {seen_len}): entries were dropped"
            )
        else:
            at_seen = GENESIS if seen_len == 0 else entries[seen_len - 1].get("entry_hash")
            if at_seen != seen_hash:
                errors.append("history before the last seen head was rewritten")
            appended = len(entries) - seen_len
    else:
        appended = len(entries)

    if errors:
        return WitnessResult(False, tuple(errors))
    return WitnessResult(True, (), length=length, head_hash=head_hash, appended=appended)


def download_entries(fetch, expected_length):
    """All log entries up to `expected_length` (the signed head's length), by
    following /v1/log/entries pages to the end. Returns a list, or None if a
    page is malformed or the server's cursor does not advance.

    The signed head, not the server's `has_more`, decides when to stop: we stop
    once we hold `expected_length` entries and ignore any beyond it (the log may
    have grown since the head was signed), so a server cannot make this loop
    forever. A server that serves fewer entries than its head claims, or that
    stops early, yields a short list and check_consistency refuses it."""
    if not isinstance(expected_length, int) or isinstance(expected_length, bool) or expected_length < 0:
        return []  # malformed head: check_consistency reports that before it reads entries
    entries: list = []
    path = "/v1/log/entries"
    while True:
        page = fetch(path)
        if not isinstance(page, dict) or not isinstance(page.get("entries"), list):
            return None
        entries.extend(page["entries"])
        if len(entries) >= expected_length or page.get("has_more") is not True:
            return entries[:expected_length] if len(entries) > expected_length else entries
        if not page["entries"] or not isinstance(page["entries"][-1], dict):
            return None
        cursor = page["entries"][-1].get("seq")
        if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor != len(entries) - 1:
            return None  # a page that does not continue where we stopped
        path = f"/v1/log/entries?after_seq={cursor}"


def run_witness(fetch, state_path: Path, signer: Signer, pinned_issuer: str, submit=None):
    """One witnessing round. `fetch(path) -> dict` (GET, JSON). Returns
    (exit_code, message, cosignature|None): 0 ok, 3 inconsistent history.
    State is written only on success, so a bad round never becomes the new baseline."""
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    previous = state.get(pinned_issuer)

    head_doc = fetch("/v1/log/head")
    entries = download_entries(fetch, head_doc.get("length") if isinstance(head_doc, dict) else None)
    result = check_consistency(previous, entries, head_doc, pinned_issuer=pinned_issuer)
    if not result.ok:
        return 3, "INCONSISTENT: " + "; ".join(result.errors), None

    cosignature = cosign_head(signer, pinned_issuer, result.length, result.head_hash)
    state[pinned_issuer] = {"length": result.length, "head_hash": result.head_hash}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2))
    note = f"consistent: {result.appended} new entr{'y' if result.appended == 1 else 'ies'}, head at {result.length}"
    if submit is not None:
        note += "; " + submit(cosignature)
    return 0, note, cosignature
