"""Append-only, hash-chained log of issued receipts (tamper-evident, not tamper-proof)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from diligenceos.receipt import digest
from diligenceos.signing import Signer, verify_signature

GENESIS = "sha256:" + "0" * 64
LOG_ENTRY_DOMAIN = "diligenceos.log-entry/1"


class LogCorruptError(Exception):
    pass


def _entry_hash(entry: dict) -> str:
    return digest({k: v for k, v in entry.items() if k not in ("entry_hash", "signature")})


def outcome_digest(receipt: dict) -> str:
    return digest({
        "verdict": receipt["verdict"],
        "trust_score": receipt["trust_score"],
        "findings": receipt["findings"],
        "rules": receipt["rules"],
    })


def verify_chain(
    entries,
    *,
    expected_head: str | None = None,
    trusted_issuers=None,
    require_signed: bool = False,
) -> list[str]:
    """Empty list means the chain is intact. Pure and offline.

    Entries that carry a signature must verify (and, if `trusted_issuers` is
    given, be from a listed issuer). `require_signed` also rejects entries
    that have none (logs written before Slice 26 are unsigned)."""
    errors: list[str] = []
    prev = GENESIS
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entry {i} is not an object")
            break
        if entry.get("seq") != i:
            errors.append(f"entry {i} has seq {entry.get('seq')!r}")
        if entry.get("prev_hash") != prev:
            errors.append(f"entry {i} does not link to the entry before it")
        try:
            recomputed = _entry_hash(entry)
        except (TypeError, ValueError):
            errors.append(f"entry {i} is not canonicalizable")
            break
        if entry.get("entry_hash") != recomputed:
            errors.append(f"entry {i} does not match its own hash")
        if "signature" in entry:
            if not verify_signature(
                entry.get("issuer"), LOG_ENTRY_DOMAIN, str(entry.get("entry_hash")), entry["signature"]
            ):
                errors.append(f"entry {i} signature does not verify for its issuer")
            elif trusted_issuers is not None and entry.get("issuer") not in set(trusted_issuers):
                errors.append(f"entry {i} is signed by an issuer that is not trusted")
        elif require_signed:
            errors.append(f"entry {i} is not signed")
        prev = entry.get("entry_hash")  # follow the stored hash so one edit reports once
    if expected_head is not None and prev != expected_head:
        errors.append("head does not match the expected head (entries dropped or replaced)")
    return errors


class ReceiptLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._entries: list[dict] = []
        if path is not None and path.exists():
            try:
                self._entries = [
                    json.loads(line) for line in path.read_text().splitlines() if line.strip()
                ]
            except ValueError as exc:
                raise LogCorruptError(f"receipt log is not valid JSON lines: {exc}") from exc
            errors = verify_chain(self._entries)
            if errors:
                raise LogCorruptError("receipt log failed verification: " + "; ".join(errors))
        receipts = [e for e in self._entries if e.get("kind", "receipt") == "receipt"]
        self._by_receipt = {e["receipt_id"]: e for e in receipts}
        self._first_by_inputs: dict[str, dict] = {}
        for e in receipts:
            self._first_by_inputs.setdefault(e["inputs_digest"], e)

    @property
    def head(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else GENESIS

    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    def lookup(self, receipt_id: str) -> dict | None:
        return self._by_receipt.get(receipt_id)

    def conflicts(self) -> list[dict]:
        return [e for e in self._entries if e.get("conflict_with") is not None]

    def revocation_entries(self) -> list[dict]:
        return [e for e in self._entries if e.get("kind") == "revocation"]

    def head_at(self, length: int) -> str | None:
        """The head hash when the log had `length` entries, or None if it never did."""
        if length == 0:
            return GENESIS
        return self._entries[length - 1]["entry_hash"] if 0 < length <= len(self._entries) else None

    def verify(self) -> list[str]:
        return verify_chain(self._entries)

    def append(self, receipt: dict, *, now: str | None = None, signer: Signer | None = None) -> dict:
        existing = self._by_receipt.get(receipt["id"])
        if existing is not None:
            return existing  # idempotent per receipt id

        outcome = outcome_digest(receipt)
        first = self._first_by_inputs.get(receipt["inputs_digest"])
        conflict = first["seq"] if first is not None and first["outcome_digest"] != outcome else None
        entry = {
            "seq": len(self._entries),
            "kind": "receipt",
            "receipt_id": receipt["id"],
            "inputs_digest": receipt["inputs_digest"],
            "outcome_digest": outcome,
            "logged_at": now or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "conflict_with": conflict,
            "prev_hash": self.head,
        }
        self._seal_and_write(entry, signer)
        self._by_receipt[receipt["id"]] = entry
        self._first_by_inputs.setdefault(receipt["inputs_digest"], entry)
        return entry

    def append_revocation(
        self, target_id: str, reason: str, revoked_by: str | None,
        *, now: str | None = None, signer: Signer | None = None,
    ) -> dict:
        entry = {
            "seq": len(self._entries),
            "kind": "revocation",
            "target_id": target_id,
            "reason": reason,
            "revoked_by": revoked_by,
            "logged_at": now or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "prev_hash": self.head,
        }
        self._seal_and_write(entry, signer)
        return entry

    def _seal_and_write(self, entry: dict, signer: Signer | None) -> None:
        if signer is not None:
            entry["issuer"] = signer.issuer_id  # inside the hashed body
        entry["entry_hash"] = _entry_hash(entry)
        if signer is not None:
            entry["signature"] = signer.sign(LOG_ENTRY_DOMAIN, entry["entry_hash"])
        if self.path is not None:  # write first: only remember what reached disk
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._entries.append(entry)
