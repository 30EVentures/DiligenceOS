"""Append-only, hash-chained log of issued receipts (tamper-evident, not tamper-proof)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from diligenceos.receipt import digest

GENESIS = "sha256:" + "0" * 64


class LogCorruptError(Exception):
    pass


def _entry_hash(entry: dict) -> str:
    return digest({k: v for k, v in entry.items() if k != "entry_hash"})


def outcome_digest(receipt: dict) -> str:
    return digest({
        "verdict": receipt["verdict"],
        "trust_score": receipt["trust_score"],
        "findings": receipt["findings"],
        "rules": receipt["rules"],
    })


def verify_chain(entries, *, expected_head: str | None = None) -> list[str]:
    """Empty list means the chain is intact. Pure and offline."""
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
        self._by_receipt = {e["receipt_id"]: e for e in self._entries}
        self._first_by_inputs: dict[str, dict] = {}
        for e in self._entries:
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
        return [e for e in self._entries if e["conflict_with"] is not None]

    def verify(self) -> list[str]:
        return verify_chain(self._entries)

    def append(self, receipt: dict, *, now: str | None = None) -> dict:
        existing = self._by_receipt.get(receipt["id"])
        if existing is not None:
            return existing  # idempotent per receipt id

        outcome = outcome_digest(receipt)
        first = self._first_by_inputs.get(receipt["inputs_digest"])
        conflict = first["seq"] if first is not None and first["outcome_digest"] != outcome else None
        entry = {
            "seq": len(self._entries),
            "receipt_id": receipt["id"],
            "inputs_digest": receipt["inputs_digest"],
            "outcome_digest": outcome,
            "logged_at": now or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "conflict_with": conflict,
            "prev_hash": self.head,
        }
        entry["entry_hash"] = _entry_hash(entry)

        if self.path is not None:  # write first: only remember what reached disk
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._entries.append(entry)
        self._by_receipt[receipt["id"]] = entry
        self._first_by_inputs.setdefault(receipt["inputs_digest"], entry)
        return entry
