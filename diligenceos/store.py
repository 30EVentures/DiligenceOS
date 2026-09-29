"""A mutable, optionally-durable holder for the sanctions/registry/ledger
data the web UI lets someone add to. With no persist_path, purely
in-memory (Slice 12's original shape). With one, every addition is saved
immediately to a JSON file outside this repo's checked-in fixtures
entirely (see docs/decisions.md).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from diligenceos.identity import RegistryLookup, RegistryRecord
from diligenceos.sanctions import SanctionsEntry, SanctionsList
from diligenceos.receipt_log import ReceiptLog
from diligenceos.signing import Signer
from diligenceos.witness import verify_cosignature
from diligenceos.track_record import DeliveryRecord, Ledger
from diligenceos.types import Money

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REQUEST_PATH = REPO_ROOT / "fixtures" / "golden" / "sample_request.json"


class Store:
    def __init__(self, persist_path: Path | None = None) -> None:
        self._sanctions_entries: list[SanctionsEntry] = []
        self._registry: dict[str, RegistryRecord] = {}
        self._ledger = Ledger()
        self._revocations: dict[str, dict] = {}
        self._spend: dict[str, dict[str, dict]] = {}  # budget -> receipt id -> Money dict
        self.persist_path = persist_path
        self._log: ReceiptLog | None = None
        self._signer: Signer | None = None
        self._cosignatures: dict[str, dict[str, dict]] = {}  # head hash -> witness -> doc
        self._nonces: dict[str, datetime] = {}  # in memory only; see specs/slice-25

    @classmethod
    def seeded_from_sample(cls, persist_path: Path | None = None) -> "Store":
        store = cls()  # persist_path unset while seeding: one write, not N
        request = json.loads(DEFAULT_REQUEST_PATH.read_text())

        if request.get("sanctions_list_path"):
            raw = json.loads((REPO_ROOT / request["sanctions_list_path"]).read_text())
            for item in raw:
                store.add_sanctions_entry(
                    name=item["name"],
                    program=item["program"],
                    aliases=item.get("aliases", ()),
                )

        for reg_id, entry in request.get("registry", {}).items():
            store.add_registry_record(
                registration_id=reg_id,
                name=entry["name"],
                status=entry["status"],
                jurisdiction=entry.get("jurisdiction", ""),
            )

        for item in request.get("delivery_records", []):
            store.add_delivery_record(
                subject=item["subject"], on_time=item["on_time"], note=item.get("note", "")
            )

        if persist_path is not None:
            store.persist_path = persist_path
            store._save()
        return store

    @classmethod
    def from_dict(cls, data: dict, persist_path: Path | None = None) -> "Store":
        store = cls()  # persist_path unset while loading: one write, not N
        for item in data.get("sanctions_entries", []):
            store.add_sanctions_entry(
                name=item["name"], program=item["program"], aliases=item.get("aliases", ())
            )
        for reg_id, entry in data.get("registry", {}).items():
            store.add_registry_record(
                registration_id=reg_id,
                name=entry["name"],
                status=entry["status"],
                jurisdiction=entry.get("jurisdiction", ""),
            )
        for item in data.get("delivery_records", []):
            store.add_delivery_record(
                subject=item["subject"], on_time=item["on_time"], note=item.get("note", "")
            )
        store._revocations = dict(data.get("revocations", {}))
        store._spend = {b: dict(v) for b, v in data.get("spend", {}).items()}
        store._cosignatures = {h: dict(v) for h, v in data.get("cosignatures", {}).items()}
        store.persist_path = persist_path
        return store

    @classmethod
    def load_or_seed(cls, persist_path: Path) -> "Store":
        if persist_path.exists():
            data = json.loads(persist_path.read_text())
            return cls.from_dict(data, persist_path=persist_path)
        return cls.seeded_from_sample(persist_path=persist_path)

    def add_sanctions_entry(self, name: str, program: str, aliases=()) -> None:
        self._sanctions_entries.append(
            SanctionsEntry(name=name, program=program, aliases=tuple(aliases))
        )
        self._maybe_save()

    def add_registry_record(
        self, registration_id: str, name: str, status: str, jurisdiction: str = ""
    ) -> None:
        self._registry[registration_id] = RegistryRecord(
            name=name, registration_id=registration_id, status=status, jurisdiction=jurisdiction
        )
        self._maybe_save()

    def add_delivery_record(self, subject: str, on_time: bool, note: str = "") -> None:
        self._ledger.record(DeliveryRecord(subject=subject, on_time=on_time, note=note))
        self._maybe_save()

    def sanctions_list(self) -> SanctionsList:
        return SanctionsList(entries=tuple(self._sanctions_entries))

    def registry_lookup(self) -> RegistryLookup:
        return self._registry.get

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    @property
    def sanctions_entries(self) -> tuple[SanctionsEntry, ...]:
        return tuple(self._sanctions_entries)

    @property
    def registry_records(self) -> tuple[RegistryRecord, ...]:
        return tuple(self._registry.values())

    @property
    def delivery_records(self) -> tuple[DeliveryRecord, ...]:
        return self._ledger.all_records()

    def to_dict(self) -> dict:
        return {
            "sanctions_entries": [
                {"name": e.name, "program": e.program, "aliases": list(e.aliases)}
                for e in self._sanctions_entries
            ],
            "registry": {
                rid: {"name": r.name, "status": r.status, "jurisdiction": r.jurisdiction}
                for rid, r in self._registry.items()
            },
            "delivery_records": [
                {"subject": d.subject, "on_time": d.on_time, "note": d.note}
                for d in self._ledger.all_records()
            ],
        }

    @property
    def signer(self) -> Signer:
        """issuer.key beside the store file (an ephemeral in-memory key if the store
        has no path). Raises SignerError, every time, if the file is unusable."""
        if self._signer is None:
            self._signer = (
                Signer.load_or_create(self.persist_path.with_name("issuer.key"))
                if self.persist_path else Signer.generate()
            )
        return self._signer

    @property
    def log(self) -> ReceiptLog:
        """receipts.jsonl beside the store file (in memory if the store has no
        path). Raises LogCorruptError, every time, if the file fails verification."""
        if self._log is None:
            path = self.persist_path.with_name("receipts.jsonl") if self.persist_path else None
            self._log = ReceiptLog(path)
        return self._log

    @property
    def revocations(self) -> dict[str, dict]:
        return dict(self._revocations)

    def revoke(self, receipt_id: str, reason: str, *, by: str | None = None) -> dict:
        """Idempotent: revoking twice keeps the first reason and time. The revocation
        is appended to the signed log *first*, so if the log or key is unusable this
        raises (LogCorruptError / SignerError) instead of recording an unattested one."""
        if receipt_id not in self._revocations:
            entry = self.log.append_revocation(receipt_id, reason, by, signer=self.signer)
            self._revocations[receipt_id] = {
                "reason": reason,
                "revoked_at": entry["logged_at"],
                "revoked_by": by,
                "log_seq": entry["seq"],
            }
            self._maybe_save()
        return self._revocations[receipt_id]

    def cosignatures_for(self, head_hash: str) -> list[dict]:
        return list(self._cosignatures.get(head_hash, {}).values())

    def add_cosignature(self, doc: dict, allowed_witnesses) -> None:
        """Raises ValueError, saying why, unless `doc` is a valid cosignature by a listed
        witness of a head this log really has (or had)."""
        if not verify_cosignature(doc):
            raise ValueError("cosignature does not verify")
        if doc["witness"] not in set(allowed_witnesses):
            raise ValueError("witness is not listed with this server")
        if doc["issuer"] != self.signer.issuer_id:
            raise ValueError("cosignature is for a different issuer")
        if not isinstance(doc["length"], int) or self.log.head_at(doc["length"]) != doc["head_hash"]:
            raise ValueError("this log never had that head")
        self._cosignatures.setdefault(doc["head_hash"], {})[doc["witness"]] = {
            k: doc[k] for k in ("issuer", "length", "head_hash", "witness", "signature")
        }
        self._maybe_save()

    def spend_entry(self, budget_id: str, receipt_id: str) -> Money | None:
        entry = self._spend.get(budget_id, {}).get(receipt_id)
        return Money.from_dict(entry) if entry else None

    def spent(self, budget_id: str, currency: str) -> int:
        return sum(
            e["amount_minor"] for e in self._spend.get(budget_id, {}).values()
            if e["currency"] == currency
        )

    def commit_spend(
        self, budget_id: str, receipt_id: str, amount: Money, caller: str | None = None
    ) -> None:
        self._spend.setdefault(budget_id, {})[receipt_id] = {**amount.to_dict(), "caller": caller}
        self._maybe_save()

    def remember_nonce(self, nonce: str, now: str, window_seconds: int = 600) -> bool:
        """True if `nonce` was already seen inside the window; otherwise records it.
        Entries older than the window are dropped (auth already rejects stale requests)."""
        moment = datetime.fromisoformat(now)
        self._nonces = {
            n: t for n, t in self._nonces.items() if (moment - t).total_seconds() < window_seconds
        }
        if nonce in self._nonces:
            return True
        self._nonces[nonce] = moment
        return False

    def _state_dict(self) -> dict:
        # to_dict() stays the checks' data (and the data_digest input); revocations
        # and spend are operational state that must not change what a verdict covers.
        return {
            **self.to_dict(), "revocations": self._revocations, "spend": self._spend,
            "cosignatures": self._cosignatures,
        }

    def _maybe_save(self) -> None:
        if self.persist_path is not None:
            self._save()

    def _save(self) -> None:
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        self.persist_path.write_text(json.dumps(self._state_dict(), indent=2))
