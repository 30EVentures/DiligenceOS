"""A small, mutable, in-memory holder for the sanctions/registry/ledger data
the web UI lets someone add to at runtime. Seeded once from the bundled
sample dataset; nothing here survives a process restart (see docs/decisions.md).
"""

from __future__ import annotations

import json
from pathlib import Path

from diligenceos.identity import RegistryLookup, RegistryRecord
from diligenceos.sanctions import SanctionsEntry, SanctionsList
from diligenceos.track_record import DeliveryRecord, Ledger

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REQUEST_PATH = REPO_ROOT / "fixtures" / "golden" / "sample_request.json"


class Store:
    def __init__(self) -> None:
        self._sanctions_entries: list[SanctionsEntry] = []
        self._registry: dict[str, RegistryRecord] = {}
        self._ledger = Ledger()

    @classmethod
    def seeded_from_sample(cls) -> "Store":
        store = cls()
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

        return store

    def add_sanctions_entry(self, name: str, program: str, aliases=()) -> None:
        self._sanctions_entries.append(
            SanctionsEntry(name=name, program=program, aliases=tuple(aliases))
        )

    def add_registry_record(
        self, registration_id: str, name: str, status: str, jurisdiction: str = ""
    ) -> None:
        self._registry[registration_id] = RegistryRecord(
            name=name, registration_id=registration_id, status=status, jurisdiction=jurisdiction
        )

    def add_delivery_record(self, subject: str, on_time: bool, note: str = "") -> None:
        self._ledger.record(DeliveryRecord(subject=subject, on_time=on_time, note=note))

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
