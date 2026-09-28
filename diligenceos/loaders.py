"""Shared request-building helpers, used by both the CLI batch mode and the web app."""

from __future__ import annotations

from diligenceos.identity import RegistryLookup, RegistryRecord
from diligenceos.track_record import DeliveryRecord, Ledger


def build_registry_lookup(registry: dict) -> RegistryLookup:
    records = {
        reg_id: RegistryRecord(
            name=entry["name"],
            registration_id=reg_id,
            status=entry["status"],
            jurisdiction=entry.get("jurisdiction", ""),
        )
        for reg_id, entry in registry.items()
    }
    return records.get


def build_ledger(delivery_records: list) -> Ledger:
    ledger = Ledger()
    for item in delivery_records:
        ledger.record(
            DeliveryRecord(
                subject=item["subject"],
                on_time=item["on_time"],
                note=item.get("note", ""),
            )
        )
    return ledger
