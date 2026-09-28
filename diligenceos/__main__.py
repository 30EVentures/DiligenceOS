"""python3 -m diligenceos <request.json> — run the pipeline, print the verdict."""

from __future__ import annotations

import json
import sys

from diligenceos.identity import RegistryRecord
from diligenceos.pipeline import run_diligence
from diligenceos.sanctions import SanctionsList, load_sanctions_list
from diligenceos.serialize import verdict_result_to_dict
from diligenceos.track_record import DeliveryRecord, Ledger


def _build_registry_lookup(registry: dict) -> callable:
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


def _build_ledger(delivery_records: list) -> Ledger:
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


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python3 -m diligenceos <request.json>", file=sys.stderr)
        return 2

    request = json.loads(open(argv[1]).read())
    subject = request["subject"]

    sanctions_list = (
        load_sanctions_list(request["sanctions_list_path"])
        if request.get("sanctions_list_path")
        else SanctionsList()
    )
    registry_lookup = _build_registry_lookup(request.get("registry", {}))
    ledger = _build_ledger(request.get("delivery_records", []))

    result = run_diligence(
        name=subject["name"],
        registration_id=subject["registration_id"],
        sanctions_list=sanctions_list,
        registry_lookup=registry_lookup,
        ledger=ledger,
        document_text=request.get("document_text"),
    )
    print(json.dumps(verdict_result_to_dict(result), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
