"""Identity/legitimacy check: is this subject actually registered and active."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from diligenceos.names import normalize_name
from diligenceos.types import CheckStatus, Finding

CATEGORY = "identity"


@dataclass(frozen=True)
class RegistryRecord:
    name: str
    registration_id: str
    status: str
    jurisdiction: str
    provenance: str | None = None   # where a fetched record came from; None for one an operator typed in
    stale: bool = False             # a fetched snapshot older than the allowed age
    age_note: str | None = None


RegistryLookup = Callable[[str], "RegistryRecord | None"]


def check_identity(name: str, registration_id: str, lookup: RegistryLookup) -> Finding:
    record = lookup(registration_id)

    if record is None:
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=f"no registry record found for {registration_id!r}",
        )

    source = f" [{record.provenance}]" if record.provenance else ""

    if record.stale:
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=f"the saved registry record for {registration_id} is too old to rely on ({record.age_note}); refresh it{source}",
        )

    if record.status != "active":
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=f"{registration_id} is registered but not active (status: {record.status!r}){source}",
        )

    if normalize_name(record.name) != normalize_name(name):
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=(
                f"claimed name {name!r} does not match the registry name "
                f"{record.name!r} for {registration_id}{source}"
            ),
        )

    return Finding(
        category=CATEGORY, status=CheckStatus.PASS,
        detail=f"matches the registry record{source}" if record.provenance else None,
    )
