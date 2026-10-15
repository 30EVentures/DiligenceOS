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


RegistryLookup = Callable[[str], "RegistryRecord | None"]


def check_identity(name: str, registration_id: str, lookup: RegistryLookup) -> Finding:
    record = lookup(registration_id)

    if record is None:
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=f"no registry record found for {registration_id!r}",
        )

    if record.status != "active":
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=f"{registration_id} is registered but not active (status: {record.status!r})",
        )

    if normalize_name(record.name) != normalize_name(name):
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=(
                f"claimed name {name!r} does not match the registry name "
                f"{record.name!r} for {registration_id}"
            ),
        )

    return Finding(category=CATEGORY, status=CheckStatus.PASS)
