"""Sanctions/watchlist screening: one subject name in, one Finding out."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from diligenceos.types import CheckStatus, Finding

CATEGORY = "sanctions"


@dataclass(frozen=True)
class SanctionsEntry:
    name: str
    program: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class SanctionsList:
    entries: tuple[SanctionsEntry, ...] = ()

    def match(self, name: str) -> SanctionsEntry | None:
        needle = name.strip().casefold()
        for entry in self.entries:
            names = (entry.name, *entry.aliases)
            if any(needle == candidate.strip().casefold() for candidate in names):
                return entry
        return None


def load_sanctions_list(path: str | Path) -> SanctionsList:
    raw = json.loads(Path(path).read_text())
    entries = tuple(
        SanctionsEntry(
            name=item["name"],
            program=item["program"],
            aliases=tuple(item.get("aliases", ())),
        )
        for item in raw
    )
    return SanctionsList(entries=entries)


def screen_subject(name: str, sanctions_list: SanctionsList) -> Finding:
    match = sanctions_list.match(name)
    if match is None:
        return Finding(category=CATEGORY, status=CheckStatus.PASS)
    return Finding(
        category=CATEGORY,
        status=CheckStatus.FLAG,
        detail=f"matches {match.name!r} on the {match.program} list",
    )
