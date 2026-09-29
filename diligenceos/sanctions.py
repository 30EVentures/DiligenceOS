"""Sanctions/watchlist screening: one subject name in, one Finding out."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from diligenceos.evidence import text_digest
from diligenceos.types import CheckStatus, Evidence, Finding

CATEGORY = "sanctions"
SOURCE = "store:sanctions_entries"


@dataclass(frozen=True)
class SanctionsEntry:
    name: str
    program: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class SanctionsList:
    entries: tuple[SanctionsEntry, ...] = ()

    def source_text(self) -> str:
        """Canonical dump of the list — the text a sanctions Evidence cites."""
        return json.dumps(
            [{"name": e.name, "program": e.program, "aliases": list(e.aliases)} for e in self.entries],
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )

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
        evidence=(
            Evidence(
                source=SOURCE,
                source_digest=text_digest(sanctions_list.source_text()),
                quote=match.name,
            ),
        ),
    )
