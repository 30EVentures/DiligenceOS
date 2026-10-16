"""Sanctions/watchlist screening: one subject name in, one Finding out."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from diligenceos.evidence import text_digest
from diligenceos.names import normalize_name
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
    label: str | None = None   # what this list is ("OFAC SDN list retrieved ..."); a pass says so when it is set

    def source_text(self) -> str:
        """Canonical dump of the list — the text a sanctions Evidence cites."""
        return json.dumps(
            [{"name": e.name, "program": e.program, "aliases": list(e.aliases)} for e in self.entries],
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )

    def _index(self) -> dict:
        """normalized form -> the first entry that has it, built once per list. Official lists write a person as
        'SURNAME, Given' (one comma); that entry is also known by 'Given SURNAME'. Nothing else is derived: no fuzzy matching."""
        cached = self.__dict__.get("_idx")
        if cached is None:
            cached = {}
            for entry in self.entries:
                for candidate in (entry.name, *entry.aliases):
                    forms = [normalize_name(candidate)]
                    if candidate.count(",") == 1:
                        surname, given = candidate.split(",")
                        forms.append(normalize_name(f"{given} {surname}"))
                    for form in forms:
                        cached.setdefault(form, entry)
            object.__setattr__(self, "_idx", cached)
        return cached

    def match(self, name: str) -> SanctionsEntry | None:
        return self._index().get(normalize_name(name))


def load_sanctions_list(path: str | Path) -> SanctionsList:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
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
        # A pass is only as good as the list behind it, so it says what that was (one line; the label is data).
        detail = None
        if sanctions_list.label:
            detail = f"screened against {len(sanctions_list.entries)} entries: {' '.join(sanctions_list.label.split())[:200]}"
        return Finding(category=CATEGORY, status=CheckStatus.PASS, detail=detail)
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
