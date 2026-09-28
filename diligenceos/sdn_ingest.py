"""Ingest the real, published OFAC SDN list format.

The SDN.CSV file is headerless, 12 columns, one designation per row:
ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, Vess_type, Tonnage,
GRT, Vess_flag, Vess_owner, Remarks.
"""

from __future__ import annotations

import csv
import re
import urllib.request
from pathlib import Path

from diligenceos.sanctions import SanctionsEntry, SanctionsList

DEFAULT_SDN_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV"

_AKA_RE = re.compile(r"a\.?k\.?a\.?\s*'([^']+)'", re.IGNORECASE)

_NAME_COL = 1
_PROGRAM_COL = 3
_REMARKS_COL = 11


def _extract_aliases(remarks: str) -> tuple[str, ...]:
    return tuple(m.strip() for m in _AKA_RE.findall(remarks or ""))


def parse_sdn_csv(path: str | Path) -> SanctionsList:
    entries = []
    with Path(path).open(newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) <= _REMARKS_COL:
                continue
            name = row[_NAME_COL].strip()
            if not name:
                continue
            entries.append(
                SanctionsEntry(
                    name=name,
                    program=row[_PROGRAM_COL].strip(),
                    aliases=_extract_aliases(row[_REMARKS_COL]),
                )
            )
    return SanctionsList(entries=tuple(entries))


def fetch_sdn_list(dest_path: str | Path, url: str = DEFAULT_SDN_URL) -> Path:
    """Download the real published list. Not exercised by tests (network)."""
    dest = Path(dest_path)
    with urllib.request.urlopen(url) as response:  # noqa: S310 - intentional, human-run only
        dest.write_bytes(response.read())
    return dest
