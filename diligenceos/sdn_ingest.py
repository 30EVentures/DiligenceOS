"""Ingest the real, published OFAC SDN list format.

The SDN.CSV file is headerless, 12 columns, one designation per row:
ent_num, SDN_Name, SDN_Type, Program, Title, Call_Sign, Vess_type, Tonnage,
GRT, Vess_flag, Vess_owner, Remarks.
"""

from __future__ import annotations

import codecs
import csv
import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
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
    with Path(path).open(newline="", encoding="utf-8") as fh:
        return _parse_rows(fh)


def parse_sdn_text(text: str) -> SanctionsList:
    return _parse_rows(io.StringIO(text, newline=""))


def _parse_rows(fh) -> SanctionsList:
    entries = []
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


# ---- the human-run refresh ------------------------------------------------------------------------
# Nothing in the server or the tests calls the network. `python -m diligenceos refresh-sanctions` does, once, on purpose.

META_SCHEMA = "diligenceos.sdn-meta/1"
CSV_NAME, META_NAME = "sdn.csv", "sdn.meta.json"
DEFAULT_MIN_ENTRIES = 1000       # the real list has well over ten thousand; a smaller "list" is an error page or the wrong file
DEFAULT_MAX_BYTES = 60_000_000
_SHA = re.compile(r"^[0-9a-f]{64}\Z")


class SdnRefreshError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SdnUnavailable(Exception):
    """A list was downloaded but is not what was recorded about it: screening must stop, not quietly use less."""


def _http_get(url: str, max_bytes: int):
    req = urllib.request.Request(url, headers={"User-Agent": "diligenceos-refresh/1"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - https only, checked by the caller; human-run
        return resp.status, resp.read(max_bytes + 1)


def _https(url) -> bool:
    if not isinstance(url, str):
        return False
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        return u.scheme == "https" and bool(u.hostname) and not u.username and not u.password
    except ValueError:
        return False


def _replace(dest: Path, name: str, data: bytes) -> None:
    tmp = dest / (name + ".tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, dest / name)
    finally:
        tmp.unlink(missing_ok=True)


def refresh_sdn(dest_dir, *, url: str = DEFAULT_SDN_URL, fetch=None, now: str | None = None, encoding="utf-8",
                min_entries: int = DEFAULT_MIN_ENTRIES, max_bytes: int = DEFAULT_MAX_BYTES) -> dict:
    """Download the list, check it is plausibly the list, and save it with its provenance. Fails closed: any doubt
    raises SdnRefreshError(code) and leaves the previous good list (if any) exactly as it was."""
    if not _https(url):
        raise SdnRefreshError("BAD_URL")
    if not isinstance(encoding, str) or not encoding:
        raise SdnRefreshError("BAD_ENCODING")
    try:
        codecs.lookup(encoding)
    except LookupError:
        raise SdnRefreshError("BAD_ENCODING") from None
    if type(min_entries) is not int or min_entries < 1 or type(max_bytes) is not int or max_bytes < 1:
        raise SdnRefreshError("BAD_PARAMETER")
    try:
        status, body = (fetch or _http_get)(url, max_bytes)
    except (OSError, TimeoutError, ValueError, urllib.error.URLError):
        raise SdnRefreshError("FETCH_FAILED") from None
    if status != 200:
        raise SdnRefreshError("HTTP_STATUS")
    if not isinstance(body, (bytes, bytearray)) or not body.strip():
        raise SdnRefreshError("EMPTY")
    if len(body) > max_bytes:
        raise SdnRefreshError("TOO_LARGE")
    try:
        text = bytes(body).decode(encoding)
    except UnicodeDecodeError:
        raise SdnRefreshError("NOT_TEXT") from None
    if "\x00" in text:
        raise SdnRefreshError("NOT_TEXT")
    try:
        parsed = parse_sdn_text(text)
    except (csv.Error, ValueError):
        raise SdnRefreshError("NOT_TEXT") from None
    if len(parsed.entries) < min_entries:
        raise SdnRefreshError("TOO_FEW_ENTRIES")
    saved = text.encode("utf-8")
    meta = {
        "schema": META_SCHEMA, "source": url, "retrieved_at": now or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "bytes": len(body), "encoding": encoding, "sha256": hashlib.sha256(saved).hexdigest(), "entries": len(parsed.entries),
    }
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    _replace(dest, CSV_NAME, saved)
    _replace(dest, META_NAME, (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return meta


_CACHE: dict = {}


def load_verified_sdn(dest_dir):
    """(SanctionsList, meta) for a downloaded list that is exactly what was recorded, (None, None) if none was ever
    downloaded, and SdnUnavailable for anything in between. A file with no provenance is ignored, never trusted."""
    dest = Path(dest_dir)
    meta_path, csv_path = dest / META_NAME, dest / CSV_NAME
    if not meta_path.exists():
        return None, None
    try:
        key = (str(csv_path), csv_path.stat().st_mtime_ns, csv_path.stat().st_size, meta_path.stat().st_mtime_ns)
    except OSError:
        raise SdnUnavailable("the downloaded sanctions list is missing") from None
    if key in _CACHE:
        return _CACHE[key]
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        ok = (isinstance(meta, dict) and meta.get("schema") == META_SCHEMA and isinstance(meta.get("source"), str)
              and isinstance(meta.get("retrieved_at"), str) and type(meta.get("entries")) is int and meta["entries"] >= 0
              and type(meta.get("bytes")) is int and isinstance(meta.get("sha256"), str) and _SHA.match(meta["sha256"]))
        if ok:
            ts = datetime.fromisoformat(meta["retrieved_at"])
            ok = ts.tzinfo is not None
        if not ok:
            raise ValueError("provenance is malformed")
        data = csv_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != meta["sha256"]:
            raise ValueError("the list is not the file that was recorded")
        parsed = parse_sdn_text(data.decode("utf-8"))
        if len(parsed.entries) != meta["entries"]:
            raise ValueError("the list does not have the recorded number of entries")
    except (OSError, ValueError, UnicodeDecodeError, csv.Error, TypeError) as exc:
        raise SdnUnavailable(f"the downloaded sanctions list cannot be used: {exc}") from None
    result = (parsed, meta)
    _CACHE.clear()
    _CACHE[key] = result
    return result
