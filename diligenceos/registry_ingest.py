"""A real company register behind the identity check (specs/registry-adapter).

Same shape as the sanctions refresh: a person runs one command that fetches, the response is saved
with its provenance, and the server uses it only while it is exactly what was recorded. Nothing in
the server or the tests calls the network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from diligenceos.identity import RegistryRecord

DEFAULT_BASE_URL = "https://api.company-information.service.gov.uk"
KEY_VAR = "COMPANIES_HOUSE_API_KEY"
META_SCHEMA = "diligenceos.registry-meta/1"
SUBDIR = "registry"
NUMBER = re.compile(r"[A-Z0-9]{8}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 1_000_000
DEFAULT_MAX_AGE_DAYS = 30


class RegistryRefreshError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RegistryUnavailable(Exception):
    """A snapshot exists but is not what was recorded about it: identity must stop, not say 'no record'."""


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _reject_constant(token):
    raise ValueError(token)


def _loads(body: bytes):
    return json.loads(bytes(body).decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)


def parse_company_profile(body: bytes, number: str) -> RegistryRecord:
    """Strict: anything unexpected raises ValueError rather than becoming a record."""
    data = _loads(body)
    if not isinstance(data, dict):
        raise ValueError("not an object")
    got = data.get("company_number")
    if not isinstance(got, str) or got.upper() != number:
        raise ValueError("company_number is not the number asked for")
    name, status = data.get("company_name"), data.get("company_status")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("company_name missing")
    if not isinstance(status, str) or not status.strip():
        raise ValueError("company_status missing")
    jurisdiction = data.get("jurisdiction")
    if jurisdiction is not None and not isinstance(jurisdiction, str):
        raise ValueError("jurisdiction is not text")
    return RegistryRecord(name=name, registration_id=number, status=status.strip().lower(),
                          jurisdiction=jurisdiction or "unknown")


def _https_host(url: str) -> bool:
    try:
        u = urlsplit(url)
        return u.scheme == "https" and bool(u.hostname) and not u.username and not u.password
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _http_get(url: str, headers: dict, max_bytes: int):
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=dict(headers, **{"User-Agent": "diligenceos-registry/1"}))
    try:
        with opener.open(req, timeout=30) as resp:  # noqa: S310 - https only, checked by the caller; human-run
            return resp.status, resp.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def _replace(dest: Path, name: str, data: bytes) -> None:
    tmp = dest / (name + ".tmp")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, dest / name)
    finally:
        tmp.unlink(missing_ok=True)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def refresh_company(dest_dir, number, *, api_key, fetch=None, now=None, base_url: str = DEFAULT_BASE_URL) -> dict:
    """Fetch one company profile and save it with its provenance. Any doubt raises RegistryRefreshError(code)
    and leaves the previous snapshot (if any) as it was. The key is used for the request only."""
    if not isinstance(number, str) or not NUMBER.fullmatch(number):
        raise RegistryRefreshError("BAD_NUMBER")
    if not isinstance(api_key, str) or not api_key.strip():
        raise RegistryRefreshError("NO_KEY")
    if not _https_host(base_url):
        raise RegistryRefreshError("BAD_URL")
    url = f"{base_url.rstrip('/')}/company/{number}"
    token = base64.b64encode(f"{api_key.strip()}:".encode("utf-8")).decode("ascii")
    try:
        status, body = (fetch or _http_get)(url, {"Authorization": f"Basic {token}", "Accept": "application/json"}, MAX_BYTES)
    except (OSError, TimeoutError, ValueError, urllib.error.URLError):
        raise RegistryRefreshError("FETCH_FAILED") from None
    if status == 404:
        raise RegistryRefreshError("NOT_FOUND")
    if status != 200:
        raise RegistryRefreshError("HTTP_STATUS")
    if not isinstance(body, (bytes, bytearray)) or not body.strip():
        raise RegistryRefreshError("EMPTY")
    if len(body) > MAX_BYTES:
        raise RegistryRefreshError("TOO_LARGE")
    try:
        parse_company_profile(bytes(body), number)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise RegistryRefreshError("BAD_PROFILE") from None
    raw = bytes(body)
    meta = {
        "schema": META_SCHEMA, "number": number, "source": url, "retrieved_at": now or _now(),
        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
    }
    dest = Path(dest_dir) / SUBDIR
    dest.mkdir(parents=True, exist_ok=True)
    _replace(dest, f"{number}.json", raw)
    _replace(dest, f"{number}.meta.json", (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return meta


def _parse_time(text) -> datetime:
    ts = datetime.fromisoformat(text)
    if ts.tzinfo is None:
        raise ValueError("timestamp has no zone")
    return ts


def load_verified_record(dest_dir, number, *, now: str | None = None, max_age_days: int = DEFAULT_MAX_AGE_DAYS):
    """RegistryRecord (with provenance, and stale set when old) for a snapshot exactly as recorded; None if there
    is no snapshot for this number; RegistryUnavailable for a snapshot that cannot be trusted."""
    if not isinstance(number, str) or not NUMBER.fullmatch(number):
        return None
    base = Path(dest_dir) / SUBDIR
    data_path, meta_path = base / f"{number}.json", base / f"{number}.meta.json"
    if not data_path.exists() and not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
        ok = (isinstance(meta, dict) and meta.get("schema") == META_SCHEMA and meta.get("number") == number
              and isinstance(meta.get("source"), str) and type(meta.get("bytes")) is int
              and isinstance(meta.get("sha256"), str) and _SHA.fullmatch(meta["sha256"]))
        if not ok:
            raise ValueError("provenance is malformed")
        retrieved = _parse_time(meta.get("retrieved_at"))
        raw = data_path.read_bytes()
        if len(raw) != meta["bytes"] or hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            raise ValueError("the snapshot is not the file that was recorded")
        record = parse_company_profile(raw, number)
    except (OSError, ValueError, TypeError, UnicodeDecodeError, RecursionError) as exc:
        raise RegistryUnavailable(f"the saved registry snapshot for {number} cannot be used: {exc}") from None
    current = _parse_time(now) if now else datetime.now(timezone.utc)
    stale = current - retrieved > timedelta(days=max_age_days)
    provenance = f"{meta['source']} retrieved {meta['retrieved_at'][:10]} (sha256 {meta['sha256'][:12]})"
    return RegistryRecord(name=record.name, registration_id=number, status=record.status,
                          jurisdiction=record.jurisdiction, provenance=provenance, stale=stale,
                          age_note=f"retrieved {meta['retrieved_at'][:10]}")


def snapshot_identities(dest_dir) -> list[dict]:
    """number, sha256, retrieved_at of every saved snapshot, for a receipt's data digest. Reads provenance
    only; trust is decided at lookup."""
    base = Path(dest_dir) / SUBDIR
    out = []
    if not base.is_dir():
        return out
    for path in sorted(base.glob("*.meta.json")):
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
            out.append({k: meta[k] for k in ("number", "sha256", "retrieved_at")})
        except (OSError, ValueError, KeyError, TypeError):
            out.append({"number": path.name[:-len(".meta.json")], "sha256": "unreadable", "retrieved_at": "unreadable"})
    return out
