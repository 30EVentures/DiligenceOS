"""Files for a person to host, so that a stranger can learn which key to pin. Making them publishes nothing.

The kit holds: the issuer's public key stated and signed by that key (a claim by the key, which does not by itself show who
holds it: people must also be told the key out of band), the FlashyOS handshake (no capabilities: a capability claims something
is callable), and the charter. It never reads or writes a private key's bytes (it asks the signer to sign, nothing more)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from diligenceos.receipt import digest
from diligenceos.signing import Signer, verify_signature

STATEMENT_SCHEMA = "diligenceos.issuer-statement/1"
STATEMENT_DOMAIN = "diligenceos.issuer-statement/1"
_FIELDS = frozenset("schema issuer algorithm operator manifest profile statement signature".split())
STATEMENT = (
    "This key signs DiligenceOS receipts, log entries and payment evidence. Pin it out of band before relying on anything signed by it; "
    "this file is a claim made with the key and does not by itself show who holds the key. Verify a receipt with "
    "`python -m diligenceos verify-receipt FILE --pin <this issuer id>`; the signed manifest at the URL below describes every signed document."
)


def _https(url, what: str) -> str:
    try:
        u = urlsplit(url) if isinstance(url, str) else None
    except ValueError:
        u = None
    if u is None or u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError(f"{what} must be an https URL without credentials, a query or a fragment")
    return url.rstrip("/")


def build_kit(out_dir, signer: Signer, *, charter_text: str, profile_url, api_url) -> dict:
    """Write the kit into a new or empty directory. Raises ValueError for a bad URL or charter, FileExistsError for a non-empty directory."""
    profile, api = _https(profile_url, "profile_url"), _https(api_url, "api_url")
    try:
        charter = json.loads(charter_text)
    except (TypeError, ValueError):
        raise ValueError("the charter is not valid JSON") from None
    if not isinstance(charter, dict) or charter.get("slug") != "diligenceos":
        raise ValueError("the charter must be the DiligenceOS charter object")
    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        raise FileExistsError(f"{out} already exists and is not empty; nothing was written")
    body = {"schema": STATEMENT_SCHEMA, "issuer": signer.issuer_id, "algorithm": "ed25519", "operator": "30E Ventures", "manifest": api + "/v1/manifest",
            "profile": profile, "statement": STATEMENT}
    statement = {**body, "signature": signer.sign(STATEMENT_DOMAIN, digest(body))}
    handshake = {"mesh": "flashyos/1", "org": {"slug": "diligenceos", "name": "DiligenceOS", "profile": profile}}
    well_known = out / ".well-known"
    well_known.mkdir(parents=True, exist_ok=True)
    (well_known / "diligenceos-issuer.json").write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
    (well_known / "flashyos.json").write_text(json.dumps(handshake, indent=2) + "\n", encoding="utf-8")
    (well_known / "flashyos-charter.json").write_text(charter_text, encoding="utf-8")
    (out / "PUBLISHING.txt").write_text(_instructions(profile, api, signer.issuer_id), encoding="utf-8")
    return {"issuer": signer.issuer_id, "out": str(out), "files": sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())}


def verify_issuer_statement(doc, pinned_issuer) -> bool:
    """Offline: the statement has exactly the known fields and was signed by the PINNED key."""
    try:
        if not isinstance(doc, dict) or set(doc) != _FIELDS or doc["schema"] != STATEMENT_SCHEMA or doc["issuer"] != pinned_issuer:
            return False
        return verify_signature(pinned_issuer, STATEMENT_DOMAIN, digest({k: v for k, v in doc.items() if k != "signature"}), doc["signature"])
    except (KeyError, TypeError, ValueError):
        return False


def _instructions(profile: str, api: str, issuer: str) -> str:
    return f"""DiligenceOS publishing kit. These files have NOT been published; making them did not contact anything.

What each file is, and where it goes (on {profile}):
  .well-known/diligenceos-issuer.json   -> {profile}/.well-known/diligenceos-issuer.json
      The issuer key ({issuer}) stated and signed by itself. Anyone can fetch it, but it only helps people who were also
      TOLD the key another way (email, a conversation, a signed page). It is a claim made with the key, not proof of who holds it.
  .well-known/flashyos.json             -> {profile}/.well-known/flashyos.json
      The FlashyOS handshake. It declares no capabilities on purpose: add one only once the API at {api} is deployed and callable.
  .well-known/flashyos-charter.json     -> {profile}/.well-known/flashyos-charter.json
      The charter (pre-alpha). Check it first: python -m diligenceos.flashy.measures and the charter tests.

Serve them as JSON (Content-Type: application/json), over https, with Access-Control-Allow-Origin: *.
Before the API is reachable: set DILIGENCEOS_VERDICT_AUTH=signed, run exactly one server process, keep the data directory on a disk that
persists (store.json, receipts.jsonl, issuer.key), and back up issuer.key as a secret: losing it makes every old receipt unverifiable.
See deploy/DEPLOY.md.
"""
