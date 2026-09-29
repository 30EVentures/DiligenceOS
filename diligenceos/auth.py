"""Request authentication: prove possession of a key that holds (delegated) authority."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from diligenceos.delegation import SCOPES, verify_chain
from diligenceos.policy import Policy
from diligenceos.receipt import digest
from diligenceos.signing import Signer, verify_signature

REQUEST_DOMAIN = "diligenceos.request/1"
MAX_SKEW_SECONDS = 300


def _message(path: str, body: dict, issued_at: str, nonce: str) -> str:
    return digest({"path": path, "body": body, "issued_at": issued_at, "nonce": nonce})


def sign_request(
    signer: Signer, chain: list, path: str, body: dict,
    *, now: str | None = None, nonce: str | None = None,
) -> dict:
    """The `auth` envelope for `body` (which must not itself contain `auth`)."""
    now = now or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    nonce = nonce or secrets.token_hex(16)
    return {
        "signer": signer.issuer_id,
        "chain": chain,
        "issued_at": now,
        "nonce": nonce,
        "signature": signer.sign(REQUEST_DOMAIN, _message(path, body, now, nonce)),
    }


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    caller: str | None = None
    scopes: frozenset[str] = frozenset()
    policy: Policy | None = None
    budget_id: str | None = None
    is_root: bool = False


def _fail(*errors: str) -> AuthResult:
    return AuthResult(False, tuple(errors))


def authenticate(
    path: str, body: dict, auth, *, root_issuers, now: str, revocations=None, remember_nonce=None,
) -> AuthResult:
    """Never raises. `remember_nonce(nonce, now) -> bool` returns True if already seen."""
    try:
        signer_id = auth["signer"]
        chain, issued_at = auth["chain"], auth["issued_at"]
        nonce, signature = auth["nonce"], auth["signature"]
        if not all(isinstance(x, str) for x in (signer_id, issued_at, nonce, signature)):
            raise TypeError("signer, issued_at, nonce and signature must be strings")
        if not isinstance(chain, list):
            raise TypeError("chain must be a list")
        skew = abs((datetime.fromisoformat(now) - datetime.fromisoformat(issued_at)).total_seconds())
    except (KeyError, TypeError, ValueError):
        return _fail("auth envelope is missing or malformed")

    if skew > MAX_SKEW_SECONDS:
        return _fail(f"request time is more than {MAX_SKEW_SECONDS}s from the server's clock")
    if not verify_signature(signer_id, REQUEST_DOMAIN, _message(path, body, issued_at, nonce), signature):
        return _fail("request signature does not verify (wrong key, path, body, time or nonce)")

    if not chain:
        if signer_id not in set(root_issuers):
            return _fail("caller presented no credential and is not the operator")
        result = AuthResult(True, caller=signer_id, scopes=frozenset(SCOPES), is_root=True)
    else:
        checked = verify_chain(chain, root_issuers=root_issuers, now=now, revocations=revocations)
        if not checked.valid:
            return _fail(*(f"credential: {e}" for e in checked.errors))
        if checked.delegate != signer_id:
            return _fail("request key is not the credential's delegate")
        result = AuthResult(
            True, caller=signer_id, scopes=checked.scopes,
            policy=checked.policy, budget_id=checked.budget_id,
        )

    if remember_nonce is not None and remember_nonce(nonce, now):
        return _fail("nonce already used (replay)")
    return result
