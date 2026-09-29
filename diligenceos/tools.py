"""Small CLI for minting keys and credentials and signing requests.

    python -m diligenceos keygen KEYFILE
    python -m diligenceos delegate --subject ID --scopes spend [--key F] [--chain F] ...
    python -m diligenceos sign-request --key F --path /v1/spend [--chain F] BODYFILE|-
    python -m diligenceos witness --url U --issuer ID --key F --state F [--submit]

Everything prints JSON on stdout; errors go to stderr with exit status 2
(`witness` exits 3 when it finds the log inconsistent with what it saw before).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from diligenceos.auth import sign_request
from diligenceos.delegation import extend_chain
from diligenceos.policy import Policy
from diligenceos.signing import Signer, SignerError
from diligenceos.types import Money, Verdict

COMMANDS = ("keygen", "delegate", "sign-request", "witness")


def _operator_key_path() -> Path:
    from diligenceos import webapp  # same data dir the server uses

    return webapp._data_path().with_name("issuer.key")


def _read_json(path: str):
    return json.loads(sys.stdin.read() if path == "-" else Path(path).read_text())


def _keygen(args) -> int:
    signer = Signer.load_or_create(Path(args.keyfile).expanduser())
    print(json.dumps({"issuer": signer.issuer_id, "key_file": str(Path(args.keyfile).expanduser())}))
    return 0


def _delegate(args) -> int:
    key = Path(args.key).expanduser() if args.key else _operator_key_path()
    if not key.exists():
        raise ValueError(
            f"key file {key} does not exist: start the server once (it creates the operator "
            "key), or pass --key with a key made by `keygen`"
        )
    signer = Signer.load_or_create(key)
    chain = _read_json(args.chain) if args.chain else []

    policy = None
    if any(v is not None for v in (args.max_amount, args.currency, args.min_trust)):
        if None in (args.max_amount, args.currency, args.min_trust):
            raise ValueError("a policy needs all of --max-amount, --currency and --min-trust")
        policy = Policy(
            max_amount=Money(args.max_amount, args.currency),
            acceptable_verdicts=frozenset(Verdict(v) for v in args.verdicts.split(",")),
            min_trust_score=args.min_trust,
        )
    expires = (datetime.now(timezone.utc) + timedelta(seconds=args.ttl)).replace(microsecond=0)
    new_chain = extend_chain(
        chain, signer, delegate=args.subject, scopes=args.scopes.split(","),
        expires=expires.isoformat(), policy=policy, budget_id=args.budget,
    )
    print(json.dumps(new_chain, indent=2))
    return 0


def _sign_request(args) -> int:
    signer = Signer.load_or_create(Path(args.key).expanduser())
    chain = _read_json(args.chain) if args.chain else []
    body = _read_json(args.body)
    if not isinstance(body, dict) or "auth" in body:
        raise ValueError("body must be a JSON object without an `auth` key")
    print(json.dumps({**body, "auth": sign_request(signer, chain, args.path, body)}))
    return 0


def _witness(args) -> int:
    import urllib.error
    import urllib.request

    from diligenceos.witness import run_witness

    base = args.url.rstrip("/")

    def fetch(path: str) -> dict:
        with urllib.request.urlopen(base + path, timeout=15) as resp:
            return json.load(resp)

    def submit(cosignature: dict) -> str:
        req = urllib.request.Request(
            base + "/v1/log/cosign", data=json.dumps(cosignature).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15):
                return "cosignature accepted by the server"
        except urllib.error.HTTPError as exc:
            reason = json.load(exc).get("error", {}).get("message", exc.reason)
            return f"server did not store the cosignature ({exc.code}: {reason})"

    signer = Signer.load_or_create(Path(args.key).expanduser())
    try:
        code, message, cosignature = run_witness(
            fetch, Path(args.state).expanduser(), signer, args.issuer,
            submit=submit if args.submit else None,
        )
    except urllib.error.URLError as exc:
        raise ValueError(f"could not reach {base}: {exc.reason}") from exc
    print(json.dumps({"ok": code == 0, "message": message, "cosignature": cosignature}))
    return code


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m diligenceos")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create (or show) an Ed25519 key file")
    p.add_argument("keyfile")
    p.set_defaults(run=_keygen)

    p = sub.add_parser("delegate", help="mint a delegation chain for a subject key")
    p.add_argument("--subject", required=True, help="the delegate's issuer id (ed25519:...)")
    p.add_argument("--scopes", required=True, help="comma-separated: spend,revoke")
    p.add_argument("--key", help="signing key file (default: the operator key)")
    p.add_argument("--chain", help="existing chain (JSON file or -) when delegating onward")
    p.add_argument("--ttl", type=int, default=86400, help="seconds until expiry (default 86400)")
    p.add_argument("--budget", help="bind the credential to one budget id")
    p.add_argument("--max-amount", type=int, help="policy cap in integer minor units")
    p.add_argument("--currency", help="policy currency, e.g. USD")
    p.add_argument("--min-trust", type=int, help="policy trust-score floor, 0-100")
    p.add_argument("--verdicts", default="PROCEED", help="acceptable verdicts, comma-separated")
    p.set_defaults(run=_delegate)

    p = sub.add_parser("sign-request", help="attach an auth envelope to a request body")
    p.add_argument("--key", required=True, help="the caller's key file")
    p.add_argument("--path", required=True, help="endpoint path, e.g. /v1/spend")
    p.add_argument("--chain", help="credential chain (JSON file or -); omit for the operator")
    p.add_argument("body", help="request body JSON file, or - for stdin")
    p.set_defaults(run=_sign_request)

    p = sub.add_parser("witness", help="check the log extends what you last saw, and cosign it")
    p.add_argument("--url", required=True, help="server base URL, e.g. http://127.0.0.1:8000")
    p.add_argument("--issuer", required=True, help="the issuer id you pinned out of band")
    p.add_argument("--key", required=True, help="the witness's own key file (see `keygen`)")
    p.add_argument("--state", required=True, help="where this witness remembers heads")
    p.add_argument("--submit", action="store_true", help="also POST the cosignature to the server")
    p.set_defaults(run=_witness)

    try:
        args = parser.parse_args(argv)
        return args.run(args)
    except (ValueError, SignerError, OSError) as exc:  # includes JSON errors and bad policies
        print(f"error: {exc}", file=sys.stderr)
        return 2
