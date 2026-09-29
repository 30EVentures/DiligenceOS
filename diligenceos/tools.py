"""Small CLI for minting keys and credentials and signing requests.

    python -m diligenceos keygen KEYFILE
    python -m diligenceos delegate --subject ID --scopes spend [--key F] [--chain F] ...
    python -m diligenceos sign-request --key F --path /v1/spend [--chain F] BODYFILE|-

Everything prints JSON on stdout; errors go to stderr with exit status 2.
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

COMMANDS = ("keygen", "delegate", "sign-request")


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

    try:
        args = parser.parse_args(argv)
        return args.run(args)
    except (ValueError, SignerError, OSError) as exc:  # includes JSON errors and bad policies
        print(f"error: {exc}", file=sys.stderr)
        return 2
