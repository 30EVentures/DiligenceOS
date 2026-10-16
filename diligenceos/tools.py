"""Small CLI for minting keys and credentials and signing requests.

    python -m diligenceos keygen KEYFILE
    python -m diligenceos delegate --subject ID --scopes spend [--key F] [--chain F] ...
    python -m diligenceos sign-request --key F --path /v1/spend [--chain F] BODYFILE|-
    python -m diligenceos witness --url U --issuer ID --key F --state F [--submit]
    python -m diligenceos refresh-sanctions [--url U] [--encoding E] [--min-entries N] [--dest DIR]
    python -m diligenceos verify-receipt FILE --pin ISSUER_ID [--now ISO]     (offline; what a stranger runs)
    python -m diligenceos verify-evidence FILE --pin ISSUER_ID                (offline; a payment evidence record)

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

COMMANDS = ("keygen", "delegate", "sign-request", "witness", "refresh-sanctions", "verify-receipt", "verify-evidence")


def _operator_key_path() -> Path:
    from diligenceos import webapp  # same data dir the server uses

    return webapp._data_path().with_name("issuer.key")


def _read_json(path: str):
    return json.loads(sys.stdin.buffer.read().decode("utf-8") if path == "-" else Path(path).read_text(encoding="utf-8"))


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


MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # a full 500-entry log page is well under 1 MiB


def _json_from_response(resp) -> object:
    """Parse a server's reply, reading at most MAX_RESPONSE_BYTES. The witness exists to distrust
    the server it watches; that server must not be able to make it buffer without limit."""
    data = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ValueError(f"the server's reply is larger than {MAX_RESPONSE_BYTES} bytes; refusing to read it")
    try:
        return json.loads(data.decode("utf-8"))
    except RecursionError:
        raise ValueError("the server's reply is nested too deeply to read") from None


def _witness(args) -> int:
    import urllib.error
    import urllib.request

    from diligenceos.witness import run_witness

    base = args.url.rstrip("/")

    def fetch(path: str) -> dict:
        with urllib.request.urlopen(base + path, timeout=15) as resp:
            return _json_from_response(resp)

    def submit(cosignature: dict) -> str:
        req = urllib.request.Request(
            base + "/v1/log/cosign", data=json.dumps(cosignature).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15):
                return "cosignature accepted by the server"
        except urllib.error.HTTPError as exc:
            try:
                reason = _json_from_response(exc).get("error", {}).get("message", exc.reason)
            except (ValueError, AttributeError):
                reason = exc.reason
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


_PIN = __import__("re").compile(r"^ed25519:[0-9a-f]{64}\Z")


def _pin_and_file(args):
    if not _PIN.match(args.pin or ""):
        raise ValueError("--pin must be the issuer id you pinned: ed25519: followed by 64 lowercase hex characters")
    return json.loads(Path(args.file).expanduser().read_text(encoding="utf-8"))


def _verify_receipt(args) -> int:
    """One file, one pinned key, one answer. Offline: no server, no network. Never echoes text from the file."""
    from diligenceos.receipt import verify_receipt

    receipt = _pin_and_file(args)
    now = args.now or datetime.now(timezone.utc).isoformat()
    try:
        if datetime.fromisoformat(now).tzinfo is None:
            raise ValueError
    except ValueError:
        raise ValueError("--now must be an ISO-8601 time with a timezone") from None
    check = verify_receipt(receipt, now=now, trusted_issuers=[args.pin])
    why = []
    if not check.valid:
        why.append("it has been changed, or it is not a DiligenceOS receipt")
    if check.valid and not check.signed:
        why.append("it is not signed")
    if check.valid and check.signed and check.trusted is not True:
        why.append("it was not signed by the key you pinned")
    if check.valid and isinstance(receipt, dict) and receipt.get("expires") is None:
        why.append("it has no expiry (a receipt that never expires proves nothing about now)")
    if check.valid and check.expired:
        why.append("it has expired")
    if why:
        print("NOT VERIFIED: " + "; ".join(why) + ".")
        return 1
    print("VERIFIED: intact, signed by the key you pinned, not expired.")
    print(f"  verdict {receipt['verdict']}, trust score {receipt['trust_score']}, expires {receipt['expires']}, id {receipt['id']}")
    if isinstance(receipt.get("transaction"), dict):
        print(f"  transaction {receipt['transaction'].get('amount_minor')} {receipt['transaction'].get('currency')} (minor units)")
    print("  Not checked offline: whether it has since been revoked (see the issuer's /v1/revocations and its signed log).")
    return 0


def _verify_evidence(args) -> int:
    from diligenceos.flashy.payment_evidence import verify_payment_evidence

    doc = _pin_and_file(args)
    if not verify_payment_evidence(doc, args.pin):
        print("NOT VERIFIED: it has been changed, is not a payment evidence record, or was not signed by the key you pinned.")
        return 1
    print("VERIFIED: a payment evidence record, intact and signed by the key you pinned.")
    print(f"  {doc['amount']} of {doc['asset']} on {doc['chain']} ({doc['finality']}), from {doc['payer_address']} to {doc['payee_address']}")
    print(f"  transaction {doc['tx_hash']} with {doc['confirmations']} confirmation(s); authorized by the {doc['plane']} plane ({doc['authorized_how']}), "
          f"through {doc['grant_depth'] + 1} grant(s) from root {doc['grant_root_key']}")
    print("  This record does not approve or authorize any spend. It says only that a payment authorized elsewhere was also made.")
    print("  To check it against the underlying documents, re-run the recheck with the request, authorization, plane log and chain.")
    return 0


def _refresh_sanctions(args) -> int:
    """The one place DiligenceOS goes to the network for data, and only when a person runs this."""
    from diligenceos import sdn_ingest, webapp

    dest = Path(args.dest).expanduser() if args.dest else webapp._data_path().parent
    try:
        meta = sdn_ingest.refresh_sdn(dest, url=args.url, encoding=args.encoding, min_entries=args.min_entries)
    except sdn_ingest.SdnRefreshError as exc:
        print(f"sanctions refresh refused: {exc.code} (nothing was changed)", file=sys.stderr)
        return 2
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m diligenceos")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="create (or show) an Ed25519 key file")
    p.add_argument("keyfile")
    p.set_defaults(run=_keygen)

    p = sub.add_parser("delegate", help="mint a delegation chain for a subject key")
    p.add_argument("--subject", required=True, help="the delegate's issuer id (ed25519:...)")
    p.add_argument("--scopes", required=True, help="comma-separated: spend,revoke,verdict")
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

    for name, fn, what in (("verify-receipt", _verify_receipt, "check a verdict receipt offline against a key you pinned"),
                           ("verify-evidence", _verify_evidence, "check a payment evidence record offline against a key you pinned")):
        p = sub.add_parser(name, help=what)
        p.add_argument("file", help="the JSON file to check")
        p.add_argument("--pin", help="the issuer id you pinned, ed25519:<64 hex> (get it from the operator, not from the file)")
        if name == "verify-receipt":
            p.add_argument("--now", help="judge expiry at this ISO-8601 time with a timezone (default: now)")
        p.set_defaults(run=fn, **({} if name == "verify-receipt" else {"now": None}))

    p = sub.add_parser("refresh-sanctions", help="download the official sanctions list (human-run; the only command that fetches data)")
    from diligenceos.sdn_ingest import DEFAULT_MIN_ENTRIES, DEFAULT_SDN_URL
    p.add_argument("--url", default=DEFAULT_SDN_URL, help="https URL of SDN.CSV (default: OFAC's published file)")
    p.add_argument("--encoding", default="utf-8", help="the file's text encoding if it is not UTF-8, e.g. cp1252 (it is stored as UTF-8)")
    p.add_argument("--min-entries", type=int, default=DEFAULT_MIN_ENTRIES, help="refuse a file with fewer entries (an error page, the wrong file)")
    p.add_argument("--dest", help="directory to save into (default: beside the store)")
    p.set_defaults(run=_refresh_sanctions)

    try:
        args = parser.parse_args(argv)
        return args.run(args)
    except (ValueError, SignerError, OSError) as exc:  # includes JSON errors and bad policies
        print(f"error: {exc}", file=sys.stderr)
        return 2
