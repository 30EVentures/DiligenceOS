"""The charter's measure for the `diligence` role, computed from the signed receipt log alone.

    Receipts logged that were never revoked and never contradicted an earlier verdict on the same
    inputs, as a share of receipts logged.

Everything it needs is in the public log (`GET /v1/log/entries`), so a stranger holding the issuer key
they pinned can recompute it without trusting this server. It refuses to produce a number for a log
that does not verify under that key; an empty log has no ratio (not a perfect one); the output is
integers only and carries no text from the log.

    python3 -m diligenceos.flashy.measures --log ~/.diligenceos/receipts.jsonl --pin ed25519:<64 hex>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from diligenceos.receipt_log import GENESIS, verify_chain

MEASURE = ("Receipts logged that were never revoked and never contradicted an earlier verdict on the same inputs, "
           "as a share of receipts logged")
_PIN = re.compile(r"^ed25519:[0-9a-f]{64}\Z")


def valid_pin(pin) -> bool:
    return isinstance(pin, str) and bool(_PIN.fullmatch(pin))


def basis_points(numerator: int, denominator: int):
    return None if denominator == 0 else (numerator * 10000) // denominator


def diligence_measure(entries, pinned_issuer) -> dict:
    """{ok: True, numerator, denominator, basis_points|None, length, head_hash, measure}
    or {ok: False, code}. Never raises."""
    if not valid_pin(pinned_issuer):
        return {"ok": False, "code": "UNPINNED_KEY"}
    try:
        errors = verify_chain(entries, trusted_issuers=[pinned_issuer], require_signed=True)
        if errors:
            return {"ok": False, "code": "LOG_DOES_NOT_VERIFY"}
        receipts = [e for e in entries if e.get("kind", "receipt") == "receipt"]
        revoked = {e["target_id"] for e in entries if e.get("kind") == "revocation" and isinstance(e.get("target_id"), str)}
        clean = [e for e in receipts if e.get("conflict_with") is None and e.get("receipt_id") not in revoked]
    except Exception:  # noqa: BLE001 - a number is only ever produced from a log that was fully understood
        return {"ok": False, "code": "LOG_DOES_NOT_VERIFY"}
    return {
        "ok": True, "measure": MEASURE, "numerator": len(clean), "denominator": len(receipts),
        "basis_points": basis_points(len(clean), len(receipts)),
        "length": len(entries), "head_hash": entries[-1]["entry_hash"] if entries else GENESIS,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m diligenceos.flashy.measures", description=__doc__.split("\n\n")[0])
    parser.add_argument("--log", required=True, help="a receipts.jsonl file")
    parser.add_argument("--pin", required=True, help="the issuer key you pinned, ed25519:<64 hex>")
    args = parser.parse_args(argv)
    try:
        entries = [json.loads(line) for line in Path(args.log).expanduser().read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, ValueError):
        print(json.dumps({"ok": False, "code": "LOG_UNREADABLE"}))
        return 2
    result = diligence_measure(entries, args.pin)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 3


if __name__ == "__main__":
    sys.exit(main())
