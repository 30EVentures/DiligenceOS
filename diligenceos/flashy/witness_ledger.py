"""A signed record of every witnessing attempt, so the witness role's measure can be computed.

`witness.witness_receipt` returns a receipt for a log it could verify and raises for one it could not;
on its own that leaves no trace of the refusals, and a rate over successes alone is not a rate. This
wraps it (it does not change it): every attempt, good or refused, appends one line to a hash-chained,
signed ledger. A line holds only fixed codes, counts and hex digests, never any text from the log
that was submitted.

    outcome WITNESSED | REFUSED;  code OK or the witness's own refusal code (EMPTY_LOG, BAD_SIGNATURE, ...)

The measure (`witness_measure`): witnessing attempts that ended in a signed receipt, as a share of attempts.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from diligenceos.flashy import presence, witness
from diligenceos.flashy.measures import basis_points, valid_pin
from diligenceos.receipt import digest
from diligenceos.receipt_log import GENESIS
from diligenceos.signing import Signer, verify_signature

LEDGER_DOMAIN = "diligenceos.witness-ledger/1"
MEASURE = "Plane logs submitted for witnessing that verified end to end and were signed, as a share of logs submitted"
OUTCOMES = ("WITNESSED", "REFUSED")
_CODE = re.compile(r"^[A-Z_]{2,40}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEYS = frozenset("seq kind outcome code plane_log_key receipt_id head_hash entry_count logged_at prev_hash entry_hash issuer signature".split())


class LedgerCorrupt(Exception):
    pass


def _hash(entry: dict) -> str:
    return digest({k: v for k, v in entry.items() if k not in ("entry_hash", "signature")})


def verify_ledger(entries, pinned_issuer, expected_head=None) -> list[str]:
    """Empty list means the ledger is intact and signed by the pinned key. Pure; never raises."""
    if not valid_pin(pinned_issuer):
        return ["the witness key is not pinned"]
    if not isinstance(entries, list):
        return ["entries must be a list"]
    errors, prev = [], GENESIS
    for i, e in enumerate(entries):
        try:
            if not isinstance(e, dict) or set(e) != _KEYS:
                errors.append(f"entry {i} is malformed")
                break
            ok = (
                type(e["seq"]) is int and e["seq"] == i and e["kind"] == "witnessing" and e["outcome"] in OUTCOMES
                and isinstance(e["code"], str) and _CODE.fullmatch(e["code"])
                and (e["plane_log_key"] is None or (isinstance(e["plane_log_key"], str) and _HEX.fullmatch(e["plane_log_key"])))
                and (e["receipt_id"] is None or (isinstance(e["receipt_id"], str) and _ID.fullmatch(e["receipt_id"])))
                and (e["head_hash"] is None or (isinstance(e["head_hash"], str) and _HEX.fullmatch(e["head_hash"])))
                and (e["entry_count"] is None or (type(e["entry_count"]) is int and e["entry_count"] >= 0))
                and (e["outcome"] == "WITNESSED") == (e["receipt_id"] is not None) and isinstance(e["logged_at"], str)
            )
            if not ok:
                errors.append(f"entry {i} has a field outside the allowed vocabulary")
                break
            if e["prev_hash"] != prev:
                errors.append(f"entry {i} does not link to the entry before it")
            if e["entry_hash"] != _hash(e):
                errors.append(f"entry {i} does not match its own hash")
            if e["issuer"] != pinned_issuer or not verify_signature(pinned_issuer, LEDGER_DOMAIN, e["entry_hash"], e["signature"]):
                errors.append(f"entry {i} is not signed by the pinned witness key")
            prev = e["entry_hash"]
        except Exception:  # noqa: BLE001
            errors.append(f"entry {i} is unreadable")
            break
    if expected_head is not None and prev != expected_head:
        errors.append("the ledger does not end at the expected head (entries dropped or replaced)")
    return errors


def witness_measure(entries, pinned_issuer, expected_head=None) -> dict:
    if not valid_pin(pinned_issuer):
        return {"ok": False, "code": "UNPINNED_KEY"}
    if verify_ledger(entries, pinned_issuer, expected_head):
        return {"ok": False, "code": "LEDGER_DOES_NOT_VERIFY"}
    good = sum(1 for e in entries if e["outcome"] == "WITNESSED")
    return {"ok": True, "measure": MEASURE, "numerator": good, "denominator": len(entries),
            "basis_points": basis_points(good, len(entries)), "length": len(entries),
            "head_hash": entries[-1]["entry_hash"] if entries else GENESIS}


class WitnessLedger:
    def __init__(self, path, signer: Signer) -> None:
        self.path, self.signer = Path(path), signer
        self._entries: list[dict] = []
        if self.path.exists():
            try:
                self._entries = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
            except ValueError as exc:
                raise LedgerCorrupt("the witness ledger is not valid JSON lines") from exc
            errors = verify_ledger(self._entries, signer.issuer_id)
            if errors:
                raise LedgerCorrupt("the witness ledger failed verification: " + "; ".join(errors))

    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    @property
    def head(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else GENESIS

    def remembered(self, plane_log_key):
        """(count, head) of the last log this witness signed for under `plane_log_key`, or None on first sight."""
        for e in reversed(self._entries):
            if e["outcome"] == "WITNESSED" and e["plane_log_key"] == plane_log_key:
                return e["entry_count"], e["head_hash"]
        return None

    def witness(self, plane_entries, pinned_pub, *, issued_at, cap_base_units=None, now=None, pinned_count=None, pinned_head=None):
        """(receipt | None, ledger entry). A refusal is recorded, never raised and never signed.

        Every witnessing pins the head and count it last signed for this plane key (a cut tail is invisible to a
        hash chain), and the caller's own pin too if given; the caller cannot relax what the ledger remembers."""
        receipt, code = None, "OK"
        presence.note("witnessing")
        try:
            pins = []
            memory = self.remembered(pinned_pub) if isinstance(pinned_pub, str) else None
            if memory is not None:
                pins.append(memory)
            if pinned_count is not None or pinned_head is not None:
                pins.append((pinned_count, pinned_head))
            for count, head in pins:
                checked = witness.verify_plane_log(plane_entries, pinned_pub, pinned_count=count, pinned_head=head)
                if not checked["ok"]:
                    raise witness.PlaneLogInvalid(checked["code"], checked.get("at"))
            receipt = witness.witness_receipt(plane_entries, pinned_pub, self.signer, issued_at=issued_at, cap_base_units=cap_base_units)
        except witness.PlaneLogInvalid as exc:
            code = exc.code if isinstance(exc.code, str) and _CODE.fullmatch(exc.code) else "UNKNOWN"
        except (ValueError, TypeError):
            code = "BAD_INPUT"
        except Exception:  # noqa: BLE001 - recorded as a refusal; the witness never signs what it could not check
            code = "INTERNAL_ERROR"
        if receipt is None:
            presence.note("incident")      # a chain this witness refused
        entry = {
            "seq": len(self._entries), "kind": "witnessing",
            "outcome": "WITNESSED" if receipt else "REFUSED", "code": code,
            "plane_log_key": pinned_pub if isinstance(pinned_pub, str) and _HEX.fullmatch(pinned_pub) else None,
            "receipt_id": receipt["id"] if receipt else None,
            "head_hash": receipt["head_hash"] if receipt else None,
            "entry_count": receipt["entry_count"] if receipt else None,
            "logged_at": now or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "prev_hash": self.head, "issuer": self.signer.issuer_id,
        }
        entry["entry_hash"] = _hash(entry)
        entry["signature"] = self.signer.sign(LEDGER_DOMAIN, entry["entry_hash"])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:        # write first: only remember what reached disk
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._entries.append(entry)
        return receipt, entry


def main(argv=None) -> int:
    """python3 -m diligenceos.flashy.witness_ledger --plane-log FILE --pin HEX --ledger FILE --key FILE

    0 witnessed (the signed receipt is printed); 3 refused (the code is printed, nothing is signed);
    2 the command itself could not run (nothing is recorded: no attempt was made). It never creates a key:
    a new key would be a new identity."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="python3 -m diligenceos.flashy.witness_ledger")
    parser.add_argument("--plane-log", required=True, help="JSON file: the plane's log entries, as a list")
    parser.add_argument("--pin", required=True, help="the plane's log key you pinned (64 lowercase hex)")
    parser.add_argument("--ledger", required=True, help="witness ledger file (created if missing)")
    parser.add_argument("--key", required=True, help="this witness's existing issuer key file")
    args = parser.parse_args(argv)
    key_path = Path(args.key).expanduser()
    if not key_path.is_file():
        print(json.dumps({"ok": False, "code": "KEY_NOT_FOUND"}))
        return 2
    try:
        signer = Signer.load_or_create(key_path)
        ledger = WitnessLedger(Path(args.ledger).expanduser(), signer)
    except Exception:  # noqa: BLE001 - unusable key or a ledger that does not verify
        print(json.dumps({"ok": False, "code": "KEY_OR_LEDGER_UNUSABLE"}))
        return 2
    try:
        text = Path(args.plane_log).expanduser().read_text(encoding="utf-8")
    except OSError:
        print(json.dumps({"ok": False, "code": "PLANE_LOG_UNREADABLE"}))
        return 2
    try:
        plane_entries = json.loads(text)
    except ValueError:
        plane_entries = None            # recorded as a refusal (NOT_A_LOG): it was submitted and could not be checked
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    receipt, entry = ledger.witness(plane_entries, args.pin, issued_at=issued_at)
    print(json.dumps({"ok": receipt is not None, "outcome": entry["outcome"], "code": entry["code"], "receipt": receipt}, sort_keys=True))
    return 0 if receipt else 3


if __name__ == "__main__":
    import sys
    sys.exit(main())
