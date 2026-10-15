"""DiligenceOS as SELLER of a signed diligence receipt, paid in TESTNET / MOCK stablecoin.

Flow: make_invoice -> buyer pays on a chain -> settle_invoice (the SELLER reads the chain itself;
the buyer's claim of payment counts for nothing) -> deliverable released with a signed receipt.
Demo only: `finality` is "simulated" (local mock) or "testnet", never anything stronger.
DiligenceOS never spends; this module only reads a chain and signs a receipt.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from diligenceos.flashy.spine import (
    ADDR, AMOUNT, DOMAIN_INVOICE, DOMAIN_RECEIPT, HEX32, ISO_MS, TXHASH,
    CanonError, SpineKey, canonical, hash_of, verify_doc,
)
from diligenceos.receipt import canonical_json

# Code-level allowlist (never an env flag): adding a chain is a code change and a review.
ALLOWED_CHAINS = {"evm:31337": 31337, "evm:84532": 84532, "evm:43113": 43113}
TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SEL_TRANSFER = "a9059cbb"
INVOICE_VER = "30e-demo-invoice/1"
RECEIPT_VER = "30e-demo-receipt/1"
INVOICE_KEYS = frozenset(
    "ver invoiceId seller payee chain asset amount deliverableHash expiresAt sellerKey sig".split()
)
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def iso_ms(dt: datetime) -> str:
    """JS Date#toISOString form: UTC, millisecond precision, trailing Z."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_iso(s):
    """Strict ISO-8601 UTC 'Z' timestamp -> aware datetime, else None."""
    if not (isinstance(s, str) and ISO_MS.match(s)):
        return None
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


# ---- deliverable -------------------------------------------------------------------------------

def deliverable_from_receipt(receipt: dict) -> str:
    """The deliverable is a real DiligenceOS receipt (made by diligenceos.receipt.issue_receipt),
    serialized with that module's own canonical_json. Receipts hold non-integer numbers
    (trust_score), which the spine's canonical form refuses, so the spine carries the receipt as a
    string: deliverableHash = hashOf({d: <string>})."""
    return canonical_json(receipt).decode("utf-8")


def deliverable_hash(deliverable) -> str:
    if not isinstance(deliverable, str):
        raise TypeError("deliverable must be a string")
    return hash_of({"d": deliverable})


# ---- invoice -----------------------------------------------------------------------------------

def make_invoice(seller_key: SpineKey, *, invoice_id: str, seller: str, payee: str, chain: str, asset: str,
                 amount: str, deliverable: str, expires_at: str) -> dict:
    if chain not in ALLOWED_CHAINS:
        raise ValueError(f"chain {chain!r} is not on the testnet allowlist")
    if not (isinstance(amount, str) and AMOUNT.match(amount)) or int(amount) == 0:
        raise ValueError("amount must be a positive integer string of base units")
    if parse_iso(expires_at) is None:
        raise ValueError("expires_at must be an ISO-8601 UTC 'Z' timestamp")
    payee, asset = payee.lower(), asset.lower()
    if not (ADDR.match(payee) and ADDR.match(asset)):
        raise ValueError("payee and asset must be 0x + 40 hex")
    body = {
        "ver": INVOICE_VER, "invoiceId": invoice_id, "seller": seller, "payee": payee, "chain": chain,
        "asset": asset, "amount": amount, "deliverableHash": deliverable_hash(deliverable),
        "expiresAt": expires_at, "sellerKey": seller_key.pub_hex,
    }
    return {**body, "sig": seller_key.sign(DOMAIN_INVOICE, body)}


def verify_invoice(inv, pinned_seller_pub, now: datetime) -> bool:
    """Against a PINNED seller key only. Closed schema, canonical amount, unexpired, signature."""
    return invoice_refusal(inv, pinned_seller_pub, now) is None


def invoice_refusal(inv, pinned_seller_pub, now: datetime):
    """None if the invoice is acceptable, else a refusal code."""
    try:
        if not isinstance(inv, dict) or set(inv) != INVOICE_KEYS:
            return "INVOICE_SCHEMA"
        if not (isinstance(pinned_seller_pub, str) and HEX32.match(pinned_seller_pub)):
            return "UNPINNED_KEY"
        if inv["sellerKey"] != pinned_seller_pub:
            return "UNPINNED_KEY"
        if inv["ver"] != INVOICE_VER:
            return "INVOICE_SCHEMA"
        if not (isinstance(inv["amount"], str) and AMOUNT.match(inv["amount"])) or int(inv["amount"]) == 0:
            return "BAD_AMOUNT"
        if not (isinstance(inv["payee"], str) and ADDR.match(inv["payee"])
                and isinstance(inv["asset"], str) and ADDR.match(inv["asset"])):
            return "INVOICE_SCHEMA"
        if inv["chain"] not in ALLOWED_CHAINS:
            return "UNKNOWN_CHAIN"
        body = {k: v for k, v in inv.items() if k != "sig"}
        if not verify_doc(pinned_seller_pub, DOMAIN_INVOICE, body, inv["sig"]):
            return "BAD_SIGNATURE"
        exp = parse_iso(inv["expiresAt"])
        if exp is None or not exp > now:
            return "EXPIRED"
        return None
    except (KeyError, TypeError, CanonError):
        return "INVOICE_SCHEMA"


def verify_receipt(r, seller_pub) -> bool:
    """Verify the seller's settlement receipt against a pinned seller key (closed schema)."""
    keys = set("ver invoiceId txHash payer amount deliverableHash chain finality releasedAt seller sig".split())
    try:
        if not isinstance(r, dict) or set(r) != keys or r["ver"] != RECEIPT_VER:
            return False
        if r["finality"] not in ("simulated", "testnet"):
            return False
        return verify_doc(seller_pub, DOMAIN_RECEIPT, {k: v for k, v in r.items() if k != "sig"}, r["sig"])
    except (KeyError, TypeError):
        return False


# ---- spent-set (atomically persisted) -----------------------------------------------------------

class SpentSet:
    """Set of tx hashes that have already paid an invoice. claim() is check-and-add under an
    exclusive file lock, and the file is replaced atomically (write temp, fsync, rename), so two
    settlements racing on one tx hash cannot both win and a crash never leaves a torn file."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = self.path.with_suffix(self.path.suffix + ".lock")

    def _read(self) -> set:
        if not self.path.exists():
            return set()
        data = json.loads(self.path.read_text())
        if not (isinstance(data, list) and all(isinstance(x, str) for x in data)):
            raise ValueError("spent-set file is corrupt")
        return set(data)

    def __contains__(self, tx: str) -> bool:
        return tx in self._read()

    def claim(self, tx: str) -> bool:
        """True if this call is the first to spend `tx`. A corrupt file raises (fail closed)."""
        fd = os.open(self._lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            cur = self._read()
            if tx in cur:
                return False
            cur.add(tx)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with open(tmp, "w") as fh:
                json.dump(sorted(cur), fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            return True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


# ---- chain access ------------------------------------------------------------------------------

class RpcError(Exception):
    pass


class RpcClient:
    """Minimal JSON-RPC over HTTP. Loopback only: this demo build never talks to a real network."""

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        u = urlparse(url)
        if u.scheme != "http" or u.hostname not in LOOPBACK:
            raise ValueError("RPC endpoint must be http on loopback (demo build: localhost only)")
        self.url, self.timeout, self._id = url, timeout, 0

    def __call__(self, method: str, params: list):
        self._id += 1
        req = urllib.request.Request(
            self.url, data=json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode(),
            headers={"content-type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                msg = json.loads(resp.read(1_000_000))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RpcError(str(exc)) from exc
        if not isinstance(msg, dict) or "error" in msg or "result" not in msg:
            raise RpcError("rpc returned an error or no result")
        return msg["result"]


def _uint(hexstr):
    if isinstance(hexstr, str) and re.match(r"^0x[0-9a-f]{1,64}$", hexstr):
        return int(hexstr, 16)
    return None


def tx_outcome(rpc, chain: str, tx_hash: str, min_confirmations: int) -> dict:
    """What the CHAIN says. state: confirmed | failed | pending | unknown (never success by default)."""
    unknown = {"state": "unknown", "transfers": []}
    if chain not in ALLOWED_CHAINS:
        return {"state": "refused", "code": "UNKNOWN_CHAIN", "transfers": []}
    try:
        cid = _uint(rpc("eth_chainId", []))
        if cid != ALLOWED_CHAINS[chain]:
            return {"state": "refused", "code": "CHAIN_MISMATCH", "transfers": []}
        r = rpc("eth_getTransactionReceipt", [tx_hash])
        if r is None:
            return {"state": "pending", "transfers": []}
        if not isinstance(r, dict) or r.get("status") not in ("0x1", "0x0"):
            return unknown  # missing or odd status is UNKNOWN, never success
        if "transactionHash" in r and r["transactionHash"] != tx_hash:
            return unknown
        tip, blk = _uint(rpc("eth_blockNumber", [])), _uint(r.get("blockNumber"))
        if tip is None or blk is None:
            return unknown
        confirmations = tip - blk + 1
    except RpcError:
        return unknown
    if r["status"] == "0x0":
        return {"state": "failed", "transfers": [], "confirmations": confirmations}
    transfers = []
    logs = r.get("logs")
    for lg in logs if isinstance(logs, list) else []:
        if not isinstance(lg, dict) or lg.get("removed") is True:
            continue
        t = lg.get("topics")
        if not (isinstance(t, list) and len(t) == 3 and t[0] == TOPIC_TRANSFER and all(isinstance(x, str) for x in t)):
            continue
        amount = _uint(lg.get("data"))
        a_from, a_to, token = "0x" + t[1][26:], "0x" + t[2][26:], str(lg.get("address")).lower()
        zeros = "0x" + "0" * 24
        if (amount is None or not (t[1].startswith(zeros) and t[2].startswith(zeros) and len(t[1]) == 66 == len(t[2]))
                or not (ADDR.match(a_from) and ADDR.match(a_to) and ADDR.match(token))):
            continue
        transfers.append({"token": token, "from": a_from, "to": a_to, "amount": amount})
    state = "confirmed" if confirmations >= min_confirmations else "pending"
    return {"state": state, "transfers": transfers, "confirmations": confirmations}


def encode_erc20_transfer(to: str, amount: str) -> str:
    """transfer(address,uint256) calldata: a9059cbb + 32-byte address + 32-byte amount."""
    to = to.lower()
    if not (ADDR.match(to) and isinstance(amount, str) and AMOUNT.match(amount)):
        raise ValueError("bad transfer args")
    return "0x" + SEL_TRANSFER + to[2:].rjust(64, "0") + format(int(amount), "x").rjust(64, "0")


# ---- settlement --------------------------------------------------------------------------------

def settle_invoice(*, rpc, seller_key: SpineKey, invoice: dict, tx_hash: str, min_confirmations: int,
                   spent: SpentSet, deliverable: str, now: datetime) -> dict:
    """Seller-side settlement. Returns {ok:True, deliverable, receipt} or {ok:False, code, ...}.
    The invoice is re-verified against the seller's OWN key; the chain is read by us."""
    def no(code, **extra):
        return {"ok": False, "code": code, **extra}

    refusal = invoice_refusal(invoice, seller_key.pub_hex, now)
    if refusal:
        return no(refusal)
    if not (isinstance(tx_hash, str) and TXHASH.match(tx_hash)):
        return no("BAD_TX_HASH")
    if not (isinstance(min_confirmations, int) and not isinstance(min_confirmations, bool) and min_confirmations >= 1):
        return no("BAD_CONFIRMATIONS")
    if tx_hash in spent:
        return no("TX_ALREADY_USED")
    try:
        if deliverable_hash(deliverable) != invoice["deliverableHash"]:
            return no("DELIVERABLE_MISMATCH")
    except (TypeError, CanonError):
        return no("DELIVERABLE_MISMATCH")
    out = tx_outcome(rpc, invoice["chain"], tx_hash, min_confirmations)
    if out["state"] == "refused":
        return no(out["code"])
    if out["state"] != "confirmed":
        return no({"failed": "PAYMENT_FAILED", "unknown": "UNKNOWN_STATUS"}.get(out["state"], "NOT_CONFIRMED"),
                  state=out["state"])
    amount = int(invoice["amount"])
    hit = next((x for x in out["transfers"]
                if x["token"] == invoice["asset"] and x["to"] == invoice["payee"] and x["amount"] >= amount), None)
    if hit is None:
        return no("NO_MATCHING_TRANSFER")
    body = {
        "ver": RECEIPT_VER, "invoiceId": invoice["invoiceId"], "txHash": tx_hash, "payer": hit["from"],
        "amount": str(hit["amount"]), "deliverableHash": invoice["deliverableHash"], "chain": invoice["chain"],
        "finality": "simulated" if invoice["chain"] == "evm:31337" else "testnet",
        "releasedAt": iso_ms(now), "seller": invoice["seller"],
    }
    receipt = {**body, "sig": seller_key.sign(DOMAIN_RECEIPT, body)}
    if not spent.claim(tx_hash):  # atomic check-and-add; a racing second settlement loses here
        return no("TX_ALREADY_USED")
    return {"ok": True, "deliverable": deliverable, "receipt": receipt}
