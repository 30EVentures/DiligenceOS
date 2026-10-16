#!/usr/bin/env python3
"""Builds tests/flashy/fixtures/refusal-corpus.json: the refusal cases that BOTH the JS spine and the Python
adapter must answer the same way. Generated (signed fixtures cannot be written by hand): re-run, do not edit.

    python3 tests/flashy/build_refusal_corpus.py

`expect` is what SPINE.md and common sense require. A case where an implementation is known to answer
differently carries `gap.<impl>` (what it actually answers today) and a reason; the parity test asserts the
gap exactly, so it fails the day the gap is closed (remove the marker then) and never hides a new one.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from diligenceos.flashy.seller import TOPIC_TRANSFER  # noqa: E402
from diligenceos.flashy.spine import DOMAIN_INVOICE, DOMAIN_RECEIPT, SpineKey  # noqa: E402

OUT = Path(__file__).parent / "fixtures" / "refusal-corpus.json"
SELLER = SpineKey.from_seed_hex("a1" * 32)
OTHER = SpineKey.from_seed_hex("b2" * 32)
NOW = "2026-10-14T12:00:00.000Z"
NOW_MS = int(datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1000)
PAYEE, ASSET, PAYER = "0x" + "2b" * 20, "0x" + "ab" * 20, "0x" + "1c" * 20

# ---- invoices ----------------------------------------------------------------------------------

BODY = {
    "ver": "30e-demo-invoice/1", "invoiceId": "inv-1", "seller": "demo-seller", "payee": PAYEE, "chain": "evm:31337",
    "asset": ASSET, "amount": "1000", "deliverableHash": "ab" * 32, "expiresAt": "2026-10-15T12:00:00.000Z", "sellerKey": SELLER.pub_hex,
}


def signed(body, key=SELLER, domain=DOMAIN_INVOICE):
    return {**body, "sig": key.sign(domain, body)}


def inv_case(cid, note, invoice, valid, pinned=SELLER.pub_hex, gap=None):
    c = {"id": cid, "note": note, "invoice": invoice, "pinned": pinned, "now_ms": NOW_MS, "expect": {"valid": valid}}
    if gap:
        c["gap"] = gap
    return c


def gap(impl, answer, why):
    return {impl: answer, "why": why}


def invoices():
    cases = [inv_case("inv-valid", "A well-formed invoice.", signed(BODY), True)]
    for chain in ("evm:84532", "evm:43113", "evm:31337"):
        cases.append(inv_case(f"inv-valid-{chain[4:]}", "Every allowlisted chain is accepted.", signed({**BODY, "chain": chain}), True))
    cases.append(inv_case("inv-valid-huge-amount", "A very large integer string is still an integer string.", signed({**BODY, "amount": "1" + "0" * 40}), True))

    # closed schema
    cases.append(inv_case("inv-extra-field-signed", "An unknown field, correctly signed: closed schemas refuse it.", signed({**BODY, "memo": "x"}), False))
    cases.append(inv_case("inv-extra-field-unsigned", "An unknown field added after signing.", {**signed(BODY), "memo": "x"}, False))
    for key in [*BODY, "sig"]:
        doc = signed(BODY)
        del doc[key]
        cases.append(inv_case(f"inv-missing-{key}", f"The {key} field is missing.", doc, False))
    for label, doc in (("array", []), ("string", "inv"), ("null", None), ("number", 5)):
        cases.append(inv_case(f"inv-not-an-object-{label}", f"The invoice is a {label}.", doc, False))

    # amount: a canonical non-negative integer string, and not zero (nobody invoices nothing)
    for label, amount in (("leading-zero", "01"), ("double-zero", "00"), ("negative", "-1"), ("plus", "+1"), ("decimal", "1.5"), ("exponent", "1e3"),
                          ("leading-space", " 1"), ("trailing-space", "1 "), ("empty", ""), ("hex", "0x10"), ("trailing-newline", "1\n"),
                          ("arabic-indic-digits", "١٢٣"), ("fullwidth-digits", "１２")):
        cases.append(inv_case(f"inv-amount-{label}", f"Amount {amount!r} is not a canonical integer string.", signed({**BODY, "amount": amount}), False))
    for label, amount in (("number", 1000), ("null", None), ("list", ["1"]), ("bool", True)):
        cases.append(inv_case(f"inv-amount-type-{label}", f"Amount is a {label}, not a string.", signed({**BODY, "amount": amount}), False))
    cases.append(inv_case("inv-amount-zero", "A zero amount: a valid integer string, but an invoice for nothing.", signed({**BODY, "amount": "0"}), False,
                          gap=gap("js", {"valid": True}, "JS verifyInvoice allows '0' (the regex does); Python refuses BAD_AMOUNT")))

    # chain allowlist
    for label, chain in (("unlisted", "evm:1"), ("mainnet", "evm:8453"), ("trailing-space", "evm:84532 "), ("upper", "EVM:84532"), ("empty", ""),
                         ("number", 84532), ("null", None)):
        cases.append(inv_case(f"inv-chain-{label}", f"Chain {chain!r} is not on the testnet allowlist.", signed({**BODY, "chain": chain}), False))

    # version, key, signature, domain
    cases.append(inv_case("inv-wrong-version", "ver is not 30e-demo-invoice/1.", signed({**BODY, "ver": "30e-demo-invoice/2"}), False))
    cases.append(inv_case("inv-key-not-pinned", "Signed by a key the verifier did not pin.", signed({**BODY, "sellerKey": OTHER.pub_hex}, OTHER), False))
    cases.append(inv_case("inv-wrong-pin", "The pinned key is another key.", signed(BODY), False, pinned=OTHER.pub_hex))
    for label, pin in (("none", None), ("uppercase", SELLER.pub_hex.upper()), ("short", SELLER.pub_hex[:-2]), ("empty", "")):
        cases.append(inv_case(f"inv-pin-{label}", "A pin that is not 64 lowercase hex.", signed(BODY), False, pinned=pin))
    good = signed(BODY)
    flipped = good["sig"][:-1] + ("0" if good["sig"][-1] != "0" else "1")
    for label, sig in (("tampered", flipped), ("uppercase", good["sig"].upper()), ("short", good["sig"][:-2]), ("long", good["sig"] + "00"),
                       ("not-hex", "zz" * 64), ("empty", ""), ("null", None), ("number", 5), ("other-key", OTHER.sign(DOMAIN_INVOICE, BODY))):
        cases.append(inv_case(f"inv-sig-{label}", "A bad signature.", {**BODY, "sig": sig}, False))
    cases.append(inv_case("inv-wrong-domain", "Signed under the receipt domain.", signed(BODY, domain=DOMAIN_RECEIPT), False))
    cases.append(inv_case("inv-field-tampered", "A field changed after signing.", {**good, "amount": "9999"}, False))

    # time
    for label, exp in (("past", "2026-10-13T12:00:00.000Z"), ("exactly-now", NOW), ("one-ms-ago", "2026-10-14T11:59:59.999Z")):
        cases.append(inv_case(f"inv-expired-{label}", "Not strictly in the future.", signed({**BODY, "expiresAt": exp}), False))
    cases.append(inv_case("inv-expiry-without-milliseconds", "A UTC 'Z' timestamp without milliseconds is unambiguous and accepted.", signed({**BODY, "expiresAt": "2030-01-01T00:00:00Z"}), True))
    cases.append(inv_case("inv-expires-one-ms-ahead", "One millisecond ahead is still valid.", signed({**BODY, "expiresAt": "2026-10-14T12:00:00.001Z"}), True))
    for label, exp in (("word", "tomorrow"), ("empty", ""), ("number", 4102444800000), ("null", None)):
        cases.append(inv_case(f"inv-expiry-unreadable-{label}", "expiresAt is not a timestamp.", signed({**BODY, "expiresAt": exp}), False))
    for label, exp in (("year-only", "2030"), ("date-only", "2030-01-01"), ("no-zone", "2030-01-01T00:00:00"), ("offset", "2030-01-01T00:00:00.000+00:00"),
                       ("english", "Jan 1 2030")):
        cases.append(inv_case(f"inv-expiry-loose-{label}", f"{exp!r} is not the spine's timestamp form (UTC, milliseconds, Z).", signed({**BODY, "expiresAt": exp}), False,
                              gap=gap("js", {"valid": True}, "JS verifyInvoice uses Date.parse, which accepts many forms; Python accepts only YYYY-MM-DDTHH:MM:SS.mmmZ")))

    # payee / asset shape
    for label, field, value in (("payee-uppercase", "payee", "0x" + PAYEE[2:].upper()), ("payee-short", "payee", "0x1234"), ("payee-null", "payee", None),
                                ("asset-uppercase", "asset", "0x" + ASSET[2:].upper()), ("asset-short", "asset", "0xabc"), ("asset-number", "asset", 5),
                                ("payee-trailing-newline", "payee", PAYEE + "\n")):
        cases.append(inv_case(f"inv-{label}", f"{field} is not 0x + 40 lowercase hex.", signed({**BODY, field: value}), False,
                              gap=gap("js", {"valid": True}, "JS verifyInvoice does not check the shape of payee or asset (it matches transfers by string equality later)")))
    return cases


# ---- transaction outcomes ----------------------------------------------------------------------

def topic(addr):
    return "0x" + "0" * 24 + addr[2:]


def word(n):
    return "0x" + format(n, "064x")


def log(**over):
    base = {"address": ASSET, "topics": [TOPIC_TRANSFER, topic(PAYER), topic(PAYEE)], "data": word(1000)}
    base.update(over)
    return base


def receipt(**over):
    base = {"status": "0x1", "blockNumber": "0x10", "transactionHash": "0x" + "cd" * 32, "logs": [log()]}
    base.update(over)
    return base


HASH = "0x" + "cd" * 32
TRANSFER = {"token": ASSET, "from": PAYER, "to": PAYEE, "amount": "1000"}


def tx_case(cid, note, state, transfers=(), rcpt=None, chain="evm:31337", chain_id="0x7a69", tip="0x20", min_conf=1, tx_hash=HASH, throws=(), gap=None, no_receipt=False):
    c = {"id": cid, "note": note, "chain": chain, "txHash": tx_hash, "minConfirmations": min_conf,
         "rpc": {"eth_chainId": chain_id, "eth_blockNumber": tip, "eth_getTransactionReceipt": None if no_receipt else (receipt() if rcpt is None else rcpt)},
         "throws": list(throws), "expect": {"state": state, "transfers": list(transfers)}}
    if gap:
        c["gap"] = gap
    return c


def omit(d, key):
    return {k: v for k, v in d.items() if k != key}


def txs():
    cs = [tx_case("tx-confirmed", "A confirmed transfer of the invoiced asset.", "confirmed", [TRANSFER]),
          tx_case("tx-pending-not-enough-confirmations", "17 confirmations are not 100.", "pending", [TRANSFER], min_conf=100),
          tx_case("tx-null-receipt-is-pending", "No receipt yet.", "pending", no_receipt=True),
          tx_case("tx-failed", "status 0x0: failed, and no transfers count.", "failed", rcpt=receipt(status="0x0"))]

    for label, status in (("missing", "<missing>"), ("null", None), ("zero-x-two", "0x2"), ("padded", "0x01"), ("number", 1), ("true", True), ("empty", ""), ("upper", "0X1")):
        r = omit(receipt(), "status") if status == "<missing>" else receipt(status=status)
        cs.append(tx_case(f"tx-status-{label}", "A missing or odd status is UNKNOWN, never success.", "unknown", rcpt=r))
    cs.append(tx_case("tx-receipt-not-an-object", "The receipt is a string.", "unknown", rcpt="0x1"))
    cs.append(tx_case("tx-chain-id-mismatch", "The endpoint is another chain.", "refused", chain_id="0x1"))
    cs.append(tx_case("tx-chain-id-unreadable", "eth_chainId does not decode.", "refused", chain_id="31337"))
    cs.append(tx_case("tx-chain-not-allowlisted", "The invoice chain is not on the allowlist.", "refused", chain="evm:1"))
    for label, blk in (("missing", "<missing>"), ("not-hex", "16"), ("null", None)):
        r = omit(receipt(), "blockNumber") if blk == "<missing>" else receipt(blockNumber=blk)
        cs.append(tx_case(f"tx-block-number-{label}", "The receipt's block number is unreadable.", "unknown", rcpt=r))
    cs.append(tx_case("tx-tip-unreadable", "The chain tip does not decode.", "unknown", tip="latest",
                      gap=gap("js", {"state": "THREW", "transfers": []}, "JS txOutcome throws on an unreadable tip instead of returning unknown")))
    cs.append(tx_case("tx-rpc-error-on-receipt", "The endpoint errors on getTransactionReceipt.", "unknown", throws=["eth_getTransactionReceipt"]))

    # Transfer log parsing
    cs.append(tx_case("tx-topic-from-upper-bytes", "The 'from' topic has non-zero bytes above the address.", "confirmed",
                      rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, "0x" + "00" * 11 + "01" + PAYER[2:], topic(PAYEE)])])))
    cs.append(tx_case("tx-topic-to-upper-bytes", "The 'to' topic has non-zero bytes above the address.", "confirmed",
                      rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, topic(PAYER), "0x" + "ff" * 12 + PAYEE[2:]])])))
    cs.append(tx_case("tx-topic-uppercase-hex", "A topic written with uppercase hex is not the canonical form.", "confirmed",
                      rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, topic(PAYER), "0x" + "0" * 24 + PAYEE[2:].upper()])])))
    cs.append(tx_case("tx-topic-too-short", "A topic that is not 32 bytes.", "confirmed", rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, topic(PAYER), "0x" + PAYEE[2:]])])))
    cs.append(tx_case("tx-topic-too-long", "A topic longer than 32 bytes.", "confirmed", rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, topic(PAYER), topic(PAYEE) + "00"])])))
    cs.append(tx_case("tx-four-topics", "An ERC-721 style Transfer has four topics: not this event.", "confirmed",
                      rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, topic(PAYER), topic(PAYEE), word(7)])])))
    cs.append(tx_case("tx-two-topics", "Too few topics.", "confirmed", rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, topic(PAYER)])])))
    cs.append(tx_case("tx-other-event", "A different event signature.", "confirmed", rcpt=receipt(logs=[log(topics=["0x" + "ee" * 32, topic(PAYER), topic(PAYEE)])])))
    cs.append(tx_case("tx-topic-not-strings", "Topics that are not strings.", "confirmed", rcpt=receipt(logs=[log(topics=[TOPIC_TRANSFER, 1, 2])])))
    cs.append(tx_case("tx-topics-not-a-list", "topics is a string.", "confirmed", rcpt=receipt(logs=[log(topics="x")])))
    for label, data in (("empty-0x", "0x"), ("63-hex-digits", word(1000)[:-1]), ("65-bytes", "0x" + "00" * 31 + "0a" + "00"), ("not-hex", "0xzz"), ("uppercase", "0x" + "0" * 61 + "3E8".upper()),
                        ("number", 1000), ("null", None)):
        g = None
        if label == "63-hex-digits":
            g = gap("js", {"state": "confirmed", "transfers": [dict(TRANSFER, amount=str(int(data, 16)))]},
                    "JS decodeUint accepts any 1-64 hex digits for log data; Transfer data is exactly one 32-byte word")
        cs.append(tx_case(f"tx-data-{label}", "Transfer data that is not one canonical 32-byte unsigned integer.", "confirmed", rcpt=receipt(logs=[log(data=data)]), gap=g))
    cs.append(tx_case("tx-data-max-uint256", "The largest uint256 is still a number.", "confirmed",
                      [dict(TRANSFER, amount=str(2**256 - 1))], rcpt=receipt(logs=[log(data="0x" + "ff" * 32)])))
    cs.append(tx_case("tx-log-address-missing", "A log with no emitting address.", "confirmed", rcpt=receipt(logs=[omit(log(), "address")]),
                      gap=gap("js", {"state": "confirmed", "transfers": [{"token": None, "from": PAYER, "to": PAYEE, "amount": "1000"}]},
                              "JS pushes a transfer whose token is undefined instead of dropping the log")))
    cs.append(tx_case("tx-log-address-malformed", "The emitting address is not 0x + 40 hex.", "confirmed", rcpt=receipt(logs=[log(address="0x1234")]),
                      gap=gap("js", {"state": "confirmed", "transfers": [{"token": "0x1234", "from": PAYER, "to": PAYEE, "amount": "1000"}]},
                              "JS does not check the emitting address's shape")))
    cs.append(tx_case("tx-log-removed", "A log flagged removed (reorged out) must not count.", "confirmed", rcpt=receipt(logs=[log(removed=True)]),
                      gap=gap("js", {"state": "confirmed", "transfers": [TRANSFER]}, "JS ignores the removed flag")))
    cs.append(tx_case("tx-logs-not-a-list", "logs is a string.", "confirmed", rcpt=receipt(logs="x")))
    cs.append(tx_case("tx-logs-missing", "No logs field.", "confirmed", rcpt=omit(receipt(), "logs")))
    cs.append(tx_case("tx-two-transfers-one-bad", "One good transfer and one with bad upper bytes: only the good one counts.", "confirmed", [TRANSFER],
                      rcpt=receipt(logs=[log(), log(topics=[TOPIC_TRANSFER, "0x" + "00" * 11 + "01" + PAYER[2:], topic(PAYEE)], data=word(5))])))
    cs.append(tx_case("tx-token-case-is-folded", "The emitting address may be written in mixed case; it is compared lowercase.", "confirmed", [TRANSFER],
                      rcpt=receipt(logs=[log(address=ASSET[:2] + ASSET[2:].upper())])))

    # transaction hash equality
    cs.append(tx_case("tx-hash-echo-different", "The receipt echoes a different transaction hash.", "unknown", rcpt=receipt(transactionHash="0x" + "ef" * 32)))
    cs.append(tx_case("tx-hash-echo-same-case-folded", "The same hash with different letter case is the same hash.", "confirmed", [TRANSFER],
                      rcpt=receipt(transactionHash="0x" + "CD" * 32)))
    cs.append(tx_case("tx-hash-requested-uppercase", "The hash was requested in uppercase and echoed in lowercase.", "confirmed", [TRANSFER], tx_hash="0x" + "CD" * 32))
    cs.append(tx_case("tx-hash-echo-absent", "No echoed hash: nothing to compare, and the chain was still asked for this hash.", "confirmed", [TRANSFER], rcpt=omit(receipt(), "transactionHash")))
    for label, echo in (("number", 5), ("null", None), ("list", ["0x" + "cd" * 32]), ("empty", "")):
        cs.append(tx_case(f"tx-hash-echo-{label}", "An echoed hash that is not a hash string: fail closed.", "unknown", rcpt=receipt(transactionHash=echo),
                          gap=None if isinstance(echo, str) else gap("js", {"state": "confirmed", "transfers": [TRANSFER]}, "JS ignores an echoed hash that is not a string")))
    return cs


def build():
    return {
        "corpus": "flashy-refusal/1",
        "about": "Refusal cases for the invoice verifier and the transaction-outcome reader. Both the JS spine and the Python adapter answer every case; "
                 "`expect` is the required answer, `gap` records a known difference exactly.",
        "sets": [{"name": "invoice", "now": NOW, "cases": invoices()}, {"name": "tx", "cases": txs()}],
    }


if __name__ == "__main__":
    OUT.write_text(json.dumps(build(), indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    c = build()
    print(f"wrote {OUT.name}: {sum(len(s['cases']) for s in c['sets'])} cases ({len(c['sets'][0]['cases'])} invoice, {len(c['sets'][1]['cases'])} tx)")
