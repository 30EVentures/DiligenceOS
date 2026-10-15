"""Seller-side settlement: refusal-first, against a fake RPC (odd answers) and the real mock chain over HTTP."""

import copy
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from diligenceos.engine import assemble_verdict
from diligenceos.flashy import seller
from diligenceos.flashy.spine import SpineKey
from diligenceos.receipt import issue_receipt, verify_receipt as verify_dos_receipt
from diligenceos.signing import Signer
from diligenceos.types import CheckStatus, Finding

from .helpers import VECTORS, MockChainProc, need_node

NOW = datetime(2026, 10, 14, 9, 0, 0, tzinfo=timezone.utc)
EXPIRES = "2026-10-14T12:00:00.000Z"
TOKEN = "0x" + "ab" * 20
PAYEE = "0x" + "08" * 20
PAYER = "0x" + "90" * 20
KEY = SpineKey.from_seed_hex("a1" * 32)
TXH = "0x" + "f1" * 32
TRANSFER_TOPIC = seller.TOPIC_TRANSFER


def real_deliverable(signer=None):
    """A real DiligenceOS receipt (issue_receipt), as the deliverable."""
    subject = {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}
    r = issue_receipt(subject=subject, inputs={"subject": subject},
                      result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]),
                      issued_at="2026-10-14T09:00:00+00:00", signer=signer or Signer.generate())
    return r, seller.deliverable_from_receipt(r)


def word(addr):
    return "0x" + "0" * 24 + addr[2:]


def good_receipt(amount=1_500_000, to=PAYEE, token=TOKEN, block=0x65, status="0x1"):
    return {"status": status, "blockNumber": hex(block), "logs": [
        {"address": token, "topics": [TRANSFER_TOPIC, word(PAYER), word(to)], "data": "0x" + format(amount, "064x")}]}


class FakeRpc:
    def __init__(self, receipt=None, chain_id="0x7a69", tip=0x66, raise_on=None):
        self.receipt, self.chain_id, self.tip, self.raise_on = receipt, chain_id, tip, raise_on

    def __call__(self, method, params):
        if self.raise_on == method:
            raise seller.RpcError("down")
        return {"eth_chainId": self.chain_id, "eth_blockNumber": hex(self.tip) if isinstance(self.tip, int) else self.tip,
                "eth_getTransactionReceipt": self.receipt}[method]


class SettleBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spent = seller.SpentSet(Path(self.tmp.name) / "spent.json")
        self.dos_receipt, self.deliv = real_deliverable()
        self.inv = seller.make_invoice(KEY, invoice_id="inv-1", seller="diligenceos", payee=PAYEE, chain="evm:31337",
                                       asset=TOKEN, amount="1500000", deliverable=self.deliv, expires_at=EXPIRES)

    def settle(self, rpc, **kw):
        args = dict(rpc=rpc, seller_key=KEY, invoice=self.inv, tx_hash=TXH, min_confirmations=1, spent=self.spent,
                    deliverable=self.deliv, now=NOW)
        args.update(kw)
        return seller.settle_invoice(**args)


class SettleRefusalTest(SettleBase):
    def refused(self, res, code):
        self.assertFalse(res["ok"], res)
        self.assertEqual(res["code"], code)
        self.assertNotIn("deliverable", res)
        self.assertNotIn("receipt", res)

    def test_underpayment(self):
        self.refused(self.settle(FakeRpc(good_receipt(amount=1_499_999))), "NO_MATCHING_TRANSFER")

    def test_payment_to_another_payee(self):
        self.refused(self.settle(FakeRpc(good_receipt(to="0x" + "77" * 20))), "NO_MATCHING_TRANSFER")

    def test_payment_in_another_asset(self):
        self.refused(self.settle(FakeRpc(good_receipt(token="0x" + "cd" * 20))), "NO_MATCHING_TRANSFER")

    def test_wrong_event_topic(self):
        r = good_receipt()
        r["logs"][0]["topics"][0] = "0x" + "11" * 32
        self.refused(self.settle(FakeRpc(r)), "NO_MATCHING_TRANSFER")

    def test_dirty_address_topic_not_accepted(self):
        r = good_receipt()
        r["logs"][0]["topics"][2] = "0x" + "ff" * 12 + PAYEE[2:]  # upper bytes not zero
        self.refused(self.settle(FakeRpc(r)), "NO_MATCHING_TRANSFER")

    def test_removed_log_ignored(self):
        r = good_receipt()
        r["logs"][0]["removed"] = True
        self.refused(self.settle(FakeRpc(r)), "NO_MATCHING_TRANSFER")

    def test_wrong_chain_id_on_endpoint(self):
        self.refused(self.settle(FakeRpc(good_receipt(), chain_id="0x1")), "CHAIN_MISMATCH")

    def test_unreadable_chain_id(self):
        for cid in (None, "31337", "0xZZ", 31337, "0x"):
            self.refused(self.settle(FakeRpc(good_receipt(), chain_id=cid)), "CHAIN_MISMATCH")

    def test_undefined_or_odd_status_is_unknown_never_success(self):
        r = good_receipt()
        del r["status"]
        self.refused(self.settle(FakeRpc(r)), "UNKNOWN_STATUS")
        for odd in ("0x2", "1", 1, True, None, "0X1", ""):
            self.refused(self.settle(FakeRpc(good_receipt(status=odd))), "UNKNOWN_STATUS")
        self.refused(self.settle(FakeRpc("garbage")), "UNKNOWN_STATUS")

    def test_failed_tx(self):
        self.refused(self.settle(FakeRpc(good_receipt(status="0x0"))), "PAYMENT_FAILED")

    def test_pending_tx(self):
        self.refused(self.settle(FakeRpc(None)), "NOT_CONFIRMED")

    def test_too_few_confirmations(self):
        self.refused(self.settle(FakeRpc(good_receipt(), tip=0x65), min_confirmations=2), "NOT_CONFIRMED")

    def test_unreadable_block_numbers(self):
        self.refused(self.settle(FakeRpc(good_receipt(), tip="nope")), "UNKNOWN_STATUS")
        r = good_receipt()
        r["blockNumber"] = None
        self.refused(self.settle(FakeRpc(r)), "UNKNOWN_STATUS")

    def test_receipt_for_a_different_tx_hash(self):
        r = good_receipt()
        r["transactionHash"] = "0x" + "00" * 32
        self.refused(self.settle(FakeRpc(r)), "UNKNOWN_STATUS")

    def test_rpc_down_is_unknown(self):
        for m in ("eth_getTransactionReceipt", "eth_blockNumber"):
            self.refused(self.settle(FakeRpc(good_receipt(), raise_on=m)), "UNKNOWN_STATUS")

    def test_rpc_down_at_chain_id_is_unknown(self):
        self.refused(self.settle(FakeRpc(good_receipt(), raise_on="eth_chainId")), "UNKNOWN_STATUS")

    def test_reused_tx_hash(self):
        self.assertTrue(self.settle(FakeRpc(good_receipt()))["ok"])
        self.refused(self.settle(FakeRpc(good_receipt())), "TX_ALREADY_USED")

    def test_reused_tx_hash_survives_restart_and_other_invoice(self):
        self.assertTrue(self.settle(FakeRpc(good_receipt()))["ok"])
        inv2 = seller.make_invoice(KEY, invoice_id="inv-2", seller="diligenceos", payee=PAYEE, chain="evm:31337",
                                   asset=TOKEN, amount="1000000", deliverable=self.deliv, expires_at=EXPIRES)
        again = seller.SpentSet(Path(self.tmp.name) / "spent.json")  # new object, same file
        self.refused(self.settle(FakeRpc(good_receipt()), invoice=inv2, spent=again), "TX_ALREADY_USED")

    def test_failed_settlements_do_not_burn_the_tx_hash(self):
        self.refused(self.settle(FakeRpc(good_receipt(amount=1))), "NO_MATCHING_TRANSFER")
        self.assertTrue(self.settle(FakeRpc(good_receipt()))["ok"])

    def test_expired_invoice(self):
        self.refused(self.settle(FakeRpc(good_receipt()), now=datetime(2026, 10, 14, 12, 0, 1, tzinfo=timezone.utc)), "EXPIRED")

    def test_invoice_signed_by_someone_else(self):
        other = SpineKey.from_seed_hex("33" * 32)
        forged = seller.make_invoice(other, invoice_id="x", seller="diligenceos", payee=PAYEE, chain="evm:31337",
                                     asset=TOKEN, amount="1", deliverable=self.deliv, expires_at=EXPIRES)
        self.refused(self.settle(FakeRpc(good_receipt()), invoice=forged), "UNPINNED_KEY")

    def test_tampered_invoice(self):
        inv = {**self.inv, "amount": "1"}
        self.refused(self.settle(FakeRpc(good_receipt()), invoice=inv), "BAD_SIGNATURE")

    def test_invoice_with_extra_field(self):
        self.refused(self.settle(FakeRpc(good_receipt()), invoice={**self.inv, "x": 1}), "INVOICE_SCHEMA")

    def test_non_canonical_amount_in_invoice(self):
        for amt in (1500000, 1.5, "1.5", "0150", "", "-1", "1e6"):
            self.refused(self.settle(FakeRpc(good_receipt()), invoice={**self.inv, "amount": amt}), "BAD_AMOUNT")

    def test_invoice_for_unlisted_chain(self):
        self.refused(self.settle(FakeRpc(good_receipt()), invoice={**self.inv, "chain": "evm:1"}), "UNKNOWN_CHAIN")

    def test_deliverable_swap(self):
        self.refused(self.settle(FakeRpc(good_receipt()), deliverable=self.deliv + " "), "DELIVERABLE_MISMATCH")
        self.refused(self.settle(FakeRpc(good_receipt()), deliverable={"d": 1}), "DELIVERABLE_MISMATCH")

    def test_bad_tx_hash(self):
        for bad in ("", "0x12", "0X" + "f1" * 32, "0x" + "F1" * 32, None, 5):
            self.refused(self.settle(FakeRpc(good_receipt()), tx_hash=bad), "BAD_TX_HASH")

    def test_bad_confirmation_count(self):
        for bad in (0, -1, True, 1.0, "1", None):
            self.refused(self.settle(FakeRpc(good_receipt()), min_confirmations=bad), "BAD_CONFIRMATIONS")

    def test_corrupt_spent_set_fails_closed(self):
        (Path(self.tmp.name) / "spent.json").write_text("{not json")
        with self.assertRaises(ValueError):
            self.settle(FakeRpc(good_receipt()))

    def test_chain_allowlist_is_code_level(self):
        self.assertEqual(seller.ALLOWED_CHAINS, {"evm:31337": 31337, "evm:84532": 84532, "evm:43113": 43113})
        out = seller.tx_outcome(FakeRpc(good_receipt()), "evm:1", TXH, 1)
        self.assertEqual(out["code"], "UNKNOWN_CHAIN")

    def test_rpc_client_is_loopback_only(self):
        for url in ("http://example.com", "https://127.0.0.1:1", "http://10.0.0.1", "file:///etc/passwd", "http://127.0.0.1.evil.com"):
            with self.assertRaises(ValueError, msg=url):
                seller.RpcClient(url)
        seller.RpcClient("http://127.0.0.1:1")

    def test_concurrent_claims_have_exactly_one_winner(self):
        wins = []
        sets = [seller.SpentSet(Path(self.tmp.name) / "race.json") for _ in range(8)]
        ts = [threading.Thread(target=lambda s=s: wins.append(s.claim(TXH))) for s in sets]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(wins.count(True), 1)


class SettleHappyPathTest(SettleBase):
    def test_release_and_signed_receipt(self):
        res = self.settle(FakeRpc(good_receipt(amount=2_000_000)), min_confirmations=2)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["deliverable"], self.deliv)
        r = res["receipt"]
        self.assertEqual(r["amount"], "2000000")  # what actually moved, as an integer string
        self.assertEqual(r["finality"], "simulated")
        self.assertEqual(r["payer"], PAYER)
        self.assertTrue(seller.verify_receipt(r, KEY.pub_hex))

    def test_receipt_verification_refusals(self):
        r = self.settle(FakeRpc(good_receipt()))["receipt"]
        self.assertFalse(seller.verify_receipt(r, SpineKey.from_seed_hex("33" * 32).pub_hex))
        self.assertFalse(seller.verify_receipt({**r, "amount": "1"}, KEY.pub_hex))
        self.assertFalse(seller.verify_receipt({**r, "finality": "final"}, KEY.pub_hex))
        self.assertFalse(seller.verify_receipt({**r, "extra": 1}, KEY.pub_hex))
        self.assertFalse(seller.verify_receipt(None, KEY.pub_hex))

    def test_deliverable_is_a_real_diligenceos_receipt(self):
        import json
        got = json.loads(self.deliv)
        self.assertEqual(got, self.dos_receipt)
        self.assertTrue(verify_dos_receipt(got).valid)

    def test_testnet_label_for_testnet_chain(self):
        inv = seller.make_invoice(KEY, invoice_id="t", seller="diligenceos", payee=PAYEE, chain="evm:84532", asset=TOKEN,
                                  amount="1", deliverable=self.deliv, expires_at=EXPIRES)
        res = self.settle(FakeRpc(good_receipt(amount=1), chain_id=hex(84532)), invoice=inv)
        self.assertEqual(res["receipt"]["finality"], "testnet")


class MockChainIntegrationTest(SettleBase):
    @classmethod
    def setUpClass(cls):
        cls.chain = MockChainProc()  # skips loudly if node / demo repo missing
        cls.rpc = seller.RpcClient(cls.chain.url)

    @classmethod
    def tearDownClass(cls):
        cls.chain.close()

    def pay(self, amount="1500000", to=PAYEE, payer=None, token=None, mint="50000000"):
        payer = payer or "0x" + "%040x" % (id(object()) & (2**64 - 1))
        self.rpc("dev_mint", [payer, mint])
        return self.rpc("dev_send", [{"from": payer, "to": token or TOKEN, "data": seller.encode_erc20_transfer(to, amount)}]), payer

    def test_calldata_encoding(self):
        d = seller.encode_erc20_transfer(PAYEE, "1500000")
        self.assertEqual(d, "0xa9059cbb" + "0" * 24 + "08" * 20 + format(1500000, "064x"))
        self.assertEqual(len(d), 2 + 8 + 128)

    def test_pay_then_settle_over_http(self):
        tx, payer = self.pay()
        res = self.settle(self.rpc, tx_hash=tx)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["receipt"]["payer"], payer)
        self.assertEqual(res["receipt"]["finality"], "simulated")
        self.assertTrue(seller.verify_receipt(res["receipt"], KEY.pub_hex))
        self.assertEqual(self.settle(self.rpc, tx_hash=tx)["code"], "TX_ALREADY_USED")

    def test_underpayment_refused(self):
        tx, _ = self.pay(amount="1499999")
        self.assertEqual(self.settle(self.rpc, tx_hash=tx)["code"], "NO_MATCHING_TRANSFER")

    def test_overpayment_accepted_and_receipt_states_actual_amount(self):
        tx, _ = self.pay(amount="1600000")
        res = self.settle(self.rpc, tx_hash=tx)
        self.assertTrue(res["ok"])
        self.assertEqual(res["receipt"]["amount"], "1600000")

    def test_wrong_payee_refused(self):
        tx, _ = self.pay(to="0x" + "99" * 20)
        self.assertEqual(self.settle(self.rpc, tx_hash=tx)["code"], "NO_MATCHING_TRANSFER")

    def test_reverted_tx_refused(self):
        self.rpc("dev_revertNext", [])
        tx, _ = self.pay()
        self.assertEqual(self.settle(self.rpc, tx_hash=tx)["code"], "PAYMENT_FAILED")

    def test_insufficient_balance_reverts_on_chain(self):
        tx, _ = self.pay(mint="1")
        self.assertEqual(self.settle(self.rpc, tx_hash=tx)["code"], "PAYMENT_FAILED")

    def test_unknown_tx_hash_is_pending_not_success(self):
        self.assertEqual(self.settle(self.rpc, tx_hash="0x" + "ee" * 32)["code"], "NOT_CONFIRMED")

    def test_confirmations_then_mine(self):
        tx, _ = self.pay()
        self.assertEqual(self.settle(self.rpc, tx_hash=tx, min_confirmations=3)["code"], "NOT_CONFIRMED")
        self.rpc("dev_mine", [2])
        self.assertTrue(self.settle(self.rpc, tx_hash=tx, min_confirmations=3)["ok"])

    def test_invoice_for_testnet_label_refused_on_mock_endpoint(self):
        inv = seller.make_invoice(KEY, invoice_id="w", seller="diligenceos", payee=PAYEE, chain="evm:84532", asset=TOKEN,
                                  amount="1500000", deliverable=self.deliv, expires_at=EXPIRES)
        tx, _ = self.pay()
        self.assertEqual(self.settle(self.rpc, tx_hash=tx, invoice=inv)["code"], "CHAIN_MISMATCH")

    def test_payment_in_wrong_token_contract_reverts(self):
        tx, _ = self.pay(token="0x" + "cd" * 20)
        self.assertEqual(self.settle(self.rpc, tx_hash=tx)["code"], "PAYMENT_FAILED")

    def test_node_verifies_python_invoice_and_receipt(self):
        need_node()
        from .helpers import node_json
        tx, _ = self.pay()
        res = self.settle(self.rpc, tx_hash=tx)
        out = node_json(
            "const { verifyInvoice, verifyReceipt } = await D('src/invoice.js');"
            "console.log(JSON.stringify({ inv: verifyInvoice(IN.inv, IN.pub, new Date(IN.now)), rcpt: verifyReceipt(IN.rcpt, IN.pub),"
            " badInv: verifyInvoice({ ...IN.inv, amount: '1' }, IN.pub, new Date(IN.now)), badRcpt: verifyReceipt({ ...IN.rcpt, amount: '1' }, IN.pub) }))",
            {"inv": self.inv, "rcpt": res["receipt"], "pub": KEY.pub_hex, "now": NOW.isoformat()})
        self.assertEqual(out, {"inv": True, "rcpt": True, "badInv": False, "badRcpt": False})


if __name__ == "__main__":
    unittest.main()
