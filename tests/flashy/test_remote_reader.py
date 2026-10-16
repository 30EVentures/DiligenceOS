"""Reading a real testnet is possible but only on purpose: off by default, https only, read-only by construction, and the
chain id the endpoint reports must be an allowlisted testnet (so a mainnet endpoint is refused whatever its URL says).
Nothing here makes a request: the transport is replaced by a fake."""

import io
import json
import unittest
import urllib.error

from diligenceos.flashy import seller
from diligenceos.flashy.seller import RpcClient, RpcError, tx_outcome

KEY = "sekret-api-key-123"          # an RPC provider often puts the key in the URL: it must never be printed


class FakeOpener:
    def __init__(self, answers=None, exc=None):
        self.answers, self.exc, self.calls = answers or {}, exc, []

    def open(self, req, timeout=None):
        body = json.loads(req.data)
        self.calls.append((req.full_url, body["method"], timeout))
        if self.exc:
            raise self.exc
        out = {"jsonrpc": "2.0", "id": body["id"], "result": self.answers.get(body["method"])}
        return io.BytesIO(json.dumps(out).encode())


def remote(url=f"https://rpc.example.org/v1/{KEY}", **kw):
    client = RpcClient(url, allow_remote=True, **kw)
    return client


class RemoteIsOffByDefault(unittest.TestCase):
    def test_a_remote_url_is_refused_unless_asked_for(self):
        for url in ("https://rpc.example.org", "https://rpc.example.org/v1/abc", "http://rpc.example.org", "http://10.0.0.1:8545"):
            with self.assertRaises(ValueError, msg=url):
                RpcClient(url)

    def test_the_loopback_behaviour_is_unchanged(self):
        RpcClient("http://127.0.0.1:8545")
        RpcClient("http://localhost:8545")
        with self.assertRaises(ValueError):
            RpcClient("https://127.0.0.1:8545")


class RemoteIsNarrow(unittest.TestCase):
    def test_even_when_allowed_only_https_without_credentials_in_the_authority(self):
        for url in ("http://rpc.example.org", "ftp://rpc.example.org", "file:///etc/passwd", "https://user:pass@rpc.example.org", "https://", "", "rpc.example.org",
                    "https://rpc.example.org#frag", "javascript:alert(1)", None, 5):
            with self.assertRaises(ValueError, msg=url):
                RpcClient(url, allow_remote=True)

    def test_allow_remote_must_be_exactly_true(self):
        for flag in ("yes", 1, "true", [True]):
            with self.assertRaises(ValueError, msg=flag):
                RpcClient("https://rpc.example.org", allow_remote=flag)

    def test_it_reads_and_never_writes(self):
        c = remote()
        c._opener = FakeOpener({"eth_chainId": "0x14a34"})
        self.assertEqual(c("eth_chainId", []), "0x14a34")
        for method in ("eth_sendRawTransaction", "eth_sendTransaction", "personal_sign", "eth_sign", "eth_accounts", "debug_traceTransaction", "", None, 5, "eth_chainId ", "ETH_CHAINID"):
            with self.assertRaises(RpcError, msg=repr(method)):
                c(method, [])
        self.assertEqual(len(c._opener.calls), 1, "a refused method must not reach the network")

    def test_only_the_three_reads_the_seller_needs_are_allowed(self):
        c = remote()
        c._opener = FakeOpener({"eth_chainId": "0x1", "eth_blockNumber": "0x1", "eth_getTransactionReceipt": None})
        for method in ("eth_chainId", "eth_blockNumber", "eth_getTransactionReceipt"):
            c(method, ["0x" + "ab" * 32] if method == "eth_getTransactionReceipt" else [])
        for method in ("eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode"):
            with self.assertRaises(RpcError):
                c(method, [])

    def test_the_url_never_appears_in_an_error_or_a_representation(self):
        c = remote()
        for exc in (urllib.error.URLError(f"cannot reach https://rpc.example.org/v1/{KEY}"), OSError(f"https://rpc.example.org/v1/{KEY}"), TimeoutError()):
            c._opener = FakeOpener(exc=exc)
            with self.assertRaises(RpcError) as caught:
                c("eth_chainId", [])
            self.assertNotIn(KEY, str(caught.exception) + repr(caught.exception))
        self.assertNotIn(KEY, repr(c) + str(c))

    def test_a_redirect_is_never_followed(self):
        c = remote()
        handlers = [type(h).__name__ for h in c._opener.handlers]
        self.assertNotIn("HTTPRedirectHandler", handlers)
        c._opener = FakeOpener(exc=urllib.error.HTTPError("https://x", 302, "Found", {}, None))
        with self.assertRaises(RpcError):
            c("eth_chainId", [])

    def test_a_bad_answer_is_an_error_not_a_value(self):
        c = remote()
        for raw in (b"not json", b"[]", b'{"error": {"code": -1}}', b'{"jsonrpc": "2.0", "id": 1}', b""):
            class Raw:
                def open(self, req, timeout=None, raw=raw):
                    return io.BytesIO(raw)
            c._opener = Raw()
            with self.assertRaises(RpcError):
                c("eth_chainId", [])

    def test_a_huge_answer_is_cut_off(self):
        c = remote()

        class Big:
            def open(self, req, timeout=None):
                return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":"' + b"a" * 3_000_000 + b'"}')
        c._opener = Big()
        with self.assertRaises(RpcError):
            c("eth_chainId", [])


class TheChainIdIsStillTheGate(unittest.TestCase):
    """A mainnet endpoint is refused by what it says it is, not by what it is called."""

    def reader(self, chain_id):
        c = remote()
        c._opener = FakeOpener({"eth_chainId": chain_id, "eth_blockNumber": "0x20", "eth_getTransactionReceipt": None})
        return c

    def test_mainnet_and_unknown_chains_are_refused(self):
        for chain_id in ("0x1", "0xa", "0x2105", "0x89", "0x0", "84532", None, "0x14a35"):
            out = tx_outcome(self.reader(chain_id), "evm:84532", "0x" + "ab" * 32, 1)
            self.assertEqual(out["state"], "refused", chain_id)

    def test_an_allowlisted_testnet_is_read(self):
        out = tx_outcome(self.reader("0x14a34"), "evm:84532", "0x" + "ab" * 32, 1)
        self.assertEqual(out["state"], "pending")

    def test_a_chain_label_off_the_allowlist_is_refused_before_any_request(self):
        c = self.reader("0x1")
        self.assertEqual(tx_outcome(c, "evm:1", "0x" + "ab" * 32, 1)["state"], "refused")
        self.assertEqual(c._opener.calls, [])


if __name__ == "__main__":
    unittest.main()
