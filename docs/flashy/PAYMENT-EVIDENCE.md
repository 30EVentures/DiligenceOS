# Payment evidence: a signed record that a payment was authorized and made

`diligenceos/flashy/payment_evidence.py`. Built and tested against the demo spine (stand-in plane, signer, MOCK chain); nothing here moved money or touched a real network.

## What the record binds
| Question | Bound by | How a third party checks it |
|---|---|---|
| How much, which asset, which chain | `amount` (integer string), `asset`, `chain` | the plane's signed authorization and the chain's transfer log must both say exactly this |
| Who paid | `payer_address` (read from the chain's transfer), `agent_key` | `payer_registry_checked` says whether it was compared with the verifier's own registry; without one, the link between the agent key and the wallet is the plane's word, not proven here |
| Who was paid | `payee_address` | authorization destination = request destination = transfer recipient (= invoice payee, if an invoice is named) |
| Why | `purpose_digest`, `purpose_length` (never the text) | digest of the purpose in the agent's signed request, also in the plane's log |
| Under what authority | `grant_chain_digest`, `grant_depth`, `grant_root_key`, `grant_leaf_id`, `agent_key` | every link signed by its issuer, only narrowing, valid when used; rooted at a key the verifier pinned; the leaf allows this asset, destination, kind, chain and amount |
| Who authorized | `authorization_id`, `authorization_digest`, `authorized_how`, `approver_key`, `plane`, `plane_key` | plane signature under a pinned key; for a human approval, an approval entry from a pinned approver before the authorization |
| What the log says | `log_seq_*`, `log_head_hash`, `log_entry_count`, `plane_log_key` | the log verifies under a pinned key; request, authorization and outcome entries each exist once, agree with the documents and come in order; the head and count can be pinned by a later witness |
| That it was made | `tx_hash`, `confirmations`, `finality` | read from the chain endpoint: allowlisted chain id, confirmed with enough confirmations, exactly one matching transfer. `finality` is `simulated` on the mock chain and `testnet` on a testnet; never anything stronger |
| Optional | `invoice_id`, `diligence_receipt_id` | a signed invoice naming the same payee and amount; a fresh PROCEED receipt from DiligenceOS |

## What it does not say
It approves nothing and holds no spending authority. It does not judge the plane's decision (only that the plane's records agree with each other and with the chain), cannot know a grant was revoked afterwards (revocation lives in the plane), does not show the payee is who they claim, and reads a mock chain in the demo. `plane: stand-in` is recorded honestly; Flashy's real plane is closed, so its logs cannot be checked yet.

## Checking it (offline)
```
python -m diligenceos verify-evidence evidence.json --pin <issuer id>
python -m diligenceos recheck-evidence evidence.json --pin <issuer id> --request request.json --authorization authorization.json \
    --plane-log plane-log.json --pins pins.json --chain chain.json
python3 scripts/demo_payment_evidence.py OUT_DIR       # makes all of these from one demo-spine payment, with throwaway keys
```
Refusals are closed codes: `BAD_INPUT REQUEST_INVALID AUTHORIZATION_INVALID AUTH_REQUEST_MISMATCH GRANT_CHAIN_INVALID GRANT_DOES_NOT_ALLOW LOG_INVALID LOG_ENTRY_MISSING LOG_MISMATCH OUTCOME_NOT_CONFIRMED APPROVAL_INVALID CHAIN_REFUSED CHAIN_NOT_CONFIRMED TRANSFER_MISMATCH PAYER_MISMATCH DILIGENCE_RECEIPT_REFUSED INVOICE_REFUSED`.

## Reading a real testnet
`RpcClient(url, allow_remote=True)` accepts an https endpoint, read-only (three methods, no redirects, answer capped, URL never printed). The chain id the endpoint reports must be an allowlisted testnet, so a mainnet endpoint is refused. It is off by default and nothing calls it; no testnet run has been done.
