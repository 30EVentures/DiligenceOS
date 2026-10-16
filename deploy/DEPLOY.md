# Putting DiligenceOS where other agents can reach it

Nothing here deploys anything. It is the checklist for the person who does, in the order that matters. [Nothing below was run against a real host.]

## The rules the code depends on
1. **One process, one thread.** The signed log, the spend ledger and the replay-protection nonces live in one process and are not locked. Two workers or two servers on one data directory would fork the log (both then refuse to start) and could drop a revocation. Use a supervisor that restarts the one process; never scale it out.
2. **A disk that survives restarts** for the data directory (`DILIGENCEOS_DATA_PATH`'s folder): `store.json`, `receipts.jsonl`, `issuer.key`, and (after `refresh-sanctions`) `sdn.csv` + `sdn.meta.json`.
3. **`issuer.key` is the identity.** Back it up as a secret, outside the repo and outside any image. Lose it and every old receipt becomes unverifiable; leak it and anyone can sign as you.
4. **Bind to loopback and put a TLS proxy in front.** The server speaks plain HTTP. With `DILIGENCEOS_HOST` anything but loopback it now treats the verdict endpoint as closed (signed callers only) unless you set `DILIGENCEOS_VERDICT_AUTH=open` yourself, and it warns if you do.
5. **The proxy does the rest:** read and write timeouts (the server has none), a body limit of 1 MiB, a request rate limit, and `Access-Control-Allow-Origin: *` only on the `.well-known` files.

## Environment
| Variable | Meaning |
|---|---|
| `DILIGENCEOS_DATA_PATH` | where `store.json` lives (the other files sit beside it) |
| `DILIGENCEOS_HOST`, `DILIGENCEOS_PORT` | bind address (default `127.0.0.1:8000`) |
| `DILIGENCEOS_BEHIND_TLS_PROXY=1` | says a proxy terminates TLS (silences the startup warning; it is a statement, not a check) |
| `DILIGENCEOS_VERDICT_AUTH` | `signed` (the default off loopback) or `open` |
| `DILIGENCEOS_ADMIN_TOKEN` | enables `/data` writes; unset means they are refused |
| `DILIGENCEOS_RECEIPT_TTL_SECONDS` | receipt lifetime, 0 to one year (default 24 h) |
| `DILIGENCEOS_WITNESSES` | issuer ids allowed to submit cosignatures |
| `FLASHYOS_ORG_ID`, `FLASHYOS_AGENT_TOKEN`, `FLASHYOS_AGENT_NAME` | presence on the mesh; all three or nothing is sent. Secrets: environment or a secret store only |

## Order of work
1. Run once on the target host with loopback only; `curl localhost:8000/v1/issuer`. That is the key you will publish.
2. `python -m diligenceos refresh-sanctions` (a person, once; needs network). Without it every `sanctions: pass` says no official list is loaded.
3. `python -m diligenceos publish-kit --out ./kit --profile-url https://<profile> --api-url https://<api>` writes the files to host. Hosting them is your decision; tell people the issuer id another way as well.
4. Mint a credential for each caller: `python -m diligenceos delegate --subject <agent id> --scopes verdict --ttl 86400`.
5. Put the proxy in front; bind the server to the address the proxy uses; keep `DILIGENCEOS_VERDICT_AUTH` unset (signed) or `signed`.
6. From outside: an unsigned `POST /v1/verdict` must return 401; a signed one 200; `python -m diligenceos verify-receipt receipt.json --pin <issuer id>` must say VERIFIED.
7. Run a witness from a different machine with its own key so a rewritten history is noticed (`python -m diligenceos witness ...`).

## Proxy example (Caddy)
```
api.example.org {
    request_body { max_size 1MB }
    reverse_proxy 127.0.0.1:8000 { transport http { read_timeout 15s  write_timeout 15s } }
}
```

## Not provided
Deployment itself; a rate limiter in the app (use the proxy); a database (files only); a second node; backups.
