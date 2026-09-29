# DiligenceOS

The due-diligence agent you call before any transaction, hire, or contract.

DiligenceOS takes a subject and a transaction and returns one verdict —
`PROCEED`, `HOLD`, or `RED_FLAG` — built from independently checkable
evidence, not self-reported claims. It's meant to be called two ways: by a
human doing diligence by hand, and by an agent mid-task, gating its own next
action (a payment, a signature, an offer) on the verdict.

Status: pre-alpha. Nothing here is production-ready or licensed for real
compliance decisions yet. See `ROADMAP.md`.

## Callers and credentials

`/v1/revoke` and `/v1/spend` need a signed request. The operator (the
server's own key, `~/.diligenceos/issuer.key`) can sign directly; anyone
else needs a credential the operator (or a delegate) minted, which can only
be narrowed as it is passed on:

```
.venv/bin/python -m diligenceos keygen agent.key            # prints the agent's id
.venv/bin/python -m diligenceos delegate --subject <id> --scopes spend \
    --max-amount 30000000 --currency USD --min-trust 70 --budget q4 > chain.json
.venv/bin/python -m diligenceos sign-request --key agent.key --chain chain.json \
    --path /v1/spend body.json | curl -s -X POST localhost:8000/v1/spend --data-binary @-
```

## Witnessing the log

The server's own log check (`/v1/log/verify`) can't catch the operator
rewriting history and re-signing it — a rewrite that is internally
consistent *is* valid. A witness can, because it remembers what it saw:

```
.venv/bin/python -m diligenceos keygen witness.key
.venv/bin/python -m diligenceos witness --url http://127.0.0.1:8000 \
    --issuer <the issuer id you pinned> --key witness.key --state witness.json
```

Exit `0`: the log is an append-only extension of what this witness saw last,
and the witness cosigned the head. Exit `3`: it is not (history rewritten or
truncated) — investigate. To be worth anything the witness must be run by
someone other than the operator, who keeps its own state file. Add
`--submit` and list the witness in the server's `DILIGENCEOS_WITNESSES` to
have cosignatures served with `/v1/log/head`.

## Getting started

```
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m diligenceos
```

Opens a local web front end at `http://127.0.0.1:8000` — enter a subject
name, a registration id, and optional contract text, get a verdict back.
Visit `/data` to add sanctions entries, registry records, or delivery
records of your own — additions are checkable immediately and persist
across restarts in `~/.diligenceos/store.json`. Still not real registries
or sanctions data — everything starts from a bundled sample dataset. See
`CLAUDE.md` for how to run tests and the batch (JSON in, JSON out) mode.
