# DiligenceOS

The due-diligence agent you call before any transaction, hire, or contract.

DiligenceOS takes a subject and a transaction and returns one verdict —
`PROCEED`, `HOLD`, or `RED_FLAG` — built from independently checkable
evidence, not self-reported claims. It's meant to be called two ways: by a
human doing diligence by hand, and by an agent mid-task, gating its own next
action (a payment, a signature, an offer) on the verdict.

Status: pre-alpha. Nothing here is production-ready or licensed for real
compliance decisions yet. See `ROADMAP.md`.

## Getting started

```
python3 -m diligenceos
```

Opens a local web front end at `http://127.0.0.1:8000` — enter a subject
name, a registration id, and optional contract text, get a verdict back.
Runs against a bundled sample dataset, not real registries or sanctions
data. See `CLAUDE.md` for how to run tests and the batch (JSON in, JSON
out) mode.
