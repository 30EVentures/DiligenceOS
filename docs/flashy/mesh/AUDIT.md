# Mesh readiness audit: DiligenceOS, 2026-10-14

Tags: **[VERIFIED]** read in the code, **[RAN]** executed and observed, **[INFERENCE]** reasoned, not observed.
"Before" is `flashy-demo-p3` @ 6be9b0b; "after" is this branch. Nothing here was run against FlashyOS.

## Bad news first

1. **The previous charter's `diligence` measure could not be computed.** It said "verdicts whose evidence re-verifies offline, as a share of verdicts issued". The server keeps no receipts and no source documents: the log holds ids and digests only. [VERIFIED `receipt_log.py`, `api._verdict`] Replaced (below).
2. **The `witness` role left no record, so its measure could not be computed either.** `witness_receipt` signs for a log it can verify and raises for one it cannot; nothing recorded the refusals, and nothing in the product called it at all (no route, no command). [VERIFIED `flashy/witness.py`; grep for callers]
3. **The previous charter overclaimed.** Its `diligence` purpose said "built from independently checkable evidence"; identity and track-record findings are explicitly exempt from citation. [VERIFIED `pipeline.UNCITED_CATEGORIES`] It also offered `log-witnessing`, which no other agent can call. Both removed.
4. **`POST /v1/verdict` is unauthenticated by default and every request appends a signed entry to the log.** Anyone who can reach a public bind can grow the log without bound. An opt-in signed mode now exists, but the default is still open (kept so local use and every existing test is unchanged). **Set `DILIGENCEOS_VERDICT_AUTH=signed` before the server is reachable by anyone else.** [RAN `tests/test_verdict_surface.py`]
5. **Unknown request fields were silently ignored**, so a misspelt `transction` produced a receipt with no transaction. Now a 400. This is the one change that makes a previously accepted request fail. [VERIFIED before; RAN after]
6. **Nothing is deployed and no discovery file is published.** The API is localhost-only plain HTTP, there is no public URL, and no `.well-known` handshake or charter is served (not mine to publish). Another agent cannot call the verdict surface yet. [VERIFIED README, `webapp.py`]
7. **The verdicts are only as good as the loaded data.** The bundled sanctions list has 3 entries and there is no registry client; the identity check flags every company it has not been given. Listing a "due-diligence-verdict" capability on the mesh before real data is loaded would be a claim the product cannot back. [VERIFIED `fixtures/golden/sanctions_sample.json`, `ROADMAP.md`]
8. **Repository hygiene.** The prep commit 6be9b0b (`docs/flashy/mesh/TONIGHT.md`) names a sibling product, which `CLAUDE.md` forbids anywhere in the repo including history. This branch removes the text but cannot remove the commit; if this branch is ever pushed, squash it first. I did not rewrite history. [VERIFIED `git log -p`]
9. **This base does not include the overnight hardening branch** (`overnight/diligenceos-bugs`, unmerged): the duplicate-key, huge-`Content-Length` and similar fixes are not here. [VERIFIED `git branch`]
10. **The heartbeat wire format is copied from the SDK, not tested against FlashyOS.** Nothing was sent anywhere. Status names and the endpoint come from `@flashyos/agent` 0.21.0 as recorded in `mesh_reporter.py`. [INFERENCE that it is accepted]

## Requirement by requirement

| Requirement | Before | After | Evidence |
|---|---|---|---|
| Honest charter, measures computed from what is recorded | **partial** (valid shape; two uncomputable measures; overclaims) | **done** | both measures are functions over signed records (`flashy/measures.py`, `flashy/witness_ledger.py`); the charter's measure text is imported from those functions and a test fails if they diverge or if the charter claims production use, certification, an approving witness, or offers `log-witnessing` [RAN `test_charter.py`]. Valid under the local AAO checker and `@flashyos/aao` 0.4.2 `validateCharterDocument` (no issues) [RAN] |
| Machine-callable verdict surface | **partial** (JSON in/out, structured errors, but open schema, no auth) | **partial, deliberately** | closed schema [RAN]; optional signed mode with a new `verdict` scope that only narrows [RAN]; an agent holding a credential calls it with no human and checks the receipt offline against its pinned key [RAN `test_an_agent_with_a_verdict_credential_needs_no_human`]. Still: default is open; not deployed (bad news 4, 6) |
| Receipts and signed log verifiable by a stranger against a pinned key | **done in code** | **done in code, plus** the charter number is recomputable from the public log pages with only the pinned key [RAN `test_a_stranger_can_compute_it...`] | `GET /v1/manifest` states every signed document and how to verify it; an existing test verifies real documents using only the manifest [RAN]. Missing: a public place to learn the key to pin (bad news 6) |
| Real heartbeats | **missing** (a script that sends IDLE; the server never reports) | **done in code, unproven on the wire** | `flashy/presence.py`: request received, gathering evidence, verdict issued, idle, from the API and the web form; inert without the three variables; never in the verdict's path [RAN `test_presence.py`] |

## What was changed (all additive except where noted)

- New: `diligenceos/flashy/presence.py`, `measures.py`, `witness_ledger.py`; tests `tests/flashy/test_presence.py`, `test_measures.py`, `test_charter.py`, `tests/test_verdict_surface.py`; `docs/flashy/mesh/READINESS.md`, this file.
- Edited: `api.py` (presence events; closed schema; verdict auth mode; capabilities and manifest state the mode), `webapp.py` (presence events; worker starts with the server), `delegation.py` (scope list gains `verdict`), `tools.py` (help text), `tests/test_manifest.py` (pins the scope list), the charter draft. Not touched: gate, spend, receipt, witness, signing.

## Proposals, not done

1. Persist receipts and the documents they were checked against, so "evidence re-verifies offline" can become a measure (a data-retention decision for the owner).
2. Merge the overnight hardening branch before exposing the server.
3. Make `DILIGENCEOS_VERDICT_AUTH` default to `signed` once there is a deployment, and add a per-credential quota.
4. Declare no capability on the mesh until a deployment exists and real data is loaded.
