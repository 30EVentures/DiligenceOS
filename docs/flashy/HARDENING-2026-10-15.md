# Hardening after integration, 2026-10-15

Branch `harden-r2` (local, not pushed), based on `mesh-ready` @ e9a9edd. Tags: **[RAN]** executed, **[VERIFIED]** read in code, **[INFERENCE]** reasoned.
Tests: **698 before, 792 after** (`python -m unittest discover -s tests`, all OK; 4 consecutive runs). Hygiene check (`python3 scripts/prepush_check.py`): clean. Mutation checks: 29 breakages of the new guards, 27 caught first time, the other 2 caught after one added test each.

## Bad news first
1. **Several things in the brief were already true or already fixed; I checked rather than assumed.**
   - `hardening-d1-d3` and `flashy-integration-d1` are merged into `main` and pushed (PRs for both); they hold no unpushed work. [RAN `git merge-base --is-ancestor`]
   - `vectors.json` no longer names the sibling product: it was fixed in 292eaee (seller `demo-seller`). The copy on this branch and the demo repo's copy are byte-identical (sha256 `72ebc9d5...`, the pinned value). [RAN]
   - `trust_score` is an integer in every receipt, not a float: the engine does integer arithmetic and `verify_receipt` refuses any other type. The spine's canonical form accepts a whole real receipt, and the three canonicalisers (receipt, spine, JS) agree byte for byte on 13 awkward names. So there was nothing to move to basis points. [RAN `tests/flashy/test_receipt_canonical.py`]
   - The midnight bug is already fixed in the plane (`plane.js:57` stores the issue day) and the JS suite has a test for it, which a test here re-runs. [VERIFIED, RAN]
   - Most JS "gaps" in the demo notes (closed schema, amount format, chain allowlist, topic upper bytes, tx-hash comparison) are fixed upstream too; the real remaining ones are in item 3 of "Phase 1" below. [RAN]
2. **Real Python bugs, found by the new shared corpus:** the `$` anchors in the spine and adapter regexes accepted a trailing newline (amount `"1\n"`, a payee address, a hash, a timestamp, an env token); an echoed transaction hash in another letter case was refused as unknown; Transfer log data of fewer than 32 bytes was accepted. All fixed. [RAN]
3. **The witness's cap check hid overspends.** It netted every release out of the day's total after the fact, so an authorization given back after midnight made a same-day overspend invisible. It now judges the cap at each issuance and reports the peak. [RAN `test_midnight.py`]
4. **History problems that block a push:** the local branches `flashy-demo-p3` and `mesh-ready-r1` contain the sibling product's name in their history (the original vectors fixture and `TONIGHT.md`); the checker finds 3 hits in each. They must never be pushed (their content is already on `mesh-ready`, which is clean). `main` itself has 25 commits whose author email is a personal one (GitHub web-merge identity, reported earlier; no history rewrite is authorized). [RAN `scripts/prepush_check.py`]
5. **I cannot confirm where the real agent token lives.** I can say it is in no tracked file, no untracked file and no commit of this repo, in any of its 9 worktrees [RAN], that none of the three env vars is set in my shell, and that the only credential-bearing path I found is `~/.flashy/` (dir 0700, `config.json` 0600), outside every repo. I did not read it. Whether your secret store holds the token is yours to confirm.
6. **Not done:** `~/FlashyDemo` was not edited (the JS fixes are a proposed diff); the seal witness is not wired into the witness ledger; the main log still has no server-side high-water mark (proposal below); the verdict API is still open by default (carried over).

> **Update 2026-10-16:** the JS diff was applied to `~/FlashyDemo` on a new local branch `parity-fixes` (72e6351, not pushed), with
> `test/parity-fixes.test.js` (JS suite 37 -> 40, the 3 new tests fail without the fix). The 21 recorded JS gaps are removed from the
> corpus builder, so the parity tests now require the JS spine to answer all 140 cases exactly as required. They need that branch checked
> out in `~/FlashyDemo`; on an unpatched demo repo the JS half of `test_parity.py` fails, by design.

## NEEDS CALEB
1. Delete or keep local-only `flashy-demo-p3` and `mesh-ready-r1`; do not push them (history names a sibling product). `mesh-ready` carries the same content cleanly.
2. Approve (or not) applying `docs/flashy/parity/upstream-js-proposed.diff` to `~/FlashyDemo`. Verified on a scratch copy: corpus 0 differences, JS suite 37/37.
3. Version question for the deliverable: it is carried as the receipt's `canonical_json` string because an old note thought `trust_score` was a float. It is not, so the receipt could travel as an object, but that changes `deliverableHash` for the same receipt (a new invoice version). Recommendation: leave as is; only change if a buyer needs the object form.
4. Confirm the real token's location yourself (item 5 above); rotate it if it was ever pasted anywhere.
5. Publish or not: the seal-witness receipt schema (`docs/flashy/proposals/seal-witness-receipt.md`). Nothing is published.
6. Server-side high-water mark: record the log length and head hash in `store.json` and refuse to load a log shorter than that (catches an accidentally restored old `receipts.jsonl`, which would also resurrect revoked receipts). Not built: it touches store load and needs your OK.
7. Unchanged from before: `DILIGENCEOS_VERDICT_AUTH` defaults to `open`; the personal-email commits on `main`.

## Phase 0
1. **Secrets.** `scripts/prepush_check.py` finds token-shaped assignments (`..._TOKEN=`, bearer values, one-time claim links, PEM blocks, provider keys), credential files (`.env*`, `*.key`, `*.pem`, `.flashy/`, the generated `*-agent-reporter.ts`) and prints the rule and place only, never the match. `tests/test_prepush_hygiene.py` runs it over this repo's tree. `.gitignore` now excludes those files. What `npx @flashyos/agent init` writes was read from the package: `./.env` (token under `FLASHYOS_AGENT_TOKEN_<AGENT>`), a `<agent>-agent-reporter.ts`, and session credentials in `~/.flashy/`; all three are covered. [VERIFIED package, RAN]
2. **Brand rule.** The same checker has banned-name rules (the sibling products, the named person and company, any gmail address other than the public one) and `--range origin/main..HEAD` scans every commit about to be pushed, including content a later commit removed, and every author. Run it before any push.
3. **Presence.** Exactly your mapping: issuing a receipt = BUILDING, verifying (receipts, decisions, the log) = TESTING, witnessing = REVIEWING, a refused or broken chain = INCIDENT (kept visible 8x longer), idle = IDLE. Five fixed labels, no data can reach a heartbeat, silent without the three env vars, never blocks or raises. A merely refused request (400) shows nothing.

## Phase 1
4. **Tail cut.** `verify_plane_log` takes `pinned_count`/`pinned_head` (`TAIL_CUT`, `HISTORY_REWRITTEN`, `BAD_PIN`). The witness ledger remembers, per plane key, the head and count it last signed and pins them on every witnessing; a caller can add a stricter pin but never relax it; a refusal moves nothing. The main log's own witness already refused a cut tail; that is now pinned by a test. [RAN `test_tail_cut.py`]
5. **Parity corpus.** `tests/flashy/fixtures/refusal-corpus.json`, generated by `build_refusal_corpus.py`: 140 cases (86 invoice, 54 transaction), 90% refusals (126 of 140). Both implementations must answer each as required or as a recorded gap. Python: 0 gaps. JS: 21 gaps (zero-amount invoices; loose `expiresAt` forms; payee/asset shape not checked; unreadable chain tip throws; log with no/odd emitting address counted; removed logs counted; Transfer data of any width; a non-string echoed hash ignored). All 21 close with the proposed diff.
6. **trust_score.** Premise did not hold (above). Pinned by tests instead.
7. **Midnight.** See bad news 1 and 3.
8. **D1 and D3** were already done and merged: log pagination (`GET /v1/log/entries`, bounded pages, 23 tests; `docs/decisions.md` entry D1) and the honest note that signed fields are not sanitized (README section, `untrusted_fields` in capabilities and the manifest, entry D3). The TLS note is in the README and in a startup warning. [VERIFIED]

## Phase 2
9. **Cross-product witness.** `diligenceos/flashy/seal_witness.py` and `docs/flashy/proposals/seal-witness-receipt.md`. Tested against the producing product's own sealer and verifier as the oracle. The producer's store holds no seals yet, so the pilot used seals made by the real sealer in a temp directory.
10. **Merge readiness.** Below.

## Merge readiness (every branch not yet on `main`)
| Branch | State | Must pass before merge | Needs Caleb |
|---|---|---|---|
| `mesh-ready` | pushed, 1 commit, clean history | suite, hygiene check | merge decision; verdict auth default |
| `harden-r2` | local only, 6 commits on top of `mesh-ready` | suite 792; `prepush_check.py --range origin/main..HEAD` | merge `mesh-ready` first (or merge this one, it contains it); items 2-6 above |
| `flashy-demo-p3`, `mesh-ready-r1` | local only | **do not push** (history names a sibling product) | delete or keep local |
| `design-proceed-gate-mcp` | local only, 1 commit (design note), clean | hygiene check passes | update the note (money bound decided, payer check built) or push as is |
| `money-bound-2-53`, `payment-receipt-check`, `overnight/diligenceos-bugs`, `hardening-d1-d3`, `flashy-integration-d1`, `fix-*` | merged | none | delete leftovers whenever |
