# Proposal: make the signed log, not `store.json`, the source of revocation enforcement

Status: **proposal only, no code.** It changes what the server enforces after a
restart, so it waits for the owner's go-ahead. Audit item: `mine-diligenceos.md`
§10 item 9.

## The problem (reproduced against `main` at 4205487)

`Store.revoke()` appends a signed revocation entry to the log first, then updates
`self._revocations` and saves `store.json`. On restart, `Store.from_dict` rebuilds
`_revocations` from the `revocations` key of `store.json` only; it never looks at
the log. So if the process dies after the log append and before the save
completes, the revocation is durably logged (a witness or auditor can see it) but
**not enforced**: `/v1/verify`, `/v1/decide`, `/v1/spend` and delegation-chain
checks all consult the index and will accept the revoked receipt or delegation.

Reproduced: log a revocation, skip the save, build a fresh `Store` from the same
path. The log contains the entry; `fresh.revocations` does not. Nothing heals it:
the gap persists until someone revokes the same id again. The same divergence
follows from any hand-edit or restore of `store.json`.

(Fix (c), atomic writes, removes the corrupt-file variant of this. It does not
close this window: a crash can still land between the two writes.)

## Options

1. **Derive the index from the log at load (log is authoritative).** On load,
   verify the chain and rebuild `_revocations` from the `kind: "revocation"`
   entries; `store.json` stops carrying a revocation index. Closes the crash
   window and the edited-file case. Cost: load time is O(log); a corrupt log means
   revocations are unknowable, so the server must fail closed (refuse the
   endpoints that need them) rather than enforce nothing. Needs a migration for
   indexes written before Slice 26, which hold revocations with no log entry.
2. **Union at load: index ∪ log.** Enforce everything either source says. Never
   loses enforcement, no migration, smallest change. An edited `store.json` can
   still add revocations (a nuisance, not a loss of safety), and the two sources
   keep existing, so the divergence is repaired rather than removed.
3. **Write-ahead intent record before the log append.** Complete, but adds a third
   durable artifact to reason about for a window option 1 or 2 already closes.

## Recommendation

Option 2 now: revocation errs in the safe direction, so enforcing the union cannot
weaken anything, and it needs no migration. Option 1 later, once the index can be
dropped. Either way, make `revoke()` consult the log's own record for idempotency,
so re-revoking after a crash does not append a duplicate entry.

## Decisions needed from the owner

- Union (2) or log-authoritative (1)?
- If the log fails verification at startup: refuse to start, or serve with
  revocation-dependent endpoints returning 503? (Today `store.log` raises lazily,
  per request.)
- Legacy index entries with no log entry: keep, or require re-revocation?

## Test plan (when approved)

The reproduction above as a regression test; a corrupt-log case asserting fail
closed; a legacy-index case; idempotent re-revoke.

## Out of scope here

Spend commits and delegation issuance are not logged either (noted in the same
audit item). That is a separate, larger change to what the log attests.
