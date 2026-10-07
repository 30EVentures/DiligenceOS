"""Conformance: our own refusal-first corpus (conformance/diligenceos-1.json),
an adapter that answers it over a JSON-lines protocol, and a fail-closed runner.

Protocol (stdin -> stdout, one JSON object per line):

    in   {"id", "set", "input", "context"?}
    out  {"id", "valid": bool, "codes": [...]}                for `validate` sets
         {"id", "verdict": "ALLOW|ESCALATE|DENY", "valid": bool, "codes": [...]}   for `decide` sets
         (`valid` on a decide answer means verdict == ALLOW)

An unexpected exception inside a verifier is NOT answered with a refusal: that
would let a crash pass as a correct "no". The line is answered with a `crash`
field and no verdict, which a runner counts as unreadable, i.e. a failure.

Run the adapter:   python -m diligenceos.conformance
Run it in-process: diligenceos.conformance.run_corpus(load_corpus(path))

Stable codes are ours (the verifiers return English sentences); `_classify`
maps a sentence to a code, and the corpus run fails if any sentence is left
unclassified, so a reworded error cannot silently drop out of the vocabulary.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from diligenceos import api
from diligenceos.auth import sign_request
from diligenceos.delegation import verify_chain as verify_delegation_chain
from diligenceos.policy import Policy, WideningError, decide, narrow
from diligenceos.receipt import verify_receipt
from diligenceos.receipt_log import verify_chain as verify_log_chain
from diligenceos.signing import Signer
from diligenceos.store import Store
from diligenceos.types import Money

CORPUS_PATH = Path(__file__).resolve().parent.parent / "conformance" / "diligenceos-1.json"
OUTCOMES = ("ALLOW", "ESCALATE", "DENY")
MIN_REFUSAL_SHARE = 0.60

# Test-only keys, derived from fixed seeds so the corpus is reproducible. They
# protect nothing; never use one outside this corpus.
OPERATOR_SEED = bytes([1]) * 32  # the server under test, for the HTTP-shaped sets


def test_signer(n: int) -> Signer:
    return Signer(Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32))


# ── error sentence -> stable code ───────────────────────────────────────────

_RULES = (
    # receipts
    (r"^receipt must be a JSON object", "not-an-object"),
    (r"^unknown schema", "unknown-schema"),
    (r"^unknown rules", "unknown-rules"),
    (r"^id does not match the document", "id-mismatch"),
    (r"not canonicalizable JSON", "not-canonicalizable"),
    (r"^findings unreadable", "findings-unreadable"),
    (r"^verdict .* does not follow", "verdict-replay-mismatch"),
    (r"^trust_score .* does not follow", "score-replay-mismatch"),
    (r"^signature does not verify for this issuer", "bad-signature"),
    (r"names an issuer but carries no signature", "unsigned-but-names-issuer"),
    (r"^expires/now is not an ISO", "bad-timestamp"),
    (r"does not match the digest the claim", "evidence-digest-mismatch"),
    (r"not found in", "evidence-quote-missing"),
    (r"was claimed absent but appears", "evidence-absent-present"),
    # delegation chains
    (r"must be a non-empty list", "chain-empty"),
    (r"chain is longer than", "chain-too-long"),
    (r"^now is not a timezone-aware", "bad-now"),
    (r"link \d+: id does not match", "bad-id"),
    (r"link \d+: signature does not verify", "bad-signature"),
    (r"link \d+: expired", "expired"),
    (r"link \d+: revoked", "revoked"),
    (r"does not start at a trusted root", "untrusted-root"),
    (r"must not name a parent", "bad-parent"),
    (r"delegator is not the previous", "delegator-mismatch"),
    (r"parent does not name the previous", "parent-mismatch"),
    (r"link \d+: widens scopes", "widens-scopes"),
    (r"expires later than its parent", "expires-after-parent"),
    (r"changes the budget", "budget-changed"),
    (r"drops the policy", "drops-policy"),
    (r"link \d+: widens ", "widens-policy"),
    (r"link \d+: malformed", "malformed-link"),
    # receipt log
    (r"^entries must be a list", "entries-not-a-list"),
    (r"^entry \d+ is not an object", "not-an-object"),
    (r"^entry \d+ has seq", "bad-seq"),
    (r"does not link to the entry before", "broken-link"),
    (r"^entry \d+ is not canonicalizable", "not-canonicalizable"),
    (r"does not match its own hash", "entry-hash-mismatch"),
    (r"^entry \d+ signature does not verify", "bad-signature"),
    (r"issuer that is not trusted", "untrusted-issuer"),
    (r"^entry \d+ is not signed", "unsigned-entry"),
    (r"^head does not match the expected head", "head-mismatch"),
    # decisions
    (r"^receipt invalid:", "receipt-invalid"),
    (r"not validly signed by a trusted issuer", "untrusted-issuer"),
    (r"^receipt was revoked", "revoked"),
    (r"^verdict is RED_FLAG", "red-flag"),
    (r"is not acceptable under this policy", "verdict-not-acceptable"),
    (r"is below the minimum", "score-below-floor"),
    (r"carries no transaction", "no-transaction"),
    (r"^currency .* differs from policy", "currency-mismatch"),
    (r"exceeds the cap", "over-cap"),
    (r"^receipt has expired", "expired"),
    (r"malformed transaction", "malformed-transaction"),
    (r"cumulative spend would exceed", "over-cap"),
)
_COMPILED = tuple((re.compile(p), c) for p, c in _RULES)


def _classify(message: str) -> str:
    text = str(message)
    if text.startswith("receipt invalid: "):
        text = text[len("receipt invalid: "):]
    for pattern, code in _COMPILED:
        if pattern.search(text):
            return code
    return "unclassified"


def _codes(messages, *extra: str) -> list[str]:
    out: list[str] = []
    wrapped = ["receipt-invalid" for m in messages if str(m).startswith("receipt invalid: ")]
    for code in [*wrapped, *(_classify(m) for m in messages), *extra]:
        if code not in out:
            out.append(code)
    return out


# ── the sets ────────────────────────────────────────────────────────────────

def _ctx(case: dict) -> dict:
    ctx = case.get("context")
    return ctx if isinstance(ctx, dict) else {}


def _validate(valid: bool, codes: list[str]) -> dict:
    return {"valid": valid, "codes": codes}


def _set_receipt(case: dict) -> dict:
    ctx = _ctx(case)
    check = verify_receipt(
        case["input"], now=ctx.get("now"), sources=ctx.get("sources"),
        revocations=ctx.get("revocations"), trusted_issuers=ctx.get("trusted_issuers"),
    )
    extra = []
    if check.expired:
        extra.append("expired")
    if check.revoked:
        extra.append("revoked")
    if check.trusted is False:
        extra.append("untrusted-issuer")
    valid = check.valid and not check.expired and not check.revoked and check.trusted is not False
    return _validate(valid, _codes(check.errors, *extra))


_AXIS_CODES = {
    "max_amount.currency": "currency-change",
    "max_amount.amount_minor": "widens-cap",
    "acceptable_verdicts": "widens-verdicts",
    "min_trust_score": "lowers-floor",
}


def _set_policy_narrowing(case: dict) -> dict:
    data = case["input"]
    try:
        parent, child = Policy.from_dict(data["parent"]), Policy.from_dict(data["child"])
    except (ValueError, KeyError, TypeError):
        return _validate(False, ["policy-malformed"])
    try:
        narrow(parent, child)
    except WideningError as exc:
        return _validate(False, [_AXIS_CODES.get(exc.axis, "widens-policy")])
    return _validate(True, [])


def _set_delegation_chain(case: dict) -> dict:
    ctx = _ctx(case)
    result = verify_delegation_chain(
        case["input"], root_issuers=ctx.get("root_issuers", []), now=ctx.get("now"),
        revocations=ctx.get("revocations"),
    )
    return _validate(result.valid, _codes(result.errors))


def _set_log_chain(case: dict) -> dict:
    ctx = _ctx(case)
    errors = verify_log_chain(
        case["input"], expected_head=ctx.get("expected_head"),
        trusted_issuers=ctx.get("trusted_issuers"), require_signed=bool(ctx.get("require_signed")),
    )
    return _validate(not errors, _codes(errors))


def _decision(outcome: str, codes: list[str]) -> dict:
    return {"verdict": outcome, "valid": outcome == "ALLOW", "codes": codes}


def _set_decide(case: dict) -> dict:
    ctx, data = _ctx(case), case["input"]
    policy = Policy.from_dict(data["policy"])
    decision = decide(
        data["receipt"], policy, now=ctx.get("now"), sources=ctx.get("sources"),
        revocations=ctx.get("revocations"), trusted_issuers=ctx.get("trusted_issuers"),
    )
    return _decision(decision.outcome.value, _codes(decision.reasons))


def _server() -> Store:
    store = Store()  # in memory; the server under test holds the operator test key
    store._signer = Signer(Ed25519PrivateKey.from_private_bytes(OPERATOR_SEED))
    return store


def _http(store: Store, path: str, payload) -> tuple[int, dict]:
    status, _, body = api.handle("POST", path, json.dumps(payload).encode("utf-8"), store)
    return status, json.loads(body)


def _set_decide_api(case: dict) -> dict:
    """Through the HTTP-shaped handlers, with this module's operator key as the
    server's. `context.endpoint` is `decide` (default) or `spend`, which the
    adapter signs as the operator (a valid caller: only the receipt is in question),
    or, with `context.auth == "bogus"`, gives a well-formed envelope nobody signed."""
    ctx, store = _ctx(case), _server()
    endpoint = ctx.get("endpoint", "decide")
    path = {"decide": "/v1/decide", "spend": "/v1/spend"}[endpoint]
    payload = case["input"]
    if endpoint == "spend" and isinstance(payload, dict):
        if ctx.get("auth") == "bogus":  # a well-formed envelope that no key signed
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            payload = {**payload, "auth": {"signer": "ed25519:" + "0" * 64, "chain": [], "issued_at": now,
                                           "nonce": "n", "signature": "ed25519:" + "0" * 128}}
        else:
            payload = {**payload, "auth": sign_request(store.signer, [], path, payload)}
    status, out = _http(store, path, payload)
    if status != 200:
        err = out.get("error", {})
        return _decision("DENY", [err.get("code", "http-" + str(status))] + ([err["field"]] if err.get("field") else []))
    return _decision(out["decision"], _codes(out["reasons"]))


def _op_money(value) -> dict:
    try:
        Money.from_dict(value)
    except ValueError:
        return _validate(False, ["malformed-money"])
    return _validate(True, [])


def _op_policy(value) -> dict:
    try:
        Policy.from_dict(value)
    except ValueError:
        return _validate(False, ["policy-malformed"])
    return _validate(True, [])


def _op_verdict_request(value) -> dict:
    status, out = _http(_server(), "/v1/verdict", value)
    if status == 200:
        return _validate(True, [])
    err = out.get("error", {})
    return _validate(False, [err.get("code", "http-" + str(status))] + ([err["field"]] if err.get("field") else []))


def _set_malformed(case: dict) -> dict:
    """Hostile or ill-typed inputs. Every one must be refused cleanly; `context.op`
    names the verifier: receipt, money, policy, delegation-chain, log-chain, verdict-request."""
    op = _ctx(case).get("op")
    if op == "money":
        return _op_money(case["input"])
    if op == "policy":
        return _op_policy(case["input"])
    if op == "verdict-request":
        return _op_verdict_request(case["input"])
    if op == "receipt":
        return _set_receipt(case)
    if op == "delegation-chain":
        return _set_delegation_chain(case)
    if op == "log-chain":
        return _set_log_chain(case)
    raise ValueError(f"unknown malformed-input op {op!r}")


SETS = {
    "receipt": _set_receipt,
    "policy-narrowing": _set_policy_narrowing,
    "decide": _set_decide,
    "decide-api": _set_decide_api,
    "delegation-chain": _set_delegation_chain,
    "log-chain": _set_log_chain,
    "malformed": _set_malformed,
}


def answer(case) -> dict:
    """One case in, one answer out. Never raises; a crash inside a verifier is
    reported as {"id", "crash"} (no verdict), never as a refusal."""
    case_id = case.get("id") if isinstance(case, dict) else None
    try:
        handler = SETS.get(case["set"])
        if handler is None:
            return {"id": case_id, "error": f"unknown set {case['set']!r}"}
        return {"id": case_id, **handler(case)}
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed: see module docstring
        return {"id": case_id, "crash": f"{type(exc).__name__}: {exc}"[:300]}


def main(stdin=None, stdout=None) -> int:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        if not line.strip():
            continue
        try:
            case = json.loads(line)
        except ValueError:
            print("conformance: unparseable input line skipped", file=sys.stderr)
            continue
        stdout.write(json.dumps(answer(case), allow_nan=False) + "\n")
        stdout.flush()
    return 0


# ── the runner ──────────────────────────────────────────────────────────────

def load_corpus(path: Path = CORPUS_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cases_of(corpus: dict) -> list[dict]:
    """Every case, with `set`, `kind` and `outcomes` taken from its set. Duplicate ids are an error."""
    cases, seen = [], set()
    for s in corpus.get("sets", []):
        for c in s.get("cases", []):
            if c["id"] in seen:
                raise ValueError(f"duplicate case id {c['id']!r}")
            seen.add(c["id"])
            cases.append({**c, "set": s["name"], "kind": s["kind"]})
    return cases


def is_refusal(expect: dict) -> bool:
    return expect.get("valid") is False or expect.get("verdict") == "DENY"


def judge(expect: dict, ans) -> tuple[str, str]:
    """(state, why): agreed | disagreed | unanswered | unreadable. Mirrors the
    kit's rules: `valid` or `verdict` must match; expected codes must all be present."""
    if ans is None:
        return "unanswered", "no answer line for this case"
    if not isinstance(ans, dict):
        return "unreadable", "answer is not an object"
    if "verdict" in expect:
        got = ans.get("verdict")
        if got not in OUTCOMES:
            return "unreadable", f"verdict {got!r} is not one of {OUTCOMES}" + (f" ({ans['crash']})" if "crash" in ans else "")
        if got != expect["verdict"]:
            return "disagreed", f"expected {expect['verdict']}, got {got}"
    else:
        if not isinstance(ans.get("valid"), bool):
            return "unreadable", "no boolean `valid`" + (f" ({ans['crash']})" if "crash" in ans else "")
        if ans["valid"] != expect["valid"]:
            return "disagreed", f"expected valid={expect['valid']}, got valid={ans['valid']}"
    if isinstance(expect.get("codes"), list):
        got_codes = ans.get("codes") if isinstance(ans.get("codes"), list) else []
        missing = [c for c in expect["codes"] if c not in got_codes]
        if missing:
            return "disagreed", f"missing code(s) {missing}; got {got_codes}"
    return "agreed", ""


@dataclass
class Report:
    rows: list
    executed: int
    agreed: int
    disagreed: int
    unanswered: int
    unreadable: int
    refusals: int
    known_failures: int = 0
    unexpected_passes: int = 0

    @property
    def refusal_share(self) -> float:
        return self.refusals / self.executed if self.executed else 0.0

    def problems(self) -> list[str]:
        """Empty means the corpus ran and everything agreed. Fails closed."""
        out = []
        if self.executed == 0:
            out.append("zero cases were executed")
        if self.unanswered:
            out.append(f"{self.unanswered} case(s) unanswered")
        if self.unreadable:
            out.append(f"{self.unreadable} case(s) unreadable")
        if self.disagreed:
            out.append(f"{self.disagreed} case(s) disagreed")
        if self.unexpected_passes:
            out.append(f"{self.unexpected_passes} known-failure case(s) now pass: remove the marker")
        if self.executed and self.refusal_share < MIN_REFUSAL_SHARE:
            out.append(f"refusal share {self.refusal_share:.0%} is below {MIN_REFUSAL_SHARE:.0%}")
        out += [f"{r['id']}: {r['state']}: {r['why']}" for r in self.rows if r["state"] != "agreed" and not r.get("known_failure")]
        return out


def evaluate(cases: list[dict], answers: dict) -> Report:
    """`answers` maps case id -> answer object. A case with `known_failure` is
    expected to NOT agree (documented bug); it still must have been answered."""
    rows, counts = [], {"agreed": 0, "disagreed": 0, "unanswered": 0, "unreadable": 0}
    known = unexpected = 0
    for c in cases:
        state, why = judge(c["expect"], answers.get(c["id"]))
        row = {"id": c["id"], "set": c["set"], "state": state, "why": why}
        if c.get("known_failure") and state != "unanswered":
            row["known_failure"] = c["known_failure"]
            if state == "agreed":
                unexpected += 1
            else:
                known += 1  # disagreed or crashed, as documented
        else:
            counts[state] += 1
        rows.append(row)
    return Report(
        rows=rows, executed=len(cases), refusals=sum(is_refusal(c["expect"]) for c in cases),
        known_failures=known, unexpected_passes=unexpected, **counts,
    )


def run_corpus(corpus: dict, answerer=answer) -> Report:
    cases = cases_of(corpus)
    answers = {}
    for c in cases:
        a = answerer({"id": c["id"], "set": c["set"], "input": c["input"],
                      **({"context": c["context"]} if "context" in c else {})})
        if isinstance(a, dict) and "id" in a:
            answers[a["id"]] = a
    return evaluate(cases, answers)


if __name__ == "__main__":
    raise SystemExit(main())
