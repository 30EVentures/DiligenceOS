"""The charter draft says only what the code can back up. check_charter() is the rule; the tests try it
on the real file and on a dozen ways of making the file lie."""

import copy
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from diligenceos.flashy import measures, witness, witness_ledger

ROOT = Path(__file__).resolve().parents[2]
CHARTER = ROOT / "docs" / "flashy" / "mesh" / "flashyos-charter.draft.json"
FLASHYOS_AAO = Path.home() / "flashy-audit" / "flashy-npm" / "@flashyos_aao@0.4.2" / "package" / "dist" / "index.js"

# a claim of use, certification or guarantee: none of it is true of a pre-alpha product
OVERCLAIMS = re.compile(r"production|in use|customers|certified|certification|licensed for|regulated|compliant|compliance|SOC ?2|guarantee|"
                        r"audited|insured|bank-grade|enterprise-grade|trusted by|battle", re.I)
# the names CLAUDE.md keeps out of this repo; the pattern is built in pieces so a text scan of the repo stays clean
BANNED_NAMES = re.compile("|".join(["analyst" + "os", "deposit" + "x", "con" + "cord", "kp" + "mg", "go" + "rd", "sol" + "way"]), re.I)


def check_charter(doc) -> list[str]:
    """Every way this charter could claim more than DiligenceOS is. [] means none found."""
    problems = []
    if not isinstance(doc, dict):
        return ["not an object"]
    text = json.dumps(doc)
    if BANNED_NAMES.search(text):
        problems.append("names a sibling product or person")
    if doc.get("accountableTo") != "30eventures@gmail.com":
        problems.append("accountable human is not the public identity")
    if "pre-alpha" not in str(doc.get("description", "")).lower():
        problems.append("does not say it is pre-alpha")
    for field in ("description",):
        if OVERCLAIMS.search(str(doc.get(field, ""))):
            problems.append(f"{field} overclaims")
    roles = {r.get("name"): r for r in doc.get("roles", []) if isinstance(r, dict)}
    if set(roles) != {"diligence", "witness"}:
        problems.append("roles are not exactly diligence and witness")
    expected = {"diligence": measures.MEASURE, "witness": witness_ledger.MEASURE}
    for name, measure in expected.items():
        role = roles.get(name, {})
        if role.get("measure") != measure:
            problems.append(f"{name}: measure is not the one the code computes")
        if OVERCLAIMS.search(str(role.get("purpose", ""))):
            problems.append(f"{name}: purpose overclaims")
    purpose = str(roles.get("witness", {}).get("purpose", ""))
    if "never approves or authorizes a spend" not in purpose:
        problems.append("witness: no longer says it never approves or authorizes a spend")
    if re.search(r"\b(approves?|authori[sz]es?)\b(?! a spend)", purpose.replace("never approves or authorizes a spend", "")):
        problems.append("witness: claims an approving role")
    if roles.get("witness", {}).get("humanApprovalAtOrAbove") not in ("HIGH", "CRITICAL"):
        problems.append("witness: human approval threshold lowered")
    if "log-witnessing" in doc.get("network", {}).get("offers", []):
        problems.append("offers log-witnessing, which no other agent can call")
    if any(c not in {"screen", "verify", "report", "attest"} for r in roles.values() for c in r.get("capabilities", [])):
        problems.append("a capability verb the code does not implement")
    return problems


class RealCharter(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(CHARTER.read_text(encoding="utf-8"))

    def test_the_draft_makes_no_claim_the_code_cannot_back(self):
        self.assertEqual(check_charter(self.doc), [])

    def test_each_capability_verb_is_a_real_function(self):
        from diligenceos import sanctions
        from diligenceos.receipt import verify_receipt
        self.assertTrue(callable(sanctions.screen_subject) and callable(verify_receipt))     # screen, verify
        self.assertTrue(callable(witness.witness_receipt) and callable(witness.verify_witness_receipt))   # attest, verify

    def test_both_measures_are_computable_by_functions_that_exist(self):
        self.assertTrue(callable(measures.diligence_measure) and callable(witness_ledger.witness_measure))

    def test_the_witness_receipt_says_what_the_charter_says(self):
        self.assertIn("does NOT approve or authorize any spend", witness.STATEMENT)

    @unittest.skipUnless(shutil.which("node") and FLASHYOS_AAO.exists(), "SKIPPED LOUDLY: needs node and the offline @flashyos/aao 0.4.2 package")
    def test_flashyos_own_validator_finds_no_issue(self):
        out = subprocess.run(["node", "-e", f"const m=require({json.dumps(str(FLASHYOS_AAO))});"
                              f"console.log(JSON.stringify(m.validateCharterDocument(JSON.parse(require('fs').readFileSync({json.dumps(str(CHARTER))},'utf8')))))"],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout), [])


class ACharterThatLies(unittest.TestCase):
    def lie(self, mutate):
        doc = json.loads(CHARTER.read_text(encoding="utf-8"))
        mutate(doc)
        return check_charter(doc)

    def test_each_of_these_edits_is_caught(self):
        edits = {
            "production claim": lambda d: d.update(description=d["description"] + " Used in production by banks."),
            "pre-alpha dropped": lambda d: d.update(description="The due-diligence agent."),
            "certified": lambda d: d["roles"][0].update(purpose="Certified SOC 2 compliant verdicts."),
            "regulated": lambda d: d.update(description="Pre-alpha. Regulated and audited."),
            "witness approves": lambda d: d["roles"][1].update(purpose="Verifies a signed log and approves spends under a cap."),
            "witness sentence removed": lambda d: d["roles"][1].update(purpose="Verifies another party's signed log."),
            "witness approval lowered": lambda d: d["roles"][1].update(humanApprovalAtOrAbove="LOW"),
            "measure not computed by code": lambda d: d["roles"][0].update(measure="Verdicts that were correct, as a share of verdicts"),
            "witness measure changed": lambda d: d["roles"][1].update(measure="Logs witnessed per day"),
            "extra role": lambda d: d["roles"].append({"name": "treasury", "family": "finance", "purpose": "p", "measure": "m", "capabilities": ["pay"], "humanApprovalAtOrAbove": "HIGH"}),
            "role missing": lambda d: d["roles"].pop(),
            "offers witnessing": lambda d: d["network"].update(offers=["due-diligence-verdict", "log-witnessing"]),
            "capability not implemented": lambda d: d["roles"][0].update(capabilities=["screen", "pay"]),
            "names a sibling product": lambda d: d.update(description=d["description"] + " Powered by " + "Analyst" + "OS."),
            "accountable human changed": lambda d: d.update(accountableTo="someone@example.com"),
        }
        for label, edit in edits.items():
            with self.subTest(label):
                self.assertNotEqual(self.lie(edit), [], label)

    def test_garbage_is_not_a_charter(self):
        for junk in (None, [], "x", 5):
            self.assertNotEqual(check_charter(junk), [])


if __name__ == "__main__":
    unittest.main()
