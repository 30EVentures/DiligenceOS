"""Runs conformance/diligenceos-1.json against our own verifiers, and checks that
the runner itself fails closed: a corpus that ran nothing, or answered nothing, or
was answered in garbage, is a failure, never a pass."""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

from diligenceos import conformance
from diligenceos.conformance import (
    MIN_REFUSAL_SHARE, answer, cases_of, evaluate, judge, load_corpus, run_corpus,
)

ROOT = Path(__file__).resolve().parent.parent
GENERATOR = ROOT / "conformance" / "build_diligenceos_1.py"


def tiny(expects, **extra):
    """A corpus of `receipt`-set cases with the given expectations."""
    return {"sets": [{"name": "receipt", "kind": "validate", "cases": [
        {"id": f"c{i}", "set": "receipt", "input": [], "expect": e, **extra} for i, e in enumerate(expects)]}]}


class CorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_corpus()

    def assert_clean(self, report):
        self.assertEqual(report.problems(), [])

    def test_the_corpus_is_big_enough_and_refusal_first(self):
        cases = cases_of(self.corpus)
        self.assertGreaterEqual(len(cases), 45)
        refusals = sum(conformance.is_refusal(c["expect"]) for c in cases)
        self.assertGreaterEqual(refusals / len(cases), MIN_REFUSAL_SHARE)
        for c in cases:
            self.assertTrue(c.get("note"), c["id"])
        covered = {c["set"] for c in cases}
        self.assertEqual(covered, set(conformance.SETS))

    def test_in_process_every_case_agrees(self):
        report = run_corpus(self.corpus)
        self.assert_clean(report)
        self.assertEqual(report.executed, len(cases_of(self.corpus)))

    def test_no_refusal_is_left_with_an_unclassified_code(self):
        for c in cases_of(self.corpus):
            a = answer({"id": c["id"], "set": c["set"], "input": c["input"], **({"context": c["context"]} if "context" in c else {})})
            self.assertNotIn("unclassified", a.get("codes", []), c["id"])

    def test_over_the_line_protocol(self):
        """The adapter as any conformance runner would drive it: JSON lines in, JSON lines out."""
        cases = cases_of(self.corpus)
        stdin = "".join(json.dumps({"id": c["id"], "set": c["set"], "input": c["input"],
                                    **({"context": c["context"]} if "context" in c else {})}) + "\n" for c in cases)
        proc = subprocess.run([sys.executable, "-m", "diligenceos.conformance"], input=stdin, capture_output=True,
                              text=True, cwd=ROOT, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        answers = {}
        for line in proc.stdout.splitlines():
            a = json.loads(line)
            answers[a["id"]] = a
        self.assert_clean(evaluate(cases, answers))
        # and the line protocol's own failure modes: junk lines are skipped, blank lines ignored
        proc = subprocess.run([sys.executable, "-m", "diligenceos.conformance"], input='not json\n\n{"id":"x","set":"nope","input":1}\n',
                              capture_output=True, text=True, cwd=ROOT, timeout=60)
        self.assertEqual([json.loads(l) for l in proc.stdout.splitlines()], [{"id": "x", "error": "unknown set 'nope'"}])

    def test_the_committed_corpus_is_what_the_generator_produces(self):
        spec = importlib.util.spec_from_file_location("build_diligenceos_1", GENERATOR)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fresh = json.dumps(module.build(), indent=1, ensure_ascii=True) + "\n"
        self.assertEqual(fresh, (ROOT / "conformance" / "diligenceos-1.json").read_text(encoding="utf-8"),
                         "regenerate: .venv/bin/python conformance/build_diligenceos_1.py")

    def test_known_failures_are_documented_and_few(self):
        known = [c for c in cases_of(self.corpus) if c.get("known_failure")]
        self.assertLessEqual(len(known), 5)
        for c in known:
            self.assertGreater(len(c["known_failure"]), 40, c["id"])


class RunnerFailsClosedTest(unittest.TestCase):
    """The runner must not be able to report a clean pass over nothing."""

    def refuse_all(self, case):
        return {"id": case["id"], "valid": False, "codes": []}

    def test_zero_executed_cases_is_a_failure(self):
        for corpus in ({}, {"sets": []}, {"sets": [{"name": "receipt", "kind": "validate", "cases": []}]}):
            self.assertIn("zero cases were executed", run_corpus(corpus).problems())

    def test_a_case_with_no_answer_is_a_failure(self):
        corpus = tiny([{"valid": False}] * 4 + [{"valid": True}])
        report = run_corpus(corpus, answerer=lambda case: None)
        self.assertEqual(report.unanswered, 5)
        self.assertTrue(any("unanswered" in p for p in report.problems()))

    def test_an_answer_that_is_not_a_verdict_is_a_failure(self):
        corpus = tiny([{"valid": False}] * 5)
        for junk in ({"id": "c0", "valid": "no"}, {"id": "c0", "verdict": "ALLOW"}, {"id": "c0"}, {"id": "c0", "crash": "KeyError"}):
            report = run_corpus(corpus, answerer=lambda case, junk=junk: junk if case["id"] == "c0" else self.refuse_all(case))
            self.assertEqual(report.unreadable, 1, junk)
            self.assertTrue(any("unreadable" in p for p in report.problems()), junk)

    def test_a_disagreement_is_a_failure(self):
        corpus = tiny([{"valid": False}] * 5)
        report = run_corpus(corpus, answerer=lambda case: {"id": case["id"], "valid": True})
        self.assertEqual(report.disagreed, 5)
        self.assertTrue(any("disagreed" in p for p in report.problems()))

    def test_a_missing_expected_code_is_a_disagreement_but_extra_codes_are_fine(self):
        corpus = tiny([{"valid": False, "codes": ["a"]}] * 5)
        self.assertEqual(run_corpus(corpus, answerer=lambda c: {"id": c["id"], "valid": False, "codes": ["b"]}).disagreed, 5)
        self.assertEqual(run_corpus(corpus, answerer=lambda c: {"id": c["id"], "valid": False, "codes": ["a", "b"]}).problems(), [])

    def test_a_low_refusal_share_is_a_failure(self):
        corpus = tiny([{"valid": True}] * 3 + [{"valid": False}] * 2)  # 40% refusals
        report = run_corpus(corpus, answerer=lambda c: {"id": c["id"], "valid": c["id"] in ("c0", "c1", "c2")})
        self.assertEqual((report.agreed, report.disagreed), (5, 0))
        self.assertTrue(any("refusal share" in p for p in report.problems()))

    def test_duplicate_ids_are_refused(self):
        corpus = tiny([{"valid": False}] * 2)
        corpus["sets"][0]["cases"][1]["id"] = "c0"
        with self.assertRaises(ValueError):
            run_corpus(corpus)

    def test_a_crash_inside_a_verifier_is_not_a_refusal(self):
        original = conformance.verify_receipt
        conformance.verify_receipt = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            a = answer({"id": "x", "set": "receipt", "input": {}})
        finally:
            conformance.verify_receipt = original
        self.assertIn("RuntimeError", a["crash"])
        self.assertNotIn("valid", a)
        self.assertEqual(judge({"valid": False}, a)[0], "unreadable")  # so a "refuse" case does not pass on a crash

    def test_known_failures_must_still_fail(self):
        refuse = [{"valid": False}] * 5
        corpus = tiny(refuse)
        corpus["sets"][0]["cases"][0]["known_failure"] = "documented"
        wrong_on_c0 = lambda c: {"id": c["id"], "valid": c["id"] == "c0"}  # noqa: E731
        self.assertEqual(run_corpus(corpus, answerer=wrong_on_c0).problems(), [])
        self.assertTrue(any("now pass" in p for p in run_corpus(corpus, answerer=self.refuse_all).problems()))
        self.assertTrue(any("unanswered" in p for p in run_corpus(corpus, answerer=lambda c: None).problems()))


if __name__ == "__main__":
    unittest.main()
