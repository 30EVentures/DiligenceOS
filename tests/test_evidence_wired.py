import json
import unittest

from diligenceos import api
from diligenceos.documents import SOURCE as DOC_SOURCE, scan_document
from diligenceos.engine import assemble_verdict
from diligenceos.evidence import EvidenceError, text_digest, verify_evidence
from diligenceos.pipeline import run_diligence
from diligenceos.receipt import issue_receipt, verify_receipt
from diligenceos.sanctions import SOURCE as SANC_SOURCE, SanctionsEntry, SanctionsList, screen_subject
from diligenceos.serialize import finding_from_dict, finding_to_dict
from diligenceos.store import Store
from diligenceos.track_record import Ledger
from diligenceos.types import CheckStatus, Evidence, Finding

TEXT = "Section 3: Termination. Liability Cap applies."


class EvidenceTypeTest(unittest.TestCase):
    def test_needs_exactly_one_of_quote_or_absent(self):
        with self.assertRaises(ValueError):
            Evidence("s", "d")
        with self.assertRaises(ValueError):
            Evidence("s", "d", quote="a", absent="b")


class DocumentEvidenceTest(unittest.TestCase):
    def test_absence_claim_verifies_against_original_text(self):
        finding = scan_document(TEXT)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        (ev,) = finding.evidence
        self.assertEqual((ev.source, ev.absent), (DOC_SOURCE, "indemnification"))
        self.assertEqual(verify_evidence(ev, TEXT), [])

    def test_fails_against_different_text(self):
        (ev,) = scan_document(TEXT).evidence
        self.assertTrue(verify_evidence(ev, TEXT + " edited"))

    def test_fails_when_clause_actually_present(self):
        (ev,) = scan_document(TEXT).evidence
        forged = Evidence(ev.source, text_digest(TEXT + " Indemnification."), absent="indemnification")
        self.assertTrue(any("claimed absent" in e for e in verify_evidence(forged, TEXT + " Indemnification.")))


class SanctionsEvidenceTest(unittest.TestCase):
    def test_flag_quotes_the_matched_entry_and_verifies(self):
        lst = SanctionsList((SanctionsEntry("Bad Actor Co", "SDN", ("BA Co",)),))
        finding = screen_subject("ba co", lst)
        (ev,) = finding.evidence
        self.assertEqual(ev.source, SANC_SOURCE)
        self.assertEqual(verify_evidence(ev, lst.source_text()), [])
        other = SanctionsList((SanctionsEntry("Someone Else", "SDN"),))
        self.assertTrue(verify_evidence(ev, other.source_text()))


class SerializeTest(unittest.TestCase):
    def test_evidence_round_trips(self):
        finding = scan_document(TEXT)
        self.assertEqual(finding_from_dict(finding_to_dict(finding)), finding)


class PipelineEnforcementTest(unittest.TestCase):
    def test_pipeline_runs_with_cited_flags(self):
        result = run_diligence(
            name="X", registration_id="1", sanctions_list=SanctionsList(),
            registry_lookup=lambda _: None, ledger=Ledger(), document_text=TEXT,
        )
        self.assertTrue(any(f.evidence for f in result.findings))

    def test_uncited_flag_from_a_non_exempt_category_is_refused(self):
        from diligenceos import pipeline
        original = pipeline.scan_document
        pipeline.scan_document = lambda text: Finding("document_scan", CheckStatus.FLAG, detail="vague")
        try:
            with self.assertRaises(EvidenceError):
                run_diligence(
                    name="X", registration_id="1", sanctions_list=SanctionsList(),
                    registry_lookup=lambda _: None, ledger=Ledger(), document_text=TEXT,
                )
        finally:
            pipeline.scan_document = original


class ReceiptEvidenceTest(unittest.TestCase):
    def receipt(self):
        finding = scan_document(TEXT)
        return issue_receipt(subject={"name": "X"}, inputs={}, result=assemble_verdict([finding]))

    def test_sources_recheck_and_unchecked_reporting(self):
        r = self.receipt()
        ok = verify_receipt(r, sources={DOC_SOURCE: TEXT})
        self.assertTrue(ok.valid, ok.errors)
        self.assertEqual(ok.unchecked, ())
        bad = verify_receipt(r, sources={DOC_SOURCE: "different"})
        self.assertFalse(bad.valid)
        none = verify_receipt(r)
        self.assertTrue(none.valid)
        self.assertEqual(none.unchecked, (DOC_SOURCE,))


class ApiEvidenceTest(unittest.TestCase):
    def test_verify_envelope_with_sources(self):
        store = Store.seeded_from_sample()
        req = {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
               "document_text": TEXT}
        _, _, out = api.handle("POST", "/v1/verdict", json.dumps(req).encode(), store)
        receipt = json.loads(out)
        env = {"receipt": receipt, "sources": {DOC_SOURCE: TEXT}}
        _, _, out = api.handle("POST", "/v1/verify", json.dumps(env).encode(), store)
        self.assertEqual(json.loads(out)["valid"], True)
        env["sources"][DOC_SOURCE] = "tampered"
        _, _, out = api.handle("POST", "/v1/verify", json.dumps(env).encode(), store)
        self.assertEqual(json.loads(out)["valid"], False)
        env["sources"] = {"x": 1}
        status, _, _ = api.handle("POST", "/v1/verify", json.dumps(env).encode(), store)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
