import unittest

from diligenceos.identity import RegistryRecord, check_identity
from diligenceos.types import CheckStatus

REGISTRY = {
    "UK09456213": RegistryRecord(
        name="Meridian Robotics Ltd.",
        registration_id="UK09456213",
        status="active",
        jurisdiction="UK",
    ),
    "UK00011111": RegistryRecord(
        name="Old Shell Co.",
        registration_id="UK00011111",
        status="dissolved",
        jurisdiction="UK",
    ),
}


def lookup(registration_id: str):
    return REGISTRY.get(registration_id)


class CheckIdentityTest(unittest.TestCase):
    def test_unknown_id_is_flagged(self):
        finding = check_identity("Anyone Ltd.", "UK99999999", lookup)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("no registry record", finding.detail)

    def test_inactive_status_is_flagged(self):
        finding = check_identity("Old Shell Co.", "UK00011111", lookup)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("dissolved", finding.detail)

    def test_name_mismatch_is_flagged(self):
        finding = check_identity("Totally Different Name Ltd.", "UK09456213", lookup)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("does not match", finding.detail)

    def test_active_matching_name_passes(self):
        finding = check_identity("Meridian Robotics Ltd.", "UK09456213", lookup)
        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertIsNone(finding.detail)

    def test_name_match_is_whitespace_and_case_insensitive(self):
        finding = check_identity("  meridian robotics ltd.  ", "UK09456213", lookup)
        self.assertEqual(finding.status, CheckStatus.PASS)


if __name__ == "__main__":
    unittest.main()
