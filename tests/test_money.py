import unittest

from diligenceos.types import Money


class MoneyTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(Money(24000000, "USD").to_dict(), {"amount_minor": 24000000, "currency": "USD"})
        self.assertEqual(Money.from_dict({"amount_minor": 0, "currency": "GBP"}), Money(0, "GBP"))

    def test_rejects_non_integers_bools_negatives_and_bad_codes(self):
        for args in ((240000.0, "USD"), (True, "USD"), ("5", "USD"), (-1, "USD"),
                     (5, "usd"), (5, "US"), (5, "USDD"), (5, "U5D"), (5, None)):
            with self.assertRaises(ValueError, msg=args):
                Money(*args)


if __name__ == "__main__":
    unittest.main()
