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

    def test_the_upper_bound_is_two_to_the_53_minus_1(self):
        from diligenceos.types import MAX_AMOUNT_MINOR
        self.assertEqual(MAX_AMOUNT_MINOR, 9007199254740991)
        self.assertEqual(Money(MAX_AMOUNT_MINOR, "USD").amount_minor, 9007199254740991)
        for amount in (MAX_AMOUNT_MINOR + 1, 2**63 - 1, 2**64, 2**200):
            with self.assertRaises(ValueError, msg=amount):
                Money(amount, "USD")


if __name__ == "__main__":
    unittest.main()
