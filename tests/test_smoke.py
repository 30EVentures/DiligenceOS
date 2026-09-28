import unittest

import diligenceos


class SmokeTest(unittest.TestCase):
    def test_package_imports(self):
        self.assertTrue(hasattr(diligenceos, "__doc__"))


if __name__ == "__main__":
    unittest.main()
