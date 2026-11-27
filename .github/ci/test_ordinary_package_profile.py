"""Synthetic structure checks for package diagnostic profiles."""
import unittest

from ordinary_package_profile import validate


PACKAGE = "example.test/toy"
HEADER = b"mode: atomic\n"
ROW = b"example.test/toy/report.go:1.1,1.2 1 0\n"


class OrdinaryPackageProfileTests(unittest.TestCase):
    def test_valid_zero_counts_equal_coordinates_and_repeated_blocks(self):
        validate(HEADER + ROW + b"example.test/toy/report.go:1.1,1.2 1 3\n"
                 + b"example.test/toy/empty.go:2.1,2.1 0 1\n", PACKAGE)
        validate(HEADER + ROW, PACKAGE)

    def test_missing_or_malformed_rows_fail(self):
        invalid = (
            b"", HEADER, HEADER + ROW[:-1], b"mode: count\n" + ROW,
            HEADER + ROW + b"broken\n", HEADER + ROW + b"\n", HEADER + b"\xff\n",
            HEADER + b"example.test/toy/report.go:0.1,1.2 1 1\n",
            HEADER + b"example.test/toy/report.go:2.1,1.2 1 1\n",
            HEADER + b"example.test/toy/report.go:1.1,1.2 1 -1\n",
            HEADER + b"example.test/toy/report.go:1.1,1.2 1 9223372036854775808\n",
            HEADER + ROW + b"example.test/toy/report.go:1.1,1.2 2 1\n",
            HEADER + b"example.test/other/report.go:1.1,1.2 1 1\n",
            HEADER + b"/toy/report.go:1.1,1.2 1 1\n",
            HEADER + b"example.test/toy/sub/report.go:1.1,1.2 1 1\n",
        )
        for raw in invalid:
            with self.subTest(case=invalid.index(raw)), self.assertRaises(ValueError):
                validate(raw, PACKAGE)


if __name__ == "__main__":
    unittest.main()
