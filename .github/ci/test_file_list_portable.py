"""Discover the isolated file-list portability toy tests in CI."""
import pathlib
import subprocess
import sys
import unittest


HELPER = (pathlib.Path(__file__).resolve().parents[1]
          / "coverage" / "ordinary" / "file-list-portable")


class FileListPortableDiscoveryTest(unittest.TestCase):
    def test_isolated_synthetic_suite(self):
        # Use the exact interpreter running CI discovery. Isolate the test
        # import directory; the hyphenated helper is not a Python package.
        # A missing suite or nonzero child exit must fail this CI test.
        subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "-v",
             "test_normalize.NormalizeTests"],
            cwd=HELPER, check=True,
        )
