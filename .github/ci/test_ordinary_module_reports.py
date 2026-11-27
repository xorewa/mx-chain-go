"""Discover the isolated ordinary module-report synthetic tests in CI."""
import pathlib
import subprocess
import sys
import unittest


HELPER = (pathlib.Path(__file__).resolve().parents[1]
          / "coverage" / "ordinary" / "module-reports")


class OrdinaryModuleReportsDiscoveryTest(unittest.TestCase):
    def test_isolated_synthetic_suite(self):
        # Use CI's interpreter and propagate missing-suite and test failures.
        subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "-v",
             "test_report.ModuleReports"],
            cwd=HELPER, check=True,
        )
