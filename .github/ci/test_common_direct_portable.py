"""Synthetic portable-output lifecycle checks; no diagnostic or product run."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


WRAPPER = (Path(__file__).resolve().parents[1] / "coverage" / "ordinary"
           / "common-direct" / "run-portable.sh")


class CommonDirectPortableTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.runner_temp = self.base / "runner"
        self.runner_temp.mkdir()
        self.github_output = self.base / "github-output"
        self.env = dict(os.environ, RUNNER_TEMP=str(self.runner_temp),
                        GITHUB_OUTPUT=str(self.github_output))

    def run_toy(self, body):
        # The wrapper appends --output <fresh directory> to the toy command.
        code = ("from pathlib import Path\nimport sys\n"
                "assert sys.argv[1] == '--output'\n"
                "out = Path(sys.argv[2])\n"
                "assert not out.exists()\n" + body)
        return subprocess.run(["bash", str(WRAPPER), sys.executable, "-B",
                               "-c", code], cwd=self.base, env=self.env,
                              capture_output=True, check=False)

    def portable(self):
        key, value = self.github_output.read_text().splitlines()[-1].split("=", 1)
        self.assertEqual(key, "portable")
        path = Path(value)
        self.assertTrue(path.is_relative_to(self.runner_temp))
        self.assertEqual(path.name, "portable")
        return path

    def assert_unavailable(self, path):
        self.assertEqual({p.name for p in path.iterdir()}, {"summary.json"})
        summary = json.loads((path / "summary.json").read_bytes())
        for mode in ("normal", "race"):
            self.assertEqual(summary[mode], {"status": "unavailable",
                                             "statements": None})

    def test_failed_attempt_does_not_reuse_or_remove_older_export(self):
        historical = self.base / "common-direct-report" / "portable"
        historical.mkdir(parents=True)
        prior_summary = b'{"normal":{"status":"measured","statements":{"covered":1,"total":2}}}'
        (historical / "summary.json").write_bytes(prior_summary)
        (historical / "normal.cover").write_bytes(b"prior profile")
        first = self.run_toy("sys.exit(7)\n")
        self.assertEqual(first.returncode, 7, first.stderr)
        first_path = self.portable()
        self.assert_unavailable(first_path)
        second = self.run_toy("sys.exit(9)\n")
        self.assertEqual(second.returncode, 9, second.stderr)
        second_path = self.portable()
        self.assertNotEqual(first_path, second_path)
        self.assert_unavailable(first_path)
        self.assert_unavailable(second_path)
        self.assertEqual((historical / "summary.json").read_bytes(), prior_summary)
        self.assertEqual((historical / "normal.cover").read_bytes(), b"prior profile")

    def test_interrupted_export_is_unavailable_and_status_preserved(self):
        for code in (0, 12):
            with self.subTest(exit=code):
                result = self.run_toy(
                    "(out / 'portable').mkdir(parents=True)\n"
                    "(out / 'portable' / 'normal.cover').write_bytes(b'toy')\n"
                    "(out / 'portable' / 'race.report.json').write_bytes(b'toy')\n"
                    f"sys.exit({code})\n")
                self.assertEqual(result.returncode, code or 1, result.stderr)
                self.assert_unavailable(self.portable())

    def test_completed_current_export_is_retained_even_with_partial_status(self):
        for code in (0, 1):
            with self.subTest(exit=code):
                result = self.run_toy(
                    "(out / 'portable').mkdir(parents=True)\n"
                    "(out / 'portable' / 'summary.json').write_bytes(b'toy summary')\n"
                    "(out / 'portable' / 'normal.cover').write_bytes(b'toy profile')\n"
                    f"sys.exit({code})\n")
                self.assertEqual(result.returncode, code, result.stderr)
                path = self.portable()
                self.assertEqual((path / "summary.json").read_bytes(), b"toy summary")
                self.assertEqual((path / "normal.cover").read_bytes(), b"toy profile")

    def test_failed_staging_has_no_publish_path(self):
        self.env["RUNNER_TEMP"] = str(self.base / "absent")
        result = self.run_toy("raise AssertionError('must not run')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.github_output.exists())
        self.assertNotIn(b"must not run", result.stderr)
