import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import gobco


class GobcoReportingTests(unittest.TestCase):
    def test_interrupted_publish_keeps_previous_complete_json(self):
        with tempfile.TemporaryDirectory() as folder:
            output = pathlib.Path(folder) / "summary.json"
            gobco.publish_report(output, [{"package": "./first"}])
            with patch.object(pathlib.Path, "replace", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    gobco.publish_report(output, [{"package": "./second"}])
            self.assertEqual(json.loads(output.read_text()), [{"package": "./first"}])

    def test_interrupted_trial_keeps_completed_prefix(self):
        with tempfile.TemporaryDirectory() as folder:
            output = pathlib.Path(folder) / "report"
            packages = ["./first", "./second", "./third"]

            def fake_run(argv, *, env, stdout, stderr):
                self.assertEqual(json.loads((output / "plan.json").read_text()),
                                 {"packages": packages})
                summary = json.loads((output / "summary.json").read_text())
                if argv[-1] == "./first":
                    self.assertEqual(summary, [])
                    stdout.write(b"Branch coverage: 2/3\n")
                    return subprocess.CompletedProcess(argv, 0)
                self.assertEqual([item["package"] for item in summary], ["./first"])
                stdout.write(b"partial output\n")
                raise KeyboardInterrupt

            with patch("sys.argv", ["gobco.py", "--binary", "/unused/gobco",
                                    "--output", str(output), *packages]), \
                    patch("gobco.subprocess.run", side_effect=fake_run) as run:
                with self.assertRaises(KeyboardInterrupt):
                    gobco.main()

            self.assertEqual(run.call_count, 2)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(len(summary), 1)
            self.assertEqual(summary[0]["branches"], {"covered": 2, "total": 3})
            self.assertEqual(summary[0]["status"], "measured")
            self.assertEqual((output / "1" / "stdout").read_bytes(), b"partial output\n")
            self.assertFalse((output / "2").exists())

    def test_complete_trial_retains_unknown_and_failure_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            output = pathlib.Path(folder) / "report"
            packages = ["./first", "./second", "./third"]

            def fake_run(argv, *, env, stdout, stderr):
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(len(summary), packages.index(argv[-1]))
                if argv[-1] == "./first":
                    stdout.write(b"Branch coverage: 1/1\n")
                    return subprocess.CompletedProcess(argv, 0)
                if argv[-1] == "./second":
                    stderr.write(b"synthetic tool failure\n")
                    return subprocess.CompletedProcess(argv, 2)
                return subprocess.CompletedProcess(argv, 0)

            with patch("sys.argv", ["gobco.py", "--binary", "/unused/gobco",
                                    "--output", str(output), *packages]), \
                    patch("gobco.subprocess.run", side_effect=fake_run):
                self.assertEqual(gobco.main(), 1)

            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual([item["package"] for item in summary], packages)
            self.assertEqual([item["exit"] for item in summary], [0, 2, 0])
            self.assertEqual([item["branches"] for item in summary],
                             [{"covered": 1, "total": 1}, None, None])
            self.assertEqual(summary[0]["status"], "measured")
            self.assertTrue(all(item["status"].startswith("UNKNOWN") for item in summary[1:]))
            self.assertEqual((output / "1" / "stderr").read_bytes(), b"synthetic tool failure\n")

    def test_complete_measured_trial_keeps_success_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            output = pathlib.Path(folder) / "report"

            def fake_run(argv, *, env, stdout, stderr):
                stdout.write(b"Branch coverage: 1/2\n")
                return subprocess.CompletedProcess(argv, 0)

            with patch("sys.argv", ["gobco.py", "--binary", "/unused/gobco",
                                    "--output", str(output), "./one"]), \
                    patch("gobco.subprocess.run", side_effect=fake_run):
                self.assertEqual(gobco.main(), 0)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary[0]["status"], "measured")
            self.assertEqual(summary[0]["branches"], {"covered": 1, "total": 2})


if __name__ == "__main__":
    unittest.main()
