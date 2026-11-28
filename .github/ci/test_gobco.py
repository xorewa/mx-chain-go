import json
import io
import pathlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import gobco


class GobcoReportingTests(unittest.TestCase):
    def test_additive_diagnostic_evidence_classes(self):
        def event(action, **fields):
            return json.dumps({"Action": action, "Package": "example.test/toy", **fields})

        named = event("fail", Test="TestDisplay")
        package = event("fail")
        build = event("output", Output="toy [build failed]\n")
        setup = event("output", Output="toy [setup failed]\n")
        tool_stack = "\nmain.compile()\n\t/tmp/gobco-source/toy.go:10 +0x0\n"
        compile_panic = "panic: toy.go:3:4: undefined: label" + tool_stack
        duplicate_panic = "panic: toy.go:3:4: label redeclared in this block" + tool_stack
        member_panic = "panic: toy.go:3:4: label.Text undefined (type Toy has no field Text)" + tool_stack
        rows = [
            ("measured", 0, True, "", "", [], 0, 0),
            ("missing", 0, False, "", "", ["missing_report"], 0, 0),
            ("unknown", 2, False, "FAIL toy\n", "panic: unspecified",
             ["unknown_failure", "missing_report"], 0, 0),
            ("tool and compile", 2, False, "", compile_panic,
             ["tool_error", "compile_or_setup", "missing_report"], 0, 0),
            ("tool duplicate", 2, False, "", duplicate_panic,
             ["tool_error", "compile_or_setup", "missing_report"], 0, 0),
            ("tool missing member", 2, False, "", member_panic,
             ["tool_error", "compile_or_setup", "missing_report"], 0, 0),
            ("tool only", 2, False, "", "panic: toy failure" + tool_stack,
             ["tool_error", "missing_report"], 0, 0),
            ("build", 1, False, build + "\n" + package, "",
             ["compile_or_setup", "missing_report"], 0, 1),
            ("setup", 1, False, setup + "\n" + package, "",
             ["compile_or_setup", "missing_report"], 0, 1),
            ("named", 1, False, named + "\n" + package, "",
             ["named_test_failure", "missing_report"], 1, 1),
            ("named with report", 1, True, named, "",
             ["named_test_failure"], 1, 0),
            ("unknown with report", 1, True, package, "",
             ["unknown_failure"], 0, 1),
            ("mixed", 2, False, named + "\n" + build, compile_panic,
             ["tool_error", "compile_or_setup", "named_test_failure", "missing_report"], 1, 0),
            ("unstructured", 1, False,
             "\n".join(["not JSON", "[]", json.dumps({"Action": "fail"}),
                        event("fail", Test=12), event("output", Output=12),
                        event("output", Test="TestDisplay", Output="toy [build failed]")]),
             "", ["unknown_failure", "missing_report"], 0, 0),
        ]
        for desc, code, report, stdout, stderr, classes, n, p in rows:
            with self.subTest(desc=desc):
                result = gobco.classify_diagnostic(code, report, stdout, stderr)
                self.assertEqual(result, {
                    "measurement": "measured" if code == 0 and report else "unknown",
                    "evidence_classes": classes,
                    "named_test_failure_events": n,
                    "package_failure_events": p,
                })

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
            self.assertEqual(summary[0]["diagnostic"]["measurement"], "measured")
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
            self.assertEqual([item["diagnostic"]["evidence_classes"] for item in summary],
                             [[], ["unknown_failure", "missing_report"], ["missing_report"]])
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

    def test_named_failure_evidence_keeps_raw_log_separate(self):
        with tempfile.TemporaryDirectory() as folder:
            output = pathlib.Path(folder) / "report"
            raw = b'{"Action":"fail","Package":"example.test/toy","Test":"TestDisplay"}\n'

            def fake_run(argv, *, env, stdout, stderr):
                stdout.write(raw + b"Branch coverage: 1/2\n")
                return subprocess.CompletedProcess(argv, 1)

            printed = io.StringIO()
            with patch("sys.argv", ["gobco.py", "--binary", "/unused/gobco",
                                    "--output", str(output), "./toy"]), \
                    patch("gobco.subprocess.run", side_effect=fake_run), redirect_stdout(printed):
                self.assertEqual(gobco.main(), 1)
            summary = json.loads((output / "summary.json").read_text())[0]
            self.assertEqual(summary["status"], "UNKNOWN: tool/test failure or missing branch report")
            self.assertEqual(summary["branches"], {"covered": 1, "total": 2})
            self.assertEqual(summary["diagnostic"], {
                "measurement": "unknown", "evidence_classes": ["named_test_failure"],
                "named_test_failure_events": 1, "package_failure_events": 0,
            })
            self.assertEqual(json.loads(printed.getvalue()), summary)
            self.assertNotIn("TestDisplay", printed.getvalue())
            self.assertEqual((output / "0" / "stdout").read_bytes(), raw + b"Branch coverage: 1/2\n")


class GobcoKnownUnmeasuredTests(unittest.TestCase):
    """The record of the tool's limits turns the trial green only when the
    run reproduces it exactly; every difference keeps the failure exit."""

    LIMIT = ["tool_error", "compile_or_setup", "missing_report"]
    PANIC = (b"panic: toy_test.go:3:4: undefined: toy.Exported\n"
             b"main.compile()\n\t/tmp/gobco-source/toy.go:10 +0x0\n")

    def run_trial(self, record, behaviour, packages=("./measured", "./limited")):
        with tempfile.TemporaryDirectory() as folder:
            output = pathlib.Path(folder) / "report"
            known = pathlib.Path(folder) / "known.json"
            known.write_text(json.dumps({"packages": record}))

            def fake_run(argv, *, env, stdout, stderr):
                kind = behaviour[argv[-1]]
                if kind == "measured":
                    stdout.write(b"Branch coverage: 1/2\n")
                    return subprocess.CompletedProcess(argv, 0)
                if kind == "limit":
                    stderr.write(self.PANIC)
                    return subprocess.CompletedProcess(argv, 2)
                if kind == "named":
                    stdout.write(b'{"Action":"fail","Package":"example.test/toy","Test":"TestDisplay"}\n')
                    return subprocess.CompletedProcess(argv, 1)
                return subprocess.CompletedProcess(argv, 1)

            printed = io.StringIO()
            with patch("sys.argv", ["gobco.py", "--binary", "/unused/gobco", "--known-unmeasured", str(known),
                                    "--output", str(output), *packages]), \
                    patch("gobco.subprocess.run", side_effect=fake_run), redirect_stdout(printed):
                code = gobco.main()
            summary = json.loads((output / "summary.json").read_text())
            return code, summary, json.loads((output / "known_unmeasured.json").read_text())

    def test_exact_record_succeeds_and_stays_unknown(self):
        # A recorded package outside this shard's selection is not expected here.
        record = {"./limited": self.LIMIT, "./other-shard": self.LIMIT}
        code, summary, report = self.run_trial(record, {"./measured": "measured", "./limited": "limit"})
        self.assertEqual(code, 0)
        self.assertEqual(report, {"recorded": ["./limited"], "observed": ["./limited"], "differences": []})
        self.assertEqual(summary[0]["status"], "measured")
        self.assertTrue(summary[1]["status"].startswith("UNKNOWN"))
        self.assertIsNone(summary[1]["branches"])

    def test_every_difference_keeps_the_failure_exit(self):
        limit = {"./limited": self.LIMIT}
        rows = [
            ("a package that newly cannot be measured", limit, {"./measured": "limit", "./limited": "limit"}, ["./measured"]),
            ("a recorded package that now can be measured", limit, {"./measured": "measured", "./limited": "measured"}, ["./limited"]),
            ("a test failure in a recorded package", limit, {"./measured": "measured", "./limited": "named"}, ["./limited"]),
            ("a test failure in a measured package", limit, {"./measured": "named", "./limited": "limit"}, ["./measured"]),
            ("an unclassified failure in a recorded package", limit, {"./measured": "measured", "./limited": "other"}, ["./limited"]),
            ("an empty record", {}, {"./measured": "measured", "./limited": "limit"}, ["./limited"]),
        ]
        for desc, record, behaviour, differences in rows:
            with self.subTest(desc=desc):
                code, _, report = self.run_trial(record, behaviour)
                self.assertEqual(code, 1)
                self.assertEqual(report["differences"], differences)

    def test_only_a_tool_limit_can_be_recorded(self):
        for classes in (["named_test_failure", "missing_report"], ["unknown_failure", "missing_report"],
                        ["tool_error"], [], "tool_error"):
            with self.subTest(classes=classes):
                with self.assertRaises(SystemExit):
                    self.run_trial({"./limited": classes}, {"./measured": "measured", "./limited": "limit"})

    def test_the_committed_record_is_recordable(self):
        record = json.loads((pathlib.Path(gobco.__file__).parent / "gobco_known_unmeasured.json").read_text())
        self.assertEqual(len(record["packages"]), 35)
        for package, classes in record["packages"].items():
            self.assertTrue(package.startswith("./"), package)
            self.assertIn("missing_report", classes)
            self.assertLessEqual(set(classes), {"tool_error", "compile_or_setup", "missing_report"})


if __name__ == "__main__":
    unittest.main()
