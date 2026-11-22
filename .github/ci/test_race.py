import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from race import FATAL, HOOK, MODULE, classify, race_commands, execute


class RacePolicyTests(unittest.TestCase):
    def test_split_commands_preserve_each_exit_and_keep_failures(self):
        commands = [["go", "test", "./process"], ["go", "test", "./node"]]
        for codes, expected in [([0, 0], 0), ([1, 0], 1), ([0, 1], 1), ([2, 0], 2)]:
            with tempfile.TemporaryDirectory() as folder:
                with patch("race.subprocess.run", side_effect=[subprocess.CompletedProcess(c, e) for c, e in zip(commands, codes)]) as run:
                    summary = execute(commands, pathlib.Path(folder), "fixture")
                self.assertEqual(run.call_count, 2)
                self.assertEqual(summary["exit"], expected)
                self.assertEqual([r["exit"] for r in summary["commands"]], codes)
                self.assertEqual([r["argv"] for r in summary["commands"]], commands)

    def test_skip_is_exact_and_only_in_separate_node_commands(self):
        for flags in [[], ["-gcflags=all=-d=checkptr=0"], ["-run=^$"]]:
            commands = race_commands(["./factory/core", "./node", "./process"], flags)
            self.assertEqual(len(commands), 2)
            self.assertEqual(commands[0], ["go", "test", "-race", "-json", "-count=1", *flags,
                                            "./factory/core", "./process"])
            self.assertEqual(commands[1], ["go", "test", "-race", "-json", "-count=1", *flags,
                                            "-skip=^TestWaitForSignal$", "./node"])
        self.assertEqual(race_commands(["./process"], []),
                         [["go", "test", "-race", "-json", "-count=1", "./process"]])

    def fixture(self, package="./node"):
        name = MODULE + package[2:]
        text = (FATAL + "\n\ngoroutine 19 gp=0xc00 m=0 mp=0x123 [running, locked to thread]:\n"
                "runtime.throw(0x1)\n\truntime/panic.go:1\n"
                "runtime.checkptrArithmetic(0x1)\n\truntime/checkptr.go:69\n" + HOOK + "...)\n\twasmer2/helper.go:1\n")
        return [{"Action": "output", "Package": name, "Test": "TestVM", "Output": text},
                {"Action": "fail", "Package": name}]

    def check(self, events, code=1, package="./node", stderr=""):
        return classify("\n".join(json.dumps(e) for e in events), stderr, code, [package])

    def test_only_known_active_abort_is_tolerated(self):
        r = self.check(self.fixture())
        self.assertEqual(r["errors"], [])
        self.assertEqual(r["known_wasmer2_aborts"], [MODULE + "node"])
        self.assertTrue(self.check(self.fixture("./process"), package="./process")["errors"])

    def test_signature_cannot_hide_other_failure(self):
        for extra in ["WARNING: DATA RACE\n", "--- FAIL: TestOther (0.00s)\n",
                      "panic: unexpected\n", "fatal error: another error\n", "[build failed]\n"]:
            with self.subTest(extra=extra):
                e = self.fixture()
                e[0]["Output"] += extra
                self.assertTrue(self.check(e)["errors"])
        e = self.fixture()
        e.insert(0, {"Action": "fail", "Package": MODULE + "node", "Test": "TestOther"})
        self.assertTrue(self.check(e)["errors"])

    def test_signature_must_be_on_active_checkptr_stack(self):
        for old, new in [("runtime.checkptrArithmetic(", "runtime.someOtherFailure("),
                         (HOOK, "unrelated.function("), ("[running", "[waiting")]:
            e = self.fixture()
            e[0]["Output"] = e[0]["Output"].replace(old, new) + "\n" + HOOK
            self.assertTrue(self.check(e)["errors"])

    def test_exit_stderr_and_missing_results_reject(self):
        self.assertTrue(self.check(self.fixture(), code=0)["errors"])
        self.assertTrue(self.check(self.fixture(), code=2)["errors"])
        self.assertTrue(self.check(self.fixture(), stderr="compiler failed")["errors"])
        self.assertTrue(self.check([])["errors"])
        self.assertTrue(classify("garbage", "", 1, ["./node"])["errors"])
        self.assertTrue(self.check(self.fixture() * 2)["errors"])

    def test_pass_skip_and_contradictory_results(self):
        for action in ["pass", "skip"]:
            self.assertEqual(self.check([{"Action": action, "Package": MODULE + "node"}], code=0)["errors"], [])
        e = self.fixture()
        e[-1]["Action"] = "pass"
        self.assertTrue(self.check(e, code=0)["errors"])

    def test_driver_runs_both_labels_and_rejects_adjusted_failure(self):
        # An independent executable fixture records actual subprocess arguments.
        # It returns the known default abort and toggles the adjusted run's exit.
        script = pathlib.Path(__file__).with_name("race.py").resolve()
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            fake = root / "go"
            events = self.fixture()
            fake.write_text("#!" + sys.executable + "\nimport json,os,sys\n"
                            "adjusted='-gcflags=all=-d=checkptr=0' in sys.argv\n"
                            "with open(os.environ['CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                            "if not adjusted:\n"
                            " print(" + repr("\n".join(map(json.dumps, events))) + ")\n sys.exit(1)\n"
                            "sys.exit(int(os.environ['ADJUSTED_EXIT']))\n")
            fake.chmod(0o700)
            for adjusted_exit in (0, 1, 2):
                target = root / str(adjusted_exit)
                calls = root / (str(adjusted_exit) + ".calls")
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           ADJUSTED_EXIT=str(adjusted_exit), CALLS=str(calls))
                run = subprocess.run([sys.executable, "-B", str(script), "--output", str(target), "./node"],
                                     env=env, capture_output=True, text=True)
                self.assertEqual(run.returncode, int(adjusted_exit != 0), run.stderr)
                commands = list(map(json.loads, calls.read_text().splitlines()))
                self.assertEqual(len(commands), 2)
                self.assertNotIn("-gcflags=all=-d=checkptr=0", commands[0])
                self.assertIn("-gcflags=all=-d=checkptr=0", commands[1])
                for command in commands:
                    self.assertIn("-skip=^TestWaitForSignal$", command)
                self.assertTrue(all(not any("cover" in arg for arg in command) for command in commands))
                summary = json.loads((target / "summary.json").read_text())
                self.assertEqual(summary["default"]["exit"], 1)
                self.assertEqual(summary["checkptr_disabled_race"]["exit"], adjusted_exit)


if __name__ == "__main__":
    unittest.main()
