import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


class GobcoPolicyTests(unittest.TestCase):
    def test_driver_excludes_only_mock_elements_and_preserves_failures(self):
        script = pathlib.Path(__file__).with_name("gobco.py").resolve()
        packages = ["./mock", "./api/mock", "./a/mock/b", "./process",
                    "./mockery", "./a/mocks", "./integrationTests", "./testscommon"]
        excluded = [{"package": p, "exit": None, "branches": None,
                     "status": "excluded by policy: test helper (path element mock)"}
                    for p in packages[:3]]
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            fake = root / "gobco"
            fake.write_text("#!" + sys.executable + "\nimport json,os,sys\n"
                            "with open(os.environ['CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                            "print(os.environ['REPORT'])\n"
                            "sys.exit(int(os.environ['TOOL_EXIT']))\n")
            fake.chmod(0o700)
            for case, code, report in [("measured", 0, "Branch coverage: 3/7"),
                                       ("exit2", 2, "Branch coverage: 3/7"),
                                       ("missing", 0, "no report")]:
                with self.subTest(case=case):
                    target = root / case
                    calls = root / (case + ".calls")
                    env = dict(os.environ, CALLS=str(calls), REPORT=report, TOOL_EXIT=str(code))
                    run = subprocess.run([sys.executable, "-I", "-B", str(script),
                                          "--binary", str(fake), "--output", str(target), *packages],
                                         env=env, capture_output=True, text=True)
                    self.assertEqual(run.returncode, int(case != "measured"), run.stderr)
                    rows = json.loads((target / "summary.json").read_text())
                    self.assertEqual(list(map(json.loads, run.stdout.splitlines())), rows)
                    self.assertEqual(rows[:3], excluded)
                    self.assertEqual([row["package"] for row in rows], packages)
                    commands = list(map(json.loads, calls.read_text().splitlines()))
                    self.assertEqual([command[-1] for command in commands], packages[3:])
                    for row in rows[3:]:
                        self.assertEqual(row["exit"], code)
                        self.assertEqual(row["branches"], None if case == "missing" else
                                         {"covered": 3, "total": 7})
                        self.assertEqual(row["status"], "measured" if case == "measured" else
                                         "UNKNOWN: tool/test failure or missing branch report")


if __name__ == "__main__":
    unittest.main()
