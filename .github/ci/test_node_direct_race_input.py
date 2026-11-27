"""Current-attempt input binding checks; no Node tests execute."""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


GITHUB = pathlib.Path(__file__).resolve().parents[1]
TOOL = GITHUB / "coverage/ordinary/node-direct-race/diagnostic.py"


class NodeDirectRaceInputTests(unittest.TestCase):
    def sections(self):
        workflow = (GITHUB / "workflows/drwa-ci.yml").read_text()
        section = workflow.split("      - name: Allocate current Node direct race input directory", 1)[1]
        section = section.split("      - name: Upload read-only Node direct race diagnostic", 1)[0]
        allocate, rest = section.split("      - name: Produce reviewed Node direct race input", 1)
        producer, reader = rest.split("      - name: Read source-bound Node direct race diagnostic", 1)
        return allocate, producer, reader

    def test_unique_allocation_and_shared_input_binding(self):
        allocate, producer, reader = self.sections()
        binding = "NODE_DIRECT_RACE_INPUT: ${{ steps.node-direct-race-input.outcome == 'success' && steps.node-direct-race-input.outputs.directory || '' }}"
        self.assertIn(binding, producer)
        self.assertIn(binding, reader)
        self.assertIn("steps.node-direct-race-input.outcome == 'success' && steps.node-direct-race-input.outputs.directory != ''", producer)
        self.assertIn('diagnostic.py --output "$NODE_DIRECT_RACE_INPUT"', producer)
        self.assertIn('profile="${NODE_DIRECT_RACE_INPUT:+$NODE_DIRECT_RACE_INPUT/coverage.out}"', reader)
        self.assertIn('if [[ -n "$profile" && -f "$profile" ]] && unshare', reader)
        self.assertNotIn("pathlib.Path('node-direct-race-input')", reader)
        self.assertIn("continue-on-error: true", allocate)
        self.assertIn("continue-on-error: true", producer)
        self.assertIn("continue-on-error: true", reader)
        command = "\n".join(line[10:] for line in allocate.split("        run: |\n", 1)[1].splitlines())
        with tempfile.TemporaryDirectory(prefix="ordinary toy ") as folder:
            root = pathlib.Path(folder)
            temp = root / "runner temp"
            temp.mkdir()
            def run(label, directory):
                output = root / (label + ".output")
                env = dict(os.environ, RUNNER_TEMP=str(directory), GITHUB_OUTPUT=str(output))
                result = subprocess.run(["bash", "-euc", command], cwd=root, env=env,
                                        capture_output=True, text=True)
                return result, output
            one, first_out = run("one", temp)
            self.assertEqual(one.returncode, 0)
            first = pathlib.Path(first_out.read_text().removeprefix("directory=").strip())
            self.assertFalse(first.exists())
            first.mkdir()
            prior = first / "coverage.out"
            prior.write_bytes(b"prior toy input\n")
            two, second_out = run("two", temp)
            self.assertEqual(two.returncode, 0)
            second = pathlib.Path(second_out.read_text().removeprefix("directory=").strip())
            self.assertNotEqual(first, second)
            self.assertFalse(second.exists())
            bad = root / "not a directory"
            bad.write_text("toy")
            failed, failure_out = run("failed", bad)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(failure_out.exists())
            self.assertEqual(prior.read_bytes(), b"prior toy input\n")

    def test_producer_requires_explicit_path_and_does_not_use_old_default(self):
        spec = importlib.util.spec_from_file_location("node_direct_race_toy", TOOL)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        subject = "a" * 40
        with tempfile.TemporaryDirectory(prefix="ordinary toy ") as folder:
            output = pathlib.Path(folder).resolve() / "new" / "input"
            with patch.dict(os.environ, {"GITHUB_SHA": subject}), \
                 patch.object(tool.subprocess, "check_output", return_value=subject + "\n"), \
                 patch.object(tool, "produce") as produce:
                self.assertEqual(tool.main(["--output", str(output)]), 0)
                self.assertEqual(produce.call_count, 1)
                self.assertEqual(produce.call_args.args[1], output)
                self.assertEqual(produce.call_args.args[3], subject)
                produce.reset_mock()
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as absent:
                    tool.main([])
                self.assertEqual(absent.exception.code, 2)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(tool.main(["--output", "relative"]), 1)
                produce.assert_not_called()

    def test_reader_unavailable_input_ignores_previous_fixed_directory(self):
        _, _, reader = self.sections()
        command = "\n".join(line[10:] if line.startswith("          ") else line
                            for line in reader.split("        run: |\n", 1)[1].splitlines())
        for supplied in (False, True):
            with self.subTest(allocated_missing=supplied), tempfile.TemporaryDirectory(prefix="ordinary toy ") as folder:
                root = pathlib.Path(folder).resolve()
                # Copy only the approved static census and selector data. No
                # production code, toolchain or tests are invoked by this fixture.
                ordinary = root / ".github/coverage/ordinary"
                (ordinary / "node-direct-race").mkdir(parents=True)
                shutil.copyfile(GITHUB / "coverage/ordinary/node-direct-r25.json", ordinary / "node-direct-r25.json")
                shutil.copyfile(TOOL.parent / "selectors-r28.json", ordinary / "node-direct-race/selectors-r28.json")
                old = root / "node-direct-race-input"
                old.mkdir()
                stale = {"coverage.out": b"prior toy profile\n", "provenance.json": b"prior toy receipt\n"}
                for name, raw in stale.items():
                    (old / name).write_bytes(raw)
                temp = root / "runner temp"
                temp.mkdir()
                output = root / "step.output"
                stub = root / "unshare"
                stub.write_text("#!/bin/sh\n: > reporter-was-called\nexit 97\n")
                stub.chmod(0o755)
                new_input = root / "new attempt" / "input"
                env = dict(os.environ, RUNNER_TEMP=str(temp), GITHUB_OUTPUT=str(output),
                           NODE_DIRECT_RACE_INPUT=str(new_input) if supplied else "",
                           PATH=str(root) + os.pathsep + os.environ["PATH"])
                result = subprocess.run(["bash", "-euc", command], cwd=root, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertFalse((root / "reporter-was-called").exists())
                report_dir = pathlib.Path(output.read_text().removeprefix("directory=").strip())
                self.assertEqual(json.loads((report_dir / "report.json").read_text()),
                                 {"scope": "partial Node direct race read-only diagnostic", "status": "unavailable", "aggregate_statements": None})
                self.assertEqual(json.loads((report_dir / "provenance.json").read_text()),
                                 {"run_mode": "race", "status": "unavailable"})
                self.assertFalse((report_dir / "bound-manifest.json").exists())
                self.assertEqual({f.name: f.read_bytes() for f in old.iterdir()}, stale)


if __name__ == "__main__":
    unittest.main()
