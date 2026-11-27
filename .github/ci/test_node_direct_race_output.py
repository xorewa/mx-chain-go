"""Check only the isolated Node race diagnostic report output binding."""
import os
import pathlib
import subprocess
import tempfile
import unittest


class NodeDirectRaceOutputTests(unittest.TestCase):
    def test_report_and_upload_bind_current_attempt_even_on_failure(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1] / "workflows/drwa-ci.yml").read_text()
        section = workflow.split("      - name: Read source-bound Node direct race diagnostic", 1)[1]
        section = section.split("      - name: Report Common65 direct display subset", 1)[0]
        report, upload = section.split("      - name: Upload read-only Node direct race diagnostic", 1)
        self.assertIn("id: node-direct-race-report", report)
        self.assertIn("continue-on-error: true", report)
        self.assertIn("continue-on-error: true", upload)
        self.assertIn("always() && steps.isolation-preflight.outcome == 'success' && steps.node-direct-race-report.outputs.directory != ''", upload)
        self.assertNotIn("steps.node-direct-race-report.outcome", upload)
        paths = upload.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], [
            "${{ steps.node-direct-race-report.outputs.directory }}/scope.txt",
            "${{ steps.node-direct-race-report.outputs.directory }}/provenance.json",
            "${{ steps.node-direct-race-report.outputs.directory }}/bound-manifest.json",
            "${{ steps.node-direct-race-report.outputs.directory }}/report.json",
        ])
        self.assertNotIn("ordinary-node-race-report/", section)
        prefix = report.split("        run: |\n", 1)[1].split('          cat > "$output/scope.txt"', 1)[0]
        self.assertTrue(all(line.startswith("          ") for line in prefix.splitlines()))
        command = "\n".join(line[10:] for line in prefix.splitlines())
        with tempfile.TemporaryDirectory(prefix="ordinary toy ") as folder:
            root = pathlib.Path(folder)
            temp = root / "runner temp"
            temp.mkdir()
            previous = root / "ordinary-node-race-report"
            previous.mkdir()
            old = previous / "report.json"
            old.write_bytes(b"prior toy report\n")
            def allocate(label, path, suffix=""):
                output = root / (label + ".output")
                env = dict(os.environ, RUNNER_TEMP=str(path), GITHUB_OUTPUT=str(output))
                result = subprocess.run(["bash", "-euc", command + suffix], cwd=root, env=env,
                                        capture_output=True, text=True)
                return result, output
            first, first_output = allocate("first", temp)
            self.assertEqual(first.returncode, 0)
            first_dir = pathlib.Path(first_output.read_text().removeprefix("directory=").strip())
            self.assertEqual(first_dir.parent, temp)
            self.assertEqual(list(first_dir.iterdir()), [])
            (first_dir / "report.json").write_bytes(b"earlier invocation toy report\n")
            # The existing optional fallback returns nonzero but its current
            # partial artifact path remains available for always-upload.
            second, second_output = allocate("second", temp, '\nprintf toy > "$output/report.json"; exit 1')
            self.assertEqual(second.returncode, 1)
            second_dir = pathlib.Path(second_output.read_text().removeprefix("directory=").strip())
            self.assertEqual(second_dir.parent, temp)
            self.assertNotEqual(first_dir, second_dir)
            self.assertEqual((second_dir / "report.json").read_bytes(), b"toy")
            self.assertEqual((first_dir / "report.json").read_bytes(), b"earlier invocation toy report\n")
            self.assertEqual(old.read_bytes(), b"prior toy report\n")
            bad = root / "not a directory"
            bad.write_text("toy")
            failure, failure_output = allocate("failure", bad)
            self.assertNotEqual(failure.returncode, 0)
            self.assertFalse(failure_output.exists())
            self.assertEqual(old.read_bytes(), b"prior toy report\n")


if __name__ == "__main__":
    unittest.main()
