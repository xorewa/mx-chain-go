"""Exercise only the report-output shell blocks with local synthetic files."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "drwa-ci.yml"
OBSERVE = "Observe optional normal coverage input before primary"
ALLOCATE = "Allocate current ordinary normal diagnostic output"
ROSTER = "Report standard-token roster package coverage (diagnostic only)"
DIRECT = "Report reviewed Node direct ordinary subset (partial diagnostic only)"
UPLOAD = "Upload diagnostic standard-token roster reports"
OUTPUT = "${{ steps.ordinary-normal-output.outputs.directory }}"
FILES = {"input.json", "scope.txt", "node.json", "common.json", "node-direct-scope.txt",
         "node-direct-r25.json", "node-direct-r25-bound-manifest.json"}


def step(name):
    text = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
    return text.split("      - name: ", 1)[0]


def script(name):
    return textwrap.dedent(step(name).split("        run: |\n", 1)[1])


class OrdinaryNormalOutputsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.runner = self.base / "runner temp"
        self.runner.mkdir()
        self.output = self.base / "github-output"
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        # No actual coverage reporter: the local stub returns a tiny JSON
        # object or a nonzero status, selected by a generic toy setting.
        go = bin_dir / "go"
        go.write_text("#!/bin/sh\n"
                      "printf 'called\\n' >> toy-reporter-calls\n"
                      "case \"$*\" in *coverage-input.cover*) ;; *) exit 99;; esac\n"
                      "case \"$*\" in *'-functions'*) group=direct;; "
                      "*'toy/node'*) group=node;; *) group=common;; esac\n"
                      "if [ \"$group\" = \"$TOY_FAIL\" ]; then "
                      "printf 'partial toy output'; exit 7; fi\n"
                      "printf '{\"group\":\"%s\",\"value\":\"toy\"}\\n' \"$group\"\n")
        go.chmod(0o755)
        self.env = dict(os.environ, RUNNER_TEMP=str(self.runner),
                        GITHUB_OUTPUT=str(self.output),
                        PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                        NODE_REPORT_PACKAGES="toy/node",
                        COMMON_REPORT_PACKAGES="toy/common", TOY_FAIL="")
        self.census = self.base / ".github/coverage/ordinary/node-direct-r25.json"
        self.census.parent.mkdir(parents=True)
        self.census.write_text('{"toy": true}')
        self.profile = self.base / "coverage.out"
        self.env.update(ORDINARY_PROFILE_BEFORE="absent", ORDINARY_PRIMARY_OUTCOME="success")
        self.profile.write_bytes(b"toy profile")

    def run_block(self, name):
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script(name)],
                              cwd=self.base, env=self.env, capture_output=True)

    def allocate(self):
        result = self.run_block(ALLOCATE)
        self.assertEqual(result.returncode, 0, result.stderr)
        key, value = self.output.read_text().splitlines()[-1].split("=", 1)
        self.assertEqual(key, "directory")
        path = Path(value)
        self.assertTrue(path.is_relative_to(self.runner))
        self.assertTrue((path / "input.json").is_file())
        self.env["ORDINARY_REPORT_DIRECTORY"] = str(path)
        return path

    def test_failed_roster_does_not_reuse_prior_report(self):
        historical = self.base / "ordinary-coverage-report"
        historical.mkdir()
        (historical / "node.json").write_bytes(b'{"old":true}')
        (historical / "node-direct-r25-bound-manifest.json").write_bytes(b"old manifest")
        first = self.allocate()
        self.assertEqual(self.run_block(ROSTER).returncode, 0)
        self.assertEqual(self.run_block(DIRECT).returncode, 0)
        prior = {p.name: p.read_bytes() for p in first.iterdir()}
        self.assertEqual(set(prior), FILES | {"coverage-input.cover"})

        second = self.allocate()
        self.assertNotEqual(first, second)
        self.env["TOY_FAIL"] = "node"
        self.assertEqual(self.run_block(ROSTER).returncode, 1)
        self.assertFalse((second / "node.json").exists())
        self.assertFalse((second / "node.json.tmp").exists())
        self.assertEqual(json.loads((second / "common.json").read_bytes())["group"], "common")
        self.assertIn("node reporter failed", (second / "scope.txt").read_text())
        self.assertEqual(self.run_block(DIRECT).returncode, 0)
        manifest = json.loads((second / "node-direct-r25-bound-manifest.json").read_bytes())
        self.assertEqual(manifest["profile_sha256"], hashlib.sha256(self.profile.read_bytes()).hexdigest())
        self.assertEqual({p.name: p.read_bytes() for p in first.iterdir()}, prior)
        self.assertEqual((historical / "node.json").read_bytes(), b'{"old":true}')
        self.assertEqual((historical / "node-direct-r25-bound-manifest.json").read_bytes(), b"old manifest")

    def test_direct_manifest_failure_has_current_unavailable_and_no_old_manifest(self):
        first = self.allocate()
        self.assertEqual(self.run_block(DIRECT).returncode, 0)
        original = (first / "node-direct-r25-bound-manifest.json").read_bytes()
        second = self.allocate()
        self.census.unlink()
        self.assertEqual(self.run_block(DIRECT).returncode, 1)
        result = json.loads((second / "node-direct-r25.json").read_bytes())
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["aggregate_statements"])
        self.assertFalse((second / "node-direct-r25-bound-manifest.json").exists())
        self.assertFalse((second / "node-direct-r25-bound-manifest.json.tmp").exists())
        self.assertEqual((first / "node-direct-r25-bound-manifest.json").read_bytes(), original)

    def test_direct_report_failure_retains_current_bound_manifest_and_null(self):
        current = self.allocate()
        self.env["TOY_FAIL"] = "direct"
        self.assertEqual(self.run_block(DIRECT).returncode, 1)
        report = json.loads((current / "node-direct-r25.json").read_bytes())
        self.assertIsNone(report["aggregate_statements"])
        self.assertEqual(report["status"], "unavailable")
        self.assertTrue((current / "node-direct-r25-bound-manifest.json").is_file())
        self.assertFalse((current / "node-direct-r25.json.tmp").exists())

    def test_failed_allocation_has_no_publish_path_and_upload_is_explicit(self):
        self.env["RUNNER_TEMP"] = str(self.base / "absent")
        self.assertNotEqual(self.run_block(ALLOCATE).returncode, 0)
        self.assertFalse(self.output.exists())
        for name in (ROSTER, DIRECT, UPLOAD):
            self.assertIn("steps.ordinary-normal-output.outputs.directory != ''", step(name))
        upload = step(UPLOAD).split("          path: |\n", 1)[1].split("          if-no-files-found", 1)[0]
        self.assertEqual({line.strip() for line in upload.splitlines() if line.strip()}, {OUTPUT + "/" + name for name in FILES})

    def test_pre_primary_observation_never_reads_or_removes_retained_file(self):
        original = self.profile.read_bytes()
        result = self.run_block(OBSERVE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text().strip(), "profile_status=present")
        self.assertEqual(self.profile.read_bytes(), original)
        self.profile.unlink()
        result = self.run_block(OBSERVE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text().splitlines()[-1], "profile_status=absent")

    def test_unbound_profile_is_not_read_by_either_optional_reporter(self):
        for before, outcome, reason in (
            ("present", "success", "prior_absence_not_established"),
            ("", "success", "prior_absence_not_established"),
            ("absent", "skipped", "primary_not_successful"),
            ("absent", "failure", "primary_not_successful"),
        ):
            with self.subTest(before=before, outcome=outcome):
                self.env.update(ORDINARY_PROFILE_BEFORE=before,
                                ORDINARY_PRIMARY_OUTCOME=outcome)
                original = self.profile.read_bytes()
                current = self.allocate()
                receipt = json.loads((current / "input.json").read_bytes())
                self.assertEqual(receipt["status"], "unavailable")
                self.assertEqual(receipt["reason"], reason)
                self.assertIsNone(receipt["profile_sha256"])
                self.assertFalse((current / "coverage-input.cover").exists())
                self.assertEqual(self.run_block(ROSTER).returncode, 1)
                for group in ("node", "common"):
                    result = json.loads((current / f"{group}.json").read_bytes())
                    self.assertEqual(result["status"], "unavailable")
                    self.assertIsNone(result["aggregate_statements"])
                    self.assertIsNone(result["observed_statements"])
                    self.assertTrue(all(r["statements"] is None for r in result["packages"]))
                self.assertEqual(self.run_block(DIRECT).returncode, 1)
                direct = json.loads((current / "node-direct-r25.json").read_bytes())
                self.assertEqual(direct["status"], "unavailable")
                self.assertIsNone(direct["aggregate_statements"])
                self.assertFalse((current / "node-direct-r25-bound-manifest.json").exists())
                self.assertEqual(self.profile.read_bytes(), original)
                self.assertFalse((self.base / "toy-reporter-calls").exists())

    def test_success_without_profile_is_unknown(self):
        self.profile.unlink()
        current = self.allocate()
        receipt = json.loads((current / "input.json").read_bytes())
        self.assertEqual(receipt["reason"], "current_profile_absent")
        self.assertIsNone(receipt["profile_sha256"])
        self.assertFalse((current / "coverage-input.cover").exists())

    def test_bound_snapshot_is_sole_reader_input(self):
        original = self.profile.read_bytes()
        current = self.allocate()
        receipt = json.loads((current / "input.json").read_bytes())
        self.assertEqual(receipt["status"], "bound")
        expected = hashlib.sha256(original).hexdigest()
        self.assertEqual(receipt["profile_sha256"], expected)
        self.assertEqual((current / "coverage-input.cover").read_bytes(), original)
        self.profile.write_bytes(b"other later toy bytes")
        self.assertEqual(self.run_block(ROSTER).returncode, 0)
        self.assertEqual(self.run_block(DIRECT).returncode, 0)
        manifest = json.loads((current / "node-direct-r25-bound-manifest.json").read_bytes())
        self.assertEqual(manifest["profile_sha256"], expected)
        self.assertNotIn("coverage-input.cover", FILES)
