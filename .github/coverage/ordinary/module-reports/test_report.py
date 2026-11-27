import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from report import InvalidInput, consolidate, digest


class ModuleReports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.alpha = self.group("alpha", "example.invalid/alpha", "normal")
        self.beta = self.group("beta", "example.invalid/beta", "race")

    @staticmethod
    def group(gid, module, mode):
        return {"id": gid, "module": module, "mode": mode, "revision": "a" * 40,
                "packages": [module, module + "/labels"], "evidence": None}

    @staticmethod
    def encode(value):
        return json.dumps(value).encode()

    def put(self, name, raw):
        (self.base / name).write_bytes(raw)
        return {"file": name, "sha256": digest(raw)}

    def pair(self, group, rows, *, observed=None, aggregate=None, expected_files=None):
        # Use consistent toy profile blocks, leaving absent packages unrecorded.
        blocks = []
        for package, covered, total in rows:
            if covered is None:
                continue
            if covered:
                blocks.append(f"{package}/toy.go:1.1,1.3 {covered} 1")
            if covered < total or total == 0:
                blocks.append(f"{package}/toy.go:2.1,2.3 {total - covered} 0")
        if not blocks:
            blocks.append("example.invalid/unselected/toy.go:1.1,1.3 1 0")
        profile = ("mode: atomic\n" + "\n".join(blocks) + "\n").encode()
        totals = {"covered": sum(row[1] for row in rows if row[1] is not None),
                  "total": sum(row[2] for row in rows if row[2] is not None)}
        complete = all(row[1] is not None for row in rows)
        report = {"profile_status": "present", "profile_mode": "atomic",
                  "profile_sha256": digest(profile),
                  "packages": [{"package": pkg, "status": "measured" if c is not None else "package_absent",
                                "statements": {"covered": c, "total": t} if c is not None else None}
                               for pkg, c, t in rows],
                  "all_requested_packages_present": complete,
                  "observed_statements": totals if observed is None else observed,
                  "aggregate_statements": totals if complete and expected_files is not False else None}
        if aggregate is not None:
            report["aggregate_statements"] = aggregate
        if expected_files is not None:
            report["manifest"] = {"all_expected_files_present": expected_files}
        group["evidence"] = {"profile": self.put(group["id"] + ".cover", profile),
                             "report": self.put(group["id"] + ".json", self.encode(report))}
        return report

    def manifest(self, *groups):
        return self.encode({"schema": "ordinary-module-reports-input-v1", "groups": list(groups)})

    def run_index(self, *groups):
        return consolidate(self.manifest(*groups), self.base)

    def complete(self, group, first=(1, 2), second=(3, 4)):
        return self.pair(group, [(group["packages"][0], *first), (group["packages"][1], *second)])

    def replace_report(self, group, value):
        group["evidence"]["report"] = self.put(group["id"] + ".json", self.encode(value))

    def test_two_modules_keep_separate_counts_and_hashes(self):
        self.complete(self.alpha)
        self.complete(self.beta, first=(5, 6), second=(2, 8))
        manifest = self.manifest(self.alpha, self.beta)
        result = consolidate(manifest, self.base)
        self.assertEqual(result["manifest_sha256"], digest(manifest))
        self.assertIsNone(result["cross_module_aggregate"])
        a, b = result["groups"]
        self.assertEqual(a["reported_aggregate_statements"], {"covered": 4, "total": 6})
        self.assertEqual(b["reported_aggregate_statements"], {"covered": 7, "total": 14})
        self.assertEqual(a["profile_sha256"], self.alpha["evidence"]["profile"]["sha256"])
        self.assertEqual(b["report_sha256"], self.beta["evidence"]["report"]["sha256"])
        self.assertEqual((a["execution_mode"], b["execution_mode"]), ("normal", "race"))

    def test_same_module_separate_modes(self):
        self.beta = self.group("alpha-race", self.alpha["module"], "race")
        self.complete(self.alpha)
        self.complete(self.beta)
        self.assertEqual(len(self.run_index(self.alpha, self.beta)["groups"]), 2)

    def test_missing_group_null_not_zero(self):
        self.complete(self.alpha)
        result = self.run_index(self.alpha, self.beta)["groups"][1]
        self.assertEqual(result["status"], "not_supplied")
        self.assertIsNone(result["reported_observed_statements"])
        self.assertIsNone(result["reported_aggregate_statements"])
        self.assertTrue(all(row["status"] == "unknown" and row["statements"] is None for row in result["packages"]))

    def test_missing_artifact_preserves_available_digest(self):
        self.complete(self.alpha)
        (self.base / self.alpha["evidence"]["profile"]["file"]).unlink()
        result = self.run_index(self.alpha)["groups"][0]
        self.assertEqual(result["status"], "artifact_absent")
        self.assertEqual(result["report_sha256"], self.alpha["evidence"]["report"]["sha256"])
        self.assertIsNone(result["profile_sha256"])
        self.assertIsNone(result["reported_aggregate_statements"])

    def test_partial_and_measured_zero(self):
        self.pair(self.alpha, [(self.alpha["packages"][0], 0, 5),
                               (self.alpha["packages"][1], None, None)])
        result = self.run_index(self.alpha)["groups"][0]
        self.assertEqual(result["status"], "reported_partial")
        self.assertEqual(result["reported_observed_statements"], {"covered": 0, "total": 5})
        self.assertIsNone(result["reported_aggregate_statements"])
        self.assertIsNone(result["packages"][1]["statements"])

    def test_all_absent_report_has_no_observed_measurement(self):
        self.pair(self.alpha, [(pkg, None, None) for pkg in self.alpha["packages"]])
        result = self.run_index(self.alpha)["groups"][0]
        self.assertEqual(result["status"], "reported_partial")
        self.assertIsNone(result["reported_observed_statements"])
        self.assertIsNone(result["reported_aggregate_statements"])

    def test_header_only_profile_preserves_unknown_measurement(self):
        report = self.pair(self.alpha, [(pkg, None, None) for pkg in self.alpha["packages"]])
        profile = b"mode: atomic\n"
        self.alpha["evidence"]["profile"] = self.put("alpha.cover", profile)
        report["profile_sha256"] = digest(profile)
        self.replace_report(self.alpha, report)
        result = self.run_index(self.alpha)
        group = result["groups"][0]
        self.assertEqual(group["status"], "reported_partial")
        self.assertEqual(group["execution_mode"], "normal")
        self.assertEqual(group["profile_sha256"], digest(profile))
        self.assertEqual(group["report_sha256"], self.alpha["evidence"]["report"]["sha256"])
        self.assertEqual(group["packages"], [
            {"package": pkg, "status": "package_absent", "statements": None}
            for pkg in self.alpha["packages"]
        ])
        self.assertIsNone(group["reported_observed_statements"])
        self.assertIsNone(group["reported_aggregate_statements"])
        self.assertIsNone(result["cross_module_aggregate"])

    def test_report_file_digest_mismatch_independent_of_profile(self):
        original = self.complete(self.alpha)
        path = self.base / self.alpha["evidence"]["report"]["file"]
        raw = path.read_bytes()
        profile_path = self.base / self.alpha["evidence"]["profile"]["file"]
        self.assertEqual(digest(raw), self.alpha["evidence"]["report"]["sha256"])
        self.assertEqual(digest(profile_path.read_bytes()), original["profile_sha256"])
        # The report remains semantically identical, but the declared digest
        # refers to its original bytes, not these independently modified bytes.
        path.write_bytes(raw + b"\n")
        self.assertEqual(json.loads(path.read_bytes()), original)
        self.assertNotEqual(digest(path.read_bytes()), self.alpha["evidence"]["report"]["sha256"])
        self.assertEqual(digest(profile_path.read_bytes()), original["profile_sha256"])
        with self.assertRaisesRegex(InvalidInput, "^artifact digest mismatch$"):
            self.run_index(self.alpha)

    def test_incomplete_file_manifest_keeps_aggregate_null(self):
        self.pair(self.alpha, [(pkg, 2, 3) for pkg in self.alpha["packages"]], expected_files=False)
        result = self.run_index(self.alpha)["groups"][0]
        self.assertEqual(result["reported_observed_statements"], {"covered": 4, "total": 6})
        self.assertEqual(result["status"], "reported_partial")
        self.assertIsNone(result["reported_aggregate_statements"])

    def test_digest_roster_profile_and_count_mismatches_fail(self):
        original = self.complete(self.alpha)
        for field, value in [("profile_sha256", "f" * 64), ("profile_mode", "set"),
                             ("packages", list(reversed(original["packages"]))),
                             ("observed_statements", {"covered": 1, "total": 6}),
                             ("aggregate_statements", None), ("all_requested_packages_present", False)]:
            with self.subTest(field=field):
                mutated = dict(original, **{field: value})
                self.replace_report(self.alpha, mutated)
                with self.assertRaises(InvalidInput):
                    self.run_index(self.alpha)
        self.replace_report(self.alpha, original)
        self.alpha["evidence"]["profile"]["sha256"] = "f" * 64
        with self.assertRaises(InvalidInput):
            self.run_index(self.alpha)

    def test_invalid_null_and_count_types_fail(self):
        original = self.complete(self.alpha)
        for counts in ({"covered": True, "total": 2}, {"covered": 3, "total": 2},
                       {"covered": -1, "total": 2}, None):
            with self.subTest(counts=counts):
                changed = copy.deepcopy(original)
                changed["packages"][0]["statements"] = counts
                self.replace_report(self.alpha, changed)
                with self.assertRaises(InvalidInput):
                    self.run_index(self.alpha)
        changed = copy.deepcopy(original)
        changed["packages"][0]["status"] = "package_absent"
        self.replace_report(self.alpha, changed)
        with self.assertRaises(InvalidInput):
            self.run_index(self.alpha)

    def test_partial_claiming_aggregate_fails(self):
        self.pair(self.alpha, [(self.alpha["packages"][0], 1, 2),
                               (self.alpha["packages"][1], None, None)], aggregate={"covered": 1, "total": 2})
        with self.assertRaises(InvalidInput):
            self.run_index(self.alpha)

    def test_bad_group_identity_and_roster_fail(self):
        for update in ({"id": "../bad"}, {"mode": "both"}, {"revision": "short"},
                       {"packages": ["example.invalid/beta"]}, {"packages": self.alpha["packages"] * 2}):
            with self.subTest(update=update):
                with self.assertRaises(InvalidInput):
                    self.run_index(dict(self.alpha, **update))
        with self.assertRaises(InvalidInput):
            self.run_index(self.alpha, dict(self.beta, id=self.alpha["id"]))
        with self.assertRaises(InvalidInput):
            self.run_index(self.alpha, dict(self.alpha, id="other"))

    def test_artifact_path_and_duplicate_json_key_fail(self):
        self.complete(self.alpha)
        for bad in ("../outside", "/outside"):
            with self.subTest(path=bad):
                self.alpha["evidence"]["report"]["file"] = bad
                with self.assertRaises(InvalidInput):
                    self.run_index(self.alpha)
        with self.assertRaises(InvalidInput):
            consolidate(b'{"schema":"one","schema":"two","groups":[]}', self.base)

    def test_cli_success_and_path_free_error(self):
        script = Path(__file__).with_name("report.py")
        self.complete(self.alpha)
        path = self.base / "manifest.json"
        path.write_bytes(self.manifest(self.alpha, self.beta))
        argv = [sys.executable, "-B", str(script), "--manifest", str(path)]
        result = subprocess.run(argv, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), self.run_index(self.alpha, self.beta))
        self.assertNotIn(str(self.base).encode(), result.stdout)
        path.write_bytes(b"malformed")
        result = subprocess.run(argv, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(result.stdout)
        self.assertNotIn(str(self.base).encode(), result.stderr)


if __name__ == "__main__":
    unittest.main()
