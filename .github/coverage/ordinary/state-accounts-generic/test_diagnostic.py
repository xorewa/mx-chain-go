import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import sys

import diagnostic as d


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.census = json.loads(Path(d.__file__).with_name("census.json").read_text())
        self.subject = "a" * 40
        self.events = b"\n".join(json.dumps({"Package": self.census["package"], "Action": "pass", "Test": name}).encode() for name in self.census["expected_passes"]) + b"\n" + json.dumps({"Package": self.census["package"], "Action": "pass"}).encode() + b"\n"
        self.profile = b"mode: atomic\n"
        self.argv = ["go", "test", "-mod=readonly", "-p=2", "-short", "-count=1", "-timeout=120s", "-covermode=atomic", "-coverprofile=toy.cover", "-run", self.census["selector"], "-json", "./state/accounts"]
        self.receipt = {"candidate": self.subject, "common": self.census["common_commit"], "exit": 0,
                        "argv": self.argv, "profile_sha256": d.digest(self.profile), "stdout_sha256": d.digest(self.events)}

    def bind(self, mode="normal", **changes):
        receipt = dict(self.receipt, **changes)
        return d.bind_mode(self.census, self.subject, mode, self.profile, self.events, receipt)

    def test_static_census_and_selections(self):
        d.check_census(self.census)
        manifest = self.bind()
        self.assertEqual(len(manifest["functions"]), 37)
        self.assertEqual(manifest["profile_sha256"], d.digest(self.profile))
        self.bind("race", argv=self.argv[:-1] + ["-race", self.argv[-1]])
        wrong = copy.deepcopy(self.census)
        wrong["roots"].pop()
        with self.assertRaises(ValueError):
            d.check_census(wrong)

    def test_pin_validation(self):
        (self.root / "toy").write_bytes(b"source")
        fixture = {"source_test_lock_sha256": {"toy": d.digest(b"source")}}
        d.check_sources(self.root, fixture)
        (self.root / "toy").write_bytes(b"different")
        with self.assertRaises(ValueError):
            d.check_sources(self.root, fixture)

    def test_receipt_refusals(self):
        for fields in ({"exit": 1}, {"candidate": "b" * 40}, {"common": "c" * 40},
                       {"stdout_sha256": "bad"}, {"profile_sha256": "bad"},
                       {"argv": self.argv[:-1] + ["./..."]},
                       {"argv": self.argv[:-1] + ["-race", self.argv[-1]]},
                       {"argv": ["go", "test", "./state/accounts"]}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.bind(**fields)
        with self.assertRaises(ValueError):
            self.bind("race")

    def test_event_refusals(self):
        for raw in (b"", self.events + self.events, self.events.replace(b'"pass"', b'"fail"'),
                    self.events.replace(self.census["roots"][0].encode(), b"TestUnexpected")):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError):
                d.check_events(raw, self.census)

    def test_profile_rows_not_rewritten(self):
        self.profile += (self.census["package"] + "/userAccountData.pb.go:1.1,1.2 1 0\n").encode()
        self.bind(profile_sha256=d.digest(self.profile))
        self.profile += b"/tmp/toy.go:1.1,1.2 1 1\n"
        with self.assertRaises(ValueError):
            self.bind(profile_sha256=d.digest(self.profile))

    def toy_report(self, missing):
        manifest = self.bind()
        rows = []
        for spec in manifest["functions"]:
            total = sum(x["statements"] for x in spec["blocks"])
            status = "blocks_absent" if missing else "measured"
            counts = None if missing else {"covered": 0, "total": total}
            rows.append({**{k: spec[k] for k in ("source", "source_sha256", "profile_file", "name", "span")},
                         "status": status, "expected_statements": total, "observed_statements": counts,
                         "statements": counts, "missing_blocks": spec["blocks"] if missing else []})
        return {"manifest_sha256": d.digest(d.encode(manifest)), "profile_sha256": d.digest(self.profile), "profile_mode": "atomic",
                "profile_status": "present", "expected_statements": 229, "functions": rows,
                "observed_statements": {"covered": 0, "total": 0 if missing else 229},
                "aggregate_statements": None if missing else {"covered": 0, "total": 229}}

    def test_missing_is_not_measured_zero(self):
        for missing in (True, False):
            report = d.portable_report(self.toy_report(missing), self.census, d.encode(self.bind()), self.profile)
            self.assertEqual(report["aggregate_statements"], None if missing else {"covered": 0, "total": 229})
        changed = self.toy_report(False)
        changed["functions"][0]["span"] = [1, 1, 1, 2]
        with self.assertRaises(ValueError):
            d.portable_report(changed, self.census, d.encode(self.bind()), self.profile)

    def test_main_absent_and_unavailable(self):
        for invalid in (False, True):
            output = self.root / ("invalid" if invalid else "absent")
            argv = ["diagnostic", "--source-root", str(self.root), "--output", str(output)]
            with patch.object(sys, "argv", argv), patch.object(d, "check_sources", side_effect=ValueError("toy mismatch") if invalid else None), patch.object(d.subprocess, "check_output", return_value=self.subject + "\n"):
                exit_code = d.main()
            self.assertEqual(exit_code, int(invalid))
            result = json.loads((output / "summary.json").read_text())
            self.assertEqual(result["candidate"], None if invalid else self.subject)
            for mode in ("normal", "race"):
                self.assertEqual(result["modes"][mode], d.unknown("source_unavailable" if invalid else "profile_absent"))

    def test_optional_report_and_invalid_reporter(self):
        args = (self.root, self.root, self.census, self.subject, "normal")
        self.assertEqual(d.report_mode(*args, [None] * 3, None), d.unknown("profile_absent"))
        self.assertEqual(d.report_mode(*args, [self.root / "missing", None, None], None), d.unknown("input_incomplete"))
        paths = [self.root / x for x in ("profile", "events", "receipt")]
        for path, raw in zip(paths, (self.profile, self.events, d.encode(self.receipt))):
            path.write_bytes(raw)
        self.assertEqual(d.report_mode(*args, paths, None), d.unknown("reporter_unavailable"))
        for missing in (False, True):
            mock = subprocess.CompletedProcess([], 0, d.encode(self.toy_report(missing)))
            with patch.object(d.subprocess, "run", return_value=mock):
                result = d.report_mode(*args, paths, self.root / "toy-reporter")
            self.assertEqual(result["status"], "partial" if missing else "measured")
            self.assertTrue((self.root / "normal.report.json").is_file())
        with patch.object(d.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"")):
            self.assertEqual(d.report_mode(*args, paths, self.root / "toy-reporter"), d.unknown("invalid_input_or_reporter"))


if __name__ == "__main__":
    unittest.main()
