import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import diagnostic as d


class DiagnosticTests(unittest.TestCase):
    def test_selector_modes_are_exact(self):
        for mode in ("normal", "race"):
            argv = d.test_args(mode, Path("toy.cover"))
            self.assertEqual(argv[-3:], ["-run", d.SELECTOR, d.PACKAGE])
            self.assertEqual("-race" in argv, mode == "race")
            self.assertIn("-covermode=atomic", argv)
        self.assertEqual(d.offline_env()["GOPROXY"], "off")
        self.assertEqual(d.offline_env()["GOWORK"], "off")

    def test_exact_event_roster(self):
        events = [{"Action": action, "Test": root, "Package": d.PACKAGE}
                  for root in d.ROOTS for action in ("run", "pass")]
        events.append({"Action": "pass", "Package": d.PACKAGE})
        def encode(rows):
            return b"\n".join(json.dumps(row).encode() for row in rows)
        d.verify_events(encode(events))
        with self.assertRaises(ValueError):
            d.verify_events(encode(events[:-1]))

    def test_missing_module_is_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with patch.object(d, "verify_module", side_effect=ValueError("missing module")):
                self.assertEqual(d.diagnostic(out, out), 1)
            result = json.loads((out / "result.json").read_text())
            for mode in ("normal", "race"):
                self.assertEqual(result[mode]["status"], "unavailable")
                self.assertIsNone(result[mode]["statements"])

    def test_missing_reporter_does_not_run_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with patch.object(d, "verify_module", return_value=out), \
                 patch.object(d, "run_phase", side_effect=ValueError("missing helper")) as run:
                self.assertEqual(d.diagnostic(out, out), 1)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[2], "reporter-build")
            result = json.loads((out / "result.json").read_text())
            self.assertTrue(all(result[m]["statements"] is None for m in ("normal", "race")))

    def test_separate_profile_reports_with_toy_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            events = [{"Action": action, "Test": root, "Package": d.PACKAGE}
                      for root in d.ROOTS for action in ("run", "pass")]
            events.append({"Action": "pass", "Package": d.PACKAGE})
            event_bytes = b"\n".join(json.dumps(row).encode() for row in events)
            def fake_run(root, out, label, argv):
                if label == "reporter-build":
                    return b""
                mode = label.split("-", 1)[0]
                profile = out / f"{mode}.cover"
                if label.endswith("-test"):
                    profile.write_text("mode: atomic\n")
                    self.assertEqual("-race" in argv, mode == "race")
                    return event_bytes
                return json.dumps({"profile_sha256": d.sha(profile.read_bytes()),
                                   "profile_mode": "atomic", "expected_statements": 14,
                                   "aggregate_statements": None}).encode()
            with patch.object(d, "verify_module", return_value=out), \
                 patch.object(d, "run_phase", side_effect=fake_run):
                self.assertEqual(d.diagnostic(out, out), 1)
            result = json.loads((out / "result.json").read_text())
            for mode in ("normal", "race"):
                self.assertEqual(result[mode]["status"], "partial")
                self.assertIsNone(result[mode]["statements"])
                self.assertTrue((out / f"{mode}.manifest.json").is_file())

    def portable_fixture(self, out, mode, profile):
        census = json.loads((d.HERE / "census.json").read_text())
        raw = profile.encode()
        (out / f"{mode}.cover").write_bytes(raw)
        manifest = d.census_manifest(census, out / f"{mode}.cover")
        d.write_json(out / f"{mode}.manifest.json", manifest)
        functions = []
        for spec in census["functions"]:
            expected = sum(b["statements"] for b in spec["blocks"])
            functions.append({**spec, "status": "measured", "expected_statements": expected,
                              "observed_statements": {"covered": expected - 1, "total": expected},
                              "statements": {"covered": expected - 1, "total": expected},
                              "missing_blocks": [], "unwanted": "/toy/private/local"})
        aggregate = {"covered": 12, "total": 14}
        d.write_json(out / f"{mode}.report.json", {
            "profile_sha256": d.sha(raw), "profile_mode": "atomic", "expected_statements": 14,
            "profile_status": "present",
            "manifest_sha256": d.sha((out / f"{mode}.manifest.json").read_bytes()),
            "aggregate_statements": aggregate, "observed_statements": aggregate,
            "functions": functions, "extra": "/toy/private/local",
        })
        d.write_json(out / f"{mode}-test.execution.json", {
            "exit": 0, "argv": ["/toy/private/local"], "stderr_sha256": "ignored",
        })
        return {"status": "measured", "statements": aggregate, "profile_sha256": d.sha(raw)}

    def test_portable_artifact_roster_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            profile = "mode: atomic\n" + d.PACKAGE + "/utils.go:1.1,2.1 1 1\n"
            result = {m: self.portable_fixture(out, m, profile) for m in ("normal", "race")}
            (out / "ordinary-reporter").write_bytes(b"binary with /toy/private/local")
            (out / "module-download.stdout").write_text("/toy/private/local")
            self.assertTrue(d.publish_portable(out, result))
            portable = out / "portable"
            self.assertEqual({p.name for p in portable.iterdir()}, {
                "summary.json", "normal.cover", "race.cover", "normal.report.json",
                "race.report.json", "normal.manifest.json", "race.manifest.json",
            })
            for p in portable.iterdir():
                self.assertNotIn(b"/toy/private/local", p.read_bytes())
            self.assertEqual((portable / "normal.cover").read_bytes(), profile.encode())
            self.assertEqual((portable / "race.cover").read_bytes(), profile.encode())
            summary = json.loads((portable / "summary.json").read_text())
            for m in ("normal", "race"):
                self.assertEqual(summary[m]["statements"], result[m]["statements"])
                self.assertEqual(summary[m]["test_exit"], 0)
            self.assertTrue((out / "ordinary-reporter").is_file())
            self.assertTrue((out / "module-download.stdout").is_file())

    def test_nonportable_profile_and_raw_error_not_exported(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            profile = "mode: atomic\n/toy/private/local.go:1.1,2.1 1 1\n"
            normal = self.portable_fixture(out, "normal", profile)
            race = {"status": "unavailable", "statements": None, "reason": "/toy/private/local"}
            self.assertFalse(d.publish_portable(out, {"normal": normal, "race": race}))
            self.assertEqual({p.name for p in (out / "portable").iterdir()}, {"summary.json"})
            raw = (out / "portable" / "summary.json").read_bytes()
            self.assertNotIn(b"/toy/private/local", raw)
            self.assertEqual(json.loads(raw)["normal"]["status"], "unavailable")
            self.assertEqual(json.loads(raw)["normal"]["test_exit"], 0)
            self.assertIsNone(json.loads(raw)["normal"]["statements"])

    def test_static_census_bound_to_profile_digest(self):
        census = json.loads((d.HERE / "census.json").read_text())
        self.assertEqual(d.sha((d.HERE / "census.json").read_bytes()), d.CENSUS_HASH)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "toy.cover"
            p.write_text("mode: atomic\n")
            manifest = d.census_manifest(census, p)
            self.assertEqual(manifest["profile_sha256"], d.sha(p.read_bytes()))
            self.assertEqual([f["name"] for f in manifest["functions"]],
                             ["computeTokenIdentifier", "extractTokenAndNonce"])
            p.write_text("mode: count\n")
            with self.assertRaises(ValueError):
                d.census_manifest(census, p)


if __name__ == "__main__":
    unittest.main()
