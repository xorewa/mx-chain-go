import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import diagnostic as d


def events(package, roots):
    package = d.MODULE + "/" + package
    rows = []
    for root in roots:
        rows.extend([{"Action": "run", "Package": package, "Test": root},
                     {"Action": "run", "Package": package, "Test": root + "/toy"},
                     {"Action": "pass", "Package": package, "Test": root + "/toy"},
                     {"Action": "pass", "Package": package, "Test": root}])
    rows.append({"Action": "pass", "Package": package})
    return b"\n".join(json.dumps(row).encode() for row in rows)


def profile(package, line="2.3,3.4 1 1"):
    return ("mode: atomic\n" + d.MODULE + "/" + package + "/toy.go:" + line + "\n").encode()


class DiagnosticTest(unittest.TestCase):
    def test_exact_selector(self):
        args = d.selector_args("toy/alpha", ["TestBeta", "TestAlpha"], Path("one.cover"))
        self.assertEqual(args, ["go", "test", "-json", "-count=1", "-race", "-covermode=atomic",
                                "-coverprofile=one.cover", "-run", "^(TestAlpha|TestBeta)$", "./toy/alpha"])
        for roots in [["Test.*"], ["TestAlpha", "TestAlpha"], []]:
            with self.assertRaises(ValueError):
                d.selector_args("toy/alpha", roots, Path("one.cover"))

    def test_root_events_are_exact(self):
        d.verify_events(events("toy/alpha", ["TestAlpha"]), "toy/alpha", ["TestAlpha"])
        for raw in [events("toy/alpha", ["TestOther"]), events("toy/beta", ["TestAlpha"]),
                    events("toy/alpha", ["TestAlpha"]).replace(b'"pass"', b'"fail"', 1),
                    events("toy/alpha", ["TestAlpha"]).rsplit(b"\n", 1)[0]]:
            with self.assertRaises(ValueError):
                d.verify_events(raw, "toy/alpha", ["TestAlpha"])

    def test_profile_coordinates_and_package(self):
        self.assertEqual(len(d.profile_blocks(profile("toy/alpha"), "toy/alpha")), 1)
        self.assertEqual(len(d.profile_blocks(profile("toy/alpha", "2.3,2.3 0 0"), "toy/alpha")), 1)
        for raw in [profile("toy/beta"), profile("toy/alpha", "3.4,2.3 1 0"),
                    profile("toy/alpha", "0.3,2.4 1 0"), profile("toy/alpha").replace(b"atomic", b"set")]:
            with self.assertRaises(ValueError):
                d.profile_blocks(raw, "toy/alpha")

    def test_duplicate_blocks_use_consistent_weights(self):
        raw = profile("toy/alpha")
        line = raw.splitlines()[1]
        self.assertEqual(next(iter(d.profile_blocks(raw + line + b"\n", "toy/alpha").values())), (1, 2))
        with self.assertRaises(ValueError):
            d.profile_blocks(raw + line.replace(b" 1 1", b" 2 1") + b"\n", "toy/alpha")

    def fixture(self, root):
        (root / "toy.go").write_text("package toy\n")
        census = root / ".github/coverage/ordinary/node-direct-r25.json"
        census.parent.mkdir(parents=True)
        census.write_text("{}\n")
        return {"files": {"toy.go": d.digest((root / "toy.go").read_bytes())},
                "census_sha256": d.digest(census.read_bytes()), "review_sha256": "a" * 64,
                "packages": [{"package": "toy/alpha", "roots": ["TestAlpha"]},
                             {"package": "toy/beta", "roots": ["TestBeta"]}]}

    def test_produce_combines_only_separate_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.fixture(root)
            calls = []

            def runner(_, raw_dir, package, roots):
                self.assertTrue(raw_dir.is_dir())
                calls.append((package, roots))
                return d.profile_blocks(profile(package), package)

            output = root / "input"
            d.produce(root, output, manifest, "b" * 40, runner)
            self.assertEqual(calls, [("toy/alpha", ["TestAlpha"]), ("toy/beta", ["TestBeta"])])
            receipt = json.loads((output / "provenance.json").read_text())
            raw = (output / "coverage.out").read_bytes()
            self.assertEqual(len(raw.splitlines()), 3)
            self.assertEqual(receipt["profile_sha256"], d.digest(raw))
            self.assertEqual(receipt["run_mode"], "race")
            self.assertEqual(receipt["test_exit"], 0)

    def test_changed_source_prevents_any_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.fixture(root)
            (root / "toy.go").write_text("package changed\n")
            with patch.object(d, "run_package") as runner, self.assertRaises(ValueError):
                d.produce(root, root / "input", manifest, "b" * 40, runner)
            runner.assert_not_called()
            self.assertFalse((root / "input").exists())

    def test_failed_package_never_publishes_combined_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.fixture(root)

            def runner(_, __, package, ___):
                if package == "toy/beta":
                    raise ValueError("toy failure")
                return d.profile_blocks(profile(package), package)

            output = root / "input"
            with self.assertRaises(ValueError):
                d.produce(root, output, manifest, "b" * 40, runner)
            self.assertFalse((output / "coverage.out").exists())
            self.assertFalse((output / "provenance.json").exists())

    def test_offline_env(self):
        env = d.offline_env()
        self.assertEqual([env[k] for k in ("GOPROXY", "GONOPROXY", "GOSUMDB", "GOVCS")],
                         ["off", "none", "off", "*:off"])
        self.assertIn("-mod=readonly", env["GOFLAGS"])

    def test_run_package_uses_only_mocked_exact_race_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw"
            raw.mkdir()

            def fake_run(args, **kwargs):
                self.assertEqual(args, d.selector_args("toy/alpha", ["TestAlpha"], raw / "toy_alpha.cover"))
                self.assertEqual(kwargs["cwd"], root)
                self.assertEqual(kwargs["env"]["GOPROXY"], "off")
                (raw / "toy_alpha.cover").write_bytes(profile("toy/alpha"))
                return d.subprocess.CompletedProcess(args, 0, events("toy/alpha", ["TestAlpha"]), b"")

            with patch.object(d.subprocess, "run", side_effect=fake_run) as runner:
                self.assertEqual(len(d.run_package(root, raw, "toy/alpha", ["TestAlpha"])), 1)
            runner.assert_called_once()


if __name__ == "__main__":
    unittest.main()
