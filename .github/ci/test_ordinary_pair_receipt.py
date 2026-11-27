"""Retained toy ordinary evidence only; no product test execution."""

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import ordinary_pair_receipt as pair


PACKAGE = "example.test/paint"
ROOT = "TestPaint"
LEAF = ROOT + "/blue"


class OrdinaryPairReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.manifest = {
            "schema": "ordinary-pair-receipt-v1", "package": PACKAGE, "tests": [LEAF],
        }
        for side, rev in (("candidate", "a"), ("reference", "b")):
            item = {"revision": rev * 40, "locks": {"go.mod": rev * 64, "go.sum": "c" * 64},
                    "sources": {"paint.go": "d" * 64, "paint_test.go": "e" * 64}, "modes": {}}
            self.manifest[side] = item
            for mode in ("normal", "race"):
                events = [{"Package": PACKAGE, "Action": action, **({"Test": test} if test else {})}
                          for action, test in (("start", None), ("run", ROOT), ("run", LEAF),
                                               ("pass", LEAF), ("pass", ROOT), ("pass", None))]
                raw = ("\n".join(json.dumps(e) for e in events) + "\n").encode()
                profile = f"mode: atomic\n{PACKAGE}/paint.go:1.1,2.1 1 1\n".encode()
                item["modes"][mode] = {"exit": 0,
                    "events": self.artifact(f"{side}-{mode}.jsonl", raw),
                    "profile": self.artifact(f"{side}-{mode}.cover", profile)}

    def artifact(self, name, data):
        (self.base / name).write_bytes(data)
        return {"file": name, "sha256": hashlib.sha256(data).hexdigest()}

    def test_pair_keeps_modes_and_locks_distinct(self):
        result = pair.verify(self.manifest, self.base)
        self.assertEqual(result["paired_named_pass"], {"normal": True, "race": True})
        self.assertNotEqual(result["subjects"]["candidate"]["locks"], result["subjects"]["reference"]["locks"])
        self.assertEqual(result["subjects"]["candidate"]["modes"]["normal"]["verified_test_count_including_parents"], 2)

    def test_absent_leg_is_unknown_not_a_pair(self):
        self.manifest["reference"]["modes"]["race"] = None
        result = pair.verify(self.manifest, self.base)
        self.assertEqual(result["paired_named_pass"], {"normal": True, "race": None})
        self.assertIsNone(result["subjects"]["reference"]["modes"]["race"])

    def test_declared_source_difference_not_comparable(self):
        self.manifest["reference"]["sources"]["paint_test.go"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "source or fixture mismatch"):
            pair.verify(self.manifest, self.base)

    def test_cli_binds_manifest_and_keeps_artifact_paths_out_of_output(self):
        raw = json.dumps(self.manifest).encode()
        manifest = self.base / "pair.json"
        manifest.write_bytes(raw)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pair.main(["--manifest", str(manifest)])
        report = json.loads(output.getvalue())
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotIn(str(self.base), output.getvalue())
        self.assertNotIn("candidate-normal.jsonl", output.getvalue())

        self.manifest["candidate"]["modes"]["normal"]["exit"] = 1
        manifest.write_text(json.dumps(self.manifest))
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()) as invalid:
            with self.assertRaises(SystemExit) as err:
                pair.main(["--manifest", str(manifest)])
        self.assertEqual(err.exception.code, 1)
        self.assertEqual(invalid.getvalue(), "")

    def test_nonpassing_or_mismatched_artifacts_not_accepted(self):
        for change in ("exit", "digest", "reuse", "empty_profile", "root_only"):
            with self.subTest(change=change):
                manifest = copy.deepcopy(self.manifest)
                leg = manifest["reference"]["modes"]["race"]
                if change == "exit":
                    leg["exit"] = 1
                elif change == "digest":
                    leg["events"]["sha256"] = "0" * 64
                elif change == "reuse":
                    leg["events"] = manifest["candidate"]["modes"]["normal"]["events"]
                elif change == "empty_profile":
                    leg["profile"] = self.artifact("empty.cover", b"mode: atomic\n")
                else:
                    raw = b"\n".join(json.dumps({"Package": PACKAGE, "Action": a,
                        **({"Test": ROOT} if is_test else {})}).encode() for a, is_test in
                        (("start", False), ("run", True), ("pass", True), ("pass", False))) + b"\n"
                    leg["events"] = self.artifact("root-only.jsonl", raw)
                with self.assertRaises(ValueError):
                    pair.verify(manifest, self.base)


if __name__ == "__main__":
    unittest.main()
