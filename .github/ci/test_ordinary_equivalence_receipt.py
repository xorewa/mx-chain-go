"""Pure synthetic ordinary receipt comparator checks."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import ordinary_equivalence_receipt as eq


PACKAGE = "example.test/paint"
TEST = "TestPaint/blue"


class OrdinaryEquivalenceReceiptTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.cohort = {"id": "paint", "package": PACKAGE, "tests": [TEST],
                       "candidate": self.subject("a"), "reference": self.subject("b"),
                       "third": None}
        self.manifest = {"schema": "ordinary-equivalence-receipt-v1",
                         "cohorts": [self.cohort]}

    def artifact(self, name, raw):
        (self.base / name).write_bytes(raw)
        return {"file": name, "sha256": hashlib.sha256(raw).hexdigest()}

    def subject(self, rev):
        modes = {}
        for mode in eq.MODES:
            stem = rev + "-" + mode
            records = [{"Package": PACKAGE, "Action": action,
                        **({"Test": test} if test else {})}
                       for action, test in (("start", None), ("run", "TestPaint"),
                                            ("run", TEST), ("pass", TEST),
                                            ("pass", "TestPaint"), ("pass", None))]
            events = ("\n".join(json.dumps(x) for x in records) + "\n").encode()
            profile = f"mode: atomic\n{PACKAGE}/paint.go:1.1,2.1 1 1\n".encode()
            modes[mode] = {"exit": 0, "events": self.artifact(stem + ".jsonl", events),
                           "profile": self.artifact(stem + ".cover", profile),
                           "output": self.artifact(stem + ".txt", b"blue\n")}
        return {"revision": rev * 40, "locks": {"go.mod": rev * 64, "go.sum": "f" * 64},
                "sources": {"paint.go": "c" * 64, "paint_test.go": "d" * 64},
                "modes": modes}

    def report(self):
        return eq.verify(self.manifest, self.base)["cohorts"][0]

    def test_two_modes_match_and_third_is_missing(self):
        result = self.report()
        for mode in eq.MODES:
            self.assertEqual(result["candidate_reference"][mode], {
                "status": "measured", "exit_equal": True, "named_pass": True,
                "output_equal": True})
            self.assertEqual(result["candidate_third"][mode], {
                "status": "not_supplied", "exit_equal": None, "named_pass": None,
                "output_equal": None})
        self.assertIsNone(result["subjects"]["third"])
        self.assertNotEqual(result["subjects"]["candidate"]["locks"],
                            result["subjects"]["reference"]["locks"])

    def test_actual_third_can_reuse_revision_but_not_artifacts(self):
        third = self.subject("c")
        third["revision"] = self.cohort["candidate"]["revision"]
        third["modes"]["race"] = None
        self.cohort["third"] = third
        result = self.report()
        self.assertTrue(result["candidate_third"]["normal"]["output_equal"])
        self.assertTrue(result["reference_third"]["normal"]["named_pass"])
        self.assertIsNone(result["candidate_third"]["race"]["named_pass"])
        third["modes"]["normal"]["events"] = self.cohort["candidate"]["modes"]["normal"]["events"]
        with self.assertRaises(ValueError):
            self.report()

    def test_output_difference_and_absence_do_not_become_equal(self):
        self.cohort["reference"]["modes"]["normal"]["output"] = self.artifact(
            "different.txt", b"green\n")
        self.cohort["reference"]["modes"]["race"]["output"] = None
        result = self.report()["candidate_reference"]
        self.assertFalse(result["normal"]["output_equal"])
        self.assertTrue(result["normal"]["named_pass"])
        self.assertIsNone(result["race"]["output_equal"])

    def test_exit_failure_is_distinct_from_missing(self):
        leg = self.cohort["reference"]["modes"]["normal"]
        leg.update(exit=1, profile=None)
        self.cohort["reference"]["modes"]["race"] = None
        result = self.report()["candidate_reference"]
        self.assertEqual(result["normal"], {"status": "nonpassing", "exit_equal": False,
                                           "named_pass": False, "output_equal": None})
        self.assertEqual(result["race"]["status"], "not_supplied")
        self.assertIsNone(result["race"]["exit_equal"])

    def test_invalid_inputs_never_produce_a_result(self):
        for change in ("empty", "duplicate", "source", "third_source", "digest",
                       "missing_profile", "wrong_events", "bool_exit", "same_revision"):
            with self.subTest(change=change):
                manifest = copy.deepcopy(self.manifest)
                item = manifest["cohorts"][0]
                leg = item["reference"]["modes"]["normal"]
                if change == "empty":
                    manifest["cohorts"] = []
                elif change == "duplicate":
                    manifest["cohorts"].append(copy.deepcopy(item))
                elif change == "source":
                    item["reference"]["sources"]["paint.go"] = "e" * 64
                elif change == "third_source":
                    item["third"] = self.subject("c")
                    item["third"]["sources"]["paint.go"] = "e" * 64
                elif change == "digest":
                    leg["events"]["sha256"] = "0" * 64
                elif change == "missing_profile":
                    leg["profile"] = None
                elif change == "wrong_events":
                    leg["events"] = self.artifact("wrong.jsonl", b"{}\n")
                elif change == "bool_exit":
                    leg["exit"] = False
                elif change == "same_revision":
                    item["reference"]["revision"] = item["candidate"]["revision"]
                with self.assertRaises(ValueError):
                    eq.verify(manifest, self.base)

    def test_multiple_cohorts_are_kept_separate(self):
        second = {"id": "another", "package": PACKAGE, "tests": [TEST],
                  "candidate": self.subject("c"), "reference": self.subject("d"),
                  "third": None}
        self.manifest["cohorts"].append(second)
        result = eq.verify(self.manifest, self.base)["cohorts"]
        self.assertEqual([x["id"] for x in result], ["paint", "another"])

    def test_cli_hashes_manifest_and_rejects_duplicate_members(self):
        path = self.base / "manifest.json"
        raw = json.dumps(self.manifest).encode()
        path.write_bytes(raw)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            eq.main(["--manifest", str(path)])
        self.assertEqual(json.loads(output.getvalue())["manifest_sha256"],
                         hashlib.sha256(raw).hexdigest())
        self.assertNotIn(str(self.base), output.getvalue())
        path.write_text('{"schema":"first","schema":"second","cohorts":[]}')
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                eq.main(["--manifest", str(path)])
        self.assertEqual(error.exception.code, 1)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
