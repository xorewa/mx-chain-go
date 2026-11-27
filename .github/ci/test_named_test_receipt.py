"""Synthetic named-test event fixtures only; no product test execution."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import named_test_receipt as receipt


PACKAGE = "example.test/ordinary"
ROOT = "TestPaint"
LEAF = ROOT + "/blue"


def event(action, test=None, package=PACKAGE):
    value = {"Action": action, "Package": package}
    if test is not None:
        value["Test"] = test
    return value


def stream(events):
    return ("\n".join(json.dumps(value) for value in events) + "\n").encode()


def complete():
    return [event("start"), event("run", ROOT), event("run", LEAF),
            event("output", LEAF), event("pass", LEAF), event("pass", ROOT),
            event("output"), event("pass")]


class ReceiptTest(unittest.TestCase):
    def rejects(self, rows, names=(LEAF,), exit_code=0):
        with self.assertRaises(ValueError):
            receipt.verify(stream(rows), PACKAGE, names, exit_code)

    def test_exact_nested_leaf_needs_and_verifies_parent(self):
        result = receipt.verify(stream(complete()), PACKAGE, [LEAF], 0)
        self.assertEqual(result, {"status": "pass", "explicit_expected_count": 1,
                                  "verified_test_count_including_parents": 2})
        self.assertEqual(receipt.verify(stream(complete()), PACKAGE, [ROOT, LEAF], 0)
                         ["verified_test_count_including_parents"], 2)

    def test_literal_apostrophes_in_nested_leaf(self):
        leaf = ROOT + "/should_return_'blue'_for_absent_colour"
        rows = [event("start"), event("run", ROOT), event("run", leaf),
                event("pass", leaf), event("pass", ROOT), event("pass")]
        self.assertEqual(receipt.expected_names([leaf]), {ROOT, leaf})
        self.assertEqual(receipt.verify(stream(rows), PACKAGE, [leaf], 0),
                         {"status": "pass", "explicit_expected_count": 1,
                          "verified_test_count_including_parents": 2})
        mismatched = leaf.replace("'", "")
        with self.assertRaisesRegex(ValueError, "unexpected test name"):
            receipt.verify(stream(rows), PACKAGE, [mismatched], 0)

    def test_root_only_pass_cannot_satisfy_named_leaf(self):
        self.rejects([event("start"), event("run", ROOT), event("pass", ROOT), event("pass")])

    def test_exact_root_only_and_multiple_explicit_leaves(self):
        root_only = [event("start"), event("run", ROOT), event("pass", ROOT), event("pass")]
        self.assertEqual(receipt.verify(stream(root_only), PACKAGE, [ROOT], 0)
                         ["verified_test_count_including_parents"], 1)
        other = ROOT + "/green"
        rows = complete()[:5] + [event("run", other), event("pass", other)] + complete()[5:]
        self.assertEqual(receipt.verify(stream(rows), PACKAGE, [LEAF, other], 0)
                         ["verified_test_count_including_parents"], 3)

    def test_deep_nested_literal_go_names_include_all_ancestors(self):
        parent = ROOT + "/colour_palette"
        leaf = parent + "/blue-gray"
        repeated = leaf + "#01"
        # Go reports normalized spaces as underscores and disambiguates
        # repeated subtest labels with numeric suffixes. Those names remain
        # distinct literal events, including every intermediate ancestor.
        rows = [
            event("start"), event("run", ROOT), event("run", parent),
            event("run", leaf), event("pass", leaf),
            event("run", repeated), event("pass", repeated),
            event("pass", parent), event("pass", ROOT), event("pass"),
        ]
        self.assertEqual(receipt.expected_names([repeated, leaf]),
                         {ROOT, parent, leaf, repeated})
        self.assertEqual(receipt.verify(stream(rows), PACKAGE, [repeated, leaf], 0),
                         {"status": "pass", "explicit_expected_count": 2,
                          "verified_test_count_including_parents": 4})
        self.assertEqual(receipt.verify(stream(rows), PACKAGE,
                                        [repeated, ROOT, parent, leaf], 0),
                         {"status": "pass", "explicit_expected_count": 4,
                          "verified_test_count_including_parents": 4})

    def test_interleaved_parallel_roots_and_leaves_pass(self):
        other_root = "TestLabel"
        other_leaf = ROOT + "/green"
        # Parallel roots may pause, resume and finish interleaved with
        # parallel children. The parent must finish after both leaves, not
        # before another root, and expected names need not be in event order.
        rows = [
            event("start"),
            event("run", ROOT), event("pause", ROOT),
            event("run", other_root), event("pause", other_root),
            event("cont", ROOT),
            event("run", LEAF), event("pause", LEAF),
            event("run", other_leaf), event("pause", other_leaf),
            event("cont", other_root),
            dict(event("output", other_root), Output="ordinary label\n"),
            dict(event("pass", other_root), Elapsed=0.01),
            event("cont", other_leaf),
            dict(event("pass", other_leaf), Elapsed=0.01),
            event("cont", LEAF),
            dict(event("pass", LEAF), Elapsed=0.01),
            dict(event("pass", ROOT), Elapsed=0.02),
            event("output"), event("pass"),
        ]
        for names in ([other_leaf, other_root, LEAF], [LEAF, ROOT, other_leaf, other_root]):
            with self.subTest(explicit_count=len(names)):
                self.assertEqual(receipt.verify(stream(rows), PACKAGE, names, 0),
                                 {"status": "pass", "explicit_expected_count": len(names),
                                  "verified_test_count_including_parents": 4})

    def test_go_generated_nested_parallel_events_pass(self):
        # The earlier positive fixtures model Go events by hand. Exercise
        # the actual Go JSON producer on an isolated dependency-free module.
        source = """package ordinary

import "testing"

func TestPaint(t *testing.T) {
    t.Parallel()
    t.Run("colour palette", func(t *testing.T) {
        for _, label := range []string{"blue-gray", "blue-gray"} {
            t.Run(label, func(t *testing.T) {
                t.Parallel()
                t.Log("ordinary colour")
            })
        }
    })
}

func TestLabel(t *testing.T) {
    t.Parallel()
    t.Log("ordinary label")
}
"""
        parent = ROOT + "/colour_palette"
        leaf = parent + "/blue-gray"
        repeated = leaf + "#01"
        other_root = "TestLabel"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module " + PACKAGE + "\n\ngo 1.26\n",
                                          encoding="utf-8")
            (root / "display_test.go").write_text(source, encoding="utf-8")
            env = dict(os.environ, GOWORK="off", GOTOOLCHAIN="local",
                       GOPROXY="off", GOSUMDB="off", GOVCS="*:off",
                       GOFLAGS="-mod=readonly")
            result = subprocess.run(
                ["go", "test", "-json", "-count=1", "-parallel=2",
                 "-run", "^(TestPaint|TestLabel)$", "."],
                cwd=root, env=env, capture_output=True, check=False, timeout=120,
            )
            self.assertEqual(result.returncode, 0, "synthetic Go test did not pass")
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        parallel = {ROOT, other_root, leaf, repeated}
        for action in ("pause", "cont"):
            self.assertEqual({row.get("Test") for row in rows if row["Action"] == action},
                             parallel)
        self.assertEqual(receipt.verify(result.stdout, PACKAGE,
                                        [repeated, other_root, leaf], result.returncode),
                         {"status": "pass", "explicit_expected_count": 3,
                          "verified_test_count_including_parents": 5})

    def test_zero_exit_without_tests_does_not_count(self):
        warning = dict(event("output"), Output="testing: warning: no tests to run\n")
        self.rejects([event("start"), warning, event("pass")])

    def test_wrong_leaf_or_extra_test_does_not_count(self):
        wrong = ROOT + "/green"
        self.rejects([event("start"), event("run", ROOT), event("run", wrong),
                      event("pass", wrong), event("pass", ROOT), event("pass")])
        self.rejects(complete(), names=(ROOT,))

    def test_failure_skip_duplicate_or_pass_without_run_do_not_count(self):
        for action in ("fail", "skip"):
            with self.subTest(action=action):
                self.rejects(complete()[:3] + [event(action, LEAF)] + complete()[4:])
        self.rejects(complete()[:3] + [event("run", LEAF)] + complete()[3:])
        self.rejects(complete()[:5] + [event("pass", LEAF)] + complete()[5:])
        self.rejects([event("start"), event("pass", LEAF), event("pass")])
        self.rejects([event("start"), event("run", LEAF), event("pass", LEAF)])

    def test_wrong_package_missing_terminal_and_nonzero_exit_do_not_count(self):
        self.rejects(complete()[:-1])
        self.rejects(complete() + [event("pass")])
        self.rejects(complete()[:3] + [event("pass", LEAF, "example.test/other")] + complete()[5:])
        self.rejects(complete(), exit_code=1)
        self.rejects(complete(), exit_code=False)
        self.rejects([event("start")] + complete())

    def test_malformed_json_and_invalid_expected_names_do_not_count(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON test event"):
            receipt.verify(b"not-json\n", PACKAGE, [LEAF], 0)
        for names in ([], [LEAF, LEAF], [""], [ROOT + "/"], ["^Test.*$"], [1]):
            with self.subTest(names=names):
                self.rejects(complete(), names=tuple(names))

    def test_cli_outputs_counts_not_event_values_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            args = ["--events", str(path), "--package", PACKAGE, "--expect", LEAF,
                    "--exit-code", "0"]
            path.write_bytes(stream(complete()))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(receipt.main(args), 0)
            self.assertNotIn(LEAF, out.getvalue())
            self.assertEqual(err.getvalue(), "")
            path.write_bytes(stream([event("start"), event("pass")]))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(receipt.main(args), 1)
            self.assertEqual(out.getvalue(), "")
            self.assertNotIn(str(path), err.getvalue())
            path.unlink()
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(receipt.main(args), 1)
            self.assertEqual(err.getvalue(), "named test receipt: event stream unavailable\n")


if __name__ == "__main__":
    unittest.main()
