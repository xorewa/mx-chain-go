import argparse
import importlib.metadata
import io
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import validate


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.supplier = self.root / "supplier"
        self.supplier.mkdir()
        (self.supplier / "label.txt").write_text("synthetic supplier bytes")
        self.runtime = self.root / "python"
        self.runtime.write_bytes(b"synthetic runtime bytes")
        self.args = argparse.Namespace(
            validator_root=str(self.supplier),
            validator_tree_sha256=validate.supplier_digest(self.supplier),
            validator_version="toy-test-version",
            python_sha256=validate.sha256(self.runtime.read_bytes()),
        )

    def invoke(self, loader=None, **kwargs):
        kwargs.setdefault("runtime_path", self.runtime)
        kwargs.setdefault("isolated", True)
        if loader is None:
            def loader(*unused):
                self.fail("validator must not be invoked")
        return validate.run(self.args, loader=loader, **kwargs)

    def test_missing_supplier_never_passes(self):
        self.args.validator_root = None
        code, report = self.invoke()
        self.assertEqual((code, report["status"], report["reason"]), (2, "blocked", "validator_pin_missing"))
        self.assertIsNone(report["schema_compilation"])
        self.assertIsNone(report["cases"])

    def test_isolation_and_pin_mismatches(self):
        code, report = self.invoke(isolated=False)
        self.assertEqual((code, report["reason"]), (2, "isolated_runtime_required"))
        old = self.args.python_sha256
        self.args.python_sha256 = "wrong"
        self.assertEqual(self.invoke()[1]["reason"], "runtime_identity_mismatch")
        self.args.python_sha256 = old
        self.args.validator_tree_sha256 = "wrong"
        self.assertEqual(self.invoke()[1]["reason"], "supplier_identity_mismatch")
        self.args.validator_root = str(self.root / "absent")
        self.assertEqual(self.invoke()[1]["reason"], "supplier_or_runtime_unavailable")

    def test_inputs_are_bound_to_exact_bytes(self):
        altered = self.root / "altered.json"
        altered.write_text("{}")
        self.assertEqual(self.invoke(schema_path=altered)[1]["reason"], "schema_identity_mismatch")
        self.assertEqual(self.invoke(fixtures_path=altered)[1]["reason"], "fixture_identity_mismatch")
        self.assertEqual(self.invoke(fixtures_path=self.root / "absent")[1]["reason"], "input_unavailable")

    def test_supplier_digest_is_relative_and_exact(self):
        old = self.args.validator_tree_sha256
        copy = self.root / "other"
        copy.mkdir()
        (copy / "label.txt").write_text("synthetic supplier bytes")
        self.assertEqual(validate.supplier_digest(copy), old)
        (copy / "label.txt").write_text("changed")
        self.assertNotEqual(validate.supplier_digest(copy), old)
        (copy / "alias").symlink_to(self.supplier / "label.txt")
        with self.assertRaises(ValueError):
            validate.supplier_digest(copy)
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(ValueError):
            validate.supplier_digest(empty)
        with self.assertRaises(FileNotFoundError):
            validate.supplier_digest(self.root / "absent")
        if hasattr(os, "mkfifo"):
            os.mkfifo(empty / "nonregular")
            with self.assertRaises(ValueError):
                validate.supplier_digest(empty)

    def test_cli_missing_pin_and_unisolated_runtime_are_not_passes(self):
        out = io.StringIO()
        with patch("sys.argv", ["validate.py"]), redirect_stdout(out):
            self.assertEqual(validate.main(), 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result["reason"], "validator_pin_missing")
        self.assertIsNone(result["schema_compilation"])
        self.assertIsNone(result["cases"])
        with patch.object(sys, "flags", types.SimpleNamespace(
                isolated=0, no_site=0, dont_write_bytecode=0)):
            code, result = self.invoke(isolated=None)
        self.assertEqual((code, result["reason"]), (2, "isolated_runtime_required"))

    def test_validator_load_failures_are_distinct(self):
        for error, reason, code in [
            (ImportError(), "validator_unavailable", 2),
            (importlib.metadata.PackageNotFoundError(), "validator_unavailable", 2),
            (ValueError(), "validator_identity_mismatch", 2),
            (RuntimeError(), "validator_load_error", 1),
        ]:
            with self.subTest(reason=reason):
                def loader(*unused):
                    raise error
                actual, report = self.invoke(loader)
                self.assertEqual((actual, report["reason"]), (code, reason))
                self.assertIsNone(report["schema_compilation"])

    def test_validator_identity_checks_use_only_supplied_root(self):
        root = self.supplier
        meta = types.SimpleNamespace(version="toy", locate_file=lambda _: root)
        fake = types.SimpleNamespace(__file__=str(root / "jsonschema.py"),
                                     Draft202012Validator=types.SimpleNamespace(META_SCHEMA={"$id": validate.DRAFT}))
        with patch.object(sys, "path", []), patch.object(importlib.metadata, "distribution", return_value=meta), \
                patch.dict(sys.modules, {"jsonschema": fake}):
            self.assertIs(validate.load_validator(root, "toy"), fake.Draft202012Validator)
            with self.assertRaises(ValueError):
                validate.load_validator(root, "other")
            fake.Draft202012Validator.META_SCHEMA = {"$id": "other"}
            with self.assertRaises(ValueError):
                validate.load_validator(root, "toy")
            fake.__file__ = str(self.root / "outside.py")
            with self.assertRaises(ValueError):
                validate.load_validator(root, "toy")

    def test_mocked_outcomes_distinguish_compile_validation_and_pass(self):
        # Pure harness unit test. The fake class only echoes predeclared
        # outcomes; it does not perform, or claim, schema conformance.
        cases = json.loads(validate.FIXTURES.read_text())
        expected = {json.dumps(c["document"], sort_keys=True): c["expected_valid"] for c in cases}
        class Fake:
            def check_schema(schema):
                self.assertEqual(schema["$schema"], validate.DRAFT)

            def __init__(self, schema):
                pass

            def is_valid(self, document):
                return expected[json.dumps(document, sort_keys=True)]

        code, report = self.invoke(lambda *_: Fake)
        self.assertEqual((code, report["status"]), (0, "pass"))
        self.assertTrue(report["schema_compilation"])
        self.assertEqual(len(report["cases"]), 9)
        self.assertTrue(all(row["matches"] for row in report["cases"]))

        class Mismatch(Fake):
            def is_valid(self, document):
                return not super().is_valid(document)
        self.assertEqual(self.invoke(lambda *_: Mismatch)[1]["reason"], "fixture_mismatch")

        class CompileFailure(Fake):
            def check_schema(schema):
                raise ValueError
        code, report = self.invoke(lambda *_: CompileFailure)
        self.assertEqual((code, report["schema_compilation"], report["cases"]), (1, False, None))

        class EvaluationFailure(Fake):
            def is_valid(self, document):
                raise RuntimeError
        self.assertEqual(self.invoke(lambda *_: EvaluationFailure)[1]["reason"], "validation_error")

        class NonBoolean(Fake):
            def is_valid(self, document):
                return "not a boolean"
        self.assertEqual(self.invoke(lambda *_: NonBoolean)[1]["reason"], "validation_error")


if __name__ == "__main__":
    unittest.main()
