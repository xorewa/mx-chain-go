"""Optional offline Draft 2020-12 conformance check for public display data."""
import argparse
import hashlib
import importlib.metadata
import json
import pathlib
import sys


HERE = pathlib.Path(__file__).resolve().parent
SCHEMA = HERE.parents[3] / "api/shared/observation-v1.schema.json"
FIXTURES = HERE / "fixtures.json"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
ADOPTED_SCHEMA_SHA256 = "f2018331d7c86c2daa1c2b3d34003c8d10d3403381cd0cb8a6ddb7c26ba1c617"
FIXTURES_SHA256 = "7facf7ca775372684c91d792da6d4b10bc666eaf4207fdcb7666b43b15d55a1d"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def supplier_digest(root):
    """Hash all supplied files, including dependency metadata, by relative name."""
    if not root.is_dir():
        raise FileNotFoundError
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("supplier contains a symbolic link")
        if path.is_file():
            files.append([path.relative_to(root).as_posix(), sha256(path.read_bytes())])
        elif not path.is_dir():
            raise ValueError("supplier contains a non-regular entry")
    if not files:
        raise ValueError("empty supplier")
    return sha256(json.dumps(files, separators=(",", ":"), ensure_ascii=True).encode())


def load_validator(root, expected_version):
    """Use only the explicitly supplied jsonschema installation and dependencies."""
    sys.path.insert(0, str(root))
    distribution = importlib.metadata.distribution("jsonschema")
    if distribution.version != expected_version or pathlib.Path(distribution.locate_file("")).resolve() != root:
        raise ValueError("validator identity mismatch")
    import jsonschema
    if not pathlib.Path(jsonschema.__file__).resolve().is_relative_to(root):
        raise ValueError("validator source mismatch")
    validator = jsonschema.Draft202012Validator
    if validator.META_SCHEMA.get("$id") != DRAFT:
        raise ValueError("validator does not declare expected dialect")
    return validator


def evaluate(validator, schema, fixtures):
    """Return explicit compilation and per-document structural results."""
    try:
        validator.check_schema(schema)
        compiled = validator(schema)
    except Exception:
        return False, None
    results = []
    for case in fixtures:
        try:
            actual = compiled.is_valid(case["document"])
        except Exception:
            return True, None
        if type(actual) is not bool:
            return True, None
        results.append({"name": case["name"], "expected_valid": case["expected_valid"],
                        "actual_valid": actual, "matches": actual == case["expected_valid"]})
    return True, results


def run(args, *, schema_path=SCHEMA, fixtures_path=FIXTURES, runtime_path=None, isolated=None, loader=load_validator):
    report = {"status": "blocked", "reason": None, "dialect": DRAFT,
              "schema_sha256": None, "fixtures_sha256": None,
              "validator": {"implementation": "python-jsonschema", "version": None,
                            "supplier_tree_sha256": None, "python_sha256": None,
                            "python_version": None},
              "schema_compilation": None, "cases": None}

    def finish(reason, status="blocked", code=2):
        report.update(status=status, reason=reason)
        return code, report

    try:
        schema_bytes, fixture_bytes = schema_path.read_bytes(), fixtures_path.read_bytes()
        report["schema_sha256"], report["fixtures_sha256"] = sha256(schema_bytes), sha256(fixture_bytes)
        if report["schema_sha256"] != ADOPTED_SCHEMA_SHA256:
            return finish("schema_identity_mismatch")
        if report["fixtures_sha256"] != FIXTURES_SHA256:
            return finish("fixture_identity_mismatch")
        schema, fixtures = json.loads(schema_bytes), json.loads(fixture_bytes)
    except (OSError, ValueError):
        return finish("input_unavailable")
    if not all((args.validator_root, args.validator_tree_sha256, args.validator_version, args.python_sha256)):
        return finish("validator_pin_missing")
    if isolated is None:
        isolated = sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
    if not isolated:
        return finish("isolated_runtime_required")
    try:
        runtime_path = pathlib.Path(runtime_path or sys.executable).resolve(strict=True)
        report["validator"]["python_sha256"] = sha256(runtime_path.read_bytes())
        report["validator"]["python_version"] = ".".join(str(x) for x in sys.version_info[:3])
        if report["validator"]["python_sha256"] != args.python_sha256:
            return finish("runtime_identity_mismatch")
        supplier = pathlib.Path(args.validator_root).resolve(strict=True)
        report["validator"]["supplier_tree_sha256"] = supplier_digest(supplier)
    except (OSError, ValueError):
        return finish("supplier_or_runtime_unavailable")
    if report["validator"]["supplier_tree_sha256"] != args.validator_tree_sha256:
        return finish("supplier_identity_mismatch")
    try:
        validator = loader(supplier, args.validator_version)
    except (ImportError, importlib.metadata.PackageNotFoundError, AttributeError):
        return finish("validator_unavailable")
    except ValueError:
        return finish("validator_identity_mismatch")
    except Exception:
        return finish("validator_load_error", "error", 1)
    report["validator"]["version"] = args.validator_version
    report["schema_compilation"], report["cases"] = evaluate(validator, schema, fixtures)
    if not report["schema_compilation"]:
        return finish("schema_compilation_failed", "fail", 1)
    if report["cases"] is None:
        return finish("validation_error", "error", 1)
    if not all(case["matches"] for case in report["cases"]):
        return finish("fixture_mismatch", "fail", 1)
    return finish(None, "pass", 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validator-root", help="offline installation root (jsonschema and its dependencies)")
    parser.add_argument("--validator-tree-sha256")
    parser.add_argument("--validator-version")
    parser.add_argument("--python-sha256")
    code, report = run(parser.parse_args())
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
