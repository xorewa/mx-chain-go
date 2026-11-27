"""Compare independently bound ordinary named-test receipts offline.

No execution or subject authentication is performed. Outputs are optional
caller-supplied canonical ordinary observations, never extracted from logs.
"""

import argparse
import hashlib
import json
from pathlib import Path

import named_test_receipt
import ordinary_package_profile
from ordinary_pair_receipt import hex_digest, identities, keys, read_artifact, require


MODES = ("normal", "race")
SIDES = ("candidate", "reference", "third")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def subject(item):
    keys(item, ("revision", "locks", "sources", "modes"))
    require(hex_digest(item["revision"], 40), "invalid revision")
    keys(item["locks"], ("go.mod", "go.sum"))
    identities(item["locks"])
    identities(item["sources"])
    keys(item["modes"], MODES)


def verify_leg(leg, base, seen, package, tests):
    if leg is None:
        return None
    keys(leg, ("exit", "events", "profile", "output"))
    code = leg["exit"]
    require(type(code) is int, "invalid command exit")
    event = read_artifact(base, leg["events"], seen)
    result = {"exit": code, "events_sha256": leg["events"]["sha256"],
              "status": "nonpassing" if code else "pass",
              "profile_sha256": None, "output_sha256": None,
              "named_pass": None}
    if leg["profile"] is not None:
        raw = read_artifact(base, leg["profile"], seen)
        ordinary_package_profile.validate(raw, package)
        result["profile_sha256"] = leg["profile"]["sha256"]
    if leg["output"] is not None:
        raw = read_artifact(base, leg["output"], seen)
        result["output_sha256"] = hashlib.sha256(raw).hexdigest()
    if code == 0:
        require(result["profile_sha256"] is not None, "missing profile for passed leg")
        result["named_pass"] = named_test_receipt.verify(event, package, tests, code)
    return result


def compare(left, right):
    if left is None or right is None:
        return {"status": "not_supplied", "exit_equal": None,
                "named_pass": None, "output_equal": None}
    both_pass = left["exit"] == right["exit"] == 0
    output_equal = None
    if both_pass and left["output_sha256"] is not None and right["output_sha256"] is not None:
        output_equal = left["output_sha256"] == right["output_sha256"]
    return {"status": "measured" if both_pass else "nonpassing",
            "exit_equal": left["exit"] == right["exit"],
            "named_pass": both_pass, "output_equal": output_equal}


def verify(manifest, base):
    keys(manifest, ("schema", "cohorts"))
    require(manifest["schema"] == "ordinary-equivalence-receipt-v1", "unknown schema")
    cohorts = manifest["cohorts"]
    require(isinstance(cohorts, list) and bool(cohorts), "empty cohort list")
    base = base.resolve()
    seen = set()
    labels = set()
    results = []
    for cohort in cohorts:
        keys(cohort, ("id", "package", "tests", *SIDES))
        label, package, tests = (cohort[k] for k in ("id", "package", "tests"))
        require(isinstance(label, str) and bool(label) and label.isprintable()
                and label not in labels, "invalid or repeated cohort id")
        labels.add(label)
        require(isinstance(package, str) and bool(package) and package.isprintable()
                and not any(c.isspace() for c in package), "invalid package")
        require(isinstance(tests, list), "invalid named test list")
        named_test_receipt.expected_names(tests)
        for side in ("candidate", "reference"):
            subject(cohort[side])
        require(cohort["candidate"]["revision"] != cohort["reference"]["revision"],
                "identical counterpart revision")
        shared = cohort["candidate"]["sources"]
        require(shared == cohort["reference"]["sources"], "declared source or fixture mismatch")
        if cohort["third"] is not None:
            subject(cohort["third"])
            require(shared == cohort["third"]["sources"], "declared third-leg source mismatch")

        sides = {}
        for side in SIDES:
            item = cohort[side]
            if item is None:
                sides[side] = None
                continue
            sides[side] = {
                "revision": item["revision"], "locks": item["locks"],
                "modes": {mode: verify_leg(item["modes"][mode], base, seen, package, tests)
                          for mode in MODES},
            }

        def leg(side, mode):
            return None if sides[side] is None else sides[side]["modes"][mode]

        results.append({
            "id": label, "package": package, "tests": tests,
            "declared_shared_sources": shared, "subjects": sides,
            "candidate_reference": {m: compare(leg("candidate", m), leg("reference", m))
                                    for m in MODES},
            "candidate_third": {m: compare(leg("candidate", m), leg("third", m))
                                for m in MODES},
            "reference_third": {m: compare(leg("reference", m), leg("third", m))
                                for m in MODES},
        })
    return {"schema": "ordinary-equivalence-receipt-result-v1", "cohorts": results,
            "scope": "declared provenance and named assertions only; optional canonical output "
                     "byte equality, not an independent operational oracle or qualification"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw = args.manifest.read_bytes()
        result = verify(json.loads(raw, object_pairs_hook=unique_object), args.manifest.parent)
    except (ValueError, OSError):
        parser.exit(1, "ordinary equivalence receipt unavailable or invalid\n")
    result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
