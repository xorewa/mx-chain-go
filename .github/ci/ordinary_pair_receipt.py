"""Read-only validation of retained, ordinary named Go test pairs.

This tool checks declared identities, file digests, exact test events and
package profile structure. It neither executes commands nor authenticates
the caller's revision, mode, source or lock declarations. A passing pair is
not an operational equivalence or coverage qualification result.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

import named_test_receipt
import ordinary_package_profile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hex_digest(value, size=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{size}}}", value) is not None


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "unexpected record fields")


def read_artifact(base, value, seen):
    keys(value, ("file", "sha256"))
    name = value["file"]
    require(isinstance(name, str) and name and hex_digest(value["sha256"]), "invalid artifact identity")
    rel = Path(name)
    require(not rel.is_absolute() and ".." not in rel.parts, "artifact outside manifest directory")
    src = (base / rel).resolve()
    require(src.is_relative_to(base) and src not in seen and src.is_file(),
            "artifact unavailable, outside directory or reused")
    seen.add(src)
    data = src.read_bytes()
    require(hashlib.sha256(data).hexdigest() == value["sha256"], "artifact digest mismatch")
    return data


def identities(mapping):
    require(isinstance(mapping, dict) and bool(mapping) and all(
        isinstance(k, str) and k and k.isprintable() and not Path(k).is_absolute()
        and ".." not in Path(k).parts and "\\" not in k and hex_digest(v)
        for k, v in mapping.items()), "invalid declared source identity")
    return mapping


def verify(manifest, base):
    keys(manifest, ("schema", "package", "tests", "candidate", "reference"))
    require(manifest["schema"] == "ordinary-pair-receipt-v1", "unknown schema")
    package, tests = manifest["package"], manifest["tests"]
    require(isinstance(package, str) and bool(package) and package.isprintable()
            and not any(c.isspace() for c in package), "invalid package")
    require(isinstance(tests, list) and bool(tests), "empty named selection")
    named_test_receipt.expected_names(tests)
    base = base.resolve()
    seen = set()
    sides = {}
    for side in ("candidate", "reference"):
        item = manifest[side]
        keys(item, ("revision", "locks", "sources", "modes"))
        require(hex_digest(item["revision"], 40), "invalid revision")
        keys(item["locks"], ("go.mod", "go.sum"))
        identities(item["locks"])
        identities(item["sources"])
        keys(item["modes"], ("normal", "race"))
        sides[side] = {"revision": item["revision"], "locks": item["locks"], "modes": {}}
    require(sides["candidate"]["revision"] != sides["reference"]["revision"], "identical counterpart revision")
    shared_sources = manifest["candidate"]["sources"]
    require(shared_sources == manifest["reference"]["sources"], "declared source or fixture mismatch")

    for side in sides:
        for mode in ("normal", "race"):
            leg = manifest[side]["modes"][mode]
            if leg is None:
                sides[side]["modes"][mode] = None
                continue
            keys(leg, ("exit", "events", "profile"))
            events = read_artifact(base, leg["events"], seen)
            profile = read_artifact(base, leg["profile"], seen)
            result = named_test_receipt.verify(events, package, tests, leg["exit"])
            ordinary_package_profile.validate(profile, package)
            sides[side]["modes"][mode] = {**result,
                "events_sha256": leg["events"]["sha256"],
                "profile_sha256": leg["profile"]["sha256"]}

    return {"schema": "ordinary-pair-receipt-result-v1", "package": package,
            "tests": tests, "declared_shared_sources": shared_sources,
            "subjects": sides,
            "paired_named_pass": {mode: (True if all(sides[s]["modes"][mode] is not None
                                                      for s in sides) else None)
                                  for mode in ("normal", "race")},
            "scope": "named pass/profile structure only; external provenance and behavior equivalence not established"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw = args.manifest.read_bytes()
        result = verify(json.loads(raw), args.manifest.parent)
    except (ValueError, OSError):
        parser.exit(1, "ordinary pair receipt unavailable or invalid\n")
    result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
