"""Index independently produced package reports without combining modules."""
import argparse
import hashlib
import json
import re
from pathlib import Path


class InvalidInput(ValueError):
    """Invalid report identity or incompatible input metadata."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, reason):
    if not condition:
        raise InvalidInput(reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_json(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidInput("invalid JSON input") from None


def exact_keys(obj, keys, reason):
    require(isinstance(obj, dict) and set(obj) == set(keys), reason)


def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def import_path(value):
    return matches(value, r"[A-Za-z0-9_.~-]+(?:/[A-Za-z0-9_.~-]+)*") and all(
        part not in (".", "..") for part in value.split("/")
    )


def counts(value):
    exact_keys(value, ("covered", "total"), "invalid statement counts")
    covered, total = value["covered"], value["total"]
    require(type(covered) is int and type(total) is int and 0 <= covered <= total,
            "invalid statement counts")
    return {"covered": covered, "total": total}


def artifact(base, spec):
    exact_keys(spec, ("file", "sha256"), "invalid artifact identity")
    name = spec["file"]
    require(isinstance(name, str) and name and not Path(name).is_absolute() and
            all(ord(char) >= 32 and ord(char) != 127 for char in name),
            "expected relative artifact filename")
    require(matches(spec["sha256"], r"[0-9a-f]{64}"), "invalid artifact digest")
    path = (base / name).resolve()
    require(path.is_relative_to(base), "artifact outside input directory")
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    require(digest(raw) == spec["sha256"], "artifact digest mismatch")
    return raw


def absent_group(group, status):
    return {
        "status": status,
        "packages": [{"package": package, "status": "unknown", "statements": None}
                     for package in group["packages"]],
        "reported_observed_statements": None,
        "reported_aggregate_statements": None,
        "profile_sha256": None,
        "report_sha256": None,
    }


def verify_report(raw, profile, packages):
    report = load_json(raw)
    require(isinstance(report, dict) and report.get("profile_status") == "present",
            "expected report for a present profile")
    require(report.get("profile_sha256") == digest(profile), "report/profile mismatch")
    mode = report.get("profile_mode")
    require(mode in ("atomic", "count", "set") and
            profile.split(b"\n", 1)[0] == ("mode: " + mode).encode("ascii"),
            "coverage profile mode mismatch")
    rows = report.get("packages")
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
            and [row.get("package") for row in rows] == packages,
            "report package roster mismatch")
    observed = {"covered": 0, "total": 0}
    presented = []
    for row in rows:
        status = row.get("status")
        if status == "measured":
            statements = counts(row.get("statements"))
            for key in observed:
                observed[key] += statements[key]
        else:
            require(status == "package_absent" and "statements" in row and
                    row["statements"] is None, "invalid package status")
            statements = None
        presented.append({"package": row["package"], "status": status,
                          "statements": statements})
    complete = all(row["status"] == "measured" for row in presented)
    require(report.get("all_requested_packages_present") is complete and
            counts(report.get("observed_statements")) == observed,
            "package totals inconsistent")
    manifest = report.get("manifest")
    if manifest is not None:
        require(isinstance(manifest, dict) and
                type(manifest.get("all_expected_files_present")) is bool,
                "invalid expected-file manifest status")
        complete = complete and manifest["all_expected_files_present"]
    require("aggregate_statements" in report, "missing aggregate status")
    aggregate = report["aggregate_statements"]
    if complete:
        require(counts(aggregate) == observed, "aggregate totals inconsistent")
    else:
        require(aggregate is None, "incomplete report claims an aggregate")
    return {
        "status": "reported_complete" if complete else "reported_partial",
        "packages": presented,
        # A zero accumulator for an entirely absent roster is not a measurement.
        "reported_observed_statements": observed if any(
            row["status"] == "measured" for row in presented) else None,
        "reported_aggregate_statements": aggregate,
        "profile_sha256": digest(profile),
        "report_sha256": digest(raw),
    }


def consolidate(manifest_raw, base):
    base = base.resolve()
    manifest = load_json(manifest_raw)
    exact_keys(manifest, ("schema", "groups"), "invalid input manifest")
    require(manifest["schema"] == "ordinary-module-reports-input-v1" and
            isinstance(manifest["groups"], list) and bool(manifest["groups"]),
            "expected nonempty module report groups")
    groups, identifiers, identities = [], set(), set()
    for group in manifest["groups"]:
        exact_keys(group, ("id", "module", "revision", "mode", "packages", "evidence"),
                   "invalid group declaration")
        gid, module, revision, mode = (group[name] for name in ("id", "module", "revision", "mode"))
        require(matches(gid, r"[A-Za-z0-9][A-Za-z0-9_-]*") and import_path(module)
                and matches(revision, r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
                and mode in ("normal", "race"), "invalid group identity")
        identity = (module, mode)
        require(gid not in identifiers and identity not in identities,
                "duplicate group identity")
        identifiers.add(gid)
        identities.add(identity)
        packages = group["packages"]
        require(isinstance(packages, list) and bool(packages) and all(
            import_path(package) and (package == module or package.startswith(module + "/"))
            for package in packages) and len(set(packages)) == len(packages),
            "invalid module package roster")
        evidence = group["evidence"]
        if evidence is None:
            result = absent_group(group, "not_supplied")
        else:
            exact_keys(evidence, ("report", "profile"), "invalid evidence declaration")
            report = artifact(base, evidence["report"])
            profile = artifact(base, evidence["profile"])
            if report is None or profile is None:
                result = absent_group(group, "artifact_absent")
                result["report_sha256"] = digest(report) if report is not None else None
                result["profile_sha256"] = digest(profile) if profile is not None else None
            else:
                result = verify_report(report, profile, packages)
        groups.append({"id": gid, "module": module, "revision": revision,
                       "execution_mode": mode, **result})
    return {
        "schema": "ordinary-module-reports-v1",
        "manifest_sha256": digest(manifest_raw),
        "groups": groups,
        "cross_module_aggregate": None,
        "scope": "retained report index only; source, execution and ordinary-scope attribution not established",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = consolidate(args.manifest.read_bytes(), args.manifest.parent)
    except (OSError, InvalidInput):
        parser.exit(1, "module report input unavailable or inconsistent\n")
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
