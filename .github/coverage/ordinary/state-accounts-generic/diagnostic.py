#!/usr/bin/env python3
"""Offline optional state/accounts DTO evidence adapter; never executes product tests."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


SCOPE = "generic account DTO diagnostic only; not direct standard-token scope or a qualification gate"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def encode(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def check_census(census):
    require(census["version"] == 1, "unsupported census")
    roots = census["roots"]
    require(len(roots) == len(set(roots)) == 11, "invalid root census")
    require(census["selector"] == "^(" + "|".join(roots) + ")$", "selector mismatch")
    require(set(roots) == {n for n in census["expected_passes"] if "/" not in n}, "event census mismatch")
    require(len(census["functions"]) == 37 and sum(
        b["statements"] for f in census["functions"] for b in f["blocks"]
    ) == census["expected_statements"] == 229, "function census mismatch")


def check_sources(root, census):
    root = root.resolve(strict=True)
    for name, expected in census["source_test_lock_sha256"].items():
        path = (root / name).resolve(strict=True)
        require(path.is_relative_to(root) and path.is_file(), "source path outside exact root")
        require(digest(path.read_bytes()) == expected, "source/test/lock digest mismatch: " + name)


def check_argv(argv, mode, census):
    # The receipt records the inner argv; the enclosing host command is retained by the producer.
    require(isinstance(argv, list) and all(isinstance(a, str) for a in argv), "invalid argv")
    require(len(argv) >= 3 and Path(argv[0]).name == "go" and argv[1] == "test", "not an exact Go test invocation")
    require(argv[-1] in ("./state/accounts", census["package"]), "wrong package selection")
    args = argv[2:-1]
    require(args.count("-run") == 1, "exact test selector required")
    i = args.index("-run")
    require(i + 1 < len(args) and args[i + 1] == census["selector"], "wrong test selector")
    args = args[:i] + args[i + 2:]
    profiles = [x for x in args if x.startswith("-coverprofile=") and len(x) > len("-coverprofile=")]
    require(len(profiles) == 1, "exact profile output required")
    args.remove(profiles[0])
    expected = ["-mod=readonly", "-p=2", "-short", "-count=1", "-timeout=120s", "-covermode=atomic", "-json"]
    if mode == "race":
        expected.append("-race")
    require(sorted(args) == sorted(expected), "wrong test options or mode")


def check_events(raw, census):
    passed = set()
    package_pass = 0
    for line in raw.splitlines():
        event = json.loads(line)
        require(event.get("Package") == census["package"], "unexpected event package")
        action, name = event.get("Action"), event.get("Test")
        require(action not in ("fail", "skip"), "nonpassing test event")
        if name is None:
            package_pass += action == "pass"
            continue
        require(name in census["expected_passes"], "unexpected test event")
        if action == "pass":
            require(name not in passed, "duplicate pass event")
            passed.add(name)
    require(passed == set(census["expected_passes"]) and package_pass == 1, "incomplete test terminal evidence")


def bind_mode(census, subject, mode, profile, events, receipt):
    require(receipt["candidate"] == subject and receipt["common"] == census["common_commit"], "candidate/dependency mismatch")
    require(type(receipt["exit"]) is int and receipt["exit"] == 0, "test failed")
    check_argv(receipt["argv"], mode, census)
    require(receipt["profile_sha256"] == digest(profile) and receipt["stdout_sha256"] == digest(events), "profile/event digest mismatch")
    check_events(events, census)
    # Do not rewrite profile data. The existing reporter validates source coordinates and counts.
    lines = profile.decode("ascii").splitlines()
    require(lines and lines[0] == "mode: atomic", "wrong profile mode")
    package = re.escape(census["package"])
    filenames = [Path(p).name for p in census["source_test_lock_sha256"] if p.startswith("state/accounts/") and p.endswith(".go") and not p.endswith("_test.go")]
    row = re.compile(package + r"/(?:" + "|".join(map(re.escape, filenames)) + r"):\d+\.\d+,\d+\.\d+ \d+ \d+")
    require(all(row.fullmatch(line) for line in lines[1:]), "nonportable or out-of-scope profile record")
    return {"profile_sha256": digest(profile), "functions": census["functions"]}


def unknown(status):
    return {"status": status, "aggregate_statements": None}


def safe_count(value, total):
    if value is None:
        return None
    require(type(value["covered"]) is int and type(value["total"]) is int
            and 0 <= value["covered"] <= value["total"] == total, "invalid reporter count")
    return {"covered": value["covered"], "total": total}


def portable_report(report, census, manifest_raw, profile):
    require(report["manifest_sha256"] == digest(manifest_raw) and report["profile_sha256"] == digest(profile)
            and report["profile_mode"] == "atomic" and report["profile_status"] == "present"
            and report["expected_statements"] == census["expected_statements"], "reporter binding mismatch")
    rows = []
    for spec, item in zip(census["functions"], report["functions"], strict=True):
        keys = ("source", "source_sha256", "profile_file", "name", "span")
        require(all(item[k] == spec[k] for k in keys), "reporter function identity mismatch")
        total = sum(b["statements"] for b in spec["blocks"])
        require(item["expected_statements"] == total, "reporter statement census mismatch")
        missing = item["missing_blocks"]
        require(isinstance(missing, list) and all(b in spec["blocks"] for b in missing)
                and len({encode(b) for b in missing}) == len(missing), "invalid missing blocks")
        observed_total = total - sum(b["statements"] for b in missing)
        status = "measured" if not missing else "blocks_absent" if len(missing) == len(spec["blocks"]) else "partial"
        require(item["status"] == status, "reporter status mismatch")
        obs = safe_count(item["observed_statements"], observed_total)
        stmts = safe_count(item["statements"], total)
        require((obs is None) == (status == "blocks_absent")
                and (stmts is None) == (status != "measured")
                and (stmts is None or stmts == obs), "invalid absent/observed counts")
        rows.append({**{k: spec[k] for k in keys}, "status": status,
                     "expected_statements": total, "observed_statements": obs,
                     "statements": stmts, "missing_blocks": missing})
    observed = {k: sum((r["observed_statements"] or {}).get(k, 0) for r in rows) for k in ("covered", "total")}
    require(safe_count(report["observed_statements"], observed["total"]) == observed, "reporter observed aggregate mismatch")
    aggregate = observed if all(r["status"] == "measured" for r in rows) else None
    require(safe_count(report["aggregate_statements"], census["expected_statements"]) == aggregate, "reporter aggregate mismatch")
    return {"scope": SCOPE, "manifest_sha256": digest(manifest_raw), "profile_sha256": digest(profile),
            "profile_mode": "atomic", "profile_status": "present", "expected_statements": census["expected_statements"],
            "observed_statements": observed, "aggregate_statements": aggregate, "functions": rows}


def report_mode(root, out, census, subject, mode, paths, reporter):
    if all(p is None for p in paths):
        return unknown("profile_absent")
    if any(p is None or not p.is_file() for p in paths):
        return unknown("input_incomplete")
    if reporter is None:
        return unknown("reporter_unavailable")
    profile_path, events_path, receipt_path = paths
    try:
        profile, events, receipt_raw = [p.read_bytes() for p in paths]
        manifest = bind_mode(census, subject, mode, profile, events, json.loads(receipt_raw))
        manifest_raw = encode(manifest)
        manifest_path = out / f"{mode}.manifest.json"
        manifest_path.write_bytes(manifest_raw)
        # Reuse the existing source/AST/block validator. No Go build or test here.
        run = subprocess.run([str(reporter.resolve()), "-profile", str(profile_path.resolve()),
                              "-functions", str(manifest_path.resolve()), "-source-root", str(root.resolve())],
                             capture_output=True, check=False, timeout=30)
        require(run.returncode == 0, "reporter failed")
        report = portable_report(json.loads(run.stdout), census, manifest_raw, profile)
        aggregate = report["aggregate_statements"]
        # Reporter output is structured only. Never include raw events, argv, local paths or stderr.
        (out / f"{mode}.report.json").write_bytes(encode(report))
        return {"status": "measured" if aggregate is not None else "partial", "aggregate_statements": aggregate,
                "profile_sha256": digest(profile), "receipt_sha256": digest(receipt_raw),
                "manifest_sha256": digest(manifest_raw), "report_sha256": digest(encode(report))}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return unknown("invalid_input_or_reporter")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reporter", type=Path, help="existing ordinary coverage reporter binary")
    for mode in ("normal", "race"):
        for suffix in ("profile", "events", "receipt"):
            parser.add_argument(f"--{mode}-{suffix}", type=Path)
    a = parser.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    census_raw = Path(__file__).with_name("census.json").read_bytes()
    census = json.loads(census_raw)
    result = {"scope": SCOPE, "census_sha256": digest(census_raw), "source_census_sha256": census["source_census_sha256"], "candidate": None,
              "common_commit": census["common_commit"], "expected_statements": 229,
              "modes": {mode: unknown("source_unavailable") for mode in ("normal", "race")}}
    try:
        check_census(census)
        check_sources(a.source_root, census)
        subject = subprocess.check_output(["git", "-C", str(a.source_root), "rev-parse", "HEAD"], text=True).strip()
        require(re.fullmatch(r"[0-9a-f]{40}", subject), "invalid candidate identity")
        result["candidate"] = subject
        for mode in ("normal", "race"):
            paths = [getattr(a, f"{mode}_{suffix}") for suffix in ("profile", "events", "receipt")]
            result["modes"][mode] = report_mode(a.source_root, a.output, census, subject, mode, paths, a.reporter)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
    (a.output / "summary.json").write_bytes(encode(result))
    return int(any(r["status"] not in ("measured", "partial", "profile_absent") for r in result["modes"].values()))


if __name__ == "__main__":
    raise SystemExit(main())
