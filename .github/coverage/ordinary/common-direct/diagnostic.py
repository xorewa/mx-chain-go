"""Opt-in, two-root Common65 diagnostic; run inside the existing offline test enclosure."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ORIGINAL = "github.com/multiversx/mx-chain-vm-common-go"
REPLACEMENT = "github.com/xorewa/mx-chain-vm-common-go"
VERSION = "v0.0.0-20261121171453-65fdfdd8ff11"
PACKAGE = ORIGINAL + "/parsers/dataField"
ARCHIVE_SUM = "h1:wXchOd4x7UXBYbZtNK7wqOU9RXAjCrNr0rgmOfr014A="
MOD_SUM = "h1:Lk2ZNxVCThYFbFhjXxy1S8PwqjcEnF7uvTQ0QvA4BbQ="
ROOTS = ("TestComputeTokenIdentifier", "TestExtractTokenAndNonce")
SELECTOR = "^(" + "|".join(ROOTS) + ")$"
SOURCE_HASH = "30e6c6bc390b0ae6cbd07da596845885aee959c1f425bc55db75eb7d3805c5ad"
TEST_HASH = "fe81e4b58fc3fc2fb363d8e4beeb8110a0d4a7135572d0b150c230553158af38"
CENSUS_HASH = "99c87ebbc6421c68c366fded3325a32b4a9d93a8b2d151eda1420985e3e5e77f"
HERE = Path(__file__).resolve().parent
PROFILE_FILES = ("dtos.go", "parseMultiESDTNFTTransfer.go", "parseSingleESDTTransfer.go",
                 "parseSingleNFTTransfer.go", "parser.go", "utils.go")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hash1(files):
    data = "".join(f"{sha(raw)}  {name}\n" for name, raw in sorted(files.items()))
    return "h1:" + base64.b64encode(hashlib.sha256(data.encode()).digest()).decode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def offline_env():
    env = os.environ.copy()
    env.update(GOPROXY="off", GONOPROXY="none", GOSUMDB="off", GOVCS="*:off",
               GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GOFLAGS="-mod=readonly -buildvcs=false",
               GOTELEMETRY="off")
    return env


def run_phase(root, out, label, argv):
    try:
        completed = subprocess.run(argv, cwd=root, env=offline_env(), capture_output=True,
                                   timeout=180, check=False)
        stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, code = exc.stdout or b"", exc.stderr or b"", 124
    (out / f"{label}.stdout").write_bytes(stdout)
    (out / f"{label}.stderr").write_bytes(stderr)
    write_json(out / f"{label}.execution.json", {
        "argv": argv, "exit": code, "stdout_sha256": sha(stdout),
        "stderr_sha256": sha(stderr),
    })
    require(code == 0, f"{label} exited {code}")
    return stdout


def verify_events(raw):
    runs, passes, package_pass = [], [], 0
    for line in raw.splitlines():
        event = json.loads(line)
        require(event.get("Package") == PACKAGE, "unexpected test package")
        action, name = event.get("Action"), event.get("Test")
        require(action not in ("fail", "skip"), "failed or skipped test event")
        if action == "run":
            runs.append(name)
        elif action == "pass":
            if name is None:
                package_pass += 1
            else:
                passes.append(name)
    require(sorted(runs) == sorted(ROOTS) and sorted(passes) == sorted(ROOTS)
            and package_pass == 1, "exact two-root/package pass events missing")


def verify_module(root, out):
    require((root / "go.mod").is_file(), "run from Node module root")
    version = run_phase(root, out, "toolchain", ["go", "version"]).decode().split()
    require(len(version) >= 3 and version[2] == "go1.26.2", "unexpected Go version")
    mod = (root / "go.mod").read_text()
    sums = set((root / "go.sum").read_text().splitlines())
    require(f"replace {ORIGINAL} => {REPLACEMENT} {VERSION}" in mod.splitlines(),
            "unexpected Common replacement")
    require(f"{REPLACEMENT} {VERSION} {ARCHIVE_SUM}" in sums
            and f"{REPLACEMENT} {VERSION}/go.mod {MOD_SUM}" in sums, "Common checksum lock mismatch")
    download = json.loads(run_phase(root, out, "module-download", [
        "go", "mod", "download", "-json", f"{REPLACEMENT}@{VERSION}"]))
    require(download.get("Path") == REPLACEMENT and download.get("Version") == VERSION
            and download.get("Sum") == ARCHIVE_SUM and download.get("GoModSum") == MOD_SUM,
            "cached module identity mismatch")
    listed = json.loads(run_phase(root, out, "module-effective", ["go", "list", "-m", "-json", ORIGINAL]))
    replacement = listed.get("Replace", {})
    directory = Path(download["Dir"]).resolve()
    require(listed.get("Path") == ORIGINAL and listed.get("Version") == "v1.7.3"
            and replacement.get("Path") == REPLACEMENT and replacement.get("Version") == VERSION
            and Path(replacement["Dir"]).resolve() == directory, "effective module mismatch")
    require(hash1({"go.mod": Path(download["GoMod"]).read_bytes()}) == MOD_SUM,
            "cached module metadata checksum mismatch")
    prefix = f"{REPLACEMENT}@{VERSION}/"
    with zipfile.ZipFile(download["Zip"]) as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")]
        require(len(names) == len(set(names)) and all(n.startswith(prefix) for n in names),
                "unexpected archive members")
        members = {n: archive.read(n) for n in names}
    require(hash1(members) == ARCHIVE_SUM, "cached archive checksum mismatch")
    # Verify the actual complete extracted module against the exact archive,
    # including its test files, before invoking any test.
    expected = {n.removeprefix(prefix): raw for n, raw in members.items()}
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    require(actual == set(expected), "extracted Common file roster mismatch")
    require(all((directory / p).read_bytes() == raw for p, raw in expected.items()),
            "extracted Common bytes mismatch")
    require(sha(expected["parsers/dataField/utils.go"]) == SOURCE_HASH
            and sha(expected["parsers/dataField/utils_test.go"]) == TEST_HASH,
            "selected source or test mismatch")
    return directory


def census_manifest(census, profile):
    require(census.get("common_commit") == "65fdfdd8ff11f6b98489b60efd35e9c682979dd0"
            and census.get("source_sha256") == SOURCE_HASH, "static census identity mismatch")
    functions = census["functions"]
    require([x["name"] for x in functions] == ["computeTokenIdentifier", "extractTokenAndNonce"]
            and all(x["source"] == "parsers/dataField/utils.go"
                    and x["profile_file"] == PACKAGE + "/utils.go"
                    and x["source_sha256"] == SOURCE_HASH for x in functions)
            and sum(b["statements"] for x in functions for b in x["blocks"]) == 14
            and sum(len(x["blocks"]) for x in functions) == 8, "static census scope mismatch")
    require(profile.read_bytes().startswith(b"mode: atomic\n"), "missing atomic profile")
    return {"profile_sha256": sha(profile.read_bytes()), "functions": functions}


def test_args(mode, profile):
    require(mode in ("normal", "race"), "unexpected mode")
    return ["go", "test", "-json", "-count=1", "-timeout=70s"] + (
        ["-race"] if mode == "race" else []) + [
        "-covermode=atomic", f"-coverprofile={profile}", "-run", SELECTOR, PACKAGE]



def safe_counts(value, expected):
    if value is None:
        return None
    covered, total = value["covered"], value["total"]
    require(type(covered) is int and type(total) is int and 0 <= covered <= total <= expected,
            "invalid report counts")
    return {"covered": covered, "total": total}


def portable_profile(raw):
    # The actual profile has Go import paths, not local filesystem paths.
    # Refuse anything else rather than redacting or rewriting measured rows.
    lines = raw.decode("ascii").splitlines()
    require(lines and lines[0] == "mode: atomic" and len(lines) > 1,
            "invalid portable profile")
    filenames = "|".join(re.escape(name) for name in PROFILE_FILES)
    row = re.compile(re.escape(PACKAGE) + r"/(?:" + filenames + r"):"
                     r"[0-9]+\.[0-9]+,[0-9]+\.[0-9]+ [0-9]+ [0-9]+")
    require(all(row.fullmatch(line) for line in lines[1:]), "non-portable profile filename")
    return raw


def portable_mode(out, mode, status, census):
    raw = portable_profile((out / f"{mode}.cover").read_bytes())
    profile_sha = sha(raw)
    require(status["profile_sha256"] == profile_sha, "portable profile digest mismatch")
    report = json.loads((out / f"{mode}.report.json").read_text())
    require(report["profile_sha256"] == profile_sha and report["profile_mode"] == "atomic"
            and report["profile_status"] == "present"
            and report["expected_statements"] == 14, "portable report binding mismatch")
    manifest = {"profile_sha256": profile_sha, "functions": census["functions"]}
    manifest_raw = (out / f"{mode}.manifest.json").read_bytes()
    require(manifest_raw == (json.dumps(manifest, indent=2) + "\n").encode()
            and report["manifest_sha256"] == sha(manifest_raw),
            "portable manifest mismatch")
    functions = []
    for spec, item in zip(census["functions"], report["functions"], strict=True):
        expected = sum(b["statements"] for b in spec["blocks"])
        require(all(item[k] == spec[k] for k in ("name", "source", "source_sha256",
                                                "profile_file", "span"))
                and item["expected_statements"] == expected
                and item["status"] in ("measured", "partial", "blocks_absent"),
                "portable function mismatch")
        missing = item["missing_blocks"]
        require(all(b in spec["blocks"] for b in missing), "unexpected missing block")
        functions.append({
            **{k: spec[k] for k in ("name", "source", "source_sha256", "profile_file", "span")},
            "status": item["status"], "expected_statements": expected,
            "observed_statements": safe_counts(item["observed_statements"], expected),
            "statements": safe_counts(item["statements"], expected),
            "missing_blocks": missing,
        })
    aggregate = safe_counts(report["aggregate_statements"], 14)
    require(aggregate == status["statements"], "portable aggregate mismatch")
    expected_status = "measured" if aggregate is not None else "partial"
    require(status["status"] == expected_status, "portable status mismatch")
    return raw, manifest, {
        "scope": "explicit source-bound function blocks only; caller establishes provenance and census scope; not a qualification gate",
        "manifest_sha256": sha(manifest_raw), "profile_status": "present",
        "profile_sha256": profile_sha, "profile_mode": "atomic", "expected_statements": 14,
        "observed_statements": safe_counts(report["observed_statements"], 14),
        "aggregate_statements": aggregate, "functions": functions,
    }



def phase_exit(out, label):
    try:
        value = json.loads((out / f"{label}.execution.json").read_text())["exit"]
        return value if type(value) is int else None
    except (OSError, ValueError, KeyError, TypeError):
        return None

def publish_portable(out, result):
    """Export only a fixed portable roster. Never copy raw receipts or binaries."""
    portable = out / "portable"
    portable.mkdir(exist_ok=False)
    summary = {
        "scope": "Common65 two-function display diagnostic; Node-effective graph only",
        "common_commit": "65fdfdd8ff11f6b98489b60efd35e9c682979dd0",
        "module": REPLACEMENT, "version": VERSION, "archive_sum": ARCHIVE_SUM,
        "go_mod_sum": MOD_SUM, "census_sha256": CENSUS_HASH,
        "package": PACKAGE, "selected_roots": list(ROOTS), "expected_statements": 14,
    }
    try:
        census_raw = (HERE / "census.json").read_bytes()
        require(sha(census_raw) == CENSUS_HASH, "static census digest mismatch")
        census = json.loads(census_raw)
    except (OSError, ValueError):
        census = None
    for mode in ("normal", "race"):
        status = result[mode]
        test_exit = phase_exit(out, f"{mode}-test")
        summary[mode] = {"status": "unavailable", "statements": None, "test_exit": test_exit}
        if census is None or status["status"] not in ("measured", "partial") or test_exit != 0:
            continue
        try:
            raw, manifest, report = portable_mode(out, mode, status, census)
            (portable / f"{mode}.cover").write_bytes(raw)
            write_json(portable / f"{mode}.manifest.json", manifest)
            write_json(portable / f"{mode}.report.json", report)
            summary[mode] = {"status": status["status"], "statements": report["aggregate_statements"],
                             "profile_sha256": report["profile_sha256"], "test_exit": test_exit}
        except (OSError, ValueError, KeyError, TypeError):
            # Do not export local exception text. Keep it and all raw evidence
            # outside portable/. No portable measurement is claimed.
            for suffix in ("cover", "manifest.json", "report.json"):
                (portable / f"{mode}.{suffix}").unlink(missing_ok=True)
    write_json(portable / "summary.json", summary)
    return all(summary[m]["status"] == "measured" for m in ("normal", "race"))

def diagnostic(root, out):
    result = {"scope": "two existing Common65 ordinary display roots; Node-effective graph; diagnostic only",
              "normal": {"status": "unavailable", "statements": None},
              "race": {"status": "unavailable", "statements": None}}
    try:
        directory = verify_module(root, out)
        census_raw = (HERE / "census.json").read_bytes()
        require(sha(census_raw) == CENSUS_HASH, "static census digest mismatch")
        census = json.loads(census_raw)
        result["census_sha256"] = CENSUS_HASH
        # Build the existing reporter before test execution. A missing tooling
        # dependency must not consume test work that cannot be reported.
        reporter = out / "ordinary-reporter"
        run_phase(root, out, "reporter-build", [
            "go", "build", "-o", str(reporter), "./.github/coverage/ordinary"])
        for mode in ("normal", "race"):
            # Distinct fresh output files; do not reuse normal as a race profile.
            try:
                profile = out / f"{mode}.cover"
                verify_events(run_phase(root, out, f"{mode}-test", test_args(mode, profile)))
                manifest = out / f"{mode}.manifest.json"
                write_json(manifest, census_manifest(census, profile))
                raw = run_phase(root, out, f"{mode}-reporter", [
                    str(reporter), "-profile", str(profile),
                    "-functions", str(manifest), "-source-root", str(directory)])
                report = json.loads(raw)
                require(report["profile_sha256"] == sha(profile.read_bytes())
                        and report["profile_mode"] == "atomic"
                        and report["expected_statements"] == 14, "report binding mismatch")
                write_json(out / f"{mode}.report.json", report)
                result[mode] = {"status": "measured" if report["aggregate_statements"] is not None else "partial",
                                "statements": report["aggregate_statements"],
                                "profile_sha256": report["profile_sha256"]}
            except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
                result[mode]["reason"] = str(exc)
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, zipfile.BadZipFile) as exc:
        for mode in ("normal", "race"):
            result[mode]["reason"] = str(exc)
    write_json(out / "result.json", result)
    return 0 if publish_portable(out, result) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    return diagnostic(Path.cwd(), output)


if __name__ == "__main__":
    sys.exit(main())
