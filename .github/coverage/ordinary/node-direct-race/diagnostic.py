"""Optional producer for only the independently reviewed R28 reporting roots."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


HERE = Path(__file__).resolve().parent
MODULE = "github.com/multiversx/mx-chain-go"
REVIEW = "8bd94f4dd795da74a2522c6d5b006bca1310fa352c9d1b1c818b678f449b7554"
SELECTORS = "c91ecacc58d955517f538f9f27a58ffc39fd91353c1b06fcc07a6d8eb30d0384"
ROOT_NAME = re.compile(r"Test[A-Za-z0-9_]+\Z")
PACKAGE_NAME = re.compile(r"[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*\Z")
LOCATION = re.compile(r"([^:]+):(\d+)\.(\d+),(\d+)\.(\d+)\Z")
GO_FILE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.go\Z")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def offline_env():
    env = os.environ.copy()
    env.update(GOPROXY="off", GONOPROXY="none", GOSUMDB="off", GOVCS="*:off",
               GOTOOLCHAIN="local", GOENV="off", GOWORK="off",
               GOFLAGS="-mod=readonly -buildvcs=false", GOTELEMETRY="off")
    return env


def validate_files(root, files):
    require(isinstance(files, dict) and files, "missing reviewed source bindings")
    for name, expected in files.items():
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts and
                (path.suffix == ".go" or name in ("go.mod", "go.sum")) and path.as_posix() == name,
                "invalid reviewed source path")
        source = root / path
        require(source.is_file() and source.resolve().is_relative_to(root.resolve()) and
                digest(source.read_bytes()) == expected, "reviewed source changed or unavailable")


def selector_args(package, roots, profile):
    require(PACKAGE_NAME.fullmatch(package) and roots and
            len(set(roots)) == len(roots) and all(ROOT_NAME.fullmatch(root) for root in roots),
            "invalid exact root selection")
    pattern = "^(" + "|".join(sorted(roots)) + ")$"
    return ["go", "test", "-json", "-count=1", "-race", "-covermode=atomic",
            f"-coverprofile={profile}", "-run", pattern, "./" + package]


def verify_events(raw, package, roots):
    expected = set(roots)
    runs, passes = set(), set()
    all_runs, all_passes = set(), set()
    package_passes = 0
    for line in raw.splitlines():
        event = json.loads(line)
        require(isinstance(event, dict), "invalid test event")
        action, test = event.get("Action"), event.get("Test")
        if test is not None:
            require(isinstance(test, str), "invalid test event name")
            root = test.split("/", 1)[0]
            require(event.get("Package") == MODULE + "/" + package and root in expected,
                    "unexpected test event")
            require(action not in {"fail", "skip"}, "selected test did not pass")
            if action == "run":
                require(test not in all_runs, "duplicate test run")
                all_runs.add(test)
            if action == "pass":
                require(test not in all_passes, "duplicate test pass")
                all_passes.add(test)
            if test == root and action == "run":
                require(root not in runs, "duplicate root run")
                runs.add(root)
            if test == root and action == "pass":
                require(root not in passes, "duplicate root pass")
                passes.add(root)
        elif event.get("Package") == MODULE + "/" + package:
            require(action != "fail", "selected package did not pass")
            if action == "pass":
                package_passes += 1
    require(runs == expected == passes and all_runs == all_passes and package_passes == 1,
            "incomplete exact root events")


def profile_blocks(raw, package):
    lines = raw.decode("utf-8").splitlines()
    require(lines and lines[0] == "mode: atomic" and len(lines) > 1, "missing atomic profile")
    prefix = MODULE + "/" + package + "/"
    blocks = {}
    for line in lines[1:]:
        location, weight, hits = line.rsplit(" ", 2)
        match = LOCATION.fullmatch(location)
        require(match is not None, "invalid profile coordinate")
        filename, *coords = match.groups()
        points = tuple(map(int, coords))
        require(filename.startswith(prefix) and GO_FILE.fullmatch(filename[len(prefix):]) and
                min(points) > 0 and points[:2] <= points[2:], "unexpected profile file or coordinate")
        require(weight.isdecimal() and hits.isdecimal(), "invalid profile statement or hit count")
        n, count = int(weight), int(hits)
        if location in blocks:
            old_n, old_count = blocks[location]
            require(n == old_n, "inconsistent duplicate profile coordinate")
            count += old_count
        blocks[location] = n, count
    return blocks


def run_package(root, raw_dir, package, roots):
    # Raw output remains in the unuploaded input directory. Never print test output.
    prefix = raw_dir / package.replace("/", "_")
    profile = prefix.with_suffix(".cover")
    completed = subprocess.run(selector_args(package, roots, profile), cwd=root,
                               env=offline_env(), capture_output=True, check=False)
    prefix.with_suffix(".stdout").write_bytes(completed.stdout)
    prefix.with_suffix(".stderr").write_bytes(completed.stderr)
    require(completed.returncode == 0, "selected nominal package tests failed")
    verify_events(completed.stdout, package, roots)
    return profile_blocks(profile.read_bytes(), package)


def produce(root, output, reviewed, subject, runner=run_package):
    validate_files(root, reviewed["files"])
    census = root / ".github/coverage/ordinary/node-direct-r25.json"
    require(digest(census.read_bytes()) == reviewed["census_sha256"], "reviewed census changed")
    packages = reviewed["packages"]
    require(len({p["package"] for p in packages}) == len(packages), "duplicate selected package")
    # Validate all exact selectors before executing any selected test.
    for p in packages:
        selector_args(p["package"], p["roots"], Path("unused.cover"))
    output.mkdir(parents=True, exist_ok=False)
    raw_dir = output / "raw"
    raw_dir.mkdir()
    combined = {}
    for p in packages:
        blocks = runner(root, raw_dir, p["package"], p["roots"])
        require(not combined.keys() & blocks.keys(), "overlapping package profile coordinates")
        combined.update(blocks)
    require(combined, "no selected profile blocks")
    data = ("mode: atomic\n" + "".join(f"{key} {n} {hits}\n" for key, (n, hits) in sorted(combined.items()))).encode()
    profile = output / "coverage.out"
    profile.write_bytes(data)
    # Write the receipt last; incomplete generation cannot be accepted by the reader.
    receipt = {"run_mode": "race", "subject": subject,
               "selector_review_sha256": reviewed["review_sha256"],
               "selector_manifest_sha256": SELECTORS,
               "census_sha256": reviewed["census_sha256"],
               "profile_sha256": digest(data), "test_exit": 0}
    (output / "provenance.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="new current-attempt input directory")
    args = parser.parse_args(argv)
    try:
        root = Path.cwd()
        require(args.output.is_absolute(), "expected absolute current-attempt output")
        raw = (HERE / "selectors-r28.json").read_bytes()
        require(digest(raw) == SELECTORS, "reviewed selector manifest changed")
        reviewed = json.loads(raw)
        require(reviewed["review_sha256"] == REVIEW and len(reviewed["packages"]) == 5 and
                sum(len(p["roots"]) for p in reviewed["packages"]) == 12, "unexpected reviewed scope")
        subject = os.environ["GITHUB_SHA"]
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True,
                                         stderr=subprocess.DEVNULL).strip()
        require(re.fullmatch(r"[0-9a-f]{40}", subject) and subject == actual, "checkout identity mismatch")
        produce(root, args.output, reviewed, subject)
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        # No paths, subprocess output, or unverified measurements are published on failure.
        print("Optional Node direct race input unavailable.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
