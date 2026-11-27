"""Portable, isolated Go file-list diagnostic profile. No test execution."""
import argparse
import hashlib
import json
import posixpath
import re
from pathlib import Path

NODE = "github.com/multiversx/mx-chain-go/"
CORE = "github.com/multiversx/mx-chain-core-go/core/"
GROUPS = {
    "assessment_existing": "cmd/assessment/benchmarks/results.go",
    "assessment_report_boundary": "cmd/assessment/benchmarks/results.go",
    "host_display_wrap": "common/hostParameters/hostInfo.go",
    "memory_display_units": "common/statistics/osLevel/memStats.go",
}
# Exact separately attributed module roster from the reviewed memory file-list
# profile; no prefix-based acceptance of unreviewed module source paths.
CORE_FILES = (
    "address.go", "common.go", "computers.go", "constants.go", "converters.go",
    "epochFlags.go", "errorHandling.go", "file.go", "getNodeFromDBErrWithKey.go",
    "keyLoader.go", "loggingFunctions.go", "machineID.go", "p2pCore.go",
    "peerID.go", "stopWatch.go", "trie.go", "trimmers.go",
)
ROW = re.compile(r"(.+):([0-9]+)\.([0-9]+),([0-9]+)\.([0-9]+) ([0-9]+) ([0-9]+)")
MAX_INT = 2**63 - 1


class InvalidProfile(ValueError):
    """Only fixed, path-free diagnostics may be emitted."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def normalize(raw, checkout, group, mode):
    if group not in GROUPS or mode not in ("normal", "race"):
        raise InvalidProfile("unknown diagnostic group or mode")
    if (not checkout.startswith("/") or checkout.startswith("//") or checkout == "/"
            or posixpath.normpath(checkout) != checkout
            or any(ord(c) < 32 or ord(c) == 127 for c in checkout)):
        raise InvalidProfile("expected canonical absolute checkout root")
    primary = GROUPS[group]
    mapping = {checkout + "/" + primary: (NODE + primary, "node")}
    if group == "memory_display_units":
        mapping.update({CORE + name: (CORE + name, "core") for name in CORE_FILES})
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidProfile("invalid profile encoding") from None
    lines = content.split("\n")
    if len(lines) < 3 or lines[0] != "mode: atomic" or lines[-1] != "":
        raise InvalidProfile("expected a nonempty LF-terminated atomic profile")
    output = ["mode: atomic"]
    files_seen = set()
    blocks_seen = set()
    scopes = {}
    for line in lines[1:-1]:
        match = ROW.fullmatch(line)
        if not match:
            raise InvalidProfile("malformed coverage row")
        name, *fields = match.groups()
        if name not in mapping:
            raise InvalidProfile("unmapped coverage filename")
        if any(len(field) > 19 for field in fields):
            raise InvalidProfile("coverage integer out of range")
        sl, sc, el, ec, statements, count = map(int, fields)
        if (max(sl, sc, el, ec, statements, count) > MAX_INT
                or min(sl, sc, el, ec) == 0 or (sl, sc) > (el, ec)):
            raise InvalidProfile("invalid coverage coordinates or counts")
        portable, scope = mapping[name]
        key = (portable, sl, sc, el, ec)
        if key in blocks_seen:
            raise InvalidProfile("duplicate coverage block")
        blocks_seen.add(key)
        files_seen.add(name)
        totals = scopes.setdefault(scope, {"blocks": 0, "covered": 0, "total": 0})
        totals["blocks"] += 1
        totals["covered"] += statements if count > 0 else 0
        totals["total"] += statements
        # Preserve source coordinates, statements and counters byte-for-byte.
        output.append(portable + line[len(name):])
    if files_seen != set(mapping):
        raise InvalidProfile("incomplete reviewed coverage filename roster")
    portable = ("\n".join(output) + "\n").encode("utf-8")
    receipt = {
        "schema": "ordinary-file-list-portable-v1",
        "group": group,
        "execution_mode": mode,
        "coverage_mode": "atomic",
        "raw_sha256": sha256(raw),
        "portable_sha256": sha256(portable),
        "files": sorted(mapping[name][0] for name in files_seen),
        "scope_counts": scopes,
        "scope": "path conversion only; not source or test qualification",
    }
    return portable, receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--checkout", required=True)
    parser.add_argument("--group", required=True, choices=GROUPS)
    parser.add_argument("--mode", required=True, choices=("normal", "race"))
    parser.add_argument("--output", required=True, type=Path,
                        help="new dedicated directory; publish only on exit zero")
    args = parser.parse_args()
    created = False
    try:
        portable, receipt = normalize(args.profile.read_bytes(), args.checkout,
                                      args.group, args.mode)
        args.output.mkdir()
        created = True
        (args.output / "coverage.cover").write_bytes(portable)
        (args.output / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, InvalidProfile):
        if created:
            try:
                for filename in ("coverage.cover", "receipt.json"):
                    (args.output / filename).unlink(missing_ok=True)
                args.output.rmdir()
            except OSError:
                # Even if cleanup is unavailable the caller sees failure,
                # and must not publish any files from this output directory.
                pass
        # Never echo a checkout path, malformed row, or OS exception to CI.
        parser.exit(1, "portable file-list profile unavailable\n")


if __name__ == "__main__":
    main()
