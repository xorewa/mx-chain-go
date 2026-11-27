"""Validate a package-mode atomic diagnostic profile before publication.

This checks structure and the exact package namespace, not source completeness,
coverage thresholds or test authenticity. No profile data is printed.
"""
import argparse
import re
from pathlib import Path


ROW = re.compile(r"(.+):([0-9]+)\.([0-9]+),([0-9]+)\.([0-9]+) ([0-9]+) ([0-9]+)")
MAX_INT64 = 2**63 - 1


def validate(raw, package):
    lines = raw.decode("utf-8").split("\n")
    if len(lines) < 3 or lines[0] != "mode: atomic" or lines[-1] != "":
        raise ValueError("profile is not a nonempty LF-terminated atomic profile")
    blocks = {}
    for line in lines[1:-1]:
        match = ROW.fullmatch(line)
        if not match:
            raise ValueError("malformed profile row")
        name, *fields = match.groups()
        prefix = package + "/"
        if not name.startswith(prefix):
            raise ValueError("profile row is outside selected package")
        filename = name[len(prefix):]
        if (not filename.endswith(".go") or filename == ".go" or "/" in filename
                or "\\" in filename or any(ord(c) < 32 or ord(c) == 127 for c in filename)):
            raise ValueError("invalid source filename")
        if any(len(field) > 19 for field in fields):
            raise ValueError("profile integer out of range")
        sl, sc, el, ec, statements, count = map(int, fields)
        if (min(sl, sc, el, ec) == 0 or (sl, sc) > (el, ec)
                or max(sl, sc, el, ec, statements, count) > MAX_INT64):
            raise ValueError("invalid profile coordinates or counts")
        key = (name, sl, sc, el, ec)
        # Go coverage can merge repeated coordinates, provided the statement
        # counts agree. Keep the original rows; do not alter their counters.
        if key in blocks and blocks[key] != statements:
            raise ValueError("conflicting statement counts for repeated block")
        blocks[key] = statements


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--package", required=True)
    args = parser.parse_args()
    try:
        validate(args.profile.read_bytes(), args.package)
    except (OSError, ValueError):
        # Do not echo raw rows, checkout paths, or exceptions to CI logs.
        parser.exit(1, "ordinary package profile unavailable or malformed\n")


if __name__ == "__main__":
    main()
