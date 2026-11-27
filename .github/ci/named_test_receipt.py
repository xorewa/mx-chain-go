#!/usr/bin/env python3
"""Offline check of one named ordinary Go test receipt; executes no tests.

The producer supplies the exit code, the complete `go test -json -count=1`
stream, package import path and exact expected test names (including nested
leaves). A parent PASS or successful package exit does not prove a leaf ran.
The evidence producer is still responsible for binding the stream to its
command, candidate and environment.
"""

import argparse
import json
import re
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def expected_names(names):
    require(isinstance(names, (list, tuple)) and names
            and all(isinstance(name, str) for name in names)
            and len(set(names)) == len(names), "invalid expected test list")
    required = set()
    for name in names:
        parts = name.split("/")
        require(re.fullmatch(r"Test[A-Za-z0-9_]+", parts[0]) is not None
                and all(part and part.isprintable() for part in parts),
                "invalid exact test name")
        # The Go event stream also reports each enclosing test in a nested run.
        required.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    return required


def verify(raw, package, names, exit_code):
    require(type(exit_code) is int and exit_code == 0, "test command did not pass")
    require(isinstance(package, str) and bool(package)
            and package.isprintable() and not any(c.isspace() for c in package),
            "invalid package name")
    require(isinstance(raw, bytes), "invalid test event stream")
    required = expected_names(names)
    runs, passes = set(), set()
    started = finished = False

    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            raise ValueError("invalid JSON test event") from None
        require(isinstance(event, dict) and event.get("Package") == package,
                "unexpected event package")
        require(not finished, "event after terminal package pass")
        action, test = event.get("Action"), event.get("Test")
        require(action not in ("fail", "skip"), "nonpassing test or package event")

        if test is None:
            if action == "start":
                require(not started, "duplicate package start")
                started = True
            elif action == "pass":
                require(started and runs == passes == required,
                        "missing named test run or pass")
                finished = True
            else:
                require(started and action == "output", "unexpected package event")
            continue

        require(started and isinstance(test, str) and test in required,
                "unexpected test name")
        if action == "run":
            require(test not in runs, "duplicate test run")
            parents = [n for n in required if test.startswith(n + "/")]
            require(all(n in runs and n not in passes for n in parents),
                    "test run outside its enclosing test")
            runs.add(test)
        elif action == "pass":
            require(test in runs and test not in passes, "test pass without unique run")
            require(all(n in passes for n in required if n.startswith(test + "/")),
                    "enclosing test passed without its expected leaf")
            passes.add(test)
        else:
            require(action in ("output", "pause", "cont") and test in runs
                    and test not in passes, "unexpected test event")

    require(finished and runs == passes == required, "missing terminal package or test pass")
    return {"status": "pass", "explicit_expected_count": len(names),
            "verified_test_count_including_parents": len(required)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--expect", action="append", required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.events.read_bytes(), args.package, args.expect, args.exit_code)
    except OSError:
        print("named test receipt: event stream unavailable", file=sys.stderr)
        return 1
    except ValueError as error:
        # All error messages are fixed categories, not raw logs or paths.
        print("named test receipt: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
