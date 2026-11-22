"""Nonblocking trial: one gobco invocation and raw report per DRWA package."""
import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--smoke", action="store_true", help="instrument/compile only")
    parser.add_argument("packages", nargs="+")
    args = parser.parse_args()
    output = pathlib.Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for number, package in enumerate(args.packages):
        if not package.startswith("./"):
            parser.error("./ package path required")
        target = output / str(number)
        target.mkdir()
        # gobco copies/instruments the module, one package per invocation.
        # Bound even tool-abort scratch files to a disposable per-package directory.
        with tempfile.TemporaryDirectory(prefix="gobco-trial-") as scratch:
            env = dict(os.environ, TMPDIR=scratch)
            argv = [str(pathlib.Path(args.binary).resolve()), "-branch", "-list-all",
                    "-stats", str(target / "counts.json"), "-test=-json"]
            if args.smoke:
                argv.append("-test=-run=^$")
            argv.append(package)
            started = time.monotonic()
            with (target / "stdout").open("wb") as out, (target / "stderr").open("wb") as err:
                run = subprocess.run(argv, env=env, stdout=out, stderr=err)
        text = (target / "stdout").read_text()
        match = re.search(r"^Branch coverage: (\d+)/(\d+)$", text, re.M)
        results.append({"package": package, "argv": argv, "exit": run.returncode,
                        "seconds": time.monotonic() - started,
                        "branches": {"covered": int(match[1]), "total": int(match[2])} if match else None,
                        "status": "measured" if match and run.returncode == 0 else "UNKNOWN: tool/test failure or missing branch report"})
        print(json.dumps(results[-1]), flush=True)
    (output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    # Missing measurements remain visible as trial failure, never counted as zero/100%.
    return int(any(r["exit"] != 0 or r["branches"] is None for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
