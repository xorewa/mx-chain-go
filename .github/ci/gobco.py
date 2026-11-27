"""Nonblocking trial: one gobco invocation and raw report per DRWA package."""
import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time


def publish_report(path, value):
    # Keep the last complete report available if the trial is interrupted.
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def classify_diagnostic(returncode, has_report, stdout, stderr):
    """Summarize evidence, not the cause of a product failure.

    Class labels can overlap (for example, a tool panic with a compiler
    diagnostic and no branch report). Only a structured Go test fail event
    with a test name contributes to the named-failure count. Raw log text
    is deliberately absent from the summary.
    """
    named_failures = package_failures = 0
    compile_setup = False
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (not isinstance(event, dict)
                or not isinstance(event.get("Package"), str)
                or not event["Package"]):
            continue
        name = event.get("Test")
        if event.get("Action") == "fail":
            if isinstance(name, str) and name:
                named_failures += 1
            elif name is None:
                package_failures += 1
        if event.get("Action") == "output" and name is None:
            output = event.get("Output")
            if isinstance(output, str) and re.search(r"\[(?:build|setup) failed\]\s*$", output):
                compile_setup = True

    # A panic in an attributed instrumenter stack is tool evidence, not
    # a named test failure. Do not classify arbitrary nonzero exits as tool
    # errors or an unattributed panic as a product failure.
    tool_error = returncode != 0 and bool(
        re.search(r"^panic:", stderr, re.M)
        and re.search(r"^[ \t]+[^\n]*[/\\]gobco-source[/\\][^\n]*\.go:\d+", stderr, re.M)
    )
    if tool_error and re.search(
        r"^panic: [^\n]*\.go:\d+:\d+: [^\n]*(?:undefined|redeclared in this block)",
        stderr, re.M
    ):
        compile_setup = True

    classes = []
    if tool_error:
        classes.append("tool_error")
    if compile_setup:
        classes.append("compile_or_setup")
    if named_failures:
        classes.append("named_test_failure")
    if returncode != 0 and not classes:
        classes.append("unknown_failure")
    if not has_report:
        classes.append("missing_report")
    return {
        "measurement": "measured" if has_report and returncode == 0 else "unknown",
        "evidence_classes": classes,
        "named_test_failure_events": named_failures,
        "package_failure_events": package_failures,
    }


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
    publish_report(output / "plan.json", {"packages": args.packages})
    publish_report(output / "summary.json", results)
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
        diagnostic = classify_diagnostic(run.returncode, match is not None, text,
                                         (target / "stderr").read_text(errors="replace"))
        results.append({"package": package, "argv": argv, "exit": run.returncode,
                        "seconds": time.monotonic() - started,
                        "branches": {"covered": int(match[1]), "total": int(match[2])} if match else None,
                        "status": "measured" if match and run.returncode == 0 else "UNKNOWN: tool/test failure or missing branch report",
                        "diagnostic": diagnostic})
        publish_report(output / "summary.json", results)
        print(json.dumps(results[-1]), flush=True)
    # Missing measurements remain visible as trial failure, never counted as zero/100%.
    return int(any(r["exit"] != 0 or r["branches"] is None for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
