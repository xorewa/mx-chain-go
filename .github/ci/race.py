"""Keep default race evidence; narrowly classify the owner's Wasmer2 exception."""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

MODULE = "github.com/multiversx/mx-chain-go/"
KNOWN = {
    "./factory/core", "./integrationTests/realcomponents", "./node",
    "./node/chainSimulator", "./node/chainSimulator/components",
}
FATAL = "fatal error: checkptr: pointer arithmetic result points to invalid allocation"
HOOK = "github.com/multiversx/mx-chain-vm-go/wasmer2.getVMHooksFromContextRawPtr("


def classify(raw, stderr, exit_code, packages):
    expected = {MODULE + p[2:] for p in packages}
    events = {p: [] for p in expected}
    errors = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
            package = event["Package"]
            if package not in events or not isinstance(event.get("Action"), str):
                raise ValueError("unexpected package/action")
            events[package].append(event)
        except (ValueError, KeyError, TypeError):
            errors.append("malformed or unexpected go test JSON")
    tolerated = []
    failed = []
    # Compiler, runtime, test2json or invocation diagnostics must never be waived.
    if stderr.strip():
        errors.append("default race stderr is not empty")
    for package, stream in events.items():
        terminal = [e["Action"] for e in stream
                    if not e.get("Test") and e["Action"] in ("pass", "fail", "skip")]
        text = "".join(e.get("Output", "") for e in stream)
        if len(terminal) != 1:
            errors.append(package + ": missing/duplicate package terminal")
            continue
        if terminal[0] != "fail":
            # A passing/skipped package cannot carry a contradictory failure.
            if any(e["Action"] == "fail" for e in stream) or re.search(
                    r"WARNING: DATA RACE|race detected during execution|^--- FAIL:|^fatal error:|^panic:", text, re.M):
                errors.append(package + ": contradictory failure output")
            continue
        failed.append(package)
        relative = "./" + package[len(MODULE):]
        fatal = re.findall(r"^fatal error:.*$", text, re.M)
        # Match the active fatal stack, not a hook name in an unrelated goroutine/log.
        stack = re.search(r"^goroutine \d+(?: gp=\S+ m=\S+(?: mp=\S+)?)? \[running[^\n]*\]:\n(.*?)(?=\n(?:goroutine |created by )|\Z)", text, re.M | re.S)
        top = stack.group(1).splitlines()[:8] if stack else []
        known_stack = (len(top) >= 5 and top[0].startswith("runtime.throw(")
                       and top[2].startswith("runtime.checkptrArithmetic(")
                       and top[4].startswith(HOOK))
        other_failure = (any(e["Action"] == "fail" and e.get("Test") for e in stream)
                         or re.search(r"WARNING: DATA RACE|race detected during execution|^--- FAIL:|^panic:|\[build failed\]", text, re.M))
        if relative in KNOWN and fatal == [FATAL] and known_stack and not other_failure:
            tolerated.append(package)
        else:
            errors.append(package + ": default race failure outside known Wasmer2 signature")
    if exit_code not in (0, 1) or bool(failed) != (exit_code == 1):
        errors.append("default race exit/terminal mismatch")
    return {"default_exit": exit_code, "known_wasmer2_aborts": tolerated, "errors": errors}


def race_commands(packages, flags):
    base = ["go", "test", "-race", "-json", "-count=1", *flags]
    if "./node" not in packages:
        return [base + packages]
    other = [p for p in packages if p != "./node"]
    commands = [base + other] if other else []
    # Owner-authorized known upstream test defect: skip only this test in node
    # race runs. The normal coverage run retains TestWaitForSignal unchanged.
    commands.append(base + ["-skip=^TestWaitForSignal$", "./node"])
    return commands


def execute(commands, output, stem):
    started = time.monotonic()
    runs = []
    with (output / (stem + ".jsonl")).open("wb") as out, (output / (stem + ".stderr")).open("wb") as err:
        for argv in commands:
            begin = time.monotonic()
            result = subprocess.run(argv, stdout=out, stderr=err)
            runs.append({"argv": argv, "exit": result.returncode, "seconds": time.monotonic() - begin})
    exit_code = next((r["exit"] for r in runs if r["exit"] not in (0, 1)),
                     int(any(r["exit"] for r in runs)))
    return {"commands": runs, "exit": exit_code, "seconds": time.monotonic() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--smoke", action="store_true", help="compile only; run no tests")
    parser.add_argument("packages", nargs="+")
    args = parser.parse_args()
    if len(set(args.packages)) != len(args.packages) or any(not p.startswith("./") for p in args.packages):
        parser.error("unique ./ package paths required")
    output = pathlib.Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    flags = ["-run=^$"] if args.smoke else []
    default = execute(race_commands(args.packages, flags), output, "default-race")
    policy = classify((output / "default-race.jsonl").read_text(),
                      (output / "default-race.stderr").read_text(), default["exit"], args.packages)
    adjusted_packages = [p for p in args.packages if p in KNOWN]
    adjusted = None
    if adjusted_packages:
        # Run even if the default run has an unrelated failure, retaining both results.
        adjusted = execute(race_commands(adjusted_packages, ["-gcflags=all=-d=checkptr=0", *flags]),
                           output, "race-checkptr-disabled")
    summary = {"default": default, "classification": policy,
               "checkptr_disabled_race": adjusted,
               "race_only_skips": [{"package": "./node", "test": "^TestWaitForSignal$",
                                    "reason": "owner-authorized known upstream test defect; normal coverage retains test"}]
                                  if "./node" in args.packages else [],
               "scope": "owner's five-package exception; no default race credit for aborted tests"}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return int(bool(policy["errors"]) or (adjusted is not None and adjusted["exit"] != 0))


if __name__ == "__main__":
    sys.exit(main())
