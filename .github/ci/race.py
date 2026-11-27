"""Keep scoped race evidence; narrowly classify documented inherited test failures."""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

MODULE = "github.com/multiversx/mx-chain-go/"
# Only the four owner-approved VM module trees receive the compatibility flags.
VM_MODULES = ("mx-chain-vm-go", "mx-chain-vm-v1_2-go",
              "mx-chain-vm-v1_3-go", "mx-chain-vm-v1_4-go")
VM_FLAGS = tuple("-gcflags=github.com/multiversx/" + name + "/...=-d=checkptr=0"
                 for name in VM_MODULES)
TXS_FEE = "./integrationTests/vm/txsFee"
TXS_MIGRATION = "TestMigrateDataTrieBuiltInFunc"
TXS_MIGRATION_LEAVES = {
    TXS_MIGRATION + "/deterministic_trie",
    TXS_MIGRATION + "/random_trie_-_all_leaves_are_migrated_in_multiple_transactions",
}


# Owner disposition 2026-11-26: exactly these inherited stateTrie harness
# failures, not a successful race result. All raw JSON and stderr stay intact.
STATE_TRIE = "./integrationTests/state/stateTrie"
MIGRATION = "TestMigrateDataTrieBuiltinFunc"
STATE_TRIE_LEAVES = {
    "TestRollbackBlockAndCheckThatPruningIsCancelledOnAccountsTrie",
    "TestRollbackBlockWithSameRootHashAsPreviousAndCheckThatPruningIsNotDone",
    "TestTriePruningWhenBlockIsFinal", "TestStatePruningIsNotBuffered",
    "TestStatePruningIsNotBufferedOnConsecutiveBlocks", "TestSnapshotOnEpochChange",
    "TestContinuouslyAccountCodeChanges", "TestAccountRemoval",
    *(MIGRATION + "/migrate_shard_" + shard + "_" + account + "_account"
      for shard in ("0", "1") for account in ("system", "user")),
}
RACE_REPORT = re.compile(r"^==================\nWARNING: DATA RACE\n(.*?)^==================\n", re.M | re.S)
ACCESS = re.compile(r"^(Previous )?(Read|Write|read|write) at 0x[0-9a-f]+ by goroutine \d+:\n"
                    r"  ([^\n]+)\n      ([^\n]+):([0-9]+) \+0x[0-9a-f]+$", re.M)
ACCESS_HEADER = re.compile(r"^(?:Previous )?(?:Read|Write|read|write) at .* by goroutine \d+:$", re.M)
RACE_NOTICE = re.compile(r"^\s*testing\.go:\d+: race detected during execution of test\s*$", re.M)
OTHER_FAILURE = re.compile(r"^\s*(?:panic:|fatal error:|Error Trace:|Error:|Error Message:)|"
                           r"\[build failed\]|test timed out|signal: killed", re.M)
TEST_DIAGNOSTIC = re.compile(r"^\s+\S+\.go:\d+:.*$", re.M)
FAIL_LABEL = re.compile(r"^\s*--- FAIL: (\S+) \([^\n]*\)\s*$", re.M)


def inherited_state_trie(stream):
    """Return failed leaves only for complete, attributed harness diagnostics.

    Go test JSON cannot distinguish silent extra Fail calls in the same test;
    this is a classification of the emitted evidence, not passing race credit.
    """
    failures = [e["Test"] for e in stream if e["Action"] == "fail" and e.get("Test")]
    if not failures or len(failures) != len(set(failures)):
        return None
    failed = set(failures)
    leaves = failed - {MIGRATION}
    if not leaves or not leaves <= STATE_TRIE_LEAVES:
        return None
    if (MIGRATION in failed) != any(t.startswith(MIGRATION + "/") for t in leaves):
        return None
    texts = {}
    for e in stream:
        if e.get("Action") == "output":
            texts.setdefault(e.get("Test"), []).append(e.get("Output", ""))
        if e.get("Test") in failed and e.get("Action") in ("pass", "skip"):
            return None
    observed = set()
    for test, parts in texts.items():
        text = "".join(parts)
        reports = list(RACE_REPORT.finditer(text))
        if reports:
            if test not in leaves:
                return None
            for report in reports:
                accesses = ACCESS.findall(report[1])
                if len(accesses) != 2 or len(ACCESS_HEADER.findall(report[1])) != 2:
                    return None
                if [a[0] for a in accesses] != ["", "Previous "]:
                    return None
                expected = {
                    ("write", MODULE + "integrationTests.UpdateRound()", "2738"): "integrationTests/testInitializer.go",
                    ("read", MODULE + "integrationTests/mock.(*RoundHandlerMock).Index()", "30"): "integrationTests/mock/roundHandlerMock.go",
                }
                signature = {(kind.lower(), frame, line): path for _, kind, frame, path, line in accesses}
                if signature.keys() != expected.keys() or any(
                        signature[k] != suffix and not signature[k].endswith("/" + suffix)
                        for k, suffix in expected.items()):
                    return None
            observed.add(test)
        residual = RACE_REPORT.sub("", text)
        if "WARNING: DATA RACE" in residual or OTHER_FAILURE.search(residual):
            return None
        notices = RACE_NOTICE.findall(residual)
        if len(notices) != int(test in leaves):
            return None
        residual = RACE_NOTICE.sub("", residual)
        if "race detected during execution" in residual:
            return None
        if test in failed and TEST_DIAGNOSTIC.search(residual):
            return None
        labels = FAIL_LABEL.findall(residual)
        if any(label != test or label not in failed for label in labels):
            return None
        if len(labels) != int(test in failed) or "--- FAIL:" in FAIL_LABEL.sub("", residual):
            return None
    if observed != leaves or not failed <= texts.keys():
        return None
    return sorted(leaves)


def inherited_txs_fee(stream):
    """Classify only the retained upstream test-harness race, never other failures."""
    failures = [e["Test"] for e in stream if e["Action"] == "fail" and e.get("Test")]
    failed = set(failures)
    leaves = failed - {TXS_MIGRATION}
    if (len(failures) != len(failed) or TXS_MIGRATION not in failed
            or not leaves or not leaves <= TXS_MIGRATION_LEAVES):
        return None
    texts = {}
    for event in stream:
        if event.get("Test") in failed and event["Action"] in ("pass", "skip"):
            return None
        if event["Action"] == "output":
            texts.setdefault(event.get("Test"), []).append(event.get("Output", ""))
    reports_seen = 0
    for test, parts in texts.items():
        text = "".join(parts)
        for report in RACE_REPORT.finditer(text):
            if test not in leaves:
                return None
            accesses = ACCESS.findall(report[1])
            if (len(accesses) != 2 or len(ACCESS_HEADER.findall(report[1])) != 2
                    or [a[0] for a in accesses] != ["", "Previous "]):
                return None
            mock = MODULE + "integrationTests/mock.(*GasScheduleNotifierMock).RegisterNotifyHandler()"
            suffix = "integrationTests/mock/gasScheduleNotifierMock.go"
            # The reviewed inherited mock append can also have runtime.growslice
            # as one top frame. Require at least one exact mock frame in every report.
            valid = [(frame == mock and line == "23" and
                      (path == suffix or path.endswith("/" + suffix)))
                     for _, _, frame, path, line in accesses]
            if not any(valid) or any(not ok and not (frame == "runtime.growslice()" and
                    path.endswith("/runtime/slice.go") and line == "178")
                    for ok, (_, _, frame, path, line) in zip(valid, accesses)):
                return None
            reports_seen += 1
        residual = RACE_REPORT.sub("", text)
        if "WARNING: DATA RACE" in residual or OTHER_FAILURE.search(residual):
            return None
        if len(RACE_NOTICE.findall(residual)) != int(test in leaves):
            return None
        residual = RACE_NOTICE.sub("", residual)
        if "race detected during execution" in residual:
            return None
        if test in failed and TEST_DIAGNOSTIC.search(residual):
            return None
        labels = FAIL_LABEL.findall(residual)
        if (len(labels) != int(test in failed) or any(label != test for label in labels)
                or "--- FAIL:" in FAIL_LABEL.sub("", residual)):
            return None
    if not reports_seen or not failed <= texts.keys():
        return None
    return sorted(leaves)


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
    inherited = []
    inherited_txs = []
    failed = []
    # Compiler, runtime, test2json or invocation diagnostics must never be waived.
    if stderr.strip():
        errors.append("scoped race stderr is not empty")
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
        if relative == STATE_TRIE:
            leaves = inherited_state_trie(stream)
            if leaves is not None:
                inherited.append({"package": package, "failed_tests": leaves})
                continue
            errors.append(package + ": default race failure outside approved inherited stateTrie evidence")
            continue
        if relative == TXS_FEE:
            leaves = inherited_txs_fee(stream)
            if leaves is not None:
                inherited_txs.append({"package": package, "failed_tests": leaves})
                continue
        errors.append(package + ": race failure outside approved inherited evidence")
    if exit_code not in (0, 1) or bool(failed) != (exit_code == 1):
        errors.append("scoped race exit/terminal mismatch")
    return {"scoped_exit": exit_code,
            "known_inherited_statetrie_failures": inherited,
            "known_inherited_txs_fee_failures": inherited_txs, "errors": errors}


def race_commands(packages, flags):
    base = ["go", "test", "-race", "-json", "-count=1", *VM_FLAGS, *flags]
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
    scoped = execute(race_commands(args.packages, flags), output, "scoped-race")
    policy = classify((output / "scoped-race.jsonl").read_text(),
                      (output / "scoped-race.stderr").read_text(), scoped["exit"], args.packages)
    summary = {"scoped_race": scoped, "classification": policy,
               "vm_module_gcflags": list(VM_FLAGS),
               "race_only_skips": [{"package": "./node", "test": "^TestWaitForSignal$",
                                    "reason": "owner-authorized known upstream test defect; normal coverage retains test"}]
                                  if "./node" in args.packages else [],
               "scope": "four VM module compatibility flags only; inherited test failures are report-only, not clean race credit"}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return int(bool(policy["errors"]))


if __name__ == "__main__":
    sys.exit(main())
