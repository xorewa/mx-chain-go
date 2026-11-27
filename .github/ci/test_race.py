import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from race import (VM_FLAGS, MODULE, STATE_TRIE, STATE_TRIE_LEAVES, MIGRATION, TXS_FEE, TXS_MIGRATION, TXS_MIGRATION_LEAVES, classify, race_commands, execute, main)


class RacePolicyTests(unittest.TestCase):
    def test_split_commands_preserve_each_exit_and_keep_failures(self):
        commands = [["go", "test", "./process"], ["go", "test", "./node"]]
        for codes, expected in [([0, 0], 0), ([1, 0], 1), ([0, 1], 1), ([2, 0], 2)]:
            with tempfile.TemporaryDirectory() as folder:
                with patch("race.subprocess.run", side_effect=[subprocess.CompletedProcess(c, e) for c, e in zip(commands, codes)]) as run:
                    summary = execute(commands, pathlib.Path(folder), "fixture")
                self.assertEqual(run.call_count, 2)
                self.assertEqual(summary["exit"], expected)
                self.assertEqual([r["exit"] for r in summary["commands"]], codes)
                self.assertEqual([r["argv"] for r in summary["commands"]], commands)

    def test_skip_is_exact_and_only_in_separate_node_commands(self):
        for flags in [[], ["-run=^$"]]:
            commands = race_commands(["./factory/core", "./node", "./process"], flags)
            self.assertEqual(len(commands), 2)
            self.assertEqual(commands[0], ["go", "test", "-race", "-json", "-count=1", *VM_FLAGS, *flags,
                                            "./factory/core", "./process"])
            self.assertEqual(commands[1], ["go", "test", "-race", "-json", "-count=1", *VM_FLAGS, *flags,
                                            "-skip=^TestWaitForSignal$", "./node"])
        self.assertEqual(race_commands(["./process"], []),
                         [["go", "test", "-race", "-json", "-count=1", *VM_FLAGS, "./process"]])

    def fixture(self, package="./node"):
        name = MODULE + package[2:]
        text = ("fatal error: checkptr: pointer arithmetic result points to invalid allocation" + "\n\ngoroutine 19 gp=0xc00 m=0 mp=0x123 [running, locked to thread]:\n"
                "runtime.throw(0x1)\n\truntime/panic.go:1\n"
                "runtime.checkptrArithmetic(0x1)\n\truntime/checkptr.go:69\n" + "fixture.mockHook(" + "...)\n\twasmer2/helper.go:1\n")
        return [{"Action": "output", "Package": name, "Test": "TestVM", "Output": text},
                {"Action": "fail", "Package": name}]

    def check(self, events, code=1, package="./node", stderr=""):
        return classify("\n".join(json.dumps(e) for e in events), stderr, code, [package])

    def test_old_abort_no_longer_tolerated(self):
        self.assertTrue(self.check(self.fixture())["errors"])
        self.assertTrue(self.check(self.fixture("./process"), package="./process")["errors"])

    def test_vm_flag_scope_is_exact(self):
        expected = tuple("-gcflags=github.com/multiversx/" + module + "/...=-d=checkptr=0"
                         for module in ("mx-chain-vm-go", "mx-chain-vm-v1_2-go",
                                        "mx-chain-vm-v1_3-go", "mx-chain-vm-v1_4-go"))
        self.assertEqual(VM_FLAGS, expected)
        for cmd in race_commands(["./node", TXS_FEE, "./integrationTests/vm/wasm/wasmer"], []):
            self.assertEqual(tuple(x for x in cmd if x.startswith("-gcflags")), expected)
            self.assertIn("-race", cmd)

    def test_exit_stderr_and_missing_results_reject(self):
        self.assertTrue(self.check(self.fixture(), code=0)["errors"])
        self.assertTrue(self.check(self.fixture(), code=2)["errors"])
        self.assertTrue(self.check(self.fixture(), stderr="compiler failed")["errors"])
        self.assertTrue(self.check([])["errors"])
        self.assertTrue(classify("garbage", "", 1, ["./node"])["errors"])
        self.assertTrue(self.check(self.fixture() * 2)["errors"])

    def test_pass_skip_and_contradictory_results(self):
        for action in ["pass", "skip"]:
            self.assertEqual(self.check([{"Action": action, "Package": MODULE + "node"}], code=0)["errors"], [])
        e = self.fixture()
        e[-1]["Action"] = "pass"
        self.assertTrue(self.check(e, code=0)["errors"])

    def state_trie_fixture(self, leaf="TestTriePruningWhenBlockIsFinal"):
        name = MODULE + STATE_TRIE[2:]
        report = ("==================\nWARNING: DATA RACE\n"
                  "Write at 0x01 by goroutine 1:\n"
                  "  " + MODULE + "integrationTests.UpdateRound()\n"
                  "      integrationTests/testInitializer.go:2738 +0x1\n"
                  "Previous read at 0x01 by goroutine 2:\n"
                  "  " + MODULE + "integrationTests/mock.(*RoundHandlerMock).Index()\n"
                  "      integrationTests/mock/roundHandlerMock.go:30 +0x1\n"
                  "==================\n")
        events = [{"Action": "output", "Package": name, "Test": leaf, "Output": line}
                  for line in report.splitlines(keepends=True)]
        events.extend([
            {"Action": "output", "Package": name, "Test": leaf,
             "Output": "    testing.go:1712: race detected during execution of test\n"},
            {"Action": "output", "Package": name, "Test": leaf,
             "Output": "--- FAIL: " + leaf + " (0.01s)\n"},
            {"Action": "fail", "Package": name, "Test": leaf},
        ])
        if leaf.startswith(MIGRATION + "/"):
            events.extend([{"Action": "output", "Package": name, "Test": MIGRATION,
                            "Output": "--- FAIL: " + MIGRATION + " (0.01s)\n"},
                           {"Action": "fail", "Package": name, "Test": MIGRATION}])
        events.append({"Action": "fail", "Package": name})
        return events

    def test_inherited_state_trie_fixture_is_report_only(self):
        for leaf in sorted(STATE_TRIE_LEAVES):
            with self.subTest(leaf=leaf):
                r = self.check(self.state_trie_fixture(leaf), package=STATE_TRIE)
                self.assertEqual(r["errors"], [])
                self.assertEqual(r["scoped_exit"], 1)
                self.assertEqual(r["known_inherited_txs_fee_failures"], [])
                self.assertEqual(r["known_inherited_statetrie_failures"],
                                 [{"package": MODULE + STATE_TRIE[2:], "failed_tests": [leaf]}])

    def test_inherited_state_trie_rejects_other_outcomes(self):
        for leaf in ("TestUnlisted", MIGRATION, MIGRATION + "/migrate_shard_2_user_account"):
            self.assertTrue(self.check(self.state_trie_fixture(leaf), package=STATE_TRIE)["errors"])
        for old, new in (("Index()", "Other()"), ("go:30", "go:31"),
                         ("integrationTests/mock/", "unrelated/"),
                         ("WARNING: DATA RACE", "unrelated output"),
                         ("race detected during execution of test", "assertion failed")):
            events = self.state_trie_fixture()
            for e in events:
                if "Output" in e:
                    e["Output"] = e["Output"].replace(old, new)
            self.assertTrue(self.check(events, package=STATE_TRIE)["errors"])
        for extra in ("    toy_test.go:11: distinct failure\n", "panic: unrelated\n",
                      "WARNING: DATA RACE\n", "--- FAIL: TestUnlisted (0.00s)\n"):
            events = self.state_trie_fixture()
            events[0]["Output"] = extra + events[0]["Output"]
            self.assertTrue(self.check(events, package=STATE_TRIE)["errors"])
        self.assertTrue(self.check(self.state_trie_fixture(), package=STATE_TRIE, stderr="error")["errors"])

    def test_inherited_state_trie_driver_keeps_raw_scoped_and_no_rerun(self):
        script = pathlib.Path(__file__).with_name("race.py").resolve()
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            fake = root / "go"
            raw = "\n".join(map(json.dumps, self.state_trie_fixture())) + "\n"
            fake.write_text("#!" + sys.executable + "\nimport json,os,sys\n"
                            "with open(os.environ['CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                            "sys.stdout.write(" + repr(raw) + ")\nsys.exit(1)\n")
            fake.chmod(0o700)
            target = root / "output"
            calls = root / "calls"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], CALLS=str(calls))
            run = subprocess.run([sys.executable, "-B", str(script), "--output", str(target), STATE_TRIE],
                                 env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(list(map(json.loads, calls.read_text().splitlines())),
                             [["test", "-race", "-json", "-count=1", *VM_FLAGS, STATE_TRIE]])
            self.assertEqual((target / "scoped-race.jsonl").read_text(), raw)
            self.assertEqual((target / "scoped-race.stderr").read_bytes(), b"")
            summary = json.loads((target / "summary.json").read_text())
            self.assertEqual(summary["scoped_race"]["exit"], 1)
            self.assertEqual(summary["classification"]["known_inherited_statetrie_failures"],
                             [{"package": MODULE + STATE_TRIE[2:],
                               "failed_tests": ["TestTriePruningWhenBlockIsFinal"]}])

    def txs_fixture(self, leaf=None):
        leaf = leaf or sorted(TXS_MIGRATION_LEAVES)[0]
        name = MODULE + TXS_FEE[2:]
        mock = MODULE + "integrationTests/mock.(*GasScheduleNotifierMock).RegisterNotifyHandler()"
        report = ("==================\nWARNING: DATA RACE\n"
                  "Write at 0x01 by goroutine 1:\n  " + mock + "\n"
                  "      integrationTests/mock/gasScheduleNotifierMock.go:23 +0x1\n"
                  "Previous read at 0x01 by goroutine 2:\n  " + mock + "\n"
                  "      integrationTests/mock/gasScheduleNotifierMock.go:23 +0x1\n"
                  "==================\n")
        events = [{"Action": "output", "Package": name, "Test": leaf, "Output": line}
                  for line in report.splitlines(keepends=True)]
        events.extend([
            {"Action": "output", "Package": name, "Test": leaf,
             "Output": "    testing.go:1712: race detected during execution of test\n"},
            {"Action": "output", "Package": name, "Test": leaf,
             "Output": "--- FAIL: " + leaf + " (0.01s)\n"},
            {"Action": "fail", "Package": name, "Test": leaf},
            {"Action": "output", "Package": name, "Test": TXS_MIGRATION,
             "Output": "--- FAIL: " + TXS_MIGRATION + " (0.01s)\n"},
            {"Action": "fail", "Package": name, "Test": TXS_MIGRATION},
            {"Action": "fail", "Package": name},
        ])
        return events

    def test_txs_fee_exact_inherited_race_only(self):
        for leaf in TXS_MIGRATION_LEAVES:
            events = self.txs_fixture(leaf)
            result = self.check(events, package=TXS_FEE)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["scoped_exit"], 1)
            self.assertEqual(result["known_inherited_txs_fee_failures"],
                             [{"package": MODULE + TXS_FEE[2:], "failed_tests": [leaf]}])
        for leaf in (TXS_MIGRATION + "/unreviewed", "TestUnlisted", "TestMigrateDataTrieBuiltinFunc"):
            self.assertTrue(self.check(self.txs_fixture(leaf), package=TXS_FEE)["errors"])
        for old, new in (("go:23", "go:24"), ("RegisterNotifyHandler()", "Different()"),
                         ("WARNING: DATA RACE", "unrelated")):
            events = self.txs_fixture()
            for event in events:
                if "Output" in event:
                    event["Output"] = event["Output"].replace(old, new)
            self.assertTrue(self.check(events, package=TXS_FEE)["errors"])
        for extra in ("    toy.go:11: assertion failed\n", "fatal error: unexpected\n",
                      "WARNING: DATA RACE\n", "--- FAIL: TestOther (0.00s)\n"):
            events = self.txs_fixture()
            events[0]["Output"] = extra + events[0]["Output"]
            self.assertTrue(self.check(events, package=TXS_FEE)["errors"])
        self.assertTrue(self.check(self.txs_fixture(), package=TXS_FEE, stderr="error")["errors"])

    def test_txs_fee_retained_multiple_leaf_attribution(self):
        deterministic, random = sorted(TXS_MIGRATION_LEAVES)
        events = self.txs_fixture(random)
        # The reviewed JSON attributes a notice to another leaf of the same
        # root while all concrete race reports occur under the random leaf.
        name = MODULE + TXS_FEE[2:]
        events[0:0] = [
            {"Action": "output", "Package": name, "Test": deterministic,
             "Output": "    testing.go:1712: race detected during execution of test\n"},
            {"Action": "output", "Package": name, "Test": deterministic,
             "Output": "--- FAIL: " + deterministic + " (0.01s)\n"},
            {"Action": "fail", "Package": name, "Test": deterministic},
        ]
        for idx, event in enumerate(events):
            if event.get("Output", "").startswith("  " + MODULE + "integrationTests/mock."):
                event["Output"] = "  runtime.growslice()\n"
                events[idx + 1]["Output"] = "      /toy/runtime/slice.go:178 +0x1\n"
                break
        result = self.check(events, package=TXS_FEE)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["known_inherited_txs_fee_failures"][0]["failed_tests"],
                         [deterministic, random])
        # A second failure in a different root must never inherit the exception.
        events.insert(0, {"Action": "fail", "Package": name, "Test": "TestOther"})
        self.assertTrue(self.check(events, package=TXS_FEE)["errors"])

    def test_workflow_race_shards_match_declared_packages(self):
        workflow = pathlib.Path(__file__).resolve().parents[1] / "workflows/drwa-ci.yml"
        text = workflow.read_text()
        roster = text.split("  DRWA_PACKAGES: >-\n", 1)[1].split("\njobs:", 1)[0].split()
        shards = re.findall(r"            packages: >-\n((?:              \./[^\n]+\n)+)", text)
        selected = [package for shard in shards for package in shard.split()]
        self.assertEqual(len(roster), len(set(roster)))
        self.assertEqual(len(selected), len(set(selected)))
        self.assertEqual(set(selected), set(roster))
        self.assertTrue({TXS_FEE, "./integrationTests/vm/wasm/wasmer",
                         "./dataRetriever/txpool/memorytests"} <= set(selected))

    def test_workflow_coverage_helpers_include_ordinary_reporter(self):
        workflow = pathlib.Path(__file__).resolve().parents[1] / "workflows/drwa-ci.yml"
        text = workflow.read_text()
        heading = "      - name: Check coverage and race policy helpers\n"
        self.assertEqual(text.count(heading), 1)
        step = text.split(heading, 1)[1].split("\n      - name:", 1)[0]
        commands = [shlex.split(line.strip()) for line in step.splitlines()
                    if line.strip().startswith("go test ")]
        self.assertEqual(len(commands), 1)
        argv = commands[0]
        # Go package selection is not recursive. Require both helper packages
        # in this unfiltered invocation and preserve the common JSON receipt.
        self.assertEqual(argv[:4], ["go", "test", "-json", "-count=1"])
        self.assertEqual(len(argv[4:-2]), 2)
        self.assertEqual(set(argv[4:-2]), {"./.github/coverage",
                                         "./.github/coverage/ordinary"})
        self.assertEqual(argv[-2:], [">", "coverage-helper-tests.json"])

    def test_workflow_focused_ordinary_roots_are_exact(self):
        ci = pathlib.Path(__file__).resolve().parent
        script = (ci / "ordinary_named.sh").read_text()
        groups = {tuple(shlex.split(line)[1:]) for line in script.splitlines()
                  if line.startswith("run_group ")}
        self.assertEqual(groups, {
            ("writer", "./api/logs", "TestQualSP281COrdinaryLogWriterDistinctPayloadOrder"),
            ("presenter", "./cmd/termui/presenter",
             "TestQualSP281COrdinaryPresenterConcurrentCounters",
             "TestQualSP281COrdinaryPresenterCounterArithmetic",
             "TestQualSP281COrdinaryPresenterValueStoreRoundTrip"),
            ("drawable", "./cmd/termui/view/termuic/termuiRenders",
             "TestQualSP281COrdinaryDrawableContainerLayout",
             "TestQualSP281COrdinaryDrawableContainerSparseResize"),
            ("sort", "./common/compatibility",
             "TestQualSP281COrdinarySortStringMultiplicity",
             "TestQualSP281COrdinarySortModerateStringList",
             "TestQualSP218OrdinarySortRecordAssociation"),
            ("channel", "./common/errChan",
             "TestQualSP281COrdinaryErrChanGracefulCloseRetainsValue",
             "TestQualSP281COrdinaryErrChanPublicRoundTripReuse"),
            ("logging", "./common/logging", "TestQualSP281COrdinaryErrorLogRecord"),
            ("disabled-statistics", "./common/statistics/disabled",
             "TestQualSP281COrdinaryDisabledStatisticsReports"),
            ("memory-display", "./common/statistics/machine",
             "TestQualSP281COrdinaryMachineMemoryReport"),
            ("presenter-display", "./cmd/termui/presenter",
             "TestPresenterStatusHandler_GetAppVersion", "TestPresenterStatusHandler_GetNodeName",
             "TestPresenterStatusHandler_GetCpuLoadPercent", "TestPresenterStatusHandler_GetMemLoadPercent",
             "TestPresenterStatusHandler_GetTotalMem", "TestPresenterStatusHandler_GetMemUsedByNode",
             "TestPresenterStatusHandler_CheckSoftwareVersion", "TestPresenterStatusHandler_CheckSoftwareVersionNeedUpdate",
             "TestPresenterStatusHandler_GetLogLine", "TestPresenterStatusHandler_GetNodeNameShouldReturnDefaultName",
             "TestPresenterStatusHandler_GetNetworkRecvPercent", "TestPresenterStatusHandler_GetNetworkRecvBps",
             "TestPresenterStatusHandler_GetNetworkRecvBpsPeak", "TestPresenterStatusHandler_GetNetworkSentPercent",
             "TestPresenterStatusHandler_GetNetworkSentBps", "TestPresenterStatusHandler_GetNetworkSentBpsPeak",
             "TestPresenterStatusHandler_GetNetworkSendBytesInEpoch", "TestPresenterStatusHandler_GetNetworkReceivedBytesInEpoch"),
            ("disabled-status", "./common/disabled", "TestAppStatusHandler_MethodsShouldNotPanic"),
            ("statistics-report", "./common/statistics", "TestQualSP218OrdinaryStatisticsReportLabels"),
        })
        self.assertEqual(sum(line.startswith("run_group ") for line in script.splitlines()), 11)
        nested_groups = {tuple(shlex.split(line)[1:]) for line in script.splitlines()
                         if line.startswith("run_nested_group ")}
        self.assertEqual(nested_groups, {
            ("time-display", "./ntp", "TestQualSP281COrdinaryTimeDisplay",
             "zero_fraction", "leading_fraction_zeroes", "full_fraction"),
            ("label-fit", "./cmd/termui/view/termuic/termuiRenders", "TestQualSP281COrdinaryStatusLabelFit",
             "wide_pane_retains_label", "compact_pane_adds_ellipsis", "minimum_pane_leaves_label_blank"),
            ("log-layout", "./cmd/termui/view/termuic/termuiRenders", "TestWidgetsRender_prepareLogLines",
             "equal_size_should_return_the_same_slice", "should_trim", "small_size_should_return_empty"),
        })
        self.assertEqual(sum(line.startswith("run_nested_group ") for line in script.splitlines()), 3)
        self.assertIn('run_selected_group "$id" "$package" "^($selector)$" "$@"', script)
        self.assertIn('run_selected_group "$id" "$package" "^($root)$/^($selector)$" "${names[@]}"', script)
        self.assertIn('-run="$selector" "$package"', script)
        self.assertIn('race) flags=(-race)', script)
        self.assertIn('normal) flags=()', script)
        self.assertIn('named_test_receipt.py', script)
        self.assertIn('"${expected[@]}" --exit-code "$status"', script)
        self.assertIn('exit "$failed"', script)
        workflow = (ci.parent / "workflows/drwa-ci.yml").read_text()
        job = workflow.split("  ordinary-named:\n", 1)[1].split("  branch-trial:\n", 1)[0]
        self.assertIn("mode: [normal, race]", job)
        self.assertNotIn("continue-on-error", job)
        self.assertIn("GOPROXY: 'off'", job)
        self.assertIn("GOSUMDB: 'off'", job)
        self.assertIn("GOVCS: '*:off'", job)
        self.assertIn("unshare --user --map-root-user --net", job)
        self.assertIn('bash .github/ci/ordinary_named.sh ${{ matrix.mode }} "$ORDINARY_NAMED_OUTPUT"', job)
        self.assertIn("ORDINARY_NAMED_OUTPUT: ${{ steps.ordinary-output.outputs.directory }}", job)
        self.assertIn("path: ${{ steps.ordinary-output.outputs.directory }}/portable/", job)
        self.assertIn("steps.ordinary-output.outcome == 'success' && steps.ordinary-output.outputs.directory != ''", job)
        self.assertNotIn("ordinary-named-results", job)

    def test_workflow_ordinary_output_has_unique_current_invocation_path(self):
        workflow = (pathlib.Path(__file__).resolve().parents[1] / "workflows/drwa-ci.yml").read_text()
        job = workflow.split("  ordinary-named:\n", 1)[1].split("  branch-trial:\n", 1)[0]
        step = job.split("        id: ordinary-output\n        run: |\n", 1)[1].split("      - name:", 1)[0]
        self.assertTrue(all(line.startswith("          ") for line in step.splitlines()))
        command = "\n".join(line[10:] for line in step.splitlines())
        with tempfile.TemporaryDirectory(prefix="ordinary toy ") as scratch:
            root = pathlib.Path(scratch)
            runner_temp = root / "runner temp"
            runner_temp.mkdir()
            def allocate(label, temp):
                output = root / (label + ".output")
                env = dict(os.environ, RUNNER_TEMP=str(temp), GITHUB_OUTPUT=str(output))
                result = subprocess.run(["bash", "-euc", command], env=env, cwd=root,
                                        capture_output=True, text=True)
                return result, output
            first, first_output = allocate("first", runner_temp)
            self.assertEqual(first.returncode, 0)
            first_dir = pathlib.Path(first_output.read_text().removeprefix("directory=").strip())
            self.assertEqual(first_dir.parent.parent, runner_temp)
            self.assertFalse(first_dir.exists())
            prior = first_dir / "portable" / "prior.cover"
            prior.parent.mkdir(parents=True)
            prior.write_bytes(b"prior toy coverage bytes\n")
            second, second_output = allocate("second", runner_temp)
            self.assertEqual(second.returncode, 0)
            second_dir = pathlib.Path(second_output.read_text().removeprefix("directory=").strip())
            self.assertEqual(second_dir.parent.parent, runner_temp)
            self.assertNotEqual(first_dir, second_dir)
            self.assertFalse(second_dir.exists())
            self.assertEqual(prior.read_bytes(), b"prior toy coverage bytes\n")
            unavailable = root / "not a directory"
            unavailable.write_text("toy")
            failed, failure_output = allocate("failure", unavailable)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse(failure_output.exists())
            self.assertEqual(prior.read_bytes(), b"prior toy coverage bytes\n")

    def test_workflow_file_list_groups_are_exact(self):
        script = (pathlib.Path(__file__).resolve().parent / "ordinary_named.sh").read_text()
        groups = [tuple(shlex.split(line)[1:]) for line in script.splitlines()
                  if line.startswith("run_file_group ")]
        self.assertEqual(groups, [
            ("assessment_report_boundary", "cmd/assessment/benchmarks",
             "^(TestQualSP281COrdinaryAssessmentReportBoundary)$/^(empty_report_retains_total|single_report_retains_fractional_duration)$", "",
             "TestQualSP281COrdinaryAssessmentReportBoundary/empty_report_retains_total",
             "TestQualSP281COrdinaryAssessmentReportBoundary/single_report_retains_fractional_duration", "--",
             "results.go", "results_test.go", "qual_sp281c_ordinary_assessment_report_test.go"),
            ("host_display_wrap", "common/hostParameters",
             "^(TestQualSP281COrdinaryHostDisplayWrap|TestHostInfo_ToDisplayTable|TestHostInfo_ToStrings|TestQualSP281COrdinaryHostDisplayEmptyFlags)$", "",
             "TestQualSP281COrdinaryHostDisplayWrap", "TestHostInfo_ToDisplayTable", "TestHostInfo_ToStrings",
             "TestQualSP281COrdinaryHostDisplayEmptyFlags", "--", "hostInfo.go", "hostInfo_test.go",
             "qual_sp281c_ordinary_host_display_wrap_test.go"),
            ("memory_display_units", "common/statistics/osLevel", "^(TestQualSP281COrdinaryMemoryDisplayUnits)$",
             "command-line-arguments,github.com/multiversx/mx-chain-core-go/core",
             "TestQualSP281COrdinaryMemoryDisplayUnits", "--", "memStats.go", "errors.go",
             "qual_sp281c_ordinary_memory_display_units_test.go"),
            ("assessment_existing", "cmd/assessment/benchmarks",
             "^(TestTestResults_ToDisplayTable|TestTestResults_ToStrings|TestQualSP218OrdinaryAssessmentOrderedRows|TestQualSP218OrdinaryAssessmentRepeatedRowLabels)$", "",
             "TestTestResults_ToDisplayTable", "TestTestResults_ToStrings",
             "TestQualSP218OrdinaryAssessmentOrderedRows", "TestQualSP218OrdinaryAssessmentRepeatedRowLabels", "--",
             "results.go", "results_test.go", "qual_sp218_lane_f_ordinary_assessment_order_test.go",
             "qual_sp218_lane_f_ordinary_assessment_association_test.go"),
        ])
        self.assertIn('"${coverage[@]}" -run "$selector" "$@")', script)
        self.assertIn('--package command-line-arguments', script)
        self.assertIn('file-list-portable/normalize.py', script)
        self.assertIn('--group "$id" --mode "$mode"', script)
        self.assertIn('cp "$output/$id.normalized/coverage.cover" "$output/portable/$id.cover"', script)
        self.assertNotIn('cp "$output/$id.raw.cover"', script)

    def test_main_smoke_uses_scoped_flags_and_reports_fixture(self):
        with tempfile.TemporaryDirectory() as scratch:
            output = pathlib.Path(scratch) / "out"
            def fake_execute(commands, path, stem):
                self.assertEqual(stem, "scoped-race")
                self.assertEqual(commands, [["go", "test", "-race", "-json", "-count=1",
                                             *VM_FLAGS, "-run=^$", "./process"]])
                (path / (stem + ".jsonl")).write_text(json.dumps({"Action": "pass",
                                                                 "Package": MODULE + "process"}) + "\n")
                (path / (stem + ".stderr")).write_text("")
                return {"exit": 0, "commands": []}
            with patch("sys.argv", ["race.py", "--output", str(output), "--smoke", "./process"]),                     patch("race.execute", side_effect=fake_execute), patch("builtins.print"):
                self.assertEqual(main(), 0)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["vm_module_gcflags"], list(VM_FLAGS))
            self.assertEqual(summary["classification"]["errors"], [])

    def test_driver_single_scoped_run_and_rejects_unrelated_exit(self):
        script = pathlib.Path(__file__).with_name("race.py").resolve()
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            fake = root / "go"
            fake.write_text("#!" + sys.executable + "\nimport json,os,sys\n"
                            "with open(os.environ['CALLS'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n"
                            "print(json.dumps({'Action':'pass','Package':" + repr(MODULE + "node") + "}))\n"
                            "sys.exit(int(os.environ['TEST_EXIT']))\n")
            fake.chmod(0o700)
            for test_exit in (0, 1, 2):
                target = root / str(test_exit)
                calls = root / (str(test_exit) + ".calls")
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           TEST_EXIT=str(test_exit), CALLS=str(calls))
                run = subprocess.run([sys.executable, "-B", str(script), "--output", str(target), "./node"],
                                     env=env, capture_output=True, text=True)
                self.assertEqual(run.returncode, int(test_exit != 0), run.stderr)
                commands = list(map(json.loads, calls.read_text().splitlines()))
                self.assertEqual(commands, [["test", "-race", "-json", "-count=1", *VM_FLAGS,
                                             "-skip=^TestWaitForSignal$", "./node"]])
                summary = json.loads((target / "summary.json").read_text())
                self.assertEqual(summary["scoped_race"]["exit"], test_exit)
                self.assertEqual(summary["vm_module_gcflags"], list(VM_FLAGS))


if __name__ == "__main__":
    unittest.main()
