"""Synthetic checks of the focused named runner; no product tests execute."""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


CI = pathlib.Path(__file__).resolve().parent


class OrdinaryNamedRunnerTests(unittest.TestCase):
    def test_receipts_continue_through_failed_and_missing_profile_groups(self):
        for mode in ("normal", "race"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = pathlib.Path(folder)
                ci = root / ".github/ci"
                ci.mkdir(parents=True)
                shutil.copyfile(CI / "named_test_receipt.py", ci / "named_test_receipt.py")
                shutil.copyfile(CI / "ordinary_package_profile.py", ci / "ordinary_package_profile.py")
                # Invoke the actual runner functions, but only with invented package/test names.
                script = (CI / "ordinary_named.sh").read_text().split("\nrun_group writer ", 1)[0]
                runner = root / "toy-runner.sh"
                runner.write_text(script + "\n" + "\n".join([
                    "run_nested_group nested ./toy/nested TestToyNested first second",
                    "run_group failed ./toy/failed TestToyFailed",
                    "run_group missing ./toy/missing TestToyMissing",
                    "run_group invalid ./toy/invalid TestToyInvalid",
                    "run_group header ./toy/header TestToyHeader",
                    "run_group malformed ./toy/malformed TestToyMalformed",
                    "run_group truncated ./toy/truncated TestToyTruncated",
                    "run_group copyfail ./toy/copyfail TestToyCopyfail",
                    "run_group later ./toy/later TestToyLater",
                    'exit "$failed"',
                ]) + "\n")
                stub = root / "go"
                stub.write_text("#!" + sys.executable + "\n" + r'''import json, os, pathlib, sys
args = sys.argv[1:]
assert args[0] == "test"
assert ("-race" in args) == (os.environ["TOY_MODE"] == "race")
assert "-json" in args and "-count=1" in args and "-covermode=atomic" in args
package = args[-1]
name = package.rsplit("/", 1)[-1]
profile = pathlib.Path(next(a.split("=", 1)[1] for a in args if a.startswith("-coverprofile=")))
selector = next(a.split("=", 1)[1] for a in args if a.startswith("-run="))
root = {"nested":"TestToyNested", "failed":"TestToyFailed", "missing":"TestToyMissing", "invalid":"TestToyInvalid", "header":"TestToyHeader", "malformed":"TestToyMalformed", "truncated":"TestToyTruncated", "copyfail":"TestToyCopyfail", "later":"TestToyLater"}[name]
assert selector == ("^(TestToyNested)$/^(first|second)$" if name == "nested" else "^(" + root + ")$")
with pathlib.Path("calls.jsonl").open("a") as stream:
    stream.write(json.dumps({"group":name,"selector":selector}) + "\n")
def emit(action, test=None):
    data = {"Action": action, "Package": "github.com/multiversx/mx-chain-go/" + package[2:]}
    if test is not None:
        data["Test"] = test
    print(json.dumps(data))
emit("start"); emit("run", root)
if name == "nested":
    for leaf in ("first", "second"):
        emit("run", root + "/" + leaf); emit("pass", root + "/" + leaf)
if name != "missing":
    header = "mode: set" if name == "invalid" else "mode: atomic"
    row = "github.com/multiversx/mx-chain-go/toy/" + name + "/toy.go:1.1,1.2 1 " + ("0" if name == "later" else "1")
    contents = header + "\n" + row + "\n"
    if name == "header":
        contents = header + "\n"
    elif name == "malformed":
        contents += "incomplete row\n"
    elif name == "truncated":
        contents = contents[:-1]
    profile.write_text(contents)
emit("fail" if name == "failed" else "pass", root)
emit("fail" if name == "failed" else "pass")
sys.exit(1 if name == "failed" else 0)
''')
                stub.chmod(0o755)
                copy_stub = root / "cp"
                copy_stub.write_text("#!" + sys.executable + "\n" + r'''import pathlib, shutil, sys
first, second, dest = map(pathlib.Path, sys.argv[1:])
shutil.copyfile(first, dest / first.name)
if first.name.startswith("copyfail."):
    sys.exit(1)
shutil.copyfile(second, dest / second.name)
''')
                copy_stub.chmod(0o755)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], TOY_MODE=mode)
                result = subprocess.run(["bash", str(runner), mode, "results"], cwd=root, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                calls = [json.loads(line)["group"] for line in (root / "calls.jsonl").read_text().splitlines()]
                self.assertEqual(calls, ["nested", "failed", "missing", "invalid", "header", "malformed", "truncated", "copyfail", "later"])
                portable = root / "results/portable"
                expected = {"nested": (0, 0, 0, 0), "failed": (1, 1, 2, 2),
                            "missing": (0, 0, 1, 2), "invalid": (0, 0, 1, 2),
                            "header": (0, 0, 1, 2), "malformed": (0, 0, 1, 2),
                            "truncated": (0, 0, 1, 2), "copyfail": (0, 0, 0, 1), "later": (0, 0, 0, 0)}
                for group, statuses in expected.items():
                    for kind, value in zip(("test", "receipt", "profile", "publish"), statuses):
                        self.assertEqual((portable / f"{group}.{kind}.exit").read_text().strip(), str(value))
                    for suffix in ("receipt.json", "cover"):
                        self.assertEqual((portable / f"{group}.{suffix}").exists(), group in ("nested", "later"))
                nested = json.loads((portable / "nested.receipt.json").read_text())
                self.assertEqual(nested["verified_test_count_including_parents"], 3)
                raw_missing = json.loads((root / "results/missing.receipt.json").read_text())
                self.assertEqual(raw_missing["status"], "pass")


    def test_file_list_receipts_continue_after_missing_and_invalid_profiles(self):
        for mode in ("normal", "race"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="ordinary toy ") as folder:
                root = pathlib.Path(folder).resolve()
                ci = root / ".github/ci"
                ci.mkdir(parents=True)
                shutil.copyfile(CI / "named_test_receipt.py", ci / "named_test_receipt.py")
                normalizer = root / ".github/coverage/ordinary/file-list-portable"
                normalizer.mkdir(parents=True)
                shutil.copyfile(CI.parent / "coverage/ordinary/file-list-portable/normalize.py",
                                normalizer / "normalize.py")
                for directory in ("cmd/assessment/benchmarks", "common/hostParameters", "common/statistics/osLevel"):
                    (root / directory).mkdir(parents=True)
                # Only the normalization group names are real; every test name,
                # event, source file argument and coverage row here is invented.
                script = (CI / "ordinary_named.sh").read_text().split("\nrun_group writer ", 1)[0]
                runner = root / "toy-runner.sh"
                runner.write_text(script + "\n" + "\n".join([
                    "run_file_group assessment_report_boundary cmd/assessment/benchmarks '^(TestToyNested)$/^(one|two)$' '' TestToyNested/one TestToyNested/two -- toy.go toy_test.go",
                    "run_file_group host_display_wrap common/hostParameters '^(TestToyMissing)$' '' TestToyMissing -- toy.go toy_test.go",
                    "run_file_group memory_display_units common/statistics/osLevel '^(TestToyInvalid)$' 'command-line-arguments,github.com/multiversx/mx-chain-core-go/core' TestToyInvalid -- toy.go toy_test.go",
                    "run_file_group assessment_existing cmd/assessment/benchmarks '^(TestToyLater)$' '' TestToyLater -- toy.go toy_test.go",
                    'exit "$failed"',
                ]) + "\n")
                stub = root / "go"
                stub.write_text("#!" + sys.executable + "\n" + r'''import json, os, pathlib, sys
args = sys.argv[1:]
assert args[0] == "test" and args[-2:] == ["toy.go", "toy_test.go"]
assert ("-race" in args) == (os.environ["TOY_MODE"] == "race")
assert all(x in args for x in ("-mod=readonly", "-count=1", "-timeout=70s", "-json", "-covermode=atomic"))
profile = pathlib.Path(next(a.split("=", 1)[1] for a in args if a.startswith("-coverprofile=")))
group = profile.name.removesuffix(".raw.cover")
root = pathlib.Path(os.environ["TOY_ROOT"])
expected = {
    "assessment_report_boundary": ("cmd/assessment/benchmarks", "TestToyNested"),
    "host_display_wrap": ("common/hostParameters", "TestToyMissing"),
    "memory_display_units": ("common/statistics/osLevel", "TestToyInvalid"),
    "assessment_existing": ("cmd/assessment/benchmarks", "TestToyLater"),
}
directory, test = expected[group]
assert pathlib.Path.cwd() == root / directory and profile.is_absolute()
selector = args[args.index("-run") + 1]
assert selector == ("^(TestToyNested)$/^(one|two)$" if group == "assessment_report_boundary" else "^(" + test + ")$")
assert [x for x in args if x.startswith("-coverpkg=")] == (["-coverpkg=command-line-arguments,github.com/multiversx/mx-chain-core-go/core"] if group == "memory_display_units" else [])
with (root / "calls.jsonl").open("a") as stream:
    stream.write(json.dumps({"group": group}) + "\n")
def emit(action, name=None):
    data = {"Action": action, "Package": "command-line-arguments"}
    if name is not None:
        data["Test"] = name
    print(json.dumps(data))
emit("start"); emit("run", test)
if group == "assessment_report_boundary":
    for leaf in ("one", "two"):
        emit("run", test + "/" + leaf); emit("pass", test + "/" + leaf)
if group != "host_display_wrap":
    file = "invented.go" if group == "memory_display_units" else "results.go"
    profile.write_text("mode: atomic\n" + str(root / directory / file) + ":1.1,1.2 1 1\n")
emit("pass", test); emit("pass")
''')
                stub.chmod(0o755)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                           TOY_MODE=mode, TOY_ROOT=str(root))
                result = subprocess.run(["bash", str(runner), mode, "results"], cwd=root, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                calls = [json.loads(line)["group"] for line in (root / "calls.jsonl").read_text().splitlines()]
                self.assertEqual(calls, ["assessment_report_boundary", "host_display_wrap",
                                         "memory_display_units", "assessment_existing"])
                portable = root / "results/portable"
                expected = {"assessment_report_boundary": (0, 0, 0, 0), "host_display_wrap": (0, 0, 1, 2),
                            "memory_display_units": (0, 0, 1, 2), "assessment_existing": (0, 0, 0, 0)}
                for group, statuses in expected.items():
                    for kind, value in zip(("test", "receipt", "profile", "publish"), statuses):
                        self.assertEqual((portable / f"{group}.{kind}.exit").read_text().strip(), str(value))
                    for suffix in ("named-receipt.json", "normalization.json", "cover"):
                        file = portable / f"{group}.{suffix}"
                        self.assertEqual(file.exists(), statuses == (0, 0, 0, 0))
                        if file.exists():
                            self.assertNotIn(str(root), file.read_text())
                    raw_named = json.loads((root / "results" / f"{group}.named-receipt.json").read_text())
                    self.assertEqual(raw_named["status"], "pass")
                nested = json.loads((portable / "assessment_report_boundary.named-receipt.json").read_text())
                self.assertEqual(nested["verified_test_count_including_parents"], 3)
                for group in ("assessment_report_boundary", "assessment_existing"):
                    normalization = json.loads((portable / f"{group}.normalization.json").read_text())
                    self.assertEqual(normalization["group"], group)
                    self.assertEqual(normalization["execution_mode"], mode)
                    self.assertEqual(normalization["scope_counts"]["node"], {"blocks": 1, "covered": 1, "total": 1})
                    self.assertEqual((portable / f"{group}.cover").read_text(),
                                     "mode: atomic\ngithub.com/multiversx/mx-chain-go/cmd/assessment/benchmarks/results.go:1.1,1.2 1 1\n")
                self.assertFalse((root / "results/host_display_wrap.raw.cover").exists())
                self.assertTrue((root / "results/memory_display_units.raw.cover").exists())
                self.assertFalse(any(".raw." in file.name for file in portable.iterdir()))


    def test_preexisting_output_cannot_publish_prior_run_artifacts(self):
        for mode in ("normal", "race"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="ordinary toy ") as folder:
                root = pathlib.Path(folder)
                output = root / "prior results"
                portable = output / "portable"
                portable.mkdir(parents=True)
                prior = {"toy.cover": b"mode: atomic\nexample.test/toy/a.go:1.1,1.2 1 1\n",
                         "toy.receipt.json": b'{"status":"pass"}\n', "toy.test.exit": b"0\n"}
                for name, content in prior.items():
                    (portable / name).write_bytes(content)
                raw = output / "toy.events.jsonl"
                raw.write_bytes(b'{"Action":"pass","Package":"example.test/toy"}\n')
                stub = root / "go"
                stub.write_text("#!/bin/sh\n: > go-was-called\nexit 97\n")
                stub.chmod(0o755)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"])
                argv = ["bash", str(CI / "ordinary_named.sh"), mode, str(output)]
                result = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "go-was-called").exists())
                # The existing CI upload path must not contain previous results.
                self.assertFalse(portable.exists())
                archives = list(output.glob(".prior-portable.*"))
                self.assertEqual(len(archives), 1)
                preserved = archives[0] / "portable"
                self.assertEqual({f.name: f.read_bytes() for f in preserved.iterdir()}, prior)
                self.assertEqual(raw.read_bytes(), b'{"Action":"pass","Package":"example.test/toy"}\n')
                # A repeat rejection with no current portable directory leaves
                # the preserved prior artifacts untouched, with no new execution.
                second = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True)
                self.assertNotEqual(second.returncode, 0)
                self.assertFalse(portable.exists())
                self.assertFalse((root / "go-was-called").exists())
                self.assertEqual(list(output.glob(".prior-portable.*")), archives)
                self.assertEqual({f.name: f.read_bytes() for f in preserved.iterdir()}, prior)


if __name__ == "__main__":
    unittest.main()
