package main

import (
	"encoding/json"
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/cover"
)

func TestEndToEndHybridGateAndNoIgnoreRules(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	write := func(name, text string) {
		t.Helper()
		if e := os.WriteFile(name, []byte(text), 0644); e != nil {
			t.Fatal(e)
		}
	}
	run := func(args ...string) string {
		t.Helper()
		b, e := command(args...)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	write("go.mod", "module example.com/fixture\n\ngo 1.26\n")
	write("f.go", "package fixture\nfunc Existing(flag bool) int {\n if flag {\n  return 1\n }\n return 0\n}\n")
	run("git", "init", "-q")
	run("git", "add", "go.mod", "f.go")
	commit := func() {
		t.Helper()
		run("git", "-c", "user.name=Codex", "-c", "user.email=contact@dharitri.org", "-c", "commit.gpgsign=false", "commit", "--no-gpg-sign", "-qm", "SP1-COV-01: CI gate fixture")
	}
	commit()
	base := strings.TrimSpace(run("git", "rev-parse", "HEAD"))
	write("f.go", "package fixture\nfunc Existing(flag bool) int {\n if flag {\n  return 2\n }\n return 0\n}\nfunc New(flag bool) int {\n if flag {\n  return 17\n }\n return 23\n}\n")
	write("f_test.go", "package fixture\nimport \"testing\"\nfunc TestPartial(t *testing.T) { if Existing(true)!=2 || New(true)!=17 { t.Fatal(\"fixture\") } }\nfunc TestFull(t *testing.T) { if New(false)!=23 { t.Fatal(\"fixture\") } }\n")
	write("codecov.yml", "ignore:\n  - \"f.go\"\n")
	run("git", "add", "f.go", "f_test.go", "codecov.yml")
	commit()
	t.Log(run("git", "diff", "--unified=0", base, "HEAD", "--", "f.go"))
	run("go", "test", "-race", "-count=1", "-run=^TestPartial$", "-covermode=atomic", "-coverprofile=partial.out", "./")
	r, e := analyze(base, base, "partial.out", "./")
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Errors) == 0 {
		t.Fatal("uncovered new-function branch or codecov ignore bypassed gate")
	}
	if r.DiffFunctions != (counts{2, 2}) {
		t.Fatalf("function entry counts %+v", r.DiffFunctions)
	}
	if len(r.Uncovered) == 0 {
		t.Fatal("uncovered DRWA lines were omitted")
	}
	for _, f := range r.Changed {
		if f.Name == "Existing" && (f.Policy != "changed_blocks" || f.Statements != (counts{1, 1})) {
			t.Fatalf("existing upstream function %+v", f)
		}
		if f.Name == "New" && (f.Policy != "whole_function" || f.Statements != (counts{2, 3})) {
			t.Fatalf("new DRWA function %+v", f)
		}
	}
	run("go", "test", "-race", "-count=1", "-covermode=atomic", "-coverprofile=full.out", "./")
	r, e = analyze(base, base, "full.out", "./")
	if e != nil || len(r.Errors) > 0 {
		t.Fatalf("full fixture: %v, %v", e, r.Errors)
	}
	write("missing.out", "mode: atomic\n")
	r, e = analyze(base, base, "missing.out", "./")
	if e != nil || len(r.Errors) == 0 {
		t.Fatal("missing profile must reject")
	}
	write("wrong-mode.out", "mode: set\n")
	if _, e = analyze(base, base, "wrong-mode.out", "./"); e == nil {
		t.Fatal("non-atomic profile accepted")
	}
	if _, e = os.Stat(filepath.Join(dir, "codecov.yml")); e != nil {
		t.Fatal(e)
	}
}

func TestHybridPolicyDoesNotHideUntouchedNewFunctionStatements(t *testing.T) {
	// One covered statement is changed; nine uncovered statements are unchanged.
	// The upstream policy measures the changed block; the new-function policy
	// must measure all ten, independently of which line changed.
	f := function{Blocks: []cover.ProfileBlock{
		{StartLine: 2, EndLine: 2, NumStmt: 1, Count: 1},
		{StartLine: 4, EndLine: 12, NumStmt: 9, Count: 0},
	}}
	lines := map[int]bool{2: true}
	upstream := sum(selectedBlocks(f, true, lines))
	novel := sum(selectedBlocks(f, false, lines))
	if upstream != (counts{1, 1}) || !upstream.sufficient() {
		t.Fatalf("upstream changed block: %+v", upstream)
	}
	if novel != (counts{1, 10}) || novel.sufficient() {
		t.Fatalf("new function must reject 10%% coverage: %+v", novel)
	}
}
func TestThresholdAndFunctionEntry(t *testing.T) {
	for _, v := range []struct {
		c    counts
		want bool
	}{{counts{9, 10}, true}, {counts{8, 10}, false}, {counts{89, 100}, false}, {counts{90, 100}, true}, {counts{0, 0}, true}} {
		if v.c.sufficient() != v.want {
			t.Fatalf("threshold %+v", v.c)
		}
	}
	// A nested/late block cannot stand in for the entry block.
	if entered([]cover.ProfileBlock{{Count: 0}, {Count: 1}}) {
		t.Fatal("unentered function reported entered")
	}
	if !entered([]cover.ProfileBlock{{Count: 1, NumStmt: 0}}) {
		t.Fatal("empty entered function lost")
	}
	if entered(nil) {
		t.Fatal("missing instrumentation reported entered")
	}
}
func TestFunctionIdentityAndGoProfileSemantics(t *testing.T) {
	fs, e := functions("fixture.go", []byte("package fixture\ntype T struct{}\nfunc (*T) F() { if true { return }; panic(0) }\nfunc G() {}\nfunc Assembly()\n"))
	if e != nil || len(fs) != 2 || fs[0].Name != "*T.F" || fs[1].Name != "G" {
		t.Fatalf("functions %+v: %v", fs, e)
	}
	p, e := cover.ParseProfilesFromReader(strings.NewReader("mode: atomic\nfixture.go:3.15,3.26 1 1\nfixture.go:3.28,3.43 2 0\n"))
	if e != nil {
		t.Fatal(e)
	}
	if c := sum(p[0].Blocks); c != (counts{1, 3}) {
		t.Fatalf("Go statement counts %+v", c)
	}
	if _, e = cover.ParseProfilesFromReader(strings.NewReader("mode: atomic\nmalformed\n")); e == nil {
		t.Fatal("malformed profile accepted")
	}
}

func TestExcludedPackage(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"integrationTests", true}, {"integrationTests/vm", true}, {"testscommon", true}, {"testscommon/trie", true},
		{"mock", true}, {"api/mock", true}, {"production/mock/deep", true},
		{"mockable", false}, {"api/mocks", false}, {"integrationTestsExtra", false}, {"testscommonExtra", false},
		{"production/integrationTests", false}, {"production/testscommon", false}, {"process/drwa", false},
	} {
		t.Run(tc.path+" should use only exact owner-selected boundaries", func(t *testing.T) {
			if got := excludedPackage(tc.path); got != tc.want {
				t.Fatalf("excludedPackage(%q)=%v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestLoadLineExceptions_RejectsOtherLines(t *testing.T) {
	original := append([]byte(nil), exceptionJSON...)
	t.Cleanup(func() { exceptionJSON = original })
	for _, mode := range []string{"other function", "other line", "duplicate entry"} {
		t.Run(mode+" should reject the manifest", func(t *testing.T) {
			var entries []lineException
			if err := json.Unmarshal(original, &entries); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "other function":
				entries[0].Function = "OtherConstructor"
			case "other line":
				entries[0].Line--
			case "duplicate entry":
				entries[1] = entries[0]
			}
			var err error
			exceptionJSON, err = json.Marshal(entries)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = loadLineExceptions(); err == nil {
				t.Fatal("an unapproved or duplicate exception was accepted")
			}
		})
	}
}

func TestApplyLineExceptions(t *testing.T) {
	entries, err := loadLineExceptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 {
		t.Fatalf("exception count %d", len(entries))
	}
	for _, entry := range entries {
		t.Run(entry.File+fmt.Sprint(entry.Line)+" should remove only its exact defensive statement", func(t *testing.T) {
			lines := make([]string, entry.Line+2)
			lines[entry.Line-1] = "\t\treturn nil, err"
			source := []byte(strings.Join(lines, "\n"))
			fs := []function{{Name: entry.Function, Start: token.Position{Line: 1}, End: token.Position{Line: len(lines)}}}
			blocks := []cover.ProfileBlock{{StartLine: 2, EndLine: 2, NumStmt: 9, Count: 1}, {StartLine: entry.Line, EndLine: entry.Line, NumStmt: 1, Count: 0}}
			kept, outcomes := applyLineExceptions(entry.File, source, fs, blocks, []lineException{entry})
			if len(outcomes) != 1 || !outcomes[0].Applied || outcomes[0].Error != "" || outcomes[0].Removed != (counts{0, 1}) || sum(kept) != (counts{9, 9}) {
				t.Fatalf("exact exception: %+v, blocks %+v", outcomes, kept)
			}
			// Another statement on a neighboring line must remain counted.
			adjacent := append(append([]cover.ProfileBlock(nil), blocks...), cover.ProfileBlock{StartLine: entry.Line + 1, EndLine: entry.Line + 1, NumStmt: 1, Count: 0})
			kept, _ = applyLineExceptions(entry.File, source, fs, adjacent, []lineException{entry})
			if sum(kept) != (counts{9, 10}) {
				t.Fatalf("neighbor statement excluded: %+v", kept)
			}
		})
	}
}

func TestApplyLineExceptions_ChangedSource(t *testing.T) {
	entries, err := loadLineExceptions()
	if err != nil {
		t.Fatal(err)
	}
	entry := entries[0]
	for _, mode := range []string{"changed text", "moved function", "multi-statement block"} {
		t.Run(mode+" should stop the exception applying", func(t *testing.T) {
			lines := make([]string, entry.Line+2)
			lines[entry.Line-1] = "\t\treturn nil, err"
			fs := []function{{Name: entry.Function, Start: token.Position{Line: 1}, End: token.Position{Line: len(lines)}}}
			blocks := []cover.ProfileBlock{{StartLine: entry.Line, EndLine: entry.Line, NumStmt: 1, Count: 0}}
			switch mode {
			case "changed text":
				lines[entry.Line-1] = "\t\treturn nil, otherError"
			case "moved function":
				fs[0].Name = "OtherConstructor"
			case "multi-statement block":
				blocks[0].NumStmt = 2
			}
			kept, outcomes := applyLineExceptions(entry.File, []byte(strings.Join(lines, "\n")), fs, blocks, []lineException{entry})
			if len(outcomes) != 1 || outcomes[0].Applied || outcomes[0].Error == "" || sum(kept) != sum(blocks) {
				t.Fatalf("stale exception applied: %+v, %+v", outcomes, kept)
			}
		})
	}
}

func TestAnalyze_HelperExclusion(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) string {
		t.Helper()
		b, err := command(args...)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	commit := func() {
		run("git", "add", ".")
		run("git", "-c", "user.name=Codex", "-c", "user.email=contact@dharitri.org", "-c", "commit.gpgsign=false", "commit", "--no-gpg-sign", "-qm", "SP1-COV-01: coverage policy test fixture")
	}
	write("go.mod", "module example.com/policy\n\ngo 1.26\n")
	write("f.go", "package policy\nfunc Existing()int{return 0}\n")
	run("git", "init", "-q")
	commit()
	base := strings.TrimSpace(run("git", "rev-parse", "HEAD"))
	write("f.go", "package policy\nfunc Existing()int{return 1}\n")
	write("f_test.go", "package policy\nimport \"testing\"\nfunc TestExisting(t *testing.T){if Existing()!=1{t.Fatal(\"native result\")}}\n")
	helpers := []string{"mock", "integrationTests", "testscommon", "production/mock"}
	ordinary := []string{"mockable", "production/integrationTests"}
	for _, path := range append(append([]string(nil), helpers...), ordinary...) {
		write(path+"/f.go", "package fixture\nfunc Added()int{return 7}\n")
	}
	commit()
	packages := "./ ./mock ./integrationTests ./testscommon ./production/mock ./mockable ./production/integrationTests"
	args := []string{"go", "test", "-count=1", "-covermode=atomic", "-coverprofile=partial.out"}
	args = append(args, strings.Fields(packages)...)
	run(args...)
	result, err := analyze(base, base, "partial.out", packages)
	if err != nil {
		t.Fatal(err)
	}
	if result.DiffStatements != (counts{1, 3}) || result.UpstreamStatements != (counts{1, 1}) || result.DiffFunctions != (counts{1, 3}) {
		t.Fatalf("non-excluded package or helper affected gate counts: %+v %+v %+v", result.DiffStatements, result.UpstreamStatements, result.DiffFunctions)
	}
	if len(result.Errors) == 0 {
		t.Fatal("ordinary uncovered functions bypassed gate")
	}
	if len(result.ExcludedFiles) != len(helpers) {
		t.Fatalf("excluded files %+v", result.ExcludedFiles)
	}
	removed := 0
	for _, file := range result.ExcludedFiles {
		if file.Statements != (counts{0, 1}) || file.DiffStatements != (counts{0, 1}) || file.DiffFunctions != (counts{0, 1}) || file.MissingProfile {
			t.Fatalf("removed metrics %+v", file)
		}
		removed += file.DiffStatements.Total
	}
	if removed != 4 {
		t.Fatalf("removed statements %d", removed)
	}
	// All ordinary code now exercised: helper zero counters must not block the
	// healthy gate, and similarly named ordinary packages must still contribute.
	for _, path := range ordinary {
		write(path+"/f_test.go", "package fixture\nimport \"testing\"\nfunc TestAdded(t *testing.T){if Added()!=7{t.Fatal(\"native result\")}}\n")
	}
	args = []string{"go", "test", "-count=1", "-covermode=atomic", "-coverprofile=full.out"}
	args = append(args, strings.Fields(packages)...)
	run(args...)
	result, err = analyze(base, base, "full.out", packages)
	if err != nil || len(result.Errors) != 0 || result.DiffStatements != (counts{3, 3}) || result.DiffFunctions != (counts{3, 3}) {
		t.Fatalf("healthy helper-exclusion fixture: %+v, %v", result, err)
	}
}

func TestAnalyze_ChangedExceptionStopsGate(t *testing.T) {
	t.Chdir(t.TempDir())
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) string {
		t.Helper()
		b, err := command(args...)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	commit := func() {
		run("git", "add", "go.mod")
		run("git", "-c", "user.name=Codex", "-c", "user.email=contact@dharitri.org", "-c", "commit.gpgsign=false", "commit", "--no-gpg-sign", "-qm", "SP1-COV-01: exact-line policy test fixture")
	}
	write("go.mod", "module example.com/exceptions\n\ngo 1.26\n")
	run("git", "init", "-q")
	commit()
	base := strings.TrimSpace(run("git", "rev-parse", "HEAD"))
	file := "process/drwa/burnForAllAbsence.go"
	lines := make([]string, 132)
	lines[0] = "package drwa"
	lines[1] = "func NewBurnForAllAbsence()(any,error){"
	lines[2] = "var err error"
	profile := "mode: atomic\nexample.com/exceptions/" + file + ":3.1,3.14 1 1\n"
	for _, line := range []int{106, 110, 118, 124, 129} {
		lines[line-2] = "if false {"
		lines[line-1] = "\t\treturn nil, err"
		lines[line] = "}"
		profile += fmt.Sprintf("example.com/exceptions/%s:%d.3,%d.18 1 1\n", file, line, line)
	}
	lines[130] = "return nil,nil"
	lines[131] = "}"
	profile += "example.com/exceptions/" + file + ":131.1,131.15 1 1\n"
	write(file, strings.Join(lines, "\n")+"\n")
	write("profile.out", profile)
	run("git", "add", file)
	run("git", "-c", "user.name=Codex", "-c", "user.email=contact@dharitri.org", "-c", "commit.gpgsign=false", "commit", "--no-gpg-sign", "-qm", "SP1-COV-01: listed-line policy test fixture")
	result, err := analyze(base, base, "profile.out", "./process/drwa")
	if err != nil || len(result.Errors) != 0 || result.DiffStatements != (counts{2, 2}) || len(result.LineExceptions) != 5 {
		t.Fatalf("healthy listed-line policy: %+v %v", result, err)
	}
	for _, line := range result.NonInstrumented {
		for _, entry := range result.LineExceptions {
			if entry.Applied && line.File == entry.File && line.Line == entry.Line {
				t.Fatal("an explicitly excluded instrumented line was reported as non-instrumented")
			}
		}
	}
	// Synthetic profile counters are deliberately all covered. The changed
	// source must reject because the exception is stale, independently of ratios.
	lines[105] = "\t\treturn nil, nil"
	write(file, strings.Join(lines, "\n")+"\n")
	result, err = analyze(base, base, "profile.out", "./process/drwa")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, message := range result.Errors {
		if strings.Contains(message, "line exception no longer applies") {
			found = true
		}
	}
	if !found || result.DiffStatements != (counts{3, 3}) {
		t.Fatalf("changed source did not stop the exception: %+v", result)
	}
}
