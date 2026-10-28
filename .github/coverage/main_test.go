package main

import (
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
		run("git", "-c", "user.name=Codex", "-c", "user.email=codex@localhost", "-c", "commit.gpgsign=false", "commit", "--no-gpg-sign", "-qm", "CI gate fixture")
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
