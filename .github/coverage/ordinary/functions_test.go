package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const toySource = `package toy

func First() int {
 x := 1
 return x
}

func Second() int {
 return 2
}
`
const toyFunctionProfile = "mode: atomic\nexample.invalid/toy/one.go:3.18,4.8 1 1\nexample.invalid/toy/one.go:5.2,6.2 1 0\nexample.invalid/toy/one.go:8.19,10.2 1 0\n"

func toyManifest(profile string) functionManifest {
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(toySource)))
	return functionManifest{ProfileSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(profile))), Functions: []functionSpec{
		{Source: "one.go", SourceSHA256: sha, ProfileFile: "example.invalid/toy/one.go", Name: "First", Span: [4]int{3, 1, 6, 2}, Blocks: []blockSpec{{point{3, 18}, point{4, 8}, 1}, {point{5, 2}, point{6, 2}, 1}}},
		{Source: "one.go", SourceSHA256: sha, ProfileFile: "example.invalid/toy/one.go", Name: "Second", Span: [4]int{8, 1, 10, 2}, Blocks: []blockSpec{{point{8, 19}, point{10, 2}, 1}}},
	}}
}

func functionFixture(t *testing.T, profile, source string, m functionManifest) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	manifest, profilePath := filepath.Join(root, "manifest.json"), filepath.Join(root, "toy.cover")
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{manifest: raw, profilePath: []byte(profile), filepath.Join(root, "one.go"): []byte(source)} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return profilePath, manifest, root
}

func TestFunctionReportMatching(t *testing.T) {
	p, m, r := functionFixture(t, toyFunctionProfile, toySource, toyManifest(toyFunctionProfile))
	var out bytes.Buffer
	if err := run([]string{"-profile", p, "-functions", m, "-source-root", r}, &out); err != nil {
		t.Fatal(err)
	}
	var got functionReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ProfileSHA256 != toyManifest(toyFunctionProfile).ProfileSHA256 || got.ProfileMode != "atomic" || got.ProfileStatus != "present" || got.ExpectedStatements != 3 || got.AggregateStatements == nil || *got.AggregateStatements != (counts{Covered: 1, Total: 3}) {
		t.Fatalf("unexpected report: %+v", got)
	}
	if len(got.Functions) != 2 || got.Functions[0].Status != "measured" || got.Functions[1].Status != "measured" || got.Functions[1].Statements == nil || *got.Functions[1].Statements != (counts{Covered: 0, Total: 1}) || got.Functions[0].SourceSHA256 != toyManifest(toyFunctionProfile).Functions[0].SourceSHA256 {
		t.Fatalf("unexpected functions: %+v", got.Functions)
	}
}

func TestFunctionReportGoGeneratedAtomicProfile(t *testing.T) {
	root := t.TempDir()
	const pkg = "example.invalid/palette/v2/labels"
	const source = `package labels

func Primary() string {
	label := "blue"
	return label
}

func Secondary() string {
	return "green"
}
`
	if err := os.Mkdir(filepath.Join(root, "labels"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"go.mod":                 "module example.invalid/palette/v2\n\ngo 1.26\n",
		"labels/palette.go":      source,
		"labels/palette_test.go": "package labels\nimport \"testing\"\nfunc TestPrimary(t *testing.T) { if Primary()!=\"blue\" { t.Fatal(\"fixture\") } }\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Fix the expected declaration spans and blocks from this small fixture,
	// independently of the profile that the Go compiler will produce.
	sourceSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(source)))
	manifest := functionManifest{Functions: []functionSpec{
		{Source: "labels/palette.go", SourceSHA256: sourceSHA, ProfileFile: pkg + "/palette.go", Name: "Secondary", Span: [4]int{8, 1, 10, 2}, Blocks: []blockSpec{{point{8, 25}, point{10, 2}, 1}}},
		{Source: "labels/palette.go", SourceSHA256: sourceSHA, ProfileFile: pkg + "/palette.go", Name: "Primary", Span: [4]int{3, 1, 6, 2}, Blocks: []blockSpec{{point{3, 23}, point{6, 2}, 2}}},
	}}
	profile := filepath.Join(root, "toy.cover")
	cmd := exec.Command("go", "test", "-count=1", "-covermode=atomic", "-coverprofile=toy.cover", "./labels")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off", "GOFLAGS=-mod=readonly")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated toy profile: %v: %s", err, output)
	}
	raw, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ProfileSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestRaw, 0600); err != nil {
		t.Fatal(err)
	}

	args := []string{"-profile", profile, "-functions", manifestPath, "-source-root", root}
	var out, repeated bytes.Buffer
	for _, dst := range []*bytes.Buffer{&out, &repeated} {
		if err := run(args, dst); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(out.Bytes(), repeated.Bytes()) {
		t.Fatal("function report output is not deterministic")
	}
	var got functionReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := counts{2, 3}
	if got.ManifestSHA256 != fmt.Sprintf("%x", sha256.Sum256(manifestRaw)) ||
		got.ProfileSHA256 != manifest.ProfileSHA256 || got.ProfileStatus != "present" || got.ProfileMode != "atomic" ||
		got.ExpectedStatements != 3 || got.ObservedStatements != want ||
		got.AggregateStatements == nil || *got.AggregateStatements != want || len(got.Functions) != 2 {
		t.Fatalf("unexpected generated profile report: %+v", got)
	}
	// Preserve manifest order and distinguish a measured, unentered function
	// from a missing function. Both functions have all expected blocks.
	for index, expected := range []counts{{0, 1}, {2, 2}} {
		row, spec := got.Functions[index], manifest.Functions[index]
		if row.Name != spec.Name || row.Span != spec.Span || row.Source != spec.Source ||
			row.SourceSHA256 != sourceSHA || row.ProfileFile != spec.ProfileFile || row.Status != "measured" ||
			row.ExpectedStatements != expected.Total || row.Statements == nil || *row.Statements != expected ||
			row.ObservedStatements == nil || *row.ObservedStatements != expected || len(row.MissingBlocks) != 0 {
			t.Fatalf("unexpected generated function %d: %+v", index, row)
		}
	}
}

func TestFunctionReportMissingData(t *testing.T) {
	profile := "mode: atomic\nexample.invalid/toy/one.go:3.18,4.8 1 1\n"
	p, m, r := functionFixture(t, profile, toySource, toyManifest(profile))
	got, err := aggregateFunctions(p, m, r)
	if err != nil {
		t.Fatal(err)
	}
	if got.AggregateStatements != nil || got.ExpectedStatements != 3 || got.ObservedStatements != (counts{Covered: 1, Total: 1}) || got.Functions[0].Status != "partial" || got.Functions[0].Statements != nil || len(got.Functions[0].MissingBlocks) != 1 || got.Functions[1].Status != "blocks_absent" || got.Functions[1].ObservedStatements != nil {
		t.Fatalf("unexpected report: %+v", got)
	}
	for _, path := range []string{"", filepath.Join(r, "missing.cover")} {
		got, err = aggregateFunctions(path, m, r)
		if err != nil {
			t.Fatal(err)
		}
		want := "not_supplied"
		if path != "" {
			want = "not_found"
		}
		if got.ProfileStatus != want || got.AggregateStatements != nil || got.ExpectedStatements != 3 || got.Functions[0].Status != "profile_absent" || got.Functions[0].Statements != nil || len(got.Functions[0].MissingBlocks) != 2 {
			t.Fatalf("unexpected absent report: %+v", got)
		}
	}
}

func TestFunctionReportInconsistentInputs(t *testing.T) {
	for _, tc := range []struct {
		name, profile, source, want string
		mutate                      func(*functionManifest)
	}{
		{"source", toyFunctionProfile, toySource + "\n", "source digest mismatch", nil},
		{"profile", toyFunctionProfile + "\n", toySource, "profile digest mismatch", func(m *functionManifest) { m.ProfileSHA256 = toyManifest(toyFunctionProfile).ProfileSHA256 }},
		{"count", strings.Replace(toyFunctionProfile, "4.8 1 1", "4.8 2 1", 1), toySource, "inconsistent compiler block", nil},
		{"unexpected", toyFunctionProfile + "example.invalid/toy/one.go:4.2,4.8 1 1\n", toySource, "inconsistent compiler block", nil},
		{"span", toyFunctionProfile, toySource, "missing or duplicate exact function", func(m *functionManifest) { m.Functions[0].Span[2]++ }},
		{"duplicate", toyFunctionProfile, toySource, "invalid or duplicate expected block", func(m *functionManifest) {
			m.Functions[0].Blocks = append(m.Functions[0].Blocks, m.Functions[0].Blocks[0])
		}},
		{"overlap", toyFunctionProfile, toySource, "overlapping expected blocks", func(m *functionManifest) {
			m.Functions[0].Blocks = append(m.Functions[0].Blocks, blockSpec{point{4, 2}, point{5, 4}, 1})
		}},
		{"crossing", toyFunctionProfile + "example.invalid/toy/one.go:2.1,3.18 1 1\n", toySource, "inconsistent compiler block", nil},
		{"alias", toyFunctionProfile, toySource, "multiple profile filenames", func(m *functionManifest) { m.Functions[1].ProfileFile = "example.invalid/other/one.go" }},
		{"path", toyFunctionProfile, toySource, "incomplete source/block binding", func(m *functionManifest) { m.Functions[0].ProfileFile = "../one.go" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := toyManifest(tc.profile)
			if tc.mutate != nil {
				tc.mutate(&m)
			}
			p, mp, r := functionFixture(t, tc.profile, tc.source, m)
			_, err := aggregateFunctions(p, mp, r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v; want %q", err, tc.want)
			}
		})
	}
}

func TestFunctionModeExclusive(t *testing.T) {
	for _, args := range [][]string{{"-functions", "m"}, {"-source-root", "r"}, {"-functions", "m", "-source-root", "r", "-packages", "p"}, {"-functions", "m", "-source-root", "r", "-manifest", "m"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestFunctionReportInvalidBlockCoordinates(t *testing.T) {
	for _, row := range []string{"0.1,1.4 1 1", "1.4,1.1 1 1"} {
		profile := toyFunctionProfile + "example.invalid/toy/one.go:" + row + "\n"
		p, m, r := functionFixture(t, profile, toySource, toyManifest(profile))
		if _, err := aggregateFunctions(p, m, r); err == nil {
			t.Fatal("invalid profile block outside selected function accepted")
		}
	}
}

func TestFunctionReportIndependentProfileBinding(t *testing.T) {
	other := strings.Replace(toyFunctionProfile, "4.8 1 1", "4.8 1 0", 1)
	p, m, r := functionFixture(t, toyFunctionProfile, toySource, toyManifest(toyFunctionProfile))
	q, n, s := functionFixture(t, other, toySource, toyManifest(other))
	first, err := aggregateFunctions(p, m, r)
	if err != nil || first.AggregateStatements == nil || *first.AggregateStatements != (counts{1, 3}) {
		t.Fatalf("first report: %+v, %v", first, err)
	}
	second, err := aggregateFunctions(q, n, s)
	if err != nil || second.AggregateStatements == nil || *second.AggregateStatements != (counts{0, 3}) {
		t.Fatalf("second report: %+v, %v", second, err)
	}
	if first.ProfileMode != "atomic" || second.ProfileMode != "atomic" || first.ProfileSHA256 == second.ProfileSHA256 {
		t.Fatal("independent atomic profiles not distinguished by digest")
	}
	if _, err := aggregateFunctions(q, m, r); err == nil || !strings.Contains(err.Error(), "profile digest mismatch") {
		t.Fatalf("cross-profile manifest accepted: %v", err)
	}
}
