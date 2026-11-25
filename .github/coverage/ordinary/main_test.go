package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const (
	alpha = "example.invalid/toy/alpha"
	beta  = "example.invalid/toy/beta"
	gamma = "example.invalid/toy/gamma"
)

func toyProfile(t *testing.T, content string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "profile.out")
	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestAggregateToyPackages(t *testing.T) {
	name := toyProfile(t, "mode: atomic\n"+
		alpha+"/one.go:2.1,2.4 2 3\n"+
		alpha+"/one.go:3.1,3.4 1 0\n"+
		alpha+"/two.go:2.1,2.4 4 1\n"+
		beta+"/one.go:2.1,2.4 3 0\n"+
		alpha+"/child/one.go:2.1,2.4 99 1\n"+
		gamma+"/one.go:2.1,2.4 99 1\n")
	got, err := aggregate(name, beta+" "+alpha)
	if err != nil {
		t.Fatal(err)
	}
	want := []packageResult{{beta, "measured", &counts{0, 3}}, {alpha, "measured", &counts{6, 7}}}
	if !reflect.DeepEqual(got.Packages, want) || !got.AllRequestedPackagesPresent ||
		got.AggregateStatements == nil || *got.AggregateStatements != (counts{6, 10}) || got.ObservedStatements != (counts{6, 10}) ||
		got.ProfileStatus != "present" || got.ProfileMode != "atomic" || len(got.ProfileSHA256) != 64 {
		t.Fatalf("unexpected report: %+v", got)
	}
}

func TestAggregateToyPartialProfile(t *testing.T) {
	name := toyProfile(t, "mode: set\n"+alpha+"/one.go:2.1,2.4 1 0\n")
	got, err := aggregate(name, alpha+" "+beta)
	if err != nil {
		t.Fatal(err)
	}
	want := []packageResult{{alpha, "measured", &counts{0, 1}}, {beta, "package_absent", nil}}
	if !reflect.DeepEqual(got.Packages, want) || got.AllRequestedPackagesPresent ||
		got.AggregateStatements != nil || got.ObservedStatements != (counts{0, 1}) {
		t.Fatalf("missing package was confused with measured zero: %+v", got)
	}
}

func TestAggregateToyAbsentProfile(t *testing.T) {
	for _, tc := range []struct {
		name, status string
	}{{"", "not_supplied"}, {filepath.Join(t.TempDir(), "not-there.out"), "not_found"}} {
		got, err := aggregate(tc.name, alpha)
		if err != nil {
			t.Fatal(err)
		}
		if got.ProfileStatus != tc.status || got.ProfileMode != "" || got.ProfileSHA256 != "" ||
			got.AllRequestedPackagesPresent || got.AggregateStatements != nil || got.ObservedStatements != (counts{}) ||
			!reflect.DeepEqual(got.Packages, []packageResult{{alpha, "profile_absent", nil}}) {
			t.Fatalf("absent profile: %+v", got)
		}
	}
}

func TestAggregateToyEmptyAndZeroStatementProfiles(t *testing.T) {
	for _, tc := range []struct {
		content, status string
		want            *counts
	}{{"mode: count\n", "package_absent", nil}, {"mode: count\n" + alpha + "/one.go:2.1,2.4 0 1\n", "measured", &counts{}}} {
		got, err := aggregate(toyProfile(t, tc.content), alpha)
		if err != nil {
			t.Fatal(err)
		}
		if got.ProfileStatus != "present" || got.ProfileMode != "count" || got.Packages[0].Status != tc.status ||
			!reflect.DeepEqual(got.AggregateStatements, tc.want) || !reflect.DeepEqual(got.Packages[0].Statements, tc.want) {
			t.Fatalf("empty/zero statements: %+v", got)
		}
	}
}

func TestAggregateToyRepeatedBlock(t *testing.T) {
	name := toyProfile(t, "mode: atomic\n"+alpha+"/one.go:2.1,2.4 2 0\n"+alpha+"/one.go:2.1,2.4 2 3\n")
	got, err := aggregate(name, alpha)
	if err != nil || got.AggregateStatements == nil || *got.AggregateStatements != (counts{2, 2}) {
		t.Fatalf("repeated profile region: %+v, %v", got, err)
	}
}

func TestAggregateToyInvalidInputs(t *testing.T) {
	for _, content := range []string{"", "mode: other\n", "mode: atomic\nnot a profile row\n"} {
		if _, err := aggregate(toyProfile(t, content), alpha); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	for _, packages := range []string{"", alpha + " " + alpha, "./alpha", alpha + "/...", alpha + "/*", "/alpha", "../alpha", "alpha/../beta", "alpha\\beta", alpha + ",", alpha + ":"} {
		if _, err := aggregate("", packages); err == nil {
			t.Fatal("invalid package list accepted")
		}
	}
	if _, err := aggregate(t.TempDir(), alpha); err == nil {
		t.Fatal("non-profile read error treated as absent")
	}
}

func TestAggregateToyRejectsCommaSuffixBeforeReporting(t *testing.T) {
	name := toyProfile(t, "mode: atomic\n"+alpha+"/one.go:2.1,2.4 2 1\n")
	// A mistyped import path must not become an apparently absent package.
	if _, err := aggregate(name, alpha+", "+beta); err == nil {
		t.Fatal("comma-suffixed package path accepted")
	}
	var out bytes.Buffer
	if err := run([]string{"-profile", name, "-packages", alpha + ", " + beta}, &out); err == nil || out.Len() != 0 {
		t.Fatal("invalid package list produced a report")
	}
}

func TestRunToyReportJSON(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-packages", alpha}, &out); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["aggregate_statements"]) != "null" || string(raw["profile_status"]) != `"not_supplied"` {
		t.Fatalf("report did not retain absent status: %s", out.String())
	}
	if _, found := raw["manifest"]; found {
		t.Fatal("default report unexpectedly contains manifest metadata")
	}
	for _, args := range [][]string{{"-unknown"}, {"-packages", alpha, "unexpected"}, {"-profile", "missing"}} {
		if err := run(args, &out); err == nil {
			t.Fatal("invalid invocation accepted")
		}
	}
}

func TestToyManifestCompleteIncludingMeasuredZero(t *testing.T) {
	name := toyProfile(t, "mode: atomic\n"+
		alpha+"/one.go:2.1,2.4 2 0\n"+
		beta+"/one.go:2.1,2.4 0 1\n"+
		alpha+"/extra.go:2.1,2.4 3 1\n")
	manifest := toyProfile(t, beta+"/one.go\n"+alpha+"/one.go\n")
	got, err := aggregateWithManifest(name, alpha+" "+beta, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest == nil || !got.Manifest.AllExpectedFilesPresent ||
		got.Manifest.ExpectedFiles != 2 || !reflect.DeepEqual(got.Manifest.MissingFiles, []string{}) ||
		len(got.Manifest.SHA256) != 64 || got.AggregateStatements == nil ||
		*got.AggregateStatements != (counts{3, 5}) ||
		!reflect.DeepEqual(got.Packages[1].Statements, &counts{}) {
		t.Fatalf("unexpected complete manifest report: %+v", got)
	}
	// SHA-256 of the exact beta-then-alpha fixture bytes, including both newlines.
	const expectedManifestSHA256 = "1ee5c1d5404bee1c2501c782cdaf4f3baa5be394505df8325f95c06d9cc8a582"
	if got.Manifest.SHA256 != expectedManifestSHA256 {
		t.Fatalf("manifest digest = %q, want %q", got.Manifest.SHA256, expectedManifestSHA256)
	}
}

func TestToyManifestMissingFileInPresentPackage(t *testing.T) {
	name := toyProfile(t, "mode: atomic\n"+alpha+"/one.go:2.1,2.4 2 1\n")
	manifest := toyProfile(t, alpha+"/one.go\n"+alpha+"/two.go\n"+alpha+"/three.go\n")
	got, err := aggregateWithManifest(name, alpha, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest == nil || got.Manifest.AllExpectedFilesPresent ||
		!reflect.DeepEqual(got.Manifest.MissingFiles, []string{alpha + "/two.go", alpha + "/three.go"}) ||
		!got.AllRequestedPackagesPresent || got.AggregateStatements != nil ||
		got.ObservedStatements != (counts{2, 2}) {
		t.Fatalf("partial file presence treated as complete: %+v", got)
	}
}

func TestToyManifestAbsentProfileAndPackage(t *testing.T) {
	manifest := toyProfile(t, alpha+"/one.go\n"+beta+"/one.go\n")
	for _, tc := range []struct {
		profile, status string
		missing         []string
	}{
		{"", "not_supplied", []string{alpha + "/one.go", beta + "/one.go"}},
		{filepath.Join(t.TempDir(), "missing.out"), "not_found", []string{alpha + "/one.go", beta + "/one.go"}},
		{toyProfile(t, "mode: set\n"+alpha+"/one.go:2.1,2.4 2 0\n"), "present", []string{beta + "/one.go"}},
	} {
		got, err := aggregateWithManifest(tc.profile, alpha+" "+beta, manifest)
		if err != nil {
			t.Fatal(err)
		}
		if got.Manifest == nil || got.Manifest.AllExpectedFilesPresent ||
			!reflect.DeepEqual(got.Manifest.MissingFiles, tc.missing) ||
			got.ProfileStatus != tc.status || got.AggregateStatements != nil {
			t.Fatalf("unexpected absent manifest report: %+v", got)
		}
	}
}

func TestToyManifestInvalidInputs(t *testing.T) {
	for _, contents := range []string{
		"", alpha + "/one.go", alpha + "/one.go " + alpha + "/one.go " + beta + "/one.go",
		alpha + "/one.go " + beta + "/one.txt", alpha + "/one.go " + beta + "/*.go",
		alpha + "/one.go " + beta + "/../beta/one.go", alpha + "/one.go " + beta + "/one.go " + gamma + "/one.go",
		alpha + "/one.go " + beta + "/sub/one.go",
	} {
		var out bytes.Buffer
		if err := run([]string{"-packages", alpha + " " + beta, "-manifest", toyProfile(t, contents)}, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid manifest produced a report: %q", contents)
		}
	}
	if _, err := aggregateWithManifest("", alpha, filepath.Join(t.TempDir(), "missing.manifest")); err == nil {
		t.Fatal("missing manifest accepted")
	}
	var out bytes.Buffer
	if err := run([]string{"-packages", alpha, "-manifest="}, &out); err == nil || out.Len() != 0 {
		t.Fatal("explicit empty manifest path silently disabled manifest checking")
	}
}

func TestRunToyManifestJSON(t *testing.T) {
	var out bytes.Buffer
	manifest := toyProfile(t, alpha+"/one.go\n")
	if err := run([]string{"-packages", alpha, "-manifest", manifest}, &out); err != nil {
		t.Fatal(err)
	}
	var got report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Manifest == nil || !reflect.DeepEqual(got.Manifest.MissingFiles, []string{alpha + "/one.go"}) ||
		got.AggregateStatements != nil || got.Manifest.AllExpectedFilesPresent {
		t.Fatalf("manifest JSON did not preserve absent state: %s", out.String())
	}
}
