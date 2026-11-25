// Command ordinary reports statement counts from an optional Go cover profile.
// It does not implement or modify a coverage gate.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/tools/cover"
)

type counts struct {
	Covered int `json:"covered"`
	Total   int `json:"total"`
}

type packageResult struct {
	Package    string  `json:"package"`
	Status     string  `json:"status"`
	Statements *counts `json:"statements"`
}

type manifestResult struct {
	SHA256                  string   `json:"sha256"`
	ExpectedFiles           int      `json:"expected_files"`
	MissingFiles            []string `json:"missing_files"`
	AllExpectedFilesPresent bool     `json:"all_expected_files_present"`
}

type report struct {
	ProfileStatus               string          `json:"profile_status"`
	ProfileMode                 string          `json:"profile_mode,omitempty"`
	ProfileSHA256               string          `json:"profile_sha256,omitempty"`
	Packages                    []packageResult `json:"packages"`
	AllRequestedPackagesPresent bool            `json:"all_requested_packages_present"`
	ObservedStatements          counts          `json:"observed_statements"`
	AggregateStatements         *counts         `json:"aggregate_statements"`
	Manifest                    *manifestResult `json:"manifest,omitempty"`
	Scope                       string          `json:"scope"`
}

func packageList(value string) ([]string, error) {
	packages := strings.Fields(value)
	if len(packages) == 0 {
		return nil, fmt.Errorf("an explicit package list is required")
	}
	seen := make(map[string]bool, len(packages))
	for _, pkg := range packages {
		if module.CheckImportPath(pkg) != nil || path.IsAbs(pkg) || path.Clean(pkg) != pkg || pkg == "." || pkg == ".." ||
			strings.HasPrefix(pkg, "../") || strings.Contains(pkg, "...") || strings.ContainsAny(pkg, `\*?[]`) {
			return nil, fmt.Errorf("expected an exact package import path: %q", pkg)
		}
		if seen[pkg] {
			return nil, fmt.Errorf("duplicate requested package: %q", pkg)
		}
		seen[pkg] = true
	}
	return packages, nil
}

func aggregate(profilePath, packagesArg string) (report, error) {
	return aggregateWithManifest(profilePath, packagesArg, "")
}

// readManifest accepts only exact profile filenames belonging to the
// requested packages. Each package needs at least one expected file.
func readManifest(manifestPath string, packages []string) (*manifestResult, error) {
	if manifestPath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	expected := strings.Fields(string(data))
	requested := make(map[string]bool, len(packages))
	for _, pkg := range packages {
		requested[pkg] = false
	}
	seen := make(map[string]bool, len(expected))
	for _, name := range expected {
		pkg := path.Dir(name)
		if _, ok := requested[pkg]; !ok || module.CheckFilePath(name) != nil ||
			path.Clean(name) != name || !strings.HasSuffix(name, ".go") ||
			strings.Contains(name, "...") || strings.ContainsAny(name, `\*?[]`) {
			return nil, fmt.Errorf("expected an exact Go profile filename in a requested package: %q", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate expected filename: %q", name)
		}
		seen[name] = true
		requested[pkg] = true
	}
	for _, pkg := range packages {
		if !requested[pkg] {
			return nil, fmt.Errorf("manifest has no expected files for package %q", pkg)
		}
	}
	return &manifestResult{
		SHA256:        fmt.Sprintf("%x", sha256.Sum256(data)),
		ExpectedFiles: len(expected),
		MissingFiles:  expected,
	}, nil
}

func aggregateWithManifest(profilePath, packagesArg, manifestPath string) (report, error) {
	packages, err := packageList(packagesArg)
	if err != nil {
		return report{}, err
	}
	manifest, err := readManifest(manifestPath, packages)
	if err != nil {
		return report{}, err
	}
	result := report{
		Scope:    "profile blocks for explicitly requested package paths only; not a source census or qualification gate",
		Packages: make([]packageResult, len(packages)),
		Manifest: manifest,
	}
	for i, pkg := range packages {
		result.Packages[i] = packageResult{Package: pkg, Status: "profile_absent"}
	}
	if profilePath == "" {
		result.ProfileStatus = "not_supplied"
		return result, nil
	}
	data, err := os.ReadFile(profilePath)
	if os.IsNotExist(err) {
		result.ProfileStatus = "not_found"
		return result, nil
	}
	if err != nil {
		return report{}, err
	}
	header, _, _ := bytes.Cut(data, []byte{'\n'})
	switch string(header) {
	case "mode: set", "mode: count", "mode: atomic":
		result.ProfileMode = strings.TrimPrefix(string(header), "mode: ")
	default:
		return report{}, fmt.Errorf("expected a Go coverage profile mode header")
	}
	profiles, err := cover.ParseProfilesFromReader(bytes.NewReader(data))
	if err != nil {
		return report{}, err
	}
	result.ProfileStatus = "present"
	result.ProfileSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	byPackage := make(map[string]counts)
	requested := make(map[string]bool, len(packages))
	for _, pkg := range packages {
		requested[pkg] = true
	}
	observedFiles := make(map[string]bool)
	for _, profile := range profiles {
		pkg := path.Dir(profile.FileName)
		if !requested[pkg] {
			continue
		}
		if manifest != nil {
			observedFiles[profile.FileName] = true
		}
		c := byPackage[pkg]
		for _, block := range profile.Blocks {
			c.Total += block.NumStmt
			if block.Count > 0 {
				c.Covered += block.NumStmt
			}
		}
		byPackage[pkg] = c
	}
	result.AllRequestedPackagesPresent = true
	for i := range result.Packages {
		row := &result.Packages[i]
		c, found := byPackage[row.Package]
		if !found {
			row.Status = "package_absent"
			result.AllRequestedPackagesPresent = false
			continue
		}
		row.Status = "measured"
		row.Statements = &c
		result.ObservedStatements.Covered += c.Covered
		result.ObservedStatements.Total += c.Total
	}
	if manifest != nil {
		missing := make([]string, 0)
		for _, name := range manifest.MissingFiles {
			if !observedFiles[name] {
				missing = append(missing, name)
			}
		}
		manifest.MissingFiles = missing
		manifest.AllExpectedFilesPresent = len(missing) == 0
	}
	if result.AllRequestedPackagesPresent && (manifest == nil || manifest.AllExpectedFilesPresent) {
		result.AggregateStatements = &result.ObservedStatements
	}
	return result, nil
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("ordinary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := flags.String("profile", "", "Go coverage profile (optional)")
	packages := flags.String("packages", "", "explicit space-separated package import paths")
	manifest := flags.String("manifest", "", "explicit expected Go profile filename list (optional)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	manifestSupplied := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "manifest" {
			manifestSupplied = true
		}
	})
	if manifestSupplied && *manifest == "" {
		return fmt.Errorf("manifest path must not be empty when supplied")
	}
	result, err := aggregateWithManifest(*profile, *packages, *manifest)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
