package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/tools/cover"
)

// A function manifest is a caller-reviewed compiler-block census, not a scope
// or provenance decision made by the reporter.
type functionManifest struct {
	ProfileSHA256 string         `json:"profile_sha256"`
	Functions     []functionSpec `json:"functions"`
}

type point [2]int
type blockSpec struct {
	Start      point `json:"start"`
	End        point `json:"end"`
	Statements int   `json:"statements"`
}

type functionSpec struct {
	Source       string      `json:"source"`
	SourceSHA256 string      `json:"source_sha256"`
	ProfileFile  string      `json:"profile_file"`
	Name         string      `json:"name"`
	Span         [4]int      `json:"span"`
	Blocks       []blockSpec `json:"blocks"`
}

type functionResult struct {
	Source             string      `json:"source"`
	SourceSHA256       string      `json:"source_sha256"`
	ProfileFile        string      `json:"profile_file"`
	Name               string      `json:"name"`
	Span               [4]int      `json:"span"`
	Status             string      `json:"status"`
	ExpectedStatements int         `json:"expected_statements"`
	ObservedStatements *counts     `json:"observed_statements"`
	Statements         *counts     `json:"statements"`
	MissingBlocks      []blockSpec `json:"missing_blocks"`
}

type functionReport struct {
	Scope               string           `json:"scope"`
	ManifestSHA256      string           `json:"manifest_sha256"`
	ProfileStatus       string           `json:"profile_status"`
	ProfileSHA256       string           `json:"profile_sha256,omitempty"`
	ProfileMode         string           `json:"profile_mode,omitempty"`
	Functions           []functionResult `json:"functions"`
	ExpectedStatements  int              `json:"expected_statements"`
	ObservedStatements  counts           `json:"observed_statements"`
	AggregateStatements *counts          `json:"aggregate_statements"`
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

func digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

func before(a, b point) bool { return a[0] < b[0] || a[0] == b[0] && a[1] < b[1] }

func within(start, end, outerStart, outerEnd point) bool {
	return !before(start, outerStart) && !before(outerEnd, end) && before(start, end)
}

func spanPoints(span [4]int) (point, point) {
	return point{span[0], span[1]}, point{span[2], span[3]}
}

func exactGoPath(name string) bool {
	return name != "" && !path.IsAbs(name) && path.Clean(name) == name &&
		module.CheckFilePath(name) == nil && strings.HasSuffix(name, ".go") &&
		!strings.Contains(name, "...") && !strings.ContainsAny(name, `\*?[]`)
}

func readFunctionSource(root, name string) ([]byte, error) {
	if !exactGoPath(name) {
		return nil, fmt.Errorf("expected a relative Go source path: %q", name)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("source outside source root: %q", name)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("source is not a regular file: %q", name)
	}
	return os.ReadFile(resolved)
}

func readFunctionManifest(manifestPath, sourceRoot string) (functionManifest, string, error) {
	var manifest functionManifest
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return manifest, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&manifest); err != nil {
		return manifest, "", err
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return manifest, "", fmt.Errorf("expected one function manifest JSON object")
	}
	if !validDigest(manifest.ProfileSHA256) || len(manifest.Functions) == 0 {
		return manifest, "", fmt.Errorf("expected profile SHA-256 and nonempty function list")
	}
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return manifest, "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return manifest, "", err
	}
	type fileBinding struct{ source, digest string }
	files := map[string]fileBinding{}
	sourceProfiles := map[string]string{}
	seenDecl := map[string]bool{}
	seenBlocks := map[string]map[blockSpec]bool{}
	for _, fn := range manifest.Functions {
		if !validDigest(fn.SourceSHA256) || !exactGoPath(fn.ProfileFile) ||
			(fn.ProfileFile != fn.Source && !strings.HasSuffix(fn.ProfileFile, "/"+fn.Source)) || len(fn.Blocks) == 0 {
			return manifest, "", fmt.Errorf("incomplete source/block binding for %q", fn.Name)
		}
		binding := fileBinding{fn.Source, fn.SourceSHA256}
		if old, ok := files[fn.ProfileFile]; ok && old != binding {
			return manifest, "", fmt.Errorf("inconsistent source for %q", fn.ProfileFile)
		}
		files[fn.ProfileFile] = binding
		if old, ok := sourceProfiles[fn.Source]; ok && old != fn.ProfileFile {
			return manifest, "", fmt.Errorf("multiple profile filenames for %q", fn.Source)
		}
		sourceProfiles[fn.Source] = fn.ProfileFile
		raw, err := readFunctionSource(root, fn.Source)
		if err != nil {
			return manifest, "", err
		}
		if digest(raw) != fn.SourceSHA256 {
			return manifest, "", fmt.Errorf("source digest mismatch: %q", fn.Source)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, fn.Source, raw, 0)
		if err != nil {
			return manifest, "", err
		}
		matched := false
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Name.Name != fn.Name {
				continue
			}
			s, en := fset.PositionFor(fd.Pos(), false), fset.PositionFor(fd.End(), false)
			if fn.Span == [4]int{s.Line, s.Column, en.Line, en.Column} {
				matched = true
				break
			}
		}
		declKey := fmt.Sprintf("%s:%v", fn.ProfileFile, fn.Span)
		if !matched || seenDecl[declKey] {
			return manifest, "", fmt.Errorf("missing or duplicate exact function declaration: %s %q", fn.ProfileFile, fn.Name)
		}
		seenDecl[declKey] = true
		start, end := spanPoints(fn.Span)
		if seenBlocks[fn.ProfileFile] == nil {
			seenBlocks[fn.ProfileFile] = map[blockSpec]bool{}
		}
		for _, block := range fn.Blocks {
			coord := blockSpec{Start: block.Start, End: block.End}
			if block.Statements < 0 || block.Start[0] < 1 || block.Start[1] < 1 || block.End[0] < 1 || block.End[1] < 1 ||
				!within(block.Start, block.End, start, end) || seenBlocks[fn.ProfileFile][coord] {
				return manifest, "", fmt.Errorf("invalid or duplicate expected block for %q", fn.Name)
			}
			for prior := range seenBlocks[fn.ProfileFile] {
				if before(coord.Start, prior.End) && before(prior.Start, coord.End) {
					return manifest, "", fmt.Errorf("overlapping expected blocks for %q", fn.Name)
				}
			}
			seenBlocks[fn.ProfileFile][coord] = true
		}
	}
	return manifest, digest(data), nil
}

func aggregateFunctions(profilePath, manifestPath, sourceRoot string) (functionReport, error) {
	manifest, manifestSHA, err := readFunctionManifest(manifestPath, sourceRoot)
	if err != nil {
		return functionReport{}, err
	}
	result := functionReport{Scope: "explicit source-bound function blocks only; caller establishes provenance and census scope; not a qualification gate", ManifestSHA256: manifestSHA, ProfileStatus: "not_supplied"}
	var profiles []*cover.Profile
	if profilePath != "" {
		raw, err := os.ReadFile(profilePath)
		if os.IsNotExist(err) {
			result.ProfileStatus = "not_found"
		} else if err != nil {
			return functionReport{}, err
		} else {
			if digest(raw) != manifest.ProfileSHA256 {
				return functionReport{}, fmt.Errorf("profile digest mismatch")
			}
			header, _, _ := bytes.Cut(raw, []byte{'\n'})
			switch string(header) {
			case "mode: set", "mode: count", "mode: atomic":
				result.ProfileMode = strings.TrimPrefix(string(header), "mode: ")
			default:
				return functionReport{}, fmt.Errorf("expected a Go coverage profile mode header")
			}
			profiles, err = parseCoverageProfiles(raw)
			if err != nil {
				return functionReport{}, err
			}
			result.ProfileStatus, result.ProfileSHA256 = "present", digest(raw)
		}
	}
	byFile := map[string][]cover.ProfileBlock{}
	for _, p := range profiles {
		byFile[p.FileName] = p.Blocks
	}
	complete := result.ProfileStatus == "present"
	for _, fn := range manifest.Functions {
		row := functionResult{Source: fn.Source, SourceSHA256: fn.SourceSHA256, ProfileFile: fn.ProfileFile, Name: fn.Name, Span: fn.Span, Status: "profile_absent", MissingBlocks: []blockSpec{}}
		expected := map[blockSpec]blockSpec{}
		for _, block := range fn.Blocks {
			row.ExpectedStatements += block.Statements
			expected[blockSpec{Start: block.Start, End: block.End}] = block
		}
		start, end := spanPoints(fn.Span)
		actual := map[blockSpec]cover.ProfileBlock{}
		for _, block := range byFile[fn.ProfileFile] {
			coord := blockSpec{Start: point{block.StartLine, block.StartCol}, End: point{block.EndLine, block.EndCol}}
			if !before(coord.Start, end) || !before(start, coord.End) {
				continue
			}
			want, ok := expected[coord]
			if !ok || want.Statements != block.NumStmt {
				return functionReport{}, fmt.Errorf("inconsistent compiler block for %q", fn.Name)
			}
			actual[coord] = block
		}
		observed := counts{}
		for _, block := range fn.Blocks {
			got, ok := actual[blockSpec{Start: block.Start, End: block.End}]
			if !ok {
				row.MissingBlocks = append(row.MissingBlocks, block)
				continue
			}
			observed.Total += got.NumStmt
			if got.Count > 0 {
				observed.Covered += got.NumStmt
			}
		}
		if result.ProfileStatus == "present" {
			row.Status = "blocks_absent"
			if len(actual) > 0 {
				row.Status = "partial"
				row.ObservedStatements = &observed
			}
			if len(row.MissingBlocks) == 0 {
				row.Status = "measured"
				row.Statements = &observed
			}
		}
		if row.Statements == nil {
			complete = false
		}
		result.ExpectedStatements += row.ExpectedStatements
		result.ObservedStatements.Total += observed.Total
		result.ObservedStatements.Covered += observed.Covered
		result.Functions = append(result.Functions, row)
	}
	if complete {
		result.AggregateStatements = &result.ObservedStatements
	}
	return result, nil
}
