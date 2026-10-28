// DRWA CI coverage policy. Branch coverage is enforced by review.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/cover"
)

type counts struct {
	Covered int `json:"covered"`
	Total   int `json:"total"`
}

func (c counts) sufficient() bool { return c.Total == 0 || c.Covered*100 >= c.Total*90 }

type function struct {
	Name       string
	Start, End token.Position
	Blocks     []cover.ProfileBlock
}
type packageResult struct {
	Package    string   `json:"package"`
	Statements counts   `json:"statements"`
	Functions  counts   `json:"functions"`
	Missing    []string `json:"missing_profiles,omitempty"`
}
type changedFunction struct {
	File       string `json:"file"`
	Name       string `json:"name"`
	Policy     string `json:"policy"`
	Statements counts `json:"statements"`
	Entered    bool   `json:"entered"`
}
type exclusion struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
	Side   string `json:"side"`
}
type report struct {
	Base               string            `json:"base"`
	Upstream           string            `json:"ownership_upstream"`
	Packages           []packageResult   `json:"packages"`
	DiffStatements     counts            `json:"diff_statements"`
	UpstreamStatements counts            `json:"upstream_changed_block_statements"`
	DiffFunctions      counts            `json:"diff_functions"`
	Changed            []changedFunction `json:"changed_functions"`
	Exclusions         []exclusion       `json:"excluded_lines"`
	Uncovered          []exclusion       `json:"uncovered_drwa_lines"`
	NonInstrumented    []exclusion       `json:"non_instrumented_lines"`
	Errors             []string          `json:"errors"`
	Policy             string            `json:"policy"`
}

func command(args ...string) ([]byte, error) {
	c := exec.Command(args[0], args[1:]...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	b, e := c.Output()
	if e != nil {
		return nil, fmt.Errorf("%v: %w: %s", args, e, stderr.String())
	}
	return b, nil
}
func functions(path string, src []byte) ([]function, error) {
	fs := token.NewFileSet()
	f, e := parser.ParseFile(fs, path, src, 0)
	if e != nil {
		return nil, e
	}
	var result []function
	for _, d := range f.Decls {
		fn, yes := d.(*ast.FuncDecl)
		if !yes || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil {
			var b bytes.Buffer
			if e = printer.Fprint(&b, fs, fn.Recv.List[0].Type); e != nil {
				return nil, e
			}
			name = b.String() + "." + name
		}
		result = append(result, function{Name: name, Start: fs.Position(fn.Pos()), End: fs.Position(fn.End())})
	}
	return result, nil
}
func overlaps(b cover.ProfileBlock, f function) bool {
	return !(b.StartLine > f.End.Line || b.StartLine == f.End.Line && b.StartCol >= f.End.Column ||
		b.EndLine < f.Start.Line || b.EndLine == f.Start.Line && b.EndCol <= f.Start.Column)
}
func sum(blocks []cover.ProfileBlock) counts {
	c := counts{}
	for _, b := range blocks {
		c.Total += b.NumStmt
		if b.Count > 0 {
			c.Covered += b.NumStmt
		}
	}
	return c
}
func entered(blocks []cover.ProfileBlock) bool {
	// The first instrumented block is the entry block, including zero-statement bodies.
	return len(blocks) > 0 && blocks[0].Count > 0
}
func selectedBlocks(f function, existing bool, lines map[int]bool) []cover.ProfileBlock {
	if !existing {
		return f.Blocks
	}
	var out []cover.ProfileBlock
	for _, b := range f.Blocks {
		if touches(lines, b.StartLine, b.EndLine) {
			out = append(out, b)
		}
	}
	return out
}
func touches(lines map[int]bool, start, end int) bool {
	for n := range lines {
		if n >= start && n <= end {
			return true
		}
	}
	return false
}

var hunk = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@`)

func changedLines(base, file string) (map[int]bool, error) {
	b, e := command("git", "diff", "--no-ext-diff", "--no-renames", "--unified=0", base, "HEAD", "--", file)
	if e != nil {
		return nil, e
	}
	m := map[int]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		a := hunk.FindStringSubmatch(line)
		if a == nil {
			continue
		}
		start, _ := strconv.Atoi(a[1])
		size := 1
		if a[2] != "" {
			size, _ = strconv.Atoi(a[2])
		}
		// A deletion-only edit still selects an enclosing surviving function/block.
		if size == 0 {
			if start > 0 {
				m[start] = true
			}
			m[start+1] = true
			continue
		}
		for n := start; n < start+size; n++ {
			m[n] = true
		}
	}
	// Deletion anchors are selectors, never invented current-source line numbers.
	if src, err := os.ReadFile(file); err == nil {
		n := len(bytes.Split(bytes.TrimSuffix(src, []byte("\n")), []byte("\n")))
		for line := range m {
			if line < 1 || line > n {
				delete(m, line)
			}
		}
	} else if os.IsNotExist(err) {
		m = map[int]bool{}
	} else {
		return nil, err
	}
	return m, nil
}
func oldFunctions(base, file string) (map[string]bool, error) {
	b, e := command("git", "ls-tree", "--name-only", base, "--", file)
	if e != nil {
		return nil, e
	}
	m := map[string]bool{}
	if len(bytes.TrimSpace(b)) == 0 {
		return m, nil
	}
	b, e = command("git", "show", base+":"+file)
	if e != nil {
		return nil, e
	}
	fs, e := functions(file, b)
	if e != nil {
		return nil, e
	}
	for _, f := range fs {
		m[f.Name] = true
	}
	return m, nil
}
func analyze(base, upstream, profile, packages string) (report, error) {
	r := report{Base: base, Policy: "new named functions: each whole function >=90% statements; existing named functions: changed blocks; combined selected statements >=90%; changed named function entries >=90%; branch coverage by review"}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(base) {
		return r, fmt.Errorf("base must be a full commit SHA")
	}
	if _, e := command("git", "cat-file", "-e", base+"^{commit}"); e != nil {
		return r, e
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(upstream) {
		return r, fmt.Errorf("ownership upstream must be a full commit SHA")
	}
	if _, e := command("git", "merge-base", "--is-ancestor", upstream, "HEAD"); e != nil {
		return r, e
	}
	r.Upstream = upstream
	raw, e := os.ReadFile(profile)
	if e != nil {
		return r, e
	}
	if !bytes.HasPrefix(raw, []byte("mode: atomic\n")) {
		return r, fmt.Errorf("profile must use atomic mode")
	}
	profiles, e := cover.ParseProfilesFromReader(bytes.NewReader(raw))
	if e != nil {
		return r, e
	}
	byFile := map[string]*cover.Profile{}
	for _, p := range profiles {
		if p.Mode != "atomic" {
			return r, fmt.Errorf("profile must use atomic mode")
		}
		byFile[p.FileName] = p
	}
	list := []string{"go", "list", "-json"}
	for _, p := range strings.Fields(packages) {
		if !strings.HasPrefix(p, "./") {
			return r, fmt.Errorf("package must start ./")
		}
		list = append(list, p)
	}
	if len(list) == 3 {
		return r, fmt.Errorf("no packages")
	}
	b, e := command(list...)
	if e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	root, e := os.Getwd()
	if e != nil {
		return r, e
	}
	selectedDirs := map[string]bool{}
	compiled := map[string]bool{}
	for {
		var p struct {
			ImportPath, Dir   string
			GoFiles, CgoFiles []string
		}
		e = d.Decode(&p)
		if e == io.EOF {
			break
		}
		if e != nil {
			return r, e
		}
		relDir, e := filepath.Rel(root, p.Dir)
		if e != nil {
			return r, e
		}
		selectedDirs[filepath.ToSlash(relDir)] = true
		pr := packageResult{Package: p.ImportPath}
		for _, name := range append(p.GoFiles, p.CgoFiles...) {
			file := filepath.Join(p.Dir, name)
			rel, e := filepath.Rel(root, file)
			if e != nil {
				return r, e
			}
			if strings.HasPrefix(rel, "..") {
				return r, fmt.Errorf("source outside repository")
			}
			compiled[filepath.ToSlash(rel)] = true
			src, e := os.ReadFile(file)
			if e != nil {
				return r, e
			}
			fs, e := functions(file, src)
			if e != nil {
				return r, e
			}
			prof := byFile[p.ImportPath+"/"+name]
			var blocks []cover.ProfileBlock
			if prof != nil {
				blocks = prof.Blocks
			} else {
				hasBody := len(fs) > 0
				if !hasBody {
					a, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
					if err != nil {
						return r, err
					}
					ast.Inspect(a, func(n ast.Node) bool {
						if _, yes := n.(*ast.FuncLit); yes {
							hasBody = true
						}
						return true
					})
				}
				if hasBody {
					pr.Missing = append(pr.Missing, rel)
					r.Errors = append(r.Errors, "missing profile: "+rel)
				}
			}
			c := sum(blocks)
			pr.Statements.Total += c.Total
			pr.Statements.Covered += c.Covered
			lines, e := changedLines(base, rel)
			if e != nil {
				return r, e
			}
			old, e := oldFunctions(base, rel)
			if e != nil {
				return r, e
			}
			// The v2.1.9 merge introduced upstream functions after the diff base.
			// Those are upstream-owned too; only functions absent from both pins
			// are DRWA-owned. Never infer ownership merely from a new-file diff.
			native, e := oldFunctions(upstream, rel)
			if e != nil {
				return r, e
			}
			for name := range native {
				old[name] = true
			}
			for i := range fs {
				for _, b := range blocks {
					if overlaps(b, fs[i]) {
						fs[i].Blocks = append(fs[i].Blocks, b)
					}
				}
				pr.Functions.Total++
				if entered(fs[i].Blocks) {
					pr.Functions.Covered++
				}
				if !touches(lines, fs[i].Start.Line, fs[i].End.Line) {
					continue
				}
				cf := changedFunction{File: rel, Name: fs[i].Name, Entered: entered(fs[i].Blocks), Policy: "changed_blocks"}
				if !old[fs[i].Name] {
					cf.Policy = "whole_function"
				}
				selected := selectedBlocks(fs[i], old[fs[i].Name], lines)
				cf.Statements = sum(selected)
				if cf.Policy == "changed_blocks" {
					r.UpstreamStatements.Total += cf.Statements.Total
					r.UpstreamStatements.Covered += cf.Statements.Covered
				}
				r.Changed = append(r.Changed, cf)
				r.DiffFunctions.Total++
				if cf.Entered {
					r.DiffFunctions.Covered++
				}
				if cf.Policy == "whole_function" && !cf.Statements.sufficient() {
					r.Errors = append(r.Errors, "new function below 90% statements: "+rel+":"+cf.Name)
				}
			}
			// Count each selected profile block once, including any nested function literals.
			for _, b := range blocks {
				selected := touches(lines, b.StartLine, b.EndLine)
				for _, f := range fs {
					if !old[f.Name] && touches(lines, f.Start.Line, f.End.Line) && overlaps(b, f) {
						selected = true
					}
				}
				if selected {
					r.DiffStatements.Total += b.NumStmt
					if b.Count > 0 {
						r.DiffStatements.Covered += b.NumStmt
					}
				}
			}
			uncovered := map[int]string{}
			for _, f := range fs {
				if !old[f.Name] || touches(lines, f.Start.Line, f.End.Line) {
					for _, b := range f.Blocks {
						if b.Count != 0 {
							continue
						}
						for n := b.StartLine; n <= b.EndLine; n++ {
							if !old[f.Name] || lines[n] {
								uncovered[n] = fmt.Sprintf("profile block %d.%d-%d.%d has counter=0; test-gap cause UNKNOWN", b.StartLine, b.StartCol, b.EndLine, b.EndCol)
							}
						}
					}
					if prof == nil {
						for n := f.Start.Line; n <= f.End.Line; n++ {
							if !old[f.Name] || lines[n] {
								uncovered[n] = "coverage UNKNOWN: no profile emitted for this file"
							}
						}
					}
				}
			}
			for line, reason := range uncovered {
				r.Uncovered = append(r.Uncovered, exclusion{rel, line, reason, "head"})
			}
			for line := range lines {
				inBlock := false
				for _, b := range blocks {
					if line >= b.StartLine && line <= b.EndLine {
						inBlock = true
					}
				}
				if !inBlock {
					reason := "Go emitted no coverage block spanning this line; review required"
					if prof == nil && len(fs) > 0 {
						reason = "missing profile: coverage UNKNOWN; gate rejects"
					}
					r.NonInstrumented = append(r.NonInstrumented, exclusion{rel, line, reason, "head"})
				}
			}
		}
		r.Packages = append(r.Packages, pr)
	}
	// Retain every excluded changed line in this job's selected package directories.
	b, e = command("git", "diff", "--no-ext-diff", "--no-renames", "--name-only", base, "HEAD")
	if e != nil {
		return r, e
	}
	for _, file := range strings.Fields(string(b)) {
		tooling := strings.HasPrefix(file, ".github/coverage/")
		if (!selectedDirs[filepath.ToSlash(filepath.Dir(file))] && !tooling) || compiled[file] {
			continue
		}
		lines, e := changedLines(base, file)
		if e != nil {
			return r, e
		}
		reason := "non-Go source: outside Go statement/function coverage"
		if tooling {
			reason = "CI tooling, outside the DRWA production package set; helper tests run separately"
		} else if strings.HasSuffix(file, "_test.go") {
			reason = "test source: profiles measure production statements, not test statements"
		} else if strings.HasSuffix(file, ".go") {
			reason = "not selected by go list for this OS/architecture/build configuration; review required"
		}
		if _, e = os.Stat(file); os.IsNotExist(e) {
			old, e := command("git", "show", base+":"+file)
			if e != nil {
				return r, e
			}
			for i := range bytes.Split(bytes.TrimSuffix(old, []byte("\n")), []byte("\n")) {
				r.Exclusions = append(r.Exclusions, exclusion{file, i + 1, "deleted file: no executable lines in current source", "base"})
			}
		} else if e != nil {
			return r, e
		}
		for line := range lines {
			r.Exclusions = append(r.Exclusions, exclusion{file, line, reason, "head"})
		}
	}
	if !r.DiffStatements.sufficient() {
		r.Errors = append(r.Errors, "diff statements below 90%")
	}
	if !r.UpstreamStatements.sufficient() {
		r.Errors = append(r.Errors, "upstream changed-block statements below 90%")
	}
	if !r.DiffFunctions.sufficient() {
		r.Errors = append(r.Errors, "diff function entries below 90%")
	}
	for _, list := range [][]exclusion{r.Exclusions, r.NonInstrumented, r.Uncovered} {
		sort.Slice(list, func(i, j int) bool {
			if list[i].File == list[j].File {
				return list[i].Line < list[j].Line
			}
			return list[i].File < list[j].File
		})
	}
	return r, nil
}
func main() {
	base := flag.String("base", "", "full base commit")
	upstream := flag.String("upstream", "5123176d1fa9237e52df2680d4e8bbcdc3ceb11a", "owner-selected v2.1.9 commit for function ownership")
	profile := flag.String("profile", "", "atomic cover profile")
	packages := flag.String("packages", "", "explicit space-separated ./ packages")
	output := flag.String("output", "", "JSON report including per-line exclusions")
	flag.Parse()
	r, e := analyze(*base, *upstream, *profile, *packages)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	if *output == "" {
		fmt.Fprintln(os.Stderr, "output required")
		os.Exit(2)
	}
	if e = os.WriteFile(*output, append(b, '\n'), 0644); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	fmt.Printf("diff statements %d/%d; function entries %d/%d; see %s for exclusions and package totals\n", r.DiffStatements.Covered, r.DiffStatements.Total, r.DiffFunctions.Covered, r.DiffFunctions.Total, *output)
	if len(r.Errors) > 0 {
		for _, e := range r.Errors {
			fmt.Fprintln(os.Stderr, e)
		}
		os.Exit(1)
	}
}
