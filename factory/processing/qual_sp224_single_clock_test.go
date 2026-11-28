package processing

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// SP2-24, structural guard over the product source (every non-test Go file of
// this repository). It fails when a later change gives a DRWA time consumer
// another clock or another way to obtain its time source:
//
//  1. only the clock and the native hook implement the time-source method;
//  2. only the native hook creates a clock and begins a context;
//  3. outside process/drwa and the hook, the time-source type is named in one
//     file: the function that returns the processing hook;
//  4. every production call that hands a time source to a DRWA constructor
//     passes the value that function returned, unchanged;
//  5. DRWA code reads no other time: no wall clock, no header or hook
//     timestamp accessor, no round handler, no notifier epoch.
func TestQualSP224OneClockAndOneTimeSourceInProductCode(t *testing.T) {
	root := filepath.Join("..", "..")
	files := token.NewFileSet()
	parsed := make(map[string]*ast.File)
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(files, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return parseErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		parsed[filepath.ToSlash(relative)] = file
		return nil
	}))
	require.Greater(t, len(parsed), 1000, "the whole product tree was read")

	const (
		clockFile   = "process/drwa/headertime/evaluatedHeaderTime.go"
		hookFile    = "process/smartContract/hooks/evaluatedHeaderTime.go"
		aliasFile   = "process/drwa/evaluatedHeaderTime.go"
		sourceFile  = "factory/processing/drwaHeaderTime.go"
		sourceMaker = "drwaHeaderTimeSource"
	)
	name := func(expr ast.Expr) string {
		switch e := expr.(type) {
		case *ast.Ident:
			return e.Name
		case *ast.SelectorExpr:
			return e.Sel.Name
		}
		return ""
	}

	// 1. implementers of the time-source method
	var implementers []string
	for path, file := range parsed {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || function.Name.Name != "EvaluatedHeaderTimeContext" {
				continue
			}
			receiver := function.Recv.List[0].Type
			if star, pointer := receiver.(*ast.StarExpr); pointer {
				receiver = star.X
			}
			implementers = append(implementers, path+":"+name(receiver))
		}
	}
	sort.Strings(implementers)
	require.Equal(t, []string{clockFile + ":EvaluatedHeaderTime", hookFile + ":BlockChainHookImpl"}, implementers)

	// 2. creation of a clock and of a context; 3. naming of the source type;
	// 5. other time reads in DRWA code
	creators, beginners, namers, makerCalls := map[string]bool{}, map[string]bool{}, map[string]bool{}, 0
	forbidden := map[string]bool{"Now": true, "Since": true, "Until": true, "GetTimeStamp": true, "GetTimestampMs": true, "CurrentTimeStamp": true,
		"CurrentTimeStampMs": true, "LastTimeStamp": true, "CurrentRound": true, "LastRound": true, "RoundTimeStamp": true, "TimeStamp": true,
		"CurrentEpoch": true, "LastEpoch": true, "GetCurrentEpoch": true, "GetHeaderTimestamps": true, "PrepareTimestampBasedOnHeaderData": true}
	var otherClocks []string
	for path, file := range parsed {
		drwaCode := strings.HasPrefix(path, "process/drwa/") || (strings.HasPrefix(path, "factory/processing/drwa") && strings.HasSuffix(path, ".go"))
		if drwaCode {
			for _, imported := range file.Imports {
				if imported.Path.Value == `"time"` {
					otherClocks = append(otherClocks, path+": imports time")
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.CallExpr:
				switch name(n.Fun) {
				case "NewEvaluatedHeaderTime":
					creators[path] = true
				case "BeginBound":
					beginners[path] = true
				case sourceMaker:
					makerCalls++
				}
				if drwaCode && path != clockFile && forbidden[name(n.Fun)] {
					otherClocks = append(otherClocks, path+": calls "+name(n.Fun))
				}
			case *ast.SelectorExpr:
				if n.Sel.Name == "HeaderTimeSource" && !strings.HasPrefix(path, "process/drwa/") && path != hookFile {
					namers[path] = true
				}
			}
			return true
		})
	}
	require.Equal(t, map[string]bool{aliasFile: true, hookFile: true}, creators, "who creates a clock")
	require.Equal(t, map[string]bool{hookFile: true}, beginners, "who begins a context")
	require.Equal(t, map[string]bool{sourceFile: true}, namers, "who names the time-source type outside the DRWA package")
	require.Empty(t, otherClocks)
	require.NotZero(t, makerCalls)

	// The alias in process/drwa only forwards; nothing in product code calls it.
	for path, file := range parsed {
		if path == hookFile || path == aliasFile {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			require.False(t, ok && name(call.Fun) == "NewEvaluatedHeaderTime", path)
			return true
		})
	}

	// 4. hand-over of a source to a DRWA constructor from outside the package
	sourceArgument := map[string]int{"BindNative": 1, "WithRegistrationAdmission": 0, "WithBootstrapCancellation": 0}
	handovers := 0
	for path, file := range parsed {
		if strings.HasPrefix(path, "process/drwa/") {
			continue
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			made := map[string]bool{}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				assignment, ok := node.(*ast.AssignStmt)
				if !ok || len(assignment.Rhs) != 1 || len(assignment.Lhs) == 0 {
					return true
				}
				if call, isCall := assignment.Rhs[0].(*ast.CallExpr); isCall && name(call.Fun) == sourceMaker {
					made[name(assignment.Lhs[0])] = true
				}
				return true
			})
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, isSelector := call.Fun.(*ast.SelectorExpr)
				if !isSelector {
					return true
				}
				index, consumer := sourceArgument[selector.Sel.Name]
				if !consumer {
					return true
				}
				handovers++
				require.Greater(t, len(call.Args), index, "%s: %s", path, selector.Sel.Name)
				argument, isIdent := call.Args[index].(*ast.Ident)
				require.True(t, isIdent && made[argument.Name], "%s: %s must receive the value returned by %s", path, selector.Sel.Name, sourceMaker)
				return true
			})
		}
	}
	require.Equal(t, 1, handovers, "today one production path hands a time source to a DRWA consumer; a new one must be added here on purpose")
}
