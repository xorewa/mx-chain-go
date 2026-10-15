package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/process/smartContract/builtInFunctions"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// T10 / Part A 5.5, Plan L435/L576. Source positions are lexical, not a
// runtime dominance or authentic-origin proof. No native effect is admitted.
type qualP17Call struct {
	Line       int    `json:"line"`
	Expression string `json:"expression"`
}

type qualP17RouteNode struct {
	Root     string        `json:"root"`
	File     string        `json:"source_file"`
	Hash     string        `json:"source_sha256"`
	Function string        `json:"function"`
	Receiver string        `json:"receiver"`
	Start    int           `json:"start"`
	End      int           `json:"end"`
	BodyHash string        `json:"body_sha256"`
	Calls    []qualP17Call `json:"calls"`
}

type qualP17RouteFixture struct {
	Nodes        []qualP17RouteNode `json:"nodes"`
	SystemRoutes []struct {
		Expression string `json:"dispatch_expression"`
		Handler    string `json:"handler"`
	} `json:"system_routes"`
	Implementations []struct {
		Type     string `json:"type"`
		File     string `json:"source_file"`
		Receiver string `json:"receiver"`
	} `json:"builtin_implementations"`
}

func qualP17Routes(t *testing.T) qualP17RouteFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testscommon", "testdata", "drwa", "t10", "routes_01.json"))
	require.NoError(t, err)
	var fixture qualP17RouteFixture
	require.NoError(t, json.Unmarshal(raw, &fixture))
	require.NotEmpty(t, fixture.Nodes)
	return fixture
}

func qualP17BuiltinSourceDirectory() string {
	pc := reflect.ValueOf(nativeBuiltins.NewBuiltInFunctionsCreator).Pointer()
	source, _ := runtime.FuncForPC(pc).FileLine(pc)
	return filepath.Dir(filepath.Dir(source))
}

func qualP17CheckRouteNode(raw []byte, expected qualP17RouteNode) error {
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected.Hash {
		return fmt.Errorf("source changed: %s", expected.File)
	}
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, expected.File, raw, 0)
	if err != nil {
		return err
	}
	expression := func(n ast.Node) string {
		return string(raw[fs.Position(n.Pos()).Offset:fs.Position(n.End()).Offset])
	}
	for _, declaration := range f.Decls {
		fn, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || fn.Name.Name != expected.Function {
			continue
		}
		receiver := ""
		if fn.Recv != nil {
			receiver = expression(fn.Recv.List[0].Type)
		}
		if receiver != expected.Receiver {
			continue
		}
		start, end := fs.Position(fn.Pos()).Line, fs.Position(fn.End()).Line
		if start != expected.Start || end != expected.End {
			return fmt.Errorf("function moved: %s.%s", receiver, fn.Name.Name)
		}
		lines := strings.SplitAfter(string(raw), "\n")
		body := sha256.Sum256([]byte(strings.Join(lines[start-1:end], "")))
		if hex.EncodeToString(body[:]) != expected.BodyHash {
			return fmt.Errorf("function body differs: %s.%s", receiver, fn.Name.Name)
		}
		calls := make([]qualP17Call, 0)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				calls = append(calls, qualP17Call{fs.Position(call.Pos()).Line, expression(call.Fun)})
			}
			return true
		})
		if !reflect.DeepEqual(expected.Calls, calls) {
			return fmt.Errorf("source call inventory differs: %s.%s", receiver, fn.Name.Name)
		}
		return nil
	}
	return fmt.Errorf("function missing: %s.%s", expected.Receiver, expected.Function)
}

func TestQualDRWAP17RouteSources(t *testing.T) {
	fixture := qualP17Routes(t)
	seen := make(map[string]bool)
	for _, node := range fixture.Nodes {
		key := node.Root + "/" + node.File + "/" + node.Receiver + "." + node.Function
		require.False(t, seen[key], "duplicate route source")
		seen[key] = true
		t.Run(key, func(t *testing.T) {
			root := filepath.Join("..", "..")
			if node.Root == "builtin" {
				root = qualP17BuiltinSourceDirectory()
			} else {
				require.Equal(t, "node", node.Root)
			}
			require.False(t, filepath.IsAbs(node.File))
			require.NotContains(t, filepath.ToSlash(node.File), "..")
			raw, err := os.ReadFile(filepath.Join(root, node.File))
			require.NoError(t, err)
			require.NoError(t, qualP17CheckRouteNode(raw, node))
		})
	}
}

func TestQualDRWAP17RouteImplementations(t *testing.T) {
	fixture := qualP17Routes(t)
	expected := make(map[string]bool)
	for _, impl := range fixture.Implementations {
		require.False(t, expected[impl.Type], "duplicate implementation")
		expected[impl.Type] = true
		found := false
		for _, node := range fixture.Nodes {
			found = found || (node.Root == "builtin" && node.File == impl.File && node.Receiver == impl.Receiver && node.Function == "ProcessBuiltinFunction")
		}
		require.True(t, found, "implementation must have a source-bound entry body")
	}
	for _, shard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
		t.Run(fmt.Sprint(shard), func(t *testing.T) {
			args, _, _, _ := qualDRWACandidateBuiltInArgs(t, shard)
			factory, err := builtInFunctions.CreateBuiltInFunctionsFactory(args)
			require.NoError(t, err)
			actual := make(map[string]bool)
			for key := range factory.BuiltInFunctionContainer().Keys() {
				function, err := factory.BuiltInFunctionContainer().Get(key)
				require.NoError(t, err)
				actual[reflect.TypeOf(function).String()] = true
			}
			require.Equal(t, expected, actual, "42 registrations must reach the inventoried implementation types")
		})
	}
}

func TestQualDRWAP17RouteDispatchTargets(t *testing.T) {
	fixture := qualP17Routes(t)
	expected, actual := make(map[string]string), make(map[string]string)
	for _, row := range fixture.SystemRoutes {
		require.NotContains(t, expected, row.Expression)
		expected[row.Expression] = row.Handler
		found := false
		for _, node := range fixture.Nodes {
			found = found || (node.Root == "node" && node.File == "vm/systemSmartContracts/esdt.go" && node.Receiver == "*esdt" && node.Function == row.Handler)
		}
		require.True(t, found, "dispatch handler must have a source-bound body")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "vm", "systemSmartContracts", "esdt.go"))
	require.NoError(t, err)
	f, err := parser.ParseFile(token.NewFileSet(), "esdt.go", raw, 0)
	require.NoError(t, err)
	for _, declaration := range f.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Execute" {
			continue
		}
		target := func(body ast.Node) string {
			name := ""
			ast.Inspect(body, func(n ast.Node) bool {
				if call, isCall := n.(*ast.CallExpr); isCall {
					text := qualP17Expr(call.Fun)
					if strings.HasPrefix(text, "e.") {
						require.Empty(t, name, "unexpected multi-target dispatch")
						name = strings.TrimPrefix(text, "e.")
					}
				}
				return true
			})
			return name
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.SwitchStmt:
				if qualP17Expr(stmt.Tag) == "args.Function" {
					for _, item := range stmt.Body.List {
						clause := item.(*ast.CaseClause)
						for _, label := range clause.List {
							actual[qualP17Expr(label)] = target(clause)
						}
					}
				}
			case *ast.IfStmt:
				condition, isBinary := stmt.Cond.(*ast.BinaryExpr)
				if isBinary && condition.Op == token.EQL && qualP17Expr(condition.X) == "args.Function" {
					actual[qualP17Expr(condition.Y)] = target(stmt.Body)
				}
			}
			return true
		})
	}
	require.Equal(t, expected, actual)
	entries, err := qualP17Dispatch(raw)
	require.NoError(t, err)
	require.Len(t, expected, len(entries), "all direct inventory entries need route targets")
}
