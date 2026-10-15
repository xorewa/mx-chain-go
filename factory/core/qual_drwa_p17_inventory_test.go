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
	"strconv"
	"strings"
	"testing"

	nativeCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process/smartContract/builtInFunctions"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	nativeBuiltins "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// T10 / Part A 5.5 and Plan P17 L576: direct entry inventory only. This
// qualifier permits no token effect. It reuses T09's real candidate loaders
// and constructors, with the same explicit account/guardian doubles.
type qualP17Row struct {
	Revision    string `json:"repo_revision"`
	File        string `json:"source_file"`
	Hash        string `json:"source_sha256"`
	Line        int    `json:"source_line"`
	Symbol      string `json:"dispatch_or_registration_symbol"`
	Expression  string `json:"dispatch_expression"`
	Operation   string `json:"operation_name"`
	Layer       string `json:"layer"`
	Class       string `json:"normalized_class"`
	Disposition string `json:"DRWA_disposition"`
	Test        string `json:"test_id"`
}

func qualP17Rows(t *testing.T) []qualP17Row {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testscommon", "testdata", "drwa", "t10", "inventory_01.json"))
	require.NoError(t, err)
	var inventory struct {
		Rows []qualP17Row `json:"rows"`
	}
	require.NoError(t, json.Unmarshal(raw, &inventory))
	require.NoError(t, qualP17Validate(inventory.Rows))
	return inventory.Rows
}

func qualP17Validate(rows []qualP17Row) error {
	if len(rows) == 0 {
		return fmt.Errorf("empty inventory")
	}
	seen := make(map[string]bool)
	for _, r := range rows {
		key := r.Layer + "/" + r.Operation
		if seen[key] {
			return fmt.Errorf("duplicate entry %s", key)
		}
		seen[key] = true
		if r.Layer != "builtin_factory" && r.Layer != "system_sc_dispatch" {
			return fmt.Errorf("unclassified layer %s", r.Layer)
		}
		switch r.Class {
		case "GATE", "PROTECTED_ADMIN", "DENY", "READ_ONLY", "OUT_OF_SCOPE":
		default:
			return fmt.Errorf("unclassified operation %s", key)
		}
		if len(r.Revision) != 40 || len(r.Hash) != 64 || r.Line < 1 || r.File == "" || r.Symbol == "" || r.Expression == "" || r.Operation == "" || r.Disposition == "" || r.Test == "" {
			return fmt.Errorf("incomplete entry %s", key)
		}
	}
	return nil
}

// Go's standard source parser inspects dispatch syntax, not token arguments.
// Unknown expressions are retained verbatim and therefore fail comparison.
func qualP17Expr(x ast.Expr) string {
	switch n := x.(type) {
	case *ast.BasicLit:
		return n.Value
	case *ast.Ident:
		return n.Name
	case *ast.SelectorExpr:
		return qualP17Expr(n.X) + "." + n.Sel.Name
	default:
		return fmt.Sprintf("UNCLASSIFIED_%T", x)
	}
}

func qualP17Dispatch(raw []byte) (map[string]int, error) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, "esdt.go", raw, 0)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]int)
	for _, decl := range f.Decls {
		fn, isFn := decl.(*ast.FuncDecl)
		if !isFn || fn.Name.Name != "Execute" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		star, isStar := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !isStar || qualP17Expr(star.X) != "esdt" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.SwitchStmt:
				if n.Tag == nil || qualP17Expr(n.Tag) != "args.Function" {
					break
				}
				for _, stmt := range n.Body.List {
					for _, expr := range stmt.(*ast.CaseClause).List {
						entries[qualP17Expr(expr)] = fs.Position(expr.Pos()).Line
					}
				}
			case *ast.IfStmt:
				b, isBinary := n.Cond.(*ast.BinaryExpr)
				if !isBinary || b.Op != token.EQL {
					break
				}
				if qualP17Expr(b.X) == "args.Function" {
					entries[qualP17Expr(b.Y)] = fs.Position(b.Y.Pos()).Line
				}
				if qualP17Expr(b.Y) == "args.Function" {
					entries[qualP17Expr(b.X)] = fs.Position(b.X.Pos()).Line
				}
			}
			return true
		})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("missing ESDT dispatcher")
	}
	return entries, nil
}

func qualP17Registrations(raw []byte) (map[string]int, error) {
	fs := token.NewFileSet()
	f, err := parser.ParseFile(fs, "creator.go", raw, 0)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]int)
	ast.Inspect(f, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall || qualP17Expr(call.Fun) != "b.builtInFunctions.Add" || len(call.Args) != 2 {
			return true
		}
		entries[qualP17Expr(call.Args[0])] = fs.Position(call.Pos()).Line
		return true
	})
	if len(entries) == 0 {
		return nil, fmt.Errorf("missing built-in registrations")
	}
	return entries, nil
}

func qualP17Compare(rows []qualP17Row, layer string, actual map[string]int) error {
	expected := make(map[string]int)
	for _, r := range rows {
		if r.Layer == layer {
			expected[r.Expression] = r.Line
		}
	}
	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf("%s source entry set or location differs: expected %v, actual %v", layer, expected, actual)
	}
	return nil
}

func qualP17SourceHash(t *testing.T, rows []qualP17Row, layer string, raw []byte) {
	t.Helper()
	sum := sha256.Sum256(raw)
	for _, r := range rows {
		if r.Layer == layer {
			require.Equal(t, r.Hash, hex.EncodeToString(sum[:]), "source change requires renewed inventory review")
		}
	}
}

func TestQualDRWAP17SystemDispatchInventory(t *testing.T) {
	rows := qualP17Rows(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "vm", "systemSmartContracts", "esdt.go"))
	require.NoError(t, err)
	qualP17SourceHash(t, rows, "system_sc_dispatch", raw)
	actual, err := qualP17Dispatch(raw)
	require.NoError(t, err)
	require.NoError(t, qualP17Compare(rows, "system_sc_dispatch", actual))
	// The native wire name differs from its implementation's method name.
	require.Contains(t, actual, strconv.Quote("issueNonFungible"))
	require.NotContains(t, actual, strconv.Quote("registerNonFungible"))
	require.Contains(t, actual, "core.SCDeployInitFunctionName")
	require.Contains(t, actual, "core.BuiltInFunctionESDTBurn")
}

func TestQualDRWAP17LoadedBuiltinInventory(t *testing.T) {
	rows := qualP17Rows(t)
	// Resolve the compiled dependency's source, rather than a workstation cache
	// spelling or a fixture copy. No evidence/ or qualification/ input is read.
	pc := reflect.ValueOf(nativeBuiltins.NewBuiltInFunctionsCreator).Pointer()
	source, _ := runtime.FuncForPC(pc).FileLine(pc)
	raw, err := os.ReadFile(source)
	require.NoError(t, err)
	qualP17SourceHash(t, rows, "builtin_factory", raw)
	actual, err := qualP17Registrations(raw)
	require.NoError(t, err)
	require.NoError(t, qualP17Compare(rows, "builtin_factory", actual))
	expected := make(map[string]bool)
	for _, r := range rows {
		if r.Layer == "builtin_factory" {
			expected[r.Operation] = true
		}
	}
	for _, shard := range []uint32{0, 1, 2, nativeCore.MetachainShardId} {
		for _, epoch := range []uint32{0, 1, 3} { // Existing T09 experimental boundaries.
			t.Run(fmt.Sprintf("shard_%d/epoch_%d", shard, epoch), func(t *testing.T) {
				args, _, _, _ := qualDRWACandidateBuiltInArgs(t, shard)
				factory, err := builtInFunctions.CreateBuiltInFunctionsFactory(args)
				require.NoError(t, err)
				args.EpochNotifier.(interface{ CheckEpoch(data.HeaderHandler) }).CheckEpoch(&block.Header{Epoch: epoch, Round: 440})
				container := factory.BuiltInFunctionContainer()
				keys := make(map[string]bool)
				for key := range container.Keys() {
					keys[key] = true
					function, err := container.Get(key)
					require.NoError(t, err)
					require.False(t, reflect.ValueOf(function).IsNil())
				}
				require.Equal(t, expected, keys, "native registration set; activation is distinct")
				function, err := container.Get(nativeCore.ESDTSetTokenType)
				require.NoError(t, err)
				require.Equal(t, epoch >= 1, function.IsActive(), "existing candidate DynamicESDTEnableEpoch=1")
			})
		}
	}
}

func TestQualDRWAP17InventoryRejectsDrift(t *testing.T) {
	rows := qualP17Rows(t)
	for _, fault := range []string{"empty", "duplicate", "class", "layer", "missing_symbol"} {
		t.Run(fault, func(t *testing.T) {
			copyRows := append([]qualP17Row(nil), rows...)
			switch fault {
			case "empty":
				copyRows = nil
			case "duplicate":
				copyRows = append(copyRows, copyRows[0])
			case "class":
				copyRows[0].Class = ""
			case "layer":
				copyRows[0].Layer = ""
			case "missing_symbol":
				copyRows[0].Symbol = ""
			}
			require.Error(t, qualP17Validate(copyRows))
		})
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "vm", "systemSmartContracts", "esdt.go"))
	require.NoError(t, err)
	for _, fault := range []string{"addition", "removal", "rename", "move"} {
		t.Run("source_"+fault, func(t *testing.T) {
			mutated := string(raw)
			switch fault {
			case "addition":
				mutated = strings.Replace(mutated, "switch args.Function {", "switch args.Function {\ncase \"issue__P17_UNCLASSIFIED\":\nreturn e.issue(args)", 1)
			case "removal":
				mutated = strings.Replace(mutated, "case \"issue\":\n\t\treturn e.issue(args)\n", "", 1)
			case "rename":
				mutated = strings.Replace(mutated, "case \"issue\":", "case \"issue__P17_UNCLASSIFIED\":", 1)
			case "move":
				mutated = "\n" + mutated
			}
			actual, err := qualP17Dispatch([]byte(mutated))
			require.NoError(t, err, "syntax rejection is not an inventory drift result")
			require.Error(t, qualP17Compare(rows, "system_sc_dispatch", actual))
		})
	}
}

// Source annotations only: these assertions do not execute or admit a native
// effect. Part A 5.5 L5155-5157 and L5162 specify these exclusions/exceptions;
// a valid enum alone does not make a policy annotation source-supported.
func TestQualDRWAP17SourcePolicyFloors(t *testing.T) {
	rows := qualP17Rows(t)
	for _, layer := range []string{"builtin_factory", "system_sc_dispatch"} {
		t.Run("global_burn/"+layer, func(t *testing.T) {
			for _, row := range rows {
				if row.Layer == layer && row.Operation == nativeCore.BuiltInFunctionESDTBurn {
					require.Equal(t, "DENY", row.Class)
					require.Contains(t, row.Disposition, "L5147")
					require.NotContains(t, row.Disposition, "crawler")
					return
				}
			}
			t.Fatal("missing global burn inventory row")
		})
	}
	byName := make(map[string]qualP17Row)
	for _, row := range rows {
		if row.Layer == "builtin_factory" {
			byName[row.Operation] = row
		}
	}
	for _, name := range []string{
		nativeCore.BuiltInFunctionESDTPause, nativeCore.BuiltInFunctionESDTUnPause,
		nativeCore.BuiltInFunctionESDTFreeze, nativeCore.BuiltInFunctionESDTUnFreeze,
		nativeCore.BuiltInFunctionESDTWipe,
		nativeCore.BuiltInFunctionESDTSetLimitedTransfer, nativeCore.BuiltInFunctionESDTUnSetLimitedTransfer,
		vmcommon.BuiltInFunctionESDTSetBurnRoleForAll,
		vmcommon.BuiltInFunctionESDTTransferRoleDeleteAddress, vmcommon.BuiltInFunctionESDTTransferRoleAddAddress,
	} {
		t.Run(name, func(t *testing.T) {
			row, exists := byName[name]
			require.True(t, exists)
			require.Equal(t, "DENY", row.Class, "v1 excludes this native policy/control surface")
		})
	}
	for _, name := range []string{vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll, nativeCore.ESDTSetTokenType} {
		t.Run(name, func(t *testing.T) {
			row, exists := byName[name]
			require.True(t, exists)
			require.Equal(t, "PROTECTED_ADMIN", row.Class)
			require.Contains(t, row.Disposition, "BootstrapDeny", "only the exact owning bootstrap exception is annotated")
		})
	}
}
