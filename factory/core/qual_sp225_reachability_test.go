package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// SP2-25, Plan L435, F.5 D17: every production call site that can execute a
// built-in function or write native token state outside one. The classified
// dispatch is BlockChainHookImpl.ProcessBuiltInFunction (admission before the
// first effect) and the metadata save guard. This lexical inventory fails
// when a new call site appears, so a new path cannot bypass classification
// unnoticed. It is a source inventory, not a runtime dominance proof.
func TestQualSP225TokenEffectCallSitesAreClosed(t *testing.T) {
	watched := map[string]bool{
		"ProcessBuiltinFunction":                     true, // a built-in function object, directly
		"ProcessBuiltinFunctionWithESDTTransferGate": true,
		"ProcessBuiltinFunctionWithDRWASupplyGate":   true,
		"ProcessBuiltInFunction":                     true, // the hook dispatch
		"SaveNFTMetaData":                            true, // native storage write outside a built-in
		"SaveNFTMetaDataToSystemAccount":             true,
	}
	expected := map[string][]string{
		// The classified dispatch and its guard.
		"process/smartContract/hooks/blockChainHook.go": {"ProcessBuiltinFunction", "SaveNFTMetaData"},
		// Callers of the classified dispatch: both SC processors (transactions,
		// SCRs, async calls, callbacks, refunds, relayed) and the System-SC context.
		"process/smartContract/process.go":               {"ProcessBuiltInFunction", "SaveNFTMetaDataToSystemAccount"},
		"process/smartContract/processorV2/processV2.go": {"ProcessBuiltInFunction", "SaveNFTMetaDataToSystemAccount"},
		"vm/systemSmartContracts/eei.go":                 {"ProcessBuiltInFunction"},
		// DRWA-owned operations. The identifier probe stops before any effect;
		// the others are regulated routes and are not installed in a dispatcher.
		"process/drwa/nativeClassification.go":  {"ProcessBuiltinFunctionWithESDTTransferGate"},
		"process/drwa/routeAdmission.go":        {"ProcessBuiltinFunctionWithESDTTransferGate"},
		"process/drwa/supplyNativeOperation.go": {"ProcessBuiltinFunctionWithDRWASupplyGate"},
		"process/drwa/burnForAllAbsence.go":     {"ProcessBuiltinFunction"},
	}
	root := filepath.Join("..", "..")
	actual := make(map[string][]string)
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		if entry.IsDir() {
			switch relative {
			case ".git", "testscommon", "integrationTests", "scripts", "docker", "cmd/assessment":
				return filepath.SkipDir
			}
			if strings.HasSuffix(relative, "/mock") || strings.HasSuffix(relative, "/disabled") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(relative, ".go") || strings.HasSuffix(relative, "_test.go") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !strings.Contains(string(raw), "BuiltinFunction") && !strings.Contains(string(raw), "BuiltInFunction") && !strings.Contains(string(raw), "SaveNFTMetaData") {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), relative, raw, 0)
		if parseErr != nil {
			return parseErr
		}
		seen := make(map[string]bool)
		ast.Inspect(file, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			if selector, isSelector := call.Fun.(*ast.SelectorExpr); isSelector && watched[selector.Sel.Name] {
				seen[selector.Sel.Name] = true
			}
			return true
		})
		for name := range seen {
			actual[relative] = append(actual[relative], name)
		}
		sort.Strings(actual[relative])
		return nil
	}))
	require.Equal(t, expected, actual)
}

// In the classified dispatch the admission is the first call after the
// function lookup and precedes account resolution and the native function.
func TestQualSP225HookAdmissionPrecedesNativeEffects(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "process", "smartContract", "hooks", "blockChainHook.go"))
	require.NoError(t, err)
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "blockChainHook.go", raw, 0)
	require.NoError(t, err)
	order := map[string]int{}
	position := 0
	for _, declaration := range file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Name.Name != "ProcessBuiltInFunction" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, isCall := node.(*ast.CallExpr); isCall {
				if selector, isSelector := call.Fun.(*ast.SelectorExpr); isSelector {
					position++
					if _, recorded := order[selector.Sel.Name]; !recorded {
						order[selector.Sel.Name] = position
					}
				}
			}
			return true
		})
	}
	for _, name := range []string{"Get", "admitDRWABuiltIn", "getUserAccounts", "processMaxBuiltInCounters", "JournalLen", "ProcessBuiltinFunction", "SaveAccount"} {
		require.Contains(t, order, name)
	}
	require.Less(t, order["Get"], order["admitDRWABuiltIn"])
	for _, later := range []string{"getUserAccounts", "processMaxBuiltInCounters", "JournalLen", "ProcessBuiltinFunction", "SaveAccount", "RevertToSnapshot"} {
		require.Less(t, order["admitDRWABuiltIn"], order[later], later)
	}
}
