package drwa

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// SP2-20, duty G32.H-reset-refill (tracker row 53 Notes): every DRWA path of
// this row that uses the native compiled-code functions must treat their
// reset/refill failure as deny. The protected-state, storage, migration and
// recovery code of this row uses none of them, so no DRWA decision of this
// row can read stale compiled bytes. This test keeps that true: it fails as
// soon as one of these packages calls an affected function, and the caller
// then owes the deny handling and its test.
func TestQualSP220ProtectedStatePathsDoNotReadCompiledCode(t *testing.T) {
	affected := map[string]struct{}{"GetCompiledCode": {}, "ClearCompiledCodes": {}, "SaveCompiledCode": {}, "DeleteCompiledCode": {}}
	root := filepath.Join("..", "..")
	files := 0
	for _, directory := range []string{"process/drwa", "state", "state/syncer", "state/trackableDataTrie", "update/genesis"} {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(directory)))
		require.NoError(t, err)
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(root, filepath.FromSlash(directory), name)
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			require.NoError(t, err)
			files++
			ast.Inspect(parsed, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.SelectorExpr:
					_, used := affected[n.Sel.Name]
					require.False(t, used, "%s uses %s", path, n.Sel.Name)
				case *ast.Ident:
					_, used := affected[n.Name]
					require.False(t, used, "%s names %s", path, n.Name)
				}
				return true
			})
		}
	}
	require.Greater(t, files, 50, "the scan read the production files")
}
