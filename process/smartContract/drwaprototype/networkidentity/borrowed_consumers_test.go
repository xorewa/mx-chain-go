package networkidentity

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBorrowedHeaderProductionConsumerSetAndLifetimeAreClosed(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", ".."))
	consumers, err := scanBorrowedConsumers(repoRoot)
	require.NoError(t, err)
	require.Equal(t, []string{
		"cmd/drwa-prototype-identity-orchestrate/main.go",
		"cmd/drwa-prototype-identity-rehearse/main.go",
		"factory/processing/prototypeNetworkDomain.go",
	}, consumers, "a new production decode consumer requires a new lifetime/blast-radius ruling")
}

func TestBorrowedHeaderLifetimeCheckerDetectsCopyRetentionAndAsyncMutations(t *testing.T) {
	tests := map[string]string{
		"append copy": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); owned := append([]byte(nil), record.HeaderBytes...); _ = owned }`,
		"make and builtin copy": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); n := len(record.HeaderBytes); owned := make([]byte, n); copy(owned, record.HeaderBytes); _ = owned }`,
		"clone copy": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); owned := bytes.Clone(record.HeaderBytes); _ = owned }`,
		"component retention": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); component.header = record.HeaderBytes }`,
		"async use": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); go func(){ use(record.HeaderBytes) }() }`,
		"wrapper alias copy": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); identity := struct{ headerBytes []byte }{headerBytes: record.HeaderBytes}; alias := identity.headerBytes; owned := append([]byte(nil), alias...); _ = owned }`,
		"transitive retention": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); retain(record.HeaderBytes) }
func retain(header []byte) { component.header = header }`,
		"transitive async use": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); useLater(record.HeaderBytes) }
func useLater(header []byte) { go func(){ use(header) }() }`,
		"callback capture": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); register(func(){ use(record.HeaderBytes) }) }`,
		"cross-file helper boundary": `package p
func f(envelope []byte) { record, _ := networkidentity.Decode(envelope, []byte("c")); helperDefinedElsewhere(record.HeaderBytes) }`,
		"returned alias": `package p
func f(envelope []byte) []byte { record, _ := networkidentity.Decode(envelope, []byte("c")); alias := record.HeaderBytes; return alias }`,
	}
	for name, source := range tests {
		name, source := name, source
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), name+".go", source, 0)
			require.NoError(t, err)
			require.Error(t, validateBorrowedConsumerFunctions(file))
		})
	}
}

func scanBorrowedConsumers(repoRoot string) ([]string, error) {
	consumers := make([]string, 0)
	err := filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(value), "networkidentity.Decode(") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, value, 0)
		if err != nil {
			return err
		}
		if err = validateBorrowedConsumerFunctions(file); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		relative, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		consumers = append(consumers, filepath.ToSlash(relative))
		return nil
	})
	sort.Strings(consumers)
	return consumers, err
}

func validateBorrowedConsumerFunctions(file *ast.File) error {
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		functions[function.Name.Name] = function
	}

	taintedParameters := make(map[string]map[int]bool)
	for {
		changed := false
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			functionChanged, err := validateBorrowedFunction(
				function,
				functions,
				taintedParameters,
			)
			if err != nil {
				return err
			}
			changed = changed || functionChanged
		}
		if !changed {
			return nil
		}
	}
}

func validateBorrowedFunction(
	function *ast.FuncDecl,
	functions map[string]*ast.FuncDecl,
	taintedParameters map[string]map[int]bool,
) (bool, error) {
	taintedNames := make(map[string]bool)
	parameterNames := flattenedParameterNames(function.Type.Params)
	for index := range taintedParameters[function.Name.Name] {
		if index < len(parameterNames) && parameterNames[index] != "" {
			taintedNames[parameterNames[index]] = true
		}
	}

	changed := false
	var validationErr error
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if validationErr != nil || node == nil {
			return validationErr == nil
		}
		switch value := node.(type) {
		case *ast.GoStmt:
			if containsBorrowedExpression(value, taintedNames) {
				validationErr = fmt.Errorf("borrowed HeaderBytes used asynchronously in %s", function.Name.Name)
			}
		case *ast.AssignStmt:
			if !anyAliasesBorrowedExpression(value.Rhs, taintedNames) {
				break
			}
			if anyNonLocalAssignment(value.Lhs) {
				validationErr = fmt.Errorf("borrowed HeaderBytes retained outside a local in %s", function.Name.Name)
				break
			}
			for _, expression := range value.Lhs {
				identifier, ok := expression.(*ast.Ident)
				if ok && identifier.Name != "_" {
					taintedNames[identifier.Name] = true
				}
			}
		case *ast.ReturnStmt:
			if function.Name.Name != "decodePrototypeNetworkIdentity" &&
				anyAliasesBorrowedExpression(value.Results, taintedNames) {
				validationErr = fmt.Errorf("borrowed HeaderBytes returned from %s", function.Name.Name)
			}
		case *ast.CallExpr:
			if isHeaderCopyCall(value, taintedNames) {
				validationErr = fmt.Errorf("borrowed HeaderBytes copied in %s", function.Name.Name)
				break
			}
			callee, ok := value.Fun.(*ast.Ident)
			if !ok {
				break
			}
			if functions[callee.Name] == nil {
				if anyContainsBorrowedExpression(value.Args, taintedNames) && !safeBorrowedBuiltin(callee.Name) {
					validationErr = fmt.Errorf("borrowed HeaderBytes passed beyond the inspected file in %s", function.Name.Name)
				}
				break
			}
			if taintedParameters[callee.Name] == nil {
				taintedParameters[callee.Name] = make(map[int]bool)
			}
			for index, argument := range value.Args {
				if containsBorrowedExpression(argument, taintedNames) && !taintedParameters[callee.Name][index] {
					taintedParameters[callee.Name][index] = true
					changed = true
				}
			}
		case *ast.FuncLit:
			if containsBorrowedExpression(value.Body, taintedNames) {
				validationErr = fmt.Errorf("borrowed HeaderBytes captured by a closure in %s", function.Name.Name)
			}
		}
		return validationErr == nil
	})

	return changed, validationErr
}

func safeBorrowedBuiltin(name string) bool {
	switch name {
	case "cap", "len", "string":
		return true
	default:
		return false
	}
}

func flattenedParameterNames(fields *ast.FieldList) []string {
	if fields == nil {
		return nil
	}
	names := make([]string, 0, len(fields.List))
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			names = append(names, "")
			continue
		}
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	return names
}

func containsDecodeCall(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		call, ok := candidate.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, identifierOK := selector.X.(*ast.Ident)
		if identifierOK && identifier.Name == "networkidentity" && selector.Sel.Name == "Decode" {
			found = true
			return false
		}
		return true
	})
	return found
}

func containsBorrowedExpression(node ast.Node, taintedNames map[string]bool) bool {
	found := false
	ast.Inspect(node, func(candidate ast.Node) bool {
		identifier, ok := candidate.(*ast.Ident)
		if ok && taintedNames[identifier.Name] {
			found = true
			return false
		}
		selector, ok := candidate.(*ast.SelectorExpr)
		if ok && (selector.Sel.Name == "HeaderBytes" || selector.Sel.Name == "headerBytes") {
			found = true
			return false
		}
		return true
	})
	return found
}

func anyContainsBorrowedExpression(expressions []ast.Expr, taintedNames map[string]bool) bool {
	for _, expression := range expressions {
		if containsBorrowedExpression(expression, taintedNames) {
			return true
		}
	}
	return false
}

func aliasesBorrowedExpression(expression ast.Expr, taintedNames map[string]bool) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		return taintedNames[value.Name]
	case *ast.SelectorExpr:
		return value.Sel.Name == "HeaderBytes" || value.Sel.Name == "headerBytes"
	case *ast.ParenExpr:
		return aliasesBorrowedExpression(value.X, taintedNames)
	case *ast.SliceExpr:
		return aliasesBorrowedExpression(value.X, taintedNames)
	case *ast.IndexExpr:
		return aliasesBorrowedExpression(value.X, taintedNames)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			switch typed := element.(type) {
			case *ast.KeyValueExpr:
				if aliasesBorrowedExpression(typed.Value, taintedNames) {
					return true
				}
			case ast.Expr:
				if aliasesBorrowedExpression(typed, taintedNames) {
					return true
				}
			}
		}
	}
	return false
}

func anyAliasesBorrowedExpression(expressions []ast.Expr, taintedNames map[string]bool) bool {
	for _, expression := range expressions {
		if aliasesBorrowedExpression(expression, taintedNames) {
			return true
		}
	}
	return false
}

func anyNonLocalAssignment(expressions []ast.Expr) bool {
	for _, expression := range expressions {
		switch expression.(type) {
		case *ast.SelectorExpr, *ast.IndexExpr, *ast.IndexListExpr:
			return true
		}
	}
	return false
}

func isHeaderCopyCall(call *ast.CallExpr, taintedNames map[string]bool) bool {
	if !anyContainsBorrowedExpression(call.Args, taintedNames) {
		return false
	}
	if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "append" {
		return true
	}
	if identifier, ok := call.Fun.(*ast.Ident); ok && identifier.Name == "copy" {
		return true
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	identifier, identifierOK := selector.X.(*ast.Ident)
	return identifierOK && identifier.Name == "bytes" && selector.Sel.Name == "Clone"
}
