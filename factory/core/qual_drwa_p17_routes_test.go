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
	require.NoError(t, qualP17CheckRequiredRouteNodes(fixture.Nodes))
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
		if !ok || fn.Name.Name != "execute" {
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

// RT-05 / Plan P17 L435/L576: this reviewed identity set is independent of
// routes_01.json at execution. It freezes T10's selected classifier lifecycle,
// native producer/receiver, account/save, SystemEI and loaded built-in boundaries,
// including the three T41 public-call delegates identified by FA-01 D-14.
// Updating body metadata cannot remove or substitute one of these obligations.
// This bounded set is not complete dynamic reachability (SP2-25/SP2-68).
func qualP17CheckRequiredRouteNodes(nodes []qualP17RouteNode) error {
	required := strings.Fields(`
node/process/drwa/nativeMetaContext.go/*nativeMetaContext.selectAnchor
node/process/drwa/registryMaterialization.go/*registryMaterialization.prepare
node/process/drwa/registryMaterialization.go/*registryMaterialization.classify
node/process/drwa/registryProjectionLifecycle.go/*registryCandidate.stage
node/process/drwa/registryProjectionLifecycle.go/*registryCandidate.classify
node/process/drwa/registryProjectionLifecycle.go/*registryCandidate.commit
node/process/drwa/registryProjectionLifecycle.go/*registryCandidate.abort
node/process/drwa/registryProjectionLifecycle.go/*registryCandidate.recover
node/process/drwa/registryRegistration.go/*RegistryRegistration.RegisterToken
node/process/drwa/registryTransport.go/*registryTransport.reconstruct
node/process/drwa/rollbackContainment.go/*RollbackContainment.Execute
node/process/drwa/rollbackContainment.go/*RollbackContainment.Commit
node/process/drwa/rollbackContainment.go/*RollbackContainment.Recover
node/process/drwa/rollbackContainment.go/*RollbackContainment.execute
node/process/drwa/rollbackContainment.go/*RollbackContainment.recover
node/process/drwa/rollbackContainment.go/*RollbackContainment.Abort
node/process/factory/metachain/vmContainerFactory.go/*vmContainerFactory.createSystemVMFactoryAndEEI
node/process/factory/metachain/vmContainerFactory.go/*vmContainerFactory.finalizeSystemVMCreation
node/process/smartContract/builtInFunctions/factory.go/.CreateBuiltInFunctionsFactory
node/process/smartContract/builtInFunctions/factory.go/.GetAllowedAddress
node/process/smartContract/hooks/blockChainHook.go/*BlockChainHookImpl.ProcessBuiltInFunction
node/process/smartContract/hooks/blockChainHook.go/*BlockChainHookImpl.getUserAccounts
node/process/smartContract/process.go/*scProcessor.prepareExecution
node/process/smartContract/process.go/*scProcessor.doExecuteBuiltInFunction
node/process/smartContract/process.go/*scProcessor.resolveBuiltInFunctions
node/process/smartContract/process.go/*scProcessor.isSCExecutionAfterBuiltInFunc
node/process/smartContract/process.go/.createBaseSCR
node/process/smartContract/process.go/*scProcessor.preprocessOutTransferToSCR
node/process/smartContract/process.go/*scProcessor.createSmartContractResults
node/process/smartContract/processorV2/processV2.go/*scProcessor.prepareExecution
node/process/smartContract/processorV2/processV2.go/*scProcessor.doExecuteBuiltInFunctionWithoutFailureProcessing
node/process/smartContract/processorV2/processV2.go/*scProcessor.resolveBuiltInFunctions
node/process/smartContract/processorV2/processV2.go/*scProcessor.isSameShardSCExecutionAfterBuiltInFunc
node/process/smartContract/processorV2/processV2.go/.createBaseSCR
node/process/smartContract/processorV2/processV2.go/*scProcessor.preprocessOutTransferToSCR
node/process/smartContract/processorV2/processV2.go/*scProcessor.createSmartContractResults
node/process/smartContract/scQueryService.go/*SCQueryService.executeScCall
node/process/smartContract/scQueryService.go/*SCQueryService.recreateTrie
node/process/smartContract/scQueryService.go/*SCQueryService.createVMCallInput
node/process/transaction/interceptedTransaction.go/*InterceptedTransaction.CheckValidity
node/process/unsigned/interceptedUnsignedTransaction.go/*InterceptedUnsignedTransaction.CheckValidity
node/vm/factory/systemSCFactory.go/*systemSCFactory.createESDTContract
node/vm/process/systemVM.go/*systemVM.RunSmartContractCall
node/vm/systemSmartContracts/eei.go/*vmContext.SendGlobalSettingToAll
node/vm/systemSmartContracts/eei.go/*vmContext.Transfer
node/vm/systemSmartContracts/eei.go/*vmContext.createContractCallInput
node/vm/systemSmartContracts/eei.go/*vmContext.transferBeforeInternalExec
node/vm/systemSmartContracts/eei.go/*vmContext.ExecuteOnDestContext
node/vm/systemSmartContracts/esdt.go/*esdt.Execute
node/vm/systemSmartContracts/esdt.go/*esdt.init
node/vm/systemSmartContracts/esdt.go/*esdt.issue
node/vm/systemSmartContracts/esdt.go/*esdt.registerNonFungible
node/vm/systemSmartContracts/esdt.go/*esdt.registerSemiFungible
node/vm/systemSmartContracts/esdt.go/*esdt.registerMetaESDT
node/vm/systemSmartContracts/esdt.go/*esdt.registerAndSetRoles
node/vm/systemSmartContracts/esdt.go/*esdt.changeSFTToMetaESDT
node/vm/systemSmartContracts/esdt.go/*esdt.burn
node/vm/systemSmartContracts/esdt.go/*esdt.mint
node/vm/systemSmartContracts/esdt.go/*esdt.toggleFreeze
node/vm/systemSmartContracts/esdt.go/*esdt.wipe
node/vm/systemSmartContracts/esdt.go/*esdt.toggleFreezeSingleNFT
node/vm/systemSmartContracts/esdt.go/*esdt.wipeSingleNFT
node/vm/systemSmartContracts/esdt.go/*esdt.togglePause
node/vm/systemSmartContracts/esdt.go/*esdt.setBurnRoleGlobally
node/vm/systemSmartContracts/esdt.go/*esdt.unsetBurnRoleGlobally
node/vm/systemSmartContracts/esdt.go/*esdt.configChange
node/vm/systemSmartContracts/esdt.go/*esdt.claim
node/vm/systemSmartContracts/esdt.go/*esdt.getTokenProperties
node/vm/systemSmartContracts/esdt.go/*esdt.getSpecialRoles
node/vm/systemSmartContracts/esdt.go/*esdt.basicOwnershipChecks
node/vm/systemSmartContracts/esdt.go/*esdt.transferOwnership
node/vm/systemSmartContracts/esdt.go/*esdt.controlChanges
node/vm/systemSmartContracts/esdt.go/*esdt.changeToMultiShardCreate
node/vm/systemSmartContracts/esdt.go/*esdt.prepareAndSendRoleChangeData
node/vm/systemSmartContracts/esdt.go/*esdt.setSpecialRole
node/vm/systemSmartContracts/esdt.go/*esdt.unSetSpecialRole
node/vm/systemSmartContracts/esdt.go/*esdt.sendAllTransferRoleAddresses
node/vm/systemSmartContracts/esdt.go/*esdt.transferNFTCreateRole
node/vm/systemSmartContracts/esdt.go/*esdt.stopNFTCreateForever
node/vm/systemSmartContracts/esdt.go/*esdt.updateTokenID
node/vm/systemSmartContracts/esdt.go/*esdt.registerDynamic
node/vm/systemSmartContracts/esdt.go/*esdt.registerAndSetAllRolesDynamic
node/vm/systemSmartContracts/esdt.go/*esdt.changeToDynamic
node/vm/systemSmartContracts/esdt.go/*esdt.sendTokenTypeToSystemAccounts
node/vm/systemSmartContracts/esdt.go/*esdt.getAllAddressesAndRoles
node/vm/systemSmartContracts/esdt.go/*esdt.saveToken
node/vm/systemSmartContracts/esdt.go/*esdt.getExistingToken
node/vm/systemSmartContracts/esdt.go/*esdt.saveESDTConfig
node/vm/systemSmartContracts/esdt.go/*esdt.getContractConfig
builtin/builtInFunctions/changeOwnerAddress.go/*changeOwnerAddress.ProcessBuiltinFunction
builtin/builtInFunctions/claimDeveloperRewards.go/*claimDeveloperRewards.ProcessBuiltinFunction
builtin/builtInFunctions/deleteUserName.go/*deleteUserName.ProcessBuiltinFunction
builtin/builtInFunctions/esdtBurn.go/*esdtBurn.ProcessBuiltinFunction
builtin/builtInFunctions/esdtDeleteMetadata.go/*esdtDeleteMetaData.ProcessBuiltinFunction
builtin/builtInFunctions/esdtFreezeWipe.go/*esdtFreezeWipe.ProcessBuiltinFunction
builtin/builtInFunctions/esdtGlobalSettings.go/*esdtGlobalSettings.ProcessBuiltinFunction
builtin/builtInFunctions/esdtLocalBurn.go/*esdtLocalBurn.ProcessBuiltinFunction
builtin/builtInFunctions/esdtLocalMint.go/*esdtLocalMint.ProcessBuiltinFunction
builtin/builtInFunctions/esdtMetaDataRecreate.go/*esdtMetaDataRecreate.ProcessBuiltinFunction
builtin/builtInFunctions/esdtMetaDataUpdate.go/*esdtMetaDataUpdate.ProcessBuiltinFunction
builtin/builtInFunctions/esdtModifyCreator.go/*esdtModifyCreator.ProcessBuiltinFunction
builtin/builtInFunctions/esdtModifyRoyalties.go/*esdtModifyRoyalties.ProcessBuiltinFunction
builtin/builtInFunctions/esdtNFTAddQuantity.go/*esdtNFTAddQuantity.ProcessBuiltinFunction
builtin/builtInFunctions/esdtNFTAddUri.go/*esdtNFTAddUri.ProcessBuiltinFunction
builtin/builtInFunctions/esdtNFTBurn.go/*esdtNFTBurn.ProcessBuiltinFunction
builtin/builtInFunctions/esdtNFTCreate.go/*esdtNFTCreate.ProcessBuiltinFunction
builtin/builtInFunctions/esdtNFTCreateRoleTransfer.go/*esdtNFTCreateRoleTransfer.ProcessBuiltinFunction
builtin/builtInFunctions/esdtNFTTransfer.go/*esdtNFTTransfer.ProcessBuiltinFunction
builtin/builtInFunctions/esdtRoles.go/*esdtRoles.ProcessBuiltinFunction
builtin/builtInFunctions/esdtSetNewURIs.go/*esdtSetNewURIs.ProcessBuiltinFunction
builtin/builtInFunctions/esdtSetTokenType.go/*esdtSetTokenType.ProcessBuiltinFunction
builtin/builtInFunctions/esdtTransfer.go/*esdtTransfer.ProcessBuiltinFunction
builtin/builtInFunctions/esdtTransferRole.go/*esdtTransferAddress.ProcessBuiltinFunction
builtin/builtInFunctions/guardAccount.go/*guardAccountFunc.ProcessBuiltinFunction
builtin/builtInFunctions/keyValueStorage.go/*saveKeyValueStorage.ProcessBuiltinFunction
builtin/builtInFunctions/migrateDataTrie.go/*migrateDataTrie.ProcessBuiltinFunction
builtin/builtInFunctions/multiESDTNFTTransfer.go/*esdtNFTMultiTransfer.ProcessBuiltinFunction
builtin/builtInFunctions/saveUserName.go/*saveUserName.ProcessBuiltinFunction
builtin/builtInFunctions/setGuardian.go/*setGuardian.ProcessBuiltinFunction
builtin/builtInFunctions/unGuardAccount.go/*unGuardAccountFunc.ProcessBuiltinFunction
builtin/builtInFunctions/updateNFTAttributes.go/*esdtNFTupdate.ProcessBuiltinFunction
node/vm/systemSmartContracts/esdt.go/*esdt.execute
node/vm/systemSmartContracts/drwaPublicCall.go/*vmContext.ExecuteDRWASystemCall
node/vm/systemSmartContracts/drwaPublicCall.go/*vmContext.executeWithDRWAErrorCheck
node/vm/systemSmartContracts/drwaPublicCall.go/*vmContext.executeDRWAESDTCall
`)
	actual := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		key := node.Root + "/" + node.File + "/" + node.Receiver + "." + node.Function
		if actual[key] {
			return fmt.Errorf("duplicate required route node: %s", key)
		}
		actual[key] = true
	}
	for _, key := range required {
		if !actual[key] {
			return fmt.Errorf("missing required route node: %s", key)
		}
	}
	if len(actual) != len(required) {
		return fmt.Errorf("unreviewed route node: got %d, require %d", len(actual), len(required))
	}
	return nil
}

func TestQualDRWAP17RequiredRouteNodes(t *testing.T) {
	nodes := qualP17Routes(t).Nodes
	require.NoError(t, qualP17CheckRequiredRouteNodes(nodes))
	// Each deletion is isolated; a same-count substitution must also be refused.
	for i, node := range nodes {
		t.Run("remove/"+node.Root+"/"+node.File+"/"+node.Receiver+"."+node.Function, func(t *testing.T) {
			changed := append([]qualP17RouteNode(nil), nodes[:i]...)
			changed = append(changed, nodes[i+1:]...)
			require.ErrorContains(t, qualP17CheckRequiredRouteNodes(changed), "missing required route node")
		})
	}
	t.Run("substitution", func(t *testing.T) {
		changed := append([]qualP17RouteNode(nil), nodes...)
		changed[0].Function += "__P17_UNCLASSIFIED"
		require.ErrorContains(t, qualP17CheckRequiredRouteNodes(changed), "missing required route node")
	})
	t.Run("duplicate", func(t *testing.T) {
		changed := append(append([]qualP17RouteNode(nil), nodes...), nodes[0])
		require.ErrorContains(t, qualP17CheckRequiredRouteNodes(changed), "duplicate required route node")
	})
	t.Run("addition", func(t *testing.T) {
		extra := nodes[0]
		extra.Function += "__P17_UNCLASSIFIED"
		changed := append(append([]qualP17RouteNode(nil), nodes...), extra)
		require.ErrorContains(t, qualP17CheckRequiredRouteNodes(changed), "unreviewed route node")
	})
}
