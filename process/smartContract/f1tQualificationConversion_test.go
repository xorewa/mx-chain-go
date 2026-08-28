package smartContract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/drwaqualification/f1t"
	processMock "github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// TestF1TQualificationReachesLegacyProductionConversionOnce is deliberately
// non-parallel: its captured input and coverage invocation count constitute one
// PR052 observation through ExecuteBuiltInFunction, not a reconstructed call.
func TestF1TQualificationReachesLegacyProductionConversionOnce(t *testing.T) {
	constructor := f1t.DefaultCanonicalSourceConstructor()
	selected, _, err := f1t.BuildCalibrationFixture(constructor, f1t.ProfileLegacy, "SELECTED", 1, "fixture", "topic", "peer", true)
	require.NoError(t, err)
	sentinel, _, err := f1t.BuildCalibrationFixture(constructor, f1t.ProfileLegacy, "SENTINEL_1", 1, "fixture", "topic", "peer", false)
	require.NoError(t, err)
	scr := f1tSCRFromFixture(t, selected)

	enableEpochs := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.SCDeployFlag, common.BuiltInFunctionsFlag, common.DRWAEnforcementFlag)
	coordinator := f1tDestinationCoordinator()
	var captured *vmcommon.ContractCallInput
	invocations := uint64(0)
	arguments := createMockSmartContractProcessorArguments()
	arguments.Marshalizer = &marshal.GogoProtoMarshalizer{}
	arguments.Hasher = blake2b.NewBlake2b()
	arguments.ArgsParser = NewArgumentParser()
	arguments.EnableEpochsHandler = enableEpochs
	arguments.ShardCoordinator = coordinator
	arguments.BlockChainHook = &testscommon.BlockChainHookStub{ProcessBuiltInFunctionCalled: func(input *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		invocations++
		captured = input
		return &vmcommon.VMOutput{ReturnCode: vmcommon.UserError, ReturnMessage: "qualification stop after conversion"}, nil
	}}
	processor, err := NewSmartContractProcessor(arguments)
	require.NoError(t, err)

	_, _ = processor.ExecuteBuiltInFunction(scr, nil, createAccount(scr.RcvAddr))
	require.Equal(t, uint64(1), invocations)
	require.NotNil(t, captured)

	selection, err := f1t.ClassifyObservedFixture(selected, f1t.ProfileLegacy, "topic", "peer", [][]byte{selected, sentinel}, f1t.ObservationContext{
		NetworkDomain: constructor.NetworkDomain, EnableEpochsHandler: enableEpochs, Coordinator: coordinator,
		Conversion: &f1t.DestinationConversionObservation{InvocationCount: invocations, VMInput: captured},
	})
	require.NoError(t, err)
	require.Equal(t, f1t.PredicateResult{State: "TRUE"}, selection.ObservedPredicates["PR052_DESTINATION_CONVERSION_REACHED"])
	require.Equal(t, "VP11_VALID_ROUTE", selection.ValidatorProjectionID)
	assertUniqueCreateVMCallInputCallSite(t, "process.go")
}

func f1tSCRFromFixture(t *testing.T, raw []byte) *smartContractResult.SmartContractResult {
	t.Helper()
	var fixture f1t.TransportFixture
	require.NoError(t, json.Unmarshal(raw, &fixture))
	encoded, err := hex.DecodeString(fixture.SCRHex)
	require.NoError(t, err)
	scr := &smartContractResult.SmartContractResult{}
	require.NoError(t, (&marshal.GogoProtoMarshalizer{}).Unmarshal(scr, encoded))
	return scr
}

func f1tDestinationCoordinator() *processMock.ShardCoordinatorStub {
	return &processMock.ShardCoordinatorStub{
		NumberOfShardsCalled: func() uint32 { return 3 }, SelfIdCalled: func() uint32 { return 1 },
		ComputeIdCalled: func(address []byte) uint32 {
			if len(address) == 32 && address[0] == 0x22 {
				return 1
			}
			return 0
		},
		SameShardCalled:               func(first, second []byte) bool { return bytes.Equal(first, second) },
		CommunicationIdentifierCalled: func(uint32) string { return "f1t" },
	}
}

func assertUniqueCreateVMCallInputCallSite(t *testing.T, filename string) {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	require.True(t, ok)
	parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(current), filename), nil, 0)
	require.NoError(t, err)
	count := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "createVMCallInput" {
			count++
		}
		return true
	})
	require.Equal(t, 1, count)
}
