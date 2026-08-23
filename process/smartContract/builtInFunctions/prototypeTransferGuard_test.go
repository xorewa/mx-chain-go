package builtInFunctions

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestPrototypeTransferGuardPreActivationDelegatesWithoutClassification(t *testing.T) {
	t.Parallel()

	classifierCalled := false
	delegateCalled := false
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}
	sender := &vmcommonMock.UserAccountStub{}
	destination := &vmcommonMock.UserAccountStub{}
	input := &vmcommon.ContractCallInput{
		Function: core.BuiltInFunctionESDTTransfer,
		VMInput:  vmcommon.VMInput{Arguments: [][]byte{[]byte("TOKEN-abcdef"), {1}}},
	}
	delegate := &prototypeTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(actualSender, actualDestination vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		require.Same(t, sender, actualSender)
		require.Same(t, destination, actualDestination)
		require.Same(t, input, actualInput)
		return output, nil
	}
	guard := createPrototypeTransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, false, func(_ []byte) (bool, error) {
		classifierCalled = true
		return true, nil
	})

	actualOutput, err := guard.ProcessBuiltinFunction(sender, destination, input)
	require.NoError(t, err)
	require.Same(t, output, actualOutput)
	require.True(t, delegateCalled)
	require.False(t, classifierCalled)
}

func TestPrototypeTransferGuardOrdinaryDirectAndNFTDelegateUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		functionName string
		arguments    [][]byte
	}{
		{
			name:         "direct",
			functionName: core.BuiltInFunctionESDTTransfer,
			arguments:    [][]byte{[]byte("TOKEN-abcdef"), {1}},
		},
		{
			name:         "NFT entry",
			functionName: core.BuiltInFunctionESDTNFTTransfer,
			arguments:    [][]byte{[]byte("TOKEN-abcdef"), {1}, {1}, make([]byte, 32)},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			input := &vmcommon.ContractCallInput{Function: test.functionName, VMInput: vmcommon.VMInput{Arguments: test.arguments}}
			delegateCalled := false
			delegate := &prototypeTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				require.Same(t, input, actualInput)
				return &vmcommon.VMOutput{}, nil
			}
			classified := make([]string, 0)
			guard := createPrototypeTransferGuardForTest(t, test.functionName, delegate, true, func(tokenID []byte) (bool, error) {
				classified = append(classified, string(tokenID))
				return false, nil
			})

			_, err := guard.ProcessBuiltinFunction(nil, nil, input)
			require.NoError(t, err)
			require.True(t, delegateCalled)
			require.Equal(t, []string{"TOKEN-abcdef"}, classified)
		})
	}
}

func TestPrototypeTransferGuardOrdinaryMultiFormsDelegateUnchanged(t *testing.T) {
	t.Parallel()

	firstToken := []byte("FIRST-abcdef")
	secondToken := []byte("SECOND-abcdef")
	tests := []struct {
		name  string
		input *vmcommon.ContractCallInput
	}{
		{
			name: "sender-local",
			input: &vmcommon.ContractCallInput{
				RecipientAddr: []byte("same"),
				VMInput: vmcommon.VMInput{
					CallerAddr: []byte("same"),
					Arguments:  prototypeSenderMultiArguments(firstToken, secondToken),
				},
			},
		},
		{
			name: "destination",
			input: &vmcommon.ContractCallInput{
				RecipientAddr: []byte("destination"),
				VMInput: vmcommon.VMInput{
					CallerAddr: []byte("source"),
					Arguments:  prototypeDestinationMultiArguments(firstToken, secondToken),
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			delegateCalled := false
			delegate := &prototypeTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				require.Same(t, test.input, actualInput)
				return &vmcommon.VMOutput{}, nil
			}
			classified := make([]string, 0)
			guard := createPrototypeTransferGuardForTest(t, core.BuiltInFunctionMultiESDTNFTTransfer, delegate, true, func(tokenID []byte) (bool, error) {
				classified = append(classified, string(tokenID))
				return false, nil
			})

			_, err := guard.ProcessBuiltinFunction(nil, nil, test.input)
			require.NoError(t, err)
			require.True(t, delegateCalled)
			require.Equal(t, []string{"FIRST-abcdef", "SECOND-abcdef"}, classified)
		})
	}
}

func TestPrototypeTransferGuardBlocksMarkedTokenInEveryTransferForm(t *testing.T) {
	t.Parallel()

	firstToken := []byte("FIRST-abcdef")
	markedToken := []byte("SECOND-abcdef")
	tests := []struct {
		name         string
		functionName string
		input        *vmcommon.ContractCallInput
	}{
		{
			name:         "direct",
			functionName: core.BuiltInFunctionESDTTransfer,
			input:        &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{Arguments: [][]byte{markedToken, {1}}}},
		},
		{
			name:         "NFT entry",
			functionName: core.BuiltInFunctionESDTNFTTransfer,
			input:        &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{Arguments: [][]byte{markedToken, {1}, {1}, make([]byte, 32)}}},
		},
		{
			name:         "sender-local multi second token",
			functionName: core.BuiltInFunctionMultiESDTNFTTransfer,
			input: &vmcommon.ContractCallInput{
				RecipientAddr: []byte("same"),
				VMInput: vmcommon.VMInput{
					CallerAddr: []byte("same"),
					Arguments:  prototypeSenderMultiArguments(firstToken, markedToken),
				},
			},
		},
		{
			name:         "destination multi second token",
			functionName: core.BuiltInFunctionMultiESDTNFTTransfer,
			input: &vmcommon.ContractCallInput{
				RecipientAddr: []byte("destination"),
				VMInput: vmcommon.VMInput{
					CallerAddr: []byte("source"),
					Arguments:  prototypeDestinationMultiArguments(firstToken, markedToken),
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			delegateCalled := false
			delegate := &prototypeTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{}, nil
			}
			guard := createPrototypeTransferGuardForTest(t, test.functionName, delegate, true, func(tokenID []byte) (bool, error) {
				return string(tokenID) == string(markedToken), nil
			})

			output, err := guard.ProcessBuiltinFunction(nil, nil, test.input)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrPrototypeRegulatedTransferRequiresDRWA)
			require.False(t, delegateCalled)
		})
	}
}

func TestPrototypeTransferGuardClassifierFailureBlocksDelegation(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected classifier failure")
	delegateCalled := false
	delegate := &prototypeTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		return &vmcommon.VMOutput{}, nil
	}
	guard := createPrototypeTransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
		return false, injected
	})
	input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{Arguments: [][]byte{[]byte("TOKEN-abcdef"), {1}}}}

	output, err := guard.ProcessBuiltinFunction(nil, nil, input)
	require.Nil(t, output)
	require.ErrorIs(t, err, injected)
	require.False(t, delegateCalled)
}

func TestPrototypeTransferGuardMalformedCallsDelegateToBaseline(t *testing.T) {
	t.Parallel()

	overflowingCount := make([]byte, 9)
	for index := range overflowingCount {
		overflowingCount[index] = 0xff
	}
	tests := []struct {
		name         string
		functionName string
		input        *vmcommon.ContractCallInput
	}{
		{name: "nil input", functionName: core.BuiltInFunctionESDTTransfer},
		{name: "direct no arguments", functionName: core.BuiltInFunctionESDTTransfer, input: &vmcommon.ContractCallInput{}},
		{
			name:         "multi count overflow",
			functionName: core.BuiltInFunctionMultiESDTNFTTransfer,
			input: &vmcommon.ContractCallInput{
				RecipientAddr: []byte("destination"),
				VMInput: vmcommon.VMInput{CallerAddr: []byte("source"), Arguments: [][]byte{
					overflowingCount, []byte("TOKEN-abcdef"), {0}, {1},
				}},
			},
		},
		{
			name:         "multi count exceeds arguments",
			functionName: core.BuiltInFunctionMultiESDTNFTTransfer,
			input: &vmcommon.ContractCallInput{
				RecipientAddr: []byte("destination"),
				VMInput: vmcommon.VMInput{CallerAddr: []byte("source"), Arguments: [][]byte{
					{2}, []byte("TOKEN-abcdef"), {0}, {1},
				}},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			classifierCalled := false
			delegateCalled := false
			delegate := &prototypeTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				require.Same(t, test.input, actualInput)
				return &vmcommon.VMOutput{}, nil
			}
			guard := createPrototypeTransferGuardForTest(t, test.functionName, delegate, true, func(_ []byte) (bool, error) {
				classifierCalled = true
				return true, nil
			})

			_, err := guard.ProcessBuiltinFunction(nil, nil, test.input)
			require.NoError(t, err)
			require.True(t, delegateCalled)
			require.False(t, classifierCalled)
		})
	}
}

func TestPrototypeTransferGuardSkipsInvalidTokenButStillChecksLaterValidToken(t *testing.T) {
	t.Parallel()

	markedToken := []byte("SECOND-abcdef")
	input := &vmcommon.ContractCallInput{
		RecipientAddr: []byte("destination"),
		VMInput:       vmcommon.VMInput{CallerAddr: []byte("source"), Arguments: prototypeDestinationMultiArguments([]byte("invalid"), markedToken)},
	}
	delegateCalled := false
	delegate := &prototypeTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		return &vmcommon.VMOutput{}, nil
	}
	classified := make([]string, 0)
	guard := createPrototypeTransferGuardForTest(t, core.BuiltInFunctionMultiESDTNFTTransfer, delegate, true, func(tokenID []byte) (bool, error) {
		classified = append(classified, string(tokenID))
		return string(tokenID) == string(markedToken), nil
	})

	_, err := guard.ProcessBuiltinFunction(nil, nil, input)
	require.ErrorIs(t, err, ErrPrototypeRegulatedTransferRequiresDRWA)
	require.False(t, delegateCalled)
	require.Equal(t, []string{"SECOND-abcdef"}, classified)
}

func TestPrototypeTransferGuardForwardsLifecycleMethods(t *testing.T) {
	t.Parallel()

	gasCost := &vmcommon.GasCost{}
	gasForwarded := false
	payableChecker := &prototypePayableCheckerStub{}
	payableForwarded := false
	delegate := &prototypeTransferDelegateStub{
		setPayableCheckerCalled: func(actual vmcommon.PayableChecker) error {
			payableForwarded = true
			require.Same(t, payableChecker, actual)
			return nil
		},
	}
	delegate.SetNewGasConfigCalled = func(actual *vmcommon.GasCost) {
		gasForwarded = true
		require.Same(t, gasCost, actual)
	}
	delegate.IsActiveCalled = func() bool { return false }
	guard := createPrototypeTransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
		return false, nil
	})

	guard.SetNewGasConfig(gasCost)
	require.True(t, gasForwarded)
	require.False(t, guard.IsActive())
	require.NoError(t, guard.SetPayableChecker(payableChecker))
	require.True(t, payableForwarded)
	require.False(t, guard.IsInterfaceNil())
	var nilGuard *prototypeTransferGuard
	require.True(t, nilGuard.IsInterfaceNil())
}

func TestPrototypeGuardedFactoryInstallsAndReinstallsProtocolHandlers(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	factory, err := CreateBuiltInFunctionsFactory(args)
	require.NoError(t, err)
	require.IsType(t, &prototypeGuardedBuiltInFunctionFactory{}, factory)
	require.Len(t, factory.BuiltInFunctionContainer().Keys(), 46)
	require.Equal(t, 3, countPrototypeTransferGuards(t, factory.BuiltInFunctionContainer()))
	requirePrototypeTransferGuardNames(t, factory.BuiltInFunctionContainer())
	function, err := factory.BuiltInFunctionContainer().Get(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	require.NoError(t, err)
	require.IsType(t, &prototypeDestination{}, function)
	function, err = factory.BuiltInFunctionContainer().Get(PrototypeSettlementReceiptFunction)
	require.NoError(t, err)
	require.IsType(t, &prototypeSourceCompletion{}, function)
	function, err = factory.BuiltInFunctionContainer().Get(PrototypeRefundEnvelopeFunction)
	require.NoError(t, err)
	require.IsType(t, &prototypeSourceCompletion{}, function)
	require.NoError(t, factory.SetPayableHandler(&testscommon.BlockChainHookStub{}))

	require.NoError(t, factory.CreateBuiltInFunctionContainer())
	require.Len(t, factory.BuiltInFunctionContainer().Keys(), 46)
	require.Equal(t, 3, countPrototypeTransferGuards(t, factory.BuiltInFunctionContainer()))
	requirePrototypeTransferGuardNames(t, factory.BuiltInFunctionContainer())
	function, err = factory.BuiltInFunctionContainer().Get(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	require.NoError(t, err)
	require.IsType(t, &prototypeDestination{}, function)
	require.NoError(t, factory.SetPayableHandler(&testscommon.BlockChainHookStub{}))
}

func TestNewPrototypeTransferGuardRejectsDelegateWithoutPayableChecker(t *testing.T) {
	t.Parallel()

	guard, err := newPrototypeTransferGuard(
		core.BuiltInFunctionESDTTransfer,
		&vmcommonMock.BuiltInFunctionStub{},
		func(_ []byte) (bool, error) { return false, nil },
		&vmcommonMock.EnableEpochsHandlerStub{},
	)
	require.Nil(t, guard)
	require.ErrorIs(t, err, ErrInvalidPrototypeTransferGuardDelegate)
}

type prototypeTransferDelegateStub struct {
	vmcommonMock.BuiltInFunctionStub
	setPayableCheckerCalled func(payableChecker vmcommon.PayableChecker) error
}

func (stub *prototypeTransferDelegateStub) SetPayableChecker(payableChecker vmcommon.PayableChecker) error {
	if stub.setPayableCheckerCalled != nil {
		return stub.setPayableCheckerCalled(payableChecker)
	}
	return nil
}

type prototypePayableCheckerStub struct{}

func (stub *prototypePayableCheckerStub) CheckPayable(_ *vmcommon.ContractCallInput, _ []byte, _ int) error {
	return nil
}
func (stub *prototypePayableCheckerStub) DetermineIsSCCallAfter(_ *vmcommon.ContractCallInput, _ []byte, _ int) bool {
	return false
}
func (stub *prototypePayableCheckerStub) IsInterfaceNil() bool { return stub == nil }

func createPrototypeTransferGuardForTest(
	t *testing.T,
	functionName string,
	delegate vmcommon.BuiltinFunction,
	active bool,
	classifier prototypeTokenClassifier,
) *prototypeTransferGuard {
	t.Helper()

	guard, err := newPrototypeTransferGuard(
		functionName,
		delegate,
		classifier,
		&vmcommonMock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				require.Equal(t, common.DRWAEnforcementFlag, flag)
				return active
			},
		},
	)
	require.NoError(t, err)

	return guard
}

func prototypeSenderMultiArguments(firstToken, secondToken []byte) [][]byte {
	return [][]byte{
		make([]byte, 32), {2},
		firstToken, {0}, {1},
		secondToken, {0}, {2},
	}
}

func prototypeDestinationMultiArguments(firstToken, secondToken []byte) [][]byte {
	return [][]byte{
		{2},
		firstToken, {0}, {1},
		secondToken, {0}, {2},
	}
}

func countPrototypeTransferGuards(t *testing.T, container vmcommon.BuiltInFunctionContainer) int {
	t.Helper()

	count := 0
	for functionName := range container.Keys() {
		function, err := container.Get(functionName)
		require.NoError(t, err)
		if _, ok := function.(*prototypeTransferGuard); ok {
			count++
		}
	}

	return count
}

func requirePrototypeTransferGuardNames(t *testing.T, container vmcommon.BuiltInFunctionContainer) {
	t.Helper()

	for _, functionName := range []string{
		core.BuiltInFunctionESDTTransfer,
		core.BuiltInFunctionESDTNFTTransfer,
		core.BuiltInFunctionMultiESDTNFTTransfer,
	} {
		function, err := container.Get(functionName)
		require.NoError(t, err)
		guard, ok := function.(*prototypeTransferGuard)
		require.True(t, ok)
		require.Equal(t, functionName, guard.functionName)
	}
}
