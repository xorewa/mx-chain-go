package builtInFunctions

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/smartContract/drwa"
	"github.com/multiversx/mx-chain-go/testscommon"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/testscommon/vmcommonMocks"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmcommonMock "github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B

func TestDRWATransferGuardPreActivationDelegatesWithoutClassification(t *testing.T) {
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
	delegate := &drwaTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(actualSender, actualDestination vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		require.Same(t, sender, actualSender)
		require.Same(t, destination, actualDestination)
		require.Same(t, input, actualInput)
		return output, nil
	}
	guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, false, func(_ []byte) (bool, error) {
		classifierCalled = true
		return true, nil
	})

	actualOutput, err := guard.ProcessBuiltinFunction(sender, destination, input)
	require.NoError(t, err)
	require.Same(t, output, actualOutput)
	require.True(t, delegateCalled)
	require.False(t, classifierCalled)
}

func TestDRWATransferGuardOrdinaryDirectAndNFTDelegateUnchanged(t *testing.T) {
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
			delegate := &drwaTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				require.Same(t, input, actualInput)
				return &vmcommon.VMOutput{}, nil
			}
			classified := make([]string, 0)
			guard := createDRWATransferGuardForTest(t, test.functionName, delegate, true, func(tokenID []byte) (bool, error) {
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

func TestDRWATransferGuardOrdinaryMultiFormsDelegateUnchanged(t *testing.T) {
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
					Arguments:  drwaSenderMultiArguments(firstToken, secondToken),
				},
			},
		},
		{
			name: "destination",
			input: &vmcommon.ContractCallInput{
				RecipientAddr: []byte("destination"),
				VMInput: vmcommon.VMInput{
					CallerAddr: []byte("source"),
					Arguments:  drwaDestinationMultiArguments(firstToken, secondToken),
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			delegateCalled := false
			delegate := &drwaTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				require.Same(t, test.input, actualInput)
				return &vmcommon.VMOutput{}, nil
			}
			classified := make([]string, 0)
			guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionMultiESDTNFTTransfer, delegate, true, func(tokenID []byte) (bool, error) {
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

func TestDRWATransferGuardBlocksMarkedTokenInEveryTransferForm(t *testing.T) {
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
					Arguments:  drwaSenderMultiArguments(firstToken, markedToken),
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
					Arguments:  drwaDestinationMultiArguments(firstToken, markedToken),
				},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			delegateCalled := false
			delegate := &drwaTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{}, nil
			}
			guard := createDRWATransferGuardForTest(t, test.functionName, delegate, true, func(tokenID []byte) (bool, error) {
				return string(tokenID) == string(markedToken), nil
			})

			output, err := guard.ProcessBuiltinFunction(nil, nil, test.input)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrDRWARegulatedTransferRequiresDRWA)
			require.False(t, delegateCalled)
		})
	}
}

func TestDRWATransferGuardClassifierFailureBlocksDelegation(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected classifier failure")
	delegateCalled := false
	delegate := &drwaTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		return &vmcommon.VMOutput{}, nil
	}
	guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
		return false, injected
	})
	input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{Arguments: [][]byte{[]byte("TOKEN-abcdef"), {1}}}}

	output, err := guard.ProcessBuiltinFunction(nil, nil, input)
	require.Nil(t, output)
	require.ErrorIs(t, err, injected)
	require.False(t, delegateCalled)
}

func TestDRWATransferGuardMalformedCallsDelegateToBaseline(t *testing.T) {
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
			delegate := &drwaTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				require.Same(t, test.input, actualInput)
				return &vmcommon.VMOutput{}, nil
			}
			guard := createDRWATransferGuardForTest(t, test.functionName, delegate, true, func(_ []byte) (bool, error) {
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

func TestDRWATransferGuardSkipsInvalidTokenButStillChecksLaterValidToken(t *testing.T) {
	t.Parallel()

	markedToken := []byte("SECOND-abcdef")
	input := &vmcommon.ContractCallInput{
		RecipientAddr: []byte("destination"),
		VMInput:       vmcommon.VMInput{CallerAddr: []byte("source"), Arguments: drwaDestinationMultiArguments([]byte("invalid"), markedToken)},
	}
	delegateCalled := false
	delegate := &drwaTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		return &vmcommon.VMOutput{}, nil
	}
	classified := make([]string, 0)
	guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionMultiESDTNFTTransfer, delegate, true, func(tokenID []byte) (bool, error) {
		classified = append(classified, string(tokenID))
		return string(tokenID) == string(markedToken), nil
	})

	_, err := guard.ProcessBuiltinFunction(nil, nil, input)
	require.ErrorIs(t, err, ErrDRWARegulatedTransferRequiresDRWA)
	require.False(t, delegateCalled)
	require.Equal(t, []string{"SECOND-abcdef"}, classified)
}

func TestDRWATransferGuardForwardsLifecycleMethods(t *testing.T) {
	t.Parallel()

	gasCost := &vmcommon.GasCost{}
	gasForwarded := false
	payableChecker := &drwaPayableCheckerStub{}
	payableForwarded := false
	delegate := &drwaTransferDelegateStub{
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
	guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
		return false, nil
	})

	guard.SetNewGasConfig(gasCost)
	require.True(t, gasForwarded)
	require.False(t, guard.IsActive())
	require.NoError(t, guard.SetPayableChecker(payableChecker))
	require.True(t, payableForwarded)
	require.False(t, guard.IsInterfaceNil())
	var nilGuard *drwaTransferGuard
	require.True(t, nilGuard.IsInterfaceNil())
}

func TestDRWAGuardedFactoryInstallsAndReinstallsProtocolHandlers(t *testing.T) {
	t.Parallel()

	args := createMockArguments()
	factory, err := CreateBuiltInFunctionsFactory(args)
	require.NoError(t, err)
	require.IsType(t, &drwaGuardedBuiltInFunctionFactory{}, factory)
	guardedFactory := factory.(*drwaGuardedBuiltInFunctionFactory)
	_, err = guardedFactory.drwaCurrentRound()
	require.ErrorIs(t, err, ErrDRWASameShardTransferDenied)
	require.Len(t, factory.BuiltInFunctionContainer().Keys(), 46)
	require.Equal(t, 3, countDRWATransferGuards(t, factory.BuiltInFunctionContainer()))
	requireDRWATransferGuardNames(t, factory.BuiltInFunctionContainer())
	function, err := factory.BuiltInFunctionContainer().Get(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	require.NoError(t, err)
	require.IsType(t, &drwaDestination{}, function)
	function, err = factory.BuiltInFunctionContainer().Get(DRWASettlementReceiptFunction)
	require.NoError(t, err)
	require.IsType(t, &drwaSourceCompletion{}, function)
	function, err = factory.BuiltInFunctionContainer().Get(DRWARefundEnvelopeFunction)
	require.NoError(t, err)
	require.IsType(t, &drwaSourceCompletion{}, function)
	require.NoError(t, factory.SetPayableHandler(&testscommon.BlockChainHookStub{}))
	hook := &testscommon.BlockChainHookStub{CurrentRoundCalled: func() uint64 { return 77 }}
	require.NoError(t, factory.SetBlockchainHook(hook))

	require.NoError(t, factory.CreateBuiltInFunctionContainer())
	require.Len(t, factory.BuiltInFunctionContainer().Keys(), 46)
	require.Equal(t, 3, countDRWATransferGuards(t, factory.BuiltInFunctionContainer()))
	requireDRWATransferGuardNames(t, factory.BuiltInFunctionContainer())
	function, err = factory.BuiltInFunctionContainer().Get(vmcommon.BuiltInFunctionDRWARegulatedValueEnvelope)
	require.NoError(t, err)
	require.IsType(t, &drwaDestination{}, function)
	require.NoError(t, factory.SetPayableHandler(&testscommon.BlockChainHookStub{}))
	round, err := guardedFactory.drwaCurrentRound()
	require.NoError(t, err)
	require.Equal(t, uint64(77), round)
	round, err = guardedFactory.drwaSourceDebit.currentRound()
	require.NoError(t, err)
	require.Equal(t, uint64(77), round)
	round, err = guardedFactory.drwaDestination.currentRound()
	require.NoError(t, err)
	require.Equal(t, uint64(77), round)
}

func TestNewDRWATransferGuardRejectsDelegateWithoutPayableChecker(t *testing.T) {
	t.Parallel()

	guard, err := newDRWATransferGuard(
		core.BuiltInFunctionESDTTransfer,
		&vmcommonMock.BuiltInFunctionStub{},
		func(_ []byte) (bool, error) { return false, nil },
		&vmcommonMock.EnableEpochsHandlerStub{},
		&testscommon.ShardsCoordinatorMock{},
		7,
		func() (uint64, error) { return 1, nil },
	)
	require.Nil(t, guard)
	require.ErrorIs(t, err, ErrInvalidDRWATransferGuardDelegate)
}

func TestDRWATransferGuardSameShardRegulatedSuccessDelegatesExactBaselineInput(t *testing.T) {
	t.Parallel()

	source := bytes.Repeat([]byte{0x11}, drwaAddressLength)
	destination := bytes.Repeat([]byte{0x22}, drwaAddressLength)
	tokenID := []byte("TOKEN-abcdef")
	receiverBytes, err := drwa.EncodeReceiverGateRecord(drwa.ReceiverGateRecord{
		Holder:            [drwaAddressLength]byte(destination),
		CEBEpoch:          7,
		Admitted:          true,
		ValidThroughRound: 100,
	})
	require.NoError(t, err)
	senderAccount := &vmcommonMocks.UserAccountStub{AddressBytesCalled: func() []byte { return source }}
	destinationAccount := &vmcommonMocks.UserAccountStub{
		AddressBytesCalled: func() []byte { return destination },
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
				require.Equal(t, drwa.ReceiverGateStorageKey(tokenID), key)
				return receiverBytes, 0, nil
			}}
		},
	}
	input := validDRWASameShardTransferInput(source, destination, tokenID)
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 17}
	delegateCalled := false
	delegate := &drwaTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(actualSender, actualDestination vmcommon.UserAccountHandler, actualInput *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		require.Same(t, senderAccount, actualSender)
		require.Same(t, destinationAccount, actualDestination)
		require.Same(t, input, actualInput)
		return output, nil
	}
	guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
		return true, nil
	})

	actual, err := guard.ProcessBuiltinFunction(senderAccount, destinationAccount, input)
	require.NoError(t, err)
	require.Same(t, output, actual)
	require.True(t, delegateCalled)
}

func TestDRWATransferGuardSameShardRegulatedRejectsEveryAdmissionPredicate(t *testing.T) {
	t.Parallel()

	type scenario struct {
		source      []byte
		destination []byte
		input       *vmcommon.ContractCallInput
		guard       *drwaTransferGuard
	}
	tests := []struct {
		name   string
		mutate func(*scenario)
	}{
		{name: "zero CEB", mutate: func(test *scenario) { test.guard.cebEpoch = 0 }},
		{name: "wrong function", mutate: func(test *scenario) { test.input.Function = core.BuiltInFunctionESDTNFTTransfer }},
		{name: "unknown origin", mutate: func(test *scenario) { test.input.NativeCallOrigin = vmcommon.NativeCallOriginUnknown }},
		{name: "callback", mutate: func(test *scenario) { test.input.CallType = vmData.AsynchronousCallBack }},
		{name: "nil call value", mutate: func(test *scenario) { test.input.CallValue = nil }},
		{name: "positive call value", mutate: func(test *scenario) { test.input.CallValue = big.NewInt(1) }},
		{name: "gas lock", mutate: func(test *scenario) { test.input.GasLocked = 1 }},
		{name: "return after error", mutate: func(test *scenario) { test.input.ReturnCallAfterError = true }},
		{name: "async metadata", mutate: func(test *scenario) { test.input.AsyncArguments = &vmcommon.AsyncArguments{CallID: []byte{1}} }},
		{name: "ESDT transfer metadata", mutate: func(test *scenario) {
			test.input.ESDTTransfers = []*vmcommon.ESDTTransfer{{ESDTTokenName: []byte("OTHER-abcdef")}}
		}},
		{name: "wrong argument count", mutate: func(test *scenario) { test.input.Arguments = test.input.Arguments[:1] }},
		{name: "short source", mutate: func(test *scenario) {
			test.source = test.source[:31]
			test.input.CallerAddr = append([]byte(nil), test.source...)
		}},
		{name: "short destination", mutate: func(test *scenario) {
			test.destination = test.destination[:31]
			test.input.RecipientAddr = append([]byte(nil), test.destination...)
		}},
		{name: "self transfer", mutate: func(test *scenario) {
			test.destination = append([]byte(nil), test.source...)
			test.input.RecipientAddr = append([]byte(nil), test.destination...)
		}},
		{name: "smart contract source", mutate: func(test *scenario) {
			test.source = make([]byte, drwaAddressLength)
			test.input.CallerAddr = append([]byte(nil), test.source...)
		}},
		{name: "smart contract destination", mutate: func(test *scenario) {
			test.destination = make([]byte, drwaAddressLength)
			test.input.RecipientAddr = append([]byte(nil), test.destination...)
		}},
		{name: "caller mismatch", mutate: func(test *scenario) { test.input.CallerAddr[0] ^= 0xff }},
		{name: "recipient mismatch", mutate: func(test *scenario) { test.input.RecipientAddr[0] ^= 0xff }},
		{name: "short current hash", mutate: func(test *scenario) { test.input.CurrentTxHash = test.input.CurrentTxHash[:31] }},
		{name: "short original hash", mutate: func(test *scenario) { test.input.OriginalTxHash = test.input.OriginalTxHash[:31] }},
		{name: "short previous hash", mutate: func(test *scenario) { test.input.PrevTxHash = test.input.PrevTxHash[:31] }},
		{name: "original hash mismatch", mutate: func(test *scenario) { test.input.OriginalTxHash[0] ^= 0xff }},
		{name: "previous hash mismatch", mutate: func(test *scenario) { test.input.PrevTxHash[0] ^= 0xff }},
		{name: "zero transaction identity", mutate: func(test *scenario) {
			zero := make([]byte, drwaHashLength)
			test.input.CurrentTxHash = append([]byte(nil), zero...)
			test.input.OriginalTxHash = append([]byte(nil), zero...)
			test.input.PrevTxHash = append([]byte(nil), zero...)
		}},
		{name: "empty quantity", mutate: func(test *scenario) { test.input.Arguments[1] = nil }},
		{name: "oversized quantity", mutate: func(test *scenario) { test.input.Arguments[1] = bytes.Repeat([]byte{1}, 33) }},
		{name: "non-minimal quantity", mutate: func(test *scenario) { test.input.Arguments[1] = []byte{0, 1} }},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			source := bytes.Repeat([]byte{0x11}, drwaAddressLength)
			destination := bytes.Repeat([]byte{0x22}, drwaAddressLength)
			receiverHolder := append([]byte(nil), destination...)
			tokenID := []byte("TOKEN-abcdef")
			delegateCalled := false
			delegate := &drwaTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{}, nil
			}
			guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
				return true, nil
			})
			current := &scenario{source: source, destination: destination, input: validDRWASameShardTransferInput(source, destination, tokenID), guard: guard}
			test.mutate(current)
			senderAccount := &vmcommonMocks.UserAccountStub{AddressBytesCalled: func() []byte { return current.source }}
			destinationAccount := validDRWAReceiverAccount(t, current.destination, receiverHolder, tokenID, 7, 100)

			output, err := guard.ProcessBuiltinFunction(senderAccount, destinationAccount, current.input)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrDRWASameShardTransferDenied)
			require.False(t, delegateCalled)
		})
	}
}

func TestDRWATransferGuardMarkedCrossShardFungibleStillRequiresDRWA(t *testing.T) {
	t.Parallel()

	source := bytes.Repeat([]byte{0x11}, drwaAddressLength)
	destination := bytes.Repeat([]byte{0x22}, drwaAddressLength)
	delegateCalled := false
	delegate := &drwaTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		return &vmcommon.VMOutput{}, nil
	}
	guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
		return true, nil
	})
	guard.shardCoordinator = &testscommon.ShardsCoordinatorMock{NoShards: 2, CurrentShard: 0, ComputeIdCalled: func(address []byte) uint32 {
		if bytes.Equal(address, destination) {
			return 1
		}
		return 0
	}}

	output, err := guard.ProcessBuiltinFunction(
		&vmcommonMocks.UserAccountStub{AddressBytesCalled: func() []byte { return source }},
		&vmcommonMocks.UserAccountStub{AddressBytesCalled: func() []byte { return destination }},
		validDRWASameShardTransferInput(source, destination, []byte("TOKEN-abcdef")),
	)
	require.Nil(t, output)
	require.ErrorIs(t, err, ErrDRWARegulatedTransferRequiresDRWA)
	require.False(t, delegateCalled)
}

func TestDRWATransferGuardSameShardRegulatedReceiverFailuresNeverDelegate(t *testing.T) {
	t.Parallel()

	source := bytes.Repeat([]byte{0x11}, drwaAddressLength)
	destination := bytes.Repeat([]byte{0x22}, drwaAddressLength)
	tokenID := []byte("TOKEN-abcdef")
	tests := map[string]struct {
		record       drwa.ReceiverGateRecord
		encoded      []byte
		retrieveErr  error
		currentRound uint64
		roundErr     error
		nilHandler   bool
	}{
		"missing":   {},
		"malformed": {encoded: []byte{0xff}},
		"not admitted": {
			record: drwa.ReceiverGateRecord{Holder: [drwaAddressLength]byte(destination), CEBEpoch: 7, ValidThroughRound: 100},
		},
		"wrong holder": {
			record: drwa.ReceiverGateRecord{Holder: [drwaAddressLength]byte(source), CEBEpoch: 7, Admitted: true, ValidThroughRound: 100},
		},
		"wrong CEB": {
			record: drwa.ReceiverGateRecord{Holder: [drwaAddressLength]byte(destination), CEBEpoch: 8, Admitted: true, ValidThroughRound: 100},
		},
		"expired": {
			record:       drwa.ReceiverGateRecord{Holder: [drwaAddressLength]byte(destination), CEBEpoch: 7, Admitted: true, ValidThroughRound: 9},
			currentRound: 10,
		},
		"storage failure":       {retrieveErr: errors.New("injected receiver storage failure")},
		"current round failure": {roundErr: errors.New("injected current round failure")},
		"nil data handler":      {nilHandler: true},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			encoded := append([]byte(nil), test.encoded...)
			if test.record.Holder != ([drwaAddressLength]byte{}) {
				var encodeErr error
				encoded, encodeErr = drwa.EncodeReceiverGateRecord(test.record)
				require.NoError(t, encodeErr)
			}
			senderAccount := &vmcommonMocks.UserAccountStub{AddressBytesCalled: func() []byte { return source }}
			destinationAccount := &vmcommonMocks.UserAccountStub{
				AddressBytesCalled: func() []byte { return destination },
				AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
					if test.nilHandler {
						return nil
					}
					return &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(_ []byte) ([]byte, uint32, error) {
						return encoded, 0, test.retrieveErr
					}}
				},
			}
			delegateCalled := false
			delegate := &drwaTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{}, nil
			}
			guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionESDTTransfer, delegate, true, func(_ []byte) (bool, error) {
				return true, nil
			})
			guard.currentRoundProvider = func() (uint64, error) { return test.currentRound, test.roundErr }

			output, err := guard.ProcessBuiltinFunction(senderAccount, destinationAccount, validDRWASameShardTransferInput(source, destination, tokenID))
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrDRWASameShardTransferDenied)
			if test.retrieveErr != nil {
				require.ErrorIs(t, err, test.retrieveErr)
			}
			if test.roundErr != nil {
				require.ErrorIs(t, err, test.roundErr)
			}
			require.False(t, delegateCalled)
		})
	}
}

func validDRWAReceiverAccount(
	t *testing.T,
	accountAddress, receiverHolder, tokenID []byte,
	ceb uint32,
	validThrough uint64,
) *vmcommonMocks.UserAccountStub {
	t.Helper()

	receiverBytes, err := drwa.EncodeReceiverGateRecord(drwa.ReceiverGateRecord{
		Holder:            bytesToDRWAAddress(receiverHolder),
		CEBEpoch:          ceb,
		Admitted:          true,
		ValidThroughRound: validThrough,
	})
	require.NoError(t, err)
	return &vmcommonMocks.UserAccountStub{
		AddressBytesCalled: func() []byte { return accountAddress },
		AccountDataHandlerCalled: func() vmcommon.AccountDataHandler {
			return &trieMock.DataTrieTrackerStub{RetrieveValueCalled: func(key []byte) ([]byte, uint32, error) {
				require.Equal(t, drwa.ReceiverGateStorageKey(tokenID), key)
				return receiverBytes, 0, nil
			}}
		},
	}
}

type drwaTransferDelegateStub struct {
	vmcommonMock.BuiltInFunctionStub
	setPayableCheckerCalled func(payableChecker vmcommon.PayableChecker) error
}

func (stub *drwaTransferDelegateStub) SetPayableChecker(payableChecker vmcommon.PayableChecker) error {
	if stub.setPayableCheckerCalled != nil {
		return stub.setPayableCheckerCalled(payableChecker)
	}
	return nil
}

type drwaPayableCheckerStub struct{}

func (stub *drwaPayableCheckerStub) CheckPayable(_ *vmcommon.ContractCallInput, _ []byte, _ int) error {
	return nil
}
func (stub *drwaPayableCheckerStub) DetermineIsSCCallAfter(_ *vmcommon.ContractCallInput, _ []byte, _ int) bool {
	return false
}
func (stub *drwaPayableCheckerStub) IsInterfaceNil() bool { return stub == nil }

func createDRWATransferGuardForTest(
	t *testing.T,
	functionName string,
	delegate vmcommon.BuiltinFunction,
	active bool,
	classifier drwaTokenClassifier,
) *drwaTransferGuard {
	t.Helper()

	guard, err := newDRWATransferGuard(
		functionName,
		delegate,
		classifier,
		&vmcommonMock.EnableEpochsHandlerStub{
			IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
				require.Equal(t, common.DRWAEnforcementFlag, flag)
				return active
			},
		},
		&testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: 0, ComputeIdCalled: func(_ []byte) uint32 { return 0 }},
		7,
		func() (uint64, error) { return 10, nil },
	)
	require.NoError(t, err)

	return guard
}

func validDRWASameShardTransferInput(source, destination, tokenID []byte) *vmcommon.ContractCallInput {
	txHash := bytes.Repeat([]byte{0x33}, drwaHashLength)
	return &vmcommon.ContractCallInput{
		Function:      core.BuiltInFunctionESDTTransfer,
		RecipientAddr: append([]byte(nil), destination...),
		VMInput: vmcommon.VMInput{
			CallerAddr:       append([]byte(nil), source...),
			CallValue:        big.NewInt(0),
			GasProvided:      1_000_000,
			Arguments:        [][]byte{append([]byte(nil), tokenID...), {1}},
			CurrentTxHash:    append([]byte(nil), txHash...),
			OriginalTxHash:   append([]byte(nil), txHash...),
			PrevTxHash:       append([]byte(nil), txHash...),
			NativeCallOrigin: vmcommon.NativeCallOriginOriginalUserTransaction,
			CallType:         vmData.DirectCall,
		},
	}
}

func drwaSenderMultiArguments(firstToken, secondToken []byte) [][]byte {
	return [][]byte{
		make([]byte, 32), {2},
		firstToken, {0}, {1},
		secondToken, {0}, {2},
	}
}

func drwaDestinationMultiArguments(firstToken, secondToken []byte) [][]byte {
	return [][]byte{
		{2},
		firstToken, {0}, {1},
		secondToken, {0}, {2},
	}
}

func countDRWATransferGuards(t *testing.T, container vmcommon.BuiltInFunctionContainer) int {
	t.Helper()

	count := 0
	for functionName := range container.Keys() {
		function, err := container.Get(functionName)
		require.NoError(t, err)
		if _, ok := function.(*drwaTransferGuard); ok {
			count++
		}
	}

	return count
}

func requireDRWATransferGuardNames(t *testing.T, container vmcommon.BuiltInFunctionContainer) {
	t.Helper()

	for _, functionName := range []string{
		core.BuiltInFunctionESDTTransfer,
		core.BuiltInFunctionESDTNFTTransfer,
		core.BuiltInFunctionMultiESDTNFTTransfer,
	} {
		function, err := container.Get(functionName)
		require.NoError(t, err)
		guard, ok := function.(*drwaTransferGuard)
		require.True(t, ok)
		require.Equal(t, functionName, guard.functionName)
	}
}
