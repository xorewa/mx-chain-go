package builtInFunctions

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

func TestS1AddendumMultiTransferRegulatedLegEveryPositionDeniesBeforeDelegate(t *testing.T) {
	tokens := [][]byte{[]byte("FIRST-abcdef"), []byte("SECOND-abcdef"), []byte("THIRD-abcdef")}
	for markedIndex := range tokens {
		markedIndex := markedIndex
		t.Run(string(rune('0'+markedIndex)), func(t *testing.T) {
			arguments := [][]byte{{3}}
			for index, tokenID := range tokens {
				arguments = append(arguments, append([]byte(nil), tokenID...), []byte{0}, []byte{byte(index + 1)})
			}
			input := &vmcommon.ContractCallInput{
				RecipientAddr: []byte("destination"),
				VMInput:       vmcommon.VMInput{CallerAddr: []byte("source"), Arguments: arguments},
			}
			delegateCalled := false
			delegate := &drwaTransferDelegateStub{}
			delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
				delegateCalled = true
				return &vmcommon.VMOutput{}, nil
			}
			guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionMultiESDTNFTTransfer, delegate, true, func(tokenID []byte) (bool, error) {
				return string(tokenID) == string(tokens[markedIndex]), nil
			})
			output, err := guard.ProcessBuiltinFunction(nil, nil, input)
			require.Nil(t, output)
			require.ErrorIs(t, err, ErrDRWARegulatedTransferRequiresDRWA)
			require.False(t, delegateCalled)
		})
	}
}

func TestS1AddendumOrdinaryOnlyMultiTransferPreservesDelegateRoute(t *testing.T) {
	delegateCalled := false
	delegate := &drwaTransferDelegateStub{}
	delegate.ProcessBuiltinFunctionCalled = func(_, _ vmcommon.UserAccountHandler, _ *vmcommon.ContractCallInput) (*vmcommon.VMOutput, error) {
		delegateCalled = true
		return &vmcommon.VMOutput{}, nil
	}
	guard := createDRWATransferGuardForTest(t, core.BuiltInFunctionMultiESDTNFTTransfer, delegate, true, func(_ []byte) (bool, error) { return false, nil })
	input := &vmcommon.ContractCallInput{RecipientAddr: []byte("destination"), VMInput: vmcommon.VMInput{
		CallerAddr: []byte("source"), Arguments: drwaDestinationMultiArguments([]byte("FIRST-abcdef"), []byte("SECOND-abcdef")),
	}}
	_, err := guard.ProcessBuiltinFunction(nil, nil, input)
	require.NoError(t, err)
	require.True(t, delegateCalled)
}
