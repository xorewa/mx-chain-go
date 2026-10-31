package systemSmartContracts

import (
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// This double isolates classification errors from the separate owner-health route.
type qualGateG22FaultClassifier struct{ failure error }

func (c *qualGateG22FaultClassifier) IsInterfaceNil() bool { return c == nil }
func (c *qualGateG22FaultClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return nil
}
func (c *qualGateG22FaultClassifier) WithTokenClassification(_ state.AccountsAdapter, _ []byte, execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if c.failure != nil {
		return nil, c.failure
	}
	return execute(false)
}

func TestQualGateG22ClassifierErrorLatch(t *testing.T) {
	cause := errors.New("experimental classifier unavailable")
	classifier := &qualGateG22FaultClassifier{failure: cause}
	args := createDefaultEeiArgs()
	args.DRWAClassifier = classifier
	host, err := NewVMContext(args)
	require.NoError(t, err)
	input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: core.ESDTSCAddress, Arguments: [][]byte{[]byte("TEST-123456")}, CallValue: big.NewInt(0)}, RecipientAddr: core.ESDTSCAddress, Function: "pause"}
	called := false
	execute := func() (*vmcommon.VMOutput, error) {
		called = true
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}
	out, first := host.ExecuteDRWASystemCall(input, execute)
	require.Nil(t, out)
	require.ErrorIs(t, first, cause)
	require.ErrorIs(t, first, vm.ErrDRWAExecution)
	require.False(t, called)
	classifier.failure = nil
	host.CleanCache()
	out, err = host.ExecuteDRWASystemCall(input, execute)
	require.Nil(t, out)
	require.Same(t, first, err)
	require.False(t, called)
	require.Same(t, first, host.DRWAExecutionError())
}
