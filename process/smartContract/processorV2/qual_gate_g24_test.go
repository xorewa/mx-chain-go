package processorV2

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Experimental input coordinates; signature authentication is bound separately.
func TestQualGateG24GuardianFollowOn(t *testing.T) {
	args := createMockSmartContractProcessorArguments()
	args.ArgsParser = smartContract.NewArgumentParser()
	sc, err := NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	sender, receiver := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	guardian, relayer := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	current := []byte("experimental-current-hash")
	tx := &transaction.Transaction{SndAddr: sender, RcvAddr: receiver, GuardianAddr: guardian, RelayerAddr: relayer,
		Options: transaction.MaskGuardedTransaction, Value: big.NewInt(0), Data: []byte("route@01"), GasPrice: 3, GasLimit: 1000000}
	input, err := sc.createVMCallInput(tx, current, true)
	require.NoError(t, err)
	assertIdentity := func(got *vmcommon.ContractCallInput) {
		require.Equal(t, guardian, got.TxGuardian)
		require.Equal(t, relayer, got.RelayerAddr)
		require.Equal(t, sender, got.CallerAddr)
		require.Equal(t, sender, got.OriginalCallerAddr)
		require.Equal(t, current, got.OriginalTxHash)
		require.Equal(t, current, got.CurrentTxHash)
		require.Equal(t, current, got.PrevTxHash)
		require.Equal(t, uint64(3), got.GasPrice)
		require.Zero(t, got.GasLocked)
	}
	assertIdentity(input)
	parsed := &vmcommon.ParsedESDTTransfers{RcvAddr: receiver, CallFunction: "followOn", CallArgs: [][]byte{{1}}, ESDTTransfers: []*vmcommon.ESDTTransfer{{ESDTTokenName: []byte("TEST-123456"), ESDTValue: big.NewInt(7)}}}
	output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 19}
	for _, callType := range []vmData.CallType{vmData.DirectCall, vmData.AsynchronousCallBack} {
		follow, _, err := sc.prepareExecutionAfterBuiltInFunc(&inputDataAfterBuiltInCall{
			callType: callType, vmInput: input, vmOutput: output, parsedTransfer: parsed, scExecuteOutTransfer: &vmcommon.OutputTransfer{GasLimit: 17},
		})
		require.NoError(t, err)
		assertIdentity(follow)
		require.Equal(t, receiver, follow.RecipientAddr)
		require.Equal(t, parsed.ESDTTransfers, follow.ESDTTransfers)
		require.Zero(t, follow.CallValue.Sign())
		require.Equal(t, callType, follow.CallType)
		if callType == vmData.DirectCall {
			require.Equal(t, "followOn", follow.Function)
			require.Equal(t, uint64(17), follow.GasProvided)
			require.Equal(t, [][]byte{{1}}, follow.Arguments)
		} else {
			require.Equal(t, "callBack", follow.Function)
			require.Equal(t, uint64(19), follow.GasProvided)
			require.Equal(t, [][]byte{[]byte("\x00")}, follow.Arguments)
		}
	}
}
