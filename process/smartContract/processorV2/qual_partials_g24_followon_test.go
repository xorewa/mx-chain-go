package processorV2

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Distinct SCR hashes and original/current callers detect substitutions which
// a direct transaction's equal original/current/previous hashes cannot expose.
func TestQualPartialsG24FollowOnIdentities(t *testing.T) {
	for _, route := range []string{"guarded-tx", "scr-direct", "scr-callback"} {
		t.Run(route, func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.ArgsParser = smartContract.NewArgumentParser()
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			sender, receiver, guardian, relayer, original := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32)
			current, previous, first := []byte("current-hash"), []byte("previous-hash"), []byte("original-hash")
			var input *vmcommon.ContractCallInput
			if route == "guarded-tx" {
				tx := &transaction.Transaction{SndAddr: sender, RcvAddr: receiver, GuardianAddr: guardian, RelayerAddr: relayer, Options: transaction.MaskGuardedTransaction, Value: big.NewInt(0), Data: []byte("route@01"), GasPrice: 3, GasLimit: 1000000}
				input, err = sc.createVMCallInput(tx, current, true)
				original, previous, first = sender, current, current
			} else {
				scr := &smartContractResult.SmartContractResult{SndAddr: sender, RcvAddr: receiver, OriginalSender: original, RelayerAddr: relayer, RelayedValue: big.NewInt(0), OriginalTxHash: first, PrevTxHash: previous, Value: big.NewInt(0), Data: []byte("route@01"), GasPrice: 3, GasLimit: 1000000}
				if route == "scr-callback" {
					scr.CallType = vmData.AsynchronousCallBack
					scr.Data = []byte("route@01@aa@bb@cc@05")
				}
				input, err = sc.createVMCallInput(scr, current, true)
				guardian = nil // SCR carries no transaction guardian in the pinned input decoder.
			}
			require.NoError(t, err)
			for _, hasTransfer := range []bool{false, true} {
				parsed := &vmcommon.ParsedESDTTransfers{RcvAddr: receiver, CallFunction: "followOn", CallArgs: [][]byte{{1}}, ESDTTransfers: []*vmcommon.ESDTTransfer{{ESDTTokenName: []byte("TEST-123456"), ESDTValue: big.NewInt(7)}}}
				output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 19}
				if hasTransfer {
					output.OutputAccounts = map[string]*vmcommon.OutputAccount{string(receiver): {Address: receiver, OutputTransfers: []vmcommon.OutputTransfer{{GasLimit: 17, Data: []byte("@aa@bb")}}}}
				}
				follow, _, followErr := sc.prepareExecutionAfterBuiltInFunc(&inputDataAfterBuiltInCall{callType: input.CallType, vmInput: input, vmOutput: output, parsedTransfer: parsed, scExecuteOutTransfer: &vmcommon.OutputTransfer{GasLimit: 17}})
				require.NoError(t, followErr)
				require.Equal(t, sender, follow.CallerAddr)
				require.Equal(t, original, follow.OriginalCallerAddr)
				require.Equal(t, guardian, follow.TxGuardian)
				require.Equal(t, relayer, follow.RelayerAddr)
				require.Equal(t, current, follow.CurrentTxHash)
				require.Equal(t, previous, follow.PrevTxHash)
				require.Equal(t, first, follow.OriginalTxHash)
				require.Same(t, input.AsyncArguments, follow.AsyncArguments)
				require.Equal(t, input.CallType, follow.CallType)
				require.Equal(t, receiver, follow.RecipientAddr)
				require.Equal(t, parsed.ESDTTransfers, follow.ESDTTransfers)
				if route == "scr-callback" {
					require.Equal(t, "callBack", follow.Function)
					if hasTransfer {
						require.Equal(t, uint64(17), follow.GasProvided)
						require.Equal(t, [][]byte{[]byte(""), {0xaa}, {0xbb}}, follow.Arguments)
					} else {
						require.Equal(t, uint64(19), follow.GasProvided)
						require.Equal(t, [][]byte{{0}}, follow.Arguments)
					}
				} else {
					require.Equal(t, "followOn", follow.Function)
					require.Equal(t, uint64(17), follow.GasProvided)
					require.Equal(t, parsed.CallArgs, follow.Arguments)
				}
			}
		})
	}
}
