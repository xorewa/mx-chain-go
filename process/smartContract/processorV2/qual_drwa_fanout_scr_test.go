package processorV2

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Source-shaped EEI output, not an implementation-generated expected oracle.
// Real V2 output processing is exercised. No miniblock/P2P/finality or receiver
// authentication credit follows from ordered creation of these SCRs.
func TestQualDRWAV2FanoutSCRSenderAndIndexOrdering(t *testing.T) {
	for _, receiver := range [][]byte{core.ESDTSCAddress, bytes.Repeat([]byte{0x42}, 32)} {
		t.Run(hex.EncodeToString(receiver), func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: core.MetachainShardId, ComputeIdCalled: func(address []byte) uint32 { return uint32(address[len(address)-1]) }}
			args.ArgsParser = smartContract.NewArgumentParser()
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			caller := bytes.Repeat([]byte{1}, 32)
			hash := []byte("source transaction hash")
			tx := &transaction.Transaction{SndAddr: caller, RcvAddr: receiver, Value: big.NewInt(0), GasPrice: 7}
			payloads := [][]byte{[]byte(vmcommon.BuiltInFunctionESDTSetBurnRoleForAll + "@544f4b454e2d303030303031"), []byte(core.ESDTSetTokenType + "@544f4b454e2d303030303031@" + hex.EncodeToString([]byte(core.FungibleESDT)))}
			vmOutput := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: make(map[string]*vmcommon.OutputAccount)}
			for shard := byte(0); shard < 3; shard++ {
				address := bytes.Clone(core.SystemAccountAddress)
				address[len(address)-1] = shard
				vmOutput.OutputAccounts[string(address)] = &vmcommon.OutputAccount{Address: address, BalanceDelta: big.NewInt(0), OutputTransfers: []vmcommon.OutputTransfer{
					{Index: 1 + uint32(shard), Value: big.NewInt(0), Data: bytes.Clone(payloads[0]), CallType: vmData.DirectCall},
					{Index: 4 + uint32(shard), Value: big.NewInt(0), Data: bytes.Clone(payloads[1]), CallType: vmData.DirectCall},
				}}
			}
			callback, results, err := NewVMOutputAccountsProcessor(sc, &vmcommon.VMInput{CallType: vmData.DirectCall}, vmOutput, tx, hash).Run()
			require.NoError(t, err)
			require.False(t, callback)
			require.Len(t, results, 6)
			for index, result := range results {
				scr, ok := result.(*smartContractResult.SmartContractResult)
				require.True(t, ok)
				shard := byte(index % 3)
				step := index / 3
				address := bytes.Clone(core.SystemAccountAddress)
				address[len(address)-1] = shard
				require.Equal(t, address, scr.RcvAddr, "creation order follows transfer indices, not address grouping")
				require.Equal(t, payloads[step], scr.Data)
				require.Equal(t, receiver, scr.SndAddr, "sender comes from the source transaction recipient")
				require.Equal(t, caller, scr.OriginalSender)
				require.Equal(t, hash, scr.PrevTxHash)
				require.Equal(t, hash, scr.OriginalTxHash)
				require.Equal(t, uint64(step), scr.Nonce, "per-account output position is distinct from global transfer index")
				require.Zero(t, scr.Value.Sign())
				require.Zero(t, scr.GasLimit)
				require.Equal(t, uint64(7), scr.GasPrice)
				require.Equal(t, vmData.DirectCall, scr.CallType)
			}
		})
	}
}
