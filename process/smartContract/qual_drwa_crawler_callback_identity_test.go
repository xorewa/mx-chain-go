package smartContract

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/testscommon/economicsmocks"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// A native component counterexample to absolute CallerAddr exclusion, not a
// crawler bypass or an end-to-end asynchronous-delivery qualification.
// Expected identities: upstream 06c383cf process.go L2086-2087/L2110-2118;
// vmInput.go L40. CallerAddr is provenance, not proof that that caller signed.
func TestQualDRWACrawlerNativeFailureCallbackIdentity(t *testing.T) {
	crawler := make([]byte, 32)
	crawler[0] = 1 // The native-rejected shard-0 candidate.
	contract := make([]byte, 32)
	contract[8] = 5
	coordinator, err := sharding.NewMultiShardCoordinator(3, 0)
	require.NoError(t, err)
	feeCalls, processingFeeCalls := 0, 0
	sc := &scProcessor{
		shardCoordinator: coordinator,
		argsParser:       NewArgumentParser(),
		enableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(
			common.SCDeployFlag, common.RepairCallbackFlag, common.PenalizedTooMuchGasFlag),
		economicsFee: &economicsmocks.EconomicsHandlerMock{
			ComputeTxFeeCalled: func(tx data.TransactionWithFeeHandler) *big.Int {
				feeCalls++
				return core.SafeMul(tx.GetGasLimit(), tx.GetGasPrice())
			},
			ComputeFeeForProcessingCalled: func(tx data.TransactionWithFeeHandler, gas uint64) *big.Int {
				processingFeeCalls++
				return core.SafeMul(gas, tx.GetGasPrice())
			},
		},
	}
	request := &smartContractResult.SmartContractResult{
		SndAddr: contract, RcvAddr: crawler, Value: big.NewInt(0),
		GasLimit: 100, GasPrice: 1, CallType: vmData.AsynchronousCall,
		Data: []byte(vmcommon.ESDTAddMetadata),
	}
	callback, _ := sc.createSCRsWhenError(nil, []byte("native component hash"), request,
		"user error", []byte("unauthorized caller"), 20)
	require.Equal(t, 1, feeCalls)
	require.Equal(t, 1, processingFeeCalls)
	require.Equal(t, crawler, callback.SndAddr)
	require.Equal(t, contract, callback.RcvAddr)
	require.Equal(t, vmData.AsynchronousCallBack, callback.CallType)
	input, err := sc.createVMCallInput(callback, []byte("callback component hash"), false)
	require.NoError(t, err)
	require.Equal(t, crawler, input.CallerAddr)
	require.Equal(t, contract, input.RecipientAddr)
	require.Equal(t, "callBack", input.Function)
	require.NotEqual(t, input.CallerAddr, input.RecipientAddr,
		"this native callback does not satisfy crawler caller==recipient authorization")
}
