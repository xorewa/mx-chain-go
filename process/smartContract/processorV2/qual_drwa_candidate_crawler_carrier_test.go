package processorV2

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	marshalFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

// T09 M13: synthetic output inputs to native SCR/receiving components only.
// These tests do not authenticate VM output or execute a contract/token effect.
func qualDRWACandidateCrawlerProcessor(t *testing.T, shardID, epoch uint32) (*scProcessor, [][]byte) {
	t.Helper()
	candidate := qualDRWACandidateFixtureDir(t)
	cfg, err := common.LoadMainConfig(filepath.Join(candidate, "config.toml"))
	require.NoError(t, err)
	epochs, err := common.LoadEpochConfig(filepath.Join(candidate, "enableEpochs.toml"))
	require.NoError(t, err)
	converter, err := converterFactory.NewPubkeyConverter(cfg.AddressPubkeyConverter)
	require.NoError(t, err)
	literals := []string{"0100000000000000000000000000000000000000000000000000000000000000", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"}
	require.Len(t, cfg.BuiltInFunctions.AutomaticCrawlerAddresses, len(literals))
	addresses := make([][]byte, len(literals))
	coordinator, err := sharding.NewMultiShardCoordinator(3, shardID)
	require.NoError(t, err)
	for i, encoded := range cfg.BuiltInFunctions.AutomaticCrawlerAddresses {
		addresses[i], err = converter.Decode(encoded)
		require.NoError(t, err)
		literal, err := hex.DecodeString(literals[i])
		require.NoError(t, err)
		require.Equal(t, literal, addresses[i])
		require.Equal(t, uint32(i), coordinator.ComputeId(addresses[i]))
		require.False(t, core.IsSmartContractAddress(addresses[i]))
	}
	notifier := forking.NewGenericEpochNotifier()
	handler, err := enablers.NewEnableEpochsHandler(epochs.EnableEpochs, notifier)
	require.NoError(t, err)
	notifier.CheckEpoch(&block.Header{Epoch: epoch, Round: 440})
	marshaller, err := marshalFactory.NewMarshalizer(cfg.Marshalizer.Type)
	require.NoError(t, err)
	parser, err := parsers.NewESDTTransferParser(marshaller)
	require.NoError(t, err)
	return &scProcessor{shardCoordinator: coordinator, argsParser: smartContract.NewArgumentParser(), enableEpochsHandler: handler, esdtTransferParser: parser}, addresses
}

func TestQualDRWACandidateCrawlerSCRSenderScope(t *testing.T) {
	for _, epoch := range []uint32{0, 3} {
		for sourceShard := uint32(0); sourceShard < 3; sourceShard++ {
			for crawlerShard := uint32(0); crawlerShard < 3; crawlerShard++ {
				t.Run(fmt.Sprintf("epoch_%d_source_%d_crawler_%d", epoch, sourceShard, crawlerShard), func(t *testing.T) {
					sc, addresses := qualDRWACandidateCrawlerProcessor(t, sourceShard, epoch)
					crawler := addresses[crawlerShard]
					contract := make([]byte, 32)
					contract[8] = 5
					contract[31] = byte(sourceShard)
					ordinary := make([]byte, 32)
					ordinary[0] = 2
					tx := &transaction.Transaction{SndAddr: ordinary, RcvAddr: contract, Value: big.NewInt(0), GasPrice: 1}
					outputAccount := &vmcommon.OutputAccount{Address: crawler, OutputTransfers: []vmcommon.OutputTransfer{{Index: 1, Value: big.NewInt(0), Data: []byte("ESDTAddMetadata"), SenderAddress: crawler, CallType: vmData.DirectCall}}}
					output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{string(crawler): outputAccount}}
					callback, results := sc.createSmartContractResults(&vmcommon.VMInput{CallType: vmData.DirectCall}, output, outputAccount, tx, []byte("component hash"))
					require.False(t, callback)
					require.Len(t, results, 1)
					result := results[0].result.(*smartContractResult.SmartContractResult)
					want := contract
					// Independently specified native version/epoch policy; not inferred from result.
					if sourceShard == crawlerShard {
						want = crawler
					}
					require.Equal(t, want, result.SndAddr)
					require.Equal(t, crawler, result.RcvAddr)
					require.Equal(t, []byte("ESDTAddMetadata"), result.Data)
					require.Equal(t, []byte("component hash"), result.OriginalTxHash)
					if sourceShard == crawlerShard {
						require.Equal(t, result.SndAddr, result.RcvAddr, "synthetic local VM output can serialize a matching pair; authentic producer containment is still required")
					} else {
						require.NotEqual(t, result.SndAddr, result.RcvAddr)
					}
				})
			}
		}
	}
}

func TestQualDRWACandidateCrawlerPostTransferScope(t *testing.T) {
	for sourceShard := uint32(0); sourceShard < 3; sourceShard++ {
		for crawlerShard := uint32(0); crawlerShard < 3; crawlerShard++ {
			for _, function := range []string{core.BuiltInFunctionESDTTransfer, core.BuiltInFunctionESDTNFTTransfer, core.BuiltInFunctionMultiESDTNFTTransfer} {
				t.Run(fmt.Sprintf("source_%d_crawler_%d_%s", sourceShard, crawlerShard, function), func(t *testing.T) {
					sc, addresses := qualDRWACandidateCrawlerProcessor(t, sourceShard, 3)
					caller := make([]byte, 32)
					caller[8] = 5
					caller[31] = byte(sourceShard)
					destination := addresses[crawlerShard]
					input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: caller, CallValue: big.NewInt(0)}, RecipientAddr: destination, Function: function}
					switch function {
					case core.BuiltInFunctionESDTTransfer:
						input.Arguments = [][]byte{[]byte("TOKEN-abcdef"), {1}, []byte("ordinaryControl")}
					case core.BuiltInFunctionESDTNFTTransfer:
						input.RecipientAddr = caller
						input.Arguments = [][]byte{[]byte("TOKEN-abcdef"), {1}, {1}, destination, []byte("ordinaryControl")}
					case core.BuiltInFunctionMultiESDTNFTTransfer:
						input.RecipientAddr = caller
						input.Arguments = [][]byte{destination, {1}, []byte("TOKEN-abcdef"), {1}, {1}, []byte("ordinaryControl")}
					}
					output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{string(destination): {Address: destination, OutputTransfers: []vmcommon.OutputTransfer{{Data: []byte("ordinaryControl")}}}}}
					request := &smartContractResult.SmartContractResult{CallType: vmData.DirectCall}
					dispatch, err := sc.isSameShardSCExecutionAfterBuiltInFunc(request, input, output)
					require.NoError(t, err)
					require.False(t, dispatch.isSCCallSelfShard)
				})
			}
		}
		for _, callback := range []bool{false, true} {
			t.Run(fmt.Sprintf("source_%d_same_shard_contract_callback_%t", sourceShard, callback), func(t *testing.T) {
				sc, _ := qualDRWACandidateCrawlerProcessor(t, sourceShard, 3)
				contract := make([]byte, 32)
				contract[8] = 5
				contract[31] = byte(sourceShard)
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: contract, CallValue: big.NewInt(0), Arguments: [][]byte{[]byte("TOKEN-abcdef"), {1}, []byte("ordinaryControl")}}, RecipientAddr: contract, Function: core.BuiltInFunctionESDTTransfer}
				request := &smartContractResult.SmartContractResult{CallType: vmData.DirectCall}
				if callback {
					request.CallType = vmData.AsynchronousCallBack
				}
				output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{string(contract): {Address: contract, OutputTransfers: []vmcommon.OutputTransfer{{Data: []byte("ordinaryControl")}}}}}
				dispatch, err := sc.isSameShardSCExecutionAfterBuiltInFunc(request, input, output)
				require.NoError(t, err)
				require.True(t, dispatch.isSCCallSelfShard, "native dispatch predicate only; no contract executed")
			})
		}
	}
}
