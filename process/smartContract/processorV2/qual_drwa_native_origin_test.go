package processorV2

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process/block/postprocess"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/testscommon"
	orderStub "github.com/multiversx/mx-chain-go/testscommon/common"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	storageStub "github.com/multiversx/mx-chain-go/testscommon/storage"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// These tests observe pinned native identity propagation for G3/AR-01.
// The supplied hashes are fixtures, not canonical-origin proofs. No DRWA
// identity derivation, namespace, finality predicate or production format is selected.
func TestQualDRWANativeOriginVMInput(t *testing.T) {
	for _, name := range []string{"direct", "relayed_v3", "nested_scr", "async", "callback", "return_after_error", "missing_original"} {
		t.Run(name, func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.ArgsParser = smartContract.NewArgumentParser()
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			current, original, previous := []byte("current-execution"), []byte("root-transaction"), []byte("parent-execution")
			sender, receiver, firstCaller := []byte("sender"), []byte("receiver"), []byte("original-caller")
			tx := &transaction.Transaction{SndAddr: sender, RcvAddr: receiver, Value: big.NewInt(0), Data: []byte("route"), GasLimit: 100, GasPrice: 3}
			var inputTx data.TransactionHandler = tx
			wantOriginal, wantPrevious, wantCaller := current, current, sender
			wantCallType := vmData.DirectCall
			if name == "relayed_v3" {
				tx.RelayerAddr = []byte("relayer")
			}
			if name != "direct" && name != "relayed_v3" {
				scr := &smartContractResult.SmartContractResult{SndAddr: sender, RcvAddr: receiver, OriginalSender: firstCaller, Value: big.NewInt(0), Data: []byte("route"), GasLimit: 100, GasPrice: 3, OriginalTxHash: original, PrevTxHash: previous}
				switch name {
				case "async":
					scr.CallType = vmData.AsynchronousCall
					scr.Data = []byte("route@aa@bb@00")
				case "callback":
					scr.CallType = vmData.AsynchronousCallBack
					scr.Data = []byte("@00@aa@bb@cc@00")
				case "return_after_error":
					scr.ReturnMessage = []byte("upstream error")
				case "missing_original":
					scr.OriginalTxHash = nil
					original = nil
				}
				inputTx = scr
				wantOriginal = original
				wantPrevious = previous
				wantCaller = firstCaller
				wantCallType = scr.CallType
			}
			in, err := sc.createVMCallInput(inputTx, current, false)
			require.NoError(t, err)
			require.Equal(t, current, in.CurrentTxHash)
			require.Equal(t, wantOriginal, in.OriginalTxHash)
			require.Equal(t, wantPrevious, in.PrevTxHash)
			require.Equal(t, wantCaller, in.OriginalCallerAddr)
			require.Equal(t, sender, in.CallerAddr)
			require.Equal(t, wantCallType, in.CallType)
			require.Equal(t, name == "return_after_error", in.ReturnCallAfterError)
			if name == "relayed_v3" {
				require.Equal(t, tx.RelayerAddr, in.RelayerAddr)
			}
			if name == "async" || name == "callback" {
				require.Equal(t, []byte{0xaa}, in.AsyncArguments.CallID)
				require.Equal(t, []byte{0xbb}, in.AsyncArguments.CallerCallID)
			}
			if name == "callback" {
				require.Equal(t, []byte{0xcc}, in.AsyncArguments.CallbackAsyncInitiatorCallID)
			}
		})
	}
}

// Run the real output-account processor and real native serialization/hash.
// OriginalTxHash identifies a lineage, not a unique sibling leg. Nor does a
// content hash establish canonical execution: no carrying/executed header is
// an input to this SCR hash. Network authentication remains a separate obligation.
func TestQualDRWANativeOriginSiblingResults(t *testing.T) {
	for _, nested := range []bool{false, true} {
		name := "direct"
		if nested {
			name = "nested"
		}
		t.Run(name, func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.ArgsParser = smartContract.NewArgumentParser()
			args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: 0, ComputeIdCalled: func(a []byte) uint32 { return uint32(a[len(a)-1]) }}
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			current, original := []byte("current-parent"), []byte("root-transaction")
			caller, contract := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
			caller[31] = 0
			contract[31] = 0
			var tx data.TransactionHandler = &transaction.Transaction{SndAddr: caller, RcvAddr: contract, Value: big.NewInt(0), GasPrice: 3}
			wantOriginal := current
			if nested {
				tx = &smartContractResult.SmartContractResult{SndAddr: caller, RcvAddr: contract, OriginalSender: []byte("original-caller"), Value: big.NewInt(0), GasPrice: 3, OriginalTxHash: original, PrevTxHash: []byte("grandparent")}
				wantOriginal = original
			}
			out := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: map[string]*vmcommon.OutputAccount{}}
			for shard := byte(1); shard <= 2; shard++ {
				addr := bytes.Repeat([]byte{4}, 32)
				addr[31] = shard
				out.OutputAccounts[string(addr)] = &vmcommon.OutputAccount{Address: addr, BalanceDelta: big.NewInt(0), OutputTransfers: []vmcommon.OutputTransfer{
					{Index: uint32(shard), Value: big.NewInt(0), Data: []byte("first"), CallType: vmData.DirectCall},
					{Index: 2 + uint32(shard), Value: big.NewInt(0), Data: []byte("second"), CallType: vmData.DirectCall},
				}}
			}
			callback, results, err := NewVMOutputAccountsProcessor(sc, &vmcommon.VMInput{CallType: vmData.DirectCall}, out, tx, current).Run()
			require.NoError(t, err)
			require.False(t, callback)
			require.Len(t, results, 4)
			m, h := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
			hashes := map[string]bool{}
			expectedByShard := map[uint32][][]byte{}
			for i, r := range results {
				scr, ok := r.(*smartContractResult.SmartContractResult)
				require.True(t, ok)
				require.Equal(t, wantOriginal, scr.OriginalTxHash)
				require.Equal(t, current, scr.PrevTxHash)
				require.Equal(t, uint64(i/2), scr.Nonce)
				require.Equal(t, byte(1+i%2), scr.RcvAddr[31])
				require.Equal(t, contract, scr.SndAddr)
				require.NoError(t, scr.CheckIntegrity())
				hash, err := core.CalculateHash(m, h, scr)
				require.NoError(t, err)
				require.False(t, hashes[string(hash)], "distinct source-shaped sibling results must not collapse in this fixture")
				hashes[string(hash)] = true
				shardID := uint32(scr.RcvAddr[31])
				expectedByShard[shardID] = append(expectedByShard[shardID], hash)
				encoded, err := m.Marshal(scr)
				require.NoError(t, err)
				restored := &smartContractResult.SmartContractResult{}
				require.NoError(t, m.Unmarshal(restored, encoded))
				restoredHash, err := core.CalculateHash(m, h, restored)
				require.NoError(t, err)
				require.Equal(t, hash, restoredHash)
				require.Equal(t, wantOriginal, restored.OriginalTxHash)
				require.Equal(t, current, restored.PrevTxHash)
				restored.Data = append(restored.Data, []byte("-changed")...)
				changedHash, err := core.CalculateHash(m, h, restored)
				require.NoError(t, err)
				require.NotEqual(t, hash, changedHash)
			}
			// Connect the real producer to its real miniblock consumer. Ordering modes
			// use the same content identities; neither mode supplies finality.
			for _, keepOrder := range []bool{false, true} {
				orderName := "hash_order"
				if keepOrder {
					orderName = "execution_order"
				}
				t.Run(orderName, func(t *testing.T) {
					flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.KeepExecOrderOnCreatedSCRsFlag)
					flags.IsFlagEnabledCalled = func(flag core.EnableEpochFlag) bool {
						return flag == common.KeepExecOrderOnCreatedSCRsFlag && keepOrder
					}
					forwarder, err := postprocess.NewIntermediateResultsProcessor(postprocess.ArgsNewIntermediateResultsProcessor{
						Hasher: h, Marshalizer: m, Coordinator: args.ShardCoordinator, PubkeyConv: args.PubkeyConv,
						Store: &storageStub.ChainStorerStub{}, BlockType: block.SmartContractResultBlock,
						CurrTxs: &mock.TxForCurrentBlockStub{}, EconomicsFee: args.EconomicsFee,
						EnableEpochsHandler: flags, TxExecutionOrderHandler: &orderStub.TxExecutionOrderHandlerStub{},
					})
					require.NoError(t, err)
					for attempt := 0; attempt < 2; attempt++ {
						require.NoError(t, forwarder.AddIntermediateTransactions(results, current))
						mbs := forwarder.CreateAllInterMiniBlocks()
						require.Len(t, mbs, 2)
						for _, mb := range mbs {
							require.Equal(t, uint32(0), mb.SenderShardID)
							require.Equal(t, block.SmartContractResultBlock, mb.Type)
							expected, ok := expectedByShard[mb.ReceiverShardID]
							require.True(t, ok)
							require.Len(t, mb.TxHashes, 2)
							require.ElementsMatch(t, expected, mb.TxHashes)
							if keepOrder {
								require.Equal(t, expected, mb.TxHashes)
							} else {
								require.Negative(t, bytes.Compare(mb.TxHashes[0], mb.TxHashes[1]))
							}
						}
					}
				})
			}
		})
	}
}

func TestQualDRWANativeOriginRefundBeneficiaries(t *testing.T) {
	for _, name := range []string{"direct", "relayed_v3", "relayed_scr", "callback"} {
		t.Run(name, func(t *testing.T) {
			args := createMockSmartContractProcessorArguments()
			args.ArgsParser = smartContract.NewArgumentParser()
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			current, original := []byte("current"), []byte("root")
			sender, receiver, relayer := []byte("sender"), []byte("target"), []byte("relayr")
			tx := &transaction.Transaction{SndAddr: sender, RcvAddr: receiver, Value: big.NewInt(13), GasPrice: 3, GasLimit: 100, Data: []byte("route")}
			var input data.TransactionHandler = tx
			callType := vmData.DirectCall
			wantOriginal, wantBeneficiary := current, sender
			if name == "relayed_v3" {
				tx.RelayerAddr = relayer
			}
			if name == "relayed_scr" || name == "callback" {
				scr := &smartContractResult.SmartContractResult{SndAddr: sender, RcvAddr: receiver, Value: big.NewInt(13), GasPrice: 3, GasLimit: 100, Data: []byte("route"), OriginalTxHash: original, PrevTxHash: []byte("previous"), OriginalSender: []byte("original-sender")}
				if name == "relayed_scr" {
					scr.RelayerAddr = relayer
					scr.RelayedValue = big.NewInt(0)
				}
				if name == "callback" {
					scr.CallType = vmData.AsynchronousCallBack
					callType = scr.CallType
					wantBeneficiary = receiver
				}
				input = scr
				wantOriginal = original
			}
			output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 7}
			senderRefund, relayerRefund := sc.createSCRForSenderAndRelayer(output, input, current, callType)
			require.Equal(t, wantOriginal, senderRefund.OriginalTxHash)
			require.Equal(t, current, senderRefund.PrevTxHash)
			require.Equal(t, wantBeneficiary, senderRefund.RcvAddr)
			if name == "relayed_v3" || name == "relayed_scr" {
				require.NotNil(t, relayerRefund)
				require.Equal(t, relayer, relayerRefund.RcvAddr)
				require.Equal(t, wantOriginal, relayerRefund.OriginalTxHash)
				require.Equal(t, current, relayerRefund.PrevTxHash)
				require.Zero(t, senderRefund.Value.Sign())
				require.Equal(t, big.NewInt(21), relayerRefund.Value)
			} else {
				require.Nil(t, relayerRefund)
				require.Equal(t, big.NewInt(21), senderRefund.Value)
			}
			// This is SCR construction, not account credit or DRWA refund qualification.
			failure, _ := sc.createSCRsWhenError(nil, current, input, "user error", []byte("failure"), 0)
			require.Equal(t, wantOriginal, failure.OriginalTxHash)
			require.Equal(t, current, failure.PrevTxHash)
			require.Equal(t, wantBeneficiary, failure.RcvAddr)
			require.Equal(t, big.NewInt(13), failure.Value)
		})
	}
}

func TestQualDRWANativeOriginIntegrityIsNotProvenance(t *testing.T) {
	// Native structural integrity checks PrevTxHash, not OriginalTxHash. This
	// direct helper observation does not establish acceptance by the whole node.
	scr := &smartContractResult.SmartContractResult{SndAddr: []byte("sender"), RcvAddr: []byte("receiver"), Value: big.NewInt(0), PrevTxHash: []byte("parent")}
	require.NoError(t, scr.CheckIntegrity())
	scr.OriginalTxHash = []byte("unverified-claim")
	require.NoError(t, scr.CheckIntegrity())
	scr.PrevTxHash = nil
	require.ErrorIs(t, scr.CheckIntegrity(), data.ErrNilTxHash)
}
