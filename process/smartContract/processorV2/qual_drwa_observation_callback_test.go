package processorV2

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/data/typeConverters/uint64ByteSlice"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/node/external/transactionAPI"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/smartContract"
	"github.com/multiversx/mx-chain-go/testscommon"
	poolMocks "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	historyMocks "github.com/multiversx/mx-chain-go/testscommon/dblookupext"
	storageMocks "github.com/multiversx/mx-chain-go/testscommon/storage"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	datafield "github.com/multiversx/mx-chain-vm-common-go/parsers/dataField"
	"github.com/stretchr/testify/require"
)

// Independent published-field protobuf vectors, specified before execution in
// T34 model04. No candidate-tree file reads, serializer-derived expectations,
// actual transaction, VM guest execution, canonicality or settlement credit.
const qualDRWAObservationCallbackVectors = `[{"name":"plain/no_async/ok","relayed":false,"async":false,"return_code":0,"message":"","data":"@00@0102@","wire_hex":"120200001a2001010101010101010101010101010101010101010101010101010101010101012220020202020202020202020202020202020202020202020202020202020202020232010042094030304030313032404a01aa5201bb581f600768028201200303030303030303030303030303030303030303030303030303030303030303"},{"name":"plain/no_async/denied","relayed":false,"async":false,"return_code":4,"message":"denied","data":"@04@64656e696564@0102@","wire_hex":"120200001a200101010101010101010101010101010101010101010101010101010101010101222002020202020202020202020202020202020202020202020202020202020202023201004216403034403634363536653639363536344030313032404a01aa5201bb581f600768027a0664656e6965648201200303030303030303030303030303030303030303030303030303030303030303"},{"name":"plain/async/ok","relayed":false,"async":true,"return_code":0,"message":"","data":"@00@0102@@a187a783807d78a12fb046fd2099f34bde7002ac2b29182ccfd35d6450bfb51d@a1b2c3@d4e5@00","wire_hex":"120200001a20010101010101010101010101010101010101010101010101010101010101010122200202020202020202020202020202020202020202020202020202020202020202320100425940303040303130324040613138376137383338303764373861313266623034366664323039396633346264653730303261633262323931383263636664333564363435306266623531644061316232633340643465354030304a01aa5201bb581f600768028201200303030303030303030303030303030303030303030303030303030303030303"},{"name":"plain/async/denied","relayed":false,"async":true,"return_code":4,"message":"denied","data":"@04@64656e696564@0102@@a187a783807d78a12fb046fd2099f34bde7002ac2b29182ccfd35d6450bfb51d@a1b2c3@d4e5@00","wire_hex":"120200001a2001010101010101010101010101010101010101010101010101010101010101012220020202020202020202020202020202020202020202020202020202020202020232010042664030344036343635366536393635363440303130324040613138376137383338303764373861313266623034366664323039396633346264653730303261633262323931383263636664333564363435306266623531644061316232633340643465354030304a01aa5201bb581f600768027a0664656e6965648201200303030303030303030303030303030303030303030303030303030303030303"},{"name":"relayed/no_async/ok","relayed":true,"async":false,"return_code":0,"message":"","data":"@00@0102@","wire_hex":"120200001a200101010101010101010101010101010101010101010101010101010101010101222002020202020202020202020202020202020202020202020202020202020202022a2004040404040404040404040404040404040404040404040404040404040404043202000042094030304030313032404a01aa5201bb581f600768028201200303030303030303030303030303030303030303030303030303030303030303"},{"name":"relayed/no_async/denied","relayed":true,"async":false,"return_code":4,"message":"denied","data":"@04@64656e696564@0102@","wire_hex":"120200001a200101010101010101010101010101010101010101010101010101010101010101222002020202020202020202020202020202020202020202020202020202020202022a200404040404040404040404040404040404040404040404040404040404040404320200004216403034403634363536653639363536344030313032404a01aa5201bb581f600768027a0664656e6965648201200303030303030303030303030303030303030303030303030303030303030303"},{"name":"relayed/async/ok","relayed":true,"async":true,"return_code":0,"message":"","data":"@00@0102@@a187a783807d78a12fb046fd2099f34bde7002ac2b29182ccfd35d6450bfb51d@a1b2c3@d4e5@00","wire_hex":"120200001a200101010101010101010101010101010101010101010101010101010101010101222002020202020202020202020202020202020202020202020202020202020202022a20040404040404040404040404040404040404040404040404040404040404040432020000425940303040303130324040613138376137383338303764373861313266623034366664323039396633346264653730303261633262323931383263636664333564363435306266623531644061316232633340643465354030304a01aa5201bb581f600768028201200303030303030303030303030303030303030303030303030303030303030303"},{"name":"relayed/async/denied","relayed":true,"async":true,"return_code":4,"message":"denied","data":"@04@64656e696564@0102@@a187a783807d78a12fb046fd2099f34bde7002ac2b29182ccfd35d6450bfb51d@a1b2c3@d4e5@00","wire_hex":"120200001a200101010101010101010101010101010101010101010101010101010101010101222002020202020202020202020202020202020202020202020202020202020202022a2004040404040404040404040404040404040404040404040404040404040404043202000042664030344036343635366536393635363440303130324040613138376137383338303764373861313266623034366664323039396633346264653730303261633262323931383263636664333564363435306266623531644061316232633340643465354030304a01aa5201bb581f600768027a0664656e6965648201200303030303030303030303030303030303030303030303030303030303030303"}]`

func TestQualDRWAObservationNativeCallbackProducer(t *testing.T) {
	var vectors []struct {
		Name       string `json:"name"`
		Relayed    bool   `json:"relayed"`
		Async      bool   `json:"async"`
		ReturnCode int    `json:"return_code"`
		Message    string `json:"message"`
		Data       string `json:"data"`
		WireHex    string `json:"wire_hex"`
	}
	require.NoError(t, json.Unmarshal([]byte(qualDRWAObservationCallbackVectors), &vectors))
	args := createMockSmartContractProcessorArguments()
	args.ArgsParser = smartContract.NewArgumentParser()
	args.Marshalizer = &marshal.GogoProtoMarshalizer{}
	processor, err := NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	dataParser, err := datafield.NewOperationDataFieldParser(&datafield.ArgsOperationDataFieldParser{
		AddressLength: 32, Marshalizer: args.Marshalizer, RelayedTransactionsV1V2DisableEpoch: 4,
	})
	require.NoError(t, err)
	exclusion, err := common.NewRoundExclusionHandler(nil)
	require.NoError(t, err)
	api, err := transactionAPI.NewAPITransactionProcessor(&transactionAPI.ArgAPITransactionProcessor{
		RoundHandler: &testscommon.RoundHandlerMock{}, Marshalizer: args.Marshalizer,
		AddressPubKeyConverter: testscommon.NewPubkeyConverterMock(32), ShardCoordinator: args.ShardCoordinator,
		HistoryRepository: &historyMocks.HistoryRepositoryStub{}, StorageService: &storageMocks.ChainStorerStub{},
		DataPool: &poolMocks.PoolsHolderMock{}, Uint64ByteSliceConverter: uint64ByteSlice.NewBigEndianConverter(),
		FeeComputer: &testscommon.FeeComputerStub{}, TxTypeHandler: args.TxTypeHandler,
		LogsFacade: &testscommon.LogsFacadeStub{}, DataFieldParser: dataParser, TxMarshaller: args.Marshalizer,
		EnableEpochsHandler: args.EnableEpochsHandler, EnableRoundsHandler: &testscommon.EnableRoundsHandlerStub{},
		TxVersionChecker: &testscommon.TxVersionCheckerStub{}, ChainHandler: &testscommon.ChainHandlerMock{},
		TxProcessor: &testscommon.TxProcessorMock{}, RoundExclusionHandler: exclusion,
	})
	require.NoError(t, err)
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			amount, ok := new(big.Int).SetString("9007199254740993", 10)
			require.True(t, ok)
			original := &smartContractResult.SmartContractResult{
				Nonce: 23, Value: amount, SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32),
				OriginalSender: bytes.Repeat([]byte{3}, 32), OriginalTxHash: []byte{0xbb}, GasLimit: 999, GasPrice: 7,
				CallType: vmData.AsynchronousCall,
			}
			if vector.Relayed {
				original.RelayerAddr = bytes.Repeat([]byte{4}, 32)
				original.RelayedValue = new(big.Int).Set(amount)
			}
			var asynchronous *vmcommon.AsyncArguments
			if vector.Async {
				asynchronous = &vmcommon.AsyncArguments{CallID: []byte{0xa1, 0xb2, 0xc3}, CallerCallID: []byte{0xd4, 0xe5}}
			}
			output := &vmcommon.VMOutput{ReturnCode: vmcommon.ReturnCode(vector.ReturnCode), GasRemaining: 31,
				ReturnMessage: vector.Message, ReturnData: [][]byte{{1, 2}, {}}}
			produced, err := processor.createAsyncCallBackSCRFromVMOutput(output, original, []byte{0xaa}, asynchronous)
			require.NoError(t, err)
			require.Equal(t, uint64(0), produced.Nonce)
			require.Equal(t, big.NewInt(0), produced.Value, "callback is not the original amount returned")
			require.Equal(t, bytes.Repeat([]byte{1}, 32), produced.RcvAddr)
			require.Equal(t, bytes.Repeat([]byte{2}, 32), produced.SndAddr)
			require.Equal(t, bytes.Repeat([]byte{3}, 32), produced.OriginalSender)
			require.Equal(t, []byte{0xaa}, produced.PrevTxHash)
			require.Equal(t, []byte{0xbb}, produced.OriginalTxHash)
			require.Equal(t, uint64(31), produced.GasLimit)
			require.Equal(t, uint64(7), produced.GasPrice)
			require.Equal(t, vmData.AsynchronousCallBack, produced.CallType)
			require.Equal(t, []byte(vector.Data), produced.Data)
			require.Equal(t, []byte(vector.Message), produced.ReturnMessage)
			require.Empty(t, produced.Code)
			require.Empty(t, produced.CodeMetadata)
			if vector.Relayed {
				require.Equal(t, bytes.Repeat([]byte{4}, 32), produced.RelayerAddr)
				require.Equal(t, big.NewInt(0), produced.RelayedValue)
			} else {
				require.Empty(t, produced.RelayerAddr)
				require.Nil(t, produced.RelayedValue)
			}
			expectedWire, err := hex.DecodeString(vector.WireHex)
			require.NoError(t, err)
			wire, err := args.Marshalizer.Marshal(produced)
			require.NoError(t, err)
			require.Equal(t, expectedWire, wire, "actual native producer bytes versus independent protobuf vector")
			decoded := &smartContractResult.SmartContractResult{}
			require.NoError(t, args.Marshalizer.Unmarshal(decoded, wire))
			expectedDecoded := &smartContractResult.SmartContractResult{
				Value: big.NewInt(0), RcvAddr: bytes.Repeat([]byte{1}, 32), SndAddr: bytes.Repeat([]byte{2}, 32),
				OriginalSender: bytes.Repeat([]byte{3}, 32), PrevTxHash: []byte{0xaa}, OriginalTxHash: []byte{0xbb},
				GasLimit: 31, GasPrice: 7, CallType: vmData.AsynchronousCallBack, Data: []byte(vector.Data),
			}
			// Native protobuf omits the empty ReturnMessage field; decoding into
			// a fresh object leaves nil. It retains every nonempty message.
			if vector.Message != "" {
				expectedDecoded.ReturnMessage = []byte(vector.Message)
			}
			if vector.Relayed {
				expectedDecoded.RelayerAddr = bytes.Repeat([]byte{4}, 32)
				expectedDecoded.RelayedValue = big.NewInt(0)
			}
			require.Equal(t, expectedDecoded, decoded, "actual producer-to-independent-decoded-field contract")
			require.Error(t, args.Marshalizer.Unmarshal(&smartContractResult.SmartContractResult{}, expectedWire[:len(expectedWire)-1]))
			view, err := api.UnmarshalTransaction(wire, transaction.TxTypeUnsigned, 1)
			require.NoError(t, err)
			require.Equal(t, expectedDecoded, view.Tx)
			require.Equal(t, "unsigned", view.Type)
			require.Equal(t, uint64(0), view.Nonce)
			require.Equal(t, "0", view.Value)
			require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{2}, 32)), view.Sender)
			require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), view.Receiver)
			require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{3}, 32)), view.OriginalSender)
			require.Equal(t, "aa", view.PreviousTransactionHash)
			require.Equal(t, "bb", view.OriginalTransactionHash)
			require.Equal(t, uint64(31), view.GasLimit)
			require.Equal(t, uint64(7), view.GasPrice)
			require.Equal(t, "asynchronousCallBack", view.CallType)
			require.Equal(t, []byte(vector.Data), view.Data)
			require.Equal(t, vector.Message, view.ReturnMessage)
			require.Empty(t, view.Status, "decoding does not classify execution or canonicality")
			if vector.Relayed {
				require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{4}, 32)), view.RelayerAddress)
				require.Equal(t, "0", view.RelayedValue)
			} else {
				require.Empty(t, view.RelayerAddress)
				require.Empty(t, view.RelayedValue)
			}
			apiJSON, err := json.Marshal(view)
			require.NoError(t, err)
			var apiFields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(apiJSON, &apiFields))
			require.Equal(t, `"0"`, string(apiFields["value"]))
			require.Equal(t, `"aa"`, string(apiFields["previousTransactionHash"]))
			require.Equal(t, `"bb"`, string(apiFields["originalTransactionHash"]))
			require.NotContains(t, apiFields, "prevTxHash")
			invalidView, err := api.UnmarshalTransaction(wire[:len(wire)-1], transaction.TxTypeUnsigned, 1)
			require.Error(t, err)
			require.Nil(t, invalidView)
			encoded, err := json.Marshal(decoded)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &fields))
			require.Equal(t, "0", string(fields["value"]))
			require.Contains(t, fields, "prevTxHash")
			require.Contains(t, fields, "originalTxHash")
			for _, unavailable := range []string{"canonicality", "drwa_outcome", "as_of_block", "effect_id", "source_completion"} {
				require.NotContains(t, fields, unavailable)
				require.NotContains(t, apiFields, unavailable)
			}
			t.Logf("native callback wire: %x", wire)
		})
	}
}

func TestQualDRWAObservationNativeCallbackRequiresSCR(t *testing.T) {
	args := createMockSmartContractProcessorArguments()
	args.ArgsParser = smartContract.NewArgumentParser()
	processor, err := NewSmartContractProcessorV2(args)
	require.NoError(t, err)
	result, err := processor.createAsyncCallBackSCRFromVMOutput(&vmcommon.VMOutput{ReturnCode: vmcommon.Ok},
		&transaction.Transaction{Value: big.NewInt(0)}, []byte{0xaa}, nil)
	require.ErrorIs(t, err, process.ErrWrongTransactionType)
	require.Nil(t, result)
}
