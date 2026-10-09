package transactionAPI

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dblookupext"
	"github.com/multiversx/mx-chain-go/node/filters"
	"github.com/multiversx/mx-chain-go/node/mock"
	"github.com/multiversx/mx-chain-go/process/txstatus"
	"github.com/multiversx/mx-chain-go/storage"
	dbmock "github.com/multiversx/mx-chain-go/testscommon/dblookupext"
	storagemock "github.com/multiversx/mx-chain-go/testscommon/storage"
	datafield "github.com/multiversx/mx-chain-vm-common-go/parsers/dataField"
	"github.com/stretchr/testify/require"
)

// T34 N1-N6: native labels are useful observations with limited meanings, not
// authenticated AM-012 finality, token settlement or source-completion proof.
func TestQualDRWAObservationNativeStatusLimits(t *testing.T) {
	cases := []struct {
		name       string
		self, dest uint32
		known      bool
		kind       block.Type
		notarized  uint64
		deploy     bool
		want       transaction.TxStatus
	}{
		{"local_known_no_notarization", 1, 1, true, block.TxBlock, 0, false, transaction.TxStatusSuccess},
		{"remote_known_no_notarization", 1, 2, true, block.TxBlock, 0, false, transaction.TxStatusPending},
		{"remote_known_positive_nonce", 1, 2, true, block.TxBlock, 7, false, transaction.TxStatusSuccess},
		{"invalid_overrides_nonce", 1, 2, true, block.InvalidBlock, 7, false, transaction.TxStatusInvalid},
		{"local_unknown_miniblock", 1, 1, false, block.TxBlock, 0, false, transaction.TxStatusSuccess},
		{"remote_unknown_miniblock", 1, 2, false, block.TxBlock, 7, false, transaction.TxStatusPending},
		{"deployment_without_notarization", 1, 2, true, block.TxBlock, 0, true, transaction.TxStatusSuccess},
		{"metachain_local_no_notarization", core.MetachainShardId, core.MetachainShardId, true, block.TxBlock, 0, false, transaction.TxStatusSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			computer, err := txstatus.NewStatusComputer(c.self, mock.NewNonceHashConverterMock(), &storagemock.ChainStorerStub{})
			require.NoError(t, err)
			native := &transaction.Transaction{Value: big.NewInt(0), RcvAddr: []byte("bob")}
			if c.deploy {
				native.RcvAddr = make([]byte, 32)
				native.Data = []byte("qual-deployment")
			}
			view := &transaction.ApiTransactionResult{Tx: native, DestinationShard: c.dest, Data: native.Data, NotarizedAtDestinationInMetaNonce: c.notarized}
			var status transaction.TxStatus
			if c.known {
				status, err = computer.ComputeStatusWhenInStorageKnowingMiniblock(c.kind, view)
			} else {
				status, err = computer.ComputeStatusWhenInStorageNotKnowingMiniblock(c.dest, view)
			}
			require.NoError(t, err)
			require.Equal(t, c.want, status)
			require.Empty(t, view.BlockHash)
			require.Empty(t, view.MiniBlockHash)
			require.Empty(t, view.SmartContractResults)
		})
	}
	for _, known := range []bool{false, true} {
		name := "nil_unknown"
		if known {
			name = "nil_known"
		}
		t.Run(name, func(t *testing.T) {
			computer, err := txstatus.NewStatusComputer(1, mock.NewNonceHashConverterMock(), &storagemock.ChainStorerStub{})
			require.NoError(t, err)
			if known {
				_, err = computer.ComputeStatusWhenInStorageKnowingMiniblock(block.TxBlock, nil)
			} else {
				_, err = computer.ComputeStatusWhenInStorageNotKnowingMiniblock(1, nil)
			}
			require.ErrorIs(t, err, txstatus.ErrNilApiTransactionResult)
		})
	}
}

// N7-N8: demonstrate why the native ESDTTransfer-prefix filter cannot be
// substituted for an all-family, typed protected-outcome decoder.
func TestQualDRWAObservationNativeESDTFilterLimits(t *testing.T) {
	cases := []struct {
		name, operation    string
		self, source, dest uint32
		scrNonce           uint64
		want               transaction.TxStatus
	}{
		{"fungible_match", core.BuiltInFunctionESDTTransfer, 2, 1, 2, 7, transaction.TxStatusFail},
		{"wrong_nonce", core.BuiltInFunctionESDTTransfer, 2, 1, 2, 8, transaction.TxStatusSuccess},
		{"source_observer", core.BuiltInFunctionESDTTransfer, 1, 1, 2, 7, transaction.TxStatusSuccess},
		{"same_shard", core.BuiltInFunctionESDTTransfer, 1, 1, 1, 7, transaction.TxStatusSuccess},
		{"nft_prefix_not_classified", core.BuiltInFunctionESDTNFTTransfer, 2, 1, 2, 7, transaction.TxStatusSuccess},
		{"multi_prefix_not_classified", core.BuiltInFunctionMultiESDTNFTTransfer, 2, 1, 2, 7, transaction.TxStatusSuccess},
		{"unsupported_qualification_data", "QUAL_UNSUPPORTED", 2, 1, 2, 7, transaction.TxStatusSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := c.operation + "@5155414c2d616263646566@01"
			view := &transaction.ApiTransactionResult{
				Nonce: 7, SourceShard: c.source, DestinationShard: c.dest, Data: []byte(data), Status: transaction.TxStatusSuccess,
				SmartContractResults: []*transaction.ApiSmartContractResult{{Data: data, Nonce: c.scrNonce}},
			}
			filters.NewStatusFilters(c.self).SetStatusIfIsFailedESDTTransfer(view)
			require.Equal(t, c.want, view.Status)
		})
	}
}

// N9: ordinary move-balance mirrored-value filtering preserves its native
// scope. It observes an SCR; it does not authenticate an actual return credit.
func TestQualDRWAObservationNativeMoveBalanceFilter(t *testing.T) {
	cases := []struct {
		name       string
		amount     int64
		scrAmount  int64
		scrSender  string
		withResult bool
		want       transaction.TxStatus
	}{
		{"exact_mirrored_value", 13, 13, "bob", true, transaction.TxStatusFail},
		{"different_value", 13, 12, "bob", true, transaction.TxStatusSuccess},
		{"different_sender", 13, 13, "other", true, transaction.TxStatusSuccess},
		{"no_result", 13, 13, "bob", false, transaction.TxStatusSuccess},
		{"zero_original_value", 0, 0, "bob", true, transaction.TxStatusSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			view := &transaction.ApiTransactionResult{
				Tx:     &transaction.Transaction{Value: big.NewInt(c.amount), SndAddr: []byte("alice"), RcvAddr: []byte("bob")},
				Sender: "alice", Receiver: "bob", Status: transaction.TxStatusSuccess,
			}
			if c.withResult {
				view.SmartContractResults = []*transaction.ApiSmartContractResult{{Value: big.NewInt(c.scrAmount), SndAddr: c.scrSender, RcvAddr: "alice"}}
			}
			filters.NewStatusFilters(2).SetStatusIfFailedMoveBalanceWithError(view)
			require.Equal(t, c.want, view.Status)
		})
	}
}

// N10-N11: literal malformed inputs expose the native heuristic's limits.
// They are not valid native SCR amounts and never become DRWA return fixtures.
func TestQualDRWAObservationRefundHeuristicLimits(t *testing.T) {
	cases := []struct {
		name, value, data, message string
		gas                        uint64
		want                       bool
	}{
		{"ok", "13", "@ok", "", 0, true},
		{"encoded_ok", "13", "@6f6b", "", 0, true},
		{"positive_gas", "13", "@ok", "", 31, true},
		{"relayer_message", "13", "other", core.GasRefundForRelayerMessage, 0, true},
		{"zero", "0", "@ok", "", 0, false},
		{"absent_value", "", "@ok", "", 0, false},
		{"missing_marker", "13", "other", "", 0, false},
		{"malformed_text_not_parsed", "not-a-number", "@ok", "", 0, true},
		{"negative_text_not_validated", "-13", "@ok", "", 0, true},
		{"embedded_marker_not_typed", "13", "qual@ok@unrelated", "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewRefundDetector().IsRefund(RefundDetectorInput{Value: c.value, Data: []byte(c.data), ReturnMessage: c.message, GasLimit: c.gas})
			require.Equal(t, c.want, got)
		})
	}
}

// N12: manually authored protobuf, not the serializer under test, is the input.
// Synthetic addresses and hex converter limit this to actual DTO adaptation.
func TestQualDRWAObservationNativeSCRRepresentation(t *testing.T) {
	const wireHex = "0807120800200000000000011a03626f622205616c6963654203406f6b4a01aa5201bb581f6002"
	wire, err := hex.DecodeString(wireHex)
	require.NoError(t, err)
	args := createMockArgAPITransactionProcessor()
	args.Marshalizer = &marshal.GogoProtoMarshalizer{}
	args.DataFieldParser, err = datafield.NewOperationDataFieldParser(&datafield.ArgsOperationDataFieldParser{
		AddressLength: 32, Marshalizer: args.Marshalizer, RelayedTransactionsV1V2DisableEpoch: 4,
	})
	require.NoError(t, err)
	proc, err := NewAPITransactionProcessor(args)
	require.NoError(t, err)
	scr := &smartContractResult.SmartContractResult{}
	require.NoError(t, args.Marshalizer.Unmarshal(scr, wire))
	require.Equal(t, "9007199254740993", scr.Value.String())
	require.Equal(t, uint64(7), scr.Nonce)
	require.Equal(t, []byte("alice"), scr.SndAddr)
	require.Equal(t, []byte("bob"), scr.RcvAddr)
	require.Equal(t, []byte{0xaa}, scr.PrevTxHash)
	require.Equal(t, []byte{0xbb}, scr.OriginalTxHash)
	view := proc.transactionResultsProcessor.adaptSmartContractResult([]byte{0xcc}, scr, 1)
	encoded, err := json.Marshal(view)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	require.Equal(t, "9007199254740993", string(fields["value"]))
	require.Equal(t, `"aa"`, string(fields["prevTxHash"]))
	require.Equal(t, `"bb"`, string(fields["originalTxHash"]))
	require.Equal(t, `"cc"`, string(fields["hash"]))
	require.Equal(t, "true", string(fields["isRefund"]))
	require.Equal(t, `"@ok"`, string(fields["data"]))
	t.Logf("native SCR JSON: %s", encoded)

	unsigned, err := proc.UnmarshalTransaction(wire, transaction.TxTypeUnsigned, 1)
	require.NoError(t, err)
	encodedTop, err := json.Marshal(unsigned)
	require.NoError(t, err)
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encodedTop, &top))
	require.Equal(t, `"9007199254740993"`, string(top["value"]))
	require.Equal(t, `"aa"`, string(top["previousTransactionHash"]))
	require.Equal(t, `"bb"`, string(top["originalTransactionHash"]))
	require.NotContains(t, top, "prevTxHash")
	require.NotContains(t, top, "isRefund") // computed only by a later native stage
	t.Logf("native unsigned JSON: %s", encodedTop)
	for _, unavailable := range []string{"effect_id", "context_hash", "carrier_kind", "canonicality", "as_of_block", "observation_time", "drwa_outcome"} {
		require.NotContains(t, fields, unavailable)
		require.NotContains(t, top, unavailable)
	}

	t.Run("truncated_wire", func(t *testing.T) {
		_, err := proc.UnmarshalTransaction(wire[:len(wire)-1], transaction.TxTypeUnsigned, 1)
		require.Error(t, err)
	})
	t.Run("invalid_bigint_sign", func(t *testing.T) {
		bad := bytes.Clone(wire)
		bad[4] = 2 // field2 payload begins here; sign must be 0 or 1
		_, err := proc.UnmarshalTransaction(bad, transaction.TxTypeUnsigned, 1)
		require.Error(t, err)
	})
}

// N13-N15: no results and excluded historical entries are observation limits.
// No source/destination operation is executed, and no retry is authorized.
func TestQualDRWAObservationUnavailableResultsAndExcludedHistory(t *testing.T) {
	indexFailure := errors.New("qual-results-index-unavailable")
	for _, c := range []struct {
		name string
		err  error
	}{
		{"missing_results_index", dblookupext.ErrNotFoundInStorage},
		{"failed_results_index", indexFailure},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := createMockArgAPITransactionProcessor()
			args.HistoryRepository = &dbmock.HistoryRepositoryStub{GetEventsHashesByTxHashCalled: func(hash []byte, epoch uint32) (*dblookupext.ResultsHashesByTxHash, error) {
				require.Equal(t, []byte{0xbb}, hash)
				require.Equal(t, uint32(1), epoch)
				return nil, c.err
			}}
			proc, err := NewAPITransactionProcessor(args)
			require.NoError(t, err)
			view := &transaction.ApiTransactionResult{Status: transaction.TxStatusPending}
			err = proc.transactionResultsProcessor.putResultsInTransaction([]byte{0xbb}, view, 1, 1)
			if errors.Is(c.err, dblookupext.ErrNotFoundInStorage) {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, indexFailure)
			}
			require.Empty(t, view.SmartContractResults)
			require.Nil(t, view.Receipt)
			require.Equal(t, transaction.TxStatusPending, view.Status)
		})
	}
	t.Run("excluded_round_without_storage_read", func(t *testing.T) {
		args := createMockArgAPITransactionProcessor()
		args.HistoryRepository = &dbmock.HistoryRepositoryStub{GetMiniblockMetadataByTxHashCalled: func(hash []byte) (*dblookupext.MiniblockMetadata, error) {
			require.Equal(t, []byte{0xbb}, hash)
			return &dblookupext.MiniblockMetadata{Round: 150}, nil
		}}
		var err error
		args.RoundExclusionHandler, err = common.NewRoundExclusionHandler([]config.HardforkRoundExclusionConfig{{StartRound: 100, EndRound: 199}})
		require.NoError(t, err)
		args.StorageService = &storagemock.ChainStorerStub{GetStorerCalled: func(_unit dataRetriever.UnitType) (storage.Storer, error) {
			t.Fatal("excluded historical entry must not read transaction storage")
			return nil, indexFailure
		}}
		proc, err := NewAPITransactionProcessor(args)
		require.NoError(t, err)
		view, err := proc.lookupHistoricalTransaction([]byte{0xbb}, true)
		require.ErrorIs(t, err, ErrTransactionNotFound)
		require.Nil(t, view)
	})
}
