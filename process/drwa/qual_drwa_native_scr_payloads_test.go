package drwa

import (
	"bytes"
	stdsha256 "crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/stretchr/testify/require"
)

// Native storage is an acquisition source, not a canonicality oracle. These
// fixtures exercise the existing epoch getter and actual native payload hashes;
// authority/history/funding and live ingress remain outside this component.
type qualSCRPayloadStorer struct {
	storage.Storer
	get func([]byte, uint32) ([]byte, error)
}

func (s *qualSCRPayloadStorer) IsInterfaceNil() bool { return s == nil }
func (s *qualSCRPayloadStorer) GetFromEpoch(key []byte, epoch uint32) ([]byte, error) {
	return s.get(key, epoch)
}

type qualSCRPayloadStorage struct {
	dataRetriever.StorageService
	mini, results, transactions storage.Storer
}

func (s *qualSCRPayloadStorage) IsInterfaceNil() bool { return s == nil }
func (s *qualSCRPayloadStorage) GetStorer(unit dataRetriever.UnitType) (storage.Storer, error) {
	switch unit {
	case dataRetriever.MiniBlockUnit:
		return s.mini, nil
	case dataRetriever.UnsignedTransactionUnit:
		return s.results, nil
	case dataRetriever.TransactionUnit:
		return s.transactions, nil
	default:
		return nil, errors.New("unexpected native storage unit")
	}
}

func qualReadSCRPayloads(r *ResultAccountReader, source dataRetriever.StorageService, epoch uint32,
	miniHash, resultHash []byte, limit int) ([]byte, []byte, error) {
	if reader, ok := interface{}(r).(interface {
		ReadNativeSCRPayloads(dataRetriever.StorageService, uint32, []byte, []byte, int) ([]byte, []byte, error)
	}); ok {
		return reader.ReadNativeSCRPayloads(source, epoch, miniHash, resultHash, limit)
	}
	// The pre-adapter native getters return bytes by key; they do not bind the
	// requested hash to the returned bytes before the canonical observer sees it.
	mini, err := source.GetStorer(dataRetriever.MiniBlockUnit)
	if err != nil {
		return nil, nil, err
	}
	results, err := source.GetStorer(dataRetriever.UnsignedTransactionUnit)
	if err != nil {
		return nil, nil, err
	}
	a, err := mini.GetFromEpoch(miniHash, epoch)
	if err != nil {
		return nil, nil, err
	}
	z, err := results.GetFromEpoch(resultHash, epoch)
	if err != nil {
		return nil, nil, err
	}
	return a, z, nil
}

func TestQualDRWANativeSCRPayloadSource(t *testing.T) {
	t.Run("wrong_storage_key_cannot_select_a_valid_result", func(t *testing.T) {
		f, previous, original, miniRaw, resultRaw, observerLimit := qualNativeMetaSCRFixture(t, nil)
		miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
		source := &qualSCRPayloadStorage{mini: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return miniRaw, nil }},
			results: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return resultRaw, nil }}}
		// These bytes really satisfy the separate native carrier/context observer.
		_, err := qualReadNativeMetaSCR(f, previous, original, miniRaw, resultRaw, f.w, observerLimit)
		require.NoError(t, err)
		resultHash[0] ^= 1
		a, z, err := qualReadSCRPayloads(f.reader.accounts, source, 9, miniHash, resultHash,
			len(miniHash)+len(resultHash)+len(miniRaw)+len(resultRaw))
		require.Error(t, err)
		require.Nil(t, a)
		require.Nil(t, z)
	})
	t.Run("exact_units_epoch_hashes_and_owned_bytes", func(t *testing.T) {
		f, previous, original, miniRaw, resultRaw, observerLimit := qualNativeMetaSCRFixture(t, nil)
		miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
		originalMini, originalResult := bytes.Clone(miniRaw), bytes.Clone(resultRaw)
		miniCalls, resultCalls := 0, 0
		source := &qualSCRPayloadStorage{mini: &qualSCRPayloadStorer{get: func(key []byte, epoch uint32) ([]byte, error) {
			miniCalls++
			require.Equal(t, miniHash, key)
			require.Equal(t, uint32(9), epoch)
			key[0] ^= 1
			return miniRaw, nil
		}}, results: &qualSCRPayloadStorer{get: func(key []byte, epoch uint32) ([]byte, error) {
			resultCalls++
			require.Equal(t, resultHash, key)
			require.Equal(t, uint32(9), epoch)
			// Native cache buffers may be reused by the next read.
			miniRaw[0] ^= 1
			key[0] ^= 1
			return resultRaw, nil
		}}}
		limit := len(miniHash) + len(resultHash) + len(miniRaw) + len(resultRaw)
		a, z, err := qualReadSCRPayloads(f.reader.accounts, source, 9, miniHash, resultHash, limit)
		require.NoError(t, err)
		require.Equal(t, originalMini, a)
		require.Equal(t, originalResult, z)
		require.Equal(t, f.hash(originalMini), miniHash)
		require.Equal(t, f.hash(originalResult), resultHash)
		require.Equal(t, 1, miniCalls)
		require.Equal(t, 1, resultCalls)
		resultRaw[0] ^= 1
		require.Equal(t, originalResult, z)
		observed, err := qualReadNativeMetaSCR(f, previous, original, a, z, f.w, observerLimit)
		require.NoError(t, err)
		require.Equal(t, previous, observed.result.PrevTxHash)
		require.Equal(t, original, observed.result.OriginalTxHash)
		require.Equal(t, uint32(4), observed.asOfEpoch, "lookup epoch 9 does not become source/profile or observation epoch")

	})
	t.Run("bad_miniblock_stops_before_result_read", func(t *testing.T) {
		f, _, _, miniRaw, resultRaw, _ := qualNativeMetaSCRFixture(t, nil)
		miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
		resultCalls := 0
		source := &qualSCRPayloadStorage{mini: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return []byte("corrupt"), nil }},
			results: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { resultCalls++; return resultRaw, nil }}}
		a, z, err := qualReadSCRPayloads(f.reader.accounts, source, 9, miniHash, resultHash,
			len(miniHash)+len(resultHash)+len(miniRaw)+len(resultRaw))
		require.Error(t, err)
		require.Nil(t, a)
		require.Nil(t, z)
		require.Zero(t, resultCalls)
	})
	t.Run("missing_native_source_refuses", func(t *testing.T) {
		for _, name := range []string{"nil_reader", "nil_source", "nil_miniblocks", "nil_results", "missing_hash", "key_budget"} {
			t.Run(name, func(t *testing.T) {
				f, _, _, miniRaw, resultRaw, _ := qualNativeMetaSCRFixture(t, nil)
				reader := f.reader.accounts
				miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
				var source dataRetriever.StorageService = &qualSCRPayloadStorage{
					mini:    &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return miniRaw, nil }},
					results: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return resultRaw, nil }}}
				limit := len(miniHash) + len(resultHash) + len(miniRaw) + len(resultRaw)
				switch name {
				case "nil_reader":
					reader = nil
				case "nil_source":
					source = nil
				case "nil_miniblocks":
					source.(*qualSCRPayloadStorage).mini = nil
				case "nil_results":
					source.(*qualSCRPayloadStorage).results = nil
				case "missing_hash":
					resultHash = nil
				case "key_budget":
					limit = len(miniHash)
				}
				a, z, err := qualReadSCRPayloads(reader, source, 9, miniHash, resultHash, limit)
				require.Error(t, err)
				require.Nil(t, a)
				require.Nil(t, z)
			})
		}
	})
	t.Run("unavailable_corrupt_restored_and_bounded", func(t *testing.T) {
		f, _, _, miniRaw, resultRaw, _ := qualNativeMetaSCRFixture(t, nil)
		miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
		unavailable := errors.New("fixture native epoch unavailable")
		mode := "available"
		source := &qualSCRPayloadStorage{mini: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return miniRaw, nil }},
			results: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) {
				switch mode {
				case "unavailable":
					return nil, unavailable
				case "corrupt":
					return []byte("corrupt"), nil
				case "empty":
					return nil, nil
				default:
					return resultRaw, nil
				}
			}}}
		limit := len(miniHash) + len(resultHash) + len(miniRaw) + len(resultRaw)
		for _, next := range []string{"unavailable", "corrupt", "empty"} {
			mode = next
			a, z, err := qualReadSCRPayloads(f.reader.accounts, source, 9, miniHash, resultHash, limit)
			require.Error(t, err)
			if mode == "unavailable" {
				require.ErrorIs(t, err, unavailable)
			}
			require.Nil(t, a)
			require.Nil(t, z)
		}
		mode = "available"
		a, z, err := qualReadSCRPayloads(f.reader.accounts, source, 9, miniHash, resultHash, limit)
		require.NoError(t, err)
		require.Equal(t, miniRaw, a)
		require.Equal(t, resultRaw, z)
		a, z, err = qualReadSCRPayloads(f.reader.accounts, source, 9, miniHash, resultHash, limit-1)
		require.Error(t, err)
		require.Nil(t, a)
		require.Nil(t, z)
	})
}

// The original TxBlock bytes come from the native protobuf types, and their
// expected keys are computed independently of the acquisition reader.
func TestQualDRWANativeTransactionPayloadSource(t *testing.T) {
	codec := &marshal.GogoProtoMarshalizer{}
	txRaw, err := codec.Marshal(&transaction.Transaction{
		Nonce: 17, Value: big.NewInt(0), SndAddr: bytes.Repeat([]byte{1}, 32),
		RcvAddr: bytes.Repeat([]byte{2}, 32), GasLimit: 120000,
		Data: []byte("ESDTTransfer@544f4b454e2d616263646566@01"),
	})
	require.NoError(t, err)
	txHash := stdsha256.Sum256(txRaw)
	miniRaw, err := codec.Marshal(&block.MiniBlock{
		Type: block.TxBlock, SenderShardID: 1, ReceiverShardID: 0,
		TxHashes: [][]byte{txHash[:]},
	})
	require.NoError(t, err)
	miniHash := stdsha256.Sum256(miniRaw)
	const epoch uint32 = 11
	budget := len(miniHash) + len(txHash) + len(miniRaw) + len(txRaw)
	reader := &ResultAccountReader{args: ArgsResultAccountReader{Hasher: sha256.NewSha256()}}
	readOriginal := (*ResultAccountReader).ReadNativeTransactionPayloads
	storer := func(raw []byte, err error) *qualSCRPayloadStorer {
		return &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return raw, err }}
	}

	t.Run("original_unit_epoch_and_owned_pair", func(t *testing.T) {
		miniKey, txKey := bytes.Clone(miniHash[:]), bytes.Clone(txHash[:])
		scratch := make([]byte, max(len(miniRaw), len(txRaw)))
		var reads []string
		fetch := func(name string, want, raw []byte) *qualSCRPayloadStorer {
			return &qualSCRPayloadStorer{get: func(key []byte, gotEpoch uint32) ([]byte, error) {
				reads = append(reads, name)
				require.Equal(t, epoch, gotEpoch)
				require.Equal(t, want, key)
				key[0] ^= 1
				return scratch[:copy(scratch, raw)], nil
			}}
		}
		source := &qualSCRPayloadStorage{
			mini:         fetch("miniblock", miniHash[:], miniRaw),
			transactions: fetch("original", txHash[:], txRaw),
			results:      storer(nil, errors.New("unsigned unit is not the original transaction source")),
		}
		mini, tx, err := readOriginal(reader, source, epoch, miniKey, txKey, budget)
		require.NoError(t, err)
		require.Equal(t, []string{"miniblock", "original"}, reads)
		clear(scratch)
		require.Equal(t, miniHash[:], miniKey)
		require.Equal(t, txHash[:], txKey)
		require.Equal(t, miniRaw, mini)
		require.Equal(t, txRaw, tx)
	})

	t.Run("unavailable_then_restored", func(t *testing.T) {
		missing := errors.New("original transaction unavailable at named epoch")
		source := &qualSCRPayloadStorage{
			mini: storer(miniRaw, nil), transactions: storer(nil, missing),
			results: storer(txRaw, nil),
		}
		mini, tx, err := readOriginal(reader, source, epoch, miniHash[:], txHash[:], budget)
		require.ErrorIs(t, err, missing)
		require.Nil(t, mini)
		require.Nil(t, tx)

		source.transactions = storer(txRaw, nil)
		mini, tx, err = readOriginal(reader, source, epoch, miniHash[:], txHash[:], budget)
		require.NoError(t, err)
		require.Equal(t, miniRaw, mini)
		require.Equal(t, txRaw, tx)
	})

	for _, c := range []struct {
		name      string
		configure func(*qualSCRPayloadStorage, *[]byte, *[]byte, *int)
	}{
		{"nil_miniblock_storer", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) { s.mini = nil }},
		{"unsigned_unit_cannot_replace_nil_original", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) { s.transactions = nil }},
		{"wrong_miniblock_hash", func(_ *qualSCRPayloadStorage, key, _ *[]byte, _ *int) { (*key)[0] ^= 1 }},
		{"wrong_transaction_hash", func(_ *qualSCRPayloadStorage, _, key *[]byte, _ *int) { (*key)[0] ^= 1 }},
		{"invalid_transaction_key_width", func(_ *qualSCRPayloadStorage, _, key *[]byte, _ *int) { *key = (*key)[:1] }},
		{"corrupt_miniblock", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) { s.mini = storer([]byte{1}, nil) }},
		{"corrupt_transaction", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) { s.transactions = storer([]byte{1}, nil) }},
		{"empty_miniblock", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) { s.mini = storer(nil, nil) }},
		{"empty_transaction", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) { s.transactions = storer(nil, nil) }},
		{"oversized_miniblock", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) { s.mini = storer(make([]byte, budget), nil) }},
		{"oversized_transaction", func(s *qualSCRPayloadStorage, _, _ *[]byte, _ *int) {
			s.transactions = storer(make([]byte, budget), nil)
		}},
		{"one_byte_short", func(_ *qualSCRPayloadStorage, _, _ *[]byte, limit *int) { *limit = *limit - 1 }},
		{"keys_exceed_budget", func(_ *qualSCRPayloadStorage, _, _ *[]byte, limit *int) { *limit = stdsha256.Size }},
		{"negative_budget", func(_ *qualSCRPayloadStorage, _, _ *[]byte, limit *int) { *limit = -1 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			source := &qualSCRPayloadStorage{mini: storer(miniRaw, nil), transactions: storer(txRaw, nil), results: storer(txRaw, nil)}
			miniKey, txKey := bytes.Clone(miniHash[:]), bytes.Clone(txHash[:])
			limit := budget
			c.configure(source, &miniKey, &txKey, &limit)
			mini, tx, err := readOriginal(reader, source, epoch, miniKey, txKey, limit)
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, mini)
			require.Nil(t, tx)
		})
	}

	t.Run("nil_source", func(t *testing.T) {
		mini, tx, err := readOriginal(reader, nil, epoch, miniHash[:], txHash[:], budget)
		require.ErrorIs(t, err, ErrInvalidAccountWitness)
		require.Nil(t, mini)
		require.Nil(t, tx)
	})
}
