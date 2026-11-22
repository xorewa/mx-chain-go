package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualDRWANativeTransactionProjection(t *testing.T) {
	// T06 membership plus the existing S/H/M/B proof boundary. H deliberately
	// carries S's result four nonces later. Native objects and expected identities
	// are constructed independently of the point reader. Synthetic proof and
	// storage fixtures grant neither class eligibility nor paid application.
	unavailable := errors.New("native body unavailable at supplied epoch")
	for _, tc := range []struct {
		name    string
		wantErr error
	}{
		{"delayed_carry", nil},
		{"wrong_result_root", ErrInvalidAccountWitness},
		{"different_meta_branch", ErrInvalidAccountWitness},
		{"wrong_meta_position", ErrInvalidAccountWitness},
		{"wrong_header_position", ErrInvalidAccountWitness},
		{"wrong_destination", ErrInvalidAccountWitness},
		{"different_body_count", ErrInvalidAccountWitness},
		{"wrong_transaction_position", ErrInvalidAccountWitness},
		{"past_end", process.ErrIndexIsOutOfBound},
		{"unavailable_body", unavailable},
		{"insufficient_bytes", ErrInvalidAccountWitness},
		{"same_shard", ErrInvalidAccountWitness},
		{"meta_source", ErrInvalidAccountWitness},
		{"meta_destination", ErrInvalidAccountWitness},
		{"negative_miniblock_ordinal", ErrInvalidAccountWitness},
		{"short_miniblock_identity", ErrInvalidAccountWitness},
		{"identity_budget", ErrInvalidAccountWitness},
		{"lookup_key_budget", ErrInvalidAccountWitness},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCanonicalTestFixture(t, 1, 0)
			coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: f.producer}
			tx := &transaction.Transaction{
				Nonce: 17, Value: big.NewInt(0), Signature: []byte{1},
				SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32),
				GasLimit: 120000,
			}
			txRaw := f.encode(t, tx)
			txHash := f.hash(txRaw)
			other := *tx
			other.Nonce++
			otherHash := f.hash(f.encode(t, &other))
			mini := &block.MiniBlock{Type: block.TxBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer,
				TxHashes: [][]byte{otherHash, txHash}}
			miniRaw := f.encode(t, mini)
			miniHash := f.hash(miniRaw)
			decoy := *mini
			decoy.TxHashes = [][]byte{otherHash}
			makeHeader := func(hash []byte, count uint32) block.MiniBlockHeader {
				return block.MiniBlockHeader{Hash: hash, TxCount: count, Type: block.TxBlock,
					SenderShardID: f.producer, ReceiverShardID: f.consumer}
			}
			header := makeHeader(miniHash, 2)
			if tc.name == "wrong_destination" {
				header.ReceiverShardID = 2
			}
			if tc.name == "different_body_count" {
				header.TxCount++
			}
			headers := []block.MiniBlockHeader{makeHeader(f.hash(f.encode(t, &decoy)), 1), header}
			h := &block.HeaderV3{}
			require.NoError(t, h.Unmarshal(f.w.Account.Header))
			h.ExecutionResults[0].MiniBlockHeaders = headers
			f.w.Account.Header = f.encode(t, h)
			f.w.HeaderProof = f.proof(t, h, f.w.Account.Header)
			f.metas[0].ShardInfoProposal[0].HeaderHash = f.hash(f.w.Account.Header)
			projected := append([]block.MiniBlockHeader(nil), headers...)
			if tc.name == "wrong_meta_position" {
				projected[0], projected[1] = projected[1], projected[0]
			}
			f.metas[0].ShardInfo[0].ShardMiniBlockHeaders = projected
			f.rechain(t)

			witness := f.w
			if tc.name == "different_meta_branch" {
				f.metas[len(f.metas)-1].RandSeed = []byte("different synthetic tip")
				f.rechain(t)
				witness.MetaHeaders, witness.MetaProofs = f.w.MetaHeaders, f.w.MetaProofs
				f.bHash = f.hash(witness.Consumer)
			}
			origin := f.hash(witness.Account.ExecutedHeader)
			root, err := f.s.RootHash()
			require.NoError(t, err)
			if tc.name == "wrong_result_root" {
				root = f.hash([]byte("unrelated native result root"))
			}
			ordinal, index := int32(1), int32(1)
			switch tc.name {
			case "wrong_header_position":
				ordinal = 0
			case "wrong_transaction_position":
				index = 0
			case "past_end":
				index = 2
			}

			s := &block.HeaderV3{}
			require.NoError(t, s.Unmarshal(witness.Account.ExecutedHeader))
			require.NotEqual(t, h.Epoch, s.Epoch, "the two native writers commit at different epochs")
			bodyReads := 0
			source := &qualSCRPayloadStorage{
				mini: &qualSCRPayloadStorer{get: func(key []byte, at uint32) ([]byte, error) {
					bodyReads++
					require.Equal(t, miniHash, key)
					require.Equal(t, h.Epoch, at)
					if tc.name == "unavailable_body" {
						return nil, unavailable
					}
					return miniRaw, nil
				}},
				transactions: &qualSCRPayloadStorer{get: func(key []byte, at uint32) ([]byte, error) {
					require.Equal(t, txHash, key)
					require.Equal(t, s.Epoch, at)
					return txRaw, nil
				}},
			}
			byteLimit := f.limit - f.budget + len(f.bHash) + len(origin) + len(root) +
				len(miniHash) + len(txHash) + len(miniRaw) + len(txRaw)
			producer, consumer := f.producer, f.consumer
			earlyRefusal := true
			switch tc.name {
			case "same_shard":
				consumer = producer
			case "meta_source":
				producer = core.MetachainShardId
				coordinator.CurrentShard = producer
			case "meta_destination":
				consumer = core.MetachainShardId
			case "negative_miniblock_ordinal":
				ordinal = -1
			case "short_miniblock_identity":
				miniHash = miniHash[:len(miniHash)-1]
			case "identity_budget":
				byteLimit = len(f.bHash) - 1
			case "lookup_key_budget":
				byteLimit -= len(miniRaw) + len(txRaw) + 1
			case "insufficient_bytes":
				byteLimit--
				earlyRefusal = false
			default:
				earlyRefusal = false
			}
			proofsBefore := f.oracle.calls
			gotMini, gotTx, err := f.reader.readProducerNativeTransactionProjection(source, coordinator,
				f.bHash, origin, root, miniHash, txHash, producer, consumer, ordinal, index, witness, byteLimit)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, gotMini)
				require.Nil(t, gotTx)
				if earlyRefusal {
					require.Equal(t, proofsBefore, f.oracle.calls)
					require.Zero(t, bodyReads)
				}
				switch tc.name {
				case "wrong_result_root", "different_meta_branch", "wrong_meta_position", "wrong_header_position", "wrong_destination":
					require.Zero(t, bodyReads)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, mini, gotMini)
			require.Equal(t, tx, gotTx)
			require.Equal(t, 1, bodyReads)
		})
	}
}

func TestQualDRWANativeTransactionProjectionSourceEpochs(t *testing.T) {
	// The source's proposed TxBlock stores the original transaction at the
	// committing S epoch. H's executed-data save can publish a different
	// miniblock at H's commit epoch. Construct both contexts and their lookup
	// expectations independently of the reader. The storers model explicit
	// lookup locations, not the native archive's physical retention.
	missing := errors.New("object missing from its native lookup")
	mislocated := errors.New("lookup requested at a different epoch")
	for _, tc := range []struct {
		name        string
		wantErr     error
		wantLookups int
	}{
		{"split_publication_epochs", nil, 2},
		{"same_producer_epoch_later_consumer", nil, 2},
		{"consumer_side_storage_context", ErrInvalidAccountWitness, 0},
		{"other_shard_storage_context", ErrInvalidAccountWitness, 0},
		{"missing_source_header", ErrInvalidAccountWitness, 0},
		{"missing_carrying_header", ErrInvalidAccountWitness, 0},
		{"missing_miniblock", missing, 1},
		{"missing_original_transaction", missing, 2},
		{"different_miniblock_bytes", ErrInvalidAccountWitness, 1},
		{"different_transaction_bytes", ErrInvalidAccountWitness, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCanonicalTestFixture(t, 1, 0)
			coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: f.producer}
			tx := &transaction.Transaction{
				Nonce: 27, Value: big.NewInt(0), Signature: []byte{1},
				SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32),
				GasLimit: 120000,
			}
			txRaw := f.encode(t, tx)
			txHash := f.hash(txRaw)
			mini := &block.MiniBlock{Type: block.TxBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer,
				TxHashes: [][]byte{txHash}}
			miniRaw := f.encode(t, mini)
			miniHash := f.hash(miniRaw)
			otherTx := *tx
			otherTx.Nonce++
			otherTxRaw := f.encode(t, &otherTx)
			otherMini := *mini
			otherMini.TxHashes = [][]byte{f.hash(otherTxRaw)}
			otherMiniRaw := f.encode(t, &otherMini)

			s, h := &block.HeaderV3{}, &block.HeaderV3{}
			require.NoError(t, s.Unmarshal(f.w.Account.ExecutedHeader))
			require.NoError(t, h.Unmarshal(f.w.Account.Header))
			sameProducerEpoch := tc.name == "same_producer_epoch_later_consumer"
			if sameProducerEpoch {
				h.Epoch = s.Epoch
			} else {
				require.NotEqual(t, s.Epoch, h.Epoch)
			}
			header := block.MiniBlockHeader{Hash: miniHash, TxCount: 1, Type: block.TxBlock,
				SenderShardID: f.producer, ReceiverShardID: f.consumer}
			h.ExecutionResults[0].MiniBlockHeaders = []block.MiniBlockHeader{header}
			f.w.Account.Header = f.encode(t, h)
			f.w.HeaderProof = f.proof(t, h, f.w.Account.Header)
			proposal := &f.metas[0].ShardInfoProposal[0]
			proposal.HeaderHash = f.hash(f.w.Account.Header)
			proposal.Epoch = h.Epoch
			f.metas[0].ShardInfo[0].ShardMiniBlockHeaders = []block.MiniBlockHeader{header}
			f.rechain(t)

			root, err := f.s.RootHash()
			require.NoError(t, err)
			origin := f.hash(f.w.Account.ExecutedHeader)
			if sameProducerEpoch {
				b := &block.HeaderV3{}
				require.NoError(t, b.Unmarshal(f.w.Consumer))
				require.Less(t, h.Epoch, b.Epoch)
				require.NotEqual(t, origin, proposal.HeaderHash)
			}
			witness := f.w
			switch tc.name {
			case "consumer_side_storage_context":
				coordinator.CurrentShard = f.consumer
			case "other_shard_storage_context":
				coordinator.CurrentShard = 2
			case "missing_source_header":
				witness.Account.ExecutedHeader = nil
			case "missing_carrying_header":
				witness.Account.Header = nil
			}

			lookups := 0
			available := false
			source := &qualSCRPayloadStorage{
				mini: &qualSCRPayloadStorer{get: func(key []byte, epoch uint32) ([]byte, error) {
					lookups++
					require.Equal(t, miniHash, key)
					if epoch != h.Epoch {
						return nil, mislocated
					}
					if tc.name == "missing_miniblock" && !available {
						return nil, missing
					}
					if tc.name == "different_miniblock_bytes" {
						return otherMiniRaw, nil
					}
					return miniRaw, nil
				}},
				transactions: &qualSCRPayloadStorer{get: func(key []byte, epoch uint32) ([]byte, error) {
					lookups++
					require.Equal(t, txHash, key)
					if epoch != s.Epoch {
						return nil, mislocated
					}
					if tc.name == "missing_original_transaction" && !available {
						return nil, missing
					}
					if tc.name == "different_transaction_bytes" {
						return otherTxRaw, nil
					}
					return txRaw, nil
				}},
			}
			budget := f.limit - f.budget + len(f.bHash) + len(origin) + len(root) +
				len(miniHash) + len(txHash) + len(miniRaw) + len(txRaw)
			read := func() (*block.MiniBlock, *transaction.Transaction, error) {
				return f.reader.readProducerNativeTransactionProjection(source, coordinator,
					f.bHash, origin, root, miniHash, txHash, f.producer, f.consumer, 0, 0, witness, budget)
			}
			gotMini, gotTx, err := read()
			require.Equal(t, tc.wantLookups, lookups)
			if coordinator.CurrentShard != f.producer {
				require.Zero(t, f.oracle.calls, "store locality is checked before canonical dependencies")
			}
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, gotMini)
				require.Nil(t, gotTx)
				if tc.wantErr != missing {
					return
				}
				// Restore the same bound object at its original lookup.
				available = true
				lookups = 0
				gotMini, gotTx, err = read()
				require.Equal(t, 2, lookups)
			}
			require.NoError(t, err)
			require.Equal(t, mini, gotMini)
			require.Equal(t, tx, gotTx)
		})
	}
}

func TestQualDRWANativeTransactionProjectionDescriptor(t *testing.T) {
	// Check typed native descriptor equality independently of proof fixtures,
	// storage or transaction execution.
	for _, tc := range []struct {
		name   string
		change func(*block.MiniBlockHeader, *block.ShardData)
	}{
		{"later_matching_origin", nil},
		{"source_header_type", func(source *block.MiniBlockHeader, _ *block.ShardData) { source.Type = block.SmartContractResultBlock }},
		{"source_header_sender", func(source *block.MiniBlockHeader, _ *block.ShardData) { source.SenderShardID = 2 }},
		{"meta_header_type", func(_ *block.MiniBlockHeader, meta *block.ShardData) {
			meta.ShardMiniBlockHeaders[1].Type = block.SmartContractResultBlock
		}},
		{"meta_header_sender", func(_ *block.MiniBlockHeader, meta *block.ShardData) { meta.ShardMiniBlockHeaders[1].SenderShardID = 2 }},
		{"meta_header_receiver", func(_ *block.MiniBlockHeader, meta *block.ShardData) {
			meta.ShardMiniBlockHeaders[1].ReceiverShardID = 2
		}},
		{"meta_header_count", func(_ *block.MiniBlockHeader, meta *block.ShardData) { meta.ShardMiniBlockHeaders[1].TxCount++ }},
		{"meta_header_hash", func(_ *block.MiniBlockHeader, meta *block.ShardData) {
			meta.ShardMiniBlockHeaders[1].Hash = bytes.Clone(meta.ShardMiniBlockHeaders[0].Hash)
		}},
		{"meta_shard_identity", func(_ *block.MiniBlockHeader, meta *block.ShardData) { meta.ShardID = 2 }},
		{"meta_origin_identity", func(_ *block.MiniBlockHeader, meta *block.ShardData) {
			meta.HeaderHash = []byte("a different source proposal")
		}},
		{"meta_ordinal_outside_list", func(_ *block.MiniBlockHeader, meta *block.ShardData) {
			meta.ShardMiniBlockHeaders = meta.ShardMiniBlockHeaders[:1]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCanonicalTestFixture(t, 1, 0)
			origin := f.hash(f.w.Account.ExecutedHeader)
			first := block.MiniBlockHeader{Type: block.TxBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer,
				Hash: f.hash([]byte("ordinary first descriptor")), TxCount: 1}
			second := first
			second.Hash = f.hash([]byte("ordinary second descriptor"))
			second.TxCount = 2
			earlier := &block.ExecutionResult{
				BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: f.hash([]byte("another source result"))},
				MiniBlockHeaders:    []block.MiniBlockHeader{first},
			}
			selected := &block.ExecutionResult{
				BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: origin},
				MiniBlockHeaders:    []block.MiniBlockHeader{first, second},
			}
			shard := block.ShardData{ShardID: f.producer, HeaderHash: origin, ShardMiniBlockHeaders: []block.MiniBlockHeader{first, second}}
			if tc.change != nil {
				tc.change(&selected.MiniBlockHeaders[1], &shard)
			}
			projection := &canonicalResultProjection{
				carryingHeader: &block.HeaderV3{ExecutionResults: []*block.ExecutionResult{earlier, selected}},
				meta:           &block.MetaBlockV3{ShardInfo: []block.ShardData{shard}},
			}
			count, err := projectedNativeTransactionCount(projection, origin, second.Hash, f.producer, f.consumer, 1)
			if tc.change != nil {
				require.ErrorIs(t, err, ErrInvalidAccountWitness)
				require.Zero(t, count)
				return
			}
			require.NoError(t, err)
			require.Equal(t, uint32(2), count)
		})
	}
}
