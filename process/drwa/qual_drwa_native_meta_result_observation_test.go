package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/marshallerMock"
	"github.com/stretchr/testify/require"
)

// Part B 12.3/AM-012: native output is not a business settlement/refund or
// source-completion status. The previous/original identity distinction follows
// processorV2.createSCRsWhenError/setOriginalTxHash. These are synthetic
// header/signature/profile fixtures, not native ingress or funding admission.
func qualNativeMetaSCRFixture(t *testing.T,
	mutate func(*smartContractResult.SmartContractResult, *block.MiniBlock),
) (*canonicalTestFixture, []byte, []byte, []byte, []byte, int) {
	t.Helper()
	f := newCanonicalTestFixture(t, core.MetachainShardId, 0)
	previous, original := f.hash([]byte("synthetic immediate operation")), f.hash([]byte("synthetic original submission"))
	scr := &smartContractResult.SmartContractResult{Nonce: 1, Value: big.NewInt(0),
		SndAddr: bytes.Repeat([]byte{0x22}, 32), RcvAddr: bytes.Repeat([]byte{0x11}, 32),
		PrevTxHash: bytes.Clone(previous), OriginalTxHash: bytes.Clone(original), Data: []byte("@6f6b")}
	mb := &block.MiniBlock{SenderShardID: f.producer, ReceiverShardID: f.consumer, Type: block.SmartContractResultBlock}
	if mutate != nil {
		mutate(scr, mb)
	}
	scrRaw := f.encode(t, scr)
	if mb.TxHashes == nil {
		mb.TxHashes = [][]byte{f.hash(scrRaw)}
	}
	mbRaw := f.encode(t, mb)
	h, err := f.reader.header(f.w.Account.Header, f.producer)
	require.NoError(t, err)
	meta := h.(*block.MetaBlockV3)
	header := &block.MiniBlockHeader{Hash: f.hash(mbRaw), SenderShardID: mb.SenderShardID,
		ReceiverShardID: mb.ReceiverShardID, Type: mb.Type, TxCount: uint32(len(mb.TxHashes))}
	require.NoError(t, meta.ExecutionResults[0].SetMiniBlockHeadersHandlers([]data.MiniBlockHeaderHandler{header}))
	f.w.Account.Header = f.encode(t, meta)
	f.metas[0] = meta
	f.rechain(t)
	limit := f.limit - f.budget + len(mbRaw) + len(scrRaw) + len(previous) + len(original) + len(f.bHash) + len(f.hash(f.w.Account.ExecutedHeader))
	return f, previous, original, mbRaw, scrRaw, limit
}

func qualReadNativeMetaSCR(f *canonicalTestFixture, previous, original, mbRaw, scrRaw []byte,
	w canonicalResultWitness, limit int) (*nativeSCRCarrierObservation, error) {
	if reader, ok := interface{}(f.reader).(interface {
		readNativeMetaSCRObservation([]byte, uint32, []byte, []byte, []byte, canonicalResultWitness,
			[]byte, []byte, int) (*nativeSCRCarrierObservation, error)
	}); ok {
		return reader.readNativeMetaSCRObservation(f.bHash, f.consumer, f.hash(f.w.Account.ExecutedHeader),
			previous, original, w, mbRaw, scrRaw, limit)
	}
	// The old S1 entry deliberately rejects Meta sources. This exposes a missing
	// Meta outcome consumer, not a defect in the existing S1 import permission.
	return f.r.readNativeSCRObservation(f.reader, f.bHash, f.consumer, f.producer,
		f.hash(f.w.Account.ExecutedHeader), w, mbRaw, scrRaw, limit)
}

type qualMetaProofMutator struct {
	process.InterceptedHeaderSigVerifier
	mutate func()
}

func (v *qualMetaProofMutator) VerifyHeaderProof(proof data.HeaderProofHandler) error {
	v.mutate()
	return v.InterceptedHeaderSigVerifier.VerifyHeaderProof(proof)
}

func TestQualDRWANativeMetaResultObservation(t *testing.T) {
	t.Run("native_meta_output_and_both_transaction_identities", func(t *testing.T) {
		f, previous, original, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
		_, err := f.reader.readContext(f.bHash, f.consumer, f.producer,
			f.hash(f.w.Account.ExecutedHeader), f.w, f.limit)
		require.NoError(t, err, "the existing native Meta canonical-context fixture is available")
		observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
		require.NoError(t, err)
		require.Equal(t, previous, observed.result.PrevTxHash)
		require.Equal(t, original, observed.result.OriginalTxHash)
		require.NotEqual(t, previous, original)
		require.Equal(t, []byte("@6f6b"), observed.result.Data)
		require.Empty(t, observed.originCommitment, "pointwise transaction evidence supplies no complete class list or no-work proof")
		require.Equal(t, f.hash(f.w.Account.ExecutedHeader), observed.originHash)
		require.Equal(t, f.hash(f.w.Account.Header), observed.carryingHeaderHash)
		require.Equal(t, f.bHash, observed.consumerHeaderHash)
		require.Equal(t, f.hash(mbRaw), observed.miniBlockHash)
		require.Equal(t, f.hash(scrRaw), observed.resultHash)
		require.Equal(t, f.producer, observed.producer)
		require.Equal(t, f.consumer, observed.consumer)
		require.Equal(t, uint64(100), observed.asOfNonce)
		require.Equal(t, uint64(200), observed.asOfRound)
		require.Equal(t, uint32(4), observed.asOfEpoch)
	})
	t.Run("direct_submission_identity_and_exact_bound", func(t *testing.T) {
		f, previous, _, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, func(s *smartContractResult.SmartContractResult, _ *block.MiniBlock) {
			s.OriginalTxHash = bytes.Clone(s.PrevTxHash)
		})
		observed, err := qualReadNativeMetaSCR(f, previous, previous, mbRaw, scrRaw, f.w, limit)
		require.NoError(t, err)
		require.Equal(t, previous, observed.result.OriginalTxHash)
		require.Len(t, observed.metaHeaderHashes, len(f.w.MetaHeaders))
		for i, raw := range f.w.MetaHeaders {
			require.Equal(t, f.hash(raw), observed.metaHeaderHashes[len(f.w.MetaHeaders)-1-i])
		}
		slices.Reverse(f.w.MetaHeaders)
		slices.Reverse(f.w.MetaProofs)
		reordered, err := qualReadNativeMetaSCR(f, previous, previous, mbRaw, scrRaw, f.w, limit)
		require.NoError(t, err)
		require.Equal(t, observed, reordered)
		observed, err = qualReadNativeMetaSCR(f, previous, previous, mbRaw, scrRaw, f.w, limit-1)
		require.Error(t, err)
		require.Nil(t, observed)
	})
	t.Run("execution_identity_and_duplicate_references", func(t *testing.T) {
		for _, name := range []string{"wrong_source_nonce", "duplicate_origin", "duplicate_header", "duplicate_transaction"} {
			t.Run(name, func(t *testing.T) {
				f, previous, original, mbRaw, scrRaw, _ := qualNativeMetaSCRFixture(t, nil)
				h, err := f.reader.header(f.w.Account.Header, f.producer)
				require.NoError(t, err)
				meta := h.(*block.MetaBlockV3)
				switch name {
				case "wrong_source_nonce":
					meta.ExecutionResults[0].ExecutionResult.BaseExecutionResult.HeaderNonce++
				case "duplicate_origin":
					meta.ExecutionResults = append(meta.ExecutionResults, meta.ExecutionResults[0])
				case "duplicate_header":
					headers := meta.ExecutionResults[0].GetMiniBlockHeadersHandlers()
					require.NoError(t, meta.ExecutionResults[0].SetMiniBlockHeadersHandlers(append(headers, headers[0])))
				case "duplicate_transaction":
					mini := &block.MiniBlock{}
					require.NoError(t, f.r.codec.marshaller.Unmarshal(mini, mbRaw))
					mini.TxHashes = append(mini.TxHashes, bytes.Clone(mini.TxHashes[0]))
					mbRaw = f.encode(t, mini)
					header := &block.MiniBlockHeader{Hash: f.hash(mbRaw), SenderShardID: f.producer, ReceiverShardID: f.consumer,
						Type: block.SmartContractResultBlock, TxCount: uint32(len(mini.TxHashes))}
					require.NoError(t, meta.ExecutionResults[0].SetMiniBlockHeadersHandlers([]data.MiniBlockHeaderHandler{header}))
				}
				f.w.Account.Header = f.encode(t, meta)
				f.metas[0] = meta
				f.rechain(t)
				limit := f.limit - f.budget + len(mbRaw) + len(scrRaw) + len(previous) + len(original) + len(f.bHash) + len(f.hash(f.w.Account.ExecutedHeader))
				observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
				require.Error(t, err)
				require.Nil(t, observed)
			})
		}
	})
	t.Run("wrong_previous_or_original_identity", func(t *testing.T) {
		for _, name := range []string{"previous", "original"} {
			t.Run(name, func(t *testing.T) {
				f, previous, original, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
				if name == "previous" {
					previous = bytes.Repeat([]byte{0xee}, len(previous))
				} else {
					original = bytes.Repeat([]byte{0xee}, len(original))
				}
				observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
				require.Error(t, err)
				require.Nil(t, observed)
			})
		}
	})
	t.Run("authenticated_malformed_native_output", func(t *testing.T) {
		cases := map[string]func(*smartContractResult.SmartContractResult, *block.MiniBlock){
			"negative_value": func(s *smartContractResult.SmartContractResult, _ *block.MiniBlock) { s.Value = big.NewInt(-1) },
			"wrong_route":    func(_ *smartContractResult.SmartContractResult, m *block.MiniBlock) { m.ReceiverShardID = 2 },
			"wrong_type":     func(_ *smartContractResult.SmartContractResult, m *block.MiniBlock) { m.Type = block.TxBlock },
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				f, previous, original, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, mutate)
				observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
				require.Error(t, err)
				require.Nil(t, observed)
			})
		}
	})
	t.Run("unavailable_corrupt_restored_and_replay", func(t *testing.T) {
		f, previous, original, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
		first, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
		require.NoError(t, err)
		for _, payload := range [][]byte{nil, []byte("corrupt")} {
			observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, payload, f.w, limit)
			require.Error(t, err)
			require.Nil(t, observed)
		}
		unavailable := f.w
		unavailable.MetaProofs = nil
		observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, unavailable, limit)
		require.Error(t, err)
		require.Nil(t, observed)
		restored, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
		require.NoError(t, err)
		require.Equal(t, first, restored)
		first.result.Data[0] ^= 1
		first.consumerHeaderHash[0] ^= 1
		replay, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
		require.NoError(t, err)
		require.Equal(t, restored, replay)
	})
	t.Run("input_aliases_cannot_change_selected_context", func(t *testing.T) {
		f, previous, original, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
		expectedB, expectedOrigin, expectedCarrying := bytes.Clone(f.bHash), f.hash(f.w.Account.ExecutedHeader), f.hash(f.w.Account.Header)
		expectedMB, expectedSCR := f.hash(mbRaw), f.hash(scrRaw)
		expectedMetas := make([][]byte, len(f.w.MetaHeaders))
		for i, raw := range f.w.MetaHeaders {
			expectedMetas[len(expectedMetas)-1-i] = f.hash(raw)
		}
		mutated := false
		f.reader.proofs = &qualMetaProofMutator{f.reader.proofs, func() {
			if mutated {
				return
			}
			mutated = true
			for _, raw := range [][]byte{f.bHash, previous, original, mbRaw, scrRaw, f.w.Consumer, f.w.Account.Header, f.w.Account.ExecutedHeader} {
				raw[0] ^= 1
			}
			for _, list := range [][][]byte{f.w.MetaHeaders, f.w.MetaProofs, f.w.Account.AccountProof, f.w.Account.DataProof} {
				for _, raw := range list {
					raw[0] ^= 1
				}
			}
		}}
		observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
		require.NoError(t, err)
		require.True(t, mutated)
		require.Equal(t, expectedB, observed.consumerHeaderHash)
		require.Equal(t, expectedOrigin, observed.originHash)
		require.Equal(t, expectedCarrying, observed.carryingHeaderHash)
		require.Equal(t, expectedMB, observed.miniBlockHash)
		require.Equal(t, expectedSCR, observed.resultHash)
		require.Equal(t, expectedMetas, observed.metaHeaderHashes)
	})
	t.Run("missing_context_refuses_without_observation", func(t *testing.T) {
		for _, name := range []string{"nil_reader", "nil_accounts", "missing_previous", "missing_original", "short_previous", "short_original", "meta_consumer", "missing_header", "excess_proof"} {
			t.Run(name, func(t *testing.T) {
				f, previous, original, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
				w := f.w
				proofsBefore := f.oracle.calls
				switch name {
				case "nil_reader":
					f.reader = nil
				case "nil_accounts":
					f.reader.accounts = nil
				case "missing_previous":
					previous = nil
				case "missing_original":
					original = nil
				case "short_previous":
					previous = previous[:len(previous)-1]
				case "short_original":
					original = original[:len(original)-1]
				case "meta_consumer":
					f.consumer = core.MetachainShardId
				case "missing_header":
					w.Account.Header = nil
				case "excess_proof":
					w.Account.DataProof = [][]byte{make([]byte, limit+1)}
				}
				observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, w, limit)
				require.Error(t, err)
				require.Nil(t, observed)
				require.Equal(t, proofsBefore, f.oracle.calls, "context validation must precede proof verification")
			})
		}
	})
	t.Run("wrong_consumer_or_budget", func(t *testing.T) {
		f, previous, original, mbRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
		observed, err := qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, 1)
		require.Error(t, err)
		require.Nil(t, observed)
		f.bHash = bytes.Repeat([]byte{0xee}, len(f.bHash))
		observed, err = qualReadNativeMetaSCR(f, previous, original, mbRaw, scrRaw, f.w, limit)
		require.Error(t, err)
		require.Nil(t, observed)
	})
}

func TestQualDRWAStoredNativeMetaResultObservation(t *testing.T) {
	for _, name := range []string{
		"bound_typed_payload", "raw_and_stored_agree_at_same_block",
		"bounded_native_reader_work",
		"transaction_version_is_separate_from_scr_provenance",
		"snapshot_before_native_storage", "unavailable_then_restored",
		"wrong_storage_bytes", "wrong_consumer_branch", "wrong_original", "limit_below_exact",
		"unreadable_miniblock", "unreadable_result",
	} {
		t.Run(name, func(t *testing.T) {
			f, previous, original, miniRaw, resultRaw, limit := qualNativeMetaSCRFixture(t,
				func(scr *smartContractResult.SmartContractResult, _ *block.MiniBlock) {
					scr.Value.SetInt64(117)
					scr.GasLimit, scr.GasPrice = 19, 23
				})
			b, err := f.reader.header(f.w.Consumer, f.consumer)
			require.NoError(t, err)
			bHash := bytes.Clone(f.bHash)
			origin := f.hash(f.w.Account.ExecutedHeader)
			hHash := f.hash(f.w.Account.Header)
			miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
			rawLimit := limit
			limit += len(miniHash) + len(resultHash)
			epoch := b.GetEpoch() + 1
			unavailable := errors.New("original native storage input unavailable")
			unreadable := errors.New("native epoch read failed")
			missing := name == "unavailable_then_restored"
			var epochs []uint32
			source := &qualSCRPayloadStorage{
				mini: &qualSCRPayloadStorer{get: func(key []byte, gotEpoch uint32) ([]byte, error) {
					require.Equal(t, miniHash, key)
					epochs = append(epochs, gotEpoch)
					if name == "unreadable_miniblock" {
						return nil, unreadable
					}
					if name == "snapshot_before_native_storage" {
						clear(f.bHash)
						clear(f.w.Consumer)
						clear(f.w.MetaHeaders[0])
					}
					return miniRaw, nil
				}},
				results: &qualSCRPayloadStorer{get: func(key []byte, gotEpoch uint32) ([]byte, error) {
					require.Equal(t, resultHash, key)
					epochs = append(epochs, gotEpoch)
					if name == "unreadable_result" {
						return nil, unreadable
					}
					if missing {
						return nil, unavailable
					}
					if name == "wrong_storage_bytes" {
						return append(bytes.Clone(resultRaw), 0), nil
					}
					return resultRaw, nil
				}},
			}

			if name == "wrong_consumer_branch" {
				f.bHash[0] ^= 1
			}
			wantOriginal := bytes.Clone(original)
			if name == "wrong_original" {
				original[0] ^= 1
			}
			if name == "limit_below_exact" {
				limit--
			}
			read := func() (*nativeSCRCarrierObservation, error) {
				return f.reader.readStoredNativeMetaSCRObservation(source, epoch, miniHash, resultHash, f.bHash,
					f.consumer, origin, previous, original, f.w, limit)
			}
			proofCallsBefore := f.oracle.calls
			got, err := read()
			switch name {
			case "wrong_storage_bytes", "wrong_consumer_branch", "wrong_original", "limit_below_exact":
				require.Error(t, err)
				require.Nil(t, got)
				return
			case "unreadable_miniblock", "unreadable_result":
				require.ErrorIs(t, err, unreadable)
				require.Nil(t, got)
				if name == "unreadable_miniblock" {
					require.Len(t, epochs, 1)
				} else {
					require.Len(t, epochs, 2)
				}
				return
			case "unavailable_then_restored":
				require.ErrorIs(t, err, unavailable)
				require.Nil(t, got)
				require.Equal(t, []uint32{epoch, epoch}, epochs)
				require.Equal(t, proofCallsBefore, f.oracle.calls, "missing payload must stop before proof verification")
				missing = false
				got, err = read()
				require.Equal(t, []uint32{epoch, epoch, epoch, epoch}, epochs)
				require.Equal(t, len(f.w.MetaProofs), f.oracle.calls-proofCallsBefore, "restored payload needs a fresh proof walk")
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Nil(t, got.originCommitment)
			require.Equal(t, bHash, got.consumerHeaderHash)
			require.Equal(t, origin, got.originHash)
			require.Equal(t, hHash, got.carryingHeaderHash)
			require.Equal(t, miniHash, got.miniBlockHash)
			require.Equal(t, resultHash, got.resultHash)
			require.Equal(t, b.GetEpoch(), got.asOfEpoch)
			require.Equal(t, b.GetNonce(), got.asOfNonce)
			require.Equal(t, b.GetRound(), got.asOfRound)
			require.Equal(t, core.MetachainShardId, got.producer)
			require.Equal(t, f.consumer, got.consumer)
			require.Equal(t, previous, got.result.PrevTxHash)
			require.Equal(t, wantOriginal, got.result.OriginalTxHash)
			require.Equal(t, uint64(1), got.result.Nonce)
			require.Equal(t, big.NewInt(117), got.result.Value)
			require.Equal(t, []byte("@6f6b"), got.result.Data)
			require.Equal(t, uint64(19), got.result.GasLimit)
			require.Equal(t, uint64(23), got.result.GasPrice)
			require.Equal(t, bytes.Repeat([]byte{0x22}, 32), got.result.SndAddr)
			require.Equal(t, bytes.Repeat([]byte{0x11}, 32), got.result.RcvAddr)
			require.NotEmpty(t, epochs)
			for _, gotEpoch := range epochs {
				require.Equal(t, epoch, gotEpoch)
			}
			if name == "transaction_version_is_separate_from_scr_provenance" {
				require.Equal(t, uint32(4), got.asOfEpoch)
				require.Equal(t, []uint32{5, 5}, epochs)
				scrMini := &block.MiniBlock{}
				require.NoError(t, f.reader.accounts.args.Marshaller.Unmarshal(scrMini, miniRaw))
				require.Equal(t, block.SmartContractResultBlock, scrMini.Type)
				require.Equal(t, [][]byte{got.resultHash}, scrMini.TxHashes)

				// A separate ordinary TxBlock control supplies a native Version.
				// It does not stand in for the observed SCR's original transaction.
				tx := &transaction.Transaction{
					Nonce: 17, Value: big.NewInt(0), Signature: []byte{1},
					SndAddr: bytes.Repeat([]byte{1}, 32), RcvAddr: bytes.Repeat([]byte{2}, 32),
					GasLimit: 120000, Version: core.InitialVersionOfTransaction,
				}
				txRaw := f.encode(t, tx)
				txHash := f.hash(txRaw)
				txMini := &block.MiniBlock{
					Type: block.TxBlock, SenderShardID: 1, ReceiverShardID: 0, TxHashes: [][]byte{txHash},
				}
				txMiniRaw := f.encode(t, txMini)
				txMiniHash := f.hash(txMiniRaw)
				txLimit := len(txMiniHash) + len(txHash) + len(txMiniRaw) + len(txRaw)
				coordinator := &testscommon.ShardsCoordinatorMock{NoShards: 3, CurrentShard: 1}
				member, originalTx, err := f.reader.accounts.decodeNativeTransactionMember(
					coordinator, txMiniHash, txHash, txMiniRaw, txRaw, 1, 0, 0, txLimit)
				require.NoError(t, err)
				require.Equal(t, block.TxBlock, member.Type)
				require.Equal(t, uint32(1), originalTx.Version)
				require.Equal(t, uint64(19), got.result.GasLimit)
				require.NotEqual(t, txHash, got.result.OriginalTxHash)
			}
			if name == "raw_and_stored_agree_at_same_block" {
				// Acquisition changes neither the typed result nor its B coordinate.
				require.Equal(t, []uint32{epoch, epoch}, epochs)
				require.NotEqual(t, epoch, got.asOfEpoch)
				require.Len(t, f.metas, 3)
				wantPath := [][]byte{f.hash(f.encode(t, f.metas[2])), f.hash(f.encode(t, f.metas[1])), hHash}
				require.Equal(t, wantPath, got.metaHeaderHashes)
				raw, err := f.reader.readNativeMetaSCRObservation(bHash, f.consumer, origin,
					previous, original, f.w, miniRaw, resultRaw, rawLimit)
				require.NoError(t, err)
				require.Equal(t, got, raw)

				reordered := f.w
				reordered.MetaHeaders = slices.Clone(f.w.MetaHeaders)
				reordered.MetaProofs = slices.Clone(f.w.MetaProofs)
				slices.Reverse(reordered.MetaHeaders)
				slices.Reverse(reordered.MetaProofs)

				checkOrder := func(witness canonicalResultWitness, addedBytes int) {
					t.Helper()
					stored, err := f.reader.readStoredNativeMetaSCRObservation(source, epoch, miniHash, resultHash, bHash,
						f.consumer, origin, previous, original, witness, limit+addedBytes)
					require.NoError(t, err)
					require.NotNil(t, stored)
					require.Equal(t, wantPath, stored.metaHeaderHashes)

					direct, err := f.reader.readNativeMetaSCRObservation(bHash, f.consumer, origin,
						previous, original, witness, miniRaw, resultRaw, rawLimit+addedBytes)
					require.NoError(t, err)
					require.Equal(t, stored, direct)
					require.Equal(t, got, stored)
				}
				checkOrder(reordered, 0)
				require.Equal(t, []uint32{epoch, epoch, epoch, epoch}, epochs)

				addedBytes := qualAppendUnrelatedMetaSibling(t, f)
				checkOrder(f.w, addedBytes)
				slices.Reverse(f.w.MetaHeaders)
				slices.Reverse(f.w.MetaProofs)
				checkOrder(f.w, addedBytes)
				require.Equal(t, []uint32{epoch, epoch, epoch, epoch, epoch, epoch, epoch, epoch}, epochs)
			}
			if name == "bounded_native_reader_work" {
				// The three-header fixture walks from B's anchor to H.
				require.Len(t, f.w.MetaHeaders, 3)
				require.Len(t, f.w.MetaProofs, 3)
				require.Equal(t, [][]byte{f.hash(f.w.MetaHeaders[2]),
					f.hash(f.w.MetaHeaders[1]), f.hash(f.w.MetaHeaders[0])}, got.metaHeaderHashes)
				proofCalls := f.oracle.calls - proofCallsBefore
				require.Equal(t, 3, proofCalls)
				require.Equal(t, []uint32{epoch, epoch}, epochs)

				witnessBytes := f.limit - f.budget
				identityBytes := len(bHash) + len(origin) + len(previous) + len(original)
				lookupKeyBytes := len(miniHash) + len(resultHash)
				require.Equal(t, witnessBytes+identityBytes+lookupKeyBytes+len(miniRaw)+len(resultRaw), limit)
				t.Logf("reader component: input_bytes=%d witness_bytes=%d identity_bytes=%d lookup_key_bytes=%d miniblock_bytes=%d scr_bytes=%d epoch_reads=%d stub_proof_calls=%d",
					limit, witnessBytes, identityBytes, lookupKeyBytes, len(miniRaw), len(resultRaw), len(epochs), proofCalls)
			}
		})
	}
}

func TestQualDRWANativeMetaResultRouteBoundaries(t *testing.T) {
	t.Run("reward_carrier_stops_before_payload_hashing", func(t *testing.T) {
		f, previous, original, _, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
		reward := &block.MiniBlock{Type: block.RewardsBlock, SenderShardID: f.producer, ReceiverShardID: f.consumer,
			TxHashes: [][]byte{f.hash([]byte("ordinary fixture reward identity"))}}
		rewardRaw := f.encode(t, reward)
		origin := f.hash(f.w.Account.ExecutedHeader)
		hasher := f.reader.accounts.args.Hasher
		codec := f.reader.accounts.args.Marshaller
		rewardDecodes := 0
		f.reader.accounts.args.Marshaller = &marshallerMock.MarshalizerStub{
			MarshalCalled: codec.Marshal,
			UnmarshalCalled: func(target interface{}, input []byte) error {
				if bytes.Equal(input, rewardRaw) {
					rewardDecodes++
				}
				return codec.Unmarshal(target, input)
			},
		}
		rewardHashes := 0
		f.reader.accounts.args.Hasher = &testscommon.HasherStub{
			SizeCalled: hasher.Size,
			ComputeCalled: func(input string) []byte {
				if input == string(rewardRaw) {
					rewardHashes++
				}
				return hasher.Compute(input)
			},
		}
		// Keep the existing proof context intact. A reward carrier belongs to
		// a different native family and must stop before SCR payload hashing.
		_, err := f.reader.readNativeMetaSCRObservation(f.bHash, f.consumer, origin, previous, original,
			f.w, rewardRaw, scrRaw, limit+len(rewardRaw))
		require.Error(t, err)
		require.Equal(t, 1, rewardDecodes, "the ordinary proof path reached the native body boundary")
		require.Zero(t, rewardHashes)
	})
	t.Run("meta_consumer_stops_before_storage", func(t *testing.T) {
		f, previous, original, miniRaw, scrRaw, limit := qualNativeMetaSCRFixture(t, nil)
		origin, miniHash, scrHash := f.hash(f.w.Account.ExecutedHeader), f.hash(miniRaw), f.hash(scrRaw)
		reads := 0
		unavailable := &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) {
			reads++
			return nil, errors.New("ordinary fixture storage unavailable")
		}}
		source := &qualSCRPayloadStorage{mini: unavailable, results: unavailable}
		_, err := f.reader.readStoredNativeMetaSCRObservation(source, 4, miniHash, scrHash, f.bHash,
			core.MetachainShardId, origin, previous, original, f.w, limit+len(miniHash)+len(scrHash))
		require.Error(t, err)
		require.Zero(t, reads)
	})
}

func TestQualDRWAStoredNativeMetaResultAsOf(t *testing.T) {
	f, previous, original, miniRaw, resultRaw, limit := qualNativeMetaSCRFixture(t, nil)
	origin := f.hash(f.w.Account.ExecutedHeader)
	miniHash, resultHash := f.hash(miniRaw), f.hash(resultRaw)
	oldHash, oldWitness := bytes.Clone(f.bHash), f.w

	// AM-012 and G15: the native B identity is part of the observation.
	// The same immutable upstream output can be observed at either admitted
	// B, but an older B's witness cannot answer a read bound to another B.
	next := &block.HeaderV3{}
	require.NoError(t, next.Unmarshal(oldWitness.Consumer))
	next.Nonce++
	next.Round++
	next.Epoch++
	next.PrevHash = bytes.Clone(oldHash)
	nextWitness := oldWitness
	nextWitness.Consumer = f.encode(t, next)
	nextHash := f.hash(nextWitness.Consumer)

	// Build a sibling meta tip at the same height. It shares the selected
	// source result but cannot satisfy a read whose B anchors the other tip.
	f.metas[len(f.metas)-1].RandSeed = []byte("different synthetic meta tip")
	f.rechain(t)
	mixed := f.w
	mixed.Consumer = nextWitness.Consumer
	require.NotEqual(t, next.MetaBlockHashes[0], f.hash(mixed.MetaHeaders[len(mixed.MetaHeaders)-1]))

	source := &qualSCRPayloadStorage{
		mini:    &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return miniRaw, nil }},
		results: &qualSCRPayloadStorer{get: func([]byte, uint32) ([]byte, error) { return resultRaw, nil }},
	}
	limit += len(miniHash) + len(resultHash) + len(nextWitness.Consumer) + f.limit
	read := func(b []byte, witness canonicalResultWitness) (*nativeSCRCarrierObservation, error) {
		return f.reader.readStoredNativeMetaSCRObservation(source, next.Epoch+1, miniHash, resultHash, b,
			f.consumer, origin, previous, original, witness, limit)
	}

	historical, err := read(oldHash, oldWitness)
	require.NoError(t, err)
	require.Equal(t, oldHash, historical.consumerHeaderHash)
	require.Equal(t, next.Nonce-1, historical.asOfNonce)
	require.Equal(t, next.Round-1, historical.asOfRound)
	require.Equal(t, next.Epoch-1, historical.asOfEpoch)
	wantPath := make([][]byte, len(oldWitness.MetaHeaders))
	for i, raw := range oldWitness.MetaHeaders {
		wantPath[len(wantPath)-1-i] = f.hash(raw)
	}
	require.Equal(t, wantPath, historical.metaHeaderHashes)

	current, err := read(nextHash, nextWitness)
	require.NoError(t, err)
	require.Equal(t, nextHash, current.consumerHeaderHash)
	require.Equal(t, next.Nonce, current.asOfNonce)
	require.Equal(t, next.Round, current.asOfRound)
	require.Equal(t, next.Epoch, current.asOfEpoch)
	require.Equal(t, historical.resultHash, current.resultHash)
	require.Equal(t, wantPath, current.metaHeaderHashes)

	for _, tc := range []struct {
		name    string
		b       []byte
		witness canonicalResultWitness
	}{
		{"historical_witness_for_next_block", nextHash, oldWitness},
		{"next_witness_for_historical_block", oldHash, nextWitness},
		{"different_meta_tip_under_same_block", nextHash, mixed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := read(tc.b, tc.witness)
			require.ErrorIs(t, err, ErrInvalidAccountWitness)
			require.Nil(t, got)
		})
	}
}
