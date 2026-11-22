package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"
)

// Synthetic header/signature/profile fixtures, with actual native account/data
// tries and the independent Step-1 record vector. No native ingress, authority,
// historical-service admission, pricing or funded application is qualified.
func qualBootstrapIntentOutcomeFixture(t *testing.T, value []byte) (*canonicalTestFixture, *registrationRecords, []byte) {
	t.Helper()
	f := newCanonicalTestFixture(t, core.MetachainShardId, 0)
	_, _, _, id := qualRecordBody()
	key := append([]byte(registrationIntentPrefix), id...)
	qualRecordPut(t, f.s.qualNativeStore, key, value)
	root, err := f.s.Commit()
	require.NoError(t, err)
	h, err := f.reader.header(f.w.Account.Header, f.producer)
	require.NoError(t, err)
	meta := h.(*block.MetaBlockV3)
	meta.ExecutionResults[0].ExecutionResult.BaseExecutionResult.RootHash = root
	f.w.Account.Header = f.encode(t, meta)
	f.metas[0] = meta
	f.w.Account, err = f.reader.accounts.BuildNativeWitness(f.s, f.hash(f.w.Account.Header), f.producer,
		core.SystemAccountAddress, key, f.w.Account, 1<<20)
	require.NoError(t, err)
	f.rechain(t)
	records, err := newRegistrationRecords(f.s, f.reader.accounts.args.Marshaller, f.reader.accounts.args.Hasher, 4096)
	require.NoError(t, err)
	return f, records, id
}

func qualReadBootstrapIntent(f *canonicalTestFixture, records *registrationRecords, id []byte,
	w canonicalResultWitness) (*nativeBootstrapIntentObservation, error) {
	if reader, ok := interface{}(f.reader).(interface {
		readBootstrapIntent(*registrationRecords, []byte, uint32, uint32, []byte, []byte,
			canonicalResultWitness, int) (*nativeBootstrapIntentObservation, error)
	}); ok {
		return reader.readBootstrapIntent(records, f.bHash, f.consumer, f.producer, f.hash(f.w.Account.ExecutedHeader), id, w, f.limit)
	}
	// Before the class consumer exists, exercise the real canonical byte reader.
	// A valid trie proof alone supplies bytes, not a decoded BootstrapIntent.
	raw, err := f.reader.read(f.bHash, f.consumer, f.producer, f.hash(f.w.Account.ExecutedHeader),
		append([]byte(registrationIntentPrefix), id...), w, f.limit)
	if err != nil {
		return nil, err
	}
	return &nativeBootstrapIntentObservation{intent: &bootstrapIntentRecord{encoded: raw}}, nil
}

func TestQualDRWANativeBootstrapIntentOutcome(t *testing.T) {
	_, body, digest, id := qualRecordBody()
	t.Run("authenticated_record_requires_class_decoding", func(t *testing.T) {
		wrongBody := bytes.Replace(body, []byte{0x0a, 1, '1'}, []byte{0x0a, 1, '2'}, 1)
		require.NotEqual(t, body, wrongBody)
		cases := map[string][]byte{
			"malformed":              {0xff},
			"wrong_identity":         qualRecordFrame(wrongBody, []byte("OPEN"), nil),
			"unknown_state":          qualRecordFrame(body, []byte("REGISTERED"), nil),
			"open_with_token":        qualRecordFrame(body, []byte("OPEN"), []byte("TKN-123456")),
			"consumed_without_token": qualRecordFrame(body, []byte("CONSUMED"), nil),
		}
		for name, value := range cases {
			t.Run(name, func(t *testing.T) {
				f, records, intentID := qualBootstrapIntentOutcomeFixture(t, value)
				// The native root genuinely authenticates these bytes; the class binding
				// must still reject them without returning a partial observation.
				raw, err := f.reader.read(f.bHash, f.consumer, f.producer, f.hash(f.w.Account.ExecutedHeader),
					append([]byte(registrationIntentPrefix), intentID...), f.w, f.limit)
				require.NoError(t, err)
				require.Equal(t, value, raw)
				observed, err := qualReadBootstrapIntent(f, records, intentID, f.w)
				require.Error(t, err)
				require.Nil(t, observed)
			})
		}
	})
	t.Run("open_is_not_token_registration_or_activation", func(t *testing.T) {
		f, records, intentID := qualBootstrapIntentOutcomeFixture(t, qualRecordFrame(body, []byte("OPEN"), nil))
		// Canonical decoding must not consult a warm/current local registration DB.
		records.state = nil
		observed, err := qualReadBootstrapIntent(f, records, intentID, f.w)
		require.NoError(t, err)
		require.Equal(t, "OPEN", observed.intent.status)
		require.Empty(t, observed.intent.tokenID)
		require.Equal(t, body, observed.intent.encoded)
		require.Equal(t, digest, observed.intent.digest)
		require.Equal(t, id, intentID)
		require.Equal(t, f.hash(f.w.Account.ExecutedHeader), observed.sourceHash)
		require.Equal(t, f.hash(f.w.Account.Header), observed.resultHash)
		require.Equal(t, f.bHash, observed.consumerHash)
		require.Equal(t, f.producer, observed.producer)
		require.Equal(t, f.consumer, observed.consumer)
		require.Equal(t, uint64(100), observed.consumerNonce)
		require.Equal(t, uint64(200), observed.consumerRound)
		require.Equal(t, uint32(4), observed.consumerEpoch)
	})
	t.Run("lifecycle_is_preserved", func(t *testing.T) {
		for _, state := range []string{"CONSUMED", "CANCELLED"} {
			t.Run(state, func(t *testing.T) {
				var token []byte
				if state == "CONSUMED" {
					token = []byte("TKN-123456")
				}
				f, records, intentID := qualBootstrapIntentOutcomeFixture(t, qualRecordFrame(body, []byte(state), token))
				observed, err := qualReadBootstrapIntent(f, records, intentID, f.w)
				require.NoError(t, err)
				require.Equal(t, state, observed.intent.status)
				if state == "CONSUMED" {
					require.Equal(t, token, observed.intent.tokenID)
				} else {
					require.Empty(t, observed.intent.tokenID)
				}
			})
		}
	})
	t.Run("proof_service_can_release_caller_buffers", func(t *testing.T) {
		f, records, intentID := qualBootstrapIntentOutcomeFixture(t, qualRecordFrame(body, []byte("OPEN"), nil))
		origin := f.hash(f.w.Account.ExecutedHeader)
		carrying := f.hash(f.w.Account.Header)
		consumer := bytes.Clone(f.bHash)
		released := false
		f.reader.proofs = &qualMetaProofMutator{f.reader.proofs, func() {
			if released {
				return
			}
			released = true
			clear(f.w.Consumer)
			clear(f.w.Account.DataProof[0])
		}}
		observed, err := qualReadBootstrapIntent(f, records, intentID, f.w)
		require.NoError(t, err)
		require.True(t, released)
		require.Equal(t, origin, observed.sourceHash)
		require.Equal(t, carrying, observed.resultHash)
		require.Equal(t, consumer, observed.consumerHash)
		require.Equal(t, body, observed.intent.encoded)
	})
	t.Run("unavailable_is_not_absent_and_restoration_replays", func(t *testing.T) {
		f, records, intentID := qualBootstrapIntentOutcomeFixture(t, qualRecordFrame(body, []byte("OPEN"), nil))
		rootBefore, err := f.s.RootHash()
		require.NoError(t, err)
		journalBefore := f.s.JournalLen()
		first, err := qualReadBootstrapIntent(f, records, intentID, f.w)
		require.NoError(t, err)
		unavailable := f.w
		unavailable.Account.DataProof = nil
		observed, err := qualReadBootstrapIntent(f, records, intentID, unavailable)
		require.Error(t, err)
		require.Nil(t, observed)
		corrupt := f.w
		corrupt.Account.DataProof = [][]byte{[]byte("corrupt")}
		observed, err = qualReadBootstrapIntent(f, records, intentID, corrupt)
		require.Error(t, err)
		require.Nil(t, observed)
		restored, err := qualReadBootstrapIntent(f, records, intentID, f.w)
		require.NoError(t, err)
		require.Equal(t, first, restored)
		first.intent.encoded[0] ^= 1
		first.consumerHash[0] ^= 1
		replay, err := qualReadBootstrapIntent(f, records, intentID, f.w)
		require.NoError(t, err)
		require.Equal(t, restored, replay)
		rootAfter, err := f.s.RootHash()
		require.NoError(t, err)
		require.Equal(t, rootBefore, rootAfter)
		require.Equal(t, journalBefore, f.s.JournalLen())
	})
	t.Run("incomplete_context_never_publishes", func(t *testing.T) {
		for _, name := range []string{"nil_reader", "nil_codec", "invalid_codec_bound", "missing_intent_id", "oversized_header"} {
			t.Run(name, func(t *testing.T) {
				f, records, intentID := qualBootstrapIntentOutcomeFixture(t, qualRecordFrame(body, []byte("OPEN"), nil))
				w := f.w
				switch name {
				case "nil_reader":
					f.reader = nil
				case "nil_codec":
					records = nil
				case "invalid_codec_bound":
					records.maxBytes = 0
				case "missing_intent_id":
					intentID = nil
				case "oversized_header":
					w.Consumer = make([]byte, f.limit+1)
				}
				observed, err := qualReadBootstrapIntent(f, records, intentID, w)
				require.Error(t, err)
				require.Nil(t, observed)
			})
		}
	})
	t.Run("wrong_committed_consumer", func(t *testing.T) {
		f, records, intentID := qualBootstrapIntentOutcomeFixture(t, qualRecordFrame(body, []byte("OPEN"), nil))
		f.bHash = bytes.Repeat([]byte{0xee}, len(f.bHash))
		observed, err := qualReadBootstrapIntent(f, records, intentID, f.w)
		require.Error(t, err)
		require.Nil(t, observed)
	})
}
