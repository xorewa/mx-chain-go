package resolvers

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/dataRetriever"
	"github.com/multiversx/mx-chain-go/dataRetriever/mock"
	"github.com/multiversx/mx-chain-go/dataRetriever/resolvers/disabled"
	"github.com/multiversx/mx-chain-go/heartbeat"
	"github.com/multiversx/mx-chain-go/p2p"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/cache"
	drmock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/p2pmocks"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	trieMock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/stretchr/testify/require"
)

var qualG13Error = errors.New("experimental G13 collaborator error")

// Qualification fixtures use existing private/public resolver routes without
// network I/O. Sizes, keys, objects and errors are experimental, not profiles.
func TestQualPartialsG13EquivalentPrivateErrors(t *testing.T) {
	codec := &testscommon.MarshallerStub{}
	res := &equivalentProofsResolver{baseResolver: &baseResolver{TopicResolverSender: &mock.TopicResolverSenderStub{}}, messageProcessor: messageProcessor{marshalizer: codec, antifloodHandler: &mock.P2PAntifloodHandlerStub{}}, storage: &storageMock.ChainStorerStub{GetStorerCalled: func(dataRetriever.UnitType) (storage.Storer, error) { return nil, qualG13Error }}}
	t.Run("hash_key", func(t *testing.T) {
		require.ErrorIs(t, res.resolveHashRequest([]byte("invalid"), 0, "peer", nil), common.ErrInvalidHashShardKey, "equivalent hash parse guard")
	})
	t.Run("array_unmarshal", func(t *testing.T) {
		codec.UnmarshalCalled = func(interface{}, []byte) error { return qualG13Error }
		require.ErrorIs(t, res.resolveMultipleHashesRequest(nil, 0, "peer", nil, "peer", nil), qualG13Error, "equivalent array parse guard")
	})
	t.Run("array_key", func(t *testing.T) {
		_, e := res.fetchEquivalentProofsSlicesForHeaders([][]byte{[]byte("invalid")}, 0)
		require.ErrorIs(t, e, common.ErrInvalidHashShardKey, "equivalent array key guard")
	})
	t.Run("nonce_key", func(t *testing.T) {
		_, e := res.fetchEquivalentProofsFromNonceAsByteSlices([]byte("invalid"), 0)
		require.ErrorIs(t, e, common.ErrInvalidNonceShardKey, "equivalent nonce parse guard")
	})
	t.Run("nonce_storage", func(t *testing.T) {
		_, e := res.getProofFromStorageByNonce(1, 0, 0)
		require.ErrorIs(t, e, qualG13Error, "equivalent storer lookup guard")
	})
}

func TestQualPartialsG13PeerPrivateErrors(t *testing.T) {
	for _, mode := range []string{"missing", "type", "unmarshal", "timestamp", "marshal"} {
		t.Run(mode, func(t *testing.T) {
			codec := &testscommon.MarshallerStub{}
			pool := &cache.CacherStub{}
			validator := &testscommon.PeerAuthenticationPayloadValidatorStub{}
			pool.PeekCalled = func([]byte) (interface{}, bool) {
				if mode == "missing" {
					return nil, false
				}
				if mode == "type" {
					return "wrong-type", true
				}
				return &heartbeat.PeerAuthentication{Payload: []byte{1}}, true
			}
			codec.UnmarshalCalled = func(interface{}, []byte) error {
				if mode == "unmarshal" {
					return qualG13Error
				}
				return nil
			}
			codec.MarshalCalled = func(interface{}) ([]byte, error) {
				if mode == "marshal" {
					return nil, qualG13Error
				}
				return []byte("auth"), nil
			}
			validator.ValidateTimestampCalled = func(int64) error {
				if mode == "timestamp" {
					return qualG13Error
				}
				return nil
			}
			res := &peerAuthenticationResolver{messageProcessor: messageProcessor{marshalizer: codec}, peerAuthenticationPool: pool, payloadValidator: validator}
			b, e := res.fetchPeerAuthenticationAsByteSlice([]byte("key"))
			want := qualG13Error
			if mode == "missing" {
				want = dataRetriever.ErrPeerAuthNotFound
			}
			if mode == "type" {
				want = dataRetriever.ErrWrongTypeAssertion
			}
			require.ErrorIs(t, e, want, "peer private error identity")
			require.Nil(t, b)
		})
	}
}

func TestQualPartialsG13ArrayReplyCaps(t *testing.T) {
	for _, kind := range []string{"peer", "validator", "equivalent", "miniblock"} {
		t.Run(kind, func(t *testing.T) {
			// Two such replies exceed the pinned total cap; a third item is not fetched.
			blob := bytes.Repeat([]byte{7}, maxHashArrayReplySize/2+1)
			keys := [][]byte{{1}, {2}, {3}}
			lookups, packed := 0, 0
			codec := &testscommon.MarshallerStub{MarshalCalled: func(interface{}) ([]byte, error) { return blob, nil }, UnmarshalCalled: func(v interface{}, _ []byte) error {
				if b, yes := v.(*batch.Batch); yes {
					b.Data = keys
				}
				return nil
			}}
			sender := &mock.TopicResolverSenderStub{}
			base := &baseResolver{TopicResolverSender: sender}
			mp := messageProcessor{marshalizer: codec, antifloodHandler: &mock.P2PAntifloodHandlerStub{}}
			packer := &mock.DataPackerStub{PackDataInChunksCalled: func(b [][]byte, _ int) ([][]byte, error) {
				packed = len(b)
				require.Equal(t, [][]byte{blob}, b, "miniblock reply stops before oversized aggregate")
				return nil, nil
			}}
			var got [][]byte
			var e error
			switch kind {
			case "peer":
				res := &peerAuthenticationResolver{baseResolver: base, messageProcessor: mp, payloadValidator: &testscommon.PeerAuthenticationPayloadValidatorStub{}, peerAuthenticationPool: &cache.CacherStub{PeekCalled: func([]byte) (interface{}, bool) { lookups++; return &heartbeat.PeerAuthentication{}, true }}}
				got, e = res.fetchPeerAuthenticationSlicesForPublicKeys(keys)
			case "validator":
				res := &validatorInfoResolver{TopicResolverSender: sender, messageProcessor: mp, validatorInfoPool: &testscommon.ShardedDataStub{SearchFirstDataCalled: func([]byte) (interface{}, bool) { lookups++; return "value", true }}}
				got, e = res.fetchValidatorInfoForHashes(keys, 0)
			case "equivalent":
				res := &equivalentProofsResolver{baseResolver: base, messageProcessor: mp, equivalentProofsPool: &drmock.ProofsPoolMock{GetProofCalled: func(uint32, []byte) (data.HeaderProofHandler, error) { lookups++; return &block.HeaderProof{}, nil }}}
				composite := [][]byte{}
				for _, k := range keys {
					composite = append(composite, []byte(common.GetEquivalentProofHashShardKey(k, 0)))
				}
				got, e = res.fetchEquivalentProofsSlicesForHeaders(composite, 0)
			case "miniblock":
				res := &miniblockResolver{baseResolver: base, messageProcessor: mp, miniBlockPool: &cache.CacherStub{PeekCalled: func([]byte) (interface{}, bool) { lookups++; return "value", true }}, dataPacker: packer}
				e = res.resolveMbRequestByHashArray([]byte("batch"), "peer", 0, nil, "peer", nil)
			}
			require.NoError(t, e)
			require.Equal(t, 2, lookups, "reply cap stops later fetches")
			if kind == "miniblock" {
				require.Equal(t, 1, packed)
			} else {
				require.Equal(t, [][]byte{blob}, got, "reply cap result")
			}
		})
	}
}

func TestQualPartialsG13RecoveredErrorsAndDisabled(t *testing.T) {
	mp := messageProcessor{antifloodHandler: &mock.P2PAntifloodHandlerStub{CanProcessMessageCalled: func(p2p.MessageP2P, core.PeerID) error { panic("experimental recovered collaborator panic") }}}
	entries := []struct {
		name string
		r    interface {
			ProcessReceivedMessage(p2p.MessageP2P, core.PeerID, p2p.MessageHandler) ([]byte, error)
		}
	}{
		{"HeaderResolver", &HeaderResolver{messageProcessor: mp}}, {"TxResolver", &TxResolver{messageProcessor: mp}}, {"miniblockResolver", &miniblockResolver{messageProcessor: mp}}, {"TrieNodeResolver", &TrieNodeResolver{messageProcessor: mp}}, {"peerAuthenticationResolver", &peerAuthenticationResolver{messageProcessor: mp}}, {"validatorInfoResolver", &validatorInfoResolver{messageProcessor: mp}}, {"equivalentProofsResolver", &equivalentProofsResolver{messageProcessor: mp}},
	}
	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			_, e := entry.r.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{}, "peer", nil)
			require.ErrorContains(t, e, "panic in "+entry.name+".ProcessReceivedMessage", "resolver recovered error")
		})
	}
	t.Run("disabled", func(t *testing.T) {
		r := disabled.NewDisabledResolver()
		b, e := r.ProcessReceivedMessage(nil, "", nil)
		require.NoError(t, e)
		require.NotNil(t, b)
		require.Empty(t, b)
		require.NoError(t, r.SetDebugHandler(nil))
		require.NoError(t, r.SetEpochHandler(nil))
		require.NoError(t, r.Close())
		require.False(t, r.IsInterfaceNil())
	})
}

func TestQualPartialsG13NegativeChunk(t *testing.T) {
	calls := 0
	res := &TrieNodeResolver{baseResolver: &baseResolver{TopicResolverSender: &mock.TopicResolverSenderStub{SendCalled: func([]byte, core.PeerID, p2p.MessageHandler) error { calls++; return nil }}}}
	require.NoError(t, res.sendLargeMessage([]byte("node"), []byte("hash"), -1, &p2pmocks.P2PMessageMock{}, nil))
	require.Zero(t, calls, "negative chunk never sent")
}

func TestQualPartialsG13RemainingErrorIdentities(t *testing.T) {
	sender := &mock.TopicResolverSenderStub{}
	base := &baseResolver{TopicResolverSender: sender}
	codec := &testscommon.MarshallerStub{}
	mp := messageProcessor{marshalizer: codec, antifloodHandler: &mock.P2PAntifloodHandlerStub{}, throttler: &mock.ThrottlerStub{}}
	t.Run("header_send", func(t *testing.T) {
		codec.UnmarshalCalled = func(v interface{}, _ []byte) error {
			r := v.(*dataRetriever.RequestData)
			r.Type = dataRetriever.EpochType
			r.Value = []byte(core.EpochStartIdentifier(0))
			return nil
		}
		sender.SendCalled = func([]byte, core.PeerID, p2p.MessageHandler) error { return qualG13Error }
		r := &HeaderResolver{baseResolver: base, messageProcessor: mp, baseStorageResolver: &baseSimpleResolver{storer: &storageMock.StorerStub{SearchFirstCalled: func([]byte) ([]byte, error) { return []byte("header"), nil }}}}
		_, e := r.ProcessReceivedMessage(&p2pmocks.P2PMessageMock{DataField: []byte("request")}, "peer", nil)
		require.ErrorIs(t, e, qualG13Error, "header send error identity")
	})
	t.Run("miniblock_fetch", func(t *testing.T) {
		r := &miniblockResolver{baseResolver: base, messageProcessor: mp, miniBlockPool: &cache.CacherStub{}, baseStorageResolver: &baseSimpleResolver{storer: &storageMock.StorerStub{SearchFirstCalled: func([]byte) ([]byte, error) { return nil, qualG13Error }}}}
		require.ErrorIs(t, r.resolveMbRequestByHash([]byte("hash"), "peer", 0, nil), qualG13Error, "miniblock fetch error identity")
	})
	t.Run("peer_array_parse", func(t *testing.T) {
		c := &testscommon.MarshallerStub{UnmarshalCalled: func(interface{}, []byte) error { return qualG13Error }}
		r := &peerAuthenticationResolver{messageProcessor: messageProcessor{marshalizer: c}}
		require.ErrorIs(t, r.resolveMultipleHashesRequest(nil, "peer", nil, "peer", nil), qualG13Error, "peer array parse error identity")
		_, e := r.fetchPeerAuthenticationSlicesForPublicKeys(nil)
		require.ErrorIs(t, e, dataRetriever.ErrPeerAuthNotFound, "peer empty error identity")
	})
	t.Run("trie_subtree", func(t *testing.T) {
		r := &TrieNodeResolver{baseResolver: base, trieDataGetter: &trieMock.TrieStub{GetSerializedNodesCalled: func([]byte, uint64) ([][]byte, uint64, error) { return nil, 9, qualG13Error }}}
		_, left, e := r.getSubTrie([]byte("hash"), 9)
		require.ErrorIs(t, e, qualG13Error, "trie subtree error identity")
		require.Equal(t, uint64(9), left)
	})
	t.Run("trie_chunk_marshal", func(t *testing.T) {
		r := &TrieNodeResolver{messageProcessor: messageProcessor{marshalizer: &testscommon.MarshallerStub{MarshalCalled: func(interface{}) ([]byte, error) { return nil, qualG13Error }}}}
		require.ErrorIs(t, r.sendLargeMessage([]byte("node"), []byte("hash"), 0, &p2pmocks.P2PMessageMock{}, nil), qualG13Error, "trie chunk marshal error identity")
	})
	t.Run("validator_array_hash", func(t *testing.T) {
		c := &testscommon.MarshallerStub{UnmarshalCalled: func(v interface{}, _ []byte) error {
			v.(*batch.Batch).Data = [][]byte{make([]byte, common.HashSize+1)}
			return nil
		}}
		r := &validatorInfoResolver{messageProcessor: messageProcessor{marshalizer: c, antifloodHandler: &mock.P2PAntifloodHandlerStub{}}}
		require.ErrorIs(t, r.resolveMultipleHashesRequest(nil, 0, "peer", nil, nil), dataRetriever.ErrBadRequest, "validator array hash error identity")
	})
	t.Run("validator_batch_marshal", func(t *testing.T) {
		r := &validatorInfoResolver{messageProcessor: messageProcessor{marshalizer: &testscommon.MarshallerStub{MarshalCalled: func(interface{}) ([]byte, error) { return nil, qualG13Error }}}}
		require.ErrorIs(t, r.marshalAndSend([]byte("value"), "peer", nil), qualG13Error, "validator batch marshal error identity")
	})
}

func TestQualPartialsG13StorageModesAndTrieBudgets(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(map[bool]string{false: "simple", true: "full_history"}[full], func(t *testing.T) {
			search, epoch := 0, 0
			s := &storageMock.StorerStub{SearchFirstCalled: func([]byte) ([]byte, error) { search++; return []byte("simple"), nil }, GetFromEpochCalled: func(_ []byte, e uint32) ([]byte, error) {
				require.Equal(t, uint32(17), e)
				epoch++
				return []byte("epoch"), nil
			}}
			b, e := createBaseStorageResolver(s, full).getFromStorage([]byte("key"), 17)
			require.NoError(t, e)
			if full {
				require.Equal(t, []byte("epoch"), b)
				require.Equal(t, 1, epoch)
				require.Zero(t, search)
			} else {
				require.Equal(t, []byte("simple"), b)
				require.Equal(t, 1, search)
				require.Zero(t, epoch)
			}
		})
	}
	t.Run("requested_capacity", func(t *testing.T) {
		lookups := 0
		r := &TrieNodeResolver{trieDataGetter: &trieMock.TrieStub{GetSerializedNodeCalled: func([]byte) ([]byte, error) {
			lookups++
			return bytes.Repeat([]byte{byte(lookups)}, core.MaxBufferSizeToSendTrieNodes/2+1), nil
		}}}
		nodes := map[string]struct{}{}
		used, all := r.resolveOnlyRequestedHashes([][]byte{{1}, {2}, {3}}, nodes)
		require.True(t, all)
		require.Equal(t, core.MaxBufferSizeToSendTrieNodes/2+1, used)
		require.Len(t, nodes, 1, "requested trie cap result")
		require.Equal(t, 2, lookups, "requested trie cap stops lookup")
	})
	t.Run("subtree_negative_budget", func(t *testing.T) {
		calls := 0
		r := &TrieNodeResolver{baseResolver: &baseResolver{TopicResolverSender: &mock.TopicResolverSenderStub{}}, trieDataGetter: &trieMock.TrieStub{GetSerializedNodesCalled: func([]byte, uint64) ([][]byte, uint64, error) { calls++; return nil, 0, nil }}}
		r.resolveSubTries([][]byte{{1}}, map[string]struct{}{}, core.MaxBufferSizeToSendTrieNodes+1)
		require.Zero(t, calls, "negative subtree budget cannot call getter")
	})
	t.Run("subtree_oversized_item", func(t *testing.T) {
		r := &TrieNodeResolver{baseResolver: &baseResolver{TopicResolverSender: &mock.TopicResolverSenderStub{}}, trieDataGetter: &trieMock.TrieStub{GetSerializedNodesCalled: func([]byte, uint64) ([][]byte, uint64, error) {
			return [][]byte{make([]byte, core.MaxBufferSizeToSendTrieNodes+1)}, 0, nil
		}}}
		nodes := map[string]struct{}{}
		r.resolveSubTries([][]byte{{1}}, nodes, 0)
		require.Empty(t, nodes, "oversized subtree item not inserted")
	})
	t.Run("subtree_duplicate_budget", func(t *testing.T) {
		budgets := []uint64{}
		r := &TrieNodeResolver{baseResolver: &baseResolver{TopicResolverSender: &mock.TopicResolverSenderStub{}}, trieDataGetter: &trieMock.TrieStub{GetSerializedNodesCalled: func(_ []byte, n uint64) ([][]byte, uint64, error) {
			budgets = append(budgets, n)
			if len(budgets) == 1 {
				return [][]byte{[]byte("dup"), []byte("xyz")}, 0, nil
			}
			return nil, 0, nil
		}}}
		nodes := map[string]struct{}{"dup": {}}
		r.resolveSubTries([][]byte{{1}, {2}}, nodes, core.MaxBufferSizeToSendTrieNodes-3)
		require.Equal(t, []uint64{3, 0}, budgets, "duplicate subtree not charged twice")
		require.Len(t, nodes, 2)
	})
	t.Run("empty_response", func(t *testing.T) {
		calls := 0
		r := &TrieNodeResolver{baseResolver: &baseResolver{TopicResolverSender: &mock.TopicResolverSenderStub{SendCalled: func([]byte, core.PeerID, p2p.MessageHandler) error { calls++; return nil }}}, messageProcessor: messageProcessor{marshalizer: &testscommon.MarshallerStub{MarshalCalled: func(interface{}) ([]byte, error) { calls++; return []byte("unexpected"), nil }}}}
		require.NoError(t, r.sendResponse(nil, nil, 0, &p2pmocks.P2PMessageMock{}, nil))
		require.Zero(t, calls, "empty trie response not encoded or sent")
	})
}
