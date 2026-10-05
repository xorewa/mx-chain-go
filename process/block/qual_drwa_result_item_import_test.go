package block

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE AR-01 item/result construction (Part A 6.1).
// The caller's H hash is an ASSUMED authenticated commitment, not established
// canonical finality. The trie is a synthetic item trie, not an AccountsDB
// main-trie -> account -> data-trie witness. No production codec, storage
// address, finality predicate, work limit or extra commitment is selected.
// Native protobuf, Blake2b and Patricia-trie code do the byte authentication;
// the memory database and epoch handler are existing upstream test helpers.
func qualItemTrie(t *testing.T, db *testscommon.MemDbMock) common.Trie {
	t.Helper()
	tr, err := trie.NewTrie(&storageManager.StorageManagerStub{
		GetCalled: db.Get, GetFromCurrentEpochCalled: db.Get, PutCalled: db.Put,
	}, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
		&enableEpochsHandlerMock.EnableEpochsHandlerStub{}, 5)
	require.NoError(t, err)
	return tr
}

func qualImportResultItem(t *testing.T, committedH, hBytes, sBytes, key []byte,
	proof [][]byte, producingShard uint32, byteLimit int) ([]byte, error) {
	t.Helper()
	deny := errors.New("qualification item witness rejected")
	hsh := blake2b.NewBlake2b()
	if !bytes.Equal(hsh.Compute(string(hBytes)), committedH) || len(key) == 0 {
		return nil, deny
	}
	used := 0
	for _, node := range proof {
		if len(node) == 0 || used > byteLimit || len(node) > byteLimit-used {
			return nil, deny
		}
		used += len(node)
	}
	if len(proof) == 0 {
		return nil, deny
	}
	h, s := &block.HeaderV3{}, &block.HeaderV3{}
	mar := &marshal.GogoProtoMarshalizer{}
	if mar.Unmarshal(h, hBytes) != nil || mar.Unmarshal(s, sBytes) != nil {
		return nil, deny
	}
	if h.ShardID != producingShard || s.ShardID != producingShard {
		return nil, deny
	}
	sHash := hsh.Compute(string(sBytes))
	var result *block.ExecutionResult
	for _, r := range h.ExecutionResults {
		if r == nil || r.BaseExecutionResult == nil {
			return nil, deny
		}
		if bytes.Equal(r.BaseExecutionResult.HeaderHash, sHash) {
			if result != nil {
				return nil, deny
			}
			result = r
		}
	}
	if result == nil || result.BaseExecutionResult.HeaderNonce != s.Nonce || result.BaseExecutionResult.HeaderRound != s.Round || result.BaseExecutionResult.HeaderEpoch != s.Epoch {
		return nil, deny
	}
	db := testscommon.NewMemDbMock()
	tr := qualItemTrie(t, db)
	valid, err := tr.VerifyProof(result.BaseExecutionResult.RootHash, key, proof)
	if err != nil || !valid {
		return nil, deny
	}
	for _, node := range proof {
		// Derive every storage key from these bytes; never accept caller-supplied
		// hash-to-node mappings. Get below returns the authenticated leaf value,
		// not the unauthenticated parallel value returned by a remote proof API.
		if err = db.Put(hsh.Compute(string(node)), bytes.Clone(node)); err != nil {
			return nil, err
		}
	}
	restored, err := tr.Recreate(holders.NewDefaultRootHashesHolder(result.BaseExecutionResult.RootHash))
	if err != nil {
		return nil, err
	}
	value, _, err := restored.Get(key)
	if err != nil || len(value) == 0 {
		return nil, deny
	}
	return value, nil
}

func TestQualDRWAResultItemImport(t *testing.T) {
	mar := &marshal.GogoProtoMarshalizer{}
	hsh := blake2b.NewBlake2b()
	key := []byte("fixture/item/action-A/phase-A")
	expected := []byte("literal predecessor-A;target-B;dependency-C")
	tr := qualItemTrie(t, testscommon.NewMemDbMock())
	require.NoError(t, tr.Update(key, expected))
	require.NoError(t, tr.Update([]byte("unrelated"), []byte("preserved")))
	root, err := tr.RootHash()
	require.NoError(t, err)
	proof, _, err := tr.GetProof(key)
	require.NoError(t, err)
	s := &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: 1}
	sBytes, err := mar.Marshal(s)
	require.NoError(t, err)
	result := createDummyShardExecutionResult()
	result.BaseExecutionResult.HeaderHash = hsh.Compute(string(sBytes))
	result.BaseExecutionResult.HeaderNonce, result.BaseExecutionResult.HeaderRound, result.BaseExecutionResult.HeaderEpoch = 11, 21, 3
	result.BaseExecutionResult.RootHash = root
	h := &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: 1, ExecutionResults: []*block.ExecutionResult{result}}
	hBytes, err := mar.Marshal(h)
	require.NoError(t, err)
	committed := hsh.Compute(string(hBytes))
	limit := 0
	for _, node := range proof {
		limit += len(node)
	}
	for _, name := range []string{"valid", "wrong_H", "wrong_S", "wrong_key", "wrong_shard", "missing_proof", "corrupt_proof", "reordered_native_proof", "over_budget", "wrong_result_root", "duplicate_result"} {
		t.Run(name, func(t *testing.T) {
			candidateH, candidateS, k := bytes.Clone(hBytes), bytes.Clone(sBytes), bytes.Clone(key)
			nodes := make([][]byte, len(proof))
			for i := range proof {
				nodes[i] = bytes.Clone(proof[i])
			}
			anchor, shard, budget := bytes.Clone(committed), uint32(1), limit
			switch name {
			case "wrong_H":
				candidateH = append(candidateH, 1)
			case "wrong_S":
				candidateS = append(candidateS, 1)
			case "wrong_key":
				k = []byte("other-item")
			case "wrong_shard":
				shard = 2
			case "missing_proof":
				nodes = nil
			case "corrupt_proof":
				nodes[0][0] ^= 1
			case "reordered_native_proof":
				// Native GetProof emits a root-to-leaf sequence (trie/
				// patriciaMerkleTrie.go:557-647). VerifyProof checks that
				// sequence; content-addressed Recreate/Get does not. This
				// distinguishes the existing gate without claiming that
				// proof ordering is a selected DRWA production wire format.
				require.Greater(t, len(nodes), 1)
				nodes[0], nodes[len(nodes)-1] = nodes[len(nodes)-1], nodes[0]
				db := testscommon.NewMemDbMock()
				for _, node := range nodes {
					require.NoError(t, db.Put(hsh.Compute(string(node)), bytes.Clone(node)))
				}
				rebuilt, rebuildErr := qualItemTrie(t, db).Recreate(holders.NewDefaultRootHashesHolder(root))
				require.NoError(t, rebuildErr)
				recovered, _, readErr := rebuilt.Get(key)
				require.NoError(t, readErr)
				require.Equal(t, expected, recovered, "reconstruction alone accepts the reordered node set")
			case "over_budget":
				budget--
			case "wrong_result_root", "duplicate_result":
				changed := &block.HeaderV3{}
				require.NoError(t, mar.Unmarshal(changed, hBytes))
				if name == "wrong_result_root" {
					changed.ExecutionResults[0].BaseExecutionResult.RootHash = bytes.Repeat([]byte{7}, 32)
				} else {
					changed.ExecutionResults = append(changed.ExecutionResults, changed.ExecutionResults[0])
				}
				candidateH, err = mar.Marshal(changed)
				require.NoError(t, err)
				anchor = hsh.Compute(string(candidateH)) // challenge the relation, not merely H authentication
			}
			value, err := qualImportResultItem(t, anchor, candidateH, candidateS, k, nodes, shard, budget)
			if name == "valid" {
				require.NoError(t, err)
				require.Equal(t, expected, value)
			} else {
				require.Error(t, err)
				require.Empty(t, value)
			}
		})
	}
}
