package drwa

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process"
	nativeBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/stretchr/testify/require"
)

// Real pinned native header construction validator, codec and hash; the only
// epoch stub is the previously swept, healthy qualReaderArgs dependency. No
// proof resolver or source authority is mocked as established by these tests.
type qualMetaContextFixture struct {
	c                                                                *nativeMetaContext
	candidate                                                        *block.HeaderV3
	predecessor                                                      *block.MetaBlockV3
	references                                                       []*block.MetaBlockV3
	candidateHash, candidateBytes, predecessorHash, predecessorBytes []byte
	raw                                                              [][]byte
}

func qualNativeMetaContext(t *testing.T) *qualMetaContextFixture {
	t.Helper()
	a := qualReaderArgs(false)
	v, err := nativeBlock.NewHeaderValidator(nativeBlock.ArgsHeaderValidator{
		Hasher: a.Hasher, Marshalizer: a.Marshaller, EnableEpochsHandler: a.EnableEpochsHandler})
	require.NoError(t, err)
	c, err := newNativeMetaContext(a.Marshaller, a.Hasher, v)
	require.NoError(t, err)
	result := func(nonce uint64, root string) *block.MetaExecutionResultInfo {
		return &block.MetaExecutionResultInfo{ExecutionResult: &block.BaseMetaExecutionResult{
			BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: []byte("executed-" + root),
				HeaderNonce: nonce, HeaderRound: nonce + 10, HeaderEpoch: 2, RootHash: []byte(root)}}}
	}
	f := &qualMetaContextFixture{c: c, candidate: &block.HeaderV3{ShardID: 1, Nonce: 20, Round: 50, Epoch: 2},
		predecessor: &block.MetaBlockV3{Nonce: 10, Round: 30, Epoch: 2, RandSeed: []byte("p"), LastExecutionResult: result(8, "predecessor-root")}}
	f.references = []*block.MetaBlockV3{{Nonce: 11, Round: 31, Epoch: 2, RandSeed: []byte("one"), LastExecutionResult: result(9, "first-root")},
		{Nonce: 12, Round: 32, Epoch: 2, RandSeed: []byte("two"), LastExecutionResult: result(10, "latest-root")}}
	previous := f.predecessor
	for _, next := range f.references {
		previousRaw, e := a.Marshaller.Marshal(previous)
		require.NoError(t, e)
		next.PrevHash = a.Hasher.Compute(string(previousRaw))
		next.PrevRandSeed = bytes.Clone(previous.RandSeed)
		next.LastExecutionResult.NotarizedInRound = next.Round
		next.ExecutionResults = []*block.MetaExecutionResult{{ExecutionResult: next.LastExecutionResult.ExecutionResult}}
		nativeInfo, e := process.CreateLastExecutionResultInfoFromExecutionResult(next.Round, next.ExecutionResults[0], core.MetachainShardId)
		require.NoError(t, e)
		require.True(t, next.LastExecutionResult.Equal(nativeInfo))
		require.Equal(t, previous.LastExecutionResult.ExecutionResult.BaseExecutionResult.HeaderNonce+1, next.ExecutionResults[0].GetHeaderNonce())
		previous = next
	}
	f.encode(t)
	return f
}

func (f *qualMetaContextFixture) encode(t *testing.T) {
	t.Helper()
	var err error
	f.predecessorBytes, err = f.c.marshaller.Marshal(f.predecessor)
	require.NoError(t, err)
	f.predecessorHash = f.c.hasher.Compute(string(f.predecessorBytes))
	f.raw = nil
	f.candidate.MetaBlockHashes = nil
	for _, h := range f.references {
		b, e := f.c.marshaller.Marshal(h)
		require.NoError(t, e)
		f.raw = append(f.raw, b)
		f.candidate.MetaBlockHashes = append(f.candidate.MetaBlockHashes, f.c.hasher.Compute(string(b)))
	}
	f.candidateBytes, err = f.c.marshaller.Marshal(f.candidate)
	require.NoError(t, err)
	f.candidateHash = f.c.hasher.Compute(string(f.candidateBytes))
}

func (f *qualMetaContextFixture) read() (*metaRegistryAnchor, error) {
	return f.c.selectAnchor(f.candidateHash, f.candidateBytes, f.predecessorHash, f.predecessorBytes, f.raw)
}

func TestQualDRWANativeMetaContext(t *testing.T) {
	for _, name := range []string{"latest", "no_references", "retained_last_result", "wrong_candidate", "wrong_predecessor",
		"empty_candidate", "empty_predecessor", "missing_reference", "extra_reference", "wrong_reference", "reordered",
		"nonce_gap", "lower_round", "wrong_parent", "wrong_seed", "missing_last", "missing_meta_base", "missing_base",
		"missing_executed_hash", "missing_root", "over_limit", "malformed_candidate", "malformed_predecessor", "malformed_reference",
		"trailing_candidate", "trailing_predecessor", "trailing_reference"} {
		t.Run(name, func(t *testing.T) {
			f := qualNativeMetaContext(t)
			switch name {
			case "no_references":
				f.references = nil
				f.encode(t)
			case "retained_last_result":
				// Native verification requires the last info to remain identical
				// to the preceding header when no new result is included.
				f.references[1].ExecutionResults = nil
				f.references[1].LastExecutionResult = f.references[0].LastExecutionResult
				require.True(t, f.references[1].LastExecutionResult.Equal(f.references[0].LastExecutionResult))
				f.encode(t)
			case "wrong_candidate":
				f.candidateHash[0] ^= 1
			case "wrong_predecessor":
				f.predecessorHash[0] ^= 1
			case "empty_candidate":
				f.candidateHash = nil
			case "empty_predecessor":
				f.predecessorHash = nil
			case "missing_reference":
				f.raw = f.raw[:1]
			case "extra_reference":
				f.raw = append(f.raw, f.raw[1])
			case "wrong_reference":
				f.candidate.MetaBlockHashes[1][0] ^= 1
				var e error
				f.candidateBytes, e = f.c.marshaller.Marshal(f.candidate)
				require.NoError(t, e)
				f.candidateHash = f.c.hasher.Compute(string(f.candidateBytes))
			case "reordered":
				f.references[0], f.references[1] = f.references[1], f.references[0]
				f.encode(t)
			case "nonce_gap":
				f.references[1].Nonce++
				f.encode(t)
			case "lower_round":
				f.references[1].Round = f.references[0].Round
				f.encode(t)
			case "wrong_parent":
				f.references[1].PrevHash = []byte("not the predecessor")
				f.encode(t)
			case "wrong_seed":
				f.references[1].PrevRandSeed = []byte("not the seed")
				f.encode(t)
			case "missing_last":
				f.references[1].LastExecutionResult = nil
				f.encode(t)
			case "missing_meta_base":
				f.references[1].LastExecutionResult.ExecutionResult = nil
				f.encode(t)
			case "missing_base":
				f.references[1].LastExecutionResult.ExecutionResult.BaseExecutionResult = nil
				f.encode(t)
			case "missing_executed_hash":
				f.references[1].LastExecutionResult.ExecutionResult.BaseExecutionResult.HeaderHash = nil
				f.encode(t)
			case "missing_root":
				f.references[1].LastExecutionResult.ExecutionResult.BaseExecutionResult.RootHash = nil
				f.encode(t)
			case "over_limit":
				for len(f.references) <= process.MaxMetaHeadersAllowedInOneShardBlock {
					prev := f.references[len(f.references)-1]
					b, e := f.c.marshaller.Marshal(prev)
					require.NoError(t, e)
					f.references = append(f.references, &block.MetaBlockV3{Nonce: prev.Nonce + 1, Round: prev.Round + 1, Epoch: prev.Epoch,
						PrevHash: f.c.hasher.Compute(string(b)), PrevRandSeed: bytes.Clone(prev.RandSeed), RandSeed: bytes.Clone(prev.RandSeed), LastExecutionResult: prev.LastExecutionResult})
				}
				f.encode(t)
			case "malformed_candidate":
				f.candidateBytes = []byte{0xff}
				f.candidateHash = f.c.hasher.Compute(string(f.candidateBytes))
			case "malformed_predecessor":
				f.predecessorBytes = []byte{0xff}
				f.predecessorHash = f.c.hasher.Compute(string(f.predecessorBytes))
			case "malformed_reference":
				f.raw[1] = []byte{0xff}
				f.candidate.MetaBlockHashes[1] = f.c.hasher.Compute(string(f.raw[1]))
				var err error
				f.candidateBytes, err = f.c.marshaller.Marshal(f.candidate)
				require.NoError(t, err)
				f.candidateHash = f.c.hasher.Compute(string(f.candidateBytes))
			case "trailing_candidate":
				f.candidateBytes = append(f.candidateBytes, 0xff)
				f.candidateHash = f.c.hasher.Compute(string(f.candidateBytes))
			case "trailing_predecessor":
				f.predecessorBytes = append(f.predecessorBytes, 0xff)
				f.predecessorHash = f.c.hasher.Compute(string(f.predecessorBytes))
				f.references = nil
				f.raw = nil
				f.candidate.MetaBlockHashes = nil
				var e error
				f.candidateBytes, e = f.c.marshaller.Marshal(f.candidate)
				require.NoError(t, e)
				f.candidateHash = f.c.hasher.Compute(string(f.candidateBytes))
			case "trailing_reference":
				f.raw[1] = append(f.raw[1], 0xff)
				f.candidate.MetaBlockHashes[1] = f.c.hasher.Compute(string(f.raw[1]))
				var e error
				f.candidateBytes, e = f.c.marshaller.Marshal(f.candidate)
				require.NoError(t, e)
				f.candidateHash = f.c.hasher.Compute(string(f.candidateBytes))
			}
			anchor, err := f.read()
			if name == "latest" || name == "no_references" || name == "retained_last_result" {
				require.NoError(t, err)
				root := []byte("latest-root")
				if name == "no_references" {
					root = []byte("predecessor-root")
				}
				if name == "retained_last_result" {
					root = []byte("first-root")
				}
				require.Equal(t, root, anchor.root)
				require.Equal(t, f.candidateHash, anchor.candidateHash)
				selected := f.predecessor.LastExecutionResult.ExecutionResult.BaseExecutionResult
				if name != "no_references" {
					selected = f.references[1].LastExecutionResult.ExecutionResult.BaseExecutionResult
				}
				require.Equal(t, selected.HeaderHash, anchor.executedHash)
				require.Equal(t, selected.HeaderNonce, anchor.nonce)
				require.Equal(t, selected.HeaderRound, anchor.round)
				require.Equal(t, selected.HeaderEpoch, anchor.epoch)
				if name == "no_references" {
					require.Equal(t, f.predecessorHash, anchor.metaHash)
				} else {
					require.Equal(t, f.candidate.MetaBlockHashes[1], anchor.metaHash)
				}
				anchor.root[0] ^= 1
				anchor.candidateHash[0] ^= 1
				anchor.metaHash[0] ^= 1
				anchor.executedHash[0] ^= 1
				again, e := f.read()
				require.NoError(t, e)
				require.Equal(t, root, again.root)
				require.Equal(t, f.candidateHash, again.candidateHash)
			} else {
				require.Error(t, err)
				require.Nil(t, anchor)
			}
		})
	}
}

func TestQualDRWANativeMetaContextDependencies(t *testing.T) {
	f := qualNativeMetaContext(t)
	for _, name := range []string{"marshaller", "hasher", "validator"} {
		t.Run(name, func(t *testing.T) {
			m, h, v := f.c.marshaller, f.c.hasher, f.c.validator
			if name == "marshaller" {
				m = nil
			}
			if name == "hasher" {
				h = nil
			}
			if name == "validator" {
				v = nil
			}
			c, err := newNativeMetaContext(m, h, v)
			require.Error(t, err)
			require.Nil(t, c)
		})
	}
}
