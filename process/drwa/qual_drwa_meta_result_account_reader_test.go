package drwa

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"
)

// Native trie/account proofs and literal expected values come from the existing
// AccountsDB fixture. Only the native carrying/executed header family changes.
// The complete callback sweep remains qualReaderArgs: no new mock or callback.
func qualMetaReaderFixture(t *testing.T, auto bool) *qualReaderFixture {
	t.Helper()
	f := qualNativeReaderFixture(t, auto, 1)
	old := &block.HeaderV3{}
	require.NoError(t, f.args.Marshaller.Unmarshal(old, f.w.Header))
	root := bytes.Clone(old.ExecutionResults[0].BaseExecutionResult.RootHash)
	s := &block.MetaBlockV3{Nonce: 11, Round: 21, Epoch: 3}
	var err error
	f.w.ExecutedHeader, err = f.args.Marshaller.Marshal(s)
	require.NoError(t, err)
	h := &block.MetaBlockV3{Nonce: 15, Round: 25, Epoch: 4,
		ExecutionResults: []*block.MetaExecutionResult{{ExecutionResult: &block.BaseMetaExecutionResult{
			BaseExecutionResult: &block.BaseExecutionResult{
				HeaderHash: f.args.Hasher.Compute(string(f.w.ExecutedHeader)), HeaderNonce: 11,
				HeaderRound: 21, HeaderEpoch: 3, RootHash: root},
			ValidatorStatsRootHash: bytes.Repeat([]byte{9}, 32)}}}}
	require.Nil(t, h.GetRootHash(), "native meta header cannot supply the account root")
	f.w.Header, err = f.args.Marshaller.Marshal(h)
	require.NoError(t, err)
	f.anchor = f.args.Hasher.Compute(string(f.w.Header))
	return f
}

func qualChangeMetaH(t *testing.T, f *qualReaderFixture, change func(*block.MetaBlockV3)) {
	t.Helper()
	h := &block.MetaBlockV3{}
	require.NoError(t, f.args.Marshaller.Unmarshal(h, f.w.Header))
	change(h)
	var err error
	f.w.Header, err = f.args.Marshaller.Marshal(h)
	require.NoError(t, err)
	f.anchor = f.args.Hasher.Compute(string(f.w.Header))
}

func TestQualDRWAMetaResultAccountReader(t *testing.T) {
	cases := []string{"valid", "multi_result", "wrong_H", "wrong_S", "malformed_H", "malformed_S", "trailing_H", "trailing_S",
		"wrong_family", "missing_result", "duplicate_result", "empty_result", "empty_base",
		"wrong_nonce", "wrong_round", "wrong_epoch", "wrong_root", "validator_root",
		"wrong_account", "wrong_key", "missing_account_proof", "missing_data_proof",
		"corrupt_account_proof", "corrupt_data_proof", "over_budget", "negative_budget"}
	for _, auto := range []bool{false, true} {
		for _, name := range cases {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, name), func(t *testing.T) {
				f := qualMetaReaderFixture(t, auto)
				good := qualMetaReaderFixture(t, auto)
				shard := uint32(core.MetachainShardId)
				switch name {
				case "wrong_H":
					f.anchor[0] ^= 1
				case "wrong_S":
					s := &block.MetaBlockV3{Nonce: 11, Round: 21, Epoch: 3, PrevHash: []byte("different executed meta")}
					var err error
					f.w.ExecutedHeader, err = f.args.Marshaller.Marshal(s)
					require.NoError(t, err)
				case "malformed_H":
					f.w.Header = []byte{0xff}
					f.anchor = f.args.Hasher.Compute(string(f.w.Header))
				case "malformed_S":
					f.w.ExecutedHeader = []byte{0xff}
				case "trailing_H":
					f.w.Header = append(f.w.Header, 0xff)
					f.anchor = f.args.Hasher.Compute(string(f.w.Header))
				case "trailing_S":
					f.w.ExecutedHeader = append(f.w.ExecutedHeader, 0xff)
					qualChangeMetaH(t, f, func(h *block.MetaBlockV3) {
						h.ExecutionResults[0].ExecutionResult.BaseExecutionResult.HeaderHash = f.args.Hasher.Compute(string(f.w.ExecutedHeader))
					})
				case "wrong_family":
					shard = 1
				case "missing_result":
					qualChangeMetaH(t, f, func(h *block.MetaBlockV3) { h.ExecutionResults = nil })
				case "duplicate_result":
					qualChangeMetaH(t, f, func(h *block.MetaBlockV3) { h.ExecutionResults = append(h.ExecutionResults, h.ExecutionResults[0]) })
				case "empty_result":
					qualChangeMetaH(t, f, func(h *block.MetaBlockV3) {
						h.ExecutionResults = append(h.ExecutionResults, &block.MetaExecutionResult{})
					})
				case "empty_base":
					qualChangeMetaH(t, f, func(h *block.MetaBlockV3) {
						h.ExecutionResults = append(h.ExecutionResults, &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{}})
					})
				case "multi_result":
					qualChangeMetaH(t, f, func(h *block.MetaBlockV3) {
						h.ExecutionResults = append([]*block.MetaExecutionResult{{ExecutionResult: &block.BaseMetaExecutionResult{
							BaseExecutionResult: &block.BaseExecutionResult{HeaderHash: []byte("unrelated")}}}}, h.ExecutionResults...)
					})
				case "wrong_nonce", "wrong_round", "wrong_epoch", "wrong_root", "validator_root":
					qualChangeMetaH(t, f, func(h *block.MetaBlockV3) {
						r := h.ExecutionResults[0].ExecutionResult.BaseExecutionResult
						switch name {
						case "wrong_nonce":
							r.HeaderNonce++
						case "wrong_round":
							r.HeaderRound++
						case "wrong_epoch":
							r.HeaderEpoch++
						case "wrong_root":
							r.RootHash = bytes.Repeat([]byte{7}, 32)
						case "validator_root":
							r.RootHash = h.ExecutionResults[0].ExecutionResult.ValidatorStatsRootHash
						}
					})
				case "wrong_account":
					f.address = bytes.Repeat([]byte{2}, 32)
				case "wrong_key":
					f.key = []byte("different key")
				case "missing_account_proof":
					f.w.AccountProof = nil
				case "missing_data_proof":
					f.w.DataProof = nil
				case "corrupt_account_proof":
					f.w.AccountProof[0][0] ^= 1
				case "corrupt_data_proof":
					f.w.DataProof[0][0] ^= 1
				case "over_budget":
					f.budget--
				case "negative_budget":
					f.budget = -1
				}
				r, err := NewResultAccountReader(qualReaderArgs(auto))
				require.NoError(t, err)
				value, err := r.Read(f.anchor, shard, f.address, f.key, f.w, f.budget)
				if name == "valid" || name == "multi_result" {
					require.NoError(t, err)
					require.Equal(t, f.expected, value)
				} else {
					require.Error(t, err)
					require.Nil(t, value)
				}
				value, err = r.Read(good.anchor, core.MetachainShardId, good.address, good.key, good.w, good.budget)
				require.NoError(t, err)
				require.Equal(t, good.expected, value)
				value[0] ^= 1
				again, err := r.Read(good.anchor, core.MetachainShardId, good.address, good.key, good.w, good.budget)
				require.NoError(t, err)
				require.Equal(t, good.expected, again)
			})
		}
	}
}

func TestQualDRWAMetaResultAccountReaderConcurrent(t *testing.T) {
	f := qualMetaReaderFixture(t, true)
	r, err := NewResultAccountReader(qualReaderArgs(true))
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := r.Read(f.anchor, core.MetachainShardId, f.address, f.key, f.w, f.budget)
			require.NoError(t, err)
			require.Equal(t, f.expected, value)
		}()
	}
	wg.Wait()
}
