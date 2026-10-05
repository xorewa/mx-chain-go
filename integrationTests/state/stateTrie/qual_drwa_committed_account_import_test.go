package stateTrie

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/integrationTests"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/factory"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE AR-01 prefix, not a finality or promotion mechanism.
// Compose native H -> complete result -> S -> main/account/data-trie -> item.
// Expected H/S hashes, producing shard, address/key and activation semantics are
// supplied by the trusted caller. Their canonical eligibility is NOT established
// here. In particular an authenticated H alone cannot authorize a positive read.
// M/B ancestry, consensus proofs, route eligibility, transport/pricing and durable
// first-consumer installation remain open. No production codec/key is selected.
// Upstream references: process/block/executionResultsVerifier.go:56-99;
// core v1.5.1 data/block/{blockV3,metaBlockV3,executionResult}.proto.
// This uses native full-result Equal, not a projected ShardData/root comparison.
func qualReadCommittedAccountItem(t *testing.T, expectedH, expectedS, hBytes, sBytes, resultBytes, address, key []byte,
	accountNodes, dataNodes [][]byte, shard uint32, limit int, flags common.EnableEpochsHandler) ([]byte, error) {
	t.Helper()
	deny := errors.New("qualification committed account item rejected")
	if len(expectedH) == 0 || len(expectedS) == 0 || limit < 0 {
		return nil, deny
	}
	remaining := limit
	for _, group := range [][][]byte{{hBytes, sBytes, resultBytes}, accountNodes, dataNodes} {
		for _, part := range group {
			if len(part) == 0 || len(part) > remaining {
				return nil, deny
			}
			remaining -= len(part)
		}
	}
	hash := integrationTests.TestHasher
	if !bytes.Equal(hash.Compute(string(hBytes)), expectedH) ||
		!bytes.Equal(hash.Compute(string(sBytes)), expectedS) {
		return nil, deny
	}
	var creator block.EmptyBlockCreator = block.NewEmptyHeaderV3Creator()
	var supplied data.BaseExecutionResultHandler = &block.ExecutionResult{}
	if shard == core.MetachainShardId {
		creator = block.NewEmptyMetaBlockV3Creator()
		supplied = &block.MetaExecutionResult{}
	}
	mar := integrationTests.TestMarshalizer
	h, err := block.GetHeaderFromBytes(mar, creator, hBytes)
	if err != nil {
		return nil, deny
	}
	s, err := block.GetHeaderFromBytes(mar, creator, sBytes)
	if err != nil || h.GetShardID() != shard || s.GetShardID() != shard ||
		mar.Unmarshal(supplied, resultBytes) != nil {
		return nil, deny
	}
	var selected data.BaseExecutionResultHandler
	for _, result := range h.GetExecutionResultsHandlers() {
		if check.IfNil(result) {
			return nil, deny
		}
		if bytes.Equal(result.GetHeaderHash(), expectedS) {
			if !check.IfNil(selected) {
				return nil, deny
			}
			selected = result
		}
	}
	if check.IfNil(selected) || !selected.Equal(supplied) ||
		selected.GetHeaderNonce() != s.GetNonce() ||
		selected.GetHeaderRound() != s.GetRound() ||
		selected.GetHeaderEpoch() != s.GetEpoch() || len(selected.GetRootHash()) == 0 {
		return nil, deny
	}
	// Reuse the existing native account witness; do not introduce a second
	// account decoder or raw-key fallback. The byte budget was checked jointly
	// before decoding any header or proof. It is a fixture bound, not pricing.
	return qualReadAccountWitness(t, selected.GetRootHash(), address, key, accountNodes, dataNodes, limit, flags)
}

func TestQualDRWACommittedAccountItem(t *testing.T) {
	for _, shard := range []uint32{0, 1, 2, core.MetachainShardId} {
		for _, balanced := range []bool{false, true} {
			t.Run(fmt.Sprintf("origin_%d/balanced_%t", shard, balanced), func(t *testing.T) {
				adb := createAccountsDBTestSetup()
				t.Cleanup(func() { require.NoError(t, adb.Close()) })
				flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
				if balanced {
					flags.AddActiveFlags(common.AutoBalanceDataTriesFlag)
				}
				creator, err := factory.NewAccountCreator(factory.ArgsAccountCreator{
					Hasher: integrationTests.TestHasher, Marshaller: integrationTests.TestMarshalizer,
					EnableEpochsHandler: flags, StateAccessesCollector: &stateMock.StateAccessesCollectorStub{},
				})
				require.NoError(t, err)
				address := bytes.Repeat([]byte{41}, 32)
				account, err := creator.CreateAccount(address)
				require.NoError(t, err)
				user := account.(state.UserAccountHandler)
				key := qualProtectedFixtureKey([]byte("item"), []byte("action-A"))
				expected := []byte("literal predecessor-A;target-B;dependency-C")
				require.NoError(t, user.SaveKeyValue(key, expected))
				require.NoError(t, user.SaveKeyValue([]byte("ordinary"), []byte("unchanged")))
				require.NoError(t, adb.SaveAccount(account))
				root, err := adb.Commit()
				require.NoError(t, err)
				main, err := adb.GetTrie(root)
				require.NoError(t, err)
				ap, _, err := main.GetProof(address)
				require.NoError(t, err)
				dt, err := adb.GetTrie(user.GetRootHash())
				require.NoError(t, err)
				storedKey := key
				if balanced {
					storedKey = integrationTests.TestHasher.Compute(string(key))
				}
				dp, _, err := dt.GetProof(storedKey)
				require.NoError(t, err)
				mar, hash := integrationTests.TestMarshalizer, integrationTests.TestHasher
				marshal := func(v interface{}) []byte {
					b, e := mar.Marshal(v)
					require.NoError(t, e)
					return b
				}
				cases := []string{"valid", "wrong_H_hash", "wrong_S_hash", "substituted_S_content", "swapped_S_H",
					"wrong_origin_shard", "missing_result", "duplicate_result", "result_nonce", "result_round",
					"result_epoch", "result_root", "substituted_gas", "substituted_receipts", "malformed_header",
					"malformed_result", "wrong_account", "wrong_item", "missing_account_nodes", "missing_data_nodes",
					"corrupt_data_node", "aggregate_limit", "negative_limit"}
				// MetaBlockV3.GetShardID is intrinsically MetachainShardId; it has
				// no independent shard field to substitute (core v1.5.1:212-214).
				if shard != core.MetachainShardId {
					cases = append(cases, "executed_header_wrong_shard")
				}
				for _, name := range cases {
					t.Run(name, func(t *testing.T) {
						var s, h data.HeaderHandler
						if shard == core.MetachainShardId {
							s = &block.MetaBlockV3{Nonce: 11, Round: 21, Epoch: 3}
							h = &block.MetaBlockV3{Nonce: 15, Round: 25, Epoch: 4}
						} else {
							s = &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: shard}
							h = &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: shard}
						}
						if name == "executed_header_wrong_shard" {
							// Commit the actual S bytes and result consistently. H stays
							// on the producing shard, so only S's shard binding rejects.
							require.NoError(t, s.SetShardID((shard+1)%3))
							require.Equal(t, shard, h.GetShardID())
							require.NotEqual(t, shard, s.GetShardID())
						}
						sb := marshal(s)
						expectedS := hash.Compute(string(sb))
						base := &block.BaseExecutionResult{HeaderHash: expectedS, HeaderNonce: 11, HeaderRound: 21, HeaderEpoch: 3, RootHash: root, GasUsed: 7}
						var result data.BaseExecutionResultHandler
						if shard == core.MetachainShardId {
							result = &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{BaseExecutionResult: base}, ReceiptsHash: []byte("receipts-A")}
						} else {
							result = &block.ExecutionResult{BaseExecutionResult: base, ReceiptsHash: []byte("receipts-A")}
						}
						switch name {
						case "result_nonce":
							base.HeaderNonce++
						case "result_round":
							base.HeaderRound++
						case "result_epoch":
							base.HeaderEpoch++
						case "result_root":
							base.RootHash = bytes.Repeat([]byte{9}, len(root))
						}
						require.NoError(t, h.SetExecutionResultsHandlers([]data.BaseExecutionResultHandler{result}))
						if name == "missing_result" {
							require.NoError(t, h.SetExecutionResultsHandlers(nil))
						}
						if name == "duplicate_result" {
							require.NoError(t, h.SetExecutionResultsHandlers([]data.BaseExecutionResultHandler{result, result}))
						}
						hb := marshal(h)
						// H is committed before substitutions to the separate result.
						// Identical S/root must not conceal changed full-result fields.
						if name == "substituted_gas" {
							base.GasUsed++
						}
						if name == "substituted_receipts" {
							switch r := result.(type) {
							case *block.ExecutionResult:
								r.ReceiptsHash = []byte("receipts-B")
							case *block.MetaExecutionResult:
								r.ReceiptsHash = []byte("receipts-B")
							}
						}
						rb := marshal(result)
						if name == "malformed_header" {
							hb = []byte{0xff}
						}
						if name == "malformed_result" {
							rb = []byte{0xff}
						}
						expectedH := hash.Compute(string(hb))
						a, k, producing := address, key, shard
						accountNodes, dataNodes := ap, dp
						switch name {
						case "wrong_H_hash":
							expectedH = []byte("other-H")
						case "wrong_S_hash":
							expectedS = []byte("other-S")
						case "substituted_S_content":
							// Keep the trusted S identity and H's committed result.
							// A replacement with identical shard/nonce/round/epoch is
							// distinguished only by hashing its different content.
							require.NoError(t, s.SetPrevHash([]byte("different-parent")))
							sb = marshal(s)
							require.NotEqual(t, expectedS, hash.Compute(string(sb)))
							require.Equal(t, shard, s.GetShardID())
							require.Equal(t, base.HeaderNonce, s.GetNonce())
							require.Equal(t, base.HeaderRound, s.GetRound())
							require.Equal(t, base.HeaderEpoch, s.GetEpoch())
						case "swapped_S_H":
							sb, hb = hb, sb
							expectedS, expectedH = hash.Compute(string(sb)), hash.Compute(string(hb))
						case "wrong_origin_shard":
							producing = 1
							if shard == 1 {
								producing = 2
							}
						case "wrong_account":
							a = bytes.Repeat([]byte{42}, 32)
						case "wrong_item":
							k = []byte("missing")
						case "missing_account_nodes":
							accountNodes = nil
						case "missing_data_nodes":
							dataNodes = nil
						case "corrupt_data_node":
							dataNodes = make([][]byte, len(dp))
							for i := range dp {
								dataNodes[i] = bytes.Clone(dp[i])
							}
							dataNodes[len(dataNodes)-1][0] ^= 1
						}
						budget := len(hb) + len(sb) + len(rb)
						for _, nodes := range [][][]byte{accountNodes, dataNodes} {
							for _, node := range nodes {
								budget += len(node)
							}
						}
						if name == "aggregate_limit" {
							budget--
						}
						if name == "negative_limit" {
							budget = -1
						}
						got, readErr := qualReadCommittedAccountItem(t, expectedH, expectedS, hb, sb, rb, a, k, accountNodes, dataNodes, producing, budget, flags)
						if name == "valid" {
							require.NoError(t, readErr)
							require.Equal(t, expected, got)
						} else {
							require.Error(t, readErr)
							require.Empty(t, got)
						}
						after, rootErr := adb.RootHash()
						require.NoError(t, rootErr)
						require.Equal(t, root, after, "read-only import must not mutate native state")
					})
				}
			})
		}
	}
}
