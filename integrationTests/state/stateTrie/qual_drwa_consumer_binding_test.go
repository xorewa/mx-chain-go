package stateTrie

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/integrationTests"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/state/factory"
	dataMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/pool"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	storageMock "github.com/multiversx/mx-chain-go/testscommon/storage"
	"github.com/stretchr/testify/require"
)

// NON-NORMATIVE AR-01 (Part A 6.1:5251-5284) construction, NOT promotion.
// Extend the account witness to an authenticated consumer B. This intentionally
// supports only a single-carrier reference fixture and a direct meta predecessor;
// neither is a proposed production restriction or a selected settlement depth.
// For shard origins use the native ShardInfoCreateData projection, not a second
// implementation. For meta origins H is the referenced meta header, with no
// invented ShardInfo projection. B's hash, shard identities, H proof availability,
// last-self-notarized nonce and activation handler are TRUSTED fixture inputs.
// Proof signatures/ancestry/settlement, first eligible B, delivery, gas and network
// domain qualification remain open. A successful read must NEVER authorize a
// positive DRWA decision. No state write or finality signal exists in this helper.
func qualReadConsumerBoundItem(t *testing.T, expectedB, bBytes, mBytes, hBytes, sBytes, resultBytes, address, key []byte,
	accountNodes, dataNodes [][]byte, origin, destination uint32, limit int, proofAvailable bool,
	lastMetaNonce uint64, flags common.EnableEpochsHandler) ([]byte, error) {
	t.Helper()
	deny := errors.New("qualification consumer binding rejected")
	remaining := limit
	for _, parts := range [][][]byte{{bBytes, mBytes, hBytes, sBytes, resultBytes}, accountNodes, dataNodes} {
		for _, part := range parts {
			if len(part) == 0 || len(part) > remaining {
				return nil, deny
			}
			remaining -= len(part)
		}
	}
	mar, hash := integrationTests.TestMarshalizer, integrationTests.TestHasher
	if !bytes.Equal(hash.Compute(string(bBytes)), expectedB) {
		return nil, deny
	}
	var b data.HeaderHandler
	mHash := hash.Compute(string(mBytes))
	if destination == core.MetachainShardId {
		meta := &block.MetaBlockV3{}
		if mar.Unmarshal(meta, bBytes) != nil {
			return nil, deny
		}
		b = meta
	} else {
		shard := &block.HeaderV3{}
		if mar.Unmarshal(shard, bBytes) != nil || shard.ShardID != destination {
			return nil, deny
		}
		matches := 0
		for _, ref := range shard.MetaBlockHashes {
			if bytes.Equal(ref, mHash) {
				matches++
			}
		}
		if matches != 1 {
			return nil, deny
		}
		b = shard
	}
	m := &block.MetaBlockV3{}
	if mar.Unmarshal(m, mBytes) != nil {
		return nil, deny
	}
	// Reuse native parent construction validation, including the random-seed
	// relation. Shard/meta nonce spaces are unrelated and are not compared.
	if destination == core.MetachainShardId {
		validator, err := processBlock.NewHeaderValidator(processBlock.ArgsHeaderValidator{
			Hasher: hash, Marshalizer: mar, EnableEpochsHandler: flags,
		})
		if err != nil || validator.IsHeaderConstructionValid(b, m) != nil {
			return nil, deny
		}
	}
	hHash, sHash := hash.Compute(string(hBytes)), hash.Compute(string(sBytes))
	if origin == core.MetachainShardId {
		if !bytes.Equal(mBytes, hBytes) {
			return nil, deny
		}
	} else {
		h, s := &block.HeaderV3{}, &block.HeaderV3{}
		if mar.Unmarshal(h, hBytes) != nil || mar.Unmarshal(s, sBytes) != nil || h.ShardID != origin || s.ShardID != origin {
			return nil, deny
		}
		creator, err := processBlock.NewShardInfoCreateData(processBlock.ShardInfoCreateDataArgs{
			EnableEpochsHandler: flags,
			HeadersPool: &pool.HeadersPoolStub{GetHeaderByHashCalled: func(wanted []byte) (data.HeaderHandler, error) {
				if !bytes.Equal(wanted, sHash) {
					return nil, deny
				}
				return s, nil
			}},
			ProofsPool: &dataMock.ProofsPoolMock{HasProofCalled: func(shard uint32, wanted []byte) bool {
				return proofAvailable && shard == origin && bytes.Equal(wanted, hHash)
			}},
			PendingMiniBlocksHandler: &mock.PendingMiniBlocksHandlerStub{},
			BlockTracker: &mock.BlockTrackerMock{GetLastSelfNotarizedHeaderCalled: func(shard uint32) (data.HeaderHandler, []byte, error) {
				if shard != origin {
					return nil, nil, deny
				}
				return &block.MetaBlockV3{Nonce: lastMetaNonce}, nil, nil
			}},
			Storage: &storageMock.ChainStorerStub{}, Marshaller: mar,
		})
		if err != nil {
			return nil, err
		}
		proposals, executed, err := creator.CreateShardInfoV3(m, []data.HeaderHandler{h}, [][]byte{hHash})
		if err != nil || len(proposals) != 1 || len(executed) != 1 || len(m.ShardInfoProposal) != 1 || len(m.ShardInfo) != 1 {
			return nil, deny
		}
		if !proposals[0].Equal(&m.ShardInfoProposal[0]) || !executed[0].Equal(&m.ShardInfo[0]) {
			return nil, deny
		}
	}
	// Existing reader validates full result equality, S identity and the native
	// main/account/data witness. The joint bound above also includes B and M.
	return qualReadCommittedAccountItem(t, hHash, sHash, hBytes, sBytes, resultBytes,
		address, key, accountNodes, dataNodes, origin, limit, flags)
}

func TestQualDRWAConsumerBoundAccountItem(t *testing.T) {
	for _, route := range []struct {
		name                string
		origin, destination uint32
	}{
		{"shard_local", 1, 1}, {"shard_to_shard", 1, 2}, {"shard_to_meta", 1, core.MetachainShardId},
		{"meta_to_shard", core.MetachainShardId, 2}, {"meta_local", core.MetachainShardId, core.MetachainShardId},
	} {
		for _, balanced := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/balanced_%t", route.name, balanced), func(t *testing.T) {
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
				address := bytes.Repeat([]byte{51}, 32)
				account, err := creator.CreateAccount(address)
				require.NoError(t, err)
				user := account.(state.UserAccountHandler)
				key, value := qualProtectedFixtureKey([]byte("item"), []byte("action-B")), []byte("literal item B")
				require.NoError(t, user.SaveKeyValue(key, value))
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
				encode := func(v interface{}) []byte { out, e := mar.Marshal(v); require.NoError(t, e); return out }
				cases := []string{"valid", "B_hash", "B_content", "M_content", "consumer_reference", "H_content", "S_content", "result_gas", "item_key", "missing_account", "missing_data", "joint_limit", "negative_limit"}
				if route.origin != core.MetachainShardId {
					cases = append(cases, "proposal_H_hash", "projection_S_hash", "projection_fees", "projection_tx_count", "projection_last_meta", "missing_proposal", "extra_projection", "missing_H_proof")
				} else {
					cases = append(cases, "different_meta_H")
				}
				if route.destination == core.MetachainShardId {
					cases = append(cases, "parent_nonce", "parent_round", "parent_seed")
				} else {
					cases = append(cases, "duplicate_reference", "consumer_shard")
				}
				for _, name := range cases {
					t.Run(name, func(t *testing.T) {
						var s, h data.HeaderHandler
						if route.origin == core.MetachainShardId {
							s, h = &block.MetaBlockV3{Nonce: 11, Round: 21, Epoch: 3}, &block.MetaBlockV3{Nonce: 15, Round: 25, Epoch: 4}
						} else {
							s, h = &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: route.origin, PrevHash: []byte("S-parent")}, &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: route.origin}
						}
						sb := encode(s)
						base := &block.BaseExecutionResult{HeaderHash: hash.Compute(string(sb)), HeaderNonce: 11, HeaderRound: 21, HeaderEpoch: 3, RootHash: root, GasUsed: 7}
						var result data.BaseExecutionResultHandler
						if route.origin == core.MetachainShardId {
							result = &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{BaseExecutionResult: base}}
						} else {
							result = &block.ExecutionResult{BaseExecutionResult: base, AccumulatedFees: big.NewInt(9), DeveloperFees: big.NewInt(2), ExecutedTxCount: 3}
						}
						require.NoError(t, h.SetExecutionResultsHandlers([]data.BaseExecutionResultHandler{result}))
						hb := encode(h)
						m := &block.MetaBlockV3{Nonce: 31, Round: 41, Epoch: 4}
						if route.origin == core.MetachainShardId {
							require.NoError(t, mar.Unmarshal(m, hb))
						} else {
							// Independent literal projection, NOT generated by the native
							// creator under test. S/H deliberately differ in epoch/nonce/round.
							m.ShardInfoProposal = []block.ShardDataProposal{{HeaderHash: hash.Compute(string(hb)), Nonce: 15, Round: 25, Epoch: 4, ShardID: route.origin}}
							m.ShardInfo = []block.ShardData{{HeaderHash: hash.Compute(string(sb)), Nonce: 11, Round: 21, Epoch: 3, ShardID: route.origin, PrevHash: []byte("S-parent"), TxCount: 3, AccumulatedFees: big.NewInt(9), DeveloperFees: big.NewInt(2), LastIncludedMetaNonce: 8}}
						}
						switch name {
						case "proposal_H_hash":
							m.ShardInfoProposal[0].HeaderHash = base.HeaderHash
						case "projection_S_hash":
							m.ShardInfo[0].HeaderHash = hash.Compute(string(hb))
						case "projection_fees":
							m.ShardInfo[0].AccumulatedFees = big.NewInt(10)
						case "projection_tx_count":
							m.ShardInfo[0].TxCount++
						case "projection_last_meta":
							m.ShardInfo[0].LastIncludedMetaNonce++
						case "missing_proposal":
							m.ShardInfoProposal = nil
						case "extra_projection":
							m.ShardInfo = append(m.ShardInfo, m.ShardInfo[0])
						}
						mb := encode(m)
						var b data.HeaderHandler
						if route.destination == core.MetachainShardId {
							b = &block.MetaBlockV3{Nonce: m.Nonce + 1, Round: m.Round + 1, Epoch: 4, PrevHash: hash.Compute(string(mb))}
						} else {
							b = &block.HeaderV3{Nonce: 5, Round: 51, Epoch: 4, ShardID: route.destination, MetaBlockHashes: [][]byte{hash.Compute(string(mb))}}
						}
						switch name {
						case "consumer_reference":
							if x, ok := b.(*block.HeaderV3); ok {
								x.MetaBlockHashes = [][]byte{[]byte("other-M")}
							} else {
								require.NoError(t, b.SetPrevHash([]byte("other-M")))
							}
						case "duplicate_reference":
							x := b.(*block.HeaderV3)
							x.MetaBlockHashes = append(x.MetaBlockHashes, x.MetaBlockHashes[0])
						case "consumer_shard":
							require.NoError(t, b.SetShardID(0))
						case "parent_nonce":
							require.NoError(t, b.SetNonce(m.Nonce+2))
						case "parent_round":
							require.NoError(t, b.SetRound(m.Round))
						case "parent_seed":
							require.NoError(t, b.SetPrevRandSeed([]byte("wrong-seed")))
						}
						bb := encode(b)
						expectedB := hash.Compute(string(bb))
						switch name {
						case "B_hash":
							expectedB = []byte("other-B")
						case "B_content":
							require.NoError(t, b.SetPrevRandSeed([]byte("changed")))
							bb = encode(b)
						case "M_content":
							m.PrevRandSeed = []byte("changed")
							mb = encode(m)
						case "H_content", "different_meta_H":
							require.NoError(t, h.SetPrevRandSeed([]byte("changed")))
							hb = encode(h)
						case "S_content":
							require.NoError(t, s.SetPrevRandSeed([]byte("changed")))
							sb = encode(s)
						case "result_gas":
							base.GasUsed++
						}
						rb := encode(result)
						k, an, dn := key, ap, dp
						if name == "item_key" {
							k = []byte("absent")
						}
						if name == "missing_account" {
							an = nil
						}
						if name == "missing_data" {
							dn = nil
						}
						limit := len(bb) + len(mb) + len(hb) + len(sb) + len(rb)
						for _, nodes := range [][][]byte{an, dn} {
							for _, node := range nodes {
								limit += len(node)
							}
						}
						if name == "joint_limit" {
							limit--
						}
						if name == "negative_limit" {
							limit = -1
						}
						got, readErr := qualReadConsumerBoundItem(t, expectedB, bb, mb, hb, sb, rb, address, k, an, dn, route.origin, route.destination, limit, name != "missing_H_proof", 8, flags)
						if name == "valid" {
							require.NoError(t, readErr)
							require.Equal(t, value, got)
						} else {
							require.Error(t, readErr)
							require.Empty(t, got)
						}
						after, e := adb.RootHash()
						require.NoError(t, e)
						require.Equal(t, root, after, "authentication must remain read-only")
					})
				}
			})
		}
	}
}
