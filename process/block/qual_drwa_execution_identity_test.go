package block

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	dataRetrieverMock "github.com/multiversx/mx-chain-go/testscommon/dataRetriever"
	poolMock "github.com/multiversx/mx-chain-go/testscommon/pool"
	"github.com/multiversx/mx-chain-go/testscommon/processMocks"
	"github.com/stretchr/testify/require"
)

// Part A 6.1 AR-01: S (executed block) differs from H (carrying header).
// These are upstream identity observations, not a DRWA finality predicate.
// Pool/proof/tracker stubs do not authenticate a root or establish settlement.
func TestQualDRWAExecutionIdentityProjection(t *testing.T) {
	for _, withResult := range []bool{false, true} {
		name := "proposal_without_execution"
		if withResult {
			name = "distinct_executed_and_carrying_headers"
		}
		t.Run(name, func(t *testing.T) {
			executed := &block.HeaderV3{Nonce: 11, Round: 21, Epoch: 3, ShardID: 1, PrevHash: []byte("S-parent")}
			carrier := &block.HeaderV3{Nonce: 15, Round: 25, Epoch: 4, ShardID: 1, PrevHash: []byte("H-parent")}
			result := createDummyShardExecutionResult()
			result.BaseExecutionResult.HeaderHash = []byte("S")
			result.BaseExecutionResult.HeaderNonce, result.BaseExecutionResult.HeaderRound, result.BaseExecutionResult.HeaderEpoch = 11, 21, 3
			result.BaseExecutionResult.RootHash = []byte("executed-root")
			if withResult {
				carrier.ExecutionResults = []*block.ExecutionResult{result}
			}
			args := createDefaultShardInfoCreateDataArgs()
			lookups, proofs := 0, 0
			args.HeadersPool = &poolMock.HeadersPoolStub{GetHeaderByHashCalled: func(hash []byte) (data.HeaderHandler, error) {
				lookups++
				require.Equal(t, []byte("S"), hash, "lookup must use executed identity")
				return executed, nil
			}}
			args.ProofsPool = &dataRetrieverMock.ProofsPoolMock{HasProofCalled: func(shard uint32, hash []byte) bool {
				proofs++
				require.Equal(t, uint32(1), shard)
				require.Equal(t, []byte("H"), hash, "proof lookup must use carrying header")
				return true
			}}
			args.BlockTracker = &mock.BlockTrackerMock{GetLastSelfNotarizedHeaderCalled: func(shard uint32) (data.HeaderHandler, []byte, error) {
				require.Equal(t, uint32(1), shard)
				return &block.MetaBlockV3{Nonce: 7}, []byte("M"), nil
			}}
			creator, err := NewShardInfoCreateData(args)
			require.NoError(t, err)
			proposals, infos, err := creator.CreateShardInfoV3(&block.MetaBlockV3{}, []data.HeaderHandler{carrier}, [][]byte{[]byte("H")})
			require.NoError(t, err)
			require.Len(t, proposals, 1)
			require.Equal(t, []byte("H"), proposals[0].GetHeaderHash())
			require.Equal(t, uint64(15), proposals[0].GetNonce())
			require.Equal(t, 1, proofs)
			if !withResult {
				require.Empty(t, infos, "a proposal alone is not an executed-result projection")
				require.Zero(t, lookups)
				return
			}
			require.Len(t, infos, 1)
			require.Equal(t, 1, lookups)
			require.Equal(t, []byte("S"), infos[0].GetHeaderHash())
			require.Equal(t, uint64(11), infos[0].GetNonce())
			require.Equal(t, uint64(21), infos[0].GetRound())
			require.Equal(t, []byte("S-parent"), infos[0].GetPrevHash())
			require.Equal(t, uint32(3), infos[0].(*block.ShardData).Epoch)
			// The projection has no root field. A root change keeps this projection
			// equal; consumers therefore need the full authenticated result witness.
			result.BaseExecutionResult.RootHash = []byte("different-root")
			_, other, err := creator.CreateShardInfoV3(&block.MetaBlockV3{}, []data.HeaderHandler{carrier}, [][]byte{[]byte("H")})
			require.NoError(t, err)
			require.Len(t, other, 1)
			require.True(t, infos[0].Equal(other[0]))
		})
	}
}

// A consistent header summary alone is insufficient. The public verifier must
// compare the complete result with the pending execution-manager entry.
func TestQualDRWAExecutionIdentityResultBinding(t *testing.T) {
	cases := []struct {
		name   string
		change func(*block.ExecutionResult)
	}{
		{"unchanged", func(*block.ExecutionResult) {}},
		{"root_substitution", func(r *block.ExecutionResult) { r.BaseExecutionResult.RootHash = []byte("other-root") }},
		{"origin_substitution_same_nonce", func(r *block.ExecutionResult) { r.BaseExecutionResult.HeaderHash = []byte("other-origin") }},
		{"round_substitution", func(r *block.ExecutionResult) { r.BaseExecutionResult.HeaderRound++ }},
		{"epoch_substitution", func(r *block.ExecutionResult) { r.BaseExecutionResult.HeaderEpoch++ }},
		{"receipts_substitution", func(r *block.ExecutionResult) { r.ReceiptsHash = []byte("other-receipts") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := createShardHeaderV3WithExecutionResults()
			prev := createPrevShardHeaderV3WithoutExecutionResults()
			pending := createDummyShardExecutionResult() // separately allocated reference
			tc.change(header.ExecutionResults[0])
			last, err := process.CreateLastExecutionResultInfoFromExecutionResult(header.Round, header.ExecutionResults[0], header.ShardID)
			require.NoError(t, err)
			header.LastExecutionResult = last.(*block.ExecutionResultInfo)
			calls := 0
			verifier, err := NewExecutionResultsVerifier(&testscommon.ChainHandlerStub{
				GetCurrentBlockHeaderCalled:     func() data.HeaderHandler { return prev },
				GetCurrentBlockHeaderHashCalled: func() []byte { return header.PrevHash },
			}, &processMocks.ExecutionManagerMock{GetPendingExecutionResultsCalled: func() ([]data.BaseExecutionResultHandler, error) {
				calls++
				return []data.BaseExecutionResultHandler{pending}, nil
			}})
			require.NoError(t, err)
			err = verifier.VerifyHeaderExecutionResults(header)
			require.Equal(t, 1, calls, "must reach pending-result comparison")
			if tc.name == "unchanged" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, process.ErrExecutionResultDoesNotMatch)
			}
		})
	}
}
