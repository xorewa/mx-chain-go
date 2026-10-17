package block_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	blproc "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// This observes the real shard/meta ProcessBlockProposal owner around its
// optional native adapter. Native capability/dataflow are exercised separately
// with the actual constructed hook and record consumers, never this observer.
type qualT42OperationHook struct {
	*testscommon.BlockChainHookStub
	t                      *testing.T
	active                 bool
	begins, installs, ends int
	beginErr, installErr   error
}

func (h *qualT42OperationHook) BeginDRWAHeaderEvaluation() (func(data.HeaderHandler) error, func(), error) {
	h.begins++
	if h.beginErr != nil {
		return nil, nil, h.beginErr
	}
	require.False(h.t, h.active)
	h.active = true
	return func(header data.HeaderHandler) error {
		require.True(h.t, h.active)
		h.installs++
		if h.installErr != nil {
			return h.installErr
		}
		return h.BlockChainHookStub.SetCurrentHeader(header)
	}, func() { require.True(h.t, h.active); h.ends++; h.active = false }, nil
}

func TestQualDRWAT42ProposalOperationLifetime(t *testing.T) {
	for _, locus := range []string{"shard", "meta"} {
		for _, phase := range []string{"success", "begin_error", "wrong_locus", "install_error", "after_install_error", "nil_input"} {
			t.Run(locus+"/"+phase, func(t *testing.T) {
				selected := errors.New("T42 selected owning stage failure")
				hook := &qualT42OperationHook{BlockChainHookStub: &testscommon.BlockChainHookStub{}, t: t}
				if phase == "begin_error" {
					hook.beginErr = selected
				}
				if phase == "install_error" {
					hook.installErr = selected
				}
				var err error
				if locus == "shard" {
					args := CreateMockArguments(createComponentHolderMocks())
					args.BlockChainHook = hook
					if phase == "after_install_error" {
						args.BlockProcessingCutoffHandler = &testscommon.BlockProcessingCutoffStub{HandleProcessErrorCutoffCalled: func(data.HeaderHandler) error { return selected }}
					}
					processor, e := blproc.NewShardProcessor(args)
					require.NoError(t, e)
					var header data.HeaderHandler = &block.HeaderV3{Nonce: 1}
					if phase == "wrong_locus" {
						header = &block.MetaBlockV3{Nonce: 1}
					}
					if phase == "nil_input" {
						header = nil
					}
					_, err = processor.ProcessBlockProposal(header, []byte("T42-fixture"), &block.Body{})
				} else {
					defaultMetaBlockV3 := block.MetaBlockV3{LastExecutionResult: &block.MetaExecutionResultInfo{ExecutionResult: &block.BaseMetaExecutionResult{AccumulatedFeesInEpoch: big.NewInt(0), DevFeesInEpoch: big.NewInt(0)}}}
					coreComponents, dataComponents, bootstrap, status := createMockComponentHolders()
					dataComponents.BlockChain = &testscommon.ChainHandlerStub{
						GetLastExecutionResultCalled: func() data.BaseExecutionResultHandler {
							return &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{AccumulatedFeesInEpoch: big.NewInt(10), DevFeesInEpoch: big.NewInt(10)}}
						},
						GetLastExecutedBlockHeaderCalled: func() data.HeaderHandler { return &defaultMetaBlockV3 },
					}
					args := createMockMetaArguments(coreComponents, dataComponents, bootstrap, status)
					args.BlockChainHook = hook
					if phase == "after_install_error" {
						args.BlockProcessingCutoffHandler = &testscommon.BlockProcessingCutoffStub{HandleProcessErrorCutoffCalled: func(data.HeaderHandler) error { return selected }}
					}
					processor, e := blproc.NewMetaProcessor(args)
					require.NoError(t, e)
					header := defaultMetaBlockV3
					header.Nonce = 1
					var input data.HeaderHandler = &header
					if phase == "wrong_locus" {
						input = &block.HeaderV3{Nonce: 1}
					}
					if phase == "nil_input" {
						input = nil
					}
					_, err = processor.ProcessBlockProposal(input, []byte("T42-fixture"), &block.Body{})
				}
				if phase == "success" {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
				if phase == "begin_error" || phase == "install_error" || phase == "after_install_error" {
					require.ErrorIs(t, err, selected)
				}
				require.False(t, hook.active)
				if phase == "nil_input" {
					require.Zero(t, hook.begins)
					require.Zero(t, hook.ends)
				} else {
					require.Equal(t, 1, hook.begins)
					if phase == "begin_error" {
						require.Zero(t, hook.ends)
					} else {
						require.Equal(t, 1, hook.ends)
					}
				}
				if phase == "success" || phase == "install_error" || phase == "after_install_error" {
					require.Equal(t, 1, hook.installs)
				} else {
					require.Zero(t, hook.installs)
				}
			})
		}
	}
}
