package block_test

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/process"
	blproc "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/epochNotifier"
)

type qualSP224MetaTimeOwner struct {
	*testscommon.BlockChainHookStub
	candidate data.HeaderHandler
	events    *[]string
}

func (owner *qualSP224MetaTimeOwner) BeginDRWAHeaderEvaluationForHeader(candidate data.HeaderHandler) (func(data.HeaderHandler) error, func(), error) {
	owner.candidate = candidate
	*owner.events = append(*owner.events, "begin")
	return owner.SetCurrentHeader, func() { *owner.events = append(*owner.events, "end") }, nil
}

type qualSP224NonNativeBody struct{ *block.Body }

// The observer records candidate routing. The native setter position returns
// the same sentinel in both modes before any proposal transaction execution.
func TestQualSP224MetaProposalTimeOwner(t *testing.T) {
	nativeError := errors.New("SP2-24 ordinary installation error")
	for _, tc := range []struct {
		name      string
		observe   bool
		header    data.HeaderHandler
		body      data.BodyHandler
		wantError error
		events    []string
	}{
		{"exact_proposal", true, &block.MetaBlockV3{Nonce: 1}, &block.Body{}, nativeError, []string{"begin", "round", "epoch", "install", "end"}},
		{"ordinary_setter", false, &block.MetaBlockV3{Nonce: 1}, &block.Body{}, nativeError, []string{"round", "epoch", "install"}},
		{"wrong_locus", true, &block.HeaderV3{Nonce: 1}, &block.Body{}, process.ErrWrongTypeAssertion, []string{"round", "epoch"}},
		{"wrong_body", true, &block.MetaBlockV3{Nonce: 1}, &qualSP224NonNativeBody{&block.Body{}}, process.ErrWrongTypeAssertion, []string{"round", "epoch"}},
		{"legacy", true, &block.MetaBlock{}, &block.Body{}, process.ErrInvalidHeader, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			stub := &testscommon.BlockChainHookStub{
				SetCurrentHeaderCalled: func(header data.HeaderHandler) error {
					require.Same(t, tc.header, header)
					events = append(events, "install")
					return nativeError
				},
			}
			observer := &qualSP224MetaTimeOwner{BlockChainHookStub: stub, events: &events}
			coreComponents, dataComponents, bootstrap, status := createMockComponentHolders()
			coreComponents.RoundNotifierField = &epochNotifier.RoundNotifierStub{
				CheckRoundCalled: func(header data.HeaderHandler) {
					require.Same(t, tc.header, header)
					events = append(events, "round")
				},
			}
			coreComponents.EpochNotifierField = &epochNotifier.EpochNotifierStub{
				CheckEpochCalled: func(header data.HeaderHandler) {
					require.Same(t, tc.header, header)
					events = append(events, "epoch")
				},
			}
			dataComponents.BlockChain = &testscommon.ChainHandlerStub{
				GetLastExecutedBlockHeaderCalled: func() data.HeaderHandler { return &block.MetaBlockV3{} },
				GetLastExecutionResultCalled: func() data.BaseExecutionResultHandler {
					return &block.MetaExecutionResult{ExecutionResult: &block.BaseMetaExecutionResult{}}
				},
			}
			args := createMockMetaArguments(coreComponents, dataComponents, bootstrap, status)
			args.BlockChainHook = stub
			if tc.observe {
				args.BlockChainHook = observer
			}
			processor, err := blproc.NewMetaProcessor(args)
			require.NoError(t, err)
			result, err := processor.ProcessBlockProposal(tc.header, []byte("SP2-24 fixture"), tc.body)
			require.ErrorIs(t, err, tc.wantError)
			require.Nil(t, result)
			require.Equal(t, tc.events, events)
			if tc.name == "exact_proposal" {
				require.Same(t, tc.header, observer.candidate)
			} else {
				require.Nil(t, observer.candidate)
			}
		})
	}
}
