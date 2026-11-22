package block_test

import (
	"errors"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	blproc "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
	"testing"
)

type qualS1CandidateOwner struct {
	*testscommon.BlockChainHookStub
	t                      *testing.T
	expected               data.HeaderHandler
	begins, installs, ends int
	nativeError            error
}

func (owner *qualS1CandidateOwner) BeginDRWAHeaderEvaluationForHeader(header data.HeaderHandler) (func(data.HeaderHandler) error, func(), error) {
	require.Same(owner.t, owner.expected, header)
	owner.begins++
	return func(installed data.HeaderHandler) error {
		require.Same(owner.t, header, installed)
		owner.installs++
		return owner.nativeError
	}, func() { owner.ends++ }, nil
}
func TestQualS1ProposalPassesActualCandidate(t *testing.T) {
	for _, fail := range []bool{false, true} {
		args := CreateMockArguments(createComponentHolderMocks())
		header := &block.HeaderV3{Nonce: 1, Round: 22}
		owner := &qualS1CandidateOwner{BlockChainHookStub: &testscommon.BlockChainHookStub{}, t: t, expected: header}
		if fail {
			owner.nativeError = errors.New("selected native header error")
		}
		args.BlockChainHook = owner
		processor, err := blproc.NewShardProcessor(args)
		require.NoError(t, err)
		_, err = processor.ProcessBlockProposal(header, []byte("candidate fixture"), &block.Body{})
		require.Equal(t, owner.nativeError, err)
		require.Equal(t, 1, owner.begins)
		require.Equal(t, 1, owner.installs)
		require.Equal(t, 1, owner.ends)
	}
}
