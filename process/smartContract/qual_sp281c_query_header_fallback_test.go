package smartContract

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CQueryHeaderFallback(t *testing.T) {
	t.Run("legacy executed tuple", func(t *testing.T) {
		executed := &block.HeaderV3{Nonce: 7}
		executedHash := []byte("executed-header-hash")
		executedRoot := []byte("executed-root")
		var infoReads, headerReads int

		chain := &testscommon.ChainHandlerStub{
			GetCurrentBlockHeaderCalled: func() data.HeaderHandler {
				return &block.HeaderV3{Nonce: 100}
			},
			GetLastExecutedBlockInfoCalled: func() (uint64, []byte, []byte) {
				infoReads++
				return executed.Nonce, executedHash, executedRoot
			},
			GetLastExecutedBlockHeaderCalled: func() data.HeaderHandler {
				headerReads++
				return executed
			},
		}
		// Expose only ChainHandler so the stub's optional atomic getter stays hidden.
		service := &SCQueryService{mainBlockChain: struct{ data.ChainHandler }{chain}}

		header, root, hash, err := service.extractBlockHeaderAndRootHash(&process.SCQuery{})
		require.NoError(t, err)
		require.Same(t, executed, header)
		require.Equal(t, executedRoot, root)
		require.Equal(t, executedHash, hash)
		require.Equal(t, 1, infoReads)
		require.Equal(t, 1, headerReads)
	})

	t.Run("nil explicit header", func(t *testing.T) {
		var service SCQueryService
		header, root, hash, err := service.getHeaderAndRootHashForBlock(nil, []byte("requested-header-hash"))
		require.ErrorIs(t, err, process.ErrNilBlockHeader)
		require.Nil(t, header)
		require.Nil(t, root)
		require.Nil(t, hash)
	})
}
