package smartContract

import (
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/dataRetriever/blockchain"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/statusHandler"
	"github.com/stretchr/testify/require"
)

func TestQualPartialsG17QueryUsesAtomicExecutedSnapshot(t *testing.T) {
	chain, err := blockchain.NewBlockChain(&statusHandler.AppStatusHandlerStub{})
	require.NoError(t, err)
	require.NoError(t, chain.SetCurrentBlockHeaderAndRootHash(&block.HeaderV3{Nonce: 1000}, []byte("current-root")))
	headers := []*block.HeaderV3{{Nonce: 11}, {Nonce: 12}}
	hashes := [][]byte{[]byte("executed-A"), []byte("executed-B")}
	roots := [][]byte{[]byte("root-A"), []byte("root-B")}
	chain.SetLastExecutedBlockHeaderAndRootHash(headers[0], hashes[0], roots[0])
	fallbackReads := 0
	args := createMockArgumentsForSCQuery()
	args.MainBlockChain = &testscommon.ChainHandlerStub{
		GetCurrentBlockHeaderCalled:             chain.GetCurrentBlockHeader,
		GetLastExecutedBlockHeaderAndInfoCalled: chain.GetLastExecutedBlockHeaderAndInfo,
		GetLastExecutedBlockInfoCalled: func() (uint64, []byte, []byte) {
			fallbackReads++
			return 77, []byte("poison-hash"), []byte("poison-root")
		},
		GetLastExecutedBlockHeaderCalled: func() data.HeaderHandler {
			fallbackReads++
			return &block.HeaderV3{Nonce: 77}
		},
	}
	service, err := NewSCQueryService(args)
	require.NoError(t, err)
	header, root, hash, err := service.extractBlockHeaderAndRootHash(&process.SCQuery{})
	require.NoError(t, err)
	require.Equal(t, uint64(11), header.GetNonce(), "atomic query snapshot selects executed header")
	require.Equal(t, roots[0], root)
	require.Equal(t, hashes[0], hash)
	header.(*block.HeaderV3).Nonce = 99
	header, _, _, err = service.extractBlockHeaderAndRootHash(&process.SCQuery{})
	require.NoError(t, err)
	require.Equal(t, uint64(11), header.GetNonce(), "query header clone isolates retained nonce")

	// Hash/root fixtures stay immutable: the source promises a tuple snapshot,
	// not deep copies of the caller-owned byte slices.
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; i < 1000; i++ {
			j := i % 2
			chain.SetLastExecutedBlockHeaderAndRootHash(headers[j], hashes[j], roots[j])
		}
	}()
	for i := 0; i < 1000; i++ {
		header, root, hash, err = service.extractBlockHeaderAndRootHash(&process.SCQuery{})
		if err != nil {
			t.Error(err)
			break
		}
		j := int(header.GetNonce() - 11)
		if j < 0 || j > 1 {
			t.Errorf("unexpected snapshot nonce %d", header.GetNonce())
			break
		}
		require.Equal(t, roots[j], root, "atomic query snapshot root")
		require.Equal(t, hashes[j], hash, "atomic query snapshot hash")
	}
	writer.Wait()
	require.Zero(t, fallbackReads, "atomic query snapshot must bypass split getters")
}
