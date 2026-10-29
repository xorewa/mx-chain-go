package blockchain

import (
	"bytes"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/mock"
	"github.com/stretchr/testify/require"
)

func TestSP1CoverageExecutionSnapshot(t *testing.T) {
	chain := &baseBlockChain{appStatusHandler: &mock.AppStatusHandlerStub{}, lastExecutedBlockInfo: &blockInfo{}}
	header, hash, root := chain.GetLastExecutedBlockHeaderAndInfo()
	require.Nil(t, header)
	require.Nil(t, hash)
	require.Nil(t, root)
	input := &block.HeaderV3{Nonce: 11}
	chain.SetLastExecutedBlockHeaderAndRootHash(input, []byte("executed-S"), []byte("result-root-S"))
	header, hash, root = chain.GetLastExecutedBlockHeaderAndInfo()
	require.Equal(t, uint64(11), header.GetNonce())
	require.Equal(t, []byte("executed-S"), hash)
	require.Equal(t, []byte("result-root-S"), root)
	header.(*block.HeaderV3).Nonce = 99
	retained, _, _ := chain.GetLastExecutedBlockHeaderAndInfo()
	require.Equal(t, uint64(11), retained.GetNonce())
	chain.SetLastExecutedBlockHeaderAndRootHash(nil, []byte("unusable-hash"), []byte("unusable-root"))
	header, hash, root = chain.GetLastExecutedBlockHeaderAndInfo()
	require.Nil(t, header)
	require.Nil(t, hash)
	require.Nil(t, root)

	// Setters own the input byte slices; keep them immutable for the entire
	// concurrent interval. The accessor promises an atomic snapshot, not a
	// deep copy of externally owned hash bytes.
	var workers sync.WaitGroup
	workers.Add(2)
	start := make(chan struct{})
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 512; i++ {
			chain.SetLastExecutedBlockHeaderAndRootHash(&block.HeaderV3{Nonce: 1}, []byte("S1"), []byte("root1"))
			chain.SetLastExecutedBlockHeaderAndRootHash(&block.HeaderV3{Nonce: 2}, []byte("S2"), []byte("root2"))
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 512; i++ {
			header, hash, root := chain.GetLastExecutedBlockHeaderAndInfo()
			if header == nil {
				if hash != nil || root != nil {
					t.Error("absent header exposed unrelated execution identities")
				}
				continue
			}
			if header.GetNonce() == 1 {
				if !bytes.Equal(hash, []byte("S1")) || !bytes.Equal(root, []byte("root1")) {
					t.Error("mixed first execution snapshot")
				}
			} else if header.GetNonce() == 2 {
				if !bytes.Equal(hash, []byte("S2")) || !bytes.Equal(root, []byte("root2")) {
					t.Error("mixed second execution snapshot")
				}
			} else {
				t.Errorf("unexpected retained nonce %d", header.GetNonce())
			}
		}
	}()
	close(start)
	workers.Wait()
}
