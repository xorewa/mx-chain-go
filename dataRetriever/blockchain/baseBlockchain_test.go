package blockchain

import (
	"bytes"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/mock"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/testscommon/statusHandler"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestBaseBlockchain_SetAndGetSetFinalBlockInfo(t *testing.T) {
	t.Parallel()

	base := &baseBlockChain{
		appStatusHandler: &mock.AppStatusHandlerStub{},
		finalBlockInfo:   &blockInfo{},
	}

	nonce := uint64(42)
	hash := []byte("hash")
	rootHash := []byte("root-hash")

	base.SetFinalBlockInfo(nonce, hash, rootHash)
	actualNonce, actualHash, actualRootHash := base.GetFinalBlockInfo()

	require.Equal(t, nonce, actualNonce)
	require.Equal(t, hash, actualHash)
	require.Equal(t, rootHash, actualRootHash)
}

func TestBaseBlockchain_SetAndGetSetFinalBlockInfoWorksWithNilValues(t *testing.T) {
	t.Parallel()

	base := &baseBlockChain{
		appStatusHandler: &mock.AppStatusHandlerStub{},
		finalBlockInfo:   &blockInfo{},
	}

	actualNonce, actualHash, actualRootHash := base.GetFinalBlockInfo()
	require.Equal(t, uint64(0), actualNonce)
	require.Nil(t, actualHash)
	require.Nil(t, actualRootHash)

	base.SetFinalBlockInfo(0, nil, nil)

	actualNonce, actualHash, actualRootHash = base.GetFinalBlockInfo()
	require.Equal(t, uint64(0), actualNonce)
	require.Nil(t, actualHash)
	require.Nil(t, actualRootHash)
}

func TestBaseBlockchain_SetAndGetLastExecutedBlockHeaderAndRootHash(t *testing.T) {
	t.Parallel()

	t.Run("should set nil if header nil provided", func(t *testing.T) {
		t.Parallel()

		base := &baseBlockChain{
			appStatusHandler:      &mock.AppStatusHandlerStub{},
			finalBlockInfo:        &blockInfo{},
			lastExecutedBlockInfo: &blockInfo{},
		}

		hash := []byte("hash")
		rootHash := []byte("root-hash")

		base.SetLastExecutedBlockHeaderAndRootHash(nil, hash, rootHash)

		retHeader := base.GetLastExecutedBlockHeader()

		require.Nil(t, retHeader)

		retNonce, retHeaderHash, retRootHash := base.GetLastExecutedBlockInfo()
		require.Zero(t, retNonce)
		require.Nil(t, retHeaderHash)
		require.Nil(t, retRootHash)
	})

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		base := &baseBlockChain{
			appStatusHandler:      &mock.AppStatusHandlerStub{},
			finalBlockInfo:        &blockInfo{},
			lastExecutedBlockInfo: &blockInfo{},
		}

		nonce := uint64(10)
		hash := []byte("hash")
		rootHash := []byte("root-hash")

		header1 := &block.HeaderV3{
			Nonce: nonce,
		}

		base.SetLastExecutedBlockHeaderAndRootHash(header1, hash, rootHash)

		retHeader := base.GetLastExecutedBlockHeader()

		require.Equal(t, nonce, retHeader.GetNonce())

		retNonce, retHeaderHash, retRootHash := base.GetLastExecutedBlockInfo()
		require.Equal(t, nonce, retNonce)
		require.Equal(t, hash, retHeaderHash)
		require.Equal(t, rootHash, retRootHash)
	})
}

func TestBaseBlockchain_SetAndGetLastExecutionInfo(t *testing.T) {
	t.Parallel()

	base := &baseBlockChain{
		appStatusHandler:      &mock.AppStatusHandlerStub{},
		finalBlockInfo:        &blockInfo{},
		lastExecutedBlockInfo: &blockInfo{},
	}

	nonce := uint64(10)
	hash := []byte("hash")
	rootHash := []byte("root-hash")

	header1 := &block.HeaderV3{
		Nonce: nonce,
	}

	execResult := &block.ExecutionResult{
		BaseExecutionResult: &block.BaseExecutionResult{
			RootHash:    rootHash,
			HeaderHash:  hash,
			HeaderNonce: nonce,
		},
	}

	base.SetLastExecutionInfo(header1, execResult)

	retExecResult := base.GetLastExecutionResult()
	require.Equal(t, execResult, retExecResult)

	retLastExecHeader := base.GetLastExecutedBlockHeader()
	require.Equal(t, header1, retLastExecHeader)
}

func TestBaseBlockchain_Concurrency(t *testing.T) {
	t.Parallel()

	bc := &baseBlockChain{
		appStatusHandler:      &mock.AppStatusHandlerStub{},
		finalBlockInfo:        &blockInfo{},
		lastExecutedBlockInfo: &blockInfo{},
	}

	numCalls := 100

	header := &block.HeaderV3{}
	headerHash := []byte("headerHash")
	rootHash := []byte("rootHash")

	execResult := &block.ExecutionResult{}

	var wg sync.WaitGroup
	wg.Add(numCalls)

	for i := range numCalls {
		go func(i int) {
			switch i % 12 {
			case 0:
				_ = bc.GetCurrentBlockHeaderHash()
			case 1:
				_ = bc.GetGenesisHeader()
			case 2:
				_ = bc.GetGenesisHeaderHash()
			case 3:
				_ = bc.GetLastExecutedBlockHeader()
			case 4:
				_, _, _ = bc.GetFinalBlockInfo()
			case 5:
				_, _, _ = bc.GetLastExecutedBlockInfo()
			case 6:
				bc.SetLastExecutedBlockHeaderAndRootHash(header, headerHash, rootHash)
			case 7:
				bc.SetCurrentBlockHeaderHash(headerHash)
			case 8:
				bc.SetFinalBlockInfo(0, headerHash, rootHash)
			case 9:
				bc.SetGenesisHeaderHash(headerHash)
			case 10:
				bc.SetLastExecutionInfo(header, execResult)
			case 11:
				_ = bc.GetLastExecutionResult()
			default:
				require.Fail(t, "should have not been called")
			}
			wg.Done()
		}(i)
	}

	wg.Wait()
}

func TestBaseBlockchain_setMetrics(t *testing.T) {
	t.Parallel()

	t.Run("set metrics header v1", func(t *testing.T) {
		handler := statusHandler.NewAppStatusHandlerMock()

		bc := &baseBlockChain{
			appStatusHandler: handler,
		}

		header := &block.Header{
			Nonce:     10,
			Round:     11,
			TimeStamp: 1234,
		}
		bc.setCurrentHeaderMetrics(header)

		require.Equal(t, header.Nonce, handler.GetUint64(common.MetricNonce))
		require.Equal(t, header.Round, handler.GetUint64(common.MetricSynchronizedRound))
		require.Equal(t, header.TimeStamp, handler.GetUint64(common.MetricBlockTimestamp))
		require.Equal(t, common.ConvertTimeStampSecToMs(header.TimeStamp), handler.GetUint64(common.MetricBlockTimestampMs))
	})

	t.Run("set metrics header v3", func(t *testing.T) {
		handler := statusHandler.NewAppStatusHandlerMock()

		bc := &baseBlockChain{
			appStatusHandler: handler,
		}

		header := &block.HeaderV3{
			Nonce:       10,
			Round:       11,
			TimestampMs: 1234000,
			LastExecutionResult: &block.ExecutionResultInfo{
				ExecutionResult: &block.BaseExecutionResult{
					HeaderNonce: 9,
				},
			},
		}
		bc.setCurrentHeaderMetrics(header)

		require.Equal(t, uint64(9), handler.GetUint64(common.MetricNonce))
		require.Equal(t, header.Round, handler.GetUint64(common.MetricSynchronizedRound))
		require.Equal(t, common.ConvertTimeStampMsToSec(header.TimestampMs), handler.GetUint64(common.MetricBlockTimestamp))
		require.Equal(t, header.TimestampMs, handler.GetUint64(common.MetricBlockTimestampMs))
	})
}

func TestBaseBlockchain_GetLastExecutedBlockHeaderAndInfo(t *testing.T) {
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
