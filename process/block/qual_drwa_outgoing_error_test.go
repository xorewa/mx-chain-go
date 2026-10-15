package block_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

type qualDRWAOutgoingCoordinator struct {
	*testscommon.TransactionCoordinatorMock
	failure error
	calls   int
}

func (c *qualDRWAOutgoingCoordinator) CreateMbsAndProcessTransactionsFromMe(func() bool, []byte) (block.MiniBlockSlice, error) {
	c.calls++
	return block.MiniBlockSlice{&block.MiniBlock{TxHashes: [][]byte{[]byte("partial")}}}, c.failure
}

// This exercises the real native body-producing callers, not candidate journal
// reconstruction or admission of the injected coordinator dependency.
// Synthetic dependency fixtures are experimental; replace before testnet admission.
func TestQualDRWAOutgoingBlockBodyError(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		for _, shape := range []string{"marker", "wrapped", "joined", "success"} {
			t.Run(chain+"/"+shape, func(t *testing.T) {
				original := errors.New("native operation failed")
				rollback := errors.New("native rollback failed")
				failure := vm.ErrDRWAExecution
				switch shape {
				case "wrapped":
					failure = fmt.Errorf("context: %w", failure)
				case "joined":
					failure = errors.Join(failure, original, rollback)
				case "success":
					failure = nil
				}
				coordinator := &qualDRWAOutgoingCoordinator{TransactionCoordinatorMock: &testscommon.TransactionCoordinatorMock{}, failure: failure}
				var body interface{}
				var err error
				if chain == "meta" {
					args := createMockMetaArguments(createMockComponentHolders())
					args.TxCoordinator = coordinator
					mp, e := processBlock.NewMetaProcessor(args)
					require.NoError(t, e)
					body, err = mp.CreateBlockBody(&block.MetaBlock{}, func() bool { return true })
				} else {
					args := CreateMockArgumentsMultiShard(createMockComponentHolders())
					args.TxCoordinator = coordinator
					sp, e := processBlock.NewShardProcessor(args)
					require.NoError(t, e)
					b, _, e := sp.CreateMiniBlocks(func() bool { return true })
					body = b
					err = e
				}
				require.Equal(t, 1, coordinator.calls, "reach actual native outgoing-body consumer")
				if failure == nil {
					require.NoError(t, err)
					require.NotNil(t, body)
					return
				}
				require.Same(t, failure, err)
				require.Nil(t, body, "no candidate body returned after fatal context")
				if shape == "joined" {
					require.ErrorIs(t, err, original)
					require.ErrorIs(t, err, rollback)
				}
			})
		}
	}
}
