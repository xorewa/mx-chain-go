package block_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

// DS02-M6/M7: inject at the existing incoming helper's first dependency to
// exercise its real body-producing caller. Coordinator injection is qualified
// separately; this is not a whole native recovery or classifier-admission proof.
// Inherited constructors and empty header/randomness are experimental fixtures;
// replace or confirm before testnet admission (R7).
func TestQualDRWAIncomingBlockBodyError(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		for _, shape := range []string{"marker", "wrapped", "joined", "ordinary", "success"} {
			t.Run(chain+"/"+shape, func(t *testing.T) {
				failure := vm.ErrDRWAExecution
				rollback := errors.New("experimental rollback failure")
				switch shape {
				case "wrapped":
					failure = fmt.Errorf("experimental context: %w", failure)
				case "joined":
					failure = errors.Join(failure, rollback)
				case "ordinary":
					failure = errors.New(failure.Error())
				case "success":
					failure = nil
				}
				incoming, outgoing := 0, 0
				coordinator := &testscommon.TransactionCoordinatorMock{CreateMbsAndProcessTransactionsFromMeCalled: func(func() bool) block.MiniBlockSlice { outgoing++; return nil }}
				tracker := &mock.BlockTrackerMock{
					ComputeLongestMetaChainFromLastNotarizedCalled: func() ([]data.HeaderHandler, [][]byte, error) { incoming++; return nil, nil, failure },
					ComputeLongestShardsChainsFromLastNotarizedCalled: func() ([]data.HeaderHandler, [][]byte, map[uint32][]data.HeaderHandler, error) {
						incoming++
						return nil, nil, nil, failure
					},
				}
				var body interface{}
				var err error
				if chain == "meta" {
					args := createMockMetaArguments(createMockComponentHolders())
					args.TxCoordinator, args.BlockTracker = coordinator, tracker
					mp, e := processBlock.NewMetaProcessor(args)
					require.NoError(t, e)
					body, err = mp.CreateBlockBody(&block.MetaBlock{}, func() bool { return true })
				} else {
					args := CreateMockArgumentsMultiShard(createMockComponentHolders())
					args.TxCoordinator, args.BlockTracker = coordinator, tracker
					sp, e := processBlock.NewShardProcessor(args)
					require.NoError(t, e)
					b, _, e := sp.CreateMiniBlocks(func() bool { return true })
					body, err = b, e
				}
				require.Equal(t, 1, incoming)
				if shape != "ordinary" && shape != "success" {
					require.Same(t, failure, err)
					require.Nil(t, body)
					require.Zero(t, outgoing, "no outgoing execution after incoming fatal marker")
					if shape == "joined" {
						require.ErrorIs(t, err, rollback)
					}
				} else {
					require.NoError(t, err)
					require.NotNil(t, body)
					require.Equal(t, 1, outgoing)
				}
			})
		}
	}
}
