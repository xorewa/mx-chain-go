package block_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/coordinator"
	"github.com/multiversx/mx-chain-go/process/factory/containers"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon/preprocMocks"
	"github.com/multiversx/mx-chain-go/vm"
	"github.com/stretchr/testify/require"
)

// Experimental dependency faults and miniblock coordinates. This composes the
// real coordinator and native body producers; it does not admit a preprocessor,
// factory, native VM, candidate rollback, restart or real-network execution.
func TestQualGateG25CoordinatorBlockComposition(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		for _, shape := range []string{"marker", "wrapped", "joined", "ordinary", "success"} {
			t.Run(chain+"/"+shape, func(t *testing.T) {
				failure := vm.ErrDRWAExecution
				original := errors.New("experimental native failure")
				rollback := errors.New("experimental rollback failure")
				switch shape {
				case "wrapped":
					failure = fmt.Errorf("experimental context: %w", failure)
				case "joined":
					failure = errors.Join(failure, original, rollback)
				case "ordinary":
					failure = errors.New(failure.Error())
				case "success":
					failure = nil
				}
				events := []string{}
				pre := containers.NewPreProcessorsContainer()
				for idx, typ := range []block.Type{block.TxBlock, block.SmartContractResultBlock, block.RewardsBlock} {
					name := []string{"before", "fault", "after"}[idx]
					require.NoError(t, pre.Add(typ, &preprocMocks.PreProcessorMock{
						CreateAndProcessMiniBlocksCalled: func(func() bool) (block.MiniBlockSlice, error) {
							events = append(events, name)
							mbs := block.MiniBlockSlice{&block.MiniBlock{Type: typ, TxHashes: [][]byte{[]byte(name)}}}
							if name == "fault" {
								return mbs, failure
							}
							return mbs, nil
						},
					}))
				}
				core, data, boot, status := createComponentHolderMocks()
				var body interface{}
				var err error
				if chain == "meta" {
					args := createMockMetaArguments(core, data, boot, status)
					tc, e := coordinator.NewTransactionCoordinator(createMockTransactionCoordinatorArguments(args.AccountsDB[state.UserAccountsState], data.DataPool, pre, pre))
					require.NoError(t, e)
					args.TxCoordinator = tc
					mp, e := processBlock.NewMetaProcessor(args)
					require.NoError(t, e)
					body, err = mp.CreateBlockBody(&block.MetaBlock{}, func() bool { return true })
				} else {
					args := CreateMockArgumentsMultiShard(core, data, boot, status)
					tc, e := coordinator.NewTransactionCoordinator(createMockTransactionCoordinatorArguments(args.AccountsDB[state.UserAccountsState], data.DataPool, pre, pre))
					require.NoError(t, e)
					args.TxCoordinator = tc
					sp, e := processBlock.NewShardProcessor(args)
					require.NoError(t, e)
					body, _, err = sp.CreateMiniBlocks(func() bool { return true })
				}
				if shape == "ordinary" || shape == "success" {
					require.NoError(t, err)
					require.Equal(t, []string{"before", "fault", "after"}, events)
					require.NotNil(t, body)
					miniblocks := body.(*block.Body).MiniBlocks
					require.Len(t, miniblocks, 3)
					for idx, name := range events {
						require.Equal(t, [][]byte{[]byte(name)}, miniblocks[idx].TxHashes)
					}
					return
				}
				require.Same(t, failure, err)
				require.Nil(t, body, "withhold prior and partial miniblocks at the real body boundary")
				require.Equal(t, []string{"before", "fault"}, events)
				if shape == "joined" {
					require.ErrorIs(t, err, original)
					require.ErrorIs(t, err, rollback)
				}
			})
		}
	}
}
