package block_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-go/process"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/state"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualDRWAStatusVM struct {
	*mock.VMExecutionHandlerStub
	failure error
}

func (v *qualDRWAStatusVM) DRWAExecutionError() error { return v.failure }

// DS02-M6/M7, P-05: a native owner cannot forget its existing VM failure at the
// next entry/commit. These malformed-input controls prove error precedence;
// they do not prove reconstruction, successful commit or exclusive ownership.
// Inherited constructors and the have-time duration are experimental fixtures,
// replace or confirm before testnet admission (R7).
func TestQualDRWAVMStatusBlockEntries(t *testing.T) {
	entries := []struct {
		name string
		call func(process.BlockProcessor) error
	}{
		{"process", func(p process.BlockProcessor) error {
			return p.ProcessBlock(nil, nil, func() time.Duration { return time.Second })
		}},
		{"create", func(p process.BlockProcessor) error {
			_, _, err := p.CreateBlock(nil, func() bool { return true })
			return err
		}},
		{"commit", func(p process.BlockProcessor) error { return p.CommitBlock(nil, nil) }},
		{"process_proposal", func(p process.BlockProcessor) error { _, err := p.ProcessBlockProposal(nil, nil, nil); return err }},
		{"create_proposal", func(p process.BlockProcessor) error {
			_, _, err := p.CreateBlockProposal(nil, func() bool { return true })
			return err
		}},
		{"commit_proposal", func(p process.BlockProcessor) error { return p.CommitBlockProposalState(nil, nil) }},
		{"scheduled", func(p process.BlockProcessor) error {
			return p.ProcessScheduledBlock(nil, nil, func() time.Duration { return time.Second })
		}},
	}
	for _, chain := range []string{"meta", "shard"} {
		for _, entry := range entries {
			for _, shape := range []string{"marker", "wrapped", "joined", "ordinary", "healthy"} {
				t.Run(chain+"/"+entry.name+"/"+shape, func(t *testing.T) {
					rollback := errors.New("experimental rollback failure")
					failure := vm.ErrDRWAExecution
					switch shape {
					case "wrapped":
						failure = fmt.Errorf("experimental context: %w", failure)
					case "joined":
						failure = errors.Join(failure, rollback)
					case "ordinary":
						failure = errors.New(failure.Error())
					case "healthy":
						failure = nil
					}
					statusVM := &qualDRWAStatusVM{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}, failure: failure}
					container := &mock.VMContainerMock{GetCalled: func(key []byte) (vmcommon.VMExecutionHandler, error) {
						require.Equal(t, factory.SystemVirtualMachine, key)
						return statusVM, nil
					}}
					var processor process.BlockProcessor
					var err error
					if chain == "meta" {
						args := createMockMetaArguments(createMockComponentHolders())
						args.VmContainer = container
						processor, err = processBlock.NewMetaProcessor(args)
					} else {
						args := CreateMockArgumentsMultiShard(createMockComponentHolders())
						args.VmContainer = container
						processor, err = processBlock.NewShardProcessor(args)
					}
					require.NoError(t, err)
					err = entry.call(processor)
					if shape == "ordinary" || shape == "healthy" {
						require.ErrorIs(t, err, process.ErrNilBlockHeader)
						require.NotErrorIs(t, err, vm.ErrDRWAExecution)
					} else {
						require.Same(t, failure, err)
						if shape == "joined" {
							require.ErrorIs(t, err, rollback)
						}
					}
				})
			}
		}
	}
}

// DS02-M7 on the actual native commit routine with valid header types and
// ordinary successful-commit controls. Account stores are dependency spies;
// there is no canonical root/restart or independently admitted candidate here.
func TestQualDRWAVMStatusCommitPublication(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		for _, shape := range []string{"marker", "wrapped", "joined", "ordinary", "healthy"} {
			t.Run(chain+"/"+shape, func(t *testing.T) {
				failure := vm.ErrDRWAExecution
				switch shape {
				case "wrapped":
					failure = fmt.Errorf("experimental context: %w", failure)
				case "joined":
					failure = errors.Join(failure, errors.New("experimental rollback failure"))
				case "ordinary":
					failure = errors.New(failure.Error())
				case "healthy":
					failure = nil
				}
				statusVM := &qualDRWAStatusVM{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}, failure: failure}
				container := &mock.VMContainerMock{GetCalled: func(key []byte) (vmcommon.VMExecutionHandler, error) {
					require.Equal(t, factory.SystemVirtualMachine, key)
					return statusVM, nil
				}}
				commits := 0
				accounts := &stateMock.AccountsStub{CommitCalled: func() ([]byte, error) { commits++; return nil, nil }}
				stores := map[state.AccountsDbIdentifier]state.AccountsAdapter{state.UserAccountsState: accounts}
				var processor process.BlockProcessor
				var header data.HeaderHandler
				var err error
				if chain == "meta" {
					args := createMockMetaArguments(createMockComponentHolders())
					stores[state.PeerAccountsState] = accounts
					args.AccountsDB, args.VmContainer = stores, container
					processor, err = processBlock.NewMetaProcessor(args)
					header = &block.MetaBlockV3{}
				} else {
					args := CreateMockArgumentsMultiShard(createMockComponentHolders())
					args.AccountsDB, args.VmContainer = stores, container
					processor, err = processBlock.NewShardProcessor(args)
					header = &block.HeaderV3{}
				}
				require.NoError(t, err)
				err = processor.CommitBlockProposalState(header, nil)
				if shape == "ordinary" || shape == "healthy" {
					require.NoError(t, err)
					require.Equal(t, len(stores), commits, "ordinary native commit remains reachable")
				} else {
					require.Same(t, failure, err)
					require.Zero(t, commits, "no store persistence after retained VM failure")
				}
			})
		}
	}
}
