package block_test

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/endProcess"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/dataRetriever/blockchain"
	"github.com/multiversx/mx-chain-go/process"
	processBlock "github.com/multiversx/mx-chain-go/process/block"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/mock"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmFactory "github.com/multiversx/mx-chain-go/vm/factory"
	vmMock "github.com/multiversx/mx-chain-go/vm/mock"
	vmProcess "github.com/multiversx/mx-chain-go/vm/process"
	"github.com/multiversx/mx-chain-go/vm/systemSmartContracts"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/parsers"
	"github.com/stretchr/testify/require"
)

type qualDRWAStatusVM struct {
	*mock.VMExecutionHandlerStub
	failure error
}

func (v *qualDRWAStatusVM) DRWAExecutionError() error { return v.failure }

type qualDRWAStopCore struct {
	*mock.CoreComponentsMock
	channel chan endProcess.ArgEndProcess
	reads   *atomic.Int64
}

func (c *qualDRWAStopCore) ChanStopNodeProcess() chan endProcess.ArgEndProcess {
	c.reads.Add(1)
	return c.channel
}

func qualDRWAObserveStop(args *processBlock.ArgBaseProcessor, channel chan endProcess.ArgEndProcess, reads *atomic.Int64) {
	args.CoreComponents = &qualDRWAStopCore{
		CoreComponentsMock: args.CoreComponents.(*mock.CoreComponentsMock), channel: channel, reads: reads,
	}
}

func qualDRWAAssertStop(t *testing.T, channel chan endProcess.ArgEndProcess, poison bool) {
	t.Helper()
	if !poison {
		require.Empty(t, channel, "ordinary status must not request node shutdown")
		return
	}
	select {
	case request := <-channel:
		// Owner-authorized experimental reason; literal is independent of the
		// production constant and also compiles against the pre-change source.
		require.Equal(t, "drwaExecutionFailure", request.Reason)
		require.Equal(t, vm.ErrDRWAExecution.Error(), request.Description)
	default:
		t.Fatal("retained DRWA poison did not request native shutdown")
	}
}

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
					stop := make(chan endProcess.ArgEndProcess, 1)
					var stopReads atomic.Int64
					if chain == "meta" {
						args := createMockMetaArguments(createMockComponentHolders())
						args.VmContainer = container
						qualDRWAObserveStop(&args.ArgBaseProcessor, stop, &stopReads)
						processor, err = processBlock.NewMetaProcessor(args)
					} else {
						args := CreateMockArgumentsMultiShard(createMockComponentHolders())
						args.VmContainer = container
						qualDRWAObserveStop(&args.ArgBaseProcessor, stop, &stopReads)
						processor, err = processBlock.NewShardProcessor(args)
					}
					require.NoError(t, err)
					require.Zero(t, stopReads.Load(), "construction must not query the stop channel")
					err = entry.call(processor)
					if shape == "ordinary" || shape == "healthy" {
						require.ErrorIs(t, err, process.ErrNilBlockHeader)
						require.NotErrorIs(t, err, vm.ErrDRWAExecution)
						require.Zero(t, stopReads.Load())
					} else {
						require.Same(t, failure, err)
						if shape == "joined" {
							require.ErrorIs(t, err, rollback)
						}
					}
					qualDRWAAssertStop(t, stop, shape != "ordinary" && shape != "healthy")
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
				stop := make(chan endProcess.ArgEndProcess, 1)
				var stopReads atomic.Int64
				if chain == "meta" {
					args := createMockMetaArguments(createMockComponentHolders())
					stores[state.PeerAccountsState] = accounts
					args.AccountsDB, args.VmContainer = stores, container
					qualDRWAObserveStop(&args.ArgBaseProcessor, stop, &stopReads)
					processor, err = processBlock.NewMetaProcessor(args)
					header = &block.MetaBlockV3{}
				} else {
					args := CreateMockArgumentsMultiShard(createMockComponentHolders())
					args.AccountsDB, args.VmContainer = stores, container
					qualDRWAObserveStop(&args.ArgBaseProcessor, stop, &stopReads)
					processor, err = processBlock.NewShardProcessor(args)
					header = &block.HeaderV3{}
				}
				require.NoError(t, err)
				require.Zero(t, stopReads.Load(), "construction must not query the stop channel")
				err = processor.CommitBlockProposalState(header, nil)
				if shape == "ordinary" || shape == "healthy" {
					require.NoError(t, err)
					require.Equal(t, len(stores), commits, "ordinary native commit remains reachable")
					require.Zero(t, stopReads.Load())
				} else {
					require.Same(t, failure, err)
					require.Zero(t, commits, "no store persistence after retained VM failure")
				}
				qualDRWAAssertStop(t, stop, shape != "ordinary" && shape != "healthy")
			})
		}
	}
}

// Shadowing the optional method with a field preserves the inherited required
// holder methods while exercising a native holder without a stop capability.
type qualDRWANoStopCore struct {
	*mock.CoreComponentsMock
	ChanStopNodeProcess struct{}
}

func qualDRWAStopProcessor(t *testing.T, chain string, runtime vmcommon.VMExecutionHandler,
	channel chan endProcess.ArgEndProcess, reads *atomic.Int64, absent bool,
) (process.BlockProcessor, data.HeaderHandler, *atomic.Int64) {
	t.Helper()
	commits := &atomic.Int64{}
	accounts := &stateMock.AccountsStub{CommitCalled: func() ([]byte, error) { commits.Add(1); return nil, nil }}
	stores := map[state.AccountsDbIdentifier]state.AccountsAdapter{state.UserAccountsState: accounts}
	container := &mock.VMContainerMock{GetCalled: func(_ []byte) (vmcommon.VMExecutionHandler, error) { return runtime, nil }}
	attach := func(args *processBlock.ArgBaseProcessor) {
		args.AccountsDB, args.VmContainer = stores, container
		if absent {
			args.CoreComponents = &qualDRWANoStopCore{CoreComponentsMock: args.CoreComponents.(*mock.CoreComponentsMock)}
		} else {
			qualDRWAObserveStop(args, channel, reads)
		}
	}
	var processor process.BlockProcessor
	var header data.HeaderHandler
	var err error
	if chain == "meta" {
		args := createMockMetaArguments(createMockComponentHolders())
		stores[state.PeerAccountsState] = accounts
		attach(&args.ArgBaseProcessor)
		processor, err = processBlock.NewMetaProcessor(args)
		header = &block.MetaBlockV3{}
	} else {
		args := CreateMockArgumentsMultiShard(createMockComponentHolders())
		attach(&args.ArgBaseProcessor)
		processor, err = processBlock.NewShardProcessor(args)
		header = &block.HeaderV3{}
	}
	require.NoError(t, err)
	require.Zero(t, reads.Load(), "construction must not query the stop channel")
	return processor, header, commits
}

// The native channel is receiver-owned. A missing capability or unavailable
// endpoint cannot unblock publication, erase diagnostics or stall the caller.
// Channel capacities, repetitions and concurrent callers are R7 fixtures.
func TestQualDRWANativeStopUnavailable(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		for _, endpoint := range []string{"available", "absent", "nil", "full", "unbuffered"} {
			t.Run(chain+"/"+endpoint, func(t *testing.T) {
				original, rollback := errors.New("experimental original failure"), errors.New("experimental rollback failure")
				failure := errors.Join(vm.ErrDRWAExecution, original, rollback)
				runtime := &qualDRWAStatusVM{VMExecutionHandlerStub: &mock.VMExecutionHandlerStub{}, failure: failure}
				channel := make(chan endProcess.ArgEndProcess, 1)
				switch endpoint {
				case "nil":
					channel = nil
				case "full":
					channel <- endProcess.ArgEndProcess{}
				case "unbuffered":
					channel = make(chan endProcess.ArgEndProcess)
				}
				var reads atomic.Int64
				processor, header, commits := qualDRWAStopProcessor(t, chain, runtime, channel, &reads, endpoint == "absent")
				for range 2 {
					err := processor.ProcessBlock(nil, nil, func() time.Duration { return time.Second })
					require.Same(t, failure, err)
					require.ErrorIs(t, err, original)
					require.ErrorIs(t, err, rollback)
					require.Same(t, failure, processor.CommitBlockProposalState(header, nil))
				}
				var callers sync.WaitGroup
				results := make(chan error, 2)
				for range 2 {
					callers.Go(func() {
						results <- processor.ProcessBlock(nil, nil, func() time.Duration { return time.Second })
					})
				}
				callers.Wait()
				for range 2 {
					require.Same(t, failure, <-results)
				}
				require.Zero(t, commits.Load())
				require.Same(t, failure, runtime.DRWAExecutionError())
				switch endpoint {
				case "available":
					qualDRWAAssertStop(t, channel, true)
				case "full":
					require.Equal(t, endProcess.ArgEndProcess{}, <-channel, "do not overwrite an existing native request")
				default:
					require.Empty(t, channel)
				}
				if endpoint == "absent" {
					require.Zero(t, reads.Load())
				} else {
					require.Positive(t, reads.Load())
				}
			})
		}
	}
}

type qualDRWAStopClassifier struct{ failure error }

func (c *qualDRWAStopClassifier) ValidateAccounts(state.AccountsAdapter, state.AccountsAdapter) error {
	return nil
}
func (c *qualDRWAStopClassifier) WithTokenClassification(state.AccountsAdapter, []byte,
	func(bool) (*vmcommon.VMOutput, error),
) (*vmcommon.VMOutput, error) {
	return nil, c.failure
}
func (c *qualDRWAStopClassifier) IsInterfaceNil() bool { return c == nil }

// Exercise the real native VM and VMContext latch before the block consumer.
// Classification and account dependencies are spies: this does not establish
// canonical owner admission, real rollback/reconstruction or node shutdown.
func TestQualDRWANativeStopVMContext(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		t.Run(chain, func(t *testing.T) {
			original, rollback := errors.New("experimental original failure"), errors.New("experimental rollback failure")
			accounts := &stateMock.AccountsStub{}
			ctx, err := systemSmartContracts.NewVMContext(systemSmartContracts.VMContextArgs{
				DRWAClassifier: &qualDRWAStopClassifier{failure: errors.Join(original, rollback)},
				BlockChainHook: &vmMock.BlockChainHookStub{}, CryptoHook: hooks.NewVMCryptoHook(),
				InputParser: parsers.NewCallArgsParser(), UserAccountsDB: accounts, ValidatorAccountsDB: accounts,
				ChanceComputer: &vmMock.RaterMock{}, EnableEpochsHandler: enableEpochsHandlerMock.NewEnableEpochsHandlerStub(),
			})
			require.NoError(t, err)
			contracts := vmFactory.NewSystemSCContainer()
			require.NoError(t, ctx.SetSystemSCContainer(contracts))
			runtime, err := vmProcess.NewSystemVM(vmProcess.ArgsNewSystemVM{
				SystemEI: ctx, SystemContracts: contracts, VmType: factory.SystemVirtualMachine,
				GasSchedule: testscommon.NewGasScheduleNotifierMock(map[string]map[string]uint64{
					"BaseOpsAPICost": {"AsyncCallStep": 1000, "AsyncCallbackGasLock": 3000},
				}),
			})
			require.NoError(t, err)
			require.NoError(t, runtime.DRWAExecutionError())
			channel := make(chan endProcess.ArgEndProcess, 1)
			var reads atomic.Int64
			processor, header, commits := qualDRWAStopProcessor(t, chain, runtime, channel, &reads, false)
			output, failure := runtime.RunSmartContractCall(&vmcommon.ContractCallInput{
				RecipientAddr: core.ESDTSCAddress, Function: "pause",
				VMInput: vmcommon.VMInput{Arguments: [][]byte{[]byte("TOKEN-abcdef")}},
			})
			require.Nil(t, output)
			require.ErrorIs(t, failure, vm.ErrDRWAExecution)
			require.ErrorIs(t, failure, original)
			require.ErrorIs(t, failure, rollback)
			ctx.CleanCache()
			require.Same(t, failure, runtime.DRWAExecutionError())
			require.Same(t, failure, processor.ProcessBlock(nil, nil, func() time.Duration { return time.Second }))
			qualDRWAAssertStop(t, channel, true)
			require.Same(t, failure, processor.CommitBlockProposalState(header, nil))
			qualDRWAAssertStop(t, channel, true)
			require.Same(t, failure, runtime.DRWAExecutionError())
			require.Zero(t, commits.Load())
		})
	}
}

// P-05: compose the native context selector with the existing containment owner.
// Native chain objects select the boundary; account adapters are spies. This
// does not admit a canonical candidate, retain physical trie nodes, reconstruct
// a VM or establish native factory/scheduler ownership. R7 records all fixtures.
func TestQualDRWANativeSelectedRootsContainment(t *testing.T) {
	for _, chain := range []string{"meta", "shard"} {
		for _, version := range []string{"legacy", "v3"} {
			for _, relationship := range []string{"aligned", "mismatched"} {
				t.Run(chain+"/"+version+"/"+relationship, func(t *testing.T) {
					coreComponents, dataComponents, bootstrapComponents, statusComponents := createMockComponentHolders()
					userRoot, peerHeaderRoot, peerResultRoot := []byte("rootHash"), []byte("peerRootHash"), []byte("peerRootHashX")
					expected := [][]byte{userRoot}
					if chain == "meta" {
						peerRoot := peerHeaderRoot
						if version == "v3" {
							peerRoot = peerResultRoot
						}
						expected = append(expected, peerRoot)
					}
					original, rollback := errors.New("experimental original failure"), errors.New("experimental rollback failure")
					adapters := make([]state.AccountsAdapter, len(expected))
					recreated := make([][][]byte, len(expected))
					commits := 0
					for i, selected := range expected {
						root := bytes.Clone(selected)
						if relationship == "mismatched" {
							root = []byte("rootHashX")
						}
						adapters[i] = &stateMock.AccountsStub{
							RootHashCalled:   func() ([]byte, error) { return bytes.Clone(root), nil },
							JournalLenCalled: func() int { return 0 },
							RecreateTrieCalled: func(options common.RootHashHolder) error {
								root = bytes.Clone(options.GetRootHash())
								recreated[i] = append(recreated[i], bytes.Clone(root))
								return nil
							},
							RevertToSnapshotCalled: func(int) error { return rollback },
							CommitCalled:           func() ([]byte, error) { commits++; return nil, nil },
						}
					}
					stores := map[state.AccountsDbIdentifier]state.AccountsAdapter{state.UserAccountsState: adapters[0]}
					baseResult := &block.BaseExecutionResult{HeaderNonce: 1, HeaderHash: []byte("hash1"), RootHash: userRoot}
					var candidate data.HeaderHandler
					var checkContext func(data.HeaderHandler, []byte) error
					if chain == "meta" {
						nativeChain, err := blockchain.NewMetaChain(coreComponents.StatusField)
						require.NoError(t, err)
						require.NoError(t, nativeChain.SetGenesisHeader(&block.MetaBlock{}))
						var previous data.HeaderHandler = &block.MetaBlock{Nonce: 1, ValidatorStatsRootHash: peerHeaderRoot}
						candidate = &block.MetaBlock{Nonce: 2, PrevHash: []byte("hash1")}
						if version == "v3" {
							previous = &block.MetaBlockV3{Nonce: 1}
							candidate = &block.MetaBlockV3{Nonce: 2, PrevHash: []byte("hash1")}
						}
						nativeChain.SetLastExecutionInfo(previous, &block.MetaExecutionResult{
							ExecutionResult: &block.BaseMetaExecutionResult{
								BaseExecutionResult: baseResult, ValidatorStatsRootHash: peerResultRoot,
							},
						})
						dataComponents.BlockChain = nativeChain
						args := createMockMetaArguments(coreComponents, dataComponents, bootstrapComponents, statusComponents)
						stores[state.PeerAccountsState] = adapters[1]
						args.AccountsDB = stores
						processor, err := processBlock.NewMetaProcessor(args)
						require.NoError(t, err)
						checkContext = processor.CheckContextBeforeExecution
					} else {
						nativeChain, err := blockchain.NewBlockChain(coreComponents.StatusField)
						require.NoError(t, err)
						require.NoError(t, nativeChain.SetGenesisHeader(&block.Header{}))
						var previous data.HeaderHandler = &block.Header{Nonce: 1}
						candidate = &block.Header{Nonce: 2, PrevHash: []byte("hash1")}
						if version == "v3" {
							previous = &block.HeaderV3{Nonce: 1}
							candidate = &block.HeaderV3{Nonce: 2, PrevHash: []byte("hash1")}
						}
						nativeChain.SetLastExecutionInfo(previous, &block.ExecutionResult{BaseExecutionResult: baseResult})
						dataComponents.BlockChain = nativeChain
						args := CreateMockArgumentsMultiShard(coreComponents, dataComponents, bootstrapComponents, statusComponents)
						args.AccountsDB = stores
						processor, err := processBlock.NewShardProcessor(args)
						require.NoError(t, err)
						checkContext = processor.CheckContextBeforeExecution
					}
					require.NoError(t, checkContext(candidate, []byte("headerHash")))
					for i, selected := range expected {
						if relationship == "aligned" {
							require.Empty(t, recreated[i], "native equal-root selection skips recreation")
						} else {
							require.Equal(t, [][]byte{selected}, recreated[i])
						}
						recreated[i] = nil
					}
					owner, err := drwa.NewRollbackContainment(adapters...)
					require.NoError(t, err)
					err = owner.Execute(func() (*vmcommon.VMOutput, error) { return &vmcommon.VMOutput{}, original })
					require.ErrorIs(t, err, original)
					require.ErrorIs(t, err, rollback)
					roots, outputs, err := owner.Commit()
					require.ErrorIs(t, err, original)
					require.ErrorIs(t, err, rollback)
					require.Nil(t, roots)
					require.Nil(t, outputs)
					require.Zero(t, commits)
					require.NoError(t, owner.Recover())
					for i, selected := range expected {
						require.Equal(t, [][]byte{selected}, recreated[i], "recovery forces every selected root, even with equal roots and empty journals")
					}
					require.ErrorIs(t, owner.Execute(func() (*vmcommon.VMOutput, error) {
						t.Fatal("recovered owner must not resume execution")
						return nil, nil
					}), drwa.ErrExecutionClosed)
				})
			}
		}
	}
}
