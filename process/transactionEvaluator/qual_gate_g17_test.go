package transactionEvaluator

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	stateAccounts "github.com/multiversx/mx-chain-go/state/accounts"
	"github.com/multiversx/mx-chain-go/testscommon"
	stateMock "github.com/multiversx/mx-chain-go/testscommon/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualGateG17EvaluatorSimulatorCleanup(t *testing.T) {
	for _, stage := range []string{"success", "header", "processor", "intermediate"} {
		t.Run(stage, func(t *testing.T) {
			writes, logsCleaned, executions := 0, 0, 0
			underlying := &stateMock.AccountsStub{
				GetExistingAccountCalled:              func(address []byte) (vmcommon.AccountHandler, error) { return stateAccounts.NewPeerAccount(address) },
				SaveAccountCalled:                     func(vmcommon.AccountHandler) error { writes++; return nil },
				SetTxHashForLatestStateAccessesCalled: func([]byte) { writes++ },
			}
			user, err := NewSimulationAccountsDB(underlying)
			require.NoError(t, err)
			peer, err := NewSimulationAccountsDB(underlying)
			require.NoError(t, err)
			for _, adapter := range []*simulationAccountsDB{user, peer} {
				account, readErr := adapter.GetExistingAccount([]byte("cached"))
				require.NoError(t, readErr)
				require.NoError(t, adapter.SaveAccount(account))
				adapter.SetTxHashForLatestStateAccesses([]byte("simulation"))
			}
			sentinel := errors.New("injected " + stage)
			var simulator *transactionSimulator
			var evaluator *apiTransactionEvaluator
			simArgs := getTxSimulatorArgs()
			simArgs.TxLogsProcessor = &mock.TxLogsProcessorStub{CleanCalled: func() { logsCleaned++ }}
			simArgs.BlockChainHook = &testscommon.BlockChainHookStub{SetCurrentHeaderCalled: func(header data.HeaderHandler) error {
				require.Equal(t, uint64(17), header.GetNonce())
				if stage == "header" {
					return sentinel
				}
				return nil
			}}
			simArgs.TransactionProcessor = &testscommon.TxProcessorStub{ProcessTransactionCalled: func(*transaction.Transaction) (vmcommon.ReturnCode, error) {
				if simulator.mutOperation.TryLock() {
					simulator.mutOperation.Unlock()
					t.Fatal("simulator operation lock not held at processor entry")
				}
				if evaluator.mutExecution.TryLock() {
					evaluator.mutExecution.Unlock()
					t.Fatal("evaluator operation lock not held at simulator entry")
				}
				executions++
				if stage == "processor" {
					return vmcommon.UserError, sentinel
				}
				return vmcommon.Ok, nil
			}}
			if stage == "intermediate" {
				simArgs.IntermediateProcContainer = &mock.IntermProcessorContainerStub{GetCalled: func(block.Type) (process.IntermediateTransactionHandler, error) { return nil, sentinel }}
			}
			simulator, err = NewTransactionSimulator(simArgs)
			require.NoError(t, err)
			args := createArgs()
			args.Accounts, args.PeerAccounts, args.TxSimulator = user, peer, simulator
			args.ShardCoordinator = &mock.ShardCoordinatorStub{SelfIdCalled: func() uint32 { return core.MetachainShardId }}
			require.NoError(t, args.BlockChain.SetCurrentBlockHeaderAndRootHash(&block.Header{Nonce: 17}, []byte("root")))
			evaluator, err = NewAPITransactionEvaluator(args)
			require.NoError(t, err)
			result, err := evaluator.SimulateTransactionExecution(&transaction.Transaction{Nonce: 3})
			if stage == "header" || stage == "intermediate" {
				require.ErrorIs(t, err, sentinel)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if stage == "processor" {
					require.Equal(t, transaction.TxStatusFail, result.Status)
					require.Equal(t, sentinel.Error(), result.FailReason)
				} else {
					require.Equal(t, transaction.TxStatusSuccess, result.Status)
				}
			}
			require.Empty(t, user.cachedAccounts)
			require.Empty(t, peer.cachedAccounts)
			require.Zero(t, writes)
			require.Equal(t, 1, logsCleaned)
			if stage == "header" {
				require.Zero(t, executions)
			} else {
				require.Equal(t, 1, executions)
			}
		})
	}
}
