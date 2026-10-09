package transactionEvaluator

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/smartContractResult"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	converterFactory "github.com/multiversx/mx-chain-go/common/factory"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/common/holders"
	nativeFactory "github.com/multiversx/mx-chain-go/factory"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/mock"
	txSimData "github.com/multiversx/mx-chain-go/process/transactionEvaluator/data"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	nativeFixture "github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// T09 M22 tests the real adapter/evaluator/native trie. The simulated processor
// is explicitly a double that writes ONLY through the supplied wrapper. This
// proves no actual VM/builtin/transaction effect or whole-factory API isolation.
func TestQualDRWACandidateSimulationTrieIsolation(t *testing.T) {
	candidate := filepath.Join("..", "..", "..", "..", "evidence", "sp1_t09_configuration_candidate_03")
	cfg, err := common.LoadMainConfig(filepath.Join(candidate, "config.toml"))
	require.NoError(t, err)
	epochCfg, err := common.LoadEpochConfig(filepath.Join(candidate, "enableEpochs.toml"))
	require.NoError(t, err)
	converter, err := converterFactory.NewPubkeyConverter(cfg.AddressPubkeyConverter)
	require.NoError(t, err)
	crawlers, err := nativeFactory.DecodeAddresses(converter, cfg.BuiltInFunctions.AutomaticCrawlerAddresses)
	require.NoError(t, err)
	require.Len(t, crawlers, 3)
	notifier := forking.NewGenericEpochNotifier()
	epochs, err := enablers.NewEnableEpochsHandler(epochCfg.EnableEpochs, notifier)
	require.NoError(t, err)
	header := &block.Header{Epoch: 3, Round: 440}
	notifier.CheckEpoch(header)
	// Inert protected sentinel, not an admission/holder/registry record or codec.
	key := []byte(core.ProtectedKeyPrefix + "DRWA@simulation@inertFixture")
	original, changed := []byte("original sentinel"), []byte("simulation-only sentinel")
	missing := bytes.Repeat([]byte{0x88}, 32)
	for shardID, crawler := range crawlers {
		for _, route := range []string{"transaction", "transaction-cost", "scr-cost"} {
			for _, outcome := range []string{"healthy", "processor-error", "vm-denial"} {
				t.Run(fmt.Sprintf("shard_%d/%s/%s", shardID, route, outcome), func(t *testing.T) {
					store := nativeFixture.CreateAccountsDB(nativeFixture.CreateMemUnit(), epochs)
					require.NotNil(t, store)
					t.Cleanup(func() { require.NoError(t, store.Close()) })
					addresses := [][]byte{crawler, core.SystemAccountAddress}
					for _, address := range addresses {
						a, err := store.LoadAccount(address)
						require.NoError(t, err)
						u := a.(state.UserAccountHandler)
						u.IncreaseNonce(7)
						require.NoError(t, u.AddToBalance(big.NewInt(100)))
						require.NoError(t, u.SaveKeyValue(key, original))
						require.NoError(t, store.SaveAccount(u))
					}
					root, err := store.Commit()
					require.NoError(t, err)
					require.Zero(t, store.JournalLen())
					wrapped, err := NewSimulationAccountsDB(store)
					require.NoError(t, err)
					fault := errors.New("declared simulated processor error")
					calls := 0
					simulate := func() (*txSimData.SimulationResultsWithVMOutput, error) {
						calls++
						for _, address := range addresses {
							a, err := wrapped.LoadAccount(address)
							require.NoError(t, err)
							u := a.(state.UserAccountHandler)
							require.Equal(t, uint64(7), u.GetNonce(), "previous request must not leak")
							require.Equal(t, big.NewInt(100), u.GetBalance())
							value, _, err := u.RetrieveValue(key)
							require.NoError(t, err)
							require.Equal(t, original, value)
							u.IncreaseNonce(1)
							require.NoError(t, u.AddToBalance(big.NewInt(1)))
							require.NoError(t, u.SaveKeyValue(key, changed))
							require.NoError(t, wrapped.SaveAccount(u))
							cached, err := wrapped.GetExistingAccount(address)
							require.NoError(t, err)
							require.Equal(t, uint64(8), cached.GetNonce())
							require.NoError(t, wrapped.RemoveAccount(address))
						}
						created, err := wrapped.LoadAccount(missing)
						require.NoError(t, err)
						created.IncreaseNonce(1)
						require.NoError(t, wrapped.SaveAccount(created))
						_, err = wrapped.Commit()
						require.NoError(t, err)
						_, err = wrapped.CommitInEpoch(3, 3)
						require.NoError(t, err)
						require.NoError(t, wrapped.RevertToSnapshot(0))
						unselectedRoot := holders.NewDefaultRootHashesHolder(bytes.Repeat([]byte{0x99}, 32))
						require.NoError(t, wrapped.RecreateTrie(unselectedRoot))
						require.NoError(t, wrapped.RecreateTrieIfNeeded(unselectedRoot))
						actualRoot, err := store.RootHash()
						require.NoError(t, err)
						require.Equal(t, root, actualRoot)
						require.Zero(t, store.JournalLen())
						if outcome == "processor-error" {
							return nil, fault
						}
						code := vmcommon.Ok
						if outcome == "vm-denial" {
							code = vmcommon.UserError
						}
						return &txSimData.SimulationResultsWithVMOutput{VMOutput: &vmcommon.VMOutput{
							ReturnCode: code, GasRemaining: 0, ReturnMessage: "declared simulator double"}}, nil
					}
					args := createArgs()
					args.Accounts, args.EnableEpochsHandler = wrapped, epochs
					args.ShardCoordinator, err = sharding.NewMultiShardCoordinator(3, uint32(shardID))
					require.NoError(t, err)
					args.BlockChain = &testscommon.ChainHandlerStub{GetCurrentBlockHeaderCalled: func() data.HeaderHandler { return header }}
					args.TxTypeHandler = &testscommon.TxTypeHandlerMock{ComputeTransactionTypeCalled: func(data.TransactionHandler) (process.TransactionType, process.TransactionType, bool) {
						return process.BuiltInFunctionCall, process.BuiltInFunctionCall, false
					}}
					args.TxSimulator = &mock.TransactionSimulatorStub{
						ProcessTxCalled: func(*transaction.Transaction, data.HeaderHandler) (*txSimData.SimulationResultsWithVMOutput, error) {
							return simulate()
						},
						ProcessSCRCalled: func(*smartContractResult.SmartContractResult, data.HeaderHandler) (*txSimData.SimulationResultsWithVMOutput, error) {
							return simulate()
						},
					}
					evaluator, err := NewAPITransactionEvaluator(args)
					require.NoError(t, err)
					for request := 0; request < 2; request++ {
						if route == "transaction" {
							_, err = evaluator.SimulateTransactionExecution(&transaction.Transaction{SndAddr: crawler, RcvAddr: crawler, Value: big.NewInt(0), GasLimit: 1})
							if outcome == "processor-error" {
								require.ErrorIs(t, err, fault)
							} else {
								require.NoError(t, err)
							}
						} else {
							var response *transaction.CostResponse
							if route == "scr-cost" {
								response, err = evaluator.SimulateSCRExecutionCost(&smartContractResult.SmartContractResult{SndAddr: crawler, RcvAddr: crawler, Value: big.NewInt(0), GasLimit: 1})
							} else {
								response, err = evaluator.ComputeTransactionGasLimit(&transaction.Transaction{SndAddr: crawler, RcvAddr: crawler, Value: big.NewInt(0), GasLimit: 1, GasPrice: 1, Signature: []byte{1}})
							}
							require.NoError(t, err)
							if outcome != "healthy" {
								require.NotEmpty(t, response.ReturnMessage)
							}
						}
						_, err = wrapped.GetExistingAccount(missing)
						require.ErrorIs(t, err, state.ErrAccNotFound, "request-local creation must be discarded")
						for _, address := range addresses {
							a, err := wrapped.GetExistingAccount(address)
							require.NoError(t, err)
							u := a.(state.UserAccountHandler)
							require.Equal(t, uint64(7), u.GetNonce())
							require.Equal(t, big.NewInt(100), u.GetBalance())
							value, _, err := u.RetrieveValue(key)
							require.NoError(t, err)
							require.Equal(t, original, value)
						}
						actualRoot, err := store.RootHash()
						require.NoError(t, err)
						require.Equal(t, root, actualRoot)
						require.Zero(t, store.JournalLen())
					}
					require.Equal(t, 2, calls)
				})
			}
		}
	}
}
