package wasmer

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/common/forking"
	"github.com/multiversx/mx-chain-go/config"
	nodemock "github.com/multiversx/mx-chain-go/integrationTests/mock"
	nodevm "github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/process/block/postprocess"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/guardian"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/integrationtests"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	vmtest "github.com/multiversx/mx-chain-vm-go/testcommon"
	"github.com/multiversx/mx-chain-vm-go/vmhost"
	"github.com/stretchr/testify/require"
)

// The error is injected after the real DB has journalled and saved upgraded
// code. Only the owning SC processor performs rollback; the test never restores
// an account or snapshot. This is an in-process fixture, not network admission.
type qualG32Journal struct {
	state.AccountsAdapter
	target, upgradedHash   []byte
	fault                  error
	writes, journalAtWrite int
	reverts                []int
}

func (q *qualG32Journal) SaveAccount(account vmcommon.AccountHandler) error {
	if err := q.AccountsAdapter.SaveAccount(account); err != nil {
		return err
	}
	user, isUser := account.(state.UserAccountHandler)
	if q.fault != nil && isUser && bytes.Equal(user.AddressBytes(), q.target) && bytes.Equal(user.GetCodeHash(), q.upgradedHash) {
		q.writes++
		q.journalAtWrite = q.JournalLen()
		return q.fault
	}
	return nil
}

func (q *qualG32Journal) RevertToSnapshot(snapshot int) error {
	q.reverts = append(q.reverts, snapshot)
	return q.AccountsAdapter.RevertToSnapshot(snapshot)
}

func TestQualPartialsG32NativeUpgradeJournalRollback(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		name := "post_save_failure"
		if invalid {
			name = "invalid_native_code"
		}
		t.Run(name, func(t *testing.T) {
			codeA, err := os.ReadFile("../testdata/hello-v2/output/answer.wasm")
			require.NoError(t, err)
			codeB, err := os.ReadFile("../testdata/counter/output/counter.wasm")
			require.NoError(t, err)
			owner := bytes.Repeat([]byte{1}, 32)
			target := vmtest.MakeTestSCAddressWithVMType("journal-upgrade", factory.WasmVirtualMachine)
			db := integrationtests.CreateInMemoryShardAccountsDB()
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			accounts := &qualG32Journal{AccountsAdapter: db, target: target,
				upgradedHash: integrationtests.TestHasher.Compute(string(codeB))}
			_, err = nodevm.CreateAccount(accounts, owner, 0, big.NewInt(1000000000000))
			require.NoError(t, err)
			loaded, err := accounts.LoadAccount(target)
			require.NoError(t, err)
			contract := loaded.(state.UserAccountHandler)
			codeMetadata := vmcommon.CodeMetadata{Upgradeable: true, Readable: true, Payable: true}
			metadata := codeMetadata.ToBytes()
			contract.SetCode(codeA)
			contract.SetCodeMetadata(metadata)
			contract.SetOwnerAddress(owner)
			require.NoError(t, contract.AddToBalance(big.NewInt(17)))
			require.NoError(t, contract.SaveKeyValue([]byte("witness"), []byte("original")))
			require.NoError(t, accounts.SaveAccount(contract))
			_, err = accounts.Commit()
			require.NoError(t, err)
			originalHash := bytes.Clone(contract.GetCodeHash())

			locker := &sync.RWMutex{}
			epoch := forking.NewGenericEpochNotifier()
			cfg := config.EnableEpochs{}
			enabled, err := enablers.NewEnableEpochsHandler(cfg, epoch)
			require.NoError(t, err)
			guard, err := guardian.NewGuardedAccount(integrationtests.TestMarshalizer, epoch, nodevm.EpochGuardianDelay)
			require.NoError(t, err)
			chain := &testscommon.ChainHandlerStub{}
			coordinator := nodemock.NewMultiShardsCoordinatorMock(1)
			container, hook, pool := nodevm.CreateVMAndBlockchainHookAndDataPool(accounts, nil,
				nodevm.CreateVMConfigWithVersion("*"), coordinator, locker, epoch, enabled, chain, guard)
			t.Cleanup(func() {
				require.NoError(t, pool.Close())
				require.NoError(t, hook.Close())
				require.NoError(t, container.Close())
			})
			processors, err := nodevm.CreateTxProcessorWithOneSCExecutorWithVMs(accounts, container, hook,
				postprocess.NewFeeAccumulator(), coordinator, cfg, testscommon.GetDefaultRoundsConfig(),
				locker, pool, epoch, guard, forking.NewGenericRoundNotifier(), chain, 1)
			require.NoError(t, err)
			machine, err := container.Get(factory.WasmVirtualMachine)
			require.NoError(t, err)
			callOriginal := func() {
				t.Helper()
				output, callErr := machine.RunSmartContractCall(vmtest.CreateTestContractCallInputBuilder().
					WithRecipientAddr(target).WithCallerAddr(owner).WithFunction("getUltimateAnswer").WithGasProvided(1000000).Build())
				require.NoError(t, callErr)
				require.Equal(t, vmcommon.Ok, output.ReturnCode, output.ReturnMessage)
				require.Equal(t, [][]byte{{42}}, output.ReturnData)
			}
			callOriginal()
			accounts.reverts = nil
			accounts.fault = errors.New("qualification after real upgrade save")
			if invalid {
				codeB = []byte("not WebAssembly")
			}
			tx := nodevm.CreateTx(owner, target, 0, big.NewInt(7), 1, 10000000,
				vmhost.UpgradeFunctionName+"@"+hex.EncodeToString(codeB)+"@"+hex.EncodeToString(metadata))
			sender, err := accounts.LoadAccount(owner)
			require.NoError(t, err)
			destination, err := accounts.LoadAccount(target)
			require.NoError(t, err)
			result, err := processors.SCProc.ExecuteSmartContractTransaction(tx, sender.(state.UserAccountHandler), destination.(state.UserAccountHandler))
			t.Logf("native upgrade result=%s writes=%d error=%v composite=%v", result.String(), accounts.writes, err, processors.SCProc.GetCompositeTestError())
			require.NoError(t, err) // V2 maps output-persistence errors to ExecutionFailed.
			if invalid {
				require.Equal(t, vmcommon.UserError, result)
				require.Zero(t, accounts.writes)
			} else {
				require.Equal(t, vmcommon.ExecutionFailed, result)
				require.Equal(t, 1, accounts.writes, "fault must follow a real upgraded-code write")
			}
			require.Len(t, accounts.reverts, 1, "owning processor must revert its journal")
			if !invalid {
				require.Greater(t, accounts.journalAtWrite, accounts.reverts[0])
			}
			restored, err := accounts.GetExistingAccount(target)
			require.NoError(t, err)
			actual := restored.(state.UserAccountHandler)
			require.Equal(t, originalHash, actual.GetCodeHash())
			require.Equal(t, codeA, accounts.GetCode(actual.GetCodeHash()))
			require.Equal(t, metadata, actual.GetCodeMetadata())
			require.Equal(t, owner, actual.GetOwnerAddress())
			require.Equal(t, big.NewInt(17), actual.GetBalance())
			value, _, err := actual.RetrieveValue([]byte("witness"))
			require.NoError(t, err)
			require.Equal(t, []byte("original"), value)
			callOriginal()
		})
	}
}
