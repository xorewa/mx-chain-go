package wasmer

import (
	"bytes"
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

// Inject a failure only after the owning AccountsDB has actually removed the
// account. Rollback is delegated to the node processor, never performed here.
type qualG34Journal struct {
	state.AccountsAdapter
	target             []byte
	fault              error
	removed            int
	reverts            []int
	journalAtRemoval   int
	absentAfterRemoval bool
}

func (q *qualG34Journal) RemoveAccount(address []byte) error {
	if err := q.AccountsAdapter.RemoveAccount(address); err != nil {
		return err
	}
	if bytes.Equal(address, q.target) {
		q.removed++
		q.journalAtRemoval = q.JournalLen()
		_, err := q.AccountsAdapter.GetExistingAccount(address)
		q.absentAfterRemoval = err != nil
		return q.fault
	}
	return nil
}
func (q *qualG34Journal) RevertToSnapshot(snapshot int) error {
	q.reverts = append(q.reverts, snapshot)
	return q.AccountsAdapter.RevertToSnapshot(snapshot)
}
func TestQualPartialsG34NativeDeleteJournalRollback(t *testing.T) {
	codeA, err := os.ReadFile("../testdata/hello-v2/output/answer.wasm")
	require.NoError(t, err)
	owner := bytes.Repeat([]byte{1}, 32)
	target := vmtest.MakeTestSCAddressWithVMType("journal-upgrade", factory.WasmVirtualMachine)
	db := integrationtests.CreateInMemoryShardAccountsDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	accounts := &qualG34Journal{AccountsAdapter: db, target: target, fault: errors.New("qualification after real account removal")}
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

	for attempt := 0; attempt < 2; attempt++ {
		accounts.reverts = nil
		before := accounts.removed
		tx := nodevm.CreateTx(owner, target, uint64(attempt), big.NewInt(7), 1, 10000000, vmhost.DeleteFunctionName)
		sender, err := accounts.LoadAccount(owner)
		require.NoError(t, err)
		destination, err := accounts.LoadAccount(target)
		require.NoError(t, err)
		result, err := processors.SCProc.ExecuteSmartContractTransaction(tx, sender.(state.UserAccountHandler), destination.(state.UserAccountHandler))
		t.Logf("attempt=%d result=%s removed=%d reverts=%v composite=%v", attempt, result.String(), accounts.removed, accounts.reverts, processors.SCProc.GetCompositeTestError())
		require.NoError(t, err)
		require.Equal(t, vmcommon.ExecutionFailed, result)
		require.Equal(t, before+1, accounts.removed)
		require.True(t, accounts.absentAfterRemoval, "real DB must observe the deletion before injected failure")
		require.Len(t, accounts.reverts, 1)
		require.Greater(t, accounts.journalAtRemoval, accounts.reverts[0])
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
	}
	require.Equal(t, 2, accounts.removed)
}
