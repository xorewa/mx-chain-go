package processorV2

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Reuse the native in-memory account fixture shape; this test assigns no
// bootstrap/account-factory credit. The consumer and rollback owner are real.
func qualPartialsR01Accounts(t *testing.T) state.AccountsAdapter {
	t.Helper()
	mem := testscommon.NewMemDbMock()
	codec, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	storage := &storageManager.StorageManagerStub{GetCalled: mem.Get, PutCalled: mem.Put, GetFromCurrentEpochCalled: mem.Get, GetIdentifierCalled: mem.GetIdentifier, GetStateStatsHandlerCalled: mem.GetStateStatsHandler}
	tr, err := trie.NewTrie(storage, codec, hash, flags, 5)
	require.NoError(t, err)
	collector := stateDisabled.NewDisabledStateAccessesCollector()
	creator, err := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: hash, Marshaller: codec, EnableEpochsHandler: flags, StateAccessesCollector: collector})
	require.NoError(t, err)
	db, err := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: hash, Marshaller: codec, AccountFactory: creator, StateAccessesCollector: collector, StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(), SnapshotsManager: stateDisabled.NewDisabledSnapshotsManager(), AddressConverter: testscommon.NewPubkeyConverterMock(32)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func TestQualPartialsR01MultiAccountRollback(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "late_nonce"}[reject], func(t *testing.T) {
			db := qualPartialsR01Accounts(t)
			first, second, witness := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
			for _, addr := range [][]byte{first, second, witness} {
				a, err := db.LoadAccount(addr)
				require.NoError(t, err)
				u := a.(state.UserAccountHandler)
				u.IncreaseNonce(4)
				require.NoError(t, u.AddToBalance(big.NewInt(100)))
				require.NoError(t, u.SaveKeyValue([]byte("key"), []byte("before")))
				require.NoError(t, db.SaveAccount(u))
			}
			_, err := db.Commit()
			require.NoError(t, err)
			w, err := db.LoadAccount(witness)
			require.NoError(t, err)
			require.NoError(t, w.(state.UserAccountHandler).SaveKeyValue([]byte("key"), []byte("checkpoint")))
			require.NoError(t, db.SaveAccount(w))
			snapshot := db.JournalLen()
			require.Positive(t, snapshot)
			before, err := db.RootHash()
			require.NoError(t, err)
			args := createMockSmartContractProcessorArguments()
			args.AccountsDB = db
			args.EnableEpochsHandler = enableEpochsHandlerMock.NewEnableEpochsHandlerStub(common.FixCorrectSmallIntAndGasLimitsFlag)
			args.ShardCoordinator = &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return 0 }, ComputeIdCalled: func([]byte) uint32 { return 0 }}
			sc, err := NewSmartContractProcessorV2(args)
			require.NoError(t, err)
			output := &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, OutputAccounts: make(map[string]*vmcommon.OutputAccount)}
			for _, addr := range [][]byte{first, second} {
				nonce := uint64(5)
				if reject && bytes.Equal(addr, second) {
					nonce = 3
				}
				output.OutputAccounts[string(addr)] = &vmcommon.OutputAccount{Address: addr, Nonce: nonce, BalanceDelta: big.NewInt(0), StorageUpdates: map[string]*vmcommon.StorageUpdate{"key": {Offset: []byte("key"), Data: []byte("after")}}}
			}
			tx := &transaction.Transaction{SndAddr: first, RcvAddr: second, Value: big.NewInt(0)}
			callback, results, err := NewVMOutputAccountsProcessor(sc, &vmcommon.VMInput{CallType: vmData.DirectCall}, output, tx, []byte("current-hash")).Run()
			if reject {
				require.ErrorIs(t, err, process.ErrWrongNonceInVMOutput)
				require.Nil(t, results)
				// The first account has actually been changed before the second nonce rejects.
				a, e := db.GetExistingAccount(first)
				require.NoError(t, e)
				v, _, e := a.(state.UserAccountHandler).RetrieveValue([]byte("key"))
				require.NoError(t, e)
				require.Equal(t, []byte("after"), v)
				require.NoError(t, sc.ProcessIfError(nil, []byte("current-hash"), tx, err.Error(), nil, snapshot, 0))
				after, e := db.RootHash()
				require.NoError(t, e)
				require.Equal(t, before, after)
				require.Equal(t, snapshot, db.JournalLen())
			} else {
				require.NoError(t, err)
				require.False(t, callback)
				require.Empty(t, results)
			}
			root, err := db.Commit()
			require.NoError(t, err)
			if reject {
				require.Equal(t, before, root)
			}
			require.NoError(t, db.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			for _, addr := range [][]byte{first, second, witness} {
				a, e := db.GetExistingAccount(addr)
				require.NoError(t, e)
				u := a.(state.UserAccountHandler)
				v, _, e := u.RetrieveValue([]byte("key"))
				require.NoError(t, e)
				want, nonce := []byte("after"), uint64(5)
				if reject {
					want, nonce = []byte("before"), 4
				}
				if bytes.Equal(addr, witness) {
					want, nonce = []byte("checkpoint"), 4
				}
				require.Equal(t, want, v)
				require.Equal(t, nonce, u.GetNonce())
				require.Equal(t, big.NewInt(100), u.GetBalance())
			}
		})
	}
}
