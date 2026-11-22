package process

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/genesis/mock"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	sd "github.com/multiversx/mx-chain-go/state/disabled"
	sf "github.com/multiversx/mx-chain-go/state/factory"
	pd "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/update"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Synthetic A/C groups and appointment only. Existing independently framed
// literal is copied unchanged from qual_drwa_authority_set_version_test.go;
// its retained chronology/provenance limitations remain. No native authority.
const qualStageAG6 = "0a2d445257412f494e495449414c5f50524f4752414d4d455f4150504f494e544d454e542f63616e646964617465310a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0add020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2041414141414141414141414141414141414141414141414141414141414141410a0800000000000000000a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c0a208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940a20ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10a20ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0a206e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf10a3d0a1061646d697373696f6e006f70617175650a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000ada020a25445257412f415554484f524954595f5345545f56455253494f4e2f63616e646964617465310a2042424242424242424242424242424242424242424242424242424242424242420a0800000000000000010a0e454432353531395f4d5f4f465f4e0a0800000000000000030aaa010a20d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370a20204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c210a2066cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf76330a2020828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f70a20d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da0a3a0a0d696e646570656e64656e74c3a90a2001010101010101010101010101010101010101010101010101010101010101010a0770726f6772616d0a000a000a20abababababababababababababababababababababababababababababababab"

func qualStageALimits() *drwa.InitialProgrammeLimits {
	return &drwa.InitialProgrammeLimits{Files: 2, FileBytes: 4096, AggregateBytes: 8192, RecordBytes: 4096, FieldBytes: 2048, RoleBytes: 64, Members: 10, Records: 100, RetainedBytes: 65536, NewRecordsPerEpoch: 100, AdmissionRole: []byte("admission\x00opaque"), IndependentRole: []byte("independent\xc3\xa9")}
}
func qualStageARaw(t *testing.T) []byte {
	t.Helper()
	b, e := hex.DecodeString(qualStageAG6)
	require.NoError(t, e)
	return b
}

func qualStageAGenesisDB(t *testing.T) *state.AccountsDB {
	t.Helper()
	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	mem := testscommon.NewMemDbMock()
	sm := &storageManager.StorageManagerStub{GetCalled: mem.Get, GetFromCurrentEpochCalled: mem.Get, PutCalled: mem.Put, GetIdentifierCalled: mem.GetIdentifier, GetStateStatsHandlerCalled: mem.GetStateStatsHandler}
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	tr, e := trie.NewTrie(sm, m, h, flags, 5)
	require.NoError(t, e)
	collector := sd.NewDisabledStateAccessesCollector()
	af, e := sf.NewAccountCreator(sf.ArgsAccountCreator{Hasher: h, Marshaller: m, EnableEpochsHandler: flags, StateAccessesCollector: collector})
	require.NoError(t, e)
	db, e := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: h, Marshaller: m, AccountFactory: af, StateAccessesCollector: collector, StoragePruningManager: pd.NewDisabledStoragePruningManager(), SnapshotsManager: sd.NewDisabledSnapshotsManager(), AddressConverter: &testscommon.PubkeyConverterMock{}})
	require.NoError(t, e)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

type qualStageAMetaAccounts struct {
	state.AccountsAdapter
	budget      []byte
	commits     int
	rollbacks   []int
	rollbackErr error
}

func (a *qualStageAMetaAccounts) SaveAccount(account vmcommon.AccountHandler) error {
	if user, ok := account.(state.UserAccountHandler); ok && bytes.Equal(user.AddressBytes(), core.SystemAccountAddress) {
		value, _, err := user.RetrieveValue([]byte("ELRONDDRWA@scopedAdmission@budget"))
		if err == nil {
			a.budget = bytes.Clone(value)
		}
	}
	return a.AccountsAdapter.SaveAccount(account)
}

func (a *qualStageAMetaAccounts) Commit() ([]byte, error) {
	a.commits++
	return a.AccountsAdapter.Commit()
}

func (a *qualStageAMetaAccounts) RevertToSnapshot(snapshot int) error {
	a.rollbacks = append(a.rollbacks, snapshot)
	return errors.Join(a.AccountsAdapter.RevertToSnapshot(snapshot), a.rollbackErr)
}

func TestQualDRWAInitialProgrammeGenesisOwner(t *testing.T) {
	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	l := qualStageALimits()
	evidence, e := drwa.DecodeInitialProgrammeEvidence(qualStageARaw(t), "synthetic", "pin", l, m, h)
	require.NoError(t, e)
	for _, name := range []string{"original_owner_rolls_back_native_failure", "preserves_both_errors"} {
		t.Run(name, func(t *testing.T) {
			db := qualStageAGenesisDB(t)
			before, err := db.RootHash()
			require.NoError(t, err)
			before = bytes.Clone(before)
			accounts := &qualStageAMetaAccounts{AccountsAdapter: db}
			if name == "preserves_both_errors" {
				accounts.rollbackErr = errors.New("synthetic rollback acknowledgement failure")
			}
			arg := ArgsGenesisBlockCreator{Accounts: accounts, Core: &mock.CoreComponentsMock{IntMarsh: m, Hash: h}, GenesisEpoch: 17,
				DRWAInitialProgrammes: []drwa.InitialProgrammeEvidence{evidence}, DRWAInitialProgrammeLimits: l}
			// The actual native processor constructor refuses missing round config.
			hdr, hashes, indexing, err := CreateMetaGenesisBlock(arg, nil, nil, nil)
			require.ErrorContains(t, err, "round config")
			if accounts.rollbackErr != nil {
				require.ErrorIs(t, err, accounts.rollbackErr)
			}
			require.Nil(t, hdr)
			require.Nil(t, hashes)
			require.Nil(t, indexing)
			require.Len(t, accounts.budget, 32)
			require.Equal(t, uint64(17), binary.BigEndian.Uint64(accounts.budget[16:24]))
			require.Equal(t, []int{0}, accounts.rollbacks)
			require.Zero(t, accounts.commits)
			require.Zero(t, db.JournalLen())
			after, err := db.RootHash()
			require.NoError(t, err)
			require.Equal(t, before, after)
			_, err = db.GetExistingAccount(core.SystemAccountAddress)
			require.ErrorIs(t, err, state.ErrAccNotFound)
		})
	}
	t.Run("nil_ordinary_same_native_error_no_initial_write", func(t *testing.T) {
		db := qualStageAGenesisDB(t)
		hdr, _, _, e := CreateMetaGenesisBlock(ArgsGenesisBlockCreator{Accounts: db}, nil, nil, nil)
		require.Error(t, e)
		require.Contains(t, e.Error(), "round config")
		require.Nil(t, hdr)
		require.Zero(t, db.JournalLen())
	})
	t.Run("absent_limits_before_processors", func(t *testing.T) {
		db := qualStageAGenesisDB(t)
		hdr, _, _, e := CreateMetaGenesisBlock(ArgsGenesisBlockCreator{Accounts: db, Core: &mock.CoreComponentsMock{IntMarsh: m, Hash: h}, DRWAInitialProgrammes: []drwa.InitialProgrammeEvidence{evidence}}, nil, nil, nil)
		require.ErrorIs(t, e, drwa.ErrInitialProgrammeLimits)
		require.Nil(t, hdr)
		require.Zero(t, db.JournalLen())
	})
	t.Run("import_guard_precedes_initialization", func(t *testing.T) {
		arg := ArgsGenesisBlockCreator{DRWAInitialProgrammes: []drwa.InitialProgrammeEvidence{evidence}}
		arg.HardForkConfig.AfterHardFork = true
		hdr, _, _, e := CreateMetaGenesisBlock(arg, nil, nil, nil)
		require.ErrorIs(t, e, update.ErrNilHardForkBlockProcessor)
		require.Nil(t, hdr)
	})
	t.Run("configured_minimum_without_programme_denies_before_accounts", func(t *testing.T) {
		hdr, hashes, indexing, err := CreateMetaGenesisBlock(ArgsGenesisBlockCreator{
			DRWAMinimumGenesis: &config.DRWAMinimumGenesis{},
		}, nil, nil, nil)
		require.ErrorIs(t, err, drwa.ErrInitialProgrammeLimits)
		require.Nil(t, hdr)
		require.Nil(t, hashes)
		require.Nil(t, indexing)
	})
	t.Run("configured_generation_requires_selected_metachain_adapter", func(t *testing.T) {
		accounts := qualStageAGenesisDB(t)
		other := qualStageAGenesisDB(t)
		hdr, _, _, err := CreateMetaGenesisBlock(ArgsGenesisBlockCreator{
			Accounts: accounts, drwaGenesisAccounts: other, DRWAMinimumGenesis: &config.DRWAMinimumGenesis{},
			DRWAInitialProgrammes: []drwa.InitialProgrammeEvidence{evidence},
		}, nil, nil, nil)
		require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
		require.Nil(t, hdr)
		require.Zero(t, accounts.JournalLen())
		require.Zero(t, other.JournalLen())
	})
}
