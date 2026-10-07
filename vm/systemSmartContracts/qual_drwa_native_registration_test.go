package systemSmartContracts

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/state"
	stateDisabled "github.com/multiversx/mx-chain-go/state/disabled"
	"github.com/multiversx/mx-chain-go/state/factory"
	pruningDisabled "github.com/multiversx/mx-chain-go/state/storagePruningManager/disabled"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	"github.com/multiversx/mx-chain-go/testscommon/storageManager"
	"github.com/multiversx/mx-chain-go/trie"
	"github.com/multiversx/mx-chain-go/vm/mock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

// Test addresses, gas and capacities are fixtures, not protocol allocations.
// The native account/trie fixture includes sentinel leaves so absence is a real
// Trie.Get result, not ErrNilTrie. Fault injection preserves native saves first.
type qualDRWARegistrationStore struct {
	state.AccountsAdapter
	saveFault, rollbackFault error
	saves, failAt            int
}

func (s *qualDRWARegistrationStore) SaveAccount(a vmcommon.AccountHandler) error {
	if err := s.AccountsAdapter.SaveAccount(a); err != nil {
		return err
	}
	s.saves++
	if s.saves == s.failAt {
		return s.saveFault
	}
	return nil
}
func (s *qualDRWARegistrationStore) RevertToSnapshot(n int) error {
	if s.rollbackFault != nil {
		return s.rollbackFault
	}
	return s.AccountsAdapter.RevertToSnapshot(n)
}
func qualNativeRegistration(t *testing.T) (*esdt, *vmContext, *qualDRWARegistrationStore, *drwa.RegistryRegistration, *drwa.RollbackContainment, drwaTokenCreation) {
	t.Helper()
	db := testscommon.NewMemDbMock()
	mar, hash := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
	flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
	storage := &storageManager.StorageManagerStub{GetCalled: db.Get, GetFromCurrentEpochCalled: db.Get, PutCalled: db.Put, GetStateStatsHandlerCalled: db.GetStateStatsHandler, GetIdentifierCalled: db.GetIdentifier}
	tr, err := trie.NewTrie(storage, mar, hash, flags, 5)
	require.NoError(t, err)
	collector := stateDisabled.NewDisabledStateAccessesCollector()
	f, err := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: hash, Marshaller: mar, EnableEpochsHandler: flags, StateAccessesCollector: collector})
	require.NoError(t, err)
	adb, err := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: hash, Marshaller: mar, AccountFactory: f, StateAccessesCollector: collector, StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(), SnapshotsManager: stateDisabled.NewDisabledSnapshotsManager(), AddressConverter: testscommon.NewPubkeyConverterMock(32)})
	require.NoError(t, err)
	s := &qualDRWARegistrationStore{AccountsAdapter: adb}
	for _, address := range [][]byte{core.SystemAccountAddress, core.ESDTSCAddress} {
		a, e := s.LoadAccount(address)
		require.NoError(t, e)
		require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte("fixture/sentinel"), []byte{1}))
		if bytes.Equal(address, core.SystemAccountAddress) {
			require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue([]byte(core.ProtectedKeyPrefix+"DRWA@registry@count"), make([]byte, 8)))
		}
		require.NoError(t, s.SaveAccount(a))
	}
	_, err = s.Commit()
	require.NoError(t, err)
	s.saves = 0
	eeiArgs := createDefaultEeiArgs()
	eeiArgs.UserAccountsDB = s
	eeiArgs.BlockChainHook = &mock.BlockChainHookStub{GetStorageDataCalled: func([]byte, []byte) ([]byte, uint32, error) { return nil, 0, nil }, CurrentRandomSeedCalled: func() []byte { return []byte("registration-seed") }, NumberOfShardsCalled: func() uint32 { return 3 }, CurrentNonceCalled: func() uint64 { return 1 }}
	ctx, err := NewVMContext(eeiArgs)
	require.NoError(t, err)
	ctx.SetSCAddress(core.ESDTSCAddress)
	ctx.gasRemaining = 1000000
	args := createMockArgumentsForESDT()
	args.Eei = ctx
	args.ESDTSCAddress = core.ESDTSCAddress
	args.Marshalizer = mar
	args.Hasher = hash
	e, err := NewESDTSmartContract(args)
	require.NoError(t, err)
	r, c, err := drwa.NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 2)
	require.NoError(t, err)
	request := drwaTokenCreation{issuer: bytes.Repeat([]byte{1}, 32), manager: bytes.Repeat([]byte{2}, 32), name: []byte("RegulatedToken"), ticker: []byte("TOKEN"), family: []byte(core.FungibleESDT), properties: [][]byte{[]byte(upgradable), []byte("false"), []byte(canAddSpecialRoles), []byte("true")}}
	return e, ctx, s, r, c, request
}
func qualNativeRegistrationValue(t *testing.T, s *qualDRWARegistrationStore, address, key []byte) []byte {
	t.Helper()
	a, err := s.GetExistingAccount(address)
	require.NoError(t, err)
	v, _, err := a.(state.UserAccountHandler).RetrieveValue(key)
	require.NoError(t, err)
	return v
}
func TestQualDRWANativeRegistrationFamilies(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			e, ctx, s, r, c, request := qualNativeRegistration(t)
			request.family = []byte(family)
			original := e.eei
			require.NoError(t, e.registerDRWAToken(r, request))
			require.Same(t, original, e.eei)
			require.Len(t, ctx.output, 1)
			id := ctx.output[0]
			require.True(t, vmcommon.ValidateToken(id))
			native := &ESDTDataV2{}
			require.NoError(t, e.marshalizer.Unmarshal(native, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, id)))
			require.Equal(t, request.manager, native.OwnerAddress)
			require.Equal(t, family, string(native.TokenType))
			require.Zero(t, native.MintedValue.Sign())
			require.Zero(t, native.BurntValue.Sign())
			require.False(t, native.Upgradable)
			require.True(t, native.CanAddSpecialRoles)
			require.False(t, native.CanFreeze)
			require.False(t, native.CanWipe)
			require.False(t, native.CanPause)
			require.False(t, native.CanChangeOwner)
			require.False(t, native.CanCreateMultiShard)
			require.False(t, native.CanTransferNFTCreateRole)
			require.False(t, native.Mintable)
			require.False(t, native.Burnable)
			require.Empty(t, native.SpecialRoles)
			require.Equal(t, []byte{1}, qualNativeRegistrationValue(t, s, core.SystemAccountAddress, append([]byte(core.ProtectedKeyPrefix+"DRWA@registry@member@"), id...)))
			require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualNativeRegistrationValue(t, s, core.SystemAccountAddress, []byte(core.ProtectedKeyPrefix+"DRWA@registry@count"))))
			roots, out, err := c.Commit()
			require.NoError(t, err)
			require.Len(t, out, 1)
			require.Equal(t, id, out[0].ReturnData[0])
			require.NotEmpty(t, out[0].OutputAccounts)
			require.NotEmpty(t, out[0].Logs)
			require.NoError(t, s.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
			require.NotEmpty(t, qualNativeRegistrationValue(t, s, core.ESDTSCAddress, id))
			require.Equal(t, []byte{1}, qualNativeRegistrationValue(t, s, core.SystemAccountAddress, append([]byte(core.ProtectedKeyPrefix+"DRWA@registry@member@"), id...)))
			require.Empty(t, ctx.storageUpdate)
			for _, a := range out[0].OutputAccounts {
				require.Empty(t, a.StorageUpdates)
			}
		})
	}
}
func TestQualDRWANativeRegistrationRollback(t *testing.T) {
	for _, fault := range []string{"token-save", "member-count-save", "rollback"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, r, c, request := qualNativeRegistration(t)
			root, err := s.RootHash()
			require.NoError(t, err)
			original := errors.New("native partial save fault")
			rollback := errors.New("native rollback fault")
			s.saveFault = original
			s.failAt = 1
			if fault == "member-count-save" {
				s.failAt = 2
			}
			if fault == "rollback" {
				s.rollbackFault = rollback
			}
			err = e.registerDRWAToken(r, request)
			require.ErrorIs(t, err, original)
			require.Empty(t, ctx.output)
			require.Empty(t, ctx.logs)
			require.Empty(t, ctx.outputAccounts)
			require.Empty(t, ctx.storageUpdate)
			require.Same(t, ctx, e.eei)
			if fault == "rollback" {
				require.ErrorIs(t, err, rollback)
				_, out, err := c.Commit()
				require.Error(t, err)
				require.Empty(t, out)
				return
			}
			current, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, current)
			require.Zero(t, s.JournalLen())
			require.Equal(t, make([]byte, 8), qualNativeRegistrationValue(t, s, core.SystemAccountAddress, []byte(core.ProtectedKeyPrefix+"DRWA@registry@count")))
		})
	}
}
func TestQualDRWANativeRegistrationRejects(t *testing.T) {
	for _, fault := range []string{"family", "issuer", "manager", "decimals", "name", "ticker", "upgradable", "freeze", "dirty-overlay", "wrong-context", "wrong-store"} {
		t.Run(fault, func(t *testing.T) {
			e, ctx, s, r, _, request := qualNativeRegistration(t)
			root, err := s.RootHash()
			require.NoError(t, err)
			switch fault {
			case "family":
				request.family = []byte("Unknown")
			case "issuer":
				request.issuer = nil
			case "manager":
				request.manager = nil
			case "decimals":
				request.decimals = 19
			case "name":
				request.name = []byte("Bad!")
			case "ticker":
				request.ticker = []byte("bad")
			case "upgradable":
				request.properties = nil
			case "freeze":
				request.properties = append(request.properties, []byte(canFreeze), []byte("true"))
			case "dirty-overlay":
				ctx.SetStorage([]byte("old"), []byte{1})
			case "wrong-context":
				ctx.SetSCAddress(core.SystemAccountAddress)
			case "wrong-store":
				ctx.userAccountsDB = s.AccountsAdapter
			}
			require.Error(t, e.registerDRWAToken(r, request))
			current, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, current)
			require.Zero(t, s.JournalLen())
			require.Same(t, ctx, e.eei)
		})
	}
}

func TestQualDRWANativeRegistrationNativeReadFailure(t *testing.T) {
	e, ctx, s, _, _, request := qualNativeRegistration(t)
	require.NoError(t, s.RemoveAccount(core.ESDTSCAddress))
	account, err := s.LoadAccount(core.ESDTSCAddress)
	require.NoError(t, err)
	// Existing native account deliberately has no data trie: the native reader
	// returns ErrNilTrie, not an invented absence fixture.
	require.NoError(t, s.SaveAccount(account))
	_, err = s.Commit()
	require.NoError(t, err)
	_, _, nativeErr := account.(state.UserAccountHandler).RetrieveValue([]byte("TOKEN-abcdef"))
	require.Error(t, nativeErr)
	strict := &drwaRegistrationEI{SystemEI: ctx, context: ctx, accounts: s}
	require.Empty(t, strict.GetStorage([]byte("TOKEN-abcdef")))
	require.ErrorIs(t, strict.readErr, nativeErr)
	r, _, err := drwa.NewRegistryRegistration(s, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 2)
	require.NoError(t, err)
	root, err := s.RootHash()
	require.NoError(t, err)
	require.ErrorIs(t, e.registerDRWAToken(r, request), nativeErr)
	after, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Empty(t, ctx.output)
	require.Empty(t, ctx.storageUpdate)
}
