package systemSmartContracts

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
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
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAProtectedStateActualGlobalFanout(t *testing.T) {
	args := createDefaultEeiArgs()
	args.BlockChainHook.(*mock.BlockChainHookStub).NumberOfShardsCalled = func() uint32 { return 3 }
	host, err := NewVMContext(args)
	require.NoError(t, err)
	token := []byte("TOKEN-000001")
	functions := []string{core.BuiltInFunctionESDTPause, core.BuiltInFunctionESDTUnPause,
		core.BuiltInFunctionESDTSetLimitedTransfer, core.BuiltInFunctionESDTUnSetLimitedTransfer,
		vmcommon.BuiltInFunctionESDTSetBurnRoleForAll, vmcommon.BuiltInFunctionESDTUnSetBurnRoleForAll}
	for _, function := range functions {
		host.SendGlobalSettingToAll(core.ESDTSCAddress, []byte(function+"@"+hex.EncodeToString(token)))
	}
	require.Len(t, host.outputAccounts, 3)
	for shard := byte(0); shard < 3; shard++ {
		db := testscommon.NewMemDbMock()
		storage := &storageManager.StorageManagerStub{GetCalled: db.Get, PutCalled: db.Put,
			GetFromCurrentEpochCalled: db.Get, GetIdentifierCalled: db.GetIdentifier, GetStateStatsHandlerCalled: db.GetStateStatsHandler}
		flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub()
		codec, hasher := &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b()
		tr, createErr := trie.NewTrie(storage, codec, hasher, flags, 5)
		require.NoError(t, createErr)
		collector := stateDisabled.NewDisabledStateAccessesCollector()
		creator, createErr := factory.NewAccountCreator(factory.ArgsAccountCreator{Hasher: hasher, Marshaller: codec, EnableEpochsHandler: flags, StateAccessesCollector: collector})
		require.NoError(t, createErr)
		adb, createErr := state.NewAccountsDB(state.ArgsAccountsDB{Trie: tr, Hasher: hasher, Marshaller: codec, AccountFactory: creator,
			StateAccessesCollector: collector, StoragePruningManager: pruningDisabled.NewDisabledStoragePruningManager(),
			SnapshotsManager: stateDisabled.NewDisabledSnapshotsManager(), AddressConverter: testscommon.NewPubkeyConverterMock(32)})
		require.NoError(t, createErr)
		a, loadErr := adb.LoadAccount(core.SystemAccountAddress)
		require.NoError(t, loadErr)
		// Independent literal pre-state, not an authority or registration fixture.
		key := []byte("ELRONDDRWA@membership@TOKEN-000001")
		require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(key, []byte{1}))
		require.NoError(t, adb.SaveAccount(a))
		_, createErr = adb.Commit()
		require.NoError(t, createErr)
		destination := bytes.Clone(core.SystemAccountAddress)
		destination[31] = shard
		out := host.outputAccounts[string(destination)]
		require.NotNil(t, out)
		require.Len(t, out.OutputTransfers, len(functions))
		for index, function := range functions {
			transfer := out.OutputTransfers[index]
			require.Equal(t, []byte(function+"@"+hex.EncodeToString(token)), transfer.Data)
			require.Empty(t, transfer.SenderAddress, "native helper ignores sender; processing context supplies actual System-SC provenance")
			fn, createErr := builtInFunctions.NewESDTGlobalSettingsFunc(adb, codec, index%2 == 0, function, func() bool { return true })
			require.NoError(t, createErr)
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(core.ESDTSCAddress), CallValue: big.NewInt(0), Arguments: [][]byte{token}}, RecipientAddr: destination}
			result, callErr := fn.ProcessBuiltinFunction(nil, nil, input)
			require.NoError(t, callErr)
			require.Equal(t, vmcommon.Ok, result.ReturnCode)
			a, loadErr = adb.GetExistingAccount(core.SystemAccountAddress)
			require.NoError(t, loadErr)
			value, _, readErr := a.(state.UserAccountHandler).RetrieveValue(key)
			require.NoError(t, readErr)
			require.Equal(t, []byte{1}, value)
			input.CallerAddr = bytes.Repeat([]byte{3}, 32)
			_, callErr = fn.ProcessBuiltinFunction(nil, nil, input)
			require.ErrorIs(t, callErr, builtInFunctions.ErrAddressIsNotESDTSystemSC)
		}
	}
}
