package drwa

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native creation only; regulated entry restrictions remain SP2-25/68.
func TestQualTransitionR14NFTCreateNative(t *testing.T) {
	for _, mode := range []string{"single", "multiple", "zero", "wide32", "wide80", "above", "role", "exec", "late save"} {
		t.Run(mode+" should preserve native nonce continuity", func(t *testing.T) {
			store := &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}
			marshaller := &marshal.GogoProtoMarshalizer{}
			flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.SaveToSystemAccountFlag, builtInFunctions.SendAlwaysFlag)
			settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(store, marshaller, true, core.BuiltInFunctionESDTPause, func() bool { return true })
			require.NoError(t, err)
			storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: store, GlobalSettingsHandler: settings, Marshalizer: marshaller, EnableEpochsHandler: flags, ShardCoordinator: testscommon.NewMultiShardsCoordinatorMock(3)})
			require.NoError(t, err)
			roles, err := builtInFunctions.NewESDTRolesFunc(marshaller, true)
			require.NoError(t, err)
			function, err := builtInFunctions.NewESDTNFTCreateFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, marshaller, settings, roles, storage, store, flags)
			require.NoError(t, err)
			tokenID := []byte("TOKEN-abcdef")
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), append(bytes.Clone(tokenID), 5)...)
			nonceKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTNFTLatestNonceIdentifier), tokenID...)
			account, err := store.GetExistingAccount(qualContainmentAddress)
			require.NoError(t, err)
			user := account.(state.UserAccountHandler)
			require.NoError(t, user.SaveKeyValue(nonceKey, []byte{4}))
			require.NoError(t, user.SaveKeyValue([]byte("qualification sentinel"), []byte("retained")))
			if mode != "role" {
				encoded, marshalErr := marshaller.Marshal(&esdt.ESDTRoles{Roles: [][]byte{[]byte(core.ESDTRoleNFTCreate), []byte(core.ESDTRoleNFTAddQuantity)}})
				require.NoError(t, marshalErr)
				require.NoError(t, user.SaveKeyValue(append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), tokenID...), encoded))
			}
			require.NoError(t, store.SaveAccount(user))
			root, err := store.Commit()
			require.NoError(t, err)
			hook, _ := qualT42Hook(t, store, 1, false)
			require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(core.BuiltInFunctionESDTNFTCreate, function))
			quantity := big.NewInt(1)
			if mode == "multiple" {
				quantity.SetInt64(3)
			}
			if mode == "zero" {
				quantity.SetInt64(0)
			}
			royalties := big.NewInt(500)
			switch mode {
			case "wide32":
				royalties.Add(royalties, new(big.Int).Lsh(big.NewInt(1), 32))
			case "wide80":
				royalties.Add(royalties, new(big.Int).Lsh(big.NewInt(1), 80))
			case "above":
				royalties.SetInt64(10001)
			}
			args := [][]byte{tokenID, quantity.Bytes(), []byte("name"), royalties.Bytes(), []byte("hash"), []byte("attributes"), []byte("uri one"), []byte("uri two")}
			input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(qualContainmentAddress), CallValue: big.NewInt(0), GasProvided: 1000, Arguments: args}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: core.BuiltInFunctionESDTNFTCreate}
			if mode == "exec" {
				input.CallType = vm.ExecOnDestByCaller
			}
			fault := errors.New("qualification sender save after NFT creation")
			if mode == "late save" {
				store.fault = fault
			}
			out, err := hook.ProcessBuiltInFunction(input)
			store.fault = nil
			success := mode == "single" || mode == "multiple"
			if !success {
				require.Nil(t, out)
				expected := builtInFunctions.ErrInvalidArguments
				switch mode {
				case "role", "exec":
					expected = builtInFunctions.ErrActionNotAllowed
				case "late save":
					expected = fault
				}
				require.ErrorIs(t, err, expected)
				after, rootErr := store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, root, after)
				require.Zero(t, store.JournalLen())
				committed, commitErr := store.Commit()
				require.NoError(t, commitErr)
				require.Equal(t, root, committed)
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
				account, err = store.GetExistingAccount(qualContainmentAddress)
				require.NoError(t, err)
				user = account.(state.UserAccountHandler)
				priorNonce, _, readErr := user.RetrieveValue(nonceKey)
				require.NoError(t, readErr)
				require.Equal(t, []byte{4}, priorNonce)
				absent, _, readErr := user.RetrieveValue(key)
				require.NoError(t, readErr)
				require.Empty(t, absent)
				require.Empty(t, qualRegistryValue(t, store.qualNativeStore, string(key)))
				if mode == "late save" {
					out, err = hook.ProcessBuiltInFunction(input)
					success = true
				}
			}
			if success {
				require.NoError(t, err)
				metadata := &esdt.MetaData{Nonce: 5, Name: []byte("name"), Creator: bytes.Clone(qualContainmentAddress), Royalties: 500, Hash: []byte("hash"), Attributes: []byte("attributes"), URIs: [][]byte{[]byte("uri one"), []byte("uri two")}}
				logToken := &esdt.ESDigitalToken{Type: uint32(core.NonFungible), Value: big.NewInt(quantity.Int64()), TokenMetaData: metadata}
				logBytes, marshalErr := marshaller.Marshal(logToken)
				require.NoError(t, marshalErr)
				length := 0
				for _, arg := range args {
					length += len(arg)
				}
				require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: 1000 - 7 - uint64(length), ReturnData: [][]byte{{5}}, Logs: []*vmcommon.LogEntry{{Identifier: []byte(core.BuiltInFunctionESDTNFTCreate), Address: qualContainmentAddress, Topics: [][]byte{tokenID, {5}, quantity.Bytes(), logBytes}}}}, out)
				committed, commitErr := store.Commit()
				require.NoError(t, commitErr)
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
				account, err = store.GetExistingAccount(qualContainmentAddress)
				require.NoError(t, err)
				user = account.(state.UserAccountHandler)
				actualNonce, _, readErr := user.RetrieveValue(nonceKey)
				require.NoError(t, readErr)
				require.Equal(t, []byte{5}, actualNonce)
				actual, _, readErr := user.RetrieveValue(key)
				require.NoError(t, readErr)
				want, marshalErr := marshaller.Marshal(&esdt.ESDigitalToken{Type: uint32(core.NonFungible), Value: big.NewInt(quantity.Int64())})
				require.NoError(t, marshalErr)
				require.Equal(t, want, actual)
				logToken.Reserved = []byte{1}
				want, marshalErr = marshaller.Marshal(logToken)
				require.NoError(t, marshalErr)
				require.Equal(t, want, qualRegistryValue(t, store.qualNativeStore, string(key)))
			}
			sentinel, _, readErr := user.RetrieveValue([]byte("qualification sentinel"))
			require.NoError(t, readErr)
			require.Equal(t, []byte("retained"), sentinel)
			require.Equal(t, big.NewInt(100), user.GetBalance())
		})
	}
}
