package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/multiversx/mx-chain-go/testscommon/enableEpochsHandlerMock"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// Native metadata only; classification, public denial and distribution remain SP2-25/68/40.
func TestQualTransitionR10RecreateNative(t *testing.T) {
	for _, family := range []core.ESDTType{core.DynamicNFT, core.DynamicSFT} {
		for _, mode := range []string{"valid", "wide32", "wide80", "role", "inactive", "nonce", "gas", "late save"} {
			t.Run(fmt.Sprintf("type %d %s should preserve native metadata contract", family, mode), func(t *testing.T) {
				store := &qualTransitionReceiverSaveFault{qualNativeStore: qualRegistrationStore(t, 0)}
				marshaller := &marshal.GogoProtoMarshalizer{}
				flags := enableEpochsHandlerMock.NewEnableEpochsHandlerStub(builtInFunctions.DynamicEsdtFlag, builtInFunctions.SaveToSystemAccountFlag, builtInFunctions.SendAlwaysFlag)
				if mode == "inactive" {
					flags.RemoveActiveFlags(builtInFunctions.DynamicEsdtFlag)
				}
				settings, err := builtInFunctions.NewESDTGlobalSettingsFunc(store, marshaller, true, core.BuiltInFunctionESDTPause, func() bool { return true })
				require.NoError(t, err)
				storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{Accounts: store, GlobalSettingsHandler: settings, Marshalizer: marshaller, EnableEpochsHandler: flags, ShardCoordinator: testscommon.NewMultiShardsCoordinatorMock(3)})
				require.NoError(t, err)
				roles, err := builtInFunctions.NewESDTRolesFunc(marshaller, true)
				require.NoError(t, err)
				function, err := builtInFunctions.NewESDTMetaDataRecreateFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, store, settings, storage, roles, flags, marshaller)
				require.NoError(t, err)
				tokenID := []byte("TOKEN-abcdef")
				base := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
				key := append(bytes.Clone(base), 1)
				require.NoError(t, settings.SetTokenType(base, uint32(family)))
				oldMetadata := &esdt.MetaData{Nonce: 1, Name: []byte("old")}
				old := &esdt.ESDigitalToken{Value: big.NewInt(5), Type: uint32(family), Properties: []byte{0, 0}, TokenMetaData: oldMetadata}
				prior, err := marshaller.Marshal(old)
				require.NoError(t, err)
				for _, address := range [][]byte{qualContainmentAddress, core.SystemAccountAddress} {
					account, loadErr := store.LoadAccount(address)
					require.NoError(t, loadErr)
					user := account.(state.UserAccountHandler)
					require.NoError(t, user.SaveKeyValue(key, prior))
					if bytes.Equal(address, qualContainmentAddress) && mode != "role" {
						roleBytes, marshalErr := marshaller.Marshal(&esdt.ESDTRoles{Roles: [][]byte{[]byte(core.ESDTRoleNFTRecreate)}})
						require.NoError(t, marshalErr)
						roleKey := append([]byte(core.ProtectedKeyPrefix+core.ESDTRoleIdentifier+core.ESDTKeyIdentifier), tokenID...)
						require.NoError(t, user.SaveKeyValue(roleKey, roleBytes))
					}
					require.NoError(t, store.SaveAccount(user))
				}
				root, err := store.Commit()
				require.NoError(t, err)
				hook, _ := qualT42Hook(t, store, 1, false)
				hook.SetCurrentHeader(&block.Header{Round: 17})
				require.NoError(t, function.SetBlockchainHook(hook))
				require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(core.ESDTMetaDataRecreate, function))
				royalties := big.NewInt(500)
				if mode == "wide32" {
					royalties.Add(royalties, new(big.Int).Lsh(big.NewInt(1), 32))
				}
				if mode == "wide80" {
					royalties.Add(royalties, new(big.Int).Lsh(big.NewInt(1), 80))
				}
				args := [][]byte{tokenID, {1}, []byte("new name"), royalties.Bytes(), []byte("new hash"), []byte("new attributes"), []byte("uri one"), []byte("uri two")}
				if mode == "nonce" {
					args[1] = nil
				}
				gas := uint64(1000)
				if mode == "gas" {
					gas = 0
				}
				fault := errors.New("qualification sender save after metadata mutation")
				if mode == "late save" {
					store.fault = fault
				}
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(qualContainmentAddress), CallValue: big.NewInt(0), GasProvided: gas, Arguments: args}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: core.ESDTMetaDataRecreate}
				out, err := hook.ProcessBuiltInFunction(input)
				store.fault = nil
				want := prior
				if mode == "valid" {
					require.NoError(t, err)
					version := &esdt.MetaDataVersion{Name: 17, Creator: 17, Royalties: 17, Hash: 17, URIs: 17, Attributes: 17}
					reserved, marshalErr := marshaller.Marshal(version)
					require.NoError(t, marshalErr)
					expected := &esdt.ESDigitalToken{Value: big.NewInt(5), Type: uint32(family), Properties: []byte{0, 0}, Reserved: reserved, TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("new name"), Creator: bytes.Clone(qualContainmentAddress), Royalties: 500, Hash: []byte("new hash"), Attributes: []byte("new attributes"), URIs: [][]byte{[]byte("uri one"), []byte("uri two")}}}
					want, marshalErr = marshaller.Marshal(expected)
					require.NoError(t, marshalErr)
					length := 0
					for _, arg := range args {
						length += len(arg)
					}
					difference := length - oldMetadata.Size()
					if difference < 0 {
						difference = 0
					}
					require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: gas - 7 - uint64(difference), Logs: []*vmcommon.LogEntry{{Identifier: []byte(core.ESDTMetaDataRecreate), Address: qualContainmentAddress, Topics: [][]byte{tokenID, {1}, {}, want}}}}, out)
				} else {
					require.Nil(t, out)
					expectedError := builtInFunctions.ErrInvalidArguments
					switch mode {
					case "role":
						expectedError = builtInFunctions.ErrActionNotAllowed
					case "inactive":
						expectedError = builtInFunctions.ErrBuiltInFunctionIsNotActive
					case "gas":
						expectedError = builtInFunctions.ErrNotEnoughGas
					case "late save":
						expectedError = fault
					}
					require.ErrorIs(t, err, expectedError)
					after, rootErr := store.RootHash()
					require.NoError(t, rootErr)
					require.Equal(t, root, after)
					require.Zero(t, store.JournalLen())
				}
				committed, err := store.Commit()
				require.NoError(t, err)
				if mode != "valid" {
					require.Equal(t, root, committed)
				}
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(committed)))
				for _, address := range [][]byte{qualContainmentAddress, core.SystemAccountAddress} {
					account, loadErr := store.GetExistingAccount(address)
					require.NoError(t, loadErr)
					actual, _, readErr := account.(state.UserAccountHandler).RetrieveValue(key)
					require.NoError(t, readErr)
					selected := family == core.DynamicNFT && bytes.Equal(address, qualContainmentAddress) || family == core.DynamicSFT && bytes.Equal(address, core.SystemAccountAddress)
					if selected {
						require.Equal(t, want, actual)
					} else {
						require.Equal(t, prior, actual)
					}
				}
			})
		}
	}
}
