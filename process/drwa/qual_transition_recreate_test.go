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
func TestQualTransitionR10RecreateNative(t *testing.T) { qualTransitionMetadataNative(t, "recreate") }

func qualTransitionMetadataNative(t *testing.T, operation string) {
	update, modify := operation == "update", operation == "royalties"
	name, role := core.ESDTMetaDataRecreate, core.ESDTRoleNFTRecreate
	modes := []string{"valid", "wide32", "wide80", "role", "inactive", "nonce", "gas", "late save"}
	if update {
		name, role = core.ESDTMetaDataUpdate, core.ESDTRoleNFTUpdate
		modes = append(modes, "name only", "royalties only", "hash only", "attributes only", "uris only", "empty")
	}
	if modify {
		name, role = core.ESDTModifyRoyalties, core.ESDTRoleModifyRoyalties
		modes = append(modes, "zero", "maximum", "above")
	}
	for _, family := range []core.ESDTType{core.DynamicNFT, core.DynamicSFT} {
		for _, mode := range modes {
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
				var function vmcommon.BuiltinFunction
				var bindHook func(vmcommon.BlockchainDataHook) error
				if update {
					native, nativeErr := builtInFunctions.NewESDTMetaDataUpdateFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, store, settings, storage, roles, flags, marshaller)
					require.NoError(t, nativeErr)
					function, bindHook = native, native.SetBlockchainHook
				} else if modify {
					native, nativeErr := builtInFunctions.NewESDTModifyRoyaltiesFunc(7, store, settings, storage, roles, flags, marshaller)
					require.NoError(t, nativeErr)
					function, bindHook = native, native.SetBlockchainHook
				} else {
					native, nativeErr := builtInFunctions.NewESDTMetaDataRecreateFunc(7, vmcommon.BaseOperationCost{StorePerByte: 1}, store, settings, storage, roles, flags, marshaller)
					require.NoError(t, nativeErr)
					function, bindHook = native, native.SetBlockchainHook
				}
				require.NoError(t, err)
				tokenID := []byte("TOKEN-abcdef")
				base := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), tokenID...)
				key := append(bytes.Clone(base), 1)
				require.NoError(t, settings.SetTokenType(base, uint32(family)))
				oldMetadata := &esdt.MetaData{Nonce: 1, Name: []byte("old")}
				old := &esdt.ESDigitalToken{Value: big.NewInt(5), Type: uint32(family), Properties: []byte{0, 0}, TokenMetaData: oldMetadata}
				if update || modify {
					oldMetadata.Creator, oldMetadata.Royalties = []byte("old creator"), 25
					oldMetadata.Hash, oldMetadata.Attributes, oldMetadata.URIs = []byte("old hash"), []byte("old attributes"), [][]byte{[]byte("old uri")}
					old.Reserved, err = marshaller.Marshal(&esdt.MetaDataVersion{Name: 3, Creator: 3, Royalties: 3, Hash: 3, URIs: 3, Attributes: 3})
					require.NoError(t, err)
				}
				prior, err := marshaller.Marshal(old)
				require.NoError(t, err)
				for _, address := range [][]byte{qualContainmentAddress, core.SystemAccountAddress} {
					account, loadErr := store.LoadAccount(address)
					require.NoError(t, loadErr)
					user := account.(state.UserAccountHandler)
					require.NoError(t, user.SaveKeyValue(key, prior))
					if bytes.Equal(address, qualContainmentAddress) && mode != "role" {
						roleBytes, marshalErr := marshaller.Marshal(&esdt.ESDTRoles{Roles: [][]byte{[]byte(role)}})
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
				require.NoError(t, bindHook(hook))
				require.NoError(t, hook.GetBuiltinFunctionsContainer().Add(name, function))
				royalties := big.NewInt(500)
				switch mode {
				case "zero":
					royalties.SetInt64(0)
				case "maximum":
					royalties.SetInt64(10000)
				case "above":
					royalties.SetInt64(10001)
				}
				if mode == "wide32" {
					royalties.Add(royalties, new(big.Int).Lsh(big.NewInt(1), 32))
				}
				if mode == "wide80" {
					royalties.Add(royalties, new(big.Int).Lsh(big.NewInt(1), 80))
				}
				args := [][]byte{tokenID, {1}, []byte("new name"), royalties.Bytes(), []byte("new hash"), []byte("new attributes"), []byte("uri one"), []byte("uri two")}
				if update {
					selected := map[string]int{"name only": 2, "royalties only": 3, "hash only": 4, "attributes only": 5, "uris only": 6, "empty": -1}
					if index, partial := selected[mode]; partial {
						for i := 2; i < len(args); i++ {
							if i != index && !(index == 6 && i > 6) {
								args[i] = nil
							}
						}
					}
				}
				if modify {
					args = [][]byte{tokenID, {1}, royalties.Bytes()}
				}
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
				input := &vmcommon.ContractCallInput{VMInput: vmcommon.VMInput{CallerAddr: bytes.Clone(qualContainmentAddress), CallValue: big.NewInt(0), GasProvided: gas, Arguments: args}, RecipientAddr: bytes.Clone(qualContainmentAddress), Function: name}
				out, err := hook.ProcessBuiltInFunction(input)
				store.fault = nil
				want := prior
				success := mode == "valid" || modify && (mode == "zero" || mode == "maximum") || update && (mode == "name only" || mode == "royalties only" || mode == "hash only" || mode == "attributes only" || mode == "uris only" || mode == "empty")
				if success {
					require.NoError(t, err)
					version := &esdt.MetaDataVersion{Name: 17, Creator: 17, Royalties: 17, Hash: 17, URIs: 17, Attributes: 17}
					reserved, marshalErr := marshaller.Marshal(version)
					require.NoError(t, marshalErr)
					expected := &esdt.ESDigitalToken{Value: big.NewInt(5), Type: uint32(family), Properties: []byte{0, 0}, Reserved: reserved, TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("new name"), Creator: bytes.Clone(qualContainmentAddress), Royalties: 500, Hash: []byte("new hash"), Attributes: []byte("new attributes"), URIs: [][]byte{[]byte("uri one"), []byte("uri two")}}}
					if update {
						meta := expected.TokenMetaData
						if len(args[2]) == 0 {
							meta.Name = oldMetadata.Name
							version.Name = 3
						}
						if len(args[3]) == 0 {
							meta.Royalties = oldMetadata.Royalties
							version.Royalties = 3
						}
						if len(args[4]) == 0 {
							meta.Hash = oldMetadata.Hash
							version.Hash = 3
						}
						if len(args[5]) == 0 {
							meta.Attributes = oldMetadata.Attributes
							version.Attributes = 3
						}
						if len(args[6]) == 0 {
							meta.URIs = oldMetadata.URIs
							version.URIs = 3
						}
						expected.Reserved, marshalErr = marshaller.Marshal(version)
						require.NoError(t, marshalErr)
					}
					if modify {
						expected.TokenMetaData = &esdt.MetaData{Nonce: 1, Name: []byte("old"), Creator: []byte("old creator"), Royalties: uint32(royalties.Uint64()), Hash: []byte("old hash"), Attributes: []byte("old attributes"), URIs: [][]byte{[]byte("old uri")}}
						expected.Reserved, marshalErr = marshaller.Marshal(&esdt.MetaDataVersion{Name: 3, Creator: 3, Royalties: 17, Hash: 3, URIs: 3, Attributes: 3})
						require.NoError(t, marshalErr)
					}
					want, marshalErr = marshaller.Marshal(expected)
					require.NoError(t, marshalErr)
					length := 0
					for _, arg := range args {
						length += len(arg)
					}
					difference := length - oldMetadata.Size()
					if update {
						difference = length - len(oldMetadata.Creator)
						if len(args[2]) > 0 {
							difference -= len(oldMetadata.Name)
						}
						if len(args[3]) > 0 {
							difference -= len(args[3])
						}
						if len(args[4]) > 0 {
							difference -= len(oldMetadata.Hash)
						}
						if len(args[5]) > 0 {
							difference -= len(oldMetadata.Attributes)
						}
						if len(args[6]) > 0 {
							for _, uri := range oldMetadata.URIs {
								difference -= len(uri)
							}
						}
					}
					if difference < 0 {
						difference = 0
					}
					topics := [][]byte{tokenID, {1}, {}, want}
					if modify {
						difference = 0
						topics = [][]byte{tokenID, {1}, {}, royalties.Bytes()}
					}
					require.Equal(t, &vmcommon.VMOutput{ReturnCode: vmcommon.Ok, GasRemaining: gas - 7 - uint64(difference), Logs: []*vmcommon.LogEntry{{Identifier: []byte(name), Address: qualContainmentAddress, Topics: topics}}}, out)
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
				if !success {
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
