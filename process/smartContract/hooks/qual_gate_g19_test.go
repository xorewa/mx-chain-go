package hooks_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

func TestQualGateG19MetadataStorageComposition(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "fixed"}[active], func(t *testing.T) {
			codec := &marshal.GogoProtoMarshalizer{}
			system := mock.NewUserAccount(vmcommon.SystemAccountAddress)
			user := mock.NewUserAccount(bytes.Repeat([]byte{7}, 32))
			loadError := error(nil)
			storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{
				Accounts: &mock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
					require.Equal(t, vmcommon.SystemAccountAddress, address)
					if loadError != nil {
						return nil, loadError
					}
					return system, nil
				}},
				GlobalSettingsHandler: &mock.GlobalSettingsHandlerStub{}, Marshalizer: codec,
				EnableEpochsHandler: &mock.EnableEpochsHandlerStub{IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
					return flag == builtInFunctions.SaveToSystemAccountFlag || flag == builtInFunctions.SendAlwaysFlag || (active && flag == builtInFunctions.FixCorrectSmallIntAndGasLimitsFlag)
				}},
				ShardCoordinator: &mock.ShardCoordinatorStub{NumberOfShardsCalled: func() uint32 { return 3 }},
			})
			require.NoError(t, err)
			key := []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "TOKEN-abcdef")
			nonce := uint64(1)
			fullKey := append(bytes.Clone(key), byte(1))
			initial := &esdt.ESDigitalToken{Type: uint32(core.DynamicSFT), Value: big.NewInt(500), Properties: []byte{1, 2, 3}, TokenMetaData: &esdt.MetaData{Name: []byte("old")}, Reserved: []byte{1}}
			require.NoError(t, storage.SaveMetaDataToSystemAccount(key, nonce, initial))
			incoming := &esdt.ESDigitalToken{Type: uint32(core.DynamicSFT), Value: big.NewInt(10), TokenMetaData: &esdt.MetaData{Name: []byte("new")}, Reserved: []byte{1}}
			_, err = storage.SaveESDTNFTToken(user.AddressBytes(), user, key, nonce, incoming, vmcommon.NftSaveArgs{MustUpdateAllFields: true})
			require.NoError(t, err)
			saved, err := storage.GetMetaDataFromSystemAccount(key, nonce)
			require.NoError(t, err)
			require.Equal(t, []byte("new"), saved.TokenMetaData.Name)
			require.Equal(t, uint32(core.DynamicSFT), saved.Type)
			if active {
				require.Equal(t, big.NewInt(500), saved.Value)
				require.Equal(t, []byte{1, 2, 3}, saved.Properties)
			} else {
				require.Zero(t, saved.Value.Sign())
				require.Equal(t, []byte{0, 0, 0}, saved.Properties)
			}
			// A destination read merges metadata without replacing account-local Frozen.
			frozen := &esdt.ESDigitalToken{Type: uint32(core.DynamicSFT), Value: big.NewInt(10), Properties: (&builtInFunctions.ESDTUserMetadata{Frozen: true}).ToBytes()}
			encoded, err := codec.Marshal(frozen)
			require.NoError(t, err)
			require.NoError(t, user.AccountDataHandler().SaveKeyValue(fullKey, encoded))
			got, isNew, err := storage.GetESDTNFTTokenOnDestination(user, key, nonce)
			require.NoError(t, err)
			require.False(t, isNew)
			require.Equal(t, frozen.Properties, got.Properties)
			require.Equal(t, frozen.Value, got.Value)
			require.Equal(t, []byte("new"), got.TokenMetaData.Name)
			loadError = errors.New("missing system account")
			_, _, err = storage.GetESDTNFTTokenOnDestination(user, key, nonce)
			require.ErrorIs(t, err, loadError)
			after, _, err := user.AccountDataHandler().RetrieveValue(fullKey)
			require.NoError(t, err)
			require.Equal(t, encoded, after)
		})
	}
}
