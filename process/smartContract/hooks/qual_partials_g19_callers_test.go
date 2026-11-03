package hooks_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	native "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/multiversx/mx-chain-vm-common-go/mock"
	"github.com/stretchr/testify/require"
)

// These ordinary-call compositions use the real shared storage implementation.
// Mock account maps expose serialized effects; they do not model node rollback.
func TestQualPartialsG19CallerStorageComposition(t *testing.T) {
	for _, row := range []string{"R08", "R09", "R10", "R11", "R12", "R17"} {
		t.Run(row, func(t *testing.T) {
			codec := &marshal.GogoProtoMarshalizer{}
			system := mock.NewUserAccount(vmcommon.SystemAccountAddress)
			address := bytes.Repeat([]byte{7}, 32)
			user := mock.NewUserAccount(address)
			saves := 0
			accounts := &mock.AccountsStub{
				LoadAccountCalled: func(a []byte) (vmcommon.AccountHandler, error) {
					require.Equal(t, vmcommon.SystemAccountAddress, a)
					return system, nil
				},
				SaveAccountCalled: func(a vmcommon.AccountHandler) error {
					require.Equal(t, vmcommon.SystemAccountAddress, a.AddressBytes())
					saves++
					return nil
				},
			}
			flags := &mock.EnableEpochsHandlerStub{IsFlagEnabledCalled: func(core.EnableEpochFlag) bool { return true }}
			settings := &mock.GlobalSettingsHandlerStub{GetTokenTypeCalled: func([]byte) (uint32, error) { return uint32(core.DynamicNFT), nil }}
			storage, err := native.NewESDTDataStorage(native.ArgsNewESDTDataStorage{
				Accounts: accounts, Marshalizer: codec, GlobalSettingsHandler: settings, EnableEpochsHandler: flags,
				ShardCoordinator: &mock.ShardCoordinatorStub{NumberOfShardsCalled: func() uint32 { return 3 }},
			})
			require.NoError(t, err)
			token := []byte("TOKEN-abcdef")
			key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
			full := append(bytes.Clone(key), 1)
			input := &vmcommon.ContractCallInput{RecipientAddr: address, VMInput: vmcommon.VMInput{
				CallerAddr: address, CallValue: big.NewInt(0), GasProvided: 1000000,
			}}
			if row == "R08" {
				require.NoError(t, system.AccountDataHandler().SaveKeyValue(full, []byte("metadata witness")))
				fn, err := native.NewESDTDeleteMetadataFunc(native.ArgsNewESDTDeleteMetadata{
					Marshalizer: codec, Accounts: accounts, AllowedAddress: address, Delete: true, EnableEpochsHandler: flags,
				})
				require.NoError(t, err)
				input.Arguments = [][]byte{token, {1}, {1}, {1}}
				output, err := fn.ProcessBuiltinFunction(nil, nil, input)
				require.NoError(t, err)
				require.NotNil(t, output)
				require.Empty(t, system.Storage[string(full)])
				require.Equal(t, 1, saves)
				return
			}
			if row == "R17" {
				global, err := native.NewESDTGlobalSettingsFunc(accounts, codec, true, core.BuiltInFunctionESDTPause, func() bool { return true })
				require.NoError(t, err)
				fn, err := native.NewESDTSetTokenTypeFunc(accounts, global, codec, func() bool { return true })
				require.NoError(t, err)
				input.CallerAddr = core.ESDTSCAddress
				input.RecipientAddr = vmcommon.SystemAccountAddress
				input.Arguments = [][]byte{token, []byte(core.NonFungibleESDTv2)}
				output, err := fn.ProcessBuiltinFunction(nil, nil, input)
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, output.ReturnCode)
				got, err := global.GetTokenType(key)
				require.NoError(t, err)
				require.Equal(t, uint32(core.NonFungibleV2), got)
				require.NotEmpty(t, system.Storage[string(key)])
				require.Equal(t, 1, saves)
				return
			}
			initial := &esdt.ESDigitalToken{Type: uint32(core.DynamicNFT), Value: big.NewInt(1), TokenMetaData: &esdt.MetaData{
				Nonce: 1, Name: []byte("old"), Creator: []byte("creator"), Hash: []byte("old hash"), Royalties: 10,
			}}
			if row == "R09" {
				initial.Reserved = []byte{1}
				initial.Type = uint32(core.SemiFungible)
				initial.Value = big.NewInt(37)
				initial.Properties = (&native.ESDTUserMetadata{Frozen: true}).ToBytes()
				require.NoError(t, storage.SaveMetaDataToSystemAccount(key, 1, initial))
			}
			encoded, err := codec.Marshal(initial)
			require.NoError(t, err)
			require.NoError(t, user.AccountDataHandler().SaveKeyValue(full, encoded))
			if row == "R09" {
				fn, err := native.NewESDTFreezeWipeFunc(storage, flags, codec, false, true)
				require.NoError(t, err)
				input.CallerAddr = core.ESDTSCAddress
				input.Arguments = [][]byte{append(bytes.Clone(token), 1)}
				output, err := fn.ProcessBuiltinFunction(nil, user, input)
				require.NoError(t, err)
				require.Equal(t, vmcommon.Ok, output.ReturnCode)
				require.Empty(t, user.Storage[string(full)])
				require.Empty(t, system.Storage[string(full)])
				return
			}
			roles := &mock.ESDTRoleHandlerStub{}
			var fn vmcommon.BuiltinFunction
			switch row {
			case "R10":
				fn, err = native.NewESDTMetaDataRecreateFunc(1, vmcommon.BaseOperationCost{StorePerByte: 1}, accounts, settings, storage, roles, flags, codec)
				input.Arguments = [][]byte{token, {1}, []byte("new"), {50}, []byte("new hash"), []byte("attributes"), []byte("uri")}
			case "R11":
				fn, err = native.NewESDTMetaDataUpdateFunc(1, vmcommon.BaseOperationCost{StorePerByte: 1}, accounts, settings, storage, roles, flags, codec)
				input.Arguments = [][]byte{token, {1}, []byte("new"), {}, {}, {}, {}}
			case "R12":
				fn, err = native.NewESDTModifyRoyaltiesFunc(1, accounts, settings, storage, roles, flags, codec)
				input.Arguments = [][]byte{token, {1}, {50}}
			}
			require.NoError(t, err)
			output, err := fn.ProcessBuiltinFunction(user, nil, input)
			require.NoError(t, err)
			require.Equal(t, vmcommon.Ok, output.ReturnCode)
			got := &esdt.ESDigitalToken{}
			require.NoError(t, codec.Unmarshal(got, user.Storage[string(full)]))
			switch row {
			case "R10":
				require.Equal(t, address, got.TokenMetaData.Creator)
				require.Equal(t, []byte("new"), got.TokenMetaData.Name)
				require.Equal(t, uint32(50), got.TokenMetaData.Royalties)
			case "R11":
				require.Equal(t, []byte("new"), got.TokenMetaData.Name)
				require.Equal(t, initial.TokenMetaData.Hash, got.TokenMetaData.Hash)
				require.Equal(t, address, got.TokenMetaData.Creator)
			case "R12":
				require.Equal(t, uint32(50), got.TokenMetaData.Royalties)
				require.Equal(t, initial.TokenMetaData.Name, got.TokenMetaData.Name)
				require.Equal(t, initial.TokenMetaData.Hash, got.TokenMetaData.Hash)
				require.Equal(t, initial.TokenMetaData.Creator, got.TokenMetaData.Creator)
			}
		})
	}
}
