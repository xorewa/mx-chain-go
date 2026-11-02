package hooks_test

import (
	"bytes"
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

// Real storage helper, with the serialized legacy nil value entering through
// the same account-data interface used by the ordinary liquidity path.
func TestQualPartialsG19NilLiquidity(t *testing.T) {
	codec := &marshal.GogoProtoMarshalizer{}
	system := mock.NewUserAccount(vmcommon.SystemAccountAddress)
	accounts := &mock.AccountsStub{LoadAccountCalled: func(address []byte) (vmcommon.AccountHandler, error) {
		require.Equal(t, vmcommon.SystemAccountAddress, address)
		return system, nil
	}}
	flags := &mock.EnableEpochsHandlerStub{IsFlagEnabledCalled: func(flag core.EnableEpochFlag) bool {
		return flag == builtInFunctions.SaveToSystemAccountFlag || flag == builtInFunctions.SendAlwaysFlag
	}}
	storage, err := builtInFunctions.NewESDTDataStorage(builtInFunctions.ArgsNewESDTDataStorage{
		Accounts: accounts, Marshalizer: codec, GlobalSettingsHandler: &mock.GlobalSettingsHandlerStub{},
		EnableEpochsHandler: flags, ShardCoordinator: &mock.ShardCoordinatorStub{NumberOfShardsCalled: func() uint32 { return 3 }},
	})
	require.NoError(t, err)
	key := []byte(core.ProtectedKeyPrefix + core.ESDTKeyIdentifier + "TOKEN-abcdef")
	full := append(bytes.Clone(key), 1)
	token := &esdt.ESDigitalToken{Type: uint32(core.DynamicSFT), Value: nil, Reserved: []byte{1}, TokenMetaData: &esdt.MetaData{Nonce: 1, Name: []byte("legacy")}}
	encoded, err := codec.Marshal(token)
	require.NoError(t, err)
	require.NoError(t, system.AccountDataHandler().SaveKeyValue(full, encoded))
	require.NoError(t, storage.AddToLiquiditySystemAcc(key, uint32(core.DynamicSFT), 1, big.NewInt(10), true))
	got, err := storage.GetMetaDataFromSystemAccount(key, 1)
	require.NoError(t, err)
	require.Equal(t, big.NewInt(10), got.Value)
	require.Equal(t, token.TokenMetaData, got.TokenMetaData)
	// Zero nonce is fungible and cannot mutate this NFT liquidity record.
	before, _, err := system.AccountDataHandler().RetrieveValue(full)
	require.NoError(t, err)
	require.NoError(t, storage.AddToLiquiditySystemAcc(key, uint32(core.DynamicSFT), 0, big.NewInt(99), true))
	after, _, err := system.AccountDataHandler().RetrieveValue(full)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
