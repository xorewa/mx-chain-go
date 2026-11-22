package txsFee

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/esdt"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/integrationTests/vm"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
	"github.com/stretchr/testify/require"
)

// This native component control covers the authorized crawler's absent-ID
// exception to the role/balance absence argument. It does not fabricate a
// metachain registration, prove a deployment configuration or establish finality.
// Expected behavior: vm-common v1.7.2 esdtDeleteMetadata.go L197-257.
func TestQualDRWAAbsentCrawlerNativeMetadataControl(t *testing.T) {
	ctx, err := vm.CreatePreparedTxProcessorWithVMs(config.EnableEpochs{}, 1)
	require.NoError(t, err)
	defer ctx.Close()
	accounts, ok := ctx.Accounts.(vmcommon.AccountsAdapter)
	require.True(t, ok)
	allowed := []byte("12345678901234567890123456789012")
	_, err = vm.CreateAccount(ctx.Accounts, core.SystemAccountAddress, 0, big.NewInt(0))
	require.NoError(t, err)
	_, err = ctx.Accounts.Commit()
	require.NoError(t, err)
	token := []byte("AAA-abcdef")
	key := append([]byte(core.ProtectedKeyPrefix+core.ESDTKeyIdentifier), token...)
	key = append(key, byte(1)) // Native computeESDTNFTTokenKey: big-endian nonce 1.
	system, err := ctx.Accounts.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	user := system.(state.UserAccountHandler)
	before := append([]byte(nil), user.GetRootHash()...)
	value, _, _ := user.RetrieveValue(key)
	require.Empty(t, value)
	metadata := &esdt.MetaData{Nonce: 1, Name: []byte("native crawler control")}
	raw, err := ctx.Marshalizer.Marshal(metadata)
	require.NoError(t, err)
	add, err := builtInFunctions.NewESDTDeleteMetadataFunc(builtInFunctions.ArgsNewESDTDeleteMetadata{
		Accounts: accounts, Marshalizer: ctx.Marshalizer, AllowedAddress: allowed,
		EnableEpochsHandler: ctx.EnableEpochsHandler,
	})
	require.NoError(t, err)
	require.True(t, add.IsActive(), "control requires the native SendAlways activation")
	output, err := add.ProcessBuiltinFunction(nil, nil, &vmcommon.ContractCallInput{
		VMInput: vmcommon.VMInput{CallerAddr: allowed, CallValue: big.NewInt(0),
			Arguments: [][]byte{token, {1}, raw}},
		RecipientAddr: allowed, Function: vmcommon.ESDTAddMetadata,
	})
	require.NoError(t, err)
	require.Equal(t, vmcommon.Ok, output.ReturnCode)
	_, err = ctx.Accounts.Commit()
	require.NoError(t, err)
	system, err = ctx.Accounts.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	user = system.(state.UserAccountHandler)
	require.NotEqual(t, before, user.GetRootHash())
	value, _, err = user.RetrieveValue(key)
	require.NoError(t, err)
	stored := &esdt.ESDigitalToken{}
	require.NoError(t, ctx.Marshalizer.Unmarshal(stored, value))
	require.Equal(t, metadata, stored.TokenMetaData)
	require.Zero(t, stored.Value.Sign(), "metadata creation does not create spendable supply")
	t.Logf("AN03 authorized absent-ID crawler wrote native metadata %x", value)
}
