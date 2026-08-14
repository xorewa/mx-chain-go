package hooks

import (
	"testing"

	coreSharding "github.com/multiversx/mx-chain-core-go/core/sharding"
	"github.com/stretchr/testify/require"
)

// The production adapter has no shard coordinator. For any absent 32-byte
// holder address, AccountsDB.LoadAccount creates a fresh account in this local
// AccountsDB and the adapter persists the holder profile there. In a real
// multi-shard node this same mechanism cannot distinguish an in-shard fresh
// holder from an address whose computed home is another shard.
func TestCharacterization_DRWAAdapterMaterializesAbsentHolderInLocalAccountsDB(t *testing.T) {
	accounts := createRealAccountsDBForDRWATest(t)
	adapter, err := newDRWAHookStateAdapter(accounts)
	require.NoError(t, err)

	// Under a three-shard topology this address belongs to shard 1, so it is
	// remote-shaped from the perspective of a shard-0 adapter.
	holderAddress := make([]byte, drwaAuthorizedCallerAddressLen)
	holderAddress[len(holderAddress)-1] = 1
	require.Equal(t, uint32(1), coreSharding.ComputeShardID(holderAddress, 3))
	_, err = accounts.GetExistingAccount(holderAddress)
	require.Error(t, err)

	require.NoError(t, adapter.PutHolderProfileBody(
		string(holderAddress),
		1,
		[]byte(`{"kyc_status":"approved","aml_status":"clear"}`),
	))

	materialized, err := accounts.GetExistingAccount(holderAddress)
	require.NoError(t, err)
	require.Equal(t, holderAddress, materialized.AddressBytes())

	version, err := adapter.GetHolderProfileVersion(string(holderAddress))
	require.NoError(t, err)
	require.Equal(t, uint64(1), version)
}
