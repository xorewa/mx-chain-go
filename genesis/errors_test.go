package genesis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenesisSentinelErrorsShouldRemainStable(t *testing.T) {
	require.Equal(t, "nil entire supply", ErrNilEntireSupply.Error())
	require.Equal(t, "invalid entire supply", ErrInvalidEntireSupply.Error())
	require.Equal(t, "entire supply mismatch", ErrEntireSupplyMismatch.Error())
	require.Equal(t, "duplicate address", ErrDuplicateAddress.Error())
	require.Equal(t, "nil shard coordinator", ErrNilShardCoordinator.Error())
	require.Equal(t, "nil pubkey converter", ErrNilPubkeyConverter.Error())
	require.Equal(t, "nil accounts parser", ErrNilAccountsParser.Error())
	require.Equal(t, "nil Hasher", ErrNilHasher.Error())
	require.Equal(t, "nil Marshalizer", ErrNilMarshalizer.Error())
}
