package process

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Detached fee-display values: no transaction, calculation or account is involved.
func TestQualSP218OrdinaryFeeInfoDisplayOwnership(t *testing.T) {
	t.Parallel()

	first, second := newFeeInfo(), newFeeInfo()
	require.NotSame(t, first, second)
	for _, fee := range []*big.Int{first.Fee, first.InitialPaidFee, second.Fee, second.InitialPaidFee} {
		require.NotNil(t, fee)
		require.Equal(t, "0", fee.String())
	}
	require.Zero(t, first.GasUsed)
	require.Zero(t, second.GasUsed)

	// Populate only a private presentation DTO and retain ownership of all other values.
	first.GasUsed = 7
	first.Fee.SetInt64(19)
	require.Equal(t, "0", first.InitialPaidFee.String())
	require.Equal(t, "0", second.Fee.String())
	require.Equal(t, "0", second.InitialPaidFee.String())
	first.InitialPaidFee.SetInt64(42)
	require.Equal(t, "19", first.Fee.String())
	require.Equal(t, "0", second.Fee.String())
	require.Equal(t, "0", second.InitialPaidFee.String())
	require.Zero(t, second.GasUsed)

	wire, err := json.Marshal(first)
	require.NoError(t, err)
	require.Equal(t, `{"gasUsed":7,"fee":19,"initialPaidFee":42}`, string(wire))
}
