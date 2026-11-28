package drwa

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func TestRepairPreservationLifecycleObservations(t *testing.T) {
	// Separate ordinary programme projections; neither fixture is an actual
	// repair request or an assertion of admitted CEB/profile authority.
	originOne := bytes.Repeat([]byte{1}, 32)
	originTwo := bytes.Repeat([]byte{2}, 32)
	originOtherShard := bytes.Repeat([]byte{3}, 32)
	first := lifecycleCEBFields{
		closurePlan: []byte("burn-and-retire"), supplyOrigin: bytes.Clone(originOne),
		supplyOriginShard: 1, tokenType: uint32(core.Fungible),
	}
	same := lifecycleCEBFields{
		closurePlan: []byte("burn-and-retire"), supplyOrigin: bytes.Clone(originOne),
		supplyOriginShard: 1, tokenType: uint32(core.Fungible),
	}
	t.Run("separate_equivalent_projections", func(t *testing.T) {
		require.Equal(t, repairLifecycleComparison{true, true, true, true}, compareRepairLifecycleFields(first, same))
	})

	cases := []struct {
		name  string
		other lifecycleCEBFields
		want  repairLifecycleComparison
	}{
		{"other_closure_plan", lifecycleCEBFields{[]byte("preserve-and-close"), bytes.Clone(originOne), 1, uint32(core.Fungible)}, repairLifecycleComparison{false, true, true, true}},
		{"other_origin", lifecycleCEBFields{[]byte("burn-and-retire"), bytes.Clone(originTwo), 1, uint32(core.Fungible)}, repairLifecycleComparison{true, false, true, true}},
		{"other_shard_and_origin", lifecycleCEBFields{[]byte("burn-and-retire"), bytes.Clone(originOtherShard), 2, uint32(core.Fungible)}, repairLifecycleComparison{true, false, false, true}},
		{"other_token_type", lifecycleCEBFields{[]byte("burn-and-retire"), bytes.Clone(originOne), 1, uint32(core.SemiFungible)}, repairLifecycleComparison{true, true, true, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, compareRepairLifecycleFields(first, tc.other))
			require.Equal(t, tc.want, compareRepairLifecycleFields(tc.other, first))
		})
	}
}

func TestRepairPreservationSupplyObservations(t *testing.T) {
	// The values here are small synthetic independent accounting checkpoints
	// used only for a nominal arithmetic comparison. They are not limits.
	t.Run("observed_zero_is_equal", func(t *testing.T) {
		require.Equal(t, repairSupplyComparison{true, true, true}, compareRepairSupplyAccounting(newSupplyAccounting(), newSupplyAccounting()))
	})
	first := &supplyAccounting{big.NewInt(10), big.NewInt(8), 3}
	cases := []struct {
		name  string
		other *supplyAccounting
		want  repairSupplyComparison
	}{
		{"separate_equal_amounts", &supplyAccounting{big.NewInt(10), big.NewInt(8), 3}, repairSupplyComparison{true, true, true}},
		{"distinct_issue_observations", &supplyAccounting{big.NewInt(12), big.NewInt(8), 3}, repairSupplyComparison{false, true, true}},
		{"distinct_live_observations", &supplyAccounting{big.NewInt(10), big.NewInt(7), 3}, repairSupplyComparison{true, false, true}},
		{"distinct_nonce_observations", &supplyAccounting{big.NewInt(10), big.NewInt(8), 4}, repairSupplyComparison{true, true, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, compareRepairSupplyAccounting(first, tc.other))
			require.Equal(t, tc.want, compareRepairSupplyAccounting(tc.other, first))
			require.Equal(t, "10", first.cumulativeIssued.String())
			require.Equal(t, "8", first.liveSupply.String())
		})
	}
	t.Run("unavailable_observation_is_not_zero", func(t *testing.T) {
		zero := newSupplyAccounting()
		require.Equal(t, repairSupplyComparison{}, compareRepairSupplyAccounting(nil, zero))
		require.Equal(t, repairSupplyComparison{}, compareRepairSupplyAccounting(zero, nil))
		require.Equal(t, repairSupplyComparison{}, compareRepairSupplyAccounting(nil, nil))
		require.False(t, compareObservedRepairAmount(nil, big.NewInt(0)))
		require.False(t, compareObservedRepairAmount(big.NewInt(0), nil))
		require.False(t, compareObservedRepairAmount(nil, nil))
	})
}
