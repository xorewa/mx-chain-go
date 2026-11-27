package accounts

import (
	"math/big"
	"testing"
)

func TestQualSP281COrdinaryPeerNestedDTOGetters(t *testing.T) {
	amount := big.NewInt(17)
	dto := &PeerAccountData{
		ValidatorSuccessRate:      SignRate{NumSuccess: 1, NumFailure: 2},
		LeaderSuccessRate:         SignRate{NumSuccess: 3, NumFailure: 4},
		TotalValidatorSuccessRate: SignRate{NumSuccess: 5, NumFailure: 6},
		TotalLeaderSuccessRate:    SignRate{NumSuccess: 7, NumFailure: 8},
		AccumulatedFees:           amount,
	}
	var absent *PeerAccountData
	for _, tc := range []struct {
		label string
		get   func(*PeerAccountData) SignRate
		want  SignRate
	}{
		{"first value", (*PeerAccountData).GetValidatorSuccessRate, SignRate{NumSuccess: 1, NumFailure: 2}},
		{"second value", (*PeerAccountData).GetLeaderSuccessRate, SignRate{NumSuccess: 3, NumFailure: 4}},
		{"third value", (*PeerAccountData).GetTotalValidatorSuccessRate, SignRate{NumSuccess: 5, NumFailure: 6}},
		{"fourth value", (*PeerAccountData).GetTotalLeaderSuccessRate, SignRate{NumSuccess: 7, NumFailure: 8}},
	} {
		if got, empty := tc.get(dto), tc.get(absent); got != tc.want || empty != (SignRate{}) {
			t.Errorf("unexpected nested DTO display value: %s", tc.label)
		}
	}
	if got := dto.GetAccumulatedFees(); got == nil || got.Cmp(big.NewInt(17)) != 0 || absent.GetAccumulatedFees() != nil {
		t.Fatal("unexpected scalar amount display value")
	}
}
