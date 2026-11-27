package accounts

import "testing"

func TestQualSP281COrdinaryPeerScalarGetters(t *testing.T) {
	t.Run("sign_rate_scalar", func(t *testing.T) {
		dto := &SignRate{NumSuccess: 7, NumFailure: 11}
		var absent *SignRate
		if dto.GetNumSuccess() != 7 || dto.GetNumFailure() != 11 || absent.GetNumSuccess() != 0 || absent.GetNumFailure() != 0 {
			t.Fatal("unexpected scalar DTO getter results")
		}
	})
	t.Run("peer_report_scalars", func(t *testing.T) {
		const wideNonce uint64 = 1<<40 + 17
		dto := &PeerAccountData{ShardId: 2, ValidatorIgnoredSignaturesRate: 3, Rating: 4, TempRating: 5, NumSelectedInSuccessBlocks: 6, ConsecutiveProposerMisses: 7, TotalValidatorIgnoredSignaturesRate: 8, Nonce: wideNonce, UnStakedEpoch: 9}
		var absent *PeerAccountData
		for _, tc := range []struct {
			label string
			get   func(*PeerAccountData) uint32
			want  uint32
		}{
			{"shard scalar", (*PeerAccountData).GetShardId, 2},
			{"ignored scalar", (*PeerAccountData).GetValidatorIgnoredSignaturesRate, 3},
			{"rating scalar", (*PeerAccountData).GetRating, 4},
			{"temporary scalar", (*PeerAccountData).GetTempRating, 5},
			{"selected scalar", (*PeerAccountData).GetNumSelectedInSuccessBlocks, 6},
			{"misses scalar", (*PeerAccountData).GetConsecutiveProposerMisses, 7},
			{"total scalar", (*PeerAccountData).GetTotalValidatorIgnoredSignaturesRate, 8},
			{"epoch scalar", (*PeerAccountData).GetUnStakedEpoch, 9},
		} {
			if got, zero := tc.get(dto), tc.get(absent); got != tc.want || zero != 0 {
				t.Errorf("%s: value=%d absent=%d want=%d", tc.label, got, zero, tc.want)
			}
		}
		if dto.GetNonce() != wideNonce || absent.GetNonce() != 0 {
			t.Fatal("unexpected wide scalar DTO getter")
		}
	})
}
