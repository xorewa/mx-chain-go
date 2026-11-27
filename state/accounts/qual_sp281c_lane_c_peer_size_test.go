package accounts

import "testing"

func TestQualSP281COrdinaryPeerDTOSize(t *testing.T) {
	t.Run("sign_rate_scalar_size", func(t *testing.T) {
		var absent *SignRate
		for _, tc := range []struct {
			dto  *SignRate
			want int
		}{
			{absent, 0}, {&SignRate{}, 0}, {&SignRate{NumSuccess: 7, NumFailure: 128}, 5},
		} {
			if direct, legacy := tc.dto.Size(), tc.dto.XXX_Size(); direct != tc.want || legacy != tc.want {
				t.Fatalf("scalar size: direct=%d legacy=%d want=%d", direct, legacy, tc.want)
			}
		}
	})
	t.Run("peer_scalar_size", func(t *testing.T) {
		var absent *PeerAccountData
		for _, tc := range []struct {
			dto  *PeerAccountData
			want int
		}{
			{absent, 0}, {&PeerAccountData{}, 11}, {&PeerAccountData{Nonce: 128}, 15},
		} {
			if direct, legacy := tc.dto.Size(), tc.dto.XXX_Size(); direct != tc.want || legacy != tc.want {
				t.Fatalf("scalar size: direct=%d legacy=%d want=%d", direct, legacy, tc.want)
			}
		}
	})
}
