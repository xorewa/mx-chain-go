package shared

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/api"
	"github.com/stretchr/testify/require"
)

func TestQualSP280PublicBlockInfoPresence(t *testing.T) {
	hash := ObservationHash(strings.Repeat("a", 64))
	nonce := ObservationUInt64("18446744073709551615")
	for _, tc := range []struct {
		name string
		info *api.BlockInfo
		want *PublicObservationProvenance
	}{
		{"absent", nil, nil},
		{"root only", &api.BlockInfo{RootHash: "ordinary label"}, nil},
		{"hash with omitted nonce", &api.BlockInfo{Hash: string(hash)}, &PublicObservationProvenance{AsOfBlockHash: &hash}},
		{"visible nonce", &api.BlockInfo{Nonce: math.MaxUint64}, &PublicObservationProvenance{AsOfBlockNonce: &nonce}},
		{"both coordinates", &api.BlockInfo{Hash: string(hash), Nonce: math.MaxUint64, RootHash: "ordinary label"}, &PublicObservationProvenance{AsOfBlockHash: &hash, AsOfBlockNonce: &nonce}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := json.Marshal(tc.info)
			require.NoError(t, err)
			provenance, err := ObservationProvenanceFromPublicBlockInfo(tc.info)
			require.NoError(t, err)
			require.Equal(t, tc.want, provenance)
			after, err := json.Marshal(tc.info)
			require.NoError(t, err)
			require.Equal(t, before, after)
			if tc.info != nil && tc.info.Nonce == 0 {
				var ordinary map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(after, &ordinary))
				require.NotContains(t, ordinary, "nonce")
			}
		})
	}
	provenance, err := ObservationProvenanceFromPublicBlockInfo(&api.BlockInfo{Hash: "ordinary display label"})
	require.ErrorIs(t, err, ErrMalformedObservation)
	require.Nil(t, provenance)
}
