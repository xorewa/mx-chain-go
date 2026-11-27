package groups

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-go/api/shared"
	"github.com/stretchr/testify/require"
)

func TestQualSP280PublicTokenDTOObservationFields(t *testing.T) {
	id := shared.ObservationTokenID("DEMO-abcdef")
	fungible := &esdtTokenData{TokenIdentifier: string(id), Balance: "123", Properties: "example"}
	before, err := json.Marshal(fungible)
	require.NoError(t, err)
	subject, err := fungible.ObservationSubject()
	require.NoError(t, err)
	require.Equal(t, &shared.PublicObservationSubject{TokenID: &id}, subject)
	after, err := json.Marshal(fungible)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.JSONEq(t, `{"tokenIdentifier":"DEMO-abcdef","balance":"123","properties":"example"}`, string(after))

	var missingFungible *esdtTokenData
	subject, err = missingFungible.ObservationSubject()
	require.NoError(t, err)
	require.Nil(t, subject)
	var missingNFT *ESDTNFTTokenData
	subject, err = missingNFT.ObservationSubject()
	require.NoError(t, err)
	require.Nil(t, subject)
}

func TestQualSP280PublicNFTTokenNoncePresentation(t *testing.T) {
	id := shared.ObservationTokenID("DEMO-abcdef")
	for _, tc := range []struct {
		name  string
		nonce uint64
		want  *shared.ObservationUInt64
	}{
		{"omitted zero", 0, nil},
		{"visible exact uint64", math.MaxUint64, observationNonceForTest("18446744073709551615")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := &ESDTNFTTokenData{TokenIdentifier: string(id), Nonce: tc.nonce, Balance: "9", Creator: "ordinary display label"}
			before, err := json.Marshal(token)
			require.NoError(t, err)
			subject, err := token.ObservationSubject()
			require.NoError(t, err)
			require.Equal(t, &shared.PublicObservationSubject{TokenID: &id, TokenNonce: tc.want}, subject)
			after, err := json.Marshal(token)
			require.NoError(t, err)
			require.Equal(t, before, after)
			var ordinary map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(after, &ordinary))
			if tc.want == nil {
				require.NotContains(t, ordinary, "nonce")
			} else {
				require.Equal(t, string(*tc.want), string(ordinary["nonce"]))
			}
		})
	}
}

func observationNonceForTest(v shared.ObservationUInt64) *shared.ObservationUInt64 { return &v }
