package shared

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP280PublicTokenFieldsPresence(t *testing.T) {
	tokenID := ObservationTokenID("DEMO-abcdef")
	zero := uint64(0)
	zeroDecimal := ObservationUInt64("0")

	absent, err := ObservationSubjectFromPublicTokenFields("", nil)
	require.NoError(t, err)
	require.Nil(t, absent)
	unknown, err := ObservationSubjectFromPublicTokenFields(string(tokenID), nil)
	require.NoError(t, err)
	require.Equal(t, &PublicObservationSubject{TokenID: &tokenID}, unknown)
	known, err := ObservationSubjectFromPublicTokenFields(string(tokenID), &zero)
	require.NoError(t, err)
	require.Equal(t, &PublicObservationSubject{TokenID: &tokenID, TokenNonce: &zeroDecimal}, known)
	_, err = ObservationSubjectFromPublicTokenFields(string([]byte{0xff}), nil)
	require.ErrorIs(t, err, ErrMalformedObservation)
}
