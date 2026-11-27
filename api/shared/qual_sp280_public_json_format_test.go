package shared

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP280PublicObservationOrdinaryJSONFormat(t *testing.T) {
	// A source-free empty display report is the only valid fixture.
	report := observationTestReport()
	wire, err := EncodeObservationReport(report)
	require.NoError(t, err)
	require.NotEmpty(t, wire)
	require.Equal(t, byte('}'), wire[len(wire)-1])

	// These represent ordinary text-transfer damage or a handwritten JSON typo.
	// No operation data or producer is involved.
	badEncoding := []byte("{\"caption\":\"sample ")
	badEncoding = append(badEncoding, 0xff)
	badEncoding = append(badEncoding, []byte("\"}")...)
	unterminated := append([]byte(nil), wire[:len(wire)-1]...)
	unquotedCaption := append([]byte(nil), unterminated...)
	unquotedCaption = append(unquotedCaption, []byte(`,caption:"sample"}`)...)

	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"non UTF8 caption", badEncoding},
		{"incomplete closing delimiter", unterminated},
		{"unquoted display member", unquotedCaption},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeObservationReport(tc.wire)
			require.ErrorIs(t, err, ErrMalformedObservation)
			require.Equal(t, observationLimitation(ObservationMalformed), decoded)
		})
	}
	decoded, err := DecodeObservationReport(wire)
	require.NoError(t, err)
	require.Equal(t, report, decoded)
}
