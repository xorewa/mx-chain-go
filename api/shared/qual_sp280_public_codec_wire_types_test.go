package shared

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP280PublicObservationWireTypes(t *testing.T) {
	// Presentation only: the DTO has no observations or asserted outcomes.
	report := observationTestReport()
	report.Subject = &PublicObservationSubject{
		TokenID:    observationTestPtr(ObservationTokenID("DEMO-abcdef")),
		TokenNonce: observationTestPtr(ObservationUInt64("18446744073709551615")),
		RecordRef:  observationTestPtr(ObservationOpaqueRef("sample display")),
	}
	report.ReportedAtMs = observationTestPtr(ObservationUnixMs("0"))

	wire, err := EncodeObservationReport(report)
	require.NoError(t, err)
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(wire, &object))
	var subject map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(object["subject"], &subject))
	require.Equal(t, `"18446744073709551615"`, string(subject["tokenNonce"]))
	require.Equal(t, `"0"`, string(object["reportedAtMs"]))
	require.Equal(t, "null", string(subject["policyEpoch"]))
	require.Equal(t, "[]", string(object["observations"]))

	decoded, err := DecodeObservationReport(wire)
	require.NoError(t, err)
	require.Equal(t, report, decoded)

	// A future display-only member need not be understood by a v1 reader.
	subject["displayCaption"] = json.RawMessage(`"A sample caption"`)
	object["subject"], err = json.Marshal(subject)
	require.NoError(t, err)
	wire, err = json.Marshal(object)
	require.NoError(t, err)
	decoded, err = DecodeObservationReport(wire)
	require.NoError(t, err)
	require.Equal(t, report, decoded)

	for _, tc := range []struct {
		name, field string
		replacement json.RawMessage
	}{
		{"ordinary scalar type mismatch", "reportedAtMs", json.RawMessage("0")},
		{"ordinary subject type mismatch", "subject", json.RawMessage(`"sample display"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var edited map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(wire, &edited))
			edited[tc.field] = tc.replacement
			editedWire, err := json.Marshal(edited)
			require.NoError(t, err)
			decoded, err := DecodeObservationReport(editedWire)
			require.ErrorIs(t, err, ErrMalformedObservation)
			require.Equal(t, observationLimitation(ObservationMalformed), decoded)
		})
	}
}
