package shared

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP280PublicObservationEnvelope(t *testing.T) {
	// Use only an existing ordinary public token representation. It does not
	// establish an observation or producer; the supplied report is UNKNOWN.
	nonce := uint64(0)
	subject, err := ObservationSubjectFromPublicTokenFields("DEMO-abcdef", &nonce)
	require.NoError(t, err)
	report := ObservationReportV1{
		SchemaVersion: ObservationVersionV1,
		Availability:  ObservationUnknown,
		Subject:       subject,
	}

	envelope, err := ObservationPresentationEnvelope(report)
	require.NoError(t, err)
	require.Equal(t, ReturnCodeSuccess, envelope.Code)
	require.Empty(t, envelope.Error)
	wire, err := json.Marshal(envelope)
	require.NoError(t, err)

	var outer map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(wire, &outer))
	require.Len(t, outer, 3)
	require.Equal(t, `"successful"`, string(outer["code"]))
	require.Equal(t, `""`, string(outer["error"]))
	require.JSONEq(t, `{
		"schemaVersion":"drwa-observation-v1",
		"availability":"UNKNOWN",
		"subject":{
			"recordRef":null,"effectRef":null,"contextRef":null,
			"transactionHash":null,"originalTransactionHash":null,
			"originalBatchId":null,"originalBatchRef":null,
			"tokenId":"DEMO-abcdef","tokenNonce":"0",
			"holderAddress":null,"beneficiaryAddress":null,
			"policyVersionRef":null,"policyEpoch":null
		},
		"observations":null,"reportedAtMs":null
	}`, string(outer["data"]))
	decoded, err := DecodeObservationReport(outer["data"])
	require.NoError(t, err)
	require.Equal(t, report, decoded)
}

func TestQualSP280PublicObservationEnvelopeInvalidPresentation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		report ObservationReportV1
		err    error
	}{
		{"unsupported version", ObservationReportV1{SchemaVersion: "future-display"}, ErrUnsupportedObservationVersion},
		{"invalid display list", ObservationReportV1{SchemaVersion: ObservationVersionV1, Availability: ObservationAvailable}, ErrMalformedObservation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope, err := ObservationPresentationEnvelope(tc.report)
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, GenericAPIResponse{}, envelope)
		})
	}
}
