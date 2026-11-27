package shared

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/stretchr/testify/require"
)

func TestQualSP280PublicObservationIndependentHashPresence(t *testing.T) {
	// Public DTO fields are independent optional display values, not outcomes.
	hash := ObservationHash(strings.Repeat("a", 64))
	original := ObservationHash(strings.Repeat("b", 64))
	for _, tc := range []struct {
		name                   string
		dto                    transaction.ApiTransactionResult
		want                   PublicObservationSubject
		wantHash, wantOriginal string
	}{
		{
			name:     "transaction hash only",
			dto:      transaction.ApiTransactionResult{Hash: string(hash)},
			want:     PublicObservationSubject{TransactionHash: &hash},
			wantHash: `"` + string(hash) + `"`, wantOriginal: "null",
		},
		{
			name:     "original hash only",
			dto:      transaction.ApiTransactionResult{OriginalTransactionHash: string(original)},
			want:     PublicObservationSubject{OriginalTransactionHash: &original},
			wantHash: "null", wantOriginal: `"` + string(original) + `"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject, err := ObservationSubjectFromPublicTransaction(&tc.dto)
			require.NoError(t, err)
			require.Equal(t, &tc.want, subject)

			report := observationTestReport()
			report.Subject = subject
			wire, err := EncodeObservationReport(report)
			require.NoError(t, err)

			var fields struct {
				Subject map[string]json.RawMessage `json:"subject"`
			}
			require.NoError(t, json.Unmarshal(wire, &fields))
			require.Equal(t, tc.wantHash, string(fields.Subject["transactionHash"]))
			require.Equal(t, tc.wantOriginal, string(fields.Subject["originalTransactionHash"]))

			decoded, err := DecodeObservationReport(wire)
			require.NoError(t, err)
			require.Equal(t, report, decoded)
		})
	}
}
