package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

type qualM14PredecessorReadFault struct {
	state.UserAccountHandler
	key []byte
	err error
}

func (a *qualM14PredecessorReadFault) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if bytes.Equal(key, a.key) {
		return nil, 0, a.err
	}
	return a.UserAccountHandler.RetrieveValue(key)
}

// M14 R2 §03: literal outcomes around the protected decision and withdrawal
// keys. All predecessors are synthetic native account fixtures. This test
// exercises the read-only classifier, without issuing or withdrawing anything.
func TestQualDRWAM14AdmissionPredecessors(t *testing.T) {
	for _, row := range []struct {
		name, positive, withdrawn string
		issue, withdraw           m14AdmissionPredecessor
	}{
		{"absent", "", "", m14AdmissionNewPositive, m14AdmissionDenied},
		{"exact_positive", "exact", "", m14AdmissionAlreadyRecorded, m14AdmissionNewTombstone},
		{"exact_permanent_withdrawal", "exact", "exact", m14AdmissionDenied, m14AdmissionAlreadyWithdrawn},
		{"tombstone_without_positive", "", "exact", m14AdmissionDenied, m14AdmissionDenied},
		{"conflicting_positive", "conflict", "", m14AdmissionDenied, m14AdmissionDenied},
		{"conflicting_tombstone", "exact", "conflict", m14AdmissionDenied, m14AdmissionDenied},
		{"unrelated_positive_with_matching_tombstone", "conflict", "exact", m14AdmissionDenied, m14AdmissionDenied},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := qualScopedNew(t)
			body, id := f.body(), f.id()
			positiveKey := append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@decision@"), id...)
			withdrawnKey := append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@withdrawn@"), id...)
			conflicting := f.d
			conflicting.commitment = []byte("different immutable commitment")
			conflictBody := qualRecordFrame(f.scope, conflicting.issuer, conflicting.version, conflicting.commitment,
				conflicting.authority, qualA38U64(uint64(conflicting.validUntil)))
			fixtureWrites := map[string][]byte{"exact": body, "conflict": conflictBody}
			if row.positive != "" {
				qualRecordPut(t, f.store, positiveKey, fixtureWrites[row.positive])
			}
			if row.withdrawn != "" {
				qualRecordPut(t, f.store, withdrawnKey, fixtureWrites[row.withdrawn])
			}
			account, err := f.records.codec.state.systemAccount()
			require.NoError(t, err)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			journal := f.store.JournalLen()
			proof := &m14AdmissionCarrier{body: body, decisionID: id}
			check := func(purpose string, expected m14AdmissionPredecessor) {
				actual, e := f.records.classifyM14AdmissionPredecessor(account, purpose, proof)
				require.Equal(t, expected, actual)
				if expected == m14AdmissionDenied {
					require.ErrorIs(t, e, errScopedAdmission)
				} else {
					require.NoError(t, e)
				}
			}
			check("PROGRAMME_ADMISSION_ISSUE", row.issue)
			check("PROGRAMME_ADMISSION_WITHDRAW", row.withdraw)
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
		})
	}
	t.Run("read_error_is_not_absence", func(t *testing.T) {
		f := qualScopedNew(t)
		account, err := f.records.codec.state.systemAccount()
		require.NoError(t, err)
		proof := &m14AdmissionCarrier{body: f.body(), decisionID: f.id()}
		fault := errors.New("synthetic account read failed")
		root, err := f.store.RootHash()
		require.NoError(t, err)
		journal := f.store.JournalLen()
		for _, kind := range []string{"decision", "withdrawn"} {
			key := append([]byte(core.ProtectedKeyPrefix+"DRWA@scopedAdmission@"+kind+"@"), proof.decisionID...)
			reader := &qualM14PredecessorReadFault{UserAccountHandler: account, key: key, err: fault}
			actual, e := f.records.classifyM14AdmissionPredecessor(reader, "PROGRAMME_ADMISSION_ISSUE", proof)
			require.Equal(t, m14AdmissionDenied, actual)
			require.ErrorIs(t, e, fault)
		}
		after, err := f.store.RootHash()
		require.NoError(t, err)
		require.Equal(t, root, after)
		require.Equal(t, journal, f.store.JournalLen())
	})
}
