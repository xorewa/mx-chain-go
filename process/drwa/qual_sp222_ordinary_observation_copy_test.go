package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP222OrdinaryObservationCopyOwnership(t *testing.T) {
	t.Parallel()

	// These are opaque sample labels, not encoded headers or proofs.
	original := canonicalResultWitness{
		Consumer: []byte("consumer label"), HeaderProof: []byte("header label"),
		Account: AccountItemWitness{
			Header: []byte("first label"), ExecutedHeader: []byte("second label"),
			AccountProof: [][]byte{[]byte("account label")},
			DataProof:    [][]byte{[]byte("data label")},
		},
		MetaHeaders: [][]byte{[]byte("meta one"), []byte("meta two")},
		MetaProofs:  [][]byte{[]byte("note label")},
	}
	copyView := cloneCanonicalResultWitness(original)
	require.Equal(t, original, copyView)

	copyView.Consumer[0] = 'C'
	copyView.HeaderProof[0] = 'H'
	copyView.Account.Header[0] = 'F'
	copyView.Account.ExecutedHeader[0] = 'S'
	copyView.Account.AccountProof[0][0] = 'A'
	copyView.Account.DataProof[0][0] = 'D'
	copyView.MetaHeaders[0][0] = 'M'
	copyView.MetaHeaders[1] = []byte("replacement label")
	copyView.MetaProofs[0][0] = 'N'

	require.Equal(t, []byte("consumer label"), original.Consumer)
	require.Equal(t, []byte("header label"), original.HeaderProof)
	require.Equal(t, []byte("first label"), original.Account.Header)
	require.Equal(t, []byte("second label"), original.Account.ExecutedHeader)
	require.Equal(t, [][]byte{[]byte("account label")}, original.Account.AccountProof)
	require.Equal(t, [][]byte{[]byte("data label")}, original.Account.DataProof)
	require.Equal(t, [][]byte{[]byte("meta one"), []byte("meta two")}, original.MetaHeaders)
	require.Equal(t, [][]byte{[]byte("note label")}, original.MetaProofs)
}
