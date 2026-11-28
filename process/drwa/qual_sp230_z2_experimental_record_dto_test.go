package drwa

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// The existing experimental encoding is a detached byte representation, not
// an admitted production codec or authority. Equal ordinary fixture values
// produce equal independent encodings; local DTO edits after serialization
// must not change previously returned bytes.
func TestSP230ExperimentalRecordValueOwnership(t *testing.T) {
	makeRecord := func() PrivilegedConsentScope {
		return PrivilegedConsentScope{
			Domain:  []byte("fixture-domain"),
			Token:   []byte("fixture-token"),
			Program: []byte("fixture-programme"),
			Target:  []byte("fixture-target"),
			Roles:   []byte("fixture-labels"),
			Address: []byte("fixture-display"),
		}
	}
	firstDTO := makeRecord()
	first := encodeExperimentalConsent(firstDTO, 2, 3)
	snapshot := bytes.Clone(first)
	second := encodeExperimentalConsent(makeRecord(), 2, 3)
	require.Equal(t, snapshot, second)

	for _, field := range [][]byte{firstDTO.Domain, firstDTO.Token, firstDTO.Program, firstDTO.Target, firstDTO.Roles, firstDTO.Address} {
		field[0] = 'X'
	}
	require.Equal(t, snapshot, first)
	require.Equal(t, snapshot, second)

	first[0] = 0
	require.Equal(t, snapshot, second)
	require.Equal(t, snapshot, encodeExperimentalConsent(makeRecord(), 2, 3))
}
