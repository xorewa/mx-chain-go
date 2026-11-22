package drwa

import (
	"bytes"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRegistrationCandidate_WithDRWAClassifierReplacement(t *testing.T) {
	old, _, _ := qualRegistrationCandidate(t, false, false)
	next := *old
	called := false
	require.Error(t, old.WithDRWAClassifierReplacement(&next, func() { called = true }))
	require.False(t, called)
}

func TestRegistrationCandidate_WithTokenClassificationBounds(t *testing.T) {
	admin := qualAdminNew(t)
	for _, payload := range [][]byte{nil, bytes.Repeat([]byte{1}, admin.carrier.codec.maxBytes+1)} {
		_, err := admin.carrier.normalized(payload, []byte("pause"))
		require.Error(t, err)
	}
	qualRecordPut(t, admin.store, admin.appliedKey(), bytes.Repeat([]byte{1}, admin.carrier.codec.maxBytes+1))
	_, err := admin.carrier.readApplied(admin.appliedKey())
	require.Error(t, err)
	scope := qualScopedNew(t)
	_, err = newScopedAdmissionRecords(scope.store, scope.boundary, nil, scope.records.codec.hasher, scope.records.domain, scope.records.limits, scope.mandates, scope.records.timeSource)
	require.Error(t, err)
	_, err = newScopedAdmissionRecords(scope.store, scope.boundary, scope.records.codec.marshaller, scope.records.codec.hasher, bytes.Repeat([]byte{1}, scope.records.limits.recordBytes+1), scope.records.limits, scope.mandates, scope.records.timeSource)
	require.Error(t, err)
	candidate, store, _ := qualRegistrationCandidate(t, false, false)
	_, err = candidate.BindIntent(nil, nil, nil, nil, nil, 0)
	require.Error(t, err)
	calls := 0
	execute := func(bool) (*vmcommon.VMOutput, error) {
		calls++
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}
	candidate.view.parent.mut.Lock()
	out, err := candidate.WithTokenClassification(store, []byte("TOKEN-abcdef"), execute)
	candidate.view.parent.mut.Unlock()
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.Nil(t, out)
	require.Zero(t, calls)
	require.NoError(t, candidate.abort())
	out, err = candidate.WithTokenClassification(store, []byte("TOKEN-abcdef"), execute)
	require.ErrorIs(t, err, ErrExecutionClosed)
	require.Nil(t, out)
	require.Zero(t, calls)
}
