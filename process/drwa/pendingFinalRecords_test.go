package drwa

import (
	"bytes"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPendingFinalRecords_ReadBounds(t *testing.T) {
	f := qualPendingFinalNew(t)
	qualRecordPut(t, f.s, f.finalKey, bytes.Repeat([]byte{1}, f.r.codec.maxBytes+1))
	_, err := f.r.read(f.finalKey)
	require.Error(t, err)
	scope := qualScopedNew(t)
	_, err = scope.records.scope(nil, scope.d.program)
	require.Error(t, err)
	var a *RegistrationAdmission
	require.True(t, a.IsInterfaceNil())
	require.False(t, (&RegistrationAdmission{}).IsInterfaceNil())
	var c *RegistrationCancellation
	require.True(t, c.IsInterfaceNil())
	require.False(t, (&RegistrationCancellation{}).IsInterfaceNil())
	err = a.RegisterTokenForAuthenticatedCreation(nil, nil, nil, nil, nil, nil, nil, nil, 0, nil)
	require.Error(t, err)
	err = a.RegisterTokenForCommittedCreation(nil, nil, nil, nil, nil, nil, 0, nil, nil)
	require.Error(t, err)
	var candidate *registrationCandidate
	_, err = candidate.BindIntent(nil, nil, nil, nil, nil, 0)
	require.Error(t, err)
	require.Error(t, candidate.DRWAExecutionError())
	require.Error(t, candidate.DRWAExecutionHealthError())
	_, err = candidate.WithTokenClassification(nil, nil, func(bool) (*vmcommon.VMOutput, error) { t.Fatal("missing owner authorized execution"); return nil, nil })
	require.Error(t, err)
}
