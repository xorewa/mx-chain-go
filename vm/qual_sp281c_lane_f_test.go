package vm

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFProtectedAddressSelection(t *testing.T) {
	nearby := bytes.Clone(core.SystemAccountAddress)
	nearby[len(nearby)-1] ^= 1
	require.False(t, DRWADeletionTargetsProtectedAccount(nil))
	require.False(t, DRWADeletionTargetsProtectedAccount([][]byte{nil, nearby, core.SystemAccountAddress[:len(nearby)-1]}))
	require.True(t, DRWADeletionTargetsProtectedAccount([][]byte{nearby, bytes.Clone(core.SystemAccountAddress)}))
}
