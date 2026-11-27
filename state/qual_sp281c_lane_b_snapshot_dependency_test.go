package state

import (
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/errChan"
	"github.com/stretchr/testify/require"
)

// An empty provider result item is not a usable reference. The local snapshot
// helper must report its error without opening a store or starting a snapshot.
func TestQualSP281CLocalSnapshotMissingReference(t *testing.T) {
	manager := &snapshotsManager{
		protectedChildren: func(common.RootHashHolder) ([]ProtectedChildReference, error) {
			return []ProtectedChildReference{{}}, nil
		},
	}
	fail := errChan.NewErrChanWrapper()
	t.Cleanup(fail.Close)
	manager.snapshotProtectedChildren(nil, 0, nil, fail, nil, nil)
	require.ErrorIs(t, fail.ReadFromChanNonBlocking(), errProtectedChild)
}
