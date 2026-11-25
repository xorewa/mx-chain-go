package trie

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

// Reuse the existing ordinary extension-node fixture with an inert read callback.
func TestQualOrdinaryExtensionLookupReadError(t *testing.T) {
	t.Parallel()

	_, collapsed := getEnAndCollapsedEn()
	key := []byte{'d', 2, 'd', 'o', 'g'}
	readErr := errors.New("mock read unavailable")
	const identifier = "mock-store"
	calls := 0
	db := testscommon.NewMemDbMock()
	db.GetIdentifierCalled = func() string { return identifier }
	db.GetCalled = func(got []byte) ([]byte, error) {
		calls++
		require.Equal(t, collapsed.EncodedChild, got)
		return nil, readErr
	}

	value, depth, version, err := collapsed.tryGetWithVersion(key, 0, db)
	require.Equal(t, core.NewGetNodeFromDBErrWithKey(collapsed.EncodedChild, readErr, identifier), err)
	require.Nil(t, value)
	require.Zero(t, depth)
	require.Zero(t, version)
	require.Equal(t, 1, calls)
}
