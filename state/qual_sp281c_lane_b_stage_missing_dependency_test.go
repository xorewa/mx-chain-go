package state

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/require"
)

// These calls have no usable input, account, record, decoder, or store. They
// exercise only early dependency/result checks and must not start an operation.
func TestQualSP281CLocalStageMissingDependency(t *testing.T) {
	t.Run("retained_error", func(t *testing.T) {
		expected := errors.New("local previous error")
		db := &AccountsDB{protectedCommitFailure: expected}
		require.ErrorIs(t, db.StageProtectedChildTrie(nil, nil, nil, nil, nil), expected)
	})
	t.Run("absent_input", func(t *testing.T) {
		db := &AccountsDB{}
		require.ErrorIs(t, db.StageProtectedChildTrie(nil, nil, nil, nil, nil), errProtectedChild)
	})
	t.Run("unavailable_dependency", func(t *testing.T) {
		db := &AccountsDB{}
		// The opaque placeholders only distinguish absent input from absent
		// dependency; no content is decoded or presented as a record.
		require.ErrorIs(t, db.StageProtectedChildTrie(nil, nil, nil, []byte("local placeholder"), []core.TrieData{{}}), errProtectedChild)
		result, err := db.StageDerivedProtectedChildTrie(nil, nil, nil, nil, nil, nil)
		require.ErrorIs(t, err, errProtectedChild)
		require.Nil(t, result)
	})
}
