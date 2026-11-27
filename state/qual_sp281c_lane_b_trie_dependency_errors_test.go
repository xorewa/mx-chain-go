package state

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

type localRecreateFailure struct {
	common.Trie
	err error
}

func (stub *localRecreateFailure) Recreate(common.RootHashHolder) (common.Trie, error) {
	return nil, stub.err
}

type localRootReadFailure struct {
	DataTrie
	err    error
	result []byte
}

func (stub *localRootReadFailure) RootHash() ([]byte, error) {
	return stub.result, stub.err
}

// Both dependencies fail before any real trie or state operation. The fixture
// supplies no root, record, account, or ownership data.
func TestQualSP281CLocalTrieDependencyErrors(t *testing.T) {
	t.Run("recreate_error", func(t *testing.T) {
		expected := errors.New("local dependency unavailable")
		db := &AccountsDB{mainTrie: &localRecreateFailure{err: expected}}
		result, err := db.protectedChildForUpdate(nil, nil, nil)
		require.ErrorIs(t, err, expected)
		require.Nil(t, result)
	})
	t.Run("root_read_error", func(t *testing.T) {
		expected := errors.New("local root read unavailable")
		previous := &stagedProtectedChild{trie: &localRootReadFailure{err: expected}}
		result, err := (&AccountsDB{}).protectedChildForUpdate(previous, nil, nil)
		require.ErrorIs(t, err, expected)
		require.Nil(t, result)
	})
}

// A local dependency may produce a missing or inconsistent result without
// returning an I/O error. Neither fixture has a usable trie or record.
func TestQualSP281CLocalTrieDependencyInvalidResults(t *testing.T) {
	t.Run("missing_recreated_value", func(t *testing.T) {
		db := &AccountsDB{mainTrie: &localRecreateFailure{}}
		result, err := db.protectedChildForUpdate(nil, nil, nil)
		require.ErrorIs(t, err, errProtectedChild)
		require.Nil(t, result)
	})
	t.Run("inconsistent_dependency_value", func(t *testing.T) {
		previous := &stagedProtectedChild{trie: &localRootReadFailure{result: []byte("local unexpected value")}}
		result, err := (&AccountsDB{}).protectedChildForUpdate(previous, nil, nil)
		require.ErrorIs(t, err, errProtectedChild)
		require.Nil(t, result)
	})
}
