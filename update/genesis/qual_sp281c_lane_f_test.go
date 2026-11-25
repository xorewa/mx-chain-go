package genesis

import (
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common"
	triemock "github.com/multiversx/mx-chain-go/testscommon/trie"
	"github.com/multiversx/mx-chain-go/update"
	"github.com/stretchr/testify/require"
)

type qualSP281CLaneFUnreadableRoot struct {
	triemock.TrieStub
	err error
}

func (trie *qualSP281CLaneFUnreadableRoot) RootHash() ([]byte, error) { return nil, trie.err }

func TestQualSP281CLaneFProtectedCheckpointRejectsAbsentOrUnreadableMainTrie(t *testing.T) {
	exporter := &stateExport{}
	main := CreateTrieIdentifier(0, UserAccount)
	require.ErrorContains(t, exporter.checkProtectedExport(nil), "protected account checkpoint absent")
	require.ErrorContains(t, exporter.checkProtectedExport(map[string]common.Trie{main: (*triemock.TrieStub)(nil)}),
		"protected account checkpoint absent")
	require.Error(t, exporter.checkProtectedExport(map[string]common.Trie{"malformed": nil}))

	readFailure := errors.New("inert checkpoint root failure")
	require.ErrorIs(t, exporter.checkProtectedExport(map[string]common.Trie{
		main: &qualSP281CLaneFUnreadableRoot{err: readFailure},
	}), readFailure)

	importer := &stateImport{protectedRoots: map[uint32][]byte{0: {1}}}
	require.ErrorIs(t, importer.checkProtectedImport(), update.ErrImportingData)
}

type qualSP281CLaneFChildRoot struct {
	common.Trie
	root []byte
	err  error
}

func (trie *qualSP281CLaneFChildRoot) RootHash() ([]byte, error) { return trie.root, trie.err }
