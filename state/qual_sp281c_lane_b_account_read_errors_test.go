package state

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/stateChange"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// These inert interfaces permit only the ordinary read methods used by this
// fixture. There is no native store, authenticated account or ownership input;
// every requested downstream read fails with its supplied local error.
type localReadOnlyAccount struct {
	UserAccountHandler
	root []byte
	err  error
}

func (a *localReadOnlyAccount) AddressBytes() []byte { return []byte("local fixture") }
func (a *localReadOnlyAccount) IsInterfaceNil() bool { return a == nil }
func (a *localReadOnlyAccount) GetRootHash() []byte  { return a.root }
func (a *localReadOnlyAccount) GetCode() []byte      { return nil }
func (a *localReadOnlyAccount) HasNewCode() bool     { return false }

func (a *localReadOnlyAccount) SaveDirtyData(common.Trie) ([]*stateChange.DataTrieChange, []core.TrieData, error) {
	panic("unexpected write")
}

func (a *localReadOnlyAccount) RetrieveValue([]byte) ([]byte, uint32, error) {
	return nil, 0, a.err
}

type localReadOnlyAccountFactory struct {
	AccountFactory
	account vmcommon.AccountHandler
}

func (f *localReadOnlyAccountFactory) CreateAccount([]byte) (vmcommon.AccountHandler, error) {
	return f.account, nil
}

type localReadOnlyAccountTrie struct {
	common.Trie
	err error
}

func (tr *localReadOnlyAccountTrie) Get([]byte) ([]byte, uint32, error) {
	return []byte("{}"), 0, nil
}

func (tr *localReadOnlyAccountTrie) Recreate(common.RootHashHolder) (common.Trie, error) {
	return nil, tr.err
}

type localEmptyTries struct{ common.TriesHolder }

func (*localEmptyTries) Get([]byte) common.Trie { return nil }

type localReadAccessCollector struct{ StateAccessesCollector }

func (*localReadAccessCollector) AddStateAccess(*stateChange.StateAccess) {}

func TestQualSP281CLocalAccountReadErrors(t *testing.T) {
	cause := errors.New("local read unavailable")
	for _, tc := range []struct {
		name string
		root []byte
	}{
		{name: "trie_read_error", root: bytes.Clone(common.EmptyTrieHash)},
		{name: "value_read_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := &localReadOnlyAccount{root: tc.root, err: cause}
			db := &AccountsDB{
				mainTrie: &localReadOnlyAccountTrie{err: cause}, accountFactory: &localReadOnlyAccountFactory{account: account},
				marshaller: &marshal.JsonMarshalizer{}, dataTries: &localEmptyTries{}, stateAccessesCollector: &localReadAccessCollector{},
			}
			result, err := db.protectedChildPredecessorAccount(account.AddressBytes(), nil, nil)
			require.ErrorIs(t, err, cause)
			require.Nil(t, result)
		})
	}
}

// An absent dependency cannot produce a root. The zero-value local receiver
// contains no account, native record, or decoder.
func TestQualSP281CLocalAbsentRootDependency(t *testing.T) {
	root, err := (&AccountsDB{}).protectedPredecessorRoot(nil, nil, nil)
	require.ErrorIs(t, err, errProtectedChild)
	require.Nil(t, root)
}
