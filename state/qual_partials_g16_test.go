package state

import (
	"testing"
	"time"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/stretchr/testify/require"
)

// Only the three account methods reached by loadDataTrieConcurrentSafe are
// supplied; this qualification collaborator grants no account-factory credit.
type qualG16Account struct {
	baseAccountHandler
	tr common.Trie
}

func (a *qualG16Account) AddressBytes() []byte       { return []byte("experimental-account") }
func (a *qualG16Account) GetRootHash() []byte        { return []byte("experimental-root") }
func (a *qualG16Account) SetDataTrie(tr common.Trie) { a.tr = tr }

type qualG16Trie struct {
	common.Trie
	recreate func(common.RootHashHolder) (common.Trie, error)
}

func (tr *qualG16Trie) Recreate(root common.RootHashHolder) (common.Trie, error) {
	return tr.recreate(root)
}

func (tr *qualG16Trie) IsInterfaceNil() bool { return tr == nil }

func TestQualPartialsG16AccountAndHolderLocks(t *testing.T) {
	t.Run("account_loader", func(t *testing.T) {
		adb := &AccountsDB{dataTries: NewDataTriesHolder()}
		account := &qualG16Account{}
		loaded := &qualG16Trie{}
		entered := make(chan struct{}, 1)
		mainTrie := &qualG16Trie{recreate: func(common.RootHashHolder) (common.Trie, error) {
			entered <- struct{}{}
			return loaded, nil
		}}
		started, finished := make(chan struct{}), make(chan error, 1)
		adb.mutOp.Lock()
		go func() {
			close(started)
			finished <- adb.loadDataTrieConcurrentSafe(account, mainTrie)
		}()
		<-started
		early := false
		select {
		case <-entered:
			early = true
		case <-time.After(100 * time.Millisecond):
		}
		adb.mutOp.Unlock()
		select {
		case err := <-finished:
			require.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("account loader did not finish after lock release")
		}
		require.False(t, early, "account operation lock excludes trie recreation")
		require.Same(t, loaded, account.tr)
		require.Same(t, loaded, adb.dataTries.Get(account.AddressBytes()))
	})
	t.Run("holder_lookup", func(t *testing.T) {
		holder := NewDataTriesHolder()
		loaded := &qualG16Trie{}
		holder.Put([]byte("key"), loaded)
		started, finished := make(chan struct{}), make(chan common.Trie, 1)
		holder.mutex.Lock()
		go func() {
			close(started)
			finished <- holder.Get([]byte("key"))
		}()
		<-started
		early := false
		var got common.Trie
		select {
		case got = <-finished:
			early = true
		case <-time.After(100 * time.Millisecond):
		}
		holder.mutex.Unlock()
		if !early {
			select {
			case got = <-finished:
			case <-time.After(2 * time.Second):
				t.Fatal("holder lookup did not finish after lock release")
			}
		}
		require.False(t, early, "holder lock excludes map access")
		require.Same(t, loaded, got)
	})
}
