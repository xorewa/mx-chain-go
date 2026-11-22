package state_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

func TestQualDRWAA19ProtectedChildRecordIdentityGuards(t *testing.T) {
	for _, name := range []string{"exact record", "stale predecessor same root", "replaced staged record same root"} {
		t.Run(name, func(t *testing.T) {
			address := bytes.Repeat([]byte{1}, 32)
			key := []byte(core.ProtectedKeyPrefix + "fixture/a19/record-identity")
			old := append([]byte{1}, common.EmptyTrieHash...)
			decode := func(owner, locator, record []byte) ([]byte, error) {
				if !bytes.Equal(owner, address) || !bytes.Equal(locator, key) || len(record) != len(old) {
					return nil, errors.New("invalid synthetic protected child locus")
				}
				// Both version bytes deliberately decode to the same root.
				return record[1:], nil
			}
			db, main, _ := qualA19OpenAccounts(t, filepath.Join(t.TempDir(), "record"), decode, nil)
			setRecord := func(value []byte) {
				t.Helper()
				account, err := db.LoadAccount(address)
				require.NoError(t, err)
				require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue(key, value))
				require.NoError(t, db.SaveAccount(account))
			}
			setRecord(old)
			root, err := db.Commit()
			require.NoError(t, err)
			child, err := main.Recreate(holders.NewDefaultRootHashesHolder(common.EmptyTrieHash))
			require.NoError(t, err)
			leaf := core.TrieData{Key: []byte("fixture-nonce"), Value: []byte("issued=5/live=0"), Version: core.NotSpecified}
			require.NoError(t, child.Update(leaf.Key, leaf.Value))
			nextRoot, err := child.RootHash()
			require.NoError(t, err)
			next := append([]byte{2}, nextRoot...)
			predecessor := bytes.Clone(old)
			if name == "stale predecessor same root" {
				predecessor[0] = 2
			}
			err = db.StageProtectedChildTrie(address, key, predecessor, next, []core.TrieData{leaf})
			if name == "stale predecessor same root" {
				require.Error(t, err)
				actual, rootErr := db.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, root, actual)
				require.Zero(t, db.JournalLen())
				return
			}
			require.NoError(t, err)
			if name == "replaced staged record same root" {
				replaced := bytes.Clone(next)
				replaced[0] = 3
				setRecord(replaced)
				published, err := db.Commit()
				require.Error(t, err)
				require.Nil(t, published)
				_, err = db.GetTrie(nextRoot)
				require.Error(t, err, "commit preflight must refuse before publishing the staged child")
				return
			}
			_, err = db.Commit()
			require.NoError(t, err)
			_, err = db.GetTrie(nextRoot)
			require.NoError(t, err)
		})
	}
}
