package database

import (
	"testing"

	"github.com/multiversx/mx-chain-go/storage"
	"github.com/stretchr/testify/require"
)

func TestQualSP220OrdinaryDatabaseReopen(t *testing.T) {
	constructors := []struct {
		name string
		open func(string) (storage.Persister, error)
	}{
		{"level", func(path string) (storage.Persister, error) {
			return NewLevelDB(path, 1, 10, 4, 0)
		}},
		{"serial", func(path string) (storage.Persister, error) {
			return NewSerialDB(path, 1, 10, 4, 0)
		}},
	}
	for _, tc := range constructors {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir()
			values := []struct{ key, value string }{
				{"report-alpha", "first ordinary value"},
				{"report-beta", "second ordinary value"},
			}
			func() {
				db, err := tc.open(path)
				require.NoError(t, err)
				defer func() { require.NoError(t, db.Close()) }()
				for _, item := range values {
					require.NoError(t, db.Put([]byte(item.key), []byte(item.value)))
				}
			}()

			db, err := tc.open(path)
			require.NoError(t, err)
			defer func() { require.NoError(t, db.Close()) }()
			for _, item := range values {
				actual, getErr := db.Get([]byte(item.key))
				require.NoError(t, getErr)
				require.Equal(t, []byte(item.value), actual)
			}
		})
	}
}
