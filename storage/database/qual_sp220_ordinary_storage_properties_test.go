package database

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/multiversx/mx-chain-go/storage"
	"github.com/stretchr/testify/require"
)

// FuzzQualSP220OrdinaryRecordPreservation checks only ordinary invented report
// records. The logical copy uses the Persister interface, not a chain migration.
func FuzzQualSP220OrdinaryRecordPreservation(f *testing.F) {
	f.Add("alpha", "first report")
	f.Add("Café", "été 東京")
	f.Add("empty report", "")
	f.Add("long label 0123456789", "one two three four five six seven eight nine ten")

	f.Fuzz(func(t *testing.T, label, value string) {
		if label == "" || len(label) > 128 || len(value) > 256 ||
			!utf8.ValidString(label) || !utf8.ValidString(value) {
			t.Skip("outside the ordinary display fixture domain")
		}
		for _, input := range []string{label, value} {
			for _, ch := range input {
				if !unicode.IsPrint(ch) {
					t.Skip("not an ordinary printable report label or value")
				}
			}
		}

		prefix := "ordinary-report/" + hex.EncodeToString([]byte(label))
		keys := [][]byte{[]byte(prefix + "/first"), []byte(prefix + "/second")}
		// An ordinary report is a serialized value, including when its text is
		// empty. The upstream raw zero-length value is not this report format.
		texts := []string{value, "second: " + value}
		values := make([][]byte, len(texts))
		for idx, text := range texts {
			encoded, err := json.Marshal(text)
			require.NoError(t, err)
			values[idx] = encoded
		}
		sourcePath, destinationPath := t.TempDir(), t.TempDir()
		openSource := func() (storage.Persister, error) {
			return NewLevelDB(sourcePath, 1, 10, 4, 0)
		}
		openDestination := func() (storage.Persister, error) {
			return NewSerialDB(destinationPath, 1, 10, 4, 0)
		}
		withDB := func(open func() (storage.Persister, error), use func(storage.Persister)) {
			db, err := open()
			require.NoError(t, err)
			defer func() { require.NoError(t, db.Close()) }()
			use(db)
		}
		check := func(db storage.Persister) {
			for idx, key := range keys {
				got, err := db.Get(key)
				require.NoError(t, err)
				require.Equal(t, values[idx], got)
				var decoded string
				require.NoError(t, json.Unmarshal(got, &decoded))
				require.Equal(t, texts[idx], decoded)
			}
		}

		withDB(openSource, func(source storage.Persister) {
			for idx, key := range keys {
				require.NoError(t, source.Put(key, values[idx]))
			}
			check(source)
		})
		withDB(openSource, func(source storage.Persister) {
			check(source)
			withDB(openDestination, func(destination storage.Persister) {
				for _, key := range keys {
					got, err := source.Get(key)
					require.NoError(t, err)
					require.NoError(t, destination.Put(key, got))
				}
				check(destination)
			})
		})
		withDB(openDestination, check)
		withDB(openSource, check)
	})
}
