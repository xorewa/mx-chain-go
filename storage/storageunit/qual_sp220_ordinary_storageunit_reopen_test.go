package storageunit_test

import (
	"encoding/json"
	"testing"

	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/stretchr/testify/require"
)

func TestQualSP220OrdinaryStorageUnitReopenWithFreshCache(t *testing.T) {
	type report struct {
		Label string `json:"label"`
		Count int    `json:"count"`
	}
	samples := []struct {
		key   string
		value report
	}{
		{"display-first", report{Label: "Blue sky", Count: 0}},
		{"display-second", report{Label: "Café", Count: 12}},
		{"display-third", report{Label: "Green", Count: 37}},
	}
	path := t.TempDir()
	open := func() *storageunit.Unit {
		cache, err := storageunit.NewCache(storageunit.CacheConfig{Type: "LRU", Capacity: 100})
		require.NoError(t, err)
		db, err := database.NewLevelDB(path, 1, 10, 4, 0)
		require.NoError(t, err)
		unit, err := storageunit.NewStorageUnit(cache, db)
		if err != nil {
			_ = db.Close()
		}
		require.NoError(t, err)
		return unit
	}

	func() {
		unit := open()
		defer func() { require.NoError(t, unit.Close()) }()
		for _, sample := range samples {
			encoded, err := json.Marshal(sample.value)
			require.NoError(t, err)
			require.NoError(t, unit.Put([]byte(sample.key), encoded))
		}
	}()

	// Reconstruct the storage unit with an independent cache on the same path.
	unit := open()
	defer func() { require.NoError(t, unit.Close()) }()
	for _, sample := range samples {
		expected, err := json.Marshal(sample.value)
		require.NoError(t, err)
		actual, err := unit.Get([]byte(sample.key))
		require.NoError(t, err)
		require.Equal(t, expected, actual)
		var decoded report
		require.NoError(t, json.Unmarshal(actual, &decoded))
		require.Equal(t, sample.value, decoded)
	}
}
