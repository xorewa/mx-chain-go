package storageunit_test

import (
	"testing"

	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/stretchr/testify/require"
)

// TestQualSP218OrdinaryStorageRecordLifecycle uses only disposable report
// labels and deliberately compares the same expected values before and after
// reconstruction with a fresh cache.
func TestQualSP218OrdinaryStorageRecordLifecycle(t *testing.T) {
	path := t.TempDir()
	updatedKey := []byte("report-title")
	removedKey := []byte("report-draft")
	retainedKey := []byte("report-summary")
	original := []byte("Morning report")
	replacement := []byte("Evening report")
	draft := []byte("Draft report")
	summary := []byte("Daily summary")

	open := func() *storageunit.Unit {
		t.Helper()
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
	check := func(unit *storageunit.Unit, key, expected []byte) {
		t.Helper()
		require.NoError(t, unit.Has(key))
		actual, err := unit.Get(key)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
	checkRemoved := func(unit *storageunit.Unit) {
		t.Helper()
		require.Equal(t, storage.ErrKeyNotFound, unit.Has(removedKey))
		actual, err := unit.Get(removedKey)
		require.Equal(t, storage.ErrKeyNotFound, err)
		require.Nil(t, actual)
	}

	func() {
		unit := open()
		defer func() { require.NoError(t, unit.Close()) }()
		require.NoError(t, unit.Put(updatedKey, original))
		require.NoError(t, unit.Put(removedKey, draft))
		require.NoError(t, unit.Put(retainedKey, summary))
		check(unit, updatedKey, original)
		check(unit, removedKey, draft)
		check(unit, retainedKey, summary)
	}()
	func() {
		unit := open()
		defer func() { require.NoError(t, unit.Close()) }()
		check(unit, updatedKey, original)
		check(unit, removedKey, draft)
		require.NoError(t, unit.Put(updatedKey, replacement))
		require.NoError(t, unit.Remove(removedKey))
		check(unit, updatedKey, replacement)
		checkRemoved(unit)
		check(unit, retainedKey, summary)
	}()
	func() {
		unit := open()
		defer func() { require.NoError(t, unit.Close()) }()
		check(unit, updatedKey, replacement)
		checkRemoved(unit)
		check(unit, retainedKey, summary)
	}()
}
