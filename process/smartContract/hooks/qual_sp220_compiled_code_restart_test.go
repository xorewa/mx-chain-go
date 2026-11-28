package hooks_test

import (
	"bytes"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/stretchr/testify/require"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
)

// SP2-20 carries G02.03, G32.04 and G34.04 (process restart of the persistent
// compiled-code consumer) and the G32.H-reset-refill duty. The native hook is
// the only persistent owner of compiled code. This test runs its real
// persistent store on disk and a real LRU pool through a process restart: a
// new hook, a new pool, the same working directory.
//
// It is hook-level. The admitted node factories, the native compiler and a
// physical node restart are not exercised here.
func TestQualSP220CompiledCodeGenerationDoesNotSurviveRestart(t *testing.T) {
	workingDir := t.TempDir()
	open := func() (*hooks.BlockChainHookImpl, storageCacher) {
		args := createMockBlockChainHookArgs()
		t.Cleanup(func() { _ = args.DataPool.Close() })
		pool, err := storageunit.NewCache(storageunit.CacheConfig{Type: storageunit.LRUCache, Capacity: 10, Shards: 1})
		require.NoError(t, err)
		args.CompiledSCPool = pool
		args.NilCompiledSCStore = false
		args.WorkingDir = workingDir
		args.ConfigSCStorage = config.StorageConfig{
			Cache: config.CacheConfig{Capacity: 10, Type: string(storageunit.LRUCache)},
			DB:    config.DBConfig{FilePath: "compiled", Type: string(storageunit.LvlDBSerial), BatchDelaySeconds: 1, MaxBatchSize: 1, MaxOpenFiles: 10},
		}
		hook, err := hooks.NewBlockChainHookImpl(args)
		require.NoError(t, err)
		return hook, pool
	}
	hasher := blake2b.NewBlake2b()
	// Two accounts' code, hence two code hashes.
	hashA, hashB := hasher.Compute("code of account A"), hasher.Compute("code of account B")
	compiledA, compiledB := []byte("compiled generation 1 of A"), []byte("compiled generation 1 of B")

	first, firstPool := open()
	first.SaveCompiledCode(hashA, compiledA)
	first.SaveCompiledCode(hashB, compiledB)
	requireCompiled := func(hook *hooks.BlockChainHookImpl, hash, expected []byte) {
		t.Helper()
		found, compiled := hook.GetCompiledCode(hash)
		require.Equal(t, expected != nil, found)
		require.True(t, bytes.Equal(expected, compiled))
	}
	// Inside one process the persistent generation serves a pool miss.
	firstPool.Clear()
	requireCompiled(first, hashA, compiledA)
	requireCompiled(first, hashB, compiledB)

	// A read failure of the persistent store is "not found": the caller
	// compiles from the authenticated account code. It is never stale bytes.
	require.NoError(t, first.Close())
	firstPool.Clear()
	requireCompiled(first, hashA, nil)
	requireCompiled(first, hashB, nil)

	// Process restart: no compiled code of the earlier process is admitted,
	// for either account.
	second, secondPool := open()
	t.Cleanup(func() { _ = second.Close() })
	require.Zero(t, secondPool.Len())
	requireCompiled(second, hashA, nil)
	requireCompiled(second, hashB, nil)

	// The new process builds its own generation, and an activation epoch
	// clears it again (the native reset).
	next := []byte("compiled generation 2 of A")
	second.SaveCompiledCode(hashA, next)
	requireCompiled(second, hashA, next)
	requireCompiled(second, hashB, nil)
	second.EpochConfirmed(0, 0)
	requireCompiled(second, hashA, nil)

	// A second restart after the reset is equally empty.
	require.NoError(t, second.Close())
	third, _ := open()
	t.Cleanup(func() { _ = third.Close() })
	requireCompiled(third, hashA, nil)
	requireCompiled(third, hashB, nil)
}

type storageCacher interface {
	Clear()
	Len() int
}
