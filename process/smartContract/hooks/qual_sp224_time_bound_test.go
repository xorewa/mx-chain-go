package hooks_test

import (
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/stretchr/testify/require"
)

// SP2-24: only a hook built with a hasher and the per-header activation
// predicate can be a DRWA time source.
func TestQualSP224HeaderTimeBound(t *testing.T) {
	require.False(t, (*hooks.BlockChainHookImpl)(nil).DRWAHeaderTimeBound())
	build := func(change func(*hooks.ArgBlockChainHook)) *hooks.BlockChainHookImpl {
		args := createMockBlockChainHookArgs()
		change(&args)
		hook, err := hooks.NewBlockChainHookImpl(args)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, hook.Close()) })
		return hook
	}
	always := func(uint32, uint64) bool { return true }
	require.False(t, build(func(*hooks.ArgBlockChainHook) {}).DRWAHeaderTimeBound(), "no hasher, no predicate")
	require.False(t, build(func(a *hooks.ArgBlockChainHook) { a.DRWAHeaderTimeEnabledAt = always }).DRWAHeaderTimeBound(), "no hasher")
	require.False(t, build(func(a *hooks.ArgBlockChainHook) { a.Hasher = blake2b.NewBlake2b() }).DRWAHeaderTimeBound(), "no predicate")
	require.False(t, build(func(a *hooks.ArgBlockChainHook) {
		a.Hasher, a.DRWAHeaderTimeEnabled = blake2b.NewBlake2b(), func() bool { return true }
	}).DRWAHeaderTimeBound(), "the header-less predicate is not the per-header one")
	require.True(t, build(func(a *hooks.ArgBlockChainHook) { a.Hasher, a.DRWAHeaderTimeEnabledAt = blake2b.NewBlake2b(), always }).DRWAHeaderTimeBound())
}
