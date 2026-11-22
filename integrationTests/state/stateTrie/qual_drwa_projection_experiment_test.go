package stateTrie

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/stretchr/testify/require"
)

// This is a NON-NORMATIVE, single-locus SP1 experiment. It uses real native
// account/data tries and journals, but synthetic fixture keys and an explicit
// local coordinator. It implements no DRWA endpoint, transport, authentication,
// production storage format, scheduler integration, gas rule or finality proof.
// In particular, local absence here CANNOT classify a real token as ordinary.
// Basis: Part A 5.1; corrected W04 model, local journal/reconstruction cases.
var qualProjectionUnavailable = errors.New("synthetic projection unavailable")

type qualProjectionDelta struct {
	snapshot int
	key      string
	previous bool
}

type qualLocalProjection struct {
	adb                *state.AccountsDB
	address            []byte
	keys               []string
	visible, committed map[string]bool
	delta              []qualProjectionDelta
	valid              bool
	generation         uint64 // test-local stale-handle discriminator, NOT a wire version
}

func qualCopyMembership(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func qualNewLocalProjection(t *testing.T) *qualLocalProjection {
	t.Helper()
	p := &qualLocalProjection{adb: createAccountsDBTestSetup(), address: bytes.Repeat([]byte{7}, 32), keys: []string{"fixture-a", "fixture-b", "fixture-c"}, visible: make(map[string]bool)}
	t.Cleanup(func() { require.NoError(t, p.adb.Close()) })
	acc, err := p.adb.LoadAccount(p.address)
	require.NoError(t, err)
	for _, k := range p.keys {
		require.NoError(t, acc.(state.UserAccountHandler).SaveKeyValue([]byte(k), []byte{0}))
		p.visible[k] = false
	}
	require.NoError(t, p.adb.SaveAccount(acc))
	_, err = p.adb.Commit()
	require.NoError(t, err)
	p.committed = qualCopyMembership(p.visible)
	p.valid = true
	return p
}

func (p *qualLocalProjection) lookup(key string, generation uint64) (bool, error) {
	if !p.valid || generation != p.generation {
		return false, qualProjectionUnavailable
	}
	member, knownFixture := p.visible[key]
	if !knownFixture {
		return false, qualProjectionUnavailable
	}
	return member, nil
}

func (p *qualLocalProjection) add(key string) error {
	if !p.valid {
		return qualProjectionUnavailable
	}
	previous, known := p.visible[key]
	if !known {
		return qualProjectionUnavailable
	}
	p.valid = false
	p.generation++
	snapshot := p.adb.JournalLen()
	acc, err := p.adb.LoadAccount(p.address)
	if err != nil {
		return err
	}
	err = acc.(state.UserAccountHandler).SaveKeyValue([]byte(key), []byte{1})
	if err != nil {
		return err
	}
	if err = p.adb.SaveAccount(acc); err != nil {
		return err
	}
	p.delta = append(p.delta, qualProjectionDelta{snapshot: snapshot, key: key, previous: previous})
	p.visible[key] = true
	p.valid = true
	return nil
}

func (p *qualLocalProjection) rollback(snapshot int) error {
	if !p.valid {
		return qualProjectionUnavailable
	}
	p.valid = false
	p.generation++
	if err := p.adb.RevertToSnapshot(snapshot); err != nil {
		return err
	}
	if snapshot == 0 {
		p.visible = qualCopyMembership(p.committed)
		p.delta = nil
	} else {
		for len(p.delta) > 0 && p.delta[len(p.delta)-1].snapshot >= snapshot {
			d := p.delta[len(p.delta)-1]
			p.visible[d.key] = d.previous
			p.delta = p.delta[:len(p.delta)-1]
		}
	}
	p.valid = true
	return nil
}

func (p *qualLocalProjection) commit() ([]byte, error) {
	if !p.valid {
		return nil, qualProjectionUnavailable
	}
	p.valid = false
	p.generation++
	root, err := p.adb.Commit()
	if err != nil {
		return nil, err
	}
	p.committed = qualCopyMembership(p.visible)
	p.delta = nil
	p.valid = true
	return root, nil
}

// Explicit full reconstruction at a fixture-selected persisted native root.
// This finite fixture list is NOT registry enumeration or proof of authority.
func (p *qualLocalProjection) reconstruct(root []byte) error {
	p.valid = false
	p.generation++
	if err := p.adb.RecreateTrie(holders.NewDefaultRootHashesHolder(root)); err != nil {
		return err
	}
	acc, err := p.adb.GetExistingAccount(p.address)
	if err != nil {
		return err
	}
	rebuilt := make(map[string]bool, len(p.keys))
	for _, k := range p.keys {
		value, _, readErr := acc.(state.UserAccountHandler).RetrieveValue([]byte(k))
		if readErr != nil {
			return readErr
		}
		if len(value) != 1 || value[0] > 1 {
			return qualProjectionUnavailable
		}
		rebuilt[k] = value[0] == 1
	}
	p.visible, p.committed, p.delta = rebuilt, qualCopyMembership(rebuilt), nil
	p.valid = true
	return nil
}

func qualAssertLocalMembership(t *testing.T, p *qualLocalProjection, expected ...string) {
	t.Helper()
	want := make(map[string]bool)
	for _, k := range expected {
		want[k] = true
	}
	acc, err := p.adb.GetExistingAccount(p.address)
	require.NoError(t, err)
	for _, k := range p.keys {
		actual, lookupErr := p.lookup(k, p.generation)
		require.NoError(t, lookupErr)
		require.Equal(t, want[k], actual, "projection %s", k)
		value, _, readErr := acc.(state.UserAccountHandler).RetrieveValue([]byte(k))
		require.NoError(t, readErr)
		marker := byte(0)
		if want[k] {
			marker = 1
		}
		require.Equal(t, []byte{marker}, value, "native trie %s", k)
	}
}

func TestQualDRWASyntheticProjectionJournal(t *testing.T) {
	t.Run("nested_duplicate_and_repeat_rollback", func(t *testing.T) {
		p := qualNewLocalProjection(t)
		require.NoError(t, p.add("fixture-a"))
		first := p.adb.JournalLen()
		require.Positive(t, first)
		require.NoError(t, p.add("fixture-a"))
		require.NoError(t, p.add("fixture-b"))
		second := p.adb.JournalLen()
		require.NoError(t, p.add("fixture-c"))
		qualAssertLocalMembership(t, p, "fixture-a", "fixture-b", "fixture-c")
		require.NoError(t, p.rollback(second))
		qualAssertLocalMembership(t, p, "fixture-a", "fixture-b")
		require.NoError(t, p.rollback(first))
		qualAssertLocalMembership(t, p, "fixture-a")
		require.NoError(t, p.rollback(first))
		qualAssertLocalMembership(t, p, "fixture-a")
		require.NoError(t, p.rollback(0))
		qualAssertLocalMembership(t, p)
	})
	t.Run("commit_zero_snapshot_and_replay_after_reconstruction", func(t *testing.T) {
		p := qualNewLocalProjection(t)
		rootBefore, err := p.adb.RootHash()
		require.NoError(t, err)
		require.NoError(t, p.add("fixture-a"))
		rootAfter, err := p.commit()
		require.NoError(t, err)
		require.NotEqual(t, rootBefore, rootAfter)
		require.NoError(t, p.add("fixture-b"))
		require.NoError(t, p.rollback(0))
		qualAssertLocalMembership(t, p, "fixture-a")
		require.NoError(t, p.reconstruct(rootBefore))
		qualAssertLocalMembership(t, p)
		require.NoError(t, p.add("fixture-a"))
		replayedRoot, err := p.commit()
		require.NoError(t, err)
		require.Equal(t, rootAfter, replayedRoot, "legitimate replay after predecessor reconstruction must not be suppressed")
		require.NoError(t, p.reconstruct(rootAfter))
		qualAssertLocalMembership(t, p, "fixture-a")
	})
	t.Run("equal_root_does_not_discard_overlay", func(t *testing.T) {
		p := qualNewLocalProjection(t)
		require.NoError(t, p.add("fixture-a"))
		root, err := p.adb.RootHash()
		require.NoError(t, err)
		journal := p.adb.JournalLen()
		require.NoError(t, p.adb.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(root)))
		require.Equal(t, journal, p.adb.JournalLen())
		require.Len(t, p.delta, 1)
		qualAssertLocalMembership(t, p, "fixture-a")
		// Equal-root success cannot rehabilitate an already invalid view.
		p.valid = false
		require.NoError(t, p.adb.RecreateTrieIfNeeded(holders.NewDefaultRootHashesHolder(root)))
		_, err = p.lookup("fixture-a", p.generation)
		require.ErrorIs(t, err, qualProjectionUnavailable)
	})
	t.Run("rollback_error_stale_handles_and_explicit_recovery", func(t *testing.T) {
		p := qualNewLocalProjection(t)
		root, err := p.adb.RootHash()
		require.NoError(t, err)
		old := p.generation
		require.NoError(t, p.add("fixture-a"))
		_, err = p.lookup("fixture-a", old)
		require.ErrorIs(t, err, qualProjectionUnavailable)
		require.ErrorIs(t, p.rollback(-1), state.ErrSnapshotValueOutOfBounds)
		for _, k := range p.keys {
			_, err = p.lookup(k, p.generation)
			require.ErrorIs(t, err, qualProjectionUnavailable)
		}
		require.ErrorIs(t, p.add("fixture-b"), qualProjectionUnavailable)
		_, err = p.commit()
		require.ErrorIs(t, err, qualProjectionUnavailable)
		require.ErrorIs(t, p.rollback(0), qualProjectionUnavailable)
		require.NoError(t, p.reconstruct(root))
		qualAssertLocalMembership(t, p)
	})
	t.Run("malformed_reconstruction_cannot_publish", func(t *testing.T) {
		p := qualNewLocalProjection(t)
		acc, err := p.adb.GetExistingAccount(p.address)
		require.NoError(t, err)
		require.NoError(t, acc.(state.UserAccountHandler).SaveKeyValue([]byte("fixture-a"), []byte{2}))
		require.NoError(t, p.adb.SaveAccount(acc))
		root, err := p.adb.Commit()
		require.NoError(t, err)
		require.ErrorIs(t, p.reconstruct(root), qualProjectionUnavailable)
		_, err = p.lookup("fixture-b", p.generation)
		require.ErrorIs(t, err, qualProjectionUnavailable, "partial reconstruction cannot authorize absence")
	})
}

func TestQualDRWASyntheticProjectionLocality(t *testing.T) {
	// Four independent in-memory databases, NOT a metachain/three-shard network.
	loci := make([]*qualLocalProjection, 4)
	for i := range loci {
		loci[i] = qualNewLocalProjection(t)
	}
	require.NoError(t, loci[0].add("fixture-a"))
	_, err := loci[0].commit()
	require.NoError(t, err)
	qualAssertLocalMembership(t, loci[0], "fixture-a")
	for _, p := range loci[1:] {
		qualAssertLocalMembership(t, p)
	}
	// No transport is invented: local emptiness proves nothing about locus 0.
	for _, p := range loci {
		_, err = p.lookup("outside-fixture", p.generation)
		require.ErrorIs(t, err, qualProjectionUnavailable)
	}
}

func TestQualDRWASyntheticProjectionBypassNegativeControl(t *testing.T) {
	p := qualNewLocalProjection(t)
	require.NoError(t, p.add("fixture-a"))
	// Intentionally bypass the coordinator: the native journal does NOT maintain
	// a separate projection automatically. This is a counterexample, not a fix.
	require.NoError(t, p.adb.RevertToSnapshot(0))
	stale, err := p.lookup("fixture-a", p.generation)
	require.NoError(t, err)
	require.True(t, stale)
	acc, err := p.adb.GetExistingAccount(p.address)
	require.NoError(t, err)
	value, _, err := acc.(state.UserAccountHandler).RetrieveValue([]byte("fixture-a"))
	require.NoError(t, err)
	require.Equal(t, []byte{0}, value)
}
