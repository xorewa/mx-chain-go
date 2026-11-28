package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// A fixture-only interpreter; it neither defines a wire commitment format nor
// authenticates any real transition. Its references are the ordinary local
// data from the existing lifecycle qualification fixture.
type qualP11CommitmentHost struct {
	*qualLifecycleHost
	commitment func([]byte, []currentLocalReference) ([]byte, error)
}

func (h *qualP11CommitmentHost) DependencyCommitment(body []byte, refs []currentLocalReference) ([]byte, error) {
	return h.commitment(body, refs)
}

func TestQualDRWAP11BoundCurrentDependencyCommitment(t *testing.T) {
	for _, tc := range []struct {
		name             string
		install          bool
		wrongExpectation bool
		failureAt        int
		wantConsume      int
		wantApply        int
		wantChecks       int
	}{
		{name: "complete local data", install: true, wantConsume: 1, wantApply: 1, wantChecks: 2},
		{name: "unavailable decoder", wantChecks: 0},
		{name: "different expected digest", install: true, wrongExpectation: true, wantChecks: 1},
		{name: "initial provider error", install: true, failureAt: 1, wantChecks: 1},
		{name: "final provider error", install: true, failureAt: 2, wantConsume: 1, wantChecks: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := qualLifecycleNew(t)
			digest := blake2b.NewBlake2b().Compute("fixture-local-data-commitment")
			checks, consumes, applies := 0, 0, 0
			if tc.install {
				host := &qualP11CommitmentHost{qualLifecycleHost: f.h, commitment: func(body []byte, refs []currentLocalReference) ([]byte, error) {
					checks++
					require.Equal(t, f.h.body, body)
					require.Equal(t, f.h.refs, refs)
					if checks == tc.failureAt {
						return nil, errors.New("fixture dependency decoder unavailable")
					}
					return bytes.Clone(digest), nil
				}}
				f.r.current.host, f.r.host = host, host
			}
			expected := bytes.Clone(digest)
			if tc.wrongExpectation {
				expected = blake2b.NewBlake2b().Compute("different fixture data")
			}
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			journal := f.x.f.store.JournalLen()
			err = f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
				return f.r.withBoundCurrentAndApply(f.context, []byte("TOKEN-abcdef"), 1, f.hash, expected,
					func(lifecycleReadView) (*vmcommon.VMOutput, error) {
						consumes++
						return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
					}, func() error {
						applies++
						return nil
					})
			})
			if tc.wantApply != 0 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, tc.wantChecks, checks)
			require.Equal(t, tc.wantConsume, consumes)
			require.Equal(t, tc.wantApply, applies)
			actual, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, actual)
			require.Equal(t, journal, f.x.f.store.JournalLen())
		})
	}
}

func TestQualDRWAP11BoundCurrentNeedsExplicitCommitment(t *testing.T) {
	f := qualLifecycleNew(t)
	consumer := func(lifecycleReadView) (*vmcommon.VMOutput, error) {
		t.Fatal("consumer called without a complete dependency commitment")
		return nil, nil
	}
	for _, hash := range [][]byte{nil, []byte("short")} {
		_, err := f.r.withBoundCurrentAndApply(f.context, []byte("TOKEN-abcdef"), 1, f.hash, hash, consumer, nil)
		require.ErrorIs(t, err, errCurrentLocalDependency)
	}
	var absent *currentLifecycleReader
	_, err := absent.withBoundCurrentAndApply(nil, nil, 0, nil, nil, consumer, nil)
	require.ErrorIs(t, err, errCurrentLocalDependency)
}

func TestQualDRWAP11BoundCurrentExecutionShardLocalBundle(t *testing.T) {
	f := qualLifecycleNew(t)
	// The execution-shard fixture has its own established replica, not the
	// metachain-only intent records. No remote state reader is installed.
	qualRecordPut(t, f.x.f.store, append([]byte(registrationAssociationPrefix), []byte("TOKEN-abcdef")...), nil)
	qualRecordPut(t, f.x.f.store, append([]byte(registrationIntentPrefix), f.x.f.owner.id...), nil)
	digest := blake2b.NewBlake2b().Compute("execution-shard-fixture-commitment")
	checks := 0
	host := &qualP11CommitmentHost{qualLifecycleHost: f.h, commitment: func(body []byte, refs []currentLocalReference) ([]byte, error) {
		checks++
		require.Equal(t, f.h.body, body)
		require.Equal(t, f.h.refs, refs)
		return bytes.Clone(digest), nil
	}}
	f.r.current.host = host
	hook, _ := qualT42Hook(t, f.x.f.store, 1, true)
	_, end := qualT42Install(t, hook, 1, 1)
	defer end()
	coord, err := sharding.NewMultiShardCoordinator(3, 1)
	require.NoError(t, err)
	f.r, err = newCurrentLifecycleReader(f.r.current, f.x.f.boundary, hook, coord)
	require.NoError(t, err)
	f.context, err = hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	called := 0
	require.NoError(t, f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return f.r.withBoundCurrentAndApply(f.context, []byte("TOKEN-abcdef"), 1, f.hash, digest,
			func(view lifecycleReadView) (*vmcommon.VMOutput, error) {
				called++
				require.Equal(t, "SETUP", view.lifecycle)
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}, nil)
	}))
	require.Equal(t, 1, called)
	require.Equal(t, 2, checks)
}

func TestQualDRWAP11LocalDependencyAvailabilityRetry(t *testing.T) {
	f := qualLifecycleNew(t)
	digest := blake2b.NewBlake2b().Compute("local-availability-fixture-commitment")
	checks := 0
	host := &qualP11CommitmentHost{qualLifecycleHost: f.h, commitment: func(body []byte, refs []currentLocalReference) ([]byte, error) {
		checks++
		require.Equal(t, f.h.body, body)
		require.Equal(t, f.h.refs, refs)
		return bytes.Clone(digest), nil
	}}
	f.r.host, f.r.current.host = host, host
	ref := f.h.refs[0]
	key, err := f.r.current.referenceKey(ref)
	require.NoError(t, err)
	material, err := f.r.current.read(key)
	require.NoError(t, err)
	// Model delayed availability of ordinary fixture dependency data. The
	// consumer has neither a real transaction nor an ACK to emit.
	qualRecordPut(t, f.x.f.store, key, nil)
	missingRoot, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	missingJournal := f.x.f.store.JournalLen()
	consumes, applies := 0, 0
	read := func() error {
		return f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
			return f.r.withBoundCurrentAndApply(f.context, []byte("TOKEN-abcdef"), 1, f.hash, digest,
				func(lifecycleReadView) (*vmcommon.VMOutput, error) {
					consumes++
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
				}, func() error {
					applies++
					return nil
				})
		})
	}
	for i := 0; i < 2; i++ {
		require.Error(t, read())
		root, err := f.x.f.store.RootHash()
		require.NoError(t, err)
		require.Equal(t, missingRoot, root)
		require.Equal(t, missingJournal, f.x.f.store.JournalLen())
	}
	require.Zero(t, checks)
	require.Zero(t, consumes)
	require.Zero(t, applies)

	// Only actual local availability allows the reader to proceed. Reconstruct
	// the reader over the same store with no cached readiness evidence.
	qualRecordPut(t, f.x.f.store, key, material)
	current, err := newCurrentLocalDependencies(f.x.f.store, f.r.current.codec.marshaller, f.r.current.codec.hasher,
		f.r.current.codec.maxBytes, f.r.current.maxReferences, host)
	require.NoError(t, err)
	f.r, err = newCurrentLifecycleReader(current, f.r.boundary, f.r.source, f.r.coordinator)
	require.NoError(t, err)
	readyRoot, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	readyJournal := f.x.f.store.JournalLen()
	require.NoError(t, read())
	require.Equal(t, 2, checks)
	require.Equal(t, 1, consumes)
	require.Equal(t, 1, applies)
	root, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, readyRoot, root)
	require.Equal(t, readyJournal, f.x.f.store.JournalLen())
}

func TestQualDRWAP11CommitmentReaderNeedsOwnedView(t *testing.T) {
	f := qualCurrentLocalNew(t)
	view, err := f.resolve()
	require.NoError(t, err)
	digest := blake2b.NewBlake2b().Compute("fixture-expected-commitment")
	require.ErrorIs(t, f.r.verifyDependencyCommitment(view, nil), errCurrentLocalDependency)
	require.ErrorIs(t, f.r.verifyDependencyCommitment(nil, digest), errCurrentLocalDependency)
}
