package drwa

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/stretchr/testify/require"
)

// Fixture-only interpreter. No native authority, transport or ACK is produced;
// each role has its own independently opened local store and reader.
type qualP11DiskCommitmentHost struct {
	*qualCurrentLocalHost
	t      *testing.T
	digest []byte
	checks int
}

func (h *qualP11DiskCommitmentHost) DependencyCommitment(body []byte, refs []currentLocalReference) ([]byte, error) {
	h.checks++
	require.Equal(h.t, h.body, body)
	require.Equal(h.t, h.refs, refs)
	return bytes.Clone(h.digest), nil
}

func qualP11DiskReader(t *testing.T, f *qualCurrentLocalFixture, store *qualNativeStore, digest []byte) (*currentLocalDependencies, *qualP11DiskCommitmentHost) {
	t.Helper()
	refs := make([]currentLocalReference, len(f.host.refs))
	for i, ref := range f.host.refs {
		refs[i] = cloneCurrentLocalReference(ref)
	}
	host := &qualP11DiskCommitmentHost{
		qualCurrentLocalHost: &qualCurrentLocalHost{
			body: bytes.Clone(f.body), refs: refs,
			faults: make(map[string]error), hooks: make(map[string]func()), calls: make(map[string]int),
		},
		t: t, digest: bytes.Clone(digest),
	}
	reader, err := newCurrentLocalDependencies(store, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 10, host)
	require.NoError(t, err)
	return reader, host
}

func TestQualDRWAP11PersistedLocalDependencyRoles(t *testing.T) {
	f := qualCurrentLocalNew(t)
	digest := blake2b.NewBlake2b().Compute("ordinary fixture dependency commitment for local store roles")
	var completedRoots [][]byte
	for _, tc := range []struct {
		name    string
		delayed bool
	}{
		{name: "source shard local reader"},
		{name: "destination shard separate local reader", delayed: true},
		{name: "metachain local reader"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "local-dependencies")
			store, closeStore := qualConvergenceDiskOpen(t, path, false)
			p, err := newProtectedState(store)
			require.NoError(t, err)
			require.NoError(t, p.provisionGenesis())
			qualRecordPut(t, store, f.pointerKey, f.pointer)
			qualRecordPut(t, store, f.bodyKey, f.body)
			for i, key := range f.keys {
				if tc.delayed && i == 0 {
					continue // ordinary fixture data is not yet present at this locus
				}
				qualRecordPut(t, store, key, f.materials[i])
			}
			root, err := store.Commit()
			require.NoError(t, err)
			closeStore()

			// Close and reopen the physical store, selecting the known committed
			// fixture root. Neither the old reader nor its host is retained.
			store, closeStore = qualConvergenceDiskOpen(t, path, false)
			require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
			reader, host := qualP11DiskReader(t, f, store, digest)
			if tc.delayed {
				view, err := reader.resolve(f.token, 7, f.hash)
				require.Error(t, err)
				require.Nil(t, view)
				require.Zero(t, host.checks)
				actual, err := store.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, actual)
				require.Zero(t, store.JournalLen())

				// Supply the exact ordinary fixture material to the destination
				// store only. This is not a transport or authenticated replica.
				qualRecordPut(t, store, f.keys[0], f.materials[0])
				root, err = store.Commit()
				require.NoError(t, err)
				closeStore()
				store, closeStore = qualConvergenceDiskOpen(t, path, false)
				require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
				reader, host = qualP11DiskReader(t, f, store, digest)
			}

			// Repeating the exact nominal read is idempotent: it creates no
			// application or readiness state and never consults another role.
			for i := 0; i < 2; i++ {
				view, err := reader.resolve(f.token, 7, f.hash)
				require.NoError(t, err)
				require.NoError(t, reader.verifyDependencyCommitment(view, digest))
				require.NoError(t, reader.revalidate(view))
				actual, err := store.RootHash()
				require.NoError(t, err)
				require.Equal(t, root, actual)
				require.Zero(t, store.JournalLen())
			}
			require.Equal(t, 2, host.checks)
			completedRoots = append(completedRoots, bytes.Clone(root))
			closeStore()
		})
	}
	require.Len(t, completedRoots, 3)
	require.Equal(t, completedRoots[0], completedRoots[1], "same local fixture bytes after delayed availability")
	require.Equal(t, completedRoots[0], completedRoots[2], "same local fixture bytes at each separate role")
}
