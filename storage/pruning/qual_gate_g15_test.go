package pruning_test

import (
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/multiversx/mx-chain-go/storage/mock"
	"github.com/multiversx/mx-chain-go/storage/pruning"
	"github.com/multiversx/mx-chain-go/testscommon"
	"github.com/stretchr/testify/require"
)

func TestQualG15DisabledPruningWriteOwner(t *testing.T) {
	args := getDefaultArgs()
	args.PruningEnabled = false
	args.PathManager = &testscommon.PathManagerStub{PathForEpochCalled: func(_ string, epoch uint32, _ string) string { return fmt.Sprint(epoch) }}
	owners := map[string]storage.Persister{}
	args.PersisterFactory = &mock.PersisterFactoryStub{CreateCalled: func(path string) (storage.Persister, error) {
		db := database.NewMemDB()
		owners[path] = db
		return db, nil
	}}
	ps, err := pruning.NewPruningStorer(args)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ps.Close()) })
	require.Len(t, owners, 1)
	owner := owners["0"]
	require.NotNil(t, owner)
	require.NoError(t, ps.PutInEpoch([]byte("key"), []byte("value"), 99))
	require.Len(t, owners, 1)
	require.NotContains(t, owners, "99")
	actual, err := owner.Get([]byte("key"))
	require.NoError(t, err)
	require.Equal(t, []byte("value"), actual)
	ps.ClearCache()
	actual, err = ps.Get([]byte("key"))
	require.NoError(t, err)
	require.Equal(t, []byte("value"), actual)
}
