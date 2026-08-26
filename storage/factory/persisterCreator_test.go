package factory_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/factory"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func snapshotRegularFiles(root string) (map[string][sha256.Size]byte, error) {
	snapshot := make(map[string][sha256.Size]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) && path == root {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		snapshot[relative] = sha256.Sum256(value)
		return nil
	})
	return snapshot, err
}

func createDefaultBasePersisterConfig() config.DBConfig {
	return config.DBConfig{
		Type:                "LvlDBSerial",
		BatchDelaySeconds:   2,
		MaxBatchSize:        100,
		MaxOpenFiles:        10,
		UseTmpAsFilePath:    false,
		ShardIDProviderType: "BinarySplit",
		NumShards:           1,
	}
}

func TestPersisterCreator_Create(t *testing.T) {
	t.Parallel()

	t.Run("invalid file path, should fail", func(t *testing.T) {
		t.Parallel()

		pc := factory.NewPersisterCreator(createDefaultDBConfig())

		p, err := pc.Create("")
		require.Nil(t, p)
		require.Equal(t, storage.ErrInvalidFilePath, err)
	})

	t.Run("use tmp as file path", func(t *testing.T) {
		t.Parallel()

		conf := createDefaultDBConfig()
		conf.UseTmpAsFilePath = true

		pc := factory.NewPersisterCreator(conf)

		p, err := pc.Create(t.TempDir())
		require.Nil(t, err)
		require.NotNil(t, p)
		require.NoError(t, p.Close())
	})

	t.Run("should create non sharded persister", func(t *testing.T) {
		t.Parallel()

		pc := factory.NewPersisterCreator(createDefaultBasePersisterConfig())

		dir := t.TempDir()
		p, err := pc.Create(dir)
		require.NotNil(t, p)
		require.Nil(t, err)

		assert.True(t, strings.Contains(fmt.Sprintf("%T", p), "*leveldb.SerialDB"))
	})

	t.Run("should create sharded persister", func(t *testing.T) {
		t.Parallel()

		pc := factory.NewPersisterCreator(createDefaultDBConfig())

		dir := t.TempDir()
		p, err := pc.Create(dir)
		require.NotNil(t, p)
		require.Nil(t, err)

		assert.True(t, strings.Contains(fmt.Sprintf("%T", p), "*sharded.shardedPersister"))
	})
}

func TestPersisterCreator_FixturesDoNotMutateRepositoryRelativePath1(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	packageRoot := filepath.Dir(currentFile)
	repositoryRelativeDebris := filepath.Join(packageRoot, "path1")
	before, err := snapshotRegularFiles(repositoryRelativeDebris)
	require.NoError(t, err)

	configForTemp := createDefaultDBConfig()
	configForTemp.UseTmpAsFilePath = true
	persister := factory.NewPersisterCreator(configForTemp)
	created, err := persister.Create(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, created.Close())

	after, err := snapshotRegularFiles(repositoryRelativeDebris)
	require.NoError(t, err)
	require.Equal(t, before, after, "test-owned storage creation must not change pre-existing repository debris")

	testSources, err := filepath.Glob(filepath.Join(packageRoot, "*_test.go"))
	require.NoError(t, err)
	for _, testSource := range testSources {
		value, readErr := os.ReadFile(testSource)
		require.NoError(t, readErr)
		forbiddenLiteral := "Create(" + "\"path1\")"
		require.NotContains(t, string(value), forbiddenLiteral,
			"repository-relative database fixture in %s must use t.TempDir()", filepath.Base(testSource))
	}
}

func TestPersisterCreator_CreateBasePersister(t *testing.T) {
	t.Parallel()

	t.Run("not supported type, should fail", func(t *testing.T) {
		t.Parallel()

		dbConfig := createDefaultBasePersisterConfig()
		dbConfig.Type = "not supported type"
		pc := factory.NewPersisterCreator(dbConfig)

		dir := t.TempDir()
		p, err := pc.CreateBasePersister(dir)
		require.Nil(t, p)
		require.Equal(t, storage.ErrNotSupportedDBType, err)
	})

	t.Run("leveldb", func(t *testing.T) {
		t.Parallel()

		dbConfig := createDefaultBasePersisterConfig()
		dbConfig.Type = string(storageunit.LvlDB)
		pc := factory.NewPersisterCreator(dbConfig)

		dir := t.TempDir()
		p, err := pc.CreateBasePersister(dir)
		require.NotNil(t, p)
		require.Nil(t, err)

		assert.True(t, strings.Contains(fmt.Sprintf("%T", p), "*leveldb.DB"))
	})

	t.Run("serial leveldb", func(t *testing.T) {
		t.Parallel()

		pc := factory.NewPersisterCreator(createDefaultBasePersisterConfig())

		dir := t.TempDir()
		p, err := pc.CreateBasePersister(dir)
		require.NotNil(t, p)
		require.Nil(t, err)

		assert.True(t, strings.Contains(fmt.Sprintf("%T", p), "*leveldb.SerialDB"))
	})

	t.Run("memorydb", func(t *testing.T) {
		t.Parallel()

		dbConfig := createDefaultBasePersisterConfig()
		dbConfig.Type = string(storageunit.MemoryDB)
		pc := factory.NewPersisterCreator(dbConfig)

		dir := t.TempDir()
		p, err := pc.CreateBasePersister(dir)
		require.NotNil(t, p)
		require.Nil(t, err)

		assert.True(t, strings.Contains(fmt.Sprintf("%T", p), "*memorydb.DB"))
	})
}

func TestPersisterCreator_CreateShardIDProvider(t *testing.T) {
	t.Parallel()

	t.Run("not supported type, should fail", func(t *testing.T) {
		t.Parallel()

		dbConfig := createDefaultDBConfig()
		dbConfig.ShardIDProviderType = "not supported type"
		pc := factory.NewPersisterCreator(dbConfig)

		p, err := pc.CreateShardIDProvider()
		require.Nil(t, p)
		require.Equal(t, storage.ErrNotSupportedShardIDProviderType, err)
	})

	t.Run("binary split, should work", func(t *testing.T) {
		t.Parallel()

		dbConfig := createDefaultDBConfig()
		pc := factory.NewPersisterCreator(dbConfig)

		p, err := pc.CreateShardIDProvider()
		require.NotNil(t, p)
		require.Nil(t, err)

		assert.True(t, strings.Contains(fmt.Sprintf("%T", p), "*sharded.shardIDProvider"))
	})
}
