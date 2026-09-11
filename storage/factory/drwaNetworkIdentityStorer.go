package factory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/storageunit"
)

const (
	drwaNetworkIdentityGlobalDirectory = "NodeGlobal"
	legacyStaticShardPrefix            = "Shard_"
)

// drwaNetworkIdentityStorer keeps the authoritative identity in a node-global
// database while retaining read-only access to legacy shard-scoped databases.
// Legacy databases are never modified or deleted by this adapter.
type drwaNetworkIdentityStorer struct {
	storage.Storer

	mut           sync.Mutex
	legacyStorers map[string]storage.Storer
	legacyNames   []string
	legacyClosed  bool
}

func newDRWANetworkIdentityStorer(
	pathManager storage.PathManagerHandler,
	storageConfig config.StorageConfig,
) (*drwaNetworkIdentityStorer, error) {
	globalPath := filepath.Join(
		pathManager.DatabasePath(),
		storage.DefaultStaticDbString,
		drwaNetworkIdentityGlobalDirectory,
		storageConfig.DB.FilePath,
	)
	global, err := createDRWANetworkIdentityStorageUnit(storageConfig, globalPath)
	if err != nil {
		return nil, fmt.Errorf("create node-global DRWA network identity store: %w", err)
	}

	legacy, names, err := openLegacyDRWANetworkIdentityStorers(pathManager, storageConfig)
	if err != nil {
		_ = global.Close()
		return nil, err
	}

	return &drwaNetworkIdentityStorer{
		Storer:        global,
		legacyStorers: legacy,
		legacyNames:   names,
	}, nil
}

func createDRWANetworkIdentityStorageUnit(
	storageConfig config.StorageConfig,
	dbPath string,
) (*storageunit.Unit, error) {
	dbConfig := GetDBFromConfig(storageConfig.DB)
	dbConfig.FilePath = dbPath
	persisterCreator, err := NewPersisterFactory(storageConfig.DB)
	if err != nil {
		return nil, err
	}

	return storageunit.NewStorageUnitFromConf(
		GetCacherFromConfig(storageConfig.Cache),
		dbConfig,
		persisterCreator,
	)
}

func openLegacyDRWANetworkIdentityStorers(
	pathManager storage.PathManagerHandler,
	storageConfig config.StorageConfig,
) (map[string]storage.Storer, []string, error) {
	staticRoot := filepath.Join(pathManager.DatabasePath(), storage.DefaultStaticDbString)
	entries, err := os.ReadDir(staticRoot)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]storage.Storer{}, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("scan legacy DRWA network identity root: %w", err)
	}

	names := make([]string, 0)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), legacyStaticShardPrefix) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return nil, nil, fmt.Errorf("invalid legacy DRWA network identity shard path %q", entry.Name())
		}
		legacyPath := filepath.Join(staticRoot, entry.Name(), storageConfig.DB.FilePath)
		info, statErr := os.Lstat(legacyPath)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return nil, nil, fmt.Errorf("inspect legacy DRWA network identity store %q: %w", entry.Name(), statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, nil, fmt.Errorf("invalid legacy DRWA network identity store %q", entry.Name())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	legacy := make(map[string]storage.Storer, len(names))
	for _, name := range names {
		legacyPath := filepath.Join(staticRoot, name, storageConfig.DB.FilePath)
		unit, openErr := createDRWANetworkIdentityStorageUnit(storageConfig, legacyPath)
		if openErr != nil {
			closeDRWANetworkIdentityStorers(legacy)
			return nil, nil, fmt.Errorf("open legacy DRWA network identity store %q: %w", name, openErr)
		}
		legacy[name] = unit
	}

	return legacy, names, nil
}

// DRWANetworkIdentityCandidates returns defensive copies of every retained
// candidate. The "global" entry is authoritative storage; the remaining names
// identify legacy shard-scoped stores and are stable only for diagnostics.
func (storer *drwaNetworkIdentityStorer) DRWANetworkIdentityCandidates(key []byte) (map[string][]byte, error) {
	if storer == nil {
		return nil, fmt.Errorf("nil DRWA network identity storer")
	}

	candidates := make(map[string][]byte)
	global, err := storer.Storer.Get(key)
	if err == nil {
		candidates["global"] = append([]byte(nil), global...)
	} else if !errors.Is(err, storage.ErrKeyNotFound) {
		return nil, fmt.Errorf("read node-global DRWA network identity: %w", err)
	}

	for _, name := range storer.legacyNames {
		value, getErr := storer.legacyStorers[name].Get(key)
		if getErr == nil {
			candidates["legacy/"+name] = append([]byte(nil), value...)
			continue
		}
		if !errors.Is(getErr, storage.ErrKeyNotFound) {
			return nil, fmt.Errorf("read legacy DRWA network identity %q: %w", name, getErr)
		}
	}

	return candidates, nil
}

func (storer *drwaNetworkIdentityStorer) Close() error {
	if storer == nil {
		return nil
	}

	storer.mut.Lock()
	defer storer.mut.Unlock()
	legacyErr := storer.closeLegacyLocked()
	globalErr := storer.Storer.Close()
	return errors.Join(legacyErr, globalErr)
}

func (storer *drwaNetworkIdentityStorer) DestroyUnit() error {
	if storer == nil {
		return nil
	}

	storer.mut.Lock()
	defer storer.mut.Unlock()
	legacyErr := storer.closeLegacyLocked()
	globalErr := storer.Storer.DestroyUnit()
	return errors.Join(legacyErr, globalErr)
}

func (storer *drwaNetworkIdentityStorer) closeLegacyLocked() error {
	if storer.legacyClosed {
		return nil
	}
	storer.legacyClosed = true

	var closeErr error
	for _, name := range storer.legacyNames {
		closeErr = errors.Join(closeErr, storer.legacyStorers[name].Close())
	}
	return closeErr
}

func closeDRWANetworkIdentityStorers(storers map[string]storage.Storer) {
	for _, storer := range storers {
		_ = storer.Close()
	}
}

func (storer *drwaNetworkIdentityStorer) IsInterfaceNil() bool {
	return storer == nil
}
