package processing

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// This private surface intentionally has no Remove/Destroy/overwrite method.
// A read-only identity view is not permission to use a DRWA process component.
type drwaIdentityDB interface {
	Get([]byte) ([]byte, error)
	Put([]byte, []byte) error
	Close() error
}

// Only the native startup assembly can derive this mode. Neither an empty DB
// nor a caller-supplied identity is fresh-genesis ownership. Absent-record
// late-epoch/import/checkpoint/hardfork admission remains unsupported.
type drwaIdentityMode struct {
	freshGenesis             bool
	afterHardFork            bool
	startEpoch, genesisEpoch uint32
	finalizedMetachainHeader []byte
}

// One instance belongs to one process-component factory across creation cycles.
// Its process component must Close before the next cycle can open the unit.
// This is store lifecycle ownership, not a native transaction provenance latch.
type drwaIdentityLifecycle struct {
	mutex   sync.Mutex
	unit    *drwaIdentityUnit
	failure error
}

type drwaIdentityUnit struct {
	owner    *drwaIdentityLifecycle
	db       drwaIdentityDB
	identity *drwa.DeploymentIdentity
	closed   bool
}

func drwaIdentityPath(databasePath string) (string, error) {
	if !filepath.IsAbs(databasePath) {
		return "", drwa.ErrDeploymentIdentity
	}
	unit := filepath.Join(databasePath, drwa.DeploymentIdentityRecord)
	// Exact path inspection only; no recursive search or shard template.
	for current := unit; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", drwa.ErrDeploymentIdentity
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return unit, nil
}

func validateDRWAIdentityStorage(parameters config.DBConfig, identity *drwa.DeploymentIdentity) error {
	if identity == nil || parameters.MaxBatchSize != 1 || parameters.BatchDelaySeconds <= 0 || parameters.MaxOpenFiles <= 0 || parameters.BloomFilterBitsPerKey < 0 || parameters.UseTmpAsFilePath {
		return drwa.ErrDeploymentIdentity
	}
	raw := identity.Raw()
	key := []byte(drwa.DeploymentIdentityRecord)
	// Native batch.internalLen is key+value+8 (selected batch.go116); stay in
	// the actual journal/Sync path, not its large-batch transaction alternative.
	if len(raw) == 0 || len(raw) > opt.DefaultWriteBuffer-len(key)-8 {
		return drwa.ErrDeploymentIdentity
	}
	return nil
}

func (o *drwaIdentityLifecycle) open(databasePath string, parameters config.DBConfig,
	identity *drwa.DeploymentIdentity, mode drwaIdentityMode) (*drwaIdentityUnit, error) {
	if o == nil {
		return nil, drwa.ErrDeploymentIdentity
	}
	if err := validateDRWAIdentityStorage(parameters, identity); err != nil {
		return nil, err
	}
	path, err := drwaIdentityPath(databasePath)
	if err != nil {
		return nil, err
	}
	if !o.mutex.TryLock() {
		return nil, drwa.ErrDeploymentIdentity
	}
	defer o.mutex.Unlock()
	if o.unit != nil || o.failure != nil {
		return nil, errors.Join(drwa.ErrDeploymentIdentity, o.failure)
	}
	db, err := database.NewLevelDB(path, parameters.BatchDelaySeconds, 1, parameters.MaxOpenFiles, parameters.BloomFilterBitsPerKey)
	if err != nil {
		return nil, err
	}
	return o.admitLocked(db, identity, mode)
}

// Caller owns the single lifecycle mutex. This routine also defines failure
// semantics for the existing native store; tests may isolate those semantics
// with labelled storage fixtures, never an authentication provider.
func (o *drwaIdentityLifecycle) admitLocked(db drwaIdentityDB, identity *drwa.DeploymentIdentity,
	mode drwaIdentityMode) (*drwaIdentityUnit, error) {
	raw := identity.Raw()
	key := []byte(drwa.DeploymentIdentityRecord)
	value, err := db.Get(key)
	if err != nil && !errors.Is(err, storage.ErrKeyNotFound) {
		closeErr := db.Close()
		o.failure = errors.Join(err, closeErr)
		return nil, o.failure
	}
	if err == nil {
		if !bytes.Equal(value, raw) {
			closeErr := db.Close()
			o.failure = errors.Join(drwa.ErrDeploymentIdentity, closeErr)
			return nil, o.failure
		}
	} else {
		if !mode.freshGenesis || mode.afterHardFork || mode.startEpoch != mode.genesisEpoch || mode.genesisEpoch != identity.GenesisEpoch() || !bytes.Equal(mode.finalizedMetachainHeader, identity.Header()) {
			closeErr := db.Close()
			o.failure = errors.Join(drwa.ErrDeploymentIdentity, closeErr)
			return nil, o.failure
		}
		// A returned error is NOT a storage non-event: pending bytes may persist
		// via native timer/Close. Never expose a view or destroy that valid record.
		if putErr := db.Put(key, raw); putErr != nil {
			closeErr := db.Close()
			o.failure = errors.Join(putErr, closeErr)
			return nil, o.failure
		}
	}
	unit := &drwaIdentityUnit{owner: o, db: db, identity: identity}
	o.unit = unit
	return unit, nil
}

// Domain never exposes mutable buffers or a view after closure/failure.
func (u *drwaIdentityUnit) Domain() []byte {
	if u == nil || u.owner == nil {
		return nil
	}
	o := u.owner
	o.mutex.Lock()
	defer o.mutex.Unlock()
	if o.unit != u || o.failure != nil || u.closed {
		return nil
	}
	return u.identity.Domain()
}

func (u *drwaIdentityUnit) Close() error {
	if u == nil || u.owner == nil {
		return nil
	}
	o := u.owner
	o.mutex.Lock()
	defer o.mutex.Unlock()
	if u.closed {
		return o.failure
	}
	// Invalidate the view before closing. A slow/failed close cannot be followed
	// by a second opener; open uses TryLock and the owner retains the failure.
	u.closed = true
	err := u.db.Close()
	if err != nil {
		o.failure = err
		return err
	}
	o.unit = nil
	return nil
}
