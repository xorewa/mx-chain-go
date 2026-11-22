package processing

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/block"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/drwa"
	"github.com/multiversx/mx-chain-go/storage"
	"github.com/multiversx/mx-chain-go/storage/database"
	"github.com/stretchr/testify/require"
)

// Synthetic deployment/bounds only; integrity pin is not actual trusted input
// delivery, canonical history, profile admission or native creating authority.
func qualA77Identity(t *testing.T) *drwa.DeploymentIdentity {
	t.Helper()
	m := &marshal.GogoProtoMarshalizer{}
	h := blake2b.NewBlake2b()
	header, err := m.Marshal(&block.MetaBlock{Epoch: 17, RootHash: []byte("synthetic root")})
	require.NoError(t, err)
	chain := []byte("synthetic chain")
	hash := h.Compute(string(header))
	epoch := make([]byte, 4)
	binary.BigEndian.PutUint32(epoch, 17)
	preimage := append(append([]byte("DRWA/NETWORK/v1"), chain...), hash...)
	// Independent literal field-1 Batch framing, not the decoder as an encoder.
	fields := [][]byte{[]byte("DRWA/DEPLOYMENT-IDENTITY/v1"), chain, epoch, header, hash, h.Compute(string(preimage))}
	var raw []byte
	for _, f := range fields {
		raw = append(raw, 0x0a)
		raw = binary.AppendUvarint(raw, uint64(len(f)))
		raw = append(raw, f...)
	}
	pin := sha256.Sum256(raw)
	identity, err := drwa.DecodeDeploymentIdentity(raw, pin[:], chain, 17, drwa.DeploymentIdentityBounds{Bytes: 4096, ChainIDBytes: 64, HeaderBytes: 2048}, m, h)
	require.NoError(t, err)
	return identity
}
func qualA77IdentityParameters() config.DBConfig {
	return config.DBConfig{MaxBatchSize: 1, BatchDelaySeconds: 1, MaxOpenFiles: 8}
}
func qualA77IdentityFresh(identity *drwa.DeploymentIdentity) drwaIdentityMode {
	return drwaIdentityMode{freshGenesis: true, startEpoch: 17, genesisEpoch: 17, finalizedMetachainHeader: identity.Header()}
}

type qualA77CountingDB struct {
	drwaIdentityDB
	puts       int
	closeError error
}

func (db *qualA77CountingDB) Put(key, value []byte) error {
	db.puts++
	return db.drwaIdentityDB.Put(key, value)
}
func (db *qualA77CountingDB) Close() error {
	return errors.Join(db.drwaIdentityDB.Close(), db.closeError)
}

func TestQualA72NativeIdentityFreshRestartAndRoleChange(t *testing.T) {
	identity := qualA77Identity(t)
	parameters := qualA77IdentityParameters()
	chain := filepath.Join(t.TempDir(), "chain-specific")
	owner := &drwaIdentityLifecycle{}
	unit, err := owner.open(chain, parameters, identity, qualA77IdentityFresh(identity))
	require.NoError(t, err)
	require.Equal(t, identity.Domain(), unit.Domain())
	_, err = owner.open(chain, parameters, identity, qualA77IdentityFresh(identity))
	require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
	require.NoError(t, unit.Close())
	require.Nil(t, unit.Domain())
	path, err := drwaIdentityPath(chain)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(chain, "DRWA_NETWORK_IDENTITY_V1"), path)
	// Two actual close/reopen reads. No shard value enters the path. Later-epoch
	// local empty/hardfork headers cannot replace an existing original binding.
	for _, epoch := range []uint32{200, 350} {
		db, e := database.NewLevelDB(path, parameters.BatchDelaySeconds, 1, parameters.MaxOpenFiles, 0)
		require.NoError(t, e)
		counted := &qualA77CountingDB{drwaIdentityDB: db}
		next := &drwaIdentityLifecycle{}
		next.mutex.Lock()
		unit, e = next.admitLocked(counted, identity, drwaIdentityMode{afterHardFork: true, startEpoch: epoch, genesisEpoch: 17})
		next.mutex.Unlock()
		require.NoError(t, e)
		require.Zero(t, counted.puts, "load-only is at the identity-key level, not database-file level")
		require.Equal(t, identity.Domain(), unit.Domain())
		require.NoError(t, unit.Close())
	}
}

func TestQualA72NativeIdentityUnavailableModesAndCloseFailure(t *testing.T) {
	identity := qualA77Identity(t)
	parameters := qualA77IdentityParameters()
	for _, fault := range []string{"late_epoch", "hardfork", "no_fresh_owner", "wrong_local_header", "nil_identity", "non_sync_batch", "relative_path", "symlink"} {
		t.Run(fault, func(t *testing.T) {
			owner := &drwaIdentityLifecycle{}
			path := filepath.Join(t.TempDir(), "chain")
			mode := qualA77IdentityFresh(identity)
			params := parameters
			input := identity
			switch fault {
			case "late_epoch":
				mode.startEpoch = 18
			case "hardfork":
				mode.afterHardFork = true
			case "no_fresh_owner":
				mode.freshGenesis = false
			case "wrong_local_header":
				mode.finalizedMetachainHeader = []byte("wrong")
			case "nil_identity":
				input = nil
			case "non_sync_batch":
				params.MaxBatchSize = 2
			case "relative_path":
				path = "relative-chain"
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				require.NoError(t, os.MkdirAll(target, 0700))
				require.NoError(t, os.Symlink(target, path))
			}
			got, err := owner.open(path, params, input, mode)
			require.ErrorIs(t, err, drwa.ErrDeploymentIdentity)
			require.Nil(t, got)
		})
	}
	t.Run("failed_close_blocks_recreation", func(t *testing.T) {
		owner := &drwaIdentityLifecycle{}
		chain := filepath.Join(t.TempDir(), "chain")
		unit, e := owner.open(chain, parameters, identity, qualA77IdentityFresh(identity))
		require.NoError(t, e)
		failure := errors.New("synthetic close acknowledgement failure")
		unit.db = &qualA77CountingDB{drwaIdentityDB: unit.db, closeError: failure}
		require.ErrorIs(t, unit.Close(), failure)
		require.Nil(t, unit.Domain())
		_, e = owner.open(chain, parameters, identity, qualA77IdentityFresh(identity))
		require.ErrorIs(t, e, failure)
	})
	t.Run("corrupt_record_is_not_rewritten", func(t *testing.T) {
		chain := filepath.Join(t.TempDir(), "chain")
		path, e := drwaIdentityPath(chain)
		require.NoError(t, e)
		db, e := database.NewLevelDB(path, 1, 1, 8, 0)
		require.NoError(t, e)
		require.NoError(t, db.Put([]byte("DRWA_NETWORK_IDENTITY_V1"), []byte("corrupt")))
		require.NoError(t, db.Close())
		owner := &drwaIdentityLifecycle{}
		unit, e := owner.open(chain, parameters, identity, qualA77IdentityFresh(identity))
		require.ErrorIs(t, e, drwa.ErrDeploymentIdentity)
		require.Nil(t, unit)
		db, e = database.NewLevelDB(path, 1, 1, 8, 0)
		require.NoError(t, e)
		defer func() { require.NoError(t, db.Close()) }()
		got, e := db.Get([]byte("DRWA_NETWORK_IDENTITY_V1"))
		require.NoError(t, e)
		require.Equal(t, []byte("corrupt"), got)
	})
}

// This storage-only fixture models the pinned native pending-batch contract;
// it is not a live fault, native timer/crash proof or authentication provider.
type qualA77PendingIdentityDB struct {
	value, pending      []byte
	puts, closes, ticks int
	timerBeforeClose    bool
	pendingRead         bool
	failure             error
}

func (db *qualA77PendingIdentityDB) Get(_ []byte) ([]byte, error) {
	if db.pending != nil {
		return bytes.Clone(db.pending), nil
	}
	if db.value == nil {
		return nil, storage.ErrKeyNotFound
	}
	return bytes.Clone(db.value), nil
}
func (db *qualA77PendingIdentityDB) Put(_, value []byte) error {
	db.puts++
	db.pending = bytes.Clone(value)
	return db.failure
}
func (db *qualA77PendingIdentityDB) Close() error {
	db.closes++
	got, e := db.Get(nil)
	db.pendingRead = e == nil && bytes.Equal(got, db.pending)
	if db.timerBeforeClose {
		db.ticks++
	}
	if db.pending != nil {
		db.value = bytes.Clone(db.pending)
		db.pending = nil
	}
	return nil
}
func TestQualA72IdentityPutFailureNeverExportsView(t *testing.T) {
	identity := qualA77Identity(t)
	for _, timer := range []bool{false, true} {
		db := &qualA77PendingIdentityDB{failure: errors.New("synthetic Put error"), timerBeforeClose: timer}
		owner := &drwaIdentityLifecycle{}
		owner.mutex.Lock()
		unit, e := owner.admitLocked(db, identity, qualA77IdentityFresh(identity))
		owner.mutex.Unlock()
		require.ErrorIs(t, e, db.failure)
		require.Nil(t, unit)
		require.True(t, db.pendingRead, "same-handle Get sees pending bytes, not durability")
		require.Equal(t, 1, db.puts)
		require.Equal(t, 1, db.closes)
		require.Equal(t, identity.Raw(), db.value)
		if timer {
			require.Equal(t, 1, db.ticks)
		}
		// A subsequent owner/start sees a record by ordinary exact load/verify.
		// The previous failed Put cannot become a second initialization.
		next := &drwaIdentityLifecycle{}
		next.mutex.Lock()
		unit, e = next.admitLocked(db, identity, drwaIdentityMode{})
		next.mutex.Unlock()
		require.NoError(t, e)
		require.Equal(t, 1, db.puts)
		require.Equal(t, identity.Domain(), unit.Domain())
		require.NoError(t, unit.Close())
		require.Equal(t, identity.Raw(), db.value)
	}
}
