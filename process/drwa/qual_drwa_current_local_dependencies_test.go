package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// L46 development. These native-owner decoder/provenance fixtures are explicitly
// synthetic; they establish no complete admitted CEB or canonical route proof.
// Storage, protected keys, hash reads and selected-root recreation are native.
type qualCurrentLocalHost struct {
	body          []byte
	refs          []currentLocalReference
	faults        map[string]error
	hooks         map[string]func()
	calls         map[string]int
	mutateBuffers bool
}

func (h *qualCurrentLocalHost) IsInterfaceNil() bool { return h == nil }
func (h *qualCurrentLocalHost) check(stage string) error {
	h.calls[stage]++
	if f := h.hooks[stage]; f != nil {
		f()
	}
	return h.faults[stage]
}
func (h *qualCurrentLocalHost) VerifyCurrent(token, pointer, body []byte) error {
	if !bytes.Equal(body, h.body) {
		return errCurrentLocalDependency
	}
	if h.mutateBuffers {
		token[0] ^= 1
		pointer[0] ^= 1
		body[0] ^= 1
	}
	return h.check("current")
}
func (h *qualCurrentLocalHost) Dependencies(body []byte) ([]currentLocalReference, error) {
	if !bytes.Equal(body, h.body) {
		return nil, errCurrentLocalDependency
	}
	if h.mutateBuffers {
		body[0] ^= 1
	}
	return h.refs, h.check("decoder")
}
func (h *qualCurrentLocalHost) VerifyDependency(ref currentLocalReference, material []byte) error {
	if h.mutateBuffers {
		ref.kind[0] ^= 1
		ref.id[0] ^= 1
		ref.version[0] ^= 1
		ref.hash[0] ^= 1
		material[0] ^= 1
	}
	return h.check("dependency")
}

type qualCurrentLocalFixture struct {
	store                                           *qualNativeStore
	r                                               *currentLocalDependencies
	host                                            *qualCurrentLocalHost
	token, hash, body, pointerKey, bodyKey, pointer []byte
	keys, materials                                 [][]byte
}

func qualCurrentLocalNew(t *testing.T) *qualCurrentLocalFixture {
	t.Helper()
	f := &qualCurrentLocalFixture{store: qualRegistrationStore(t, 0), token: []byte("TOKEN-abcdef")}
	hasher := blake2b.NewBlake2b()
	f.host = &qualCurrentLocalHost{faults: make(map[string]error), hooks: make(map[string]func()), calls: make(map[string]int)}
	// Independent fixture keys/fields, not the component's key or framing helper.
	for _, kind := range []string{"authority", "public-schema", "gas-schedule", "profile-parser", "token-admin"} {
		material := []byte("synthetic locally applied " + kind + " version7")
		ref := currentLocalReference{[]byte(kind), []byte("fixture-id"), []byte{7}, hasher.Compute(string(material))}
		f.host.refs = append(f.host.refs, ref)
		key := append([]byte(currentLocalDependencyPrefix), qualRecordFrame(ref.kind, ref.id, ref.version)...)
		f.keys = append(f.keys, key)
		f.materials = append(f.materials, material)
		qualRecordPut(t, f.store, key, material)
	}
	f.body = []byte("synthetic complete CEB for fixture: five required dependency classes; not an admitted profile")
	f.host.body = bytes.Clone(f.body)
	f.hash = hasher.Compute(string(f.body))
	epoch := binary.BigEndian.AppendUint64(nil, 7)
	f.pointer = qualRecordFrame(epoch, f.hash)
	f.pointerKey = append([]byte(currentLocalPointerPrefix), qualRecordFrame(f.token)...)
	f.bodyKey = append([]byte(currentLocalBodyPrefix), qualRecordFrame(f.token, epoch)...)
	qualRecordPut(t, f.store, f.pointerKey, f.pointer)
	qualRecordPut(t, f.store, f.bodyKey, f.body)
	var err error
	f.r, err = newCurrentLocalDependencies(f.store, &marshal.GogoProtoMarshalizer{}, hasher, 4096, 10, f.host)
	require.NoError(t, err)
	return f
}
func (f *qualCurrentLocalFixture) resolve() (*currentLocalView, error) {
	return f.r.resolve(f.token, 7, f.hash)
}

func TestQualDRWACurrentLocalDependenciesExactRead(t *testing.T) {
	f := qualCurrentLocalNew(t)
	journal := f.store.JournalLen()
	v, err := f.resolve()
	require.NoError(t, err)
	require.Equal(t, f.body, v.body)
	require.Len(t, v.keys, 7)
	require.NoError(t, f.r.revalidate(v))
	require.Equal(t, journal, f.store.JournalLen(), "resolver writes no readiness state")
	require.Equal(t, 2, f.host.calls["current"])
	require.Equal(t, 10, f.host.calls["dependency"])
	// No all-shard input/read exists. This is local material resolution, not
	// permission to reopen, CURRENT_ACK or economic activity.
}

func TestQualDRWACurrentLocalDependenciesPointerAndBodyDenials(t *testing.T) {
	for _, name := range []string{"missing_current", "prepared_only", "malformed_pointer", "short_epoch", "wrong_epoch", "wrong_hash", "missing_body", "changed_body", "oversized_pointer", "oversized_body", "bad_token", "oversized_token", "short_hash", "canonical_denied", "decoder_denied"} {
		t.Run(name, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			fault := errors.New("selected native-owner denial")
			switch name {
			case "missing_current", "prepared_only":
				qualRecordPut(t, f.store, f.pointerKey, nil)
				if name == "prepared_only" {
					qualRecordPut(t, f.store, []byte(core.ProtectedKeyPrefix+"fixture/preparedCEB"), f.pointer)
				}
			case "malformed_pointer":
				qualRecordPut(t, f.store, f.pointerKey, []byte("not a canonical frame"))
			case "short_epoch":
				qualRecordPut(t, f.store, f.pointerKey, qualRecordFrame([]byte{7}, f.hash))
			case "wrong_epoch":
				qualRecordPut(t, f.store, f.pointerKey, qualRecordFrame(binary.BigEndian.AppendUint64(nil, 6), f.hash))
				otherKey := append([]byte(currentLocalBodyPrefix), qualRecordFrame(f.token, binary.BigEndian.AppendUint64(nil, 6))...)
				qualRecordPut(t, f.store, otherKey, f.body)
			case "wrong_hash":
				qualRecordPut(t, f.store, f.pointerKey, qualRecordFrame(binary.BigEndian.AppendUint64(nil, 7), bytes.Repeat([]byte{9}, 32)))
			case "missing_body":
				qualRecordPut(t, f.store, f.bodyKey, nil)
			case "changed_body":
				f.host.body = []byte("another complete body") // isolate the stored current hash
				qualRecordPut(t, f.store, f.bodyKey, f.host.body)
			case "oversized_pointer":
				qualRecordPut(t, f.store, f.pointerKey, make([]byte, 4097))
			case "oversized_body":
				qualRecordPut(t, f.store, f.bodyKey, make([]byte, 4097))
			case "bad_token":
				f.token = []byte("not-a-token")
			case "oversized_token":
				f.token = make([]byte, 4097)
			case "short_hash":
				f.hash = []byte{7}
			case "canonical_denied":
				f.host.faults["current"] = fault
			case "decoder_denied":
				f.host.faults["decoder"] = fault
			}
			v, err := f.resolve()
			require.Error(t, err)
			require.Nil(t, v)
			if name == "canonical_denied" || name == "decoder_denied" {
				require.ErrorIs(t, err, fault)
			}
		})
	}
}

func TestQualDRWACurrentLocalDependenciesEveryMaterialRequired(t *testing.T) {
	for i, kind := range []string{"authority", "public-schema", "gas-schedule", "profile-parser", "token-admin"} {
		for _, mode := range []string{"absent", "hash_mismatch"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := qualCurrentLocalNew(t)
				var value []byte
				if mode == "hash_mismatch" {
					value = []byte("obsolete material")
				}
				qualRecordPut(t, f.store, f.keys[i], value)
				v, err := f.resolve()
				require.Error(t, err)
				require.Nil(t, v)
			})
		}
	}
}

func TestQualDRWACurrentLocalDependenciesReferenceDenials(t *testing.T) {
	for _, name := range []string{"empty", "too_many", "duplicate", "empty_kind", "empty_id", "empty_version", "short_hash", "oversized_id", "dependency_denied"} {
		t.Run(name, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			fault := errors.New("dependency provenance denied")
			switch name {
			case "empty":
				f.host.refs = nil
			case "too_many":
				f.r.maxReferences = 4
			case "duplicate":
				f.host.refs = append(f.host.refs, f.host.refs[0])
			case "empty_kind":
				f.host.refs[0].kind = nil
			case "empty_id":
				f.host.refs[0].id = nil
			case "empty_version":
				f.host.refs[0].version = nil
			case "short_hash":
				f.host.refs[0].hash = []byte{7}
			case "oversized_id":
				f.host.refs[0].id = make([]byte, 4097)
			case "dependency_denied":
				f.host.faults["dependency"] = fault
			}
			v, err := f.resolve()
			require.Error(t, err)
			require.Nil(t, v)
			if name == "dependency_denied" {
				require.ErrorIs(t, err, fault)
			}
		})
	}
}

func TestQualDRWACurrentLocalDependenciesChangedDuringRead(t *testing.T) {
	for _, name := range []string{"pointer", "body", "first_dependency", "last_dependency"} {
		t.Run(name, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			key := f.pointerKey
			if name == "body" {
				key = f.bodyKey
			}
			if name == "first_dependency" {
				key = f.keys[0]
			}
			if name == "last_dependency" {
				key = f.keys[4]
			}
			f.host.hooks["dependency"] = func() {
				if f.host.calls["dependency"] == 5 {
					qualRecordPut(t, f.store, key, []byte("changed after validation"))
				}
			}
			v, err := f.resolve()
			require.Error(t, err)
			require.Nil(t, v)
		})
	}
}

func TestQualDRWACurrentLocalDependenciesSnapshotRevalidation(t *testing.T) {
	for _, name := range []string{"pointer", "body", "dependency", "nil_snapshot", "foreign_owner", "material_changed", "list_changed"} {
		t.Run(name, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			v, err := f.resolve()
			require.NoError(t, err)
			switch name {
			case "pointer":
				qualRecordPut(t, f.store, f.pointerKey, qualRecordFrame(binary.BigEndian.AppendUint64(nil, 8), f.hash))
			case "body":
				qualRecordPut(t, f.store, f.bodyKey, []byte("changed body"))
			case "dependency":
				qualRecordPut(t, f.store, f.keys[0], []byte("changed dependency"))
			case "nil_snapshot":
				v = nil
			case "foreign_owner":
				other := qualCurrentLocalNew(t)
				v, err = other.resolve()
				require.NoError(t, err)
			case "material_changed":
				v.materials[2][0] ^= 1
			case "list_changed":
				f.host.refs = f.host.refs[:4]
			}
			require.Error(t, f.r.revalidate(v))
		})
	}
}

func TestQualDRWACurrentLocalDependenciesBuffersAndPersistence(t *testing.T) {
	f := qualCurrentLocalNew(t)
	f.host.mutateBuffers = true
	v, err := f.resolve()
	require.NoError(t, err)
	require.Equal(t, f.body, v.body)
	require.Equal(t, f.pointer, v.pointer)
	for i, key := range f.keys {
		require.Equal(t, f.materials[i], qualRegistryValue(t, f.store, string(key)))
	}
	require.NoError(t, f.r.revalidate(v))
	root, err := f.store.Commit()
	require.NoError(t, err)
	qualRecordPut(t, f.store, f.pointerKey, qualRecordFrame(binary.BigEndian.AppendUint64(nil, 8), f.hash))
	require.Error(t, f.r.revalidate(v))
	require.NoError(t, f.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.NoError(t, f.r.revalidate(v), "selected native root restores exact local bytes; not canonicality proof")
}

type qualCurrentLocalReadStore struct {
	state.AccountsAdapter
	key   []byte
	fault error
}
type qualCurrentLocalReadAccount struct {
	state.UserAccountHandler
	key   []byte
	fault error
}

func (a *qualCurrentLocalReadAccount) RetrieveValue(key []byte) ([]byte, uint32, error) {
	if bytes.Equal(key, a.key) {
		return nil, 0, a.fault
	}
	return a.UserAccountHandler.RetrieveValue(key)
}
func (a *qualCurrentLocalReadStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	u, err := a.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	return &qualCurrentLocalReadAccount{u.(state.UserAccountHandler), a.key, a.fault}, nil
}
func TestQualDRWACurrentLocalDependenciesReadFailuresAndConstruction(t *testing.T) {
	for _, name := range []string{"pointer", "body", "dependency"} {
		t.Run(name, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			key := f.pointerKey
			if name == "body" {
				key = f.bodyKey
			}
			if name == "dependency" {
				key = f.keys[2]
			}
			fault := errors.New("exact selected native read failed")
			f.r.codec.state.accounts = &qualCurrentLocalReadStore{f.store, key, fault}
			v, err := f.resolve()
			require.ErrorIs(t, err, fault)
			require.Nil(t, v)
		})
	}
	for _, name := range []string{"nil_host", "nil_accounts", "nil_marshaller", "nil_hasher", "zero_bytes", "zero_references", "excess_references"} {
		t.Run(name, func(t *testing.T) {
			f := qualCurrentLocalNew(t)
			a, h, m, hash := state.AccountsAdapter(f.store), currentLocalHost(f.host), f.r.codec.marshaller, f.r.codec.hasher
			n, c := 4096, 10
			switch name {
			case "nil_host":
				h = nil
			case "nil_accounts":
				a = nil
			case "nil_marshaller":
				m = nil
			case "nil_hasher":
				hash = nil
			case "zero_bytes":
				n = 0
			case "zero_references":
				c = 0
			case "excess_references":
				c = 2049
			}
			r, err := newCurrentLocalDependencies(a, m, hash, n, c, h)
			require.Error(t, err)
			require.Nil(t, r)
		})
	}
}
