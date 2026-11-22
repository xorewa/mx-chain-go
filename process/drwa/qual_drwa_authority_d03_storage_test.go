package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Unreviewed qualification-only storage component. DO NOT EXECUTE before
// W03_protected_admission_storage_parameters_01.json and these exact bytes
// receive independent review. No authority/claim/funding/terminal eligibility
// verifier is provided. Test calls are explicitly synthetic storage transitions;
// a category here cannot authorize real protected admission or cancellation.
// Fixed slots bound total structurally; both partitions live in the same item.
const w03D03StoragePrefix = "W03_D03_ACTIVE/v1"
const w03D03StorageKeyPrefix = core.ProtectedKeyPrefix + "DRWA@authorityD03Fixture@active@"

var w03ErrD03Storage = errors.New("denied synthetic W03 D03 storage")

type w03D03Slot struct {
	id                      uint64
	category, phase, length byte
	subject                 [64]byte
	digest                  [32]byte
}

type w03D03Aggregate struct {
	next  uint64
	slots [4]w03D03Slot
}

func (a w03D03Aggregate) validate() error {
	if a.next == 0 {
		return w03ErrD03Storage
	}
	var previous uint64
	var counts [2]int
	empty := false
	for i, slot := range a.slots {
		if slot.phase == 0 {
			if slot != (w03D03Slot{}) {
				return w03ErrD03Storage
			}
			empty = true
			continue
		}
		if empty || slot.phase > 2 || slot.category > 1 {
			return w03ErrD03Storage
		}
		// previous starts at zero, so strict increase also rejects zero IDs.
		if slot.id <= previous || slot.id >= a.next {
			return w03ErrD03Storage
		}
		if slot.length == 0 || slot.length > 64 {
			return w03ErrD03Storage
		}
		for _, padding := range slot.subject[slot.length:] {
			if padding != 0 {
				return w03ErrD03Storage
			}
		}
		for _, prior := range a.slots[:i] {
			if prior.length == slot.length && prior.subject == slot.subject {
				return w03ErrD03Storage
			}
		}
		counts[slot.category]++
		if counts[slot.category] > 2 {
			return w03ErrD03Storage
		}
		previous = slot.id
	}
	return nil
}

func (a w03D03Aggregate) encode() ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	value := binary.BigEndian.AppendUint64([]byte(w03D03StoragePrefix), a.next)
	for _, slot := range a.slots {
		value = binary.BigEndian.AppendUint64(value, slot.id)
		value = append(value, slot.category, slot.phase, slot.length)
		value = append(value, slot.subject[:]...)
		value = append(value, slot.digest[:]...)
	}
	return value, nil
}

func w03D03Decode(value []byte) (w03D03Aggregate, error) {
	var a w03D03Aggregate
	if len(value) != 453 || !bytes.Equal(value[:len(w03D03StoragePrefix)], []byte(w03D03StoragePrefix)) {
		return a, w03ErrD03Storage
	}
	a.next = binary.BigEndian.Uint64(value[17:25])
	for i := range a.slots {
		slot := &a.slots[i]
		start := 25 + i*107
		slot.id = binary.BigEndian.Uint64(value[start : start+8])
		slot.category, slot.phase, slot.length = value[start+8], value[start+9], value[start+10]
		copy(slot.subject[:], value[start+11:start+75])
		copy(slot.digest[:], value[start+75:start+107])
	}
	return a, a.validate()
}

func w03D03Key(token string) ([]byte, error) {
	if token != "TOKEN-000001" && token != "TOKEN-000002" {
		return nil, w03ErrD03Storage
	}
	return []byte(w03D03StorageKeyPrefix + token), nil
}

func w03D03Read(store state.AccountsAdapter, token string) (state.UserAccountHandler, w03D03Aggregate, []byte, error) {
	key, err := w03D03Key(token)
	if err != nil {
		return nil, w03D03Aggregate{}, nil, err
	}
	account, err := store.GetExistingAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, w03D03Aggregate{}, nil, err
	}
	// This fixture uses the existing native UserAccount factory exclusively.
	// It is not a production account-type or canonical context verifier.
	user := account.(state.UserAccountHandler)
	value, _, err := user.RetrieveValue(key)
	if err != nil {
		return nil, w03D03Aggregate{}, nil, err
	}
	a, err := w03D03Decode(value)
	return user, a, value, err
}

func w03D03Write(store state.AccountsAdapter, user state.UserAccountHandler, token string, a w03D03Aggregate) error {
	value, err := a.encode()
	if err != nil {
		return err
	}
	key, err := w03D03Key(token)
	if err != nil {
		return err
	}
	if err = user.SaveKeyValue(key, value); err != nil {
		return err
	}
	return store.SaveAccount(user)
}

// Called only inside the public T04 Execute owner by the synthetic tests below.
func w03D03Insert(store state.AccountsAdapter, token string, entry w03D03Slot) error {
	user, a, _, err := w03D03Read(store, token)
	if err != nil {
		return err
	}
	for _, prior := range a.slots {
		if prior.phase != 0 && prior.id == entry.id {
			if prior == entry {
				return nil // No save, journal entry, slot or nonce for exact duplicate.
			}
			return w03ErrD03Storage
		}
	}
	if entry.id != a.next || entry.phase != 1 {
		return w03ErrD03Storage
	}
	var count, live int
	for _, prior := range a.slots {
		if prior.phase != 0 {
			live++
			if prior.category == entry.category {
				count++
			}
		}
	}
	if count >= 2 {
		return w03ErrD03Storage
	}
	// Valid fixed four-slot aggregate plus count<2 in this partition implies
	// live<=3. No redundant total-cap rejection is added.
	a.slots[live] = entry
	// Category validation and a wrapped-zero next nonce fail in encode before
	// SaveKeyValue/SaveAccount. Repeating those guards here adds no guarantee.
	a.next++
	return w03D03Write(store, user, token, a)
}

// Storage-only phase/removal transition, not a real start or terminal authority.
func w03D03Transition(store state.AccountsAdapter, token string, id uint64, remove bool) error {
	user, a, _, err := w03D03Read(store, token)
	if err != nil {
		return err
	}
	for i, slot := range a.slots {
		if slot.phase == 0 || slot.id != id {
			continue
		}
		if remove {
			copy(a.slots[i:], a.slots[i+1:])
			a.slots[3] = w03D03Slot{}
		} else {
			if slot.phase == 2 {
				return nil
			}
			a.slots[i].phase = 2
		}
		return w03D03Write(store, user, token, a)
	}
	return w03ErrD03Storage
}

func w03D03StorageFixture(t *testing.T) *qualNativeStore {
	t.Helper()
	store := qualContainmentStore(t) // Real native AccountsDB/trie, read-only T04 fixture.
	account, err := store.LoadAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	user := account.(state.UserAccountHandler)
	for _, token := range []string{"TOKEN-000001", "TOKEN-000002"} {
		require.NoError(t, w03D03Write(store, user, token, w03D03Aggregate{next: 1}))
	}
	_, err = store.Commit()
	require.NoError(t, err)
	return store
}

func w03D03Entry(id uint64, category byte) w03D03Slot {
	entry := w03D03Slot{id: id, category: category, phase: 1, length: 8}
	binary.BigEndian.PutUint64(entry.subject[:8], id)
	entry.digest[0] = byte(id)
	return entry
}

func w03D03Operation(operation func() error) func() (*vmcommon.VMOutput, error) {
	return func() (*vmcommon.VMOutput, error) {
		return &vmcommon.VMOutput{ReturnData: [][]byte{[]byte("synthetic storage output")}}, operation()
	}
}

func TestQualDRWAAuthorityD03StorageOccupancy(t *testing.T) {
	store := w03D03StorageFixture(t)
	owner, err := NewRollbackContainment(store)
	require.NoError(t, err)
	_, _, tokenB, err := w03D03Read(store, "TOKEN-000002")
	require.NoError(t, err)
	for id := uint64(1); id <= 2; id++ {
		entry := w03D03Entry(id, 0)
		require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", entry) })))
	}
	_, ordinary, before, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.Equal(t, uint64(3), ordinary.next)
	require.Error(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(3, 0)) })))
	_, _, denied, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.Equal(t, before, denied)
	for id := uint64(3); id <= 4; id++ {
		entry := w03D03Entry(id, 1)
		require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", entry) })))
	}
	_, full, before, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.Equal(t, uint64(5), full.next)
	for _, slot := range full.slots {
		require.NotZero(t, slot.phase)
	}
	journal := store.JournalLen()
	require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(1, 0)) })))
	require.Equal(t, journal, store.JournalLen())
	conflict := w03D03Entry(1, 0)
	conflict.digest[0] ^= 1
	for _, entry := range []w03D03Slot{conflict, w03D03Entry(5, 0), w03D03Entry(5, 1)} {
		require.Error(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", entry) })))
	}
	_, _, unchanged, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.Equal(t, before, unchanged)
	require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Transition(store, "TOKEN-000001", 1, false) })))
	journal = store.JournalLen()
	require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Transition(store, "TOKEN-000001", 1, false) })))
	require.Equal(t, journal, store.JournalLen())
	require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Transition(store, "TOKEN-000001", 2, true) })))
	require.Error(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(2, 0)) })))
	require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(5, 0)) })))
	_, current, _, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.Equal(t, [4]uint64{1, 3, 4, 5}, [4]uint64{current.slots[0].id, current.slots[1].id, current.slots[2].id, current.slots[3].id})
	require.Equal(t, byte(2), current.slots[0].phase)
	require.Equal(t, uint64(6), current.next)
	_, _, other, err := w03D03Read(store, "TOKEN-000002")
	require.NoError(t, err)
	require.Equal(t, tokenB, other)
	_, _, _, err = w03D03Read(store, "TOKEN-000003")
	require.Error(t, err)
	roots, _, err := owner.Commit()
	require.NoError(t, err)
	require.NoError(t, store.RecreateTrie(holders.NewDefaultRootHashesHolder(roots[0])))
	_, reloaded, _, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.Equal(t, current, reloaded)
}

func TestQualDRWAAuthorityD03StorageRollback(t *testing.T) {
	for _, failedUndo := range []bool{false, true} {
		store := w03D03StorageFixture(t)
		_, _, before, err := w03D03Read(store, "TOKEN-000001")
		require.NoError(t, err)
		owner, err := NewRollbackContainment(store)
		require.NoError(t, err)
		original, rollback := errors.New("after native save"), errors.New("native undo failure")
		store.saveErr = original
		if failedUndo {
			store.revertErr = rollback
		}
		err = owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(1, 1)) }))
		require.ErrorIs(t, err, original)
		if failedUndo {
			require.ErrorIs(t, err, rollback)
			_, outputs, commitErr := owner.Commit()
			require.ErrorIs(t, commitErr, rollback)
			require.Nil(t, outputs)
			store.revertErr, store.saveErr = nil, nil
			require.NoError(t, owner.Recover())
			owner, err = NewRollbackContainment(store)
			require.NoError(t, err)
		} else {
			store.saveErr = nil
		}
		_, _, restored, err := w03D03Read(store, "TOKEN-000001")
		require.NoError(t, err)
		require.Equal(t, before, restored)
		require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(1, 1)) })))
		_, a, _, err := w03D03Read(store, "TOKEN-000001")
		require.NoError(t, err)
		require.Equal(t, uint64(2), a.next)
		_, outputs, err := owner.Commit()
		require.NoError(t, err)
		require.Len(t, outputs, 1)
	}
}

func TestQualDRWAAuthorityD03StorageCodec(t *testing.T) {
	// Independent empty bytes from the candidate grammar: 17 literal prefix,
	// eight bytes for next=1, then four all-zero 107-byte slots. No encoder
	// under test supplies these expected bytes.
	empty := append([]byte("W03_D03_ACTIVE/v1"), []byte{0, 0, 0, 0, 0, 0, 0, 1}...)
	empty = append(empty, make([]byte, 428)...)
	encoded, err := (w03D03Aggregate{next: 1}).encode()
	require.NoError(t, err)
	require.Equal(t, empty, encoded)
	require.Len(t, encoded, 453)
	decoded, err := w03D03Decode(empty)
	require.NoError(t, err)
	require.Equal(t, w03D03Aggregate{next: 1}, decoded)
	for cut := 0; cut < len(empty); cut++ {
		_, err = w03D03Decode(empty[:cut])
		require.Error(t, err)
	}
	_, err = w03D03Decode(append(bytes.Clone(empty), 0))
	require.Error(t, err)
	wrongPrefix := bytes.Clone(empty)
	wrongPrefix[0] ^= 1
	_, err = w03D03Decode(wrongPrefix)
	require.Error(t, err)
	zeroNonce := bytes.Clone(empty)
	zeroNonce[24] = 0
	_, err = w03D03Decode(zeroNonce)
	require.Error(t, err)
	// Validator witnesses keep all other constraints valid. Expected denials
	// come from the candidate grammar, not a serialize/deserialize round trip.
	valid := w03D03Aggregate{next: 3, slots: [4]w03D03Slot{w03D03Entry(1, 0), w03D03Entry(2, 1)}}
	// Independently laid-out public live vector from the declared grammar.
	// Positions are literal contract bytes, not offsets obtained from encode.
	liveBytes := bytes.Clone(empty)
	for position, value := range map[int]byte{
		24: 3, 32: 1, 34: 1, 35: 8, 43: 1, 100: 1,
		139: 2, 140: 1, 141: 1, 142: 8, 150: 2, 207: 2,
	} {
		liveBytes[position] = value
	}
	encoded, err = valid.encode()
	require.NoError(t, err)
	require.Equal(t, liveBytes, encoded)
	decoded, err = w03D03Decode(liveBytes)
	require.NoError(t, err)
	require.Equal(t, valid, decoded)
	for _, row := range []struct {
		name   string
		change func(*w03D03Aggregate)
	}{
		{"nonzero_empty", func(a *w03D03Aggregate) { a.slots[2].digest[0] = 1 }},
		{"gap", func(a *w03D03Aggregate) { a.slots[0] = w03D03Slot{} }},
		{"unknown_phase", func(a *w03D03Aggregate) { a.slots[0].phase = 3 }},
		{"unknown_category", func(a *w03D03Aggregate) { a.slots[0].category = 2 }},
		{"zero_id", func(a *w03D03Aggregate) { a.slots[0].id = 0 }},
		{"duplicate_id", func(a *w03D03Aggregate) { a.slots[1].id = 1 }},
		{"unordered_ids", func(a *w03D03Aggregate) { a.slots[0].id, a.slots[1].id = 2, 1 }},
		{"future_id", func(a *w03D03Aggregate) { a.slots[1].id = 3 }},
		{"empty_subject", func(a *w03D03Aggregate) { a.slots[0].length, a.slots[0].subject = 0, [64]byte{} }},
		{"oversized_subject", func(a *w03D03Aggregate) { a.slots[0].length = 65 }},
		{"noncanonical_padding", func(a *w03D03Aggregate) { a.slots[0].subject[8] = 1 }},
		{"duplicate_subject", func(a *w03D03Aggregate) { a.slots[1].subject = a.slots[0].subject }},
		{"ordinary_partition", func(a *w03D03Aggregate) {
			a.next = 4
			a.slots = [4]w03D03Slot{w03D03Entry(1, 0), w03D03Entry(2, 0), w03D03Entry(3, 0)}
		}},
		{"protected_partition", func(a *w03D03Aggregate) {
			a.next = 4
			a.slots = [4]w03D03Slot{w03D03Entry(1, 1), w03D03Entry(2, 1), w03D03Entry(3, 1)}
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := valid
			row.change(&a)
			require.Error(t, a.validate())
			_, err := a.encode()
			require.Error(t, err)
		})
	}
}

func TestQualDRWAAuthorityD03StorageBoundaries(t *testing.T) {
	for _, row := range []struct {
		name   string
		next   uint64
		change func(*w03D03Slot)
	}{
		{"wrong_id", 1, func(e *w03D03Slot) { e.id = 2 }},
		{"empty_slot_is_not_duplicate", 1, func(e *w03D03Slot) { *e = w03D03Slot{} }},
		{"nonce_overflow", math.MaxUint64, func(_ *w03D03Slot) {}},
		{"already_started_entry", 1, func(e *w03D03Slot) { e.phase = 2 }},
		{"unknown_partition", 1, func(e *w03D03Slot) { e.category = 2 }},
		{"invalid_subject", 1, func(e *w03D03Slot) { e.length = 0; e.subject = [64]byte{} }},
	} {
		t.Run(row.name, func(t *testing.T) {
			store := w03D03StorageFixture(t)
			user, _, _, err := w03D03Read(store, "TOKEN-000001")
			require.NoError(t, err)
			require.NoError(t, w03D03Write(store, user, "TOKEN-000001", w03D03Aggregate{next: row.next}))
			_, err = store.Commit()
			require.NoError(t, err)
			owner, err := NewRollbackContainment(store)
			require.NoError(t, err)
			_, _, before, err := w03D03Read(store, "TOKEN-000001")
			require.NoError(t, err)
			entry := w03D03Entry(row.next, 0)
			row.change(&entry)
			require.Error(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", entry) })))
			_, _, after, err := w03D03Read(store, "TOKEN-000001")
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
	store := w03D03StorageFixture(t)
	owner, err := NewRollbackContainment(store)
	require.NoError(t, err)
	require.Error(t, owner.Execute(w03D03Operation(func() error { return w03D03Transition(store, "TOKEN-000001", 1, false) })))
	require.Error(t, owner.Execute(w03D03Operation(func() error { return w03D03Transition(store, "TOKEN-000001", 1, true) })))
	// Replay of the last removed ID must deny even when there are no live IDs
	// whose ordering could independently mask the fresh-nonce equality guard.
	require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(1, 0)) })))
	require.NoError(t, owner.Execute(w03D03Operation(func() error { return w03D03Transition(store, "TOKEN-000001", 1, true) })))
	require.Error(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(1, 0)) })))
	account, err := store.GetExistingAccount(qualContainmentAddress)
	require.NoError(t, err)
	ordinary := account.(state.UserAccountHandler)
	for _, token := range []string{"TOKEN-000001", "TOKEN-000002"} {
		key, err := w03D03Key(token)
		require.NoError(t, err)
		value, _, err := ordinary.RetrieveValue(key)
		require.NoError(t, err)
		require.Empty(t, value)
	}
	// Remove only a fixture record, then prove absence cannot initialize a new
	// aggregate. This is not a production cleanup or genesis operation.
	system, err := store.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	user := system.(state.UserAccountHandler)
	key, err := w03D03Key("TOKEN-000001")
	require.NoError(t, err)
	require.NoError(t, user.SaveKeyValue(key, nil))
	require.NoError(t, store.SaveAccount(user))
	_, err = store.Commit()
	require.NoError(t, err)
	_, _, _, err = w03D03Read(store, "TOKEN-000001")
	require.Error(t, err)
}

// Qualification-only faults at declared interface boundaries. Each read may
// return valid native bytes/account together with an injected error, isolating
// error propagation from malformed-body denial. SaveAccount unwraps the user
// wrapper so persistence still uses the actual native concrete account.
type w03D03FaultStore struct {
	state.AccountsAdapter
	getErr, readErr, writeErr error
	loads, saves              int
}

type w03D03FaultUser struct {
	state.UserAccountHandler
	owner *w03D03FaultStore
}

func (s *w03D03FaultStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	s.loads++
	account, err := s.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return account, err
	}
	return &w03D03FaultUser{UserAccountHandler: account.(state.UserAccountHandler), owner: s}, s.getErr
}

func (s *w03D03FaultStore) SaveAccount(account vmcommon.AccountHandler) error {
	s.saves++
	if user, ok := account.(*w03D03FaultUser); ok {
		account = user.UserAccountHandler
	}
	return s.AccountsAdapter.SaveAccount(account)
}

func (u *w03D03FaultUser) RetrieveValue(key []byte) ([]byte, uint32, error) {
	value, depth, err := u.UserAccountHandler.RetrieveValue(key)
	if err != nil {
		return value, depth, err
	}
	return value, depth, u.owner.readErr
}

func (u *w03D03FaultUser) SaveKeyValue(key, value []byte) error {
	if err := u.UserAccountHandler.SaveKeyValue(key, value); err != nil {
		return err
	}
	return u.owner.writeErr
}

func TestQualDRWAAuthorityD03StorageErrors(t *testing.T) {
	for _, boundary := range []string{"get_account", "retrieve_value"} {
		t.Run(boundary, func(t *testing.T) {
			store := &w03D03FaultStore{AccountsAdapter: w03D03StorageFixture(t)}
			fault := errors.New("injected native interface error")
			if boundary == "get_account" {
				store.getErr = fault
			} else {
				store.readErr = fault
			}
			_, _, _, err := w03D03Read(store, "TOKEN-000001")
			require.ErrorIs(t, err, fault)
			require.ErrorIs(t, w03D03Insert(store, "TOKEN-000001", w03D03Entry(1, 0)), fault)
			require.ErrorIs(t, w03D03Transition(store, "TOKEN-000001", 1, true), fault)
			require.Zero(t, store.saves)
		})
	}
	store := &w03D03FaultStore{AccountsAdapter: w03D03StorageFixture(t)}
	_, _, _, err := w03D03Read(store, "TOKEN-000003")
	require.ErrorIs(t, err, w03ErrD03Storage)
	require.Zero(t, store.loads)
	user, _, before, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.ErrorIs(t, w03D03Write(store, user, "TOKEN-000003", w03D03Aggregate{next: 1}), w03ErrD03Storage)
	require.Zero(t, store.saves)
	owner, err := NewRollbackContainment(store)
	require.NoError(t, err)
	fault := errors.New("after native SaveKeyValue")
	store.writeErr = fault
	require.ErrorIs(t, owner.Execute(w03D03Operation(func() error { return w03D03Insert(store, "TOKEN-000001", w03D03Entry(1, 0)) })), fault)
	require.Zero(t, store.saves)
	store.writeErr = nil
	_, _, after, err := w03D03Read(store, "TOKEN-000001")
	require.NoError(t, err)
	require.Equal(t, before, after)
	// Actual native absence is separate from injected returned-valid data.
	absent := qualContainmentStore(t)
	_, _, _, err = w03D03Read(absent, "TOKEN-000001")
	require.ErrorIs(t, err, state.ErrAccNotFound)
}
