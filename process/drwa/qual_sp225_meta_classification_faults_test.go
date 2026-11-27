package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-25 fault injection on the classifier owner and on the lifecycle
// additions: every refusal is an error, none is "ordinary". Inert fixtures.

type qualSP225FaultStore struct {
	*state.AccountsDB
	rootErr       error
	systemErr     error
	systemAllowed int
	dirty         bool
}

func (s *qualSP225FaultStore) RootHash() ([]byte, error) {
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	return s.AccountsDB.RootHash()
}

func (s *qualSP225FaultStore) JournalLen() int {
	if s.dirty {
		return 1
	}
	return s.AccountsDB.JournalLen()
}

func (s *qualSP225FaultStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if s.systemErr != nil && bytes.Equal(address, core.SystemAccountAddress) {
		if s.systemAllowed == 0 {
			return nil, s.systemErr
		}
		s.systemAllowed--
	}
	return s.AccountsDB.GetExistingAccount(address)
}

type qualSP225FaultMeta struct {
	store  *qualSP225FaultStore
	peer   *state.AccountsDB
	owner  *MetaClassification
	system *qualSystemSCDispatch
}

func qualSP225NewFaultMeta(t *testing.T, tamper func(state.UserAccountHandler)) *qualSP225FaultMeta {
	t.Helper()
	db := qualGenesisAccountsFromArgs(t, qualReaderArgs(false))
	qualSP225Provision(t, db)
	if tamper != nil {
		account, err := db.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		system := account.(state.UserAccountHandler)
		tamper(system)
		require.NoError(t, db.SaveAccount(system))
		_, err = db.Commit()
		require.NoError(t, err)
	}
	store, peer := &qualSP225FaultStore{AccountsDB: db}, qualGenesisAccounts(t, false)
	owner, err := NewMetaClassification(ArgsMetaClassification{Accounts: store, PeerAccounts: peer, Coordinator: qualRegistrationCoordinator()})
	require.NoError(t, err)
	system := qualSystemSCNative(t, store, owner.Classifier(), peer)
	require.NoError(t, owner.BindNative(system.runtime, qualClockSource(qualHeaderTimeOwner(t), store), &nativeValidation.NativeValidationSource{}))
	return &qualSP225FaultMeta{store: store, peer: peer, owner: owner, system: system}
}

func (f *qualSP225FaultMeta) commitStores(t *testing.T) {
	t.Helper()
	_, err := f.store.AccountsDB.Commit()
	require.NoError(t, err)
	_, err = f.peer.Commit()
	require.NoError(t, err)
}

func qualSP225Count(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

func TestQualSP225MetaReconstructionRefusesInconsistentRegistry(t *testing.T) {
	save := func(t *testing.T, system state.UserAccountHandler, key string, value []byte) {
		require.NoError(t, system.SaveKeyValue([]byte(key), value))
	}
	for name, tamper := range map[string]func(*testing.T, state.UserAccountHandler){
		"count_above_the_genesis_maximum": func(t *testing.T, s state.UserAccountHandler) {
			save(t, s, registryCountKey, qualSP225Count(math.MaxUint64))
		},
		"malformed_count":     func(t *testing.T, s state.UserAccountHandler) { save(t, s, registryCountKey, []byte{1, 2, 3}) },
		"count_without_entry": func(t *testing.T, s state.UserAccountHandler) { save(t, s, registryCountKey, qualSP225Count(1)) },
		"invalid_entry_identifier": func(t *testing.T, s state.UserAccountHandler) {
			save(t, s, registryCountKey, qualSP225Count(1))
			save(t, s, string(registryEntryKey(0)), []byte("not a token"))
		},
		"duplicate_entry": func(t *testing.T, s state.UserAccountHandler) {
			save(t, s, registryCountKey, qualSP225Count(2))
			for ordinal := uint64(0); ordinal < 2; ordinal++ {
				save(t, s, string(registryEntryKey(ordinal)), []byte("TOKEN-abcdef"))
			}
			save(t, s, registryMemberKeyPrefix+"TOKEN-abcdef", []byte{1})
		},
		"entry_without_member_marker": func(t *testing.T, s state.UserAccountHandler) {
			save(t, s, registryCountKey, qualSP225Count(1))
			save(t, s, string(registryEntryKey(0)), []byte("TOKEN-abcdef"))
		},
		"malformed_member_marker": func(t *testing.T, s state.UserAccountHandler) {
			save(t, s, registryCountKey, qualSP225Count(1))
			save(t, s, string(registryEntryKey(0)), []byte("TOKEN-abcdef"))
			save(t, s, registryMemberKeyPrefix+"TOKEN-abcdef", []byte{2})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := qualSP225NewFaultMeta(t, func(s state.UserAccountHandler) { tamper(t, s) })
			err := f.owner.BeginExecution()
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			_, classifyErr := f.owner.ClassifyToken([]byte("TOKEN-abcdef"))
			require.Error(t, classifyErr, "an inconsistent registry classifies nothing")
			require.Empty(t, f.owner.registry.members)
			require.False(t, f.owner.reconstructed)
		})
	}

	t.Run("system_account_read_fails_after_the_genesis_profile", func(t *testing.T) {
		f := qualSP225NewFaultMeta(t, nil)
		f.store.systemErr, f.store.systemAllowed = errors.New("inert system account read failure"), 1
		err := f.owner.BeginExecution()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, f.store.systemErr)
	})
}

func TestQualSP225MetaOwnerStoreFaults(t *testing.T) {
	t.Run("constructor_on_uncommitted_store", func(t *testing.T) {
		db := qualGenesisAccountsFromArgs(t, qualReaderArgs(false))
		_, _, err := qualRegistrationCreator(t, "TOKEN-abcdef")(db)
		require.NoError(t, err)
		owner, err := NewMetaClassification(ArgsMetaClassification{Accounts: db, PeerAccounts: qualGenesisAccounts(t, false), Coordinator: qualRegistrationCoordinator()})
		require.ErrorIs(t, err, ErrUncommittedState)
		require.Nil(t, owner)
	})
	t.Run("root_identity_of_an_empty_store", func(t *testing.T) {
		anchor := rootRegistryAnchor(nil)
		require.True(t, validRegistrationAnchor(&anchor))
	})
	t.Run("root_read_failure", func(t *testing.T) {
		f := qualSP225NewFaultMeta(t, nil)
		require.NoError(t, f.owner.BeginExecution())
		f.store.rootErr = errors.New("inert root read failure")
		for _, call := range []func() error{f.owner.BeginExecution, f.owner.Committed} {
			err := call()
			require.ErrorIs(t, err, vm.ErrDRWAExecution)
			require.ErrorIs(t, err, f.store.rootErr)
		}
		f.store.rootErr = nil
		require.NoError(t, f.owner.BeginExecution(), "the owner reconstructs once the store answers")
	})
	t.Run("commit_reads_fail_after_an_addition", func(t *testing.T) {
		f := qualSP225NewFaultMeta(t, nil)
		require.NoError(t, f.owner.BeginExecution())
		require.NoError(t, f.owner.current.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
		f.commitStores(t)
		f.store.systemErr = errors.New("inert system account read failure")
		err := f.owner.Committed()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, f.store.systemErr)
		f.store.systemErr = nil
		require.NoError(t, f.owner.BeginExecution())
		regulated, err := f.owner.ClassifyToken([]byte("TOKEN-abcdef"))
		require.NoError(t, err)
		require.True(t, regulated, "the committed member is found again by reconstruction")
	})
	t.Run("commit_finds_a_malformed_count", func(t *testing.T) {
		f := qualSP225NewFaultMeta(t, nil)
		require.NoError(t, f.owner.BeginExecution())
		require.NoError(t, f.owner.current.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
		account, err := f.store.AccountsDB.GetExistingAccount(core.SystemAccountAddress)
		require.NoError(t, err)
		require.NoError(t, account.(state.UserAccountHandler).SaveKeyValue([]byte(registryCountKey), []byte{1}))
		require.NoError(t, f.store.AccountsDB.SaveAccount(account))
		f.commitStores(t)
		err = f.owner.Committed()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, ErrInvalidRegistryRegistration)
	})
	t.Run("next_candidate_cannot_begin", func(t *testing.T) {
		f := qualSP225NewFaultMeta(t, nil)
		require.NoError(t, f.owner.BeginExecution())
		require.NoError(t, f.owner.current.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))
		f.commitStores(t)
		f.owner.maxEver = 0
		err := f.owner.Committed()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, errInvalidMetaContext)
		require.False(t, f.owner.reconstructed)
	})
	t.Run("system_vm_refuses_the_handoff", func(t *testing.T) {
		f := qualSP225NewFaultMeta(t, nil)
		require.NoError(t, f.owner.BeginExecution())
		installed := f.owner.current
		refusal := errors.New("inert handoff refusal")
		f.owner.host = qualSP225RefusingHost{refusal}
		f.commitStores(t)
		err := f.owner.Committed()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, refusal)
		require.Same(t, installed, f.owner.current, "the refused successor is not adopted")
		require.Nil(t, f.owner.registry.active, "the refused successor is closed")
	})
}

type qualSP225RefusingHost struct{ err error }

func (h qualSP225RefusingHost) ReplaceDRWAClassifier(vm.DRWATokenClassifier) error { return h.err }

func TestQualSP225RebaseRequiresAHealthyClosedPredecessor(t *testing.T) {
	anchor := rootRegistryAnchor([]byte("root"))
	members := map[string]struct{}{}
	f := qualSP225NewFaultMeta(t, nil)
	require.NoError(t, f.owner.BeginExecution())
	registry, open := f.owner.registry, f.owner.current

	require.ErrorIs(t, (*committedRegistry)(nil).rebase(open, &anchor, members), errInvalidMetaContext)
	require.ErrorIs(t, registry.rebase(nil, &anchor, members), errInvalidMetaContext)
	require.ErrorIs(t, registry.rebase(open, &metaRegistryAnchor{}, members), errInvalidMetaContext)
	require.ErrorIs(t, registry.rebase(open, &anchor, nil), errInvalidMetaContext)
	require.ErrorIs(t, registry.rebase(open, &anchor, members), errInvalidMetaContext, "an open candidate cannot be rebased")

	registry.mut.Lock()
	require.ErrorIs(t, registry.rebase(open, &anchor, members), ErrExecutionBusy)
	registry.mut.Unlock()

	require.NoError(t, open.closeNative())
	failure := errors.New("inert owner failure")
	open.writer.boundary.failure = failure
	require.ErrorIs(t, registry.rebase(open, &anchor, members), failure)
	open.writer.boundary.failure = nil
	require.NoError(t, registry.rebase(open, &anchor, members))
	require.True(t, open.rebased)
	require.Equal(t, anchor.root, registry.anchor.root)
}

func TestQualSP225CandidateNativeOperationsRefuseUnhealthyStates(t *testing.T) {
	newCandidate := func(t *testing.T) (*qualSP225FaultMeta, *registrationCandidate) {
		f := qualSP225NewFaultMeta(t, nil)
		require.NoError(t, f.owner.BeginExecution())
		return f, f.owner.current
	}
	roots := func(t *testing.T, f *qualSP225FaultMeta) [][]byte {
		r, err := f.owner.committedRoots()
		require.NoError(t, err)
		return r
	}
	anchorOf := func(t *testing.T, f *qualSP225FaultMeta) *metaRegistryAnchor {
		anchor := rootRegistryAnchor(roots(t, f)[0])
		return &anchor
	}
	failure := errors.New("inert owner failure")

	t.Run("busy_registry", func(t *testing.T) {
		f, c := newCandidate(t)
		c.view.parent.mut.Lock()
		defer c.view.parent.mut.Unlock()
		_, err := c.nativeReusable(roots(t, f))
		require.ErrorIs(t, err, ErrExecutionBusy)
		require.ErrorIs(t, c.closeNative(), ErrExecutionBusy)
		_, err = c.commitNative(anchorOf(t, f))
		require.ErrorIs(t, err, ErrExecutionBusy)
		_, err = c.classifyOwn([]byte("TOKEN-abcdef"))
		require.ErrorIs(t, err, ErrExecutionBusy)
	})
	t.Run("failed_owner", func(t *testing.T) {
		f, c := newCandidate(t)
		c.writer.boundary.failure = failure
		_, err := c.nativeReusable(roots(t, f))
		require.ErrorIs(t, err, failure)
		require.ErrorIs(t, c.closeNative(), failure)
		_, err = c.commitNative(anchorOf(t, f))
		require.ErrorIs(t, err, failure)
	})
	t.Run("running_owner", func(t *testing.T) {
		f, c := newCandidate(t)
		c.writer.boundary.running = true
		_, err := c.nativeReusable(roots(t, f))
		require.ErrorIs(t, err, ErrExecutionBusy)
		require.ErrorIs(t, c.closeNative(), ErrExecutionBusy)
		_, err = c.commitNative(anchorOf(t, f))
		require.ErrorIs(t, err, ErrExecutionBusy)
	})
	t.Run("recovered_owner_cannot_close_healthy", func(t *testing.T) {
		_, c := newCandidate(t)
		c.writer.boundary.recovered = true
		require.ErrorIs(t, c.closeNative(), errInvalidMetaContext)
	})
	t.Run("uncommitted_store", func(t *testing.T) {
		f, c := newCandidate(t)
		anchor := anchorOf(t, f)
		f.store.dirty = true
		require.ErrorIs(t, c.closeNative(), ErrUncommittedState)
		_, err := c.commitNative(anchor)
		require.ErrorIs(t, err, ErrUncommittedState)
	})
	t.Run("commit_requirements", func(t *testing.T) {
		f, c := newCandidate(t)
		_, err := c.commitNative(&metaRegistryAnchor{})
		require.ErrorIs(t, err, errInvalidMetaContext, "an incomplete anchor")
		other := rootRegistryAnchor([]byte("another root"))
		_, err = c.commitNative(&other)
		require.ErrorIs(t, err, errInvalidMetaContext, "the anchor must name the committed store root")
		good := anchorOf(t, f)
		f.store.rootErr = failure
		_, err = c.commitNative(good)
		require.ErrorIs(t, err, failure)
		f.store.rootErr = nil
		added, err := c.commitNative(good)
		require.NoError(t, err)
		require.Zero(t, added)
		_, err = c.commitNative(good)
		require.ErrorIs(t, err, errInvalidMetaContext, "a committed candidate is closed")
		reusable, err := c.nativeReusable(roots(t, f))
		require.NoError(t, err)
		require.False(t, reusable)
		require.NoError(t, c.closeNative(), "closing a closed healthy candidate changes nothing")
	})
	t.Run("reuse_requires_the_same_roots", func(t *testing.T) {
		f, c := newCandidate(t)
		current := roots(t, f)
		reusable, err := c.nativeReusable(current)
		require.NoError(t, err)
		require.True(t, reusable)
		reusable, err = c.nativeReusable(current[:1])
		require.NoError(t, err)
		require.False(t, reusable)
		reusable, err = c.nativeReusable([][]byte{current[0], []byte("another peer root")})
		require.NoError(t, err)
		require.False(t, reusable)
	})
}

func TestQualSP225ReadOnlyClassifierFailsClosed(t *testing.T) {
	f := qualSP225NewFaultMeta(t, nil)
	readOnly := f.owner.ReadOnlyClassifier(f.store, f.peer)
	_, err := (*readOnlyClassifier)(nil).ClassifyToken([]byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, errInvalidMetaContext)
	called := false
	_, err = readOnly.WithTokenClassification(f.store, []byte("TOKEN-abcdef"), func(bool) (*vmcommon.VMOutput, error) { called = true; return nil, nil })
	require.True(t, vm.IsDirectDRWAClassificationUnavailable(err))
	require.ErrorIs(t, err, ErrClassificationUnresolved)
	require.False(t, called, "nothing executes on an unresolved classification")
}
