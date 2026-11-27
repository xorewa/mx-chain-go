package drwa

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-go/common/holders"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-25, Part A 5.1 rules 1-5, F.5 D17, AN-03 (same-block registration,
// restart). The production owner drives the real registry, the real candidate
// and the real System VM over real account stores. Registration itself enters
// through the candidate's in-package operation, because the public ingress is
// a separate row's first-use gate. Inert local fixtures only.

const qualSP225Denied = "DRWA public operation denied"

type qualSP225Meta struct {
	args       ArgsResultAccountReader
	user, peer *state.AccountsDB
	owner      *MetaClassification
	system     *qualSystemSCDispatch
}

func qualSP225Provision(t *testing.T, db *state.AccountsDB) []byte {
	t.Helper()
	s, err := newProtectedState(db)
	require.NoError(t, err)
	boundary, err := NewRollbackContainment(db)
	require.NoError(t, err)
	minimum := qualDRWADevelopmentMinimumGenesis(t)
	require.NoError(t, boundary.Execute(func() (*vmcommon.VMOutput, error) { return nil, s.provisionMinimumGenesis(minimum) }))
	roots, _, err := boundary.Commit()
	require.NoError(t, err)
	return roots[0]
}

// qualSP225Install builds the owner and the System VM the way the processing
// factory does: owner first, its candidate into the VM, then the native binding.
func qualSP225Install(t *testing.T, args ArgsResultAccountReader, user, peer *state.AccountsDB) *qualSP225Meta {
	t.Helper()
	owner, err := NewMetaClassification(ArgsMetaClassification{Accounts: user, PeerAccounts: peer, Coordinator: qualRegistrationCoordinator()})
	require.NoError(t, err)
	system := qualSystemSCNative(t, user, owner.Classifier(), peer)
	require.NoError(t, owner.BindNative(system.runtime, qualClockSource(qualHeaderTimeOwner(t), user), &nativeValidation.NativeValidationSource{}))
	return &qualSP225Meta{args: args, user: user, peer: peer, owner: owner, system: system}
}

func qualSP225NewMeta(t *testing.T, provision bool) *qualSP225Meta {
	t.Helper()
	args := qualReaderArgs(false)
	user, peer := qualGenesisAccountsFromArgs(t, args), qualGenesisAccounts(t, false)
	if provision {
		qualSP225Provision(t, user)
	}
	return qualSP225Install(t, args, user, peer)
}

func (f *qualSP225Meta) pause(t *testing.T, token string) (*vmcommon.VMOutput, error) {
	t.Helper()
	f.system.context.CleanCache()
	input := qualSystemSCInput("pause", token)
	input.Arguments = input.Arguments[:1]
	return f.system.runtime.RunSmartContractCall(input)
}

func (f *qualSP225Meta) requireDenied(t *testing.T, token string, denied bool) {
	t.Helper()
	output, err := f.pause(t, token)
	require.NoError(t, err)
	if denied {
		require.Equal(t, qualSP225Denied, output.ReturnMessage)
		require.Equal(t, vmcommon.UserError, output.ReturnCode)
	} else {
		require.NotEqual(t, qualSP225Denied, output.ReturnMessage)
	}
	regulated, err := f.owner.ClassifyToken([]byte(token))
	require.NoError(t, err)
	require.Equal(t, denied, regulated)
}

func (f *qualSP225Meta) register(t *testing.T, token string) {
	t.Helper()
	require.NoError(t, f.owner.current.RegisterToken(qualRegistrationCreator(t, token)))
}

func (f *qualSP225Meta) commit(t *testing.T) []byte {
	t.Helper()
	root, err := f.user.Commit()
	require.NoError(t, err)
	_, err = f.peer.Commit()
	require.NoError(t, err)
	require.NoError(t, f.owner.Committed())
	return root
}

func (f *qualSP225Meta) status() error {
	return f.system.runtime.(interface{ DRWAExecutionError() error }).DRWAExecutionError()
}

func TestQualSP225MetaUnreconstructedIsNeverOrdinary(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	_, err := f.owner.ClassifyToken([]byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, errInvalidMetaContext)
	readOnly := f.owner.ReadOnlyClassifier(f.user, f.peer)
	_, err = readOnly.ClassifyToken([]byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, ErrClassificationUnresolved)
	require.NoError(t, f.status(), "an unreconstructed candidate is not a failure")

	output, err := f.pause(t, "TOKEN-abcdef")
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.Nil(t, output)
}

func TestQualSP225MetaBeginExecutionRequirements(t *testing.T) {
	t.Run("unprovisioned_store", func(t *testing.T) {
		f := qualSP225NewMeta(t, false)
		err := f.owner.BeginExecution()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		_, err = f.owner.ClassifyToken([]byte("TOKEN-abcdef"))
		require.Error(t, err, "no projection, no ordinary answer")
		require.ErrorIs(t, f.owner.BeginExecution(), vm.ErrDRWAExecution, "the refusal repeats")
	})
	t.Run("uncommitted_store", func(t *testing.T) {
		f := qualSP225NewMeta(t, true)
		require.NoError(t, f.owner.BeginExecution())
		_, _, err := qualRegistrationCreator(t, "TOKEN-abcdef")(f.user)
		require.NoError(t, err)
		require.NotZero(t, f.user.JournalLen())
		err = f.owner.BeginExecution()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, ErrUncommittedState)
	})
	t.Run("unbound_owner", func(t *testing.T) {
		args := qualReaderArgs(false)
		user, peer := qualGenesisAccountsFromArgs(t, args), qualGenesisAccounts(t, false)
		qualSP225Provision(t, user)
		owner, err := NewMetaClassification(ArgsMetaClassification{Accounts: user, PeerAccounts: peer, Coordinator: qualRegistrationCoordinator()})
		require.NoError(t, err)
		require.ErrorIs(t, owner.BeginExecution(), vm.ErrDRWAExecution)
		require.NoError(t, owner.Committed(), "nothing ran under a projection")
	})
	t.Run("constructor_and_binding", func(t *testing.T) {
		args := qualReaderArgs(false)
		user, peer := qualGenesisAccountsFromArgs(t, args), qualGenesisAccounts(t, false)
		_, err := NewMetaClassification(ArgsMetaClassification{PeerAccounts: peer, Coordinator: qualRegistrationCoordinator()})
		require.ErrorIs(t, err, state.ErrNilAccountsAdapter)
		_, err = NewMetaClassification(ArgsMetaClassification{Accounts: user, PeerAccounts: peer})
		require.ErrorIs(t, err, ErrInvalidRegistryRegistration)
		f := qualSP225Install(t, args, user, peer)
		headers := qualClockSource(qualHeaderTimeOwner(t), user)
		require.ErrorIs(t, f.owner.BindNative(f.system.runtime, headers, &nativeValidation.NativeValidationSource{}), vm.ErrDRWAExecution, "bound once")
		other, err := NewMetaClassification(ArgsMetaClassification{Accounts: user, PeerAccounts: peer, Coordinator: qualRegistrationCoordinator()})
		require.NoError(t, err)
		require.ErrorIs(t, other.BindNative(f.system.runtime, headers, nil), vm.ErrDRWAExecution)
		require.ErrorIs(t, other.BindNative(f.system.runtime, qualClockSource(qualHeaderTimeOwner(t), peer), &nativeValidation.NativeValidationSource{}), vm.ErrDRWAExecution)
		require.ErrorIs(t, other.BindNative(nil, headers, &nativeValidation.NativeValidationSource{}), vm.ErrDRWAExecution)
		require.ErrorIs(t, other.ReadOnlyClassifier(nil, peer).ValidateAccounts(nil, peer), errInvalidMetaContext, "a nil adapter validates nothing")
		require.False(t, other.IsInterfaceNil())
	})
}

// Same-block registration then effect, commit, and the next block.
func TestQualSP225MetaSameBlockRegistrationCommitAndNextBlock(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	snapshot := f.owner.ReadOnlyClassifier(f.user, f.peer)

	require.NoError(t, f.owner.BeginExecution())
	first := f.owner.current
	f.requireDenied(t, "TOKEN-abcdef", false)
	require.NoError(t, f.owner.BeginExecution(), "an unchanged candidate is reused")
	require.Same(t, first, f.owner.current)

	f.register(t, "TOKEN-abcdef")
	f.requireDenied(t, "TOKEN-abcdef", true)
	f.requireDenied(t, "OTHER-abcdef", false)
	regulated, err := snapshot.ClassifyToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.False(t, regulated, "an uncommitted registration is not published to read-only views")

	root := f.commit(t)
	require.NotSame(t, first, f.owner.current, "an open successor is installed at commit")
	require.Equal(t, root, f.owner.registry.anchor.root)
	require.NoError(t, f.status())
	f.requireDenied(t, "TOKEN-abcdef", true)
	regulated, err = snapshot.ClassifyToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.True(t, regulated)

	second := f.owner.current
	require.NoError(t, f.owner.BeginExecution())
	require.Same(t, second, f.owner.current)
	f.requireDenied(t, "TOKEN-abcdef", true)
	f.requireDenied(t, "OTHER-abcdef", false)

	// A block that changes only the peer store still advances the candidate.
	f.commit(t)
	require.NoError(t, f.owner.BeginExecution())
	f.requireDenied(t, "TOKEN-abcdef", true)
}

// A block that is not committed: its registration is not visible afterwards.
func TestQualSP225MetaAbortedBlockDiscardsItsRegistration(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	require.NoError(t, f.owner.BeginExecution())
	aborted := f.owner.current
	f.register(t, "TOKEN-abcdef")
	f.requireDenied(t, "TOKEN-abcdef", true)

	// The native block owner resets both stores (RevertCurrentBlock).
	require.NoError(t, f.user.RevertToSnapshot(0))
	require.NoError(t, f.peer.RevertToSnapshot(0))
	require.NoError(t, f.owner.BeginExecution())
	require.NotSame(t, aborted, f.owner.current)
	require.NoError(t, f.status())
	f.requireDenied(t, "TOKEN-abcdef", false)
	_, err := aborted.classifyOwn([]byte("TOKEN-abcdef"))
	require.ErrorIs(t, err, errInvalidMetaContext, "the abandoned candidate answers nothing")

	f.register(t, "TOKEN-abcdee")
	f.commit(t)
	f.requireDenied(t, "TOKEN-abcdee", true)
	f.requireDenied(t, "TOKEN-abcdef", false)
}

// Restart and state sync: a new node reconstructs from the committed store;
// moving the store to another committed root rebuilds the projection there.
func TestQualSP225MetaRestartAndMovedStateReconstruct(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	require.NoError(t, f.owner.BeginExecution())
	empty, err := f.user.RootHash()
	require.NoError(t, err)
	f.register(t, "TOKEN-abcdef")
	one := f.commit(t)
	require.NoError(t, f.owner.BeginExecution())
	f.register(t, "TOKEN-abcdee")
	two := f.commit(t)
	require.NotEqual(t, one, two)

	t.Run("restart", func(t *testing.T) {
		reopened := qualGenesisAccountsFromArgs(t, f.args)
		require.NoError(t, reopened.RecreateTrie(holders.NewDefaultRootHashesHolder(two)))
		restarted := qualSP225Install(t, f.args, reopened, qualGenesisAccounts(t, false))
		_, err := restarted.owner.ClassifyToken([]byte("TOKEN-abcdef"))
		require.Error(t, err, "nothing is ordinary before reconstruction")
		require.NoError(t, restarted.owner.BeginExecution())
		restarted.requireDenied(t, "TOKEN-abcdef", true)
		restarted.requireDenied(t, "TOKEN-abcdee", true)
		restarted.requireDenied(t, "OTHER-abcdef", false)
		require.Len(t, restarted.owner.registry.members, 2)
	})

	t.Run("moved", func(t *testing.T) {
		for _, step := range []struct {
			root     []byte
			expected int
		}{{one, 1}, {empty, 0}, {two, 2}} {
			previous := f.owner.current
			require.NoError(t, f.user.RecreateTrie(holders.NewDefaultRootHashesHolder(step.root)))
			require.NoError(t, f.owner.BeginExecution())
			require.NotSame(t, previous, f.owner.current)
			require.True(t, previous.rebased)
			require.Len(t, f.owner.registry.members, step.expected)
			require.Equal(t, step.root, f.owner.registry.anchor.root)
			require.NoError(t, f.status())
			f.requireDenied(t, "TOKEN-abcdef", step.expected >= 1)
			f.requireDenied(t, "TOKEN-abcdee", step.expected >= 2)
		}
	})
}

// A registration whose native write an outer snapshot reverted must not become
// a permanent member: the commit-time count check forces reconstruction.
func TestQualSP225MetaCommitDeltaMustEqualCommittedRegistry(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	require.NoError(t, f.owner.BeginExecution())
	outer := f.user.JournalLen()
	f.register(t, "TOKEN-abcdef")
	require.NoError(t, f.user.RevertToSnapshot(outer))
	_, err := f.user.Commit()
	require.NoError(t, err)
	_, err = f.peer.Commit()
	require.NoError(t, err)

	err = f.owner.Committed()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.ErrorIs(t, err, ErrInvalidRegistryRegistration)
	require.NoError(t, f.owner.BeginExecution(), "reconstruction from the committed store")
	require.Empty(t, f.owner.registry.members)
	f.requireDenied(t, "TOKEN-abcdef", false)
}

// A failed rollback inside a registration poisons the candidate; the owner
// never replaces or revives it.
func TestQualSP225MetaFailedCandidateIsNotReplaced(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	require.NoError(t, f.owner.BeginExecution())
	original, rollback := errors.New("inert creator failure"), errors.New("inert rollback failure")
	failed := f.owner.current
	failed.writer.boundary.mut.Lock()
	failed.writer.boundary.stores = []state.AccountsAdapter{&qualNativeStore{AccountsAdapter: f.user, revertErr: rollback}, f.peer}
	failed.writer.boundary.mut.Unlock()
	err := failed.RegisterToken(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { return nil, nil, original })
	require.ErrorIs(t, err, original)
	require.ErrorIs(t, err, rollback)

	for _, begin := range []func() error{f.owner.BeginExecution, f.owner.Committed} {
		err = begin()
		require.ErrorIs(t, err, vm.ErrDRWAExecution)
		require.ErrorIs(t, err, rollback)
	}
	require.Same(t, failed, f.owner.current)
	require.ErrorIs(t, f.status(), vm.ErrDRWAExecution, "the System VM reports the retained failure")
}

// The read-only classifier in a second VM (API query, transaction simulator).
func TestQualSP225ReadOnlyClassifierInSecondVM(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	require.NoError(t, f.owner.BeginExecution())
	f.register(t, "TOKEN-abcdef")
	root := f.commit(t)

	apiUser := qualGenesisAccountsFromArgs(t, f.args)
	require.NoError(t, apiUser.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	apiPeer := qualGenesisAccounts(t, false)
	var readOnly vm.DRWATokenClassifier = f.owner.ReadOnlyClassifier(apiUser, apiPeer)
	require.ErrorIs(t, readOnly.ValidateAccounts(f.user, apiPeer), errInvalidMetaContext)
	require.ErrorIs(t, readOnly.ValidateAccounts(apiUser, f.peer), errInvalidMetaContext)
	_, err := readOnly.WithTokenClassification(f.user, []byte("TOKEN-abcdef"), func(bool) (*vmcommon.VMOutput, error) { return nil, nil })
	require.ErrorIs(t, err, errInvalidMetaContext)
	_, isSource := readOnly.(vm.DRWANativeCallSource)
	require.False(t, isSource, "no native-call capability")
	_, canReplace := readOnly.(interface {
		WithDRWAClassifierReplacement(vm.DRWATokenClassifier, func()) error
	})
	require.False(t, canReplace, "no handoff capability")
	protection := readOnly.(vm.DRWAAccountProtectionSource)
	ran := false
	require.NoError(t, protection.WithDRWAAccountProtection(apiUser, func() error { ran = true; return nil }))
	require.True(t, ran)
	require.ErrorIs(t, protection.WithDRWAAccountProtection(f.user, func() error { return nil }), errInvalidMetaContext)

	api := qualSystemSCNative(t, apiUser, readOnly, apiPeer)
	for token, denied := range map[string]bool{"TOKEN-abcdef": true, "OTHER-abcdef": false} {
		api.context.CleanCache()
		input := qualSystemSCInput("pause", token)
		input.Arguments = input.Arguments[:1]
		output, runErr := api.runtime.RunSmartContractCall(input)
		require.NoError(t, runErr)
		require.Equal(t, denied, output.ReturnMessage == qualSP225Denied)
	}
	require.Zero(t, apiUser.JournalLen(), "the simulated denial wrote nothing")
	after, err := apiUser.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.NoError(t, f.status(), "the processing VM is unaffected")
}

// Tracker carry (SP2-81B3b audit 3, O3): the handoff takes a blocking status
// lock, so no status reader may hold an owner or registry lock across it.
// Status is read concurrently with many handoffs; run with the race detector.
func TestQualSP225HandoffDoesNotDeadlockWithStatusReads(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	require.NoError(t, f.owner.BeginExecution())
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if err := f.status(); err != nil {
						t.Errorf("status: %v", err)
						return
					}
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		previous := f.owner.current
		f.commit(t)
		require.NotSame(t, previous, f.owner.current)
		require.NoError(t, f.owner.BeginExecution())
	}
	close(stop)
	readers.Wait()
	require.False(t, bytes.Equal(f.owner.registry.anchor.root, nil))
}

// Composition with the store's rollback status (SP2-21): while a failed revert
// leaves the store uncommitted the owner refuses to begin; after the block
// owner restored the committed root, the next execution starts from the
// committed projection and the aborted block's registration is gone.
func TestQualSP225MetaComposesWithStoreRollbackStatus(t *testing.T) {
	f := qualSP225NewMeta(t, true)
	require.NoError(t, f.owner.BeginExecution())
	f.register(t, "TOKEN-abcdef")
	require.Same(t, state.ErrSnapshotValueOutOfBounds, f.user.RevertToSnapshot(f.user.JournalLen()+1))
	require.ErrorIs(t, f.user.RollbackFailure(), state.ErrRollbackFailed)

	err := f.owner.BeginExecution()
	require.ErrorIs(t, err, vm.ErrDRWAExecution)
	require.ErrorIs(t, err, ErrUncommittedState, "a partially reverted store is not a committed root")
	_, commitErr := f.user.Commit()
	require.ErrorIs(t, commitErr, state.ErrRollbackFailed)

	// restoreBlockAccounts: every store back to its committed root.
	require.NoError(t, f.user.RevertToSnapshot(0))
	require.NoError(t, f.peer.RevertToSnapshot(0))
	require.NoError(t, f.user.RollbackFailure())
	require.NoError(t, f.owner.BeginExecution())
	require.NoError(t, f.status())
	f.requireDenied(t, "TOKEN-abcdef", false)
	require.Empty(t, f.owner.registry.members)
}

type qualSP225ContractReadFault struct {
	*state.AccountsDB
	fault  error
	faults int
}

func (s *qualSP225ContractReadFault) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if s.fault != nil && bytes.Equal(address, core.ESDTSCAddress) {
		s.faults++
		return nil, s.fault
	}
	return s.AccountsDB.GetExistingAccount(address)
}

// Tracker duty R02.H-contract-read (owner Decision 1, 3 November): when the
// account read of the called system address fails, the native context resolves
// the contract from the input address and still dispatches. Classification is
// inside that dispatch, by token identifier, so the retained failure cannot
// turn a regulated token's public mutation into a native effect.
func TestQualSP225ContractReadFailureDoesNotBypassClassification(t *testing.T) {
	args := qualReaderArgs(false)
	store := &qualSP225ContractReadFault{AccountsDB: qualGenesisAccountsFromArgs(t, args)}
	qualSP225Provision(t, store.AccountsDB)
	peer := qualGenesisAccounts(t, false)
	owner, err := NewMetaClassification(ArgsMetaClassification{Accounts: store, PeerAccounts: peer, Coordinator: qualRegistrationCoordinator()})
	require.NoError(t, err)
	system := qualSystemSCNative(t, store, owner.Classifier(), peer)
	require.NoError(t, owner.BindNative(system.runtime, qualClockSource(qualHeaderTimeOwner(t), store), &nativeValidation.NativeValidationSource{}))
	require.NoError(t, owner.BeginExecution())
	require.NoError(t, owner.current.RegisterToken(qualRegistrationCreator(t, "TOKEN-abcdef")))

	store.fault = errors.New("inert contract account read failure")
	for token, denied := range map[string]bool{"TOKEN-abcdef": true, "OTHER-abcdef": false} {
		system.context.CleanCache()
		before := store.JournalLen()
		input := qualSystemSCInput("pause", token)
		input.Arguments = input.Arguments[:1]
		output, runErr := system.runtime.RunSmartContractCall(input)
		require.NoError(t, runErr)
		require.Equal(t, denied, output.ReturnMessage == qualSP225Denied, token)
		if denied {
			require.Equal(t, vmcommon.UserError, output.ReturnCode)
			require.Equal(t, before, store.JournalLen(), "no native effect")
		}
	}
	require.Positive(t, store.faults, "the failing read was on the path")
}
