package drwa

import (
	"bytes"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	nativeTx "github.com/multiversx/mx-chain-core-go/data/transaction"
	vmData "github.com/multiversx/mx-chain-core-go/data/vm"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/process"
	nativeValidation "github.com/multiversx/mx-chain-go/process/transaction"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/vm"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// registrationCandidate couples the existing metachain registration writer and
// block-local view (Part A L4863-4888) to the SAME native containment owner. It
// adds no persistence domain or journal. Native executor/factory admission,
// scheduler dependencies and before-first-effect dispatch remain separate work.
// Every participating store must be exclusively owned throughout this handle's life.
// Native constructor dependencies, never transaction-selected providers.
// Their presence is not programme/G6/certificate admission.
type registrationNativeExecution struct {
	source   nativeValidation.NativeValidationSource
	headers  HeaderTimeSource
	physical vmcommon.VMExecutionHandler
}

type registrationCandidate struct {
	native          *registrationNativeExecution
	writer          *RegistryRegistration
	view            *registryCandidate
	nativeCommitted bool
	committedRoot   []byte
	// rebased is set only by committedRegistry.rebase, after the native block
	// owner reconstructed the projection at another committed root. The next
	// candidate then continues the reconstructed anchor, not this one's.
	rebased bool
}

// reconstructRegistrationCandidate is only for startup/state-sync/integrity
// reconstruction, never per-block full-set rebuilding. projection is the private
// authenticated transport result, with its sole-producer completeness invariant;
// the executing native store must be at that exact committed root. Stable input
// ownership is required until this call returns, as for registry transport.
func reconstructRegistrationCandidate(accounts state.AccountsAdapter, coordinator sharding.Coordinator,
	maxEver uint64, projection *registryProjection, participating ...state.AccountsAdapter) (*registrationCandidate, error) {
	if projection == nil || projection.members == nil || uint64(len(projection.members)) > maxEver {
		return nil, errInvalidRegistryTransport
	}
	a := &projection.anchor
	if len(a.candidateHash) == 0 || len(a.metaHash) == 0 || len(a.executedHash) == 0 || len(a.root) == 0 {
		return nil, errInvalidMetaContext
	}
	writer, owner, err := NewRegistryRegistration(accounts, coordinator, maxEver, participating...)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(owner.roots[0], a.root) {
		return nil, errInvalidMetaContext
	}
	parent := &committedRegistry{anchor: copyRegistryAnchor(a), members: make(map[string]struct{}, len(projection.members))}
	for id := range projection.members {
		parent.members[id] = struct{}{}
	}
	return attachRegistrationCandidate(writer, owner, parent, a), nil
}

func attachRegistrationCandidate(writer *RegistryRegistration, owner *RollbackContainment,
	parent *committedRegistry, selected *metaRegistryAnchor) *registrationCandidate {
	view := &registryCandidate{parent: parent, before: copyRegistryAnchor(&parent.anchor), after: copyRegistryAnchor(selected),
		added: make(map[string]struct{}), ready: true,
		material: &registryMaterialization{state: writer.state, owner: owner, required: copyRegistryAnchor(selected)}}
	parent.active = view
	return &registrationCandidate{writer: writer, view: view}
}

func (r *registrationCandidate) RegisterToken(create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	return r.register(r.writer.RegisterToken, create)
}

// BindIntent reuses the complete T19 identity/profile/record owner. Its native
// creator contract is unchanged, but its operation now passes through the same
// candidate publication boundary as RegisterToken. This is not authenticated
// ingress; BindIntent's existing current-authority obligations still apply.
func (r *registrationCandidate) BindIntent(id, digest, manager []byte,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, maxBytes int) (*RegistrationIntentOwner, error) {
	if r == nil || r.writer == nil || r.view == nil {
		return nil, errInvalidRegistrationRecord
	}
	owner, err := r.writer.BindIntent(id, digest, manager, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	owner.registration = r
	return owner, nil
}

func (r *registrationCandidate) IsInterfaceNil() bool { return r == nil }

// ValidateAccounts binds both native System-SC account dependencies to the
// existing containment store identities, without reading a trie or adding a
// store after its boundary was captured. Equal roots on another adapter do not
// establish journal ownership. Aliased user/validator handles need one owned
// store; distinct handles must both participate. Canonical roots, hook aliases,
// lifetime admission and exclusive native ownership remain the caller's duty.
func (r *registrationCandidate) ValidateAccounts(user, validator state.AccountsAdapter) error {
	if r == nil || r.writer == nil || r.writer.boundary == nil || user != r.writer.state.accounts {
		return errInvalidMetaContext
	}
	for _, store := range r.writer.boundary.stores {
		if store == validator {
			return r.DRWAExecutionError()
		}
	}
	return errInvalidMetaContext
}

// DRWAExecutionError observes the existing owner's failure without classifying
// a token or admitting execution. Healthy contained native work can itself
// query status; its running state is not a failure. Exclusive native ownership,
// canonical recovery and publication admission remain the outer owner's duty.
func (r *registrationCandidate) DRWAExecutionError() error {
	if r == nil || r.writer == nil || r.writer.boundary == nil {
		return errInvalidMetaContext
	}
	owner := r.writer.boundary
	owner.mut.Lock()
	defer owner.mut.Unlock()
	if err := owner.checkAvailable(); err != ErrExecutionBusy {
		return err
	}
	return nil
}

// DRWAExecutionHealthError distinguishes a healthy closed owner from permission
// to execute. Actual work still uses DRWAExecutionError. Recovery never revives
// an old VM, including when that VM did not observe the original failure.
func (r *registrationCandidate) DRWAExecutionHealthError() error {
	if r == nil || r.writer == nil || r.writer.boundary == nil {
		return errInvalidMetaContext
	}
	owner := r.writer.boundary
	owner.mut.Lock()
	defer owner.mut.Unlock()
	if owner.failure != nil {
		return owner.failure
	}
	if owner.recovered {
		return ErrExecutionClosed
	}
	return nil
}

// WithDRWAClassifierReplacement holds the existing projection owner through
// the VM's assignment. It authenticates private lineage/disposition, not the
// canonical context: the native finalizer still owes that admission before use.
// No registry scan, trie access, state publication or output release occurs.
func (r *registrationCandidate) WithDRWAClassifierReplacement(classifier vm.DRWATokenClassifier, replace func()) error {
	next, valid := classifier.(*registrationCandidate)
	if r == nil || r.view == nil || r.writer == nil || r.writer.boundary == nil ||
		!valid || next == nil || next == r || next.view == nil || next.writer == nil ||
		next.writer.boundary == nil || next.view.parent != r.view.parent || replace == nil {
		return errInvalidMetaContext
	}
	c := r.view.parent
	if !c.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer c.mut.Unlock()
	oldOwner, newOwner := r.writer.boundary, next.writer.boundary
	if oldOwner == newOwner {
		return errInvalidMetaContext
	}
	oldOwner.mut.Lock()
	defer oldOwner.mut.Unlock()
	newOwner.mut.Lock()
	defer newOwner.mut.Unlock()
	if oldOwner.failure != nil {
		return oldOwner.failure
	}
	if oldOwner.recovered || !oldOwner.closed || oldOwner.running || r.view.ready || r.view.added != nil ||
		c.active != next.view || !next.view.ready || next.nativeCommitted || newOwner.recovered || next.rebased ||
		(!r.rebased && r.writer.maxEver != next.writer.maxEver) || r.writer.state.accounts != next.writer.state.accounts ||
		len(oldOwner.stores) != len(newOwner.stores) {
		return errInvalidMetaContext
	}
	if err := newOwner.checkAvailable(); err != nil {
		return err
	}
	for i, store := range oldOwner.stores {
		if store != newOwner.stores[i] {
			return errInvalidMetaContext
		}
	}
	if r.rebased {
		// The owner replaced the projection under this registry's lock; only
		// the reconstructed anchor can be continued.
		if !sameRegistryAnchor(&c.anchor, &next.view.before) {
			return errInvalidMetaContext
		}
		replace()
		return nil
	}
	previous := &r.view.before
	if r.nativeCommitted {
		previous = &r.view.after
		if !bytes.Equal(r.committedRoot, previous.root) {
			return errInvalidMetaContext
		}
	}
	if !sameRegistryAnchor(previous, &c.anchor) || !sameRegistryAnchor(previous, &next.view.before) {
		return errInvalidMetaContext
	}
	replace()
	return nil
}

// The three operations below serve the native block owner (MetaClassification),
// which alone persists, resets and moves the participating stores. They never
// touch a store: they only check it and close this handle.

// nativeReusable reports whether this open candidate can serve another block
// execution unchanged: healthy, ready, without tentative additions, and with
// every participating store still at its captured committed root.
func (r *registrationCandidate) nativeReusable(roots [][]byte) (bool, error) {
	c := r.view.parent
	if !c.mut.TryRLock() {
		return false, ErrExecutionBusy
	}
	defer c.mut.RUnlock()
	owner := r.writer.boundary
	owner.mut.Lock()
	defer owner.mut.Unlock()
	if owner.failure != nil {
		return false, owner.failure
	}
	if owner.running {
		return false, ErrExecutionBusy
	}
	if owner.closed || owner.recovered || c.active != r.view || !r.view.ready || r.nativeCommitted ||
		len(r.view.added) != 0 || len(roots) != len(owner.roots) {
		return false, nil
	}
	for i := range roots {
		if !bytes.Equal(roots[i], owner.roots[i]) {
			return false, nil
		}
	}
	return true, nil
}

// closeNative closes a healthy candidate whose block the native owner reset,
// abandoned or moved away from. Its tentative additions are discarded. Every
// participating store must be committed (empty journal). A failed or recovered
// owner cannot take this path.
func (r *registrationCandidate) closeNative() error {
	c := r.view.parent
	if !c.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer c.mut.Unlock()
	owner := r.writer.boundary
	owner.mut.Lock()
	defer owner.mut.Unlock()
	if owner.failure != nil {
		return owner.failure
	}
	if owner.running {
		return ErrExecutionBusy
	}
	if owner.recovered {
		return errInvalidMetaContext
	}
	for _, store := range owner.stores {
		if store.JournalLen() != 0 {
			return ErrUncommittedState
		}
	}
	owner.closed, owner.outputs = true, nil
	if c.active == r.view {
		c.active = nil
	}
	r.view.ready, r.view.added = false, nil
	return nil
}

// commitNative follows the native owner's successful commit of EVERY
// participating store. It advances the committed projection by exactly this
// candidate's additions and closes the handle; it persists nothing. admitted
// names the committed user-store root the next candidate continues from.
func (r *registrationCandidate) commitNative(admitted *metaRegistryAnchor) (int, error) {
	c := r.view.parent
	if !c.mut.TryLock() {
		return 0, ErrExecutionBusy
	}
	defer c.mut.Unlock()
	owner := r.writer.boundary
	owner.mut.Lock()
	defer owner.mut.Unlock()
	if owner.failure != nil {
		return 0, owner.failure
	}
	if owner.running {
		return 0, ErrExecutionBusy
	}
	if owner.closed || c.active != r.view || !r.view.ready || r.nativeCommitted || !validRegistrationAnchor(admitted) {
		return 0, errInvalidMetaContext
	}
	for _, store := range owner.stores {
		if store.JournalLen() != 0 {
			return 0, ErrUncommittedState
		}
	}
	root, err := owner.stores[0].RootHash()
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(root, admitted.root) {
		return 0, errInvalidMetaContext
	}
	added := len(r.view.added)
	for id := range r.view.added {
		c.members[id] = struct{}{}
	}
	owner.closed, owner.outputs = true, nil
	r.nativeCommitted, r.committedRoot = true, bytes.Clone(root)
	c.anchor = copyRegistryAnchor(admitted)
	r.view.after = copyRegistryAnchor(admitted)
	c.active, r.view.ready, r.view.added = nil, false, nil
	return added, nil
}

// classifyOwn answers from this candidate's own selected identity. It is the
// same memory-only read as WithTokenClassification, for the native built-in
// dispatch of the store this candidate is bound to.
func (r *registrationCandidate) classifyOwn(tokenID []byte) (bool, error) {
	if !r.view.parent.mut.TryRLock() {
		return false, ErrExecutionBusy
	}
	defer r.view.parent.mut.RUnlock()
	return r.view.classifyLocked(r.view.after.candidateHash, tokenID)
}

func (r *registrationCandidate) registerTokenForIntent(records *registrationRecords,
	id, digest, manager []byte, create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error), guards ...registrationGuard) error {
	return r.register(func(creator func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
		return r.writer.registerTokenForIntent(records, id, digest, manager, creator, guards...)
	}, create)
}

func (r *registrationCandidate) registerTokenForIntentOwned(operation *rollbackOperation, records *registrationRecords,
	id, digest, manager []byte, create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error), guard registrationGuard) (*vmcommon.VMOutput, error) {
	var output *vmcommon.VMOutput
	err := operation.withWrite(r.writer.boundary, r.writer.state.accounts, func() error {
		if operation.registrationCandidate != r || operation.registrationID != "" {
			return errInvalidMetaContext
		}
		var added string
		write, err := r.writer.prepareRegistrationForIntent(records, id, digest, manager,
			func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				token, out, err := create(accounts)
				added = string(token)
				return bytes.Clone(token), out, err
			}, guard)
		if err != nil {
			return err
		}
		output, err = write()
		if err == nil {
			operation.registrationID = added
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return output, nil
}

// Keep the candidate lock across the original snapshot, its final verdict and
// the tentative view update. Commit and canonical projection stay separate.
func (r *registrationCandidate) executeRegistrationOwned(execute func(*rollbackOperation) ([]*vmcommon.VMOutput, error)) error {
	if !r.view.parent.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	if !r.activeNativeView() {
		return errInvalidMetaContext
	}
	var completed *rollbackOperation
	err := r.writer.boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		operation.registrationCandidate = r
		completed = operation
		return execute(operation)
	})
	if err == nil && completed.registrationID != "" {
		r.view.added[completed.registrationID] = struct{}{}
	}
	return err
}

func (r *registrationCandidate) activeNativeView() bool {
	return r.view.parent.active == r.view && r.view.ready && !r.nativeCommitted &&
		r.view.material != nil && r.view.material.owner == r.writer.boundary
}

// register holds the existing view lock over the COMPLETE selected native
// operation. In the intent path, record consumption can fail after creation;
// no memory delta is published until records, token, membership and count all
// succeed inside the unchanged T19 journal. There is no nested Execute here.
func (r *registrationCandidate) register(
	operation func(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error,
	create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	if create == nil {
		return ErrInvalidOperation
	}
	if !r.view.parent.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	var added []byte
	err := operation(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		id, out, err := create(accounts)
		// The writer and view each own their identifier bytes. A creator's
		// retained slice must not change either identity after return.
		added = bytes.Clone(id)
		return bytes.Clone(added), out, err
	})
	if err != nil {
		return err
	}
	// No fallible action follows publication. The existing view mutex hides
	// the interval between the native journal write and this memory delta.
	r.view.added[string(added)] = struct{}{}
	return nil
}

func (r *registrationCandidate) classify(candidateHash, tokenID []byte) (bool, error) {
	// A native creator can reenter classification; never deadlock on its own
	// registration lock or expose a partially written registration as absence.
	if !r.view.parent.mut.TryRLock() {
		return false, ErrExecutionBusy
	}
	defer r.view.parent.mut.RUnlock()
	return r.view.classifyLocked(candidateHash, tokenID)
}

// WithTokenClassification carries the existing view's read dependency through
// actual native System-SC execution. It exposes no membership setter or account
// handle. Admission of this private candidate remains the native owner's duty;
// capturing its selected identity does not establish canonical authority.
func (r *registrationCandidate) WithTokenClassification(accounts state.AccountsAdapter, tokenID []byte,
	execute func(bool) (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if r == nil || r.writer == nil || r.view == nil || accounts != r.writer.state.accounts || execute == nil {
		return nil, errInvalidMetaContext
	}
	if !r.view.parent.mut.TryRLock() {
		return nil, vm.NewDRWAClassificationUnavailable(ErrExecutionBusy)
	}
	defer r.view.parent.mut.RUnlock()
	regulated, err := r.view.classifyLocked(r.view.after.candidateHash, tokenID)
	if err != nil {
		return nil, err
	}
	return execute(regulated)
}

// commit releases only the existing containment owner's native receipt. The
// old handle closes; this does not manufacture the next authoritative anchor or
// publish the execution-shard projection with an obsolete metachain root.
// The finalizer must subsequently supply independently admitted native context
// to commitProjection. Local persistence does not establish that authority.
func (r *registrationCandidate) commit() ([][]byte, []*vmcommon.VMOutput, error) {
	if !r.view.parent.mut.TryLock() {
		return nil, nil, ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	roots, outputs, err := r.writer.boundary.Commit()
	if err != nil {
		return nil, nil, err
	}
	// The user/registry store is first; other native roots remain in the receipt.
	r.nativeCommitted = true
	r.committedRoot = bytes.Clone(roots[0])
	return roots, outputs, nil
}

// commitProjection applies only this candidate's successful additions, after
// native persistence AND the finalizer's independently admitted anchor. This
// field comparison is not canonical context admission. No metadata/version is
// invented at commit, no full registry copy is made, and no output is released
// a second time. Native finalizer/factory installation is still outstanding.
func (r *registrationCandidate) commitProjection(admitted *metaRegistryAnchor) (*committedRegistry, error) {
	c := r.view.parent
	if !c.mut.TryLock() {
		return nil, ErrExecutionBusy
	}
	defer c.mut.Unlock()
	if c.active != r.view || !r.nativeCommitted || !validRegistrationAnchor(admitted) ||
		!bytes.Equal(admitted.root, r.committedRoot) {
		return nil, errInvalidMetaContext
	}
	for id := range r.view.added {
		c.members[id] = struct{}{}
	}
	c.anchor = copyRegistryAnchor(admitted)
	r.view.after = copyRegistryAnchor(admitted)
	c.active, r.view.ready, r.view.added = nil, false, nil
	return c, nil
}

func validRegistrationAnchor(a *metaRegistryAnchor) bool {
	return a != nil && len(a.candidateHash) != 0 && len(a.metaHash) != 0 && len(a.executedHash) != 0 && len(a.root) != 0
}

// beginRegistration reuses this committed projection without enumerating its
// members. The native owner must establish the selected candidate's authority
// and ancestry independently. A later tip may retain the same LastExecutionResult;
// its exact execution identity/root must still match the committed projection.
func (c *committedRegistry) beginRegistration(accounts state.AccountsAdapter, coordinator sharding.Coordinator,
	maxEver uint64, before, selected *metaRegistryAnchor, participating ...state.AccountsAdapter) (*registrationCandidate, error) {
	if c == nil {
		return nil, errInvalidMetaContext
	}
	if !c.mut.TryLock() {
		return nil, ErrExecutionBusy
	}
	defer c.mut.Unlock()
	if c.active != nil || c.members == nil || uint64(len(c.members)) > maxEver ||
		!validRegistrationAnchor(before) || !validRegistrationAnchor(selected) || !sameRegistryAnchor(&c.anchor, before) ||
		!bytes.Equal(selected.root, c.anchor.root) || !bytes.Equal(selected.executedHash, c.anchor.executedHash) ||
		selected.nonce != c.anchor.nonce || selected.round != c.anchor.round || selected.epoch != c.anchor.epoch {
		return nil, errInvalidMetaContext
	}
	writer, owner, err := NewRegistryRegistration(accounts, coordinator, maxEver, participating...)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(owner.roots[0], c.anchor.root) {
		return nil, errInvalidMetaContext
	}
	return attachRegistrationCandidate(writer, owner, c, selected), nil
}

// discard detaches an aborted/recovered candidate only after native containment
// is closed with every participating store at its original root. A successful
// commit cannot take this path.
// The committed map/anchor never acquired this candidate's tentative additions.
func (r *registrationCandidate) discard() (*committedRegistry, error) {
	c := r.view.parent
	if !c.mut.TryLock() {
		return nil, ErrExecutionBusy
	}
	defer c.mut.Unlock()
	if c.active != r.view || r.nativeCommitted {
		return nil, errInvalidMetaContext
	}
	r.writer.boundary.mut.Lock()
	failed, closed := r.writer.boundary.failure, r.writer.boundary.closed
	r.writer.boundary.mut.Unlock()
	if failed != nil {
		return nil, failed
	}
	if !closed {
		return nil, ErrUncommittedState
	}
	for i, store := range r.writer.boundary.stores {
		if store.JournalLen() != 0 {
			return nil, ErrUncommittedState
		}
		root, err := store.RootHash()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(root, r.writer.boundary.roots[i]) {
			return nil, errInvalidMetaContext
		}
	}
	c.active, r.view.ready, r.view.added = nil, false, nil
	return c, nil
}

func (r *registrationCandidate) abort() error {
	if !r.view.parent.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	return r.view.material.abort()
}

func (r *registrationCandidate) recover() error {
	if !r.view.parent.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	return r.writer.boundary.Recover()
}

// WithDRWAAccountProtection retains the existing candidate read dependency
// through native deletion. It supplies no canonical/genesis authority and
// never creates a nested Execute or owns another journal.
func (r *registrationCandidate) WithDRWAAccountProtection(accounts state.AccountsAdapter, execute func() error) error {
	if r == nil || r.writer == nil || r.view == nil || r.view.parent == nil || accounts != r.writer.state.accounts || execute == nil {
		return errInvalidMetaContext
	}
	v := r.view
	c := v.parent
	if !c.mut.TryRLock() {
		return ErrExecutionBusy
	}
	defer c.mut.RUnlock()
	if c.active != v || v.material == nil || v.material.owner != r.writer.boundary || v.material.state.accounts != accounts {
		return errInvalidMetaContext
	}
	v.material.owner.mut.Lock()
	err := v.checkReadDependencyLocked(v.after.candidateHash)
	v.material.owner.mut.Unlock()
	if err != nil {
		return err
	}
	return execute()
}

// registrationNativeLease authenticates native ORIGINAL-transaction input and
// lifetime only. It is not a programme appointment, G6 locator, certificate or
// funding provider. Prepared call bytes come only from native SC preparation.
type registrationNativeLease struct {
	mut           sync.Mutex
	candidate     *registrationCandidate
	binding       *registrationNativeExecution
	operation     *rollbackOperation
	context       *HeaderTimeContext
	original      *nativeTx.Transaction
	frozen        *nativeTx.Transaction
	encoded, hash []byte
	source        nativeValidation.NativeValidationSource
	prepared      *vmcommon.ContractCallInput
	active        atomic.Bool
	verified      bool
}

func (l *registrationNativeLease) IsInterfaceNil() bool { return l == nil }

// WithDRWANativeCall uses the SAME candidate, native header capability and
// original journal. It never commits, recomputes native gas or releases a VM
// output independently of the enclosing native SC operation.
func (r *registrationCandidate) WithDRWANativeCall(tx data.TransactionHandler, validation any, accounts state.AccountsAdapter,
	physical vmcommon.VMExecutionHandler, execute func(vm.DRWANativeCallLease) (vmcommon.ReturnCode, error)) (vmcommon.ReturnCode, error) {
	if r == nil || r.writer == nil || r.writer.state == nil || r.writer.boundary == nil || r.view == nil || r.view.parent == nil || r.native == nil || execute == nil {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	binding := r.native
	original, ok := tx.(*nativeTx.Transaction)
	if !ok || original == nil || accounts != r.writer.state.accounts || check.IfNil(physical) || physical != binding.physical || check.IfNil(binding.headers) || binding.headers.GetAccountsAdapter() != accounts || check.IfNil(binding.source.ProtoMarshalizer) || check.IfNil(binding.source.Hasher) || check.IfNil(binding.source.ArgsParser) || check.IfNil(binding.source.EnableEpochsHandler) {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	if nativeValidation.RequiresDRWANativeValidationReceipt(original) {
		return r.rejectUnadmittedNativeRegistration()
	}
	receipt, proven := validation.(*nativeValidation.NativeValidationReceipt)
	if !proven || receipt == nil {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	// No relay/SCR/callback positive is inferred from a selected sender address.
	if len(receipt.InnerBytes()) != 0 || common.IsRelayedTxV3(original) || len(original.RelayerAddr) != 0 {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	source := binding.source
	source.EnableSignedTxWithHash = source.EnableEpochsHandler.IsFlagEnabled(common.TransactionSignedWithTxHashFlag)
	encoded, err := source.ProtoMarshalizer.Marshal(original)
	if err != nil {
		return vmcommon.ExecutionFailed, fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	hash := source.Hasher.Compute(string(encoded))
	if err = nativeValidation.VerifyNativeValidationReceipt(source, receipt, original, hash); err != nil {
		return vmcommon.ExecutionFailed, err
	}
	frozen := &nativeTx.Transaction{}
	if err = source.ProtoMarshalizer.Unmarshal(frozen, encoded); err != nil {
		return vmcommon.ExecutionFailed, fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	context, err := binding.headers.EvaluatedHeaderTimeContext()
	if err != nil {
		return vmcommon.ExecutionFailed, fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	function, _, _ := bytes.Cut(frozen.Data, []byte{'@'})
	run := r.writer.boundary.executeOwned
	if string(function) == "DRWARegisterToken" {
		run = r.executeRegistrationOwned
	} else {
		if !r.view.parent.mut.TryRLock() {
			return vmcommon.ExecutionFailed, ErrExecutionBusy
		}
		defer r.view.parent.mut.RUnlock()
		if !r.activeNativeView() {
			return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
		}
	}
	code := vmcommon.ExecutionFailed
	err = run(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
		_, inner := withHeaderTime(binding.headers, context, func() (*vmcommon.VMOutput, error) {
			lease := &registrationNativeLease{candidate: r, binding: binding, operation: operation, context: context, original: original, frozen: frozen, encoded: bytes.Clone(encoded), hash: bytes.Clone(hash), source: source}
			lease.active.Store(true)
			defer lease.active.Store(false)
			var failure error
			code, failure = execute(lease)
			return nil, failure
		})
		if inner == nil && code != vmcommon.Ok && operation.registrationCandidate == r {
			inner = operation.withWrite(r.writer.boundary, accounts, func() error {
				if operation.registrationID != "" {
					return vm.ErrDRWAExecution
				}
				return nil
			})
		}
		return nil, inner
	})
	if err != nil {
		return vmcommon.ExecutionFailed, fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	return code, nil
}

// rejectUnadmittedNativeRegistration checks the actual installed owner before
// denying the reserved registration requests. It opens no journal or lease.
func (r *registrationCandidate) rejectUnadmittedNativeRegistration() (vmcommon.ReturnCode, error) {
	if !r.view.parent.mut.TryRLock() {
		return vmcommon.ExecutionFailed, fmt.Errorf("%w: %w", vm.ErrDRWAExecution, ErrExecutionBusy)
	}
	defer r.view.parent.mut.RUnlock()
	if !r.activeNativeView() {
		return vmcommon.ExecutionFailed, vm.ErrDRWAExecution
	}
	if err := r.DRWAExecutionError(); err != nil {
		return vmcommon.ExecutionFailed, fmt.Errorf("%w: %w", vm.ErrDRWAExecution, err)
	}
	return vmcommon.UserError, process.ErrTransactionNotExecutable
}

// Called under the lease mutex. withWrite reuses the private original-operation
// liveness/ownership/sticky-failure checks; this callback performs no state write.
func (l *registrationNativeLease) check(execute func() error) error {
	if l == nil || !l.active.Load() || l.candidate == nil || l.binding == nil || l.operation == nil {
		return vm.ErrDRWAExecution
	}
	r := l.candidate
	return l.operation.withWrite(r.writer.boundary, r.writer.state.accounts, func() error {
		if !l.active.Load() || r.native != l.binding || r.view.parent.active != r.view || !r.view.ready {
			return vm.ErrDRWAExecution
		}
		current, err := l.binding.headers.EvaluatedHeaderTimeContext()
		if err != nil {
			return err
		}
		if current != l.context {
			return ErrInactiveHeaderTime
		}
		if _, err = l.context.Milliseconds(); err != nil {
			return err
		}
		if l.source.EnableEpochsHandler.IsFlagEnabled(common.TransactionSignedWithTxHashFlag) != l.source.EnableSignedTxWithHash {
			return vm.ErrDRWAExecution
		}
		raw, err := l.source.ProtoMarshalizer.Marshal(l.original)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, l.encoded) {
			return vm.ErrDRWAExecution
		}
		return execute()
	})
}

func (l *registrationNativeLease) VerifyTransaction(tx data.TransactionHandler, accounts state.AccountsAdapter, sender, destination state.UserAccountHandler) error {
	if l == nil {
		return vm.ErrDRWAExecution
	}
	l.mut.Lock()
	defer l.mut.Unlock()
	return l.check(func() error {
		if l.verified || tx != l.original || accounts != l.candidate.writer.state.accounts || check.IfNil(destination) || !bytes.Equal(destination.AddressBytes(), l.frozen.RcvAddr) {
			return vm.ErrDRWAExecution
		}
		local := l.source.Coordinator.ComputeId(l.frozen.SndAddr) == l.source.Coordinator.SelfId()
		if local {
			if check.IfNil(sender) || !bytes.Equal(sender.AddressBytes(), l.frozen.SndAddr) {
				return vm.ErrDRWAExecution
			}
		} else if !check.IfNil(sender) {
			return vm.ErrDRWAExecution
		}
		// Address equality is a locus check only: the sealed native crypto receipt
		// already authenticated the ORIGINAL EOA, with the factory-owned providers.
		l.verified = true
		return nil
	})
}

func (l *registrationNativeLease) BindCall(input *vmcommon.ContractCallInput) error {
	if l == nil {
		return vm.ErrDRWAExecution
	}
	l.mut.Lock()
	defer l.mut.Unlock()
	return l.check(func() error {
		if !l.verified || l.prepared != nil || input == nil || input.CallValue == nil || input.CallType != vmData.DirectCall || len(input.RelayerAddr) != 0 || len(input.ESDTTransfers) != 0 || input.GasLocked != 0 || input.ReturnCallAfterError || input.AllowInitFunction {
			return vm.ErrDRWAExecution
		}
		tx := l.frozen
		if !bytes.Equal(input.CallerAddr, tx.SndAddr) || (len(input.OriginalCallerAddr) != 0 && !bytes.Equal(input.OriginalCallerAddr, tx.SndAddr)) || !bytes.Equal(input.RecipientAddr, tx.RcvAddr) || input.CallValue.Cmp(tx.Value) != 0 || input.GasPrice != tx.GasPrice || !bytes.Equal(input.TxGuardian, tx.GuardianAddr) || !bytes.Equal(input.CurrentTxHash, l.hash) || !bytes.Equal(input.OriginalTxHash, l.hash) || !bytes.Equal(input.PrevTxHash, l.hash) {
			return vm.ErrDRWAExecution
		}
		if a := input.AsyncArguments; a != nil && (len(a.CallID) != 0 || len(a.CallerCallID) != 0 || len(a.CallbackAsyncInitiatorCallID) != 0 || a.GasAccumulated != 0) {
			return vm.ErrDRWAExecution
		}
		function, arguments, err := l.source.ArgsParser.ParseCallData(string(tx.Data))
		if err != nil {
			return err
		}
		if function != input.Function || len(arguments) != len(input.Arguments) {
			return vm.ErrDRWAExecution
		}
		for i := range arguments {
			if !bytes.Equal(arguments[i], input.Arguments[i]) {
				return vm.ErrDRWAExecution
			}
		}
		// Missing G6/current-lineage/certificate producers remain hard first-use
		// gates. Native origin and prepared bytes alone cannot enable DRWA ingress.
		switch input.Function {
		case "DRWARegisterToken", "DRWARegisterBootstrapIntent":
			return vm.ErrDRWAExecution
		}
		// Ownership of this independent copy transferred from physical SystemVM's
		// prepared-call binding. VerifyCall never accepts its own expected bytes.
		l.prepared = input
		return nil
	})
}

func (l *registrationNativeLease) VerifyCall(input *vmcommon.ContractCallInput) error {
	if l == nil {
		return vm.ErrDRWAExecution
	}
	l.mut.Lock()
	defer l.mut.Unlock()
	return l.check(func() error {
		if !l.verified || l.prepared == nil || !reflect.DeepEqual(l.prepared, input) {
			return vm.ErrDRWAExecution
		}
		return nil
	})
}
