package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
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
type registrationCandidate struct {
	writer          *RegistryRegistration
	view            *registryCandidate
	nativeCommitted bool
	committedRoot   []byte
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
		c.active != next.view || !next.view.ready || next.nativeCommitted || newOwner.recovered ||
		r.writer.maxEver != next.writer.maxEver || r.writer.state.accounts != next.writer.state.accounts ||
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

func (r *registrationCandidate) registerTokenForIntent(records *registrationRecords,
	id, digest, manager []byte, create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	return r.register(func(creator func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
		return r.writer.registerTokenForIntent(records, id, digest, manager, creator)
	}, create)
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
		return nil, ErrExecutionBusy
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
