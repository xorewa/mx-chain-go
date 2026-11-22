// Package drwa owns DRWA-specific execution constructions. It is not installed
// in an upstream processor or dispatcher. Ordinary operations do not import it.
package drwa

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// These errors describe DRWA-owned execution lifecycle states, not upstream
// return codes. They never replace an operation error after successful rollback.
var (
	ErrExecutionClosed          = errors.New("DRWA execution is closed")
	ErrExecutionBusy            = errors.New("DRWA execution is in progress")
	ErrInvalidOperation         = errors.New("nil DRWA operation")
	ErrUncommittedState         = errors.New("DRWA execution requires committed account stores")
	ErrExecutionInterrupted     = errors.New("DRWA execution was interrupted")
	errNativePersistenceOwned   = errors.New("DRWA persistence belongs to the native block owner")
	errNativePersistenceReceipt = errors.New("invalid DRWA native persistence receipt")
)

// RollbackContainment owns one isolated DRWA candidate's native journals and
// pending VM outputs (Part A P-05 L4958-4967; Part B L352). Its caller must have
// exclusive ownership of the stores and include every participating store,
// nested mutation and account save in Execute's operation. It does not classify
// tokens or police aliases of an AccountsAdapter outside this owner.
//
// Production wiring must abort the outer proposal when this owner fails and
// must not publish outputs independently or commit its stores directly. No such
// wiring exists yet. Commit releases outputs only after all native commits
// succeed; it does not prove canonical multi-store commit or disk recovery.
// Admission also requires the original main/data-trie roots to remain available
// throughout candidate persistence and recovery. Native pruning/root retention
// must establish this before wiring; this component does not pin trie nodes.
type RollbackContainment struct {
	mut     sync.Mutex
	stores  []state.AccountsAdapter
	roots   [][]byte
	outputs []*vmcommon.VMOutput
	failure error
	running bool
	closed  bool
	// Recovery closes this owner but cannot qualify its VM for healthy handoff.
	recovered bool
	// Native attachment reuses this journal/output containment without giving it
	// a second store finalizer. Only the actual native owner may acknowledge its
	// own commit or reset; these private checks do not establish canonicality.
	nativeOwned     bool
	nativeCommitted bool
	nativeReset     bool
	nativeRoots     [][]byte
}

// NewRollbackContainment starts at native committed roots. These must be the
// authoritative candidate boundary selected by the eventual production owner.
func NewRollbackContainment(stores ...state.AccountsAdapter) (*RollbackContainment, error) {
	if len(stores) == 0 {
		return nil, state.ErrNilAccountsAdapter
	}
	c := &RollbackContainment{stores: append([]state.AccountsAdapter(nil), stores...)}
	for _, store := range c.stores {
		if check.IfNil(store) {
			return nil, state.ErrNilAccountsAdapter
		}
		if store.JournalLen() != 0 {
			return nil, ErrUncommittedState
		}
		root, err := store.RootHash()
		if err != nil {
			return nil, err
		}
		c.roots = append(c.roots, bytes.Clone(root))
	}
	return c, nil
}

func (c *RollbackContainment) checkAvailable() error {
	if c.failure != nil {
		return c.failure
	}
	if c.closed {
		return ErrExecutionClosed
	}
	if c.running {
		return ErrExecutionBusy
	}
	if c.nativeRoots != nil {
		return ErrExecutionBusy
	}
	return nil
}

// Execute surrounds the whole native operation, including nested dispatch and
// saves. The output's ownership transfers here on success; the caller must not
// publish or mutate it afterwards. Concurrent/reentrant entry is refused rather
// than mixing candidate journals. Nested native work belongs inside operation.
func (c *RollbackContainment) Execute(operation func() (*vmcommon.VMOutput, error)) (err error) {
	if operation == nil {
		return c.execute(nil)
	}
	return c.execute(func() ([]*vmcommon.VMOutput, error) {
		output, err := operation()
		return []*vmcommon.VMOutput{output}, err
	})
}

// rollbackOperation borrows this owner's EXISTING native execution. It is a
// private journal lifetime, not creating-owner authentication, a header source
// or another journal. Only executeOwned issues it, inside execute's callback.
type rollbackOperation struct {
	mut     sync.Mutex
	owner   *RollbackContainment
	active  bool
	failure error
	misused atomic.Bool
	// Accessed only within withWrite. One original operation supplies one
	// final position map, even when its native effect has repeated legs.
	positionJoinUsed bool
	// A candidate binds its own exclusive view before admitting borrowed
	// registration. The identifier is written under withWrite and read by
	// the candidate only after this operation has expired.
	registrationCandidate *registrationCandidate
	registrationID        string
}

// executeOwned preserves execute's sole snapshot/error/output/commit owner.
// Consumers may perform their closed native write sets without nesting Execute.
func (c *RollbackContainment) executeOwned(operation func(*rollbackOperation) ([]*vmcommon.VMOutput, error)) error {
	if c == nil {
		return ErrExecutionClosed
	}
	if operation == nil {
		return c.execute(nil)
	}
	return c.execute(func() ([]*vmcommon.VMOutput, error) {
		current := &rollbackOperation{owner: c, active: true}
		defer current.expire()
		outputs, err := operation(current)
		return outputs, current.result(err)
	})
}

func (o *rollbackOperation) expire() {
	o.mut.Lock()
	o.active = false
	o.mut.Unlock()
}

func (o *rollbackOperation) result(original error) error {
	o.mut.Lock()
	defer o.mut.Unlock()
	o.active = false
	if o.misused.Load() {
		o.failure = errors.Join(o.failure, ErrExecutionBusy)
	}
	if o.failure == nil {
		return original
	}
	if original == nil {
		return o.failure
	}
	if errors.Is(original, o.failure) {
		return original
	}
	// A swallowed writer/header error must still reach the ORIGINAL rollback
	// owner. Only that owner determines whether rollback failure poisons commit.
	return errors.Join(original, o.failure)
}

func (o *rollbackOperation) withWrite(owner *RollbackContainment, accounts state.AccountsAdapter, write func() error) error {
	if o == nil || owner == nil || o.owner != owner {
		return errInvalidMetaContext
	}
	if !o.mut.TryLock() {
		o.misused.Store(true)
		return ErrExecutionBusy
	}
	defer o.mut.Unlock()
	if !o.active {
		return ErrExecutionClosed
	}
	if o.failure != nil {
		return o.failure
	}
	if o.misused.Load() {
		o.failure = ErrExecutionBusy
		return o.failure
	}
	owner.mut.Lock()
	err := owner.failure
	if err == nil && (!owner.running || owner.closed) {
		err = ErrExecutionClosed
	}
	member := false
	if !check.IfNil(accounts) {
		for _, store := range owner.stores {
			if store == accounts {
				member = true
				break
			}
		}
	}
	owner.mut.Unlock()
	if err == nil && !member {
		err = errInvalidMetaContext
	}
	if err == nil && write == nil {
		err = ErrInvalidOperation
	}
	if err == nil {
		err = write()
	}
	if err != nil {
		o.failure = err
	}
	return err
}

// execute retains every native observation of one bounded import without
// merging VM outputs or exposing a successful prefix before the whole import.
func (c *RollbackContainment) execute(operation func() ([]*vmcommon.VMOutput, error)) (err error) {
	c.mut.Lock()
	if err = c.checkAvailable(); err != nil {
		c.mut.Unlock()
		return err
	}
	if operation == nil {
		c.mut.Unlock()
		return ErrInvalidOperation
	}
	snapshots := make([]int, len(c.stores))
	for i, store := range c.stores {
		snapshots[i] = store.JournalLen()
	}
	c.running = true
	c.mut.Unlock()
	completed := false
	defer func() {
		if !completed {
			c.mut.Lock()
			c.failure = ErrExecutionInterrupted
			c.outputs = nil
			c.running = false
			c.mut.Unlock()
		}
	}()
	outputs, original := operation()
	c.mut.Lock()
	defer c.mut.Unlock()
	c.running = false
	if original == nil {
		c.outputs = append(c.outputs, outputs...)
		completed = true
		return nil
	}
	var rollbackErrors []error
	for i := len(c.stores) - 1; i >= 0; i-- {
		if rollback := c.stores[i].RevertToSnapshot(snapshots[i]); rollback != nil {
			rollbackErrors = append(rollbackErrors, rollback)
		}
	}
	if len(rollbackErrors) == 0 {
		completed = true
		return original
	}
	c.failure = errors.Join(append([]error{original}, rollbackErrors...)...)
	c.outputs = nil
	completed = true
	return c.failure
}

// Commit refuses a failed candidate before any store commit or output release.
// A native commit failure also closes off continuation: native Commit can clear
// its journal before failing (accountsDB.go:939-987 at 06c383cf).
// Native stores persist sequentially, so an earlier store may already persist
// when a later one fails. No roots/outputs are released; Recover must reconstruct
// EVERY store, including already persisted stores, at the retained boundary.
func (c *RollbackContainment) Commit() ([][]byte, []*vmcommon.VMOutput, error) {
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.nativeOwned {
		return nil, nil, errNativePersistenceOwned
	}
	if err := c.checkAvailable(); err != nil {
		return nil, nil, err
	}
	completed := false
	defer func() {
		if !completed {
			// A native persistence panic may follow durable writes and journal
			// clearing. Suppress observations and require root-based recovery;
			// retrying this owner would repeat an ambiguous persistence step.
			c.failure = ErrExecutionInterrupted
			c.outputs = nil
		}
	}()
	roots := make([][]byte, 0, len(c.stores))
	for _, store := range c.stores {
		root, err := store.Commit()
		if err != nil {
			c.failure = err
			c.outputs = nil
			completed = true
			return nil, nil, err
		}
		roots = append(roots, bytes.Clone(root))
	}
	c.closed = true
	outputs := c.outputs
	c.outputs = nil
	completed = true
	return roots, outputs, nil
}

// Recover reconstructs ALL participating stores at the original committed
// boundary, even for equal roots or empty journals. Any reconstruction failure
// retains containment. It cannot authenticate the external proposal, restore
// non-account state, or establish canonical/disk recovery; the eventual outer
// owner must reconstruct those too before issuing a fresh candidate.
func (c *RollbackContainment) Recover() error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.nativeOwned {
		return errNativePersistenceOwned
	}
	return c.recover()
}

// Abort discards an uncommitted consuming candidate, including a successful
// bounded promotion and every dependent operation in this owner (Part A 6.1).
// It reuses recovery at the retained native roots and closes the old context.
// It cannot retract outputs already released by Commit; native committed-block
// replacement remains the block processor's responsibility. A failed Abort
// retains containment and permits only Recover from the retained roots.
func (c *RollbackContainment) Abort() error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if c.nativeOwned {
		return errNativePersistenceOwned
	}
	if err := c.checkAvailable(); err != nil {
		return err
	}
	c.failure = ErrExecutionInterrupted
	c.outputs = nil
	return c.recover()
}

// recover runs with the owner's mutex held. Both failure recovery and healthy
// candidate replacement require exactly the same native root reconstruction.
func (c *RollbackContainment) recover() error {
	if c.running {
		return ErrExecutionBusy
	}
	if c.failure == nil {
		return ErrExecutionClosed
	}
	var recoveryErrors []error
	for i, store := range c.stores {
		if err := store.RecreateTrie(holders.NewDefaultRootHashesHolder(bytes.Clone(c.roots[i]))); err != nil {
			recoveryErrors = append(recoveryErrors, err)
		}
	}
	if len(recoveryErrors) != 0 {
		c.failure = errors.Join(append([]error{c.failure}, recoveryErrors...)...)
		return c.failure
	}
	// The recovered owner remains closed; no old execution context is revived.
	c.outputs = nil
	c.failure = nil
	c.closed = true
	c.recovered = true
	return nil
}

// newNativeRollbackContainment is attached at the actual native B boundary,
// before promotion or dependent work. It captures no extra store or writer.
func newNativeRollbackContainment(stores ...state.AccountsAdapter) (*RollbackContainment, error) {
	c, err := NewRollbackContainment(stores...)
	if err != nil {
		return nil, err
	}
	c.nativeOwned = true
	return c, nil
}

func (c *RollbackContainment) nativeOwns(accounts state.AccountsAdapter) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if !c.nativeOwned {
		return errNativePersistenceReceipt
	}
	if err := c.checkAvailable(); err != nil {
		return err
	}
	for _, store := range c.stores {
		if store == accounts {
			return nil
		}
	}
	return errNativePersistenceReceipt
}

func (c *RollbackContainment) nativeFailureLocked(err error) error {
	if err == nil {
		err = errNativePersistenceReceipt
	}
	if c.failure == nil {
		c.failure = err
	} else {
		c.failure = errors.Join(c.failure, err)
	}
	c.outputs = nil
	return c.failure
}

func (c *RollbackContainment) nativeBeforeCommit() error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if !c.nativeOwned {
		return errNativePersistenceReceipt
	}
	if err := c.checkAvailable(); err != nil {
		return err
	}
	roots := make([][]byte, len(c.stores))
	for i, store := range c.stores {
		root, err := store.RootHash()
		if err != nil {
			return c.nativeFailureLocked(err)
		}
		roots[i] = bytes.Clone(root)
	}
	c.nativeRoots = roots
	return nil
}

func (c *RollbackContainment) nativeCheckRootsLocked(roots [][]byte) error {
	if len(roots) != len(c.stores) {
		return errNativePersistenceReceipt
	}
	for i, store := range c.stores {
		if store.JournalLen() != 0 {
			return ErrUncommittedState
		}
		root, err := store.RootHash()
		if err != nil {
			return err
		}
		if !bytes.Equal(root, roots[i]) {
			return errNativePersistenceReceipt
		}
	}
	return nil
}

// nativeCommitReceipt must be called only after the actual native commit of
// EVERY participating store succeeds. It performs no persistence. The route
// still holds these observations until its projection/output handoff succeeds.
func (c *RollbackContainment) nativeCommitReceipt() ([][]byte, []*vmcommon.VMOutput, error) {
	c.mut.Lock()
	defer c.mut.Unlock()
	if !c.nativeOwned {
		return nil, nil, errNativePersistenceReceipt
	}
	if c.failure != nil {
		return nil, nil, c.failure
	}
	if c.closed {
		return nil, nil, ErrExecutionClosed
	}
	if c.running {
		return nil, nil, ErrExecutionBusy
	}
	if c.nativeRoots == nil {
		return nil, nil, c.nativeFailureLocked(errNativePersistenceReceipt)
	}
	if err := c.nativeCheckRootsLocked(c.nativeRoots); err != nil {
		return nil, nil, c.nativeFailureLocked(err)
	}
	c.closed, c.nativeCommitted = true, true
	roots := make([][]byte, len(c.nativeRoots))
	for i, root := range c.nativeRoots {
		roots[i] = bytes.Clone(root)
	}
	outputs := c.outputs
	c.outputs = nil
	return roots, outputs, nil
}

func (c *RollbackContainment) nativeCommitFailed(err error) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if !c.nativeOwned {
		return errNativePersistenceReceipt
	}
	if c.closed {
		return ErrExecutionClosed
	}
	if c.running {
		return ErrExecutionBusy
	}
	return c.nativeFailureLocked(err)
}

func (c *RollbackContainment) nativeCommittedFor(accounts state.AccountsAdapter) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if !c.nativeOwned || !c.nativeCommitted || !c.closed || c.nativeReset || c.failure != nil {
		return errNativePersistenceReceipt
	}
	if err := c.nativeCheckRootsLocked(c.nativeRoots); err != nil {
		return c.nativeFailureLocked(err)
	}
	for _, store := range c.stores {
		if store == accounts {
			return nil
		}
	}
	return errNativePersistenceReceipt
}

// nativeResetReceipt follows the actual native abort/recreation of ALL stores.
// It closes the old context and never recreates, reverts or revives a VM itself.
// Root availability, canonical replacement and native cache/gas recovery remain
// obligations of that actual caller, not consequences of root equality here.
func (c *RollbackContainment) nativeResetReceipt() error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if !c.nativeOwned {
		return errNativePersistenceReceipt
	}
	if c.closed || c.nativeCommitted {
		return ErrExecutionClosed
	}
	if c.running {
		return ErrExecutionBusy
	}
	if err := c.nativeCheckRootsLocked(c.roots); err != nil {
		return c.nativeFailureLocked(err)
	}
	c.outputs, c.nativeRoots, c.failure = nil, nil, nil
	c.closed, c.recovered, c.nativeReset = true, true, true
	return nil
}

func (c *RollbackContainment) nativeResetFor(accounts state.AccountsAdapter) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	if !c.nativeOwned || !c.nativeReset || !c.closed || c.nativeCommitted || c.failure != nil {
		return errNativePersistenceReceipt
	}
	if err := c.nativeCheckRootsLocked(c.roots); err != nil {
		return c.nativeFailureLocked(err)
	}
	for _, store := range c.stores {
		if store == accounts {
			return nil
		}
	}
	return errNativePersistenceReceipt
}
