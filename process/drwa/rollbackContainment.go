// Package drwa owns DRWA-specific execution constructions. It is not installed
// in an upstream processor or dispatcher. Ordinary operations do not import it.
package drwa

import (
	"bytes"
	"errors"
	"sync"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// These errors describe DRWA-owned execution lifecycle states, not upstream
// return codes. They never replace an operation error after successful rollback.
var (
	ErrExecutionClosed      = errors.New("DRWA execution is closed")
	ErrExecutionBusy        = errors.New("DRWA execution is in progress")
	ErrInvalidOperation     = errors.New("nil DRWA operation")
	ErrUncommittedState     = errors.New("DRWA execution requires committed account stores")
	ErrExecutionInterrupted = errors.New("DRWA execution was interrupted")
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
