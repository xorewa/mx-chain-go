package hooks

import (
	"bytes"
	"sync"
	"sync/atomic"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-go/common"
	drwa "github.com/multiversx/mx-chain-go/process/drwa/headertime"
)

// T42's engineering adapter for the existing evaluated-header capability. Its
// owner is the actual hook shared by factories and native aliases, not a reader
// wrapper. All state is local lifecycle state, never a protocol generation.
type evaluatedHeaderTime struct {
	clock  *drwa.EvaluatedHeaderTime
	hasher hashing.Hasher
	gate   sync.Mutex
	active atomic.Pointer[evaluatedHeaderOperation]
	leases atomic.Int32
	closed atomic.Bool
}

type evaluatedHeaderOperation struct {
	hook         *BlockChainHookImpl
	valid        atomic.Bool
	ended        atomic.Bool
	context      *drwa.HeaderTimeContext // guarded by the native header mutex
	identity     []byte
	milliseconds uint64
	timeError    error
}

func (bh *BlockChainHookImpl) initializeEvaluatedHeaderTime(hasher hashing.Hasher) error {
	if check.IfNil(hasher) {
		return nil
	}
	clock, err := drwa.NewEvaluatedHeaderTime(bh.enableEpochsHandler, bh.marshalizer, hasher)
	if err != nil {
		return err
	}
	bh.drwaTime = &evaluatedHeaderTime{clock: clock, hasher: hasher}
	return nil
}

// Same implementation as the ordinary CurrentTimeStampMs accessor, with its
// native error retained. The caller owns the native header read/write lock.
func (bh *BlockChainHookImpl) currentTimeStampMsLocked() (uint64, error) {
	_, milliseconds, err := common.GetHeaderTimestamps(bh.currentHdr, bh.enableEpochsHandler)
	return milliseconds, err
}

func (bh *BlockChainHookImpl) invalidateEvaluatedHeaderTime() {
	if bh.drwaTime != nil {
		if operation := bh.drwaTime.active.Load(); operation != nil {
			operation.valid.Store(false)
		}
	}
}

// Ordinary installations retain the native blocking mutex. During an actual
// DRWA lease, re-entry cannot block behind its own read lock: deny the attempted
// install, having already invalidated its capability. The enclosing time-bound
// record operation detects that invalidation before its T04 boundary commits.
func (bh *BlockChainHookImpl) lockCurrentHeaderForTime() error {
	if bh.drwaTime != nil && bh.drwaTime.leases.Load() != 0 {
		if !bh.mutCurrentHdr.TryLock() {
			return drwa.ErrInactiveHeaderTime
		}
		return nil
	}
	bh.mutCurrentHdr.Lock()
	return nil
}

// BeginDRWAHeaderEvaluation is called by an admitted native operation owner.
// It returns its private installer and idempotent exit. Raw SetCurrentHeader
// cannot issue a context, even after A -> B -> A or an unsuccessful attempt.
// Availability errors belong to the typed view; native installation preserves
// its original error, and ordinary execution never gains a time requirement.
func (bh *BlockChainHookImpl) BeginDRWAHeaderEvaluation() (func(data.HeaderHandler) error, func(), error) {
	if bh == nil {
		return nil, nil, drwa.ErrUnavailableHeaderTime
	}
	if bh.drwaTime == nil {
		return bh.SetCurrentHeader, func() {}, nil
	}
	time := bh.drwaTime
	if time.closed.Load() {
		return nil, nil, drwa.ErrInactiveHeaderTime
	}
	if !time.gate.TryLock() {
		return nil, nil, drwa.ErrInactiveHeaderTime
	}
	if err := bh.lockCurrentHeaderForTime(); err != nil {
		time.gate.Unlock()
		return nil, nil, err
	}
	time.clock.Reset()
	operation := &evaluatedHeaderOperation{hook: bh}
	operation.valid.Store(true)
	time.active.Store(operation)
	bh.mutCurrentHdr.Unlock()
	return operation.install, operation.end, nil
}

func (operation *evaluatedHeaderOperation) end() {
	if !operation.ended.CompareAndSwap(false, true) {
		return
	}
	operation.valid.Store(false)
	time := operation.hook.drwaTime
	time.active.CompareAndSwap(operation, nil)
	// No blocking clock reset here: exit may be observed from a callback holding
	// a lease. The private clock's old context has an invalid operation binding.
	// A new evaluation resets it only after acquiring the actual header mutex.
	time.gate.Unlock()
}

func (operation *evaluatedHeaderOperation) install(header data.HeaderHandler) error {
	bh, time := operation.hook, operation.hook.drwaTime
	if time.active.Load() != operation || !operation.valid.Load() || operation.ended.Load() {
		return drwa.ErrInactiveHeaderTime
	}
	if err := bh.lockCurrentHeaderForTime(); err != nil {
		operation.valid.Store(false)
		return err
	}
	defer bh.mutCurrentHdr.Unlock()
	if time.active.Load() != operation || !operation.valid.Load() || operation.ended.Load() {
		return drwa.ErrInactiveHeaderTime
	}
	operation.context, operation.timeError = nil, nil
	time.clock.Reset()
	if err := bh.setCurrentHeaderLocked(header); err != nil {
		operation.valid.Store(false)
		return err
	}
	if !operation.valid.Load() || operation.ended.Load() {
		return drwa.ErrInactiveHeaderTime
	}
	var context *drwa.HeaderTimeContext
	context, err := time.clock.BeginBound(header,
		func() (func(), error) { return operation.acquire(context) },
		func() error { return operation.validateLocked(context) })
	if err != nil {
		operation.timeError = err
		return nil
	}
	operation.context = context
	operation.identity, _ = context.HeaderIdentity()
	operation.milliseconds, operation.timeError = bh.currentTimeStampMsLocked()
	return nil
}

func (operation *evaluatedHeaderOperation) acquire(context *drwa.HeaderTimeContext) (func(), error) {
	bh, time := operation.hook, operation.hook.drwaTime
	time.leases.Add(1)
	bh.mutCurrentHdr.RLock()
	release := func() { bh.mutCurrentHdr.RUnlock(); time.leases.Add(-1) }
	if err := operation.validateLocked(context); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (operation *evaluatedHeaderOperation) validateLocked(context *drwa.HeaderTimeContext) error {
	bh, time := operation.hook, operation.hook.drwaTime
	if context == nil || time.closed.Load() || time.active.Load() != operation || !operation.valid.Load() ||
		operation.ended.Load() || operation.context != context {
		return drwa.ErrInactiveHeaderTime
	}
	if operation.timeError != nil {
		return operation.timeError
	}
	if check.IfNil(bh.currentHdr) || check.IfNil(bh.marshalizer) || check.IfNil(time.hasher) {
		return drwa.ErrUnavailableHeaderTime
	}
	milliseconds, err := bh.currentTimeStampMsLocked()
	if err != nil {
		return err
	}
	if !bh.currentHdr.IsHeaderV3() || !bh.enableEpochsHandler.IsFlagEnabledInEpoch(common.SupernovaFlag, bh.currentHdr.GetEpoch()) {
		return drwa.ErrUnavailableHeaderTime
	}
	identity, err := core.CalculateHash(bh.marshalizer, time.hasher, bh.currentHdr)
	if err != nil {
		return err
	}
	if !bytes.Equal(identity, operation.identity) || milliseconds != operation.milliseconds {
		return drwa.ErrInactiveHeaderTime
	}
	return nil
}

// EvaluatedHeaderTimeContext exposes no native installer or clock alias.
// Genesis/query/simulation and plain raw installations have no owning proposal
// operation and therefore return an explicit error rather than authorizing zero.
func (bh *BlockChainHookImpl) EvaluatedHeaderTimeContext() (*drwa.HeaderTimeContext, error) {
	if bh == nil || bh.drwaTime == nil {
		return nil, drwa.ErrUnavailableHeaderTime
	}
	bh.mutCurrentHdr.RLock()
	defer bh.mutCurrentHdr.RUnlock()
	operation := bh.drwaTime.active.Load()
	if operation == nil || !operation.valid.Load() || operation.ended.Load() {
		return nil, drwa.ErrInactiveHeaderTime
	}
	if operation.timeError != nil {
		return nil, operation.timeError
	}
	if err := operation.validateLocked(operation.context); err != nil {
		return nil, err
	}
	return operation.context, nil
}
