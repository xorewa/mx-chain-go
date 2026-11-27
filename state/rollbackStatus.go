package state

import (
	"errors"
	"fmt"
)

// ErrRollbackFailed marks an account store whose journal revert failed. The
// store then holds mutations that were neither kept nor undone (Part A P-05).
var ErrRollbackFailed = errors.New("account state rollback failed")

// RollbackStatusHandler is the separate status of an account store's reverts.
// Callers of RevertToSnapshot keep their native result; the owner of the block
// reads this status and must not continue with or commit the store while it
// reports a failure.
type RollbackStatusHandler interface {
	RollbackFailure() error
}

// retainRollbackFailure keeps the first failed revert until the store is
// recreated from a committed root. It must be called under mutOp.
func (adb *AccountsDB) retainRollbackFailure(err error) {
	if err == nil || adb.rollbackFailure != nil {
		return
	}
	adb.rollbackFailure = fmt.Errorf("%w: %w", ErrRollbackFailed, err)
	log.Warn("accountsDB.RevertToSnapshot failed, commit is refused until the trie is recreated", "error", err.Error())
}

// RollbackFailure returns the retained failure of RevertToSnapshot, or nil.
// A successful RecreateTrie, including RevertToSnapshot(0), clears it.
func (adb *AccountsDB) RollbackFailure() error {
	adb.mutOp.RLock()
	defer adb.mutOp.RUnlock()

	return adb.rollbackFailure
}
