package node

import (
	"sync/atomic"

	"github.com/multiversx/mx-chain-go/process/drwa"
)

// The process can acquire its one original role once. The runner consumes it
// before entering the first managed component cycle.
var drwaOriginalProcessAcquired atomic.Bool

type acquiredDRWAOriginal struct {
	path string
	store originalMount
	used atomic.Bool
}

type originalMount struct {
	device, inode, mount uint64
	readonly bool
}

func (a *acquiredDRWAOriginal) consume() error {
	if a == nil || !a.used.CompareAndSwap(false, true) {
		return drwa.ErrDeploymentIdentity
	}
	return recheckOriginalStore(a)
}
