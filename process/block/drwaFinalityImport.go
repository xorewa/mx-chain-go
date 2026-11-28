package block

import (
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data"
)

// beginDRWAFinalityImport is the deterministic import phase of a V3 block
// execution (Part A 6.1): the account stores are at the parent's executed root
// and nothing of this block has been applied. An error refuses the execution
// of the block on this node; the caller's failure path reverts every store.
func (bp *baseProcessor) beginDRWAFinalityImport(header data.HeaderHandler, headerHash []byte) error {
	if check.IfNil(bp.drwaFinalityImport) {
		return nil
	}

	return bp.drwaFinalityImport.BeginBlock(header, headerHash)
}

// endDRWAFinalityImport closes the execution opened by the import phase, after
// the native commit of the block state or when the block state is reverted.
func (bp *baseProcessor) endDRWAFinalityImport(committed bool) {
	if check.IfNil(bp.drwaFinalityImport) {
		return
	}

	bp.drwaFinalityImport.EndBlock(committed)
}
