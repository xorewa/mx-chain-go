package block

import "github.com/multiversx/mx-chain-core-go/data"

// QualSP221FinishBlockFailure exposes the block failure boundary. Test only.
func (bp *baseProcessor) QualSP221FinishBlockFailure(processingErr, original error) error {
	return bp.finishBlockFailure(processingErr, original)
}

// QualSP225CommitState exposes the native commit boundary. Test only.
func (bp *baseProcessor) QualSP225CommitState(header data.HeaderHandler) error {
	return bp.commitState(header)
}
