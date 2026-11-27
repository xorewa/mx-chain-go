package hooks

import (
	"errors"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"

	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/vm"
)

// ErrInvalidDRWABuiltInAdmission signals an incomplete admission dependency
var ErrInvalidDRWABuiltInAdmission = errors.New("invalid DRWA built-in admission")

// DRWABuiltInAdmission classifies the token identifiers of a built-in call
// before its first native effect (Part A 5.1, F.5 D17). It returns nil only
// for a call that carries no regulated identifier; such a call then runs the
// native dispatch unchanged. It reads no account and changes no state.
type DRWABuiltInAdmission interface {
	AdmitBuiltIn(function vmcommon.BuiltinFunction, input *vmcommon.ContractCallInput) error
	IsInterfaceNil() bool
}

// initializeDRWABuiltInAdmission is nil-preserving: a hook without the
// admission is the native hook. With it, the enforcement predicate is required.
func (bh *BlockChainHookImpl) initializeDRWABuiltInAdmission(admission DRWABuiltInAdmission,
	enforcedAt func(epoch uint32, round uint64) bool) error {
	if admission == nil {
		if enforcedAt != nil {
			return ErrInvalidDRWABuiltInAdmission
		}
		return nil
	}
	if check.IfNil(admission) || enforcedAt == nil {
		return ErrInvalidDRWABuiltInAdmission
	}
	bh.drwaBuiltInAdmission, bh.drwaBuiltInEnforcedAt = admission, enforcedAt
	return nil
}

// admitDRWABuiltIn applies the admission only while DRWA is enforced for the
// header in execution. Before enforcement, and on a hook without the
// admission, every built-in call keeps the native path.
func (bh *BlockChainHookImpl) admitDRWABuiltIn(function vmcommon.BuiltinFunction, input *vmcommon.ContractCallInput) error {
	if !bh.drwaEnforcedNow() {
		return nil
	}
	return bh.drwaBuiltInAdmission.AdmitBuiltIn(function, input)
}

// drwaEnforcedNow reports whether the admission applies to the header in
// execution. A hook without the admission is never enforced.
func (bh *BlockChainHookImpl) drwaEnforcedNow() bool {
	if bh.drwaBuiltInAdmission == nil {
		return false
	}
	bh.mutCurrentHdr.RLock()
	epoch, round := bh.currentHdr.GetEpoch(), bh.currentHdr.GetRound()
	bh.mutCurrentHdr.RUnlock()
	return bh.drwaBuiltInEnforcedAt(epoch, round)
}

// checkDRWAMetaDataSave guards the one native token-state write that does not
// pass the built-in dispatch: the metadata save after a failed incoming NFT
// transfer. That write is inert once SendAlwaysFlag is enabled (and before
// SaveToSystemAccountFlag). While DRWA is enforced, any configuration in which
// it would write is refused as a DRWA execution error instead of writing
// unclassified token state.
func (bh *BlockChainHookImpl) checkDRWAMetaDataSave() error {
	if !bh.drwaEnforcedNow() {
		return nil
	}
	if bh.enableEpochsHandler.IsFlagEnabled(common.SendAlwaysFlag) || !bh.enableEpochsHandler.IsFlagEnabled(common.SaveToSystemAccountFlag) {
		return nil
	}
	return fmt.Errorf("%w: native NFT metadata save is not classified", vm.ErrDRWAExecution)
}
