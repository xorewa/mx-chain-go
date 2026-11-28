package drwa

import (
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
)

// supplyAccountingClass is a private projection coordinate, NOT a native
// operation ID or encoding. Its caller must have independently authenticated
// the operation/purpose before using it. Neither accounting nor this coordinate
// establishes native permission, class provenance, or PA/Supply approval.
type supplyAccountingClass uint8

const (
	supplyOrdinaryIncrease supplyAccountingClass = iota + 1
	supplyOrdinaryDecrease
	supplyTerminalDecrease
)

// supplyAccountingDirection checks the disjoint class against the existing
// native family operation. Signature presence is deliberately not an input.
// This is a pure accounting classification, not terminal execution admission.
func supplyAccountingDirection(class supplyAccountingClass, function string) (bool, error) {
	switch function {
	case core.BuiltInFunctionESDTLocalMint, core.BuiltInFunctionESDTNFTCreate, core.BuiltInFunctionESDTNFTAddQuantity:
		if class == supplyOrdinaryIncrease {
			return true, nil
		}
	case core.BuiltInFunctionESDTLocalBurn, core.BuiltInFunctionESDTNFTBurn:
		if class == supplyOrdinaryDecrease || class == supplyTerminalDecrease {
			return false, nil
		}
	}
	return false, errSupplyAccounting
}

// projectClassified computes detached successor accounting, without changing any
// native record, position, balance, role or nonce. No class fallback is used.
func (s *supplyAccounting) projectClassified(class supplyAccountingClass, function string, actionNonce uint64,
	quantity, cap *big.Int, maxBytes int) (*supplyAccounting, error) {
	increase, err := supplyAccountingDirection(class, function)
	if err != nil {
		return nil, err
	}
	return s.advance(actionNonce, increase, quantity, cap, maxBytes)
}

// supplyFactor is an internal applicability coordinate for the complete E.9
// roster. These are not CEB/wire bits and do not redefine any existing transfer
// factor, HOLDER_SEND, or disposal restriction. The admitted CEB representation
// and full ordinary lifecycle, factor and restriction matrices remain external
// prerequisites; no default applicability or authority is supplied here.
type supplyFactor uint8

const (
	supplyFactorB3 supplyFactor = 1 << iota
	supplyFactorC1
	supplyFactorC2
	supplyFactorC3
	supplyFactorC4
	supplyFactorD1
	supplyFactorE1
	supplyAllFactors = supplyFactorB3 | supplyFactorC1 | supplyFactorC2 | supplyFactorC3 | supplyFactorC4 | supplyFactorD1 | supplyFactorE1
)

type ordinarySupplyFactorTable struct {
	required, notApplicable supplyFactor
}

// checkOrdinarySupplyFactors validates only the structure and evaluated result
// of a supplied direction-specific table. D1 is mandatory in both directions.
// This cannot qualify the table itself, prove the evidence's currentness, or
// authorize a supply operation. Terminal classification is never evaluated by
// the ordinary table. All retained native checks stay with their owning route.
func checkOrdinarySupplyFactors(class supplyAccountingClass, table ordinarySupplyFactorTable, positive supplyFactor) error {
	if class != supplyOrdinaryIncrease && class != supplyOrdinaryDecrease {
		return errSupplyAccounting
	}
	if table.required&table.notApplicable != 0 || table.required|table.notApplicable != supplyAllFactors ||
		table.required&supplyFactorD1 == 0 || positive != table.required {
		return errSupplyAccounting
	}
	return nil
}

type ordinaryDisposalPolicy uint8
type ordinaryDisposalObservation uint8

const (
	disposalApplies ordinaryDisposalPolicy = iota + 1
	disposalDoesNotApply
)

const (
	disposalObservedClear ordinaryDisposalObservation = iota + 1
	disposalObservedRestricted
	disposalExplicitlyNotApplicable
)

// checkOrdinaryBurnDisposal checks the independent, explicitly selected
// destruction scope, not HOLDER_SEND or another ordinary transfer bit. A
// missing policy or a missing current assessment is not an affirmative result.
// Neither this check nor the applicability table confers native authority.
func checkOrdinaryBurnDisposal(class supplyAccountingClass, policy ordinaryDisposalPolicy, observation ordinaryDisposalObservation) error {
	if class != supplyOrdinaryDecrease {
		return errSupplyAccounting
	}
	if policy == disposalApplies && observation == disposalObservedClear ||
		policy == disposalDoesNotApply && observation == disposalExplicitlyNotApplicable {
		return nil
	}
	return errSupplyAccounting
}

// openRedemptionExposure is a read-only quantity comparison for PB-02. The
// inputs must be independently reconciled, disjoint, canonical observations
// for the same token/nonce/version; no native balance reservation or new
// ledger is implied. This report is not proof of lawful control or admission.
type openRedemptionExposure struct {
	controlledRequired, settledAvailable, shortfall *big.Int
}

// measureOpenRedemptionExposure separates outstanding unfulfilled collection,
// fulfilled-but-not-burned quantity and outgoing obligations not yet reflected
// in settled origin quantity. Already-debited obligations must not be included
// in pendingOutgoing a second time. A zero shortfall is necessary but never
// sufficient for no-resale: a programme must also qualify all-path control,
// pending-effect reconciliation, recovery, and competent acceptance (PB-02).
func measureOpenRedemptionExposure(settled, unfulfilled, fulfilledNotBurned, pendingOutgoing *big.Int, maxBytes int) (openRedemptionExposure, error) {
	for _, q := range []*big.Int{settled, unfulfilled, fulfilledNotBurned, pendingOutgoing} {
		if !supplyIntegerFits(q, maxBytes) {
			return openRedemptionExposure{}, errSupplyAccounting
		}
	}
	if pendingOutgoing.Cmp(settled) > 0 {
		return openRedemptionExposure{}, errSupplyAccounting
	}
	required := new(big.Int).Add(unfulfilled, fulfilledNotBurned)
	if !supplyIntegerFits(required, maxBytes) {
		return openRedemptionExposure{}, errSupplyAccounting
	}
	available := new(big.Int).Sub(settled, pendingOutgoing)
	shortfall := new(big.Int).Sub(required, available)
	if shortfall.Sign() < 0 {
		shortfall.SetInt64(0)
	}
	return openRedemptionExposure{required, available, shortfall}, nil
}
