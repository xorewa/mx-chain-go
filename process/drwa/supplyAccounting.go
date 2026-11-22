package drwa

import (
	"errors"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core"
)

var errSupplyAccounting = errors.New("invalid DRWA supply accounting")

// supplyAccounting contains only the numeric fields of the existing SupplyState.
// It is not another ledger or a storage format. The owning native operation must
// load an explicitly initialized canonical SupplyState, bind token/origin/CEB and
// authenticated direction, and persist the successor nonce in its SAME journal
// before invoking the inner primitive. This calculation grants no authority and
// does not publish a nonce, root, position update or native balance effect.
type supplyAccounting struct {
	cumulativeIssued *big.Int
	liveSupply       *big.Int
	nextSupplyNonce  uint64
}

func newSupplyAccounting() *supplyAccounting {
	return &supplyAccounting{cumulativeIssued: new(big.Int), liveSupply: new(big.Int)}
}

// supplyIntegerFits checks width without first allocating an encoded copy.
// maxBytes must come from the admitted resource profile, never a caller's body.
func supplyIntegerFits(value *big.Int, maxBytes int) bool {
	if value == nil || maxBytes <= 0 || value.Sign() < 0 {
		return false
	}
	bits := value.BitLen()
	bytes := bits / 8
	if bits%8 != 0 {
		bytes++
	}
	return bytes <= maxBytes
}

// advance returns detached successor fields. A nil cap means an explicitly
// unbounded current policy, not missing policy. A nil prior state always denies.
// Per-nonce supply and preserve-position roots must be updated by their admitted
// native grammars in the same owning journal; this does not synthesize either.
func (s *supplyAccounting) advance(actionNonce uint64, increase bool, quantity, cap *big.Int, maxBytes int) (*supplyAccounting, error) {
	if s == nil || !supplyIntegerFits(s.cumulativeIssued, maxBytes) || !supplyIntegerFits(s.liveSupply, maxBytes) ||
		!supplyIntegerFits(quantity, maxBytes) || quantity.Sign() <= 0 ||
		s.liveSupply.Cmp(s.cumulativeIssued) > 0 || actionNonce != s.nextSupplyNonce ||
		cap != nil && !supplyIntegerFits(cap, maxBytes) {
		return nil, errSupplyAccounting
	}
	nextNonce, err := core.SafeAddUint64(s.nextSupplyNonce, 1)
	if err != nil {
		return nil, errSupplyAccounting
	}
	next := &supplyAccounting{cumulativeIssued: new(big.Int).Set(s.cumulativeIssued),
		liveSupply: new(big.Int).Set(s.liveSupply), nextSupplyNonce: nextNonce}
	if increase {
		next.cumulativeIssued.Add(next.cumulativeIssued, quantity)
		next.liveSupply.Add(next.liveSupply, quantity)
		if cap != nil && next.cumulativeIssued.Cmp(cap) > 0 {
			return nil, errSupplyAccounting
		}
	} else {
		if next.liveSupply.Cmp(quantity) < 0 {
			return nil, errSupplyAccounting
		}
		next.liveSupply.Sub(next.liveSupply, quantity)
	}
	if !supplyIntegerFits(next.cumulativeIssued, maxBytes) || !supplyIntegerFits(next.liveSupply, maxBytes) {
		return nil, errSupplyAccounting
	}
	return next, nil
}

// nonceSupplyAfter calculates a single admitted native nonce effect. A nil
// predecessor means the original operation authenticated a virgin leaf. The
// caller must bind the actual token, nonce, native quantity and role.
func (r *rootLeafRecords) nonceSupplyAfter(family core.ESDTType, function string, prior *nonceSupply,
	quantity, cap *big.Int) (nonceSupply, error) {
	if !nonceFamily(family) || !supplyIntegerFits(quantity, r.maxAmountBytes) || quantity.Sign() == 0 ||
		cap != nil && (!supplyIntegerFits(cap, r.maxAmountBytes) || uniqueNonceFamily(family)) ||
		prior != nil && !r.validNonceSupply(family, *prior) {
		return nonceSupply{}, errSupplyAccounting
	}
	next := nonceSupply{new(big.Int), new(big.Int)}
	if prior != nil {
		next.issued.Set(prior.issued)
		next.live.Set(prior.live)
	}
	switch function {
	case core.BuiltInFunctionESDTNFTCreate:
		if prior != nil {
			return nonceSupply{}, errSupplyAccounting
		}
		next.issued.Set(quantity)
		next.live.Set(quantity)
	case core.BuiltInFunctionESDTNFTAddQuantity:
		if prior == nil || uniqueNonceFamily(family) {
			return nonceSupply{}, errSupplyAccounting
		}
		next.issued.Add(next.issued, quantity)
		next.live.Add(next.live, quantity)
	case core.BuiltInFunctionESDTNFTBurn:
		if prior == nil || next.live.Cmp(quantity) < 0 {
			return nonceSupply{}, errSupplyAccounting
		}
		next.live.Sub(next.live, quantity)
	default:
		return nonceSupply{}, errSupplyAccounting
	}
	if !r.validNonceSupply(family, next) ||
		function != core.BuiltInFunctionESDTNFTBurn && cap != nil && next.issued.Cmp(cap) > 0 {
		return nonceSupply{}, errSupplyAccounting
	}
	return next, nil
}
