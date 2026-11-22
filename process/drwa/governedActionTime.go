package drwa

import (
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
)

var errGovernedActionTime = errors.New("invalid DRWA governed action time")

// governedActionWindow is the DRWA-defined GAS proposal geometry in Part A
// L1647-1685. It is a pure comparison component, not GAS state or authority.
// The actual proposal owner must supply the admitted action-class bounds and
// persist this geometry with the immutable action before consuming its nonce.
// No production ingress/dispatcher imports this unwired component.
type governedActionWindow struct {
	proposedAt, earliest, validUntil HeaderMilliseconds
}

// governedTimeAt requires T05's active evaluated-header capability at the exact
// owning locus. It selects no header or mode. Record consumers bind the native
// source at construction and retain its installation/lifecycle lease via T04.
func governedTimeAt(context *HeaderTimeContext, shard uint32) (HeaderMilliseconds, error) {
	if context == nil {
		return 0, ErrInactiveHeaderTime
	}
	_, locus := context.HeaderIdentity()
	if locus != shard {
		return 0, errGovernedActionTime
	}
	return context.Milliseconds()
}

func newGovernedActionWindow(context *HeaderTimeContext, minTimelock, maxLifetime,
	earliest, validUntil HeaderMilliseconds) (*governedActionWindow, error) {
	proposedAt, err := governedTimeAt(context, core.MetachainShardId)
	if err != nil {
		return nil, err
	}
	minimum, err := core.SafeAddUint64(uint64(proposedAt), uint64(minTimelock))
	if err != nil {
		return nil, err
	}
	maximum, err := core.SafeAddUint64(uint64(proposedAt), uint64(maxLifetime))
	if err != nil {
		return nil, err
	}
	if uint64(earliest) < minimum || validUntil <= earliest || uint64(validUntil) > maximum {
		return nil, errGovernedActionTime
	}
	return &governedActionWindow{proposedAt: proposedAt, earliest: earliest, validUntil: validUntil}, nil
}

// mayStart enforces the inclusive timelock and exclusive upper end. It grants
// no execution capability: the actual GAS owner must re-resolve every current
// dependency/certificate and serialize this comparison with its state change.
// Later IN_PROGRESS continuation must NOT use this first-start predicate.
func (w *governedActionWindow) mayStart(context *HeaderTimeContext) error {
	if w == nil || w.earliest < w.proposedAt || w.validUntil <= w.earliest {
		return errGovernedActionTime
	}
	time, err := governedTimeAt(context, core.MetachainShardId)
	if err != nil {
		return err
	}
	if time < w.earliest || time >= w.validUntil {
		return errGovernedActionTime
	}
	return nil
}

// projectionExpiry calculates the independent source-grant bound from the
// actual metachain arm coordinate. lifetime is the admitted maximum or the
// already validated earlier class bound, never an untrusted request's expiry.
// Numerical admissible ranges belong to profile admission. The existing typed
// capability is leased so a Reset/Begin cannot mix two arm coordinates here.
func (w *governedActionWindow) projectionExpiry(context *HeaderTimeContext,
	lifetime HeaderMilliseconds) (HeaderMilliseconds, error) {
	if err := w.mayStart(context); err != nil {
		return 0, err
	}
	time, _, release, err := context.Lease()
	if err != nil {
		return 0, err
	}
	defer release()
	expiry, err := core.SafeAddUint64(uint64(time), uint64(lifetime))
	return HeaderMilliseconds(expiry), err
}

// sourceProjectionBeforeExpiry checks ONLY F06 time eligibility. expiry must
// come from the exact authenticated canonical local projection of an already
// IN_PROGRESS GAS. True is not debit authority; false is not UNUSED proof.
// At/after expiry closure still needs exact durable non-consumption evidence.
// Neither this helper nor A01 introduces a destination-age deadline.
func sourceProjectionBeforeExpiry(context *HeaderTimeContext, sourceShard uint32,
	expiry HeaderMilliseconds) (bool, error) {
	if sourceShard == core.MetachainShardId {
		return false, errGovernedActionTime
	}
	time, err := governedTimeAt(context, sourceShard)
	if err != nil {
		return false, err
	}
	return time < expiry, nil
}
