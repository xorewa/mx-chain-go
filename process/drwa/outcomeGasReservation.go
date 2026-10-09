package drwa

import "github.com/multiversx/mx-chain-core-go/core"

// outcomeGasReservation is an experimental calculation of the existing AM-004
// source/destination/one-outcome/completion allocations, in source gas units.
// It owns no native gas, state, schedule, payer, beneficiary or admission right.
// The actual native owner must independently price the complete exact effect,
// bind/retain its pinned schedule, validate available source units and install
// and conserve these isolated partitions BEFORE debit. This is not that adapter.
type outcomeGasReservation struct {
	source, destination, outcome, completion, total, unreserved uint64
}

func reserveOutcomeGas(available, source, destination, success, refund, completion uint64) (outcomeGasReservation, error) {
	// Exactly one outcome is permitted. This max covers its two mutually
	// exclusive branches for ONE priced effect, not the whole-catalog policy.
	outcome := success
	if refund > outcome {
		outcome = refund
	}
	total, err := core.SafeAddUint64(source, destination)
	if err != nil {
		return outcomeGasReservation{}, err
	}
	total, err = core.SafeAddUint64(total, outcome)
	if err != nil {
		return outcomeGasReservation{}, err
	}
	total, err = core.SafeAddUint64(total, completion)
	if err != nil {
		return outcomeGasReservation{}, err
	}
	unreserved, err := core.SafeSubUint64(available, total)
	if err != nil {
		return outcomeGasReservation{}, err
	}
	return outcomeGasReservation{source: source, destination: destination, outcome: outcome,
		completion: completion, total: total, unreserved: unreserved}, nil
}

// destinationRemaining cannot borrow from outcome/completion. It is a pure
// arithmetic check, not actual VM accounting, execution or gas-refund handling.
func (r outcomeGasReservation) destinationRemaining(work uint64) (uint64, error) {
	return core.SafeSubUint64(r.destination, work)
}
