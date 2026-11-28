package drwa

import (
	"bytes"
	"math/big"
)

// repairLifecycleComparison describes equality of the existing decoded lifecycle
// projection only. It is not an admission result or proof of complete CEB
// meaning, authenticated membership, canonicality, fencing or readiness.
type repairLifecycleComparison struct {
	closurePlan, supplyOrigin, supplyOriginShard, tokenType bool
}

// compareRepairLifecycleFields compares two separately decoded projections.
// Their decoder, validation and provenance remain the owning host's duties.
func compareRepairLifecycleFields(before, after lifecycleCEBFields) repairLifecycleComparison {
	return repairLifecycleComparison{
		closurePlan:       bytes.Equal(before.closurePlan, after.closurePlan),
		supplyOrigin:      bytes.Equal(before.supplyOrigin, after.supplyOrigin),
		supplyOriginShard: before.supplyOriginShard == after.supplyOriginShard,
		tokenType:         before.tokenType == after.tokenType,
	}
}

// repairSupplyComparison reports equality of numerical observations only.
// Both observations must describe the same accounting point of the same token
// to be relevant to repair preservation. Independent lawful supply effects
// between different accounting points are outside this comparison.
type repairSupplyComparison struct {
	cumulativeIssued, liveSupply, nextSupplyNonce bool
}

// compareRepairSupplyAccounting does not verify supply identity, the cap,
// roots, positions, valid state or authority. An unavailable record cannot
// establish any equality, even if neither side has a record.
func compareRepairSupplyAccounting(before, after *supplyAccounting) repairSupplyComparison {
	if before == nil || after == nil {
		return repairSupplyComparison{}
	}

	return repairSupplyComparison{
		cumulativeIssued: compareObservedRepairAmount(before.cumulativeIssued, after.cumulativeIssued),
		liveSupply:       compareObservedRepairAmount(before.liveSupply, after.liveSupply),
		nextSupplyNonce:  before.nextSupplyNonce == after.nextSupplyNonce,
	}
}

// compareObservedRepairAmount distinguishes a missing observation from an
// observed zero. It does not mutate either operand.
func compareObservedRepairAmount(before, after *big.Int) bool {
	return before != nil && after != nil && before.Cmp(after) == 0
}
