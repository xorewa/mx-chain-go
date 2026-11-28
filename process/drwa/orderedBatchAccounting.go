package drwa

import (
	"errors"
	"math/big"

	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

var errOrderedBatchAccounting = errors.New("DRWA ordered batch accounting observation unavailable")

// orderedBatchAccountingBounds are externally supplied diagnostic bounds, not
// native admission limits or a selected asset/route policy.
type orderedBatchAccountingBounds struct {
	legs, identifierBytes, amountBytes int
}

type observedBatchAsset struct {
	identifier string
	nonce      uint64
}

type observedBatchAssetTotal struct {
	asset       observedBatchAsset
	firstLeg    int
	occurrences int
	quantity    *big.Int
}

// summarizeOrderedBatchAccounting reports detached quantity totals grouped by
// the literal native asset identifier and nonce, in first-observed order.
// The complete native ordered vector, type, metadata and authenticated
// context remain with its original producer. This is not that vector's
// commitment, a transfer, a refund, a policy decision or conservation proof.
// In particular the native EGLD identifier is not reclassified or parsed.
func summarizeOrderedBatchAccounting(legs []*vmcommon.ESDTTransfer, bounds orderedBatchAccountingBounds) ([]observedBatchAssetTotal, error) {
	if len(legs) == 0 || len(legs) > bounds.legs || bounds.identifierBytes <= 0 || bounds.amountBytes <= 0 {
		return nil, errOrderedBatchAccounting
	}

	var totals []observedBatchAssetTotal
	index := make(map[observedBatchAsset]int)
	for position, leg := range legs {
		if leg == nil || len(leg.ESDTTokenName) == 0 || len(leg.ESDTTokenName) > bounds.identifierBytes ||
			!supplyIntegerFits(leg.ESDTValue, bounds.amountBytes) {
			return nil, errOrderedBatchAccounting
		}
		asset := observedBatchAsset{identifier: string(leg.ESDTTokenName), nonce: leg.ESDTTokenNonce}
		if i, found := index[asset]; found {
			totals[i].quantity.Add(totals[i].quantity, leg.ESDTValue)
			if !supplyIntegerFits(totals[i].quantity, bounds.amountBytes) {
				return nil, errOrderedBatchAccounting
			}
			totals[i].occurrences++
			continue
		}
		index[asset] = len(totals)
		totals = append(totals, observedBatchAssetTotal{
			asset: asset, firstLeg: position, occurrences: 1, quantity: new(big.Int).Set(leg.ESDTValue),
		})
	}
	return totals, nil
}
