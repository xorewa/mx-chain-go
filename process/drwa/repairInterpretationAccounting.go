package drwa

import "errors"

var errRepairInterpretationObservation = errors.New("DRWA interpretation resource observation unavailable")

// repairInterpretationObservationBounds limits a detached accounting walk. The
// future native support owner provides admitted resource inputs. Neither field
// counts supported profiles or supplies a native resource/funding allowance.
type repairInterpretationObservationBounds struct {
	recordVisits, serializedBytes uint64
}

// repairInterpretationObservation accounts for the serialized key and material
// lengths actually observed. Record visits measure only this walk: repeated
// observations count again and these totals are not unique physical trie size,
// evaluator work, retained-meaning proof, gas or native resource admission.
type repairInterpretationObservation struct {
	recordVisits, keyBytes, materialBytes uint64
}

// measureRepairInterpretationObservations consumes already-resolved, detached
// currentLocalView projections. A current view includes no proof of historical
// retention, and this function neither authenticates nor opens those views.
// It owns no copies, store, read, mutation, interpretation or profile count.
// It cannot authorize any operation, even when all observations fit.
func measureRepairInterpretationObservations(views []*currentLocalView, bounds repairInterpretationObservationBounds) (repairInterpretationObservation, error) {
	if len(views) == 0 || bounds.recordVisits == 0 || bounds.serializedBytes == 0 {
		return repairInterpretationObservation{}, errRepairInterpretationObservation
	}

	var result repairInterpretationObservation
	remainingBytes := bounds.serializedBytes
	for _, view := range views {
		if view == nil || len(view.keys) == 0 || len(view.keys) != len(view.materials) ||
			uint64(len(view.keys)) > bounds.recordVisits-result.recordVisits {
			return repairInterpretationObservation{}, errRepairInterpretationObservation
		}
		for i, key := range view.keys {
			keyBytes := uint64(len(key))
			materialBytes := uint64(len(view.materials[i]))
			// Subtract before adding so the two subtotals share one bounded
			// budget, including on a platform with smaller native int width.
			if keyBytes == 0 || materialBytes == 0 || keyBytes > remainingBytes ||
				materialBytes > remainingBytes-keyBytes {
				return repairInterpretationObservation{}, errRepairInterpretationObservation
			}
			remainingBytes -= keyBytes + materialBytes
			result.keyBytes += keyBytes
			result.materialBytes += materialBytes
			result.recordVisits++
		}
	}
	return result, nil
}
