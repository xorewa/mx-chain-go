package drwaprototype

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

// NON_NORMATIVE_DRWA_PROTOTYPE
// DO_NOT_EXPOSE_AS_PUBLIC_WIRE_FORMAT
// REPLACED_BY_PART_B
//
// The digest grammar, limits and catalog API in this file exist only for the S1 semantic prototype.

const (
	prototypeGasScheduleProfileLimit = 256
	prototypeGasScheduleMapDomain    = "DRWA/PROTOTYPE/GAS_SCHEDULE/v1"
	prototypeGasCatalogDomain        = "DRWA/PROTOTYPE/GAS_CATALOG/v1"

	// PrototypeWorkBudgetSection is the dedicated non-normative S1 gas-schedule section.
	PrototypeWorkBudgetSection = "DRWAPrototypeCost"
	// PrototypeDestinationGateCost is the configured destination-gate work key.
	PrototypeDestinationGateCost = "DestinationGate"
	// PrototypeSuccessReceiptCost is the configured success-receipt work key.
	PrototypeSuccessReceiptCost = "SuccessReceipt"
	// PrototypeRefundGenerationCost is the configured refund-generation work key.
	PrototypeRefundGenerationCost = "RefundGeneration"
	// PrototypeSourceCompletionCost is the configured source-completion work key.
	PrototypeSourceCompletionCost = "SourceCompletion"
)

var (
	// ErrInvalidGasScheduleCatalog signals malformed or ambiguous prototype catalog input.
	ErrInvalidGasScheduleCatalog = errors.New("invalid non-normative DRWA prototype gas-schedule catalog")
	// ErrGasScheduleNotFound signals that the sealed catalog does not contain an identity.
	ErrGasScheduleNotFound = errors.New("non-normative DRWA prototype gas schedule not found")
	// ErrInvalidGasScheduleWorkBudget signals missing, zero or overflowing explicit S1 work costs.
	ErrInvalidGasScheduleWorkBudget = errors.New("invalid non-normative DRWA prototype gas-schedule work budget")
)

// GasScheduleMap is the S1 prototype view of one baseline gas-schedule map.
type GasScheduleMap map[string]map[string]uint64

// GasScheduleProfile binds one configured activation epoch to its exact schedule map.
type GasScheduleProfile struct {
	StartEpoch uint32
	Schedule   GasScheduleMap
}

// WorkBudgets holds the four separately reserved S1 protocol work components.
type WorkBudgets struct {
	DestinationGate  uint64
	SuccessReceipt   uint64
	RefundGeneration uint64
	SourceCompletion uint64
}

type sealedGasScheduleEntry struct {
	startEpoch uint32
	identity   [prototypeDigestLength]byte
}

// GasScheduleCatalog is a finite, immutable-by-API S1 catalog.
type GasScheduleCatalog struct {
	entries   []sealedGasScheduleEntry
	schedules map[[prototypeDigestLength]byte]GasScheduleMap
	identity  [prototypeDigestLength]byte
}

// SealGasScheduleCatalog validates, sorts and deep-copies a complete prototype schedule timeline.
func SealGasScheduleCatalog(profiles []GasScheduleProfile) (*GasScheduleCatalog, error) {
	if len(profiles) == 0 || len(profiles) > prototypeGasScheduleProfileLimit {
		return nil, fmt.Errorf("%w: profile count", ErrInvalidGasScheduleCatalog)
	}

	profilesCopy := make([]GasScheduleProfile, len(profiles))
	for index, profile := range profiles {
		profilesCopy[index] = GasScheduleProfile{
			StartEpoch: profile.StartEpoch,
			Schedule:   cloneGasScheduleMap(profile.Schedule),
		}
	}
	sort.Slice(profilesCopy, func(first int, second int) bool {
		return profilesCopy[first].StartEpoch < profilesCopy[second].StartEpoch
	})
	if profilesCopy[0].StartEpoch != 0 {
		return nil, fmt.Errorf("%w: first activation epoch", ErrInvalidGasScheduleCatalog)
	}

	catalog := &GasScheduleCatalog{
		entries:   make([]sealedGasScheduleEntry, 0, len(profilesCopy)),
		schedules: make(map[[prototypeDigestLength]byte]GasScheduleMap),
	}
	canonicalMaps := make(map[[prototypeDigestLength]byte][]byte)
	for index, profile := range profilesCopy {
		if index > 0 && profile.StartEpoch == profilesCopy[index-1].StartEpoch {
			return nil, fmt.Errorf("%w: duplicate activation epoch %d", ErrInvalidGasScheduleCatalog, profile.StartEpoch)
		}
		identity, canonical, err := canonicalGasScheduleIdentity(profile.Schedule)
		if err != nil {
			return nil, err
		}
		if existing, exists := canonicalMaps[identity]; exists && !bytes.Equal(existing, canonical) {
			return nil, fmt.Errorf("%w: schedule identity collision", ErrInvalidGasScheduleCatalog)
		}
		if _, exists := catalog.schedules[identity]; !exists {
			canonicalMaps[identity] = append([]byte(nil), canonical...)
			catalog.schedules[identity] = cloneGasScheduleMap(profile.Schedule)
		}
		catalog.entries = append(catalog.entries, sealedGasScheduleEntry{
			startEpoch: profile.StartEpoch,
			identity:   identity,
		})
	}

	catalog.identity = deriveGasScheduleCatalogIdentity(catalog.entries)
	return catalog, nil
}

// GasScheduleIdentity derives the deterministic identity for one exact prototype map.
func GasScheduleIdentity(schedule GasScheduleMap) ([prototypeDigestLength]byte, error) {
	identity, _, err := canonicalGasScheduleIdentity(schedule)
	return identity, err
}

// Identity returns the sealed activation-timeline identity.
func (catalog *GasScheduleCatalog) Identity() ([prototypeDigestLength]byte, error) {
	if catalog == nil {
		return [prototypeDigestLength]byte{}, fmt.Errorf("%w: nil catalog", ErrInvalidGasScheduleCatalog)
	}
	return catalog.identity, nil
}

// IdentityAtEpoch returns the last configured identity whose start epoch is not greater than epoch.
func (catalog *GasScheduleCatalog) IdentityAtEpoch(epoch uint32) ([prototypeDigestLength]byte, error) {
	if catalog == nil || len(catalog.entries) == 0 {
		return [prototypeDigestLength]byte{}, fmt.Errorf("%w: unavailable timeline", ErrInvalidGasScheduleCatalog)
	}
	selected := catalog.entries[0].identity
	for _, entry := range catalog.entries {
		if entry.startEpoch > epoch {
			break
		}
		selected = entry.identity
	}
	return selected, nil
}

// Schedule returns a deep copy of one retained profile.
func (catalog *GasScheduleCatalog) Schedule(identity [prototypeDigestLength]byte) (GasScheduleMap, error) {
	if catalog == nil {
		return nil, fmt.Errorf("%w: nil catalog", ErrInvalidGasScheduleCatalog)
	}
	schedule, exists := catalog.schedules[identity]
	if !exists {
		return nil, ErrGasScheduleNotFound
	}
	return cloneGasScheduleMap(schedule), nil
}

// MaximumWorkBudgets returns the componentwise maximum explicit cost across every sealed profile.
func (catalog *GasScheduleCatalog) MaximumWorkBudgets() (WorkBudgets, error) {
	if catalog == nil || len(catalog.entries) == 0 {
		return WorkBudgets{}, fmt.Errorf("%w: unavailable catalog", ErrInvalidGasScheduleWorkBudget)
	}

	maximum := WorkBudgets{}
	for index, entry := range catalog.entries {
		schedule, exists := catalog.schedules[entry.identity]
		if !exists {
			return WorkBudgets{}, fmt.Errorf("%w: missing retained profile %d", ErrInvalidGasScheduleWorkBudget, index)
		}
		section, exists := schedule[PrototypeWorkBudgetSection]
		if !exists {
			return WorkBudgets{}, fmt.Errorf("%w: missing section in profile %d", ErrInvalidGasScheduleWorkBudget, index)
		}

		profile, err := workBudgetsFromSection(section)
		if err != nil {
			return WorkBudgets{}, fmt.Errorf("%w: profile %d: %v", ErrInvalidGasScheduleWorkBudget, index, err)
		}
		maximum.DestinationGate = max(maximum.DestinationGate, profile.DestinationGate)
		maximum.SuccessReceipt = max(maximum.SuccessReceipt, profile.SuccessReceipt)
		maximum.RefundGeneration = max(maximum.RefundGeneration, profile.RefundGeneration)
		maximum.SourceCompletion = max(maximum.SourceCompletion, profile.SourceCompletion)
	}

	_, err := maximum.Total()
	if err != nil {
		return WorkBudgets{}, err
	}

	return maximum, nil
}

// Total returns the overflow-checked sum required before source mutation.
func (budgets WorkBudgets) Total() (uint64, error) {
	total := uint64(0)
	components := []uint64{
		budgets.DestinationGate,
		budgets.SuccessReceipt,
		budgets.RefundGeneration,
		budgets.SourceCompletion,
	}
	for _, component := range components {
		if component == 0 {
			return 0, fmt.Errorf("%w: zero component", ErrInvalidGasScheduleWorkBudget)
		}
		if math.MaxUint64-total < component {
			return 0, fmt.Errorf("%w: total overflow", ErrInvalidGasScheduleWorkBudget)
		}
		total += component
	}

	return total, nil
}

func workBudgetsFromSection(section map[string]uint64) (WorkBudgets, error) {
	if section == nil {
		return WorkBudgets{}, fmt.Errorf("%w: nil section", ErrInvalidGasScheduleWorkBudget)
	}
	budgets := WorkBudgets{
		DestinationGate:  section[PrototypeDestinationGateCost],
		SuccessReceipt:   section[PrototypeSuccessReceiptCost],
		RefundGeneration: section[PrototypeRefundGenerationCost],
		SourceCompletion: section[PrototypeSourceCompletionCost],
	}
	_, err := budgets.Total()
	if err != nil {
		return WorkBudgets{}, err
	}

	return budgets, nil
}

func canonicalGasScheduleIdentity(schedule GasScheduleMap) ([prototypeDigestLength]byte, []byte, error) {
	if len(schedule) == 0 {
		return [prototypeDigestLength]byte{}, nil, fmt.Errorf("%w: empty schedule", ErrInvalidGasScheduleCatalog)
	}
	sections := make([]string, 0, len(schedule))
	for section, operations := range schedule {
		if len(section) == 0 || len(section) > math.MaxUint16 || len(operations) == 0 {
			return [prototypeDigestLength]byte{}, nil, fmt.Errorf("%w: section", ErrInvalidGasScheduleCatalog)
		}
		sections = append(sections, section)
	}
	sort.Strings(sections)

	canonical := make([]byte, 0)
	canonical = binary.BigEndian.AppendUint32(canonical, uint32(len(sections)))
	for _, section := range sections {
		canonical = appendUint16String(canonical, section)
		operationsMap := schedule[section]
		operations := make([]string, 0, len(operationsMap))
		for operation := range operationsMap {
			if len(operation) == 0 || len(operation) > math.MaxUint16 {
				return [prototypeDigestLength]byte{}, nil, fmt.Errorf("%w: operation", ErrInvalidGasScheduleCatalog)
			}
			operations = append(operations, operation)
		}
		sort.Strings(operations)
		canonical = binary.BigEndian.AppendUint32(canonical, uint32(len(operations)))
		for _, operation := range operations {
			canonical = appendUint16String(canonical, operation)
			canonical = binary.BigEndian.AppendUint64(canonical, operationsMap[operation])
		}
	}

	preimage := append([]byte(prototypeGasScheduleMapDomain), canonical...)
	return sha256.Sum256(preimage), canonical, nil
}

func deriveGasScheduleCatalogIdentity(entries []sealedGasScheduleEntry) [prototypeDigestLength]byte {
	preimage := make([]byte, 0, len(prototypeGasCatalogDomain)+4+len(entries)*(4+prototypeDigestLength))
	preimage = append(preimage, prototypeGasCatalogDomain...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(entries)))
	for _, entry := range entries {
		preimage = binary.BigEndian.AppendUint32(preimage, entry.startEpoch)
		preimage = append(preimage, entry.identity[:]...)
	}
	return sha256.Sum256(preimage)
}

func appendUint16String(destination []byte, value string) []byte {
	destination = binary.BigEndian.AppendUint16(destination, uint16(len(value)))
	return append(destination, value...)
}

func cloneGasScheduleMap(schedule GasScheduleMap) GasScheduleMap {
	if schedule == nil {
		return nil
	}
	result := make(GasScheduleMap, len(schedule))
	for section, operations := range schedule {
		clonedOperations := make(map[string]uint64, len(operations))
		for operation, cost := range operations {
			clonedOperations[operation] = cost
		}
		result[section] = clonedOperations
	}
	return result
}
