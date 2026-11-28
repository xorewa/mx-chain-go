package drwa

import (
	"sync"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
)

// CarrierCostSection is the section of the native gas schedule that holds the
// carrier entries. EXPERIMENTAL name and layout (Part A E.18.7: the pricing
// representation is open); no schedule file of the baseline has this section,
// and until an admitted schedule supplies it every admission is refused.
const CarrierCostSection = "DRWACarrierCost"

// carrierPriceFields are the entry names of one class, after the class name.
var carrierPriceFields = [...]string{"Source", "Destination", "Success", "Refund", "Completion"}

// GasScheduleCarrierPricing is the production CarrierPriceSource: the entries
// of the schedule the native notifier holds as active. It follows schedule
// changes as every native gas consumer does (core.GasScheduleSubscribeHandler).
type GasScheduleCarrierPricing struct {
	mut     sync.RWMutex
	entries map[string]uint64
}

// NewGasScheduleCarrierPricing reads the active schedule and subscribes to its
// changes.
func NewGasScheduleCarrierPricing(schedule core.GasScheduleNotifier) (*GasScheduleCarrierPricing, error) {
	if check.IfNil(schedule) {
		return nil, ErrCarrierFunding
	}
	p := &GasScheduleCarrierPricing{}
	p.GasScheduleChange(schedule.LatestGasSchedule())
	schedule.RegisterNotifyHandler(p)
	return p, nil
}

// GasScheduleChange replaces the active entries with those of the new
// schedule. A schedule without the section prices nothing.
func (p *GasScheduleCarrierPricing) GasScheduleChange(gasSchedule map[string]map[string]uint64) {
	entries := make(map[string]uint64, len(gasSchedule[CarrierCostSection]))
	for name, cost := range gasSchedule[CarrierCostSection] {
		entries[name] = cost
	}
	p.mut.Lock()
	p.entries = entries
	p.mut.Unlock()
}

// CarrierPrice returns the five entries of class under the active schedule.
// A class with any entry missing has no price; an entry that is present with
// the value zero is a price.
func (p *GasScheduleCarrierPricing) CarrierPrice(class string) (CarrierPrice, error) {
	if len(class) == 0 {
		return CarrierPrice{}, ErrCarrierFunding
	}
	p.mut.RLock()
	defer p.mut.RUnlock()
	var values [len(carrierPriceFields)]uint64
	for i, field := range carrierPriceFields {
		value, present := p.entries[class+field]
		if !present {
			return CarrierPrice{}, ErrCarrierFunding
		}
		values[i] = value
	}
	return CarrierPrice{Source: values[0], Destination: values[1],
		Success: values[2], Refund: values[3], Completion: values[4]}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (p *GasScheduleCarrierPricing) IsInterfaceNil() bool { return p == nil }
