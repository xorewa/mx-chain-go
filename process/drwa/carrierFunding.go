package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
)

// EXPERIMENTAL representation (Part A E.18.2, phase precision): the retained
// pricing and phase record of one carried effect. Part B freezes the production
// form. The record is written only by CarrierFunding.
const carrierFundingPrefix = core.ProtectedKeyPrefix + "DRWA@carrierFunding@"

const carrierFundingTag = "DRWA/CARRIER_FUNDING/candidate1"

const carrierPriceTag = "DRWA/CARRIER_PRICE/candidate1"

// maxCarrierLegs is the largest leg count one effect can have: the legs are
// execution shards, named by the last byte of their system account address
// (registryDeltaSystemAddress), and the outcome bitmap has one bit for each.
const maxCarrierLegs = 255

// ErrCarrierFunding refuses a funding request that is malformed, unknown,
// repeated, or whose retained record or active price cannot be read exactly.
var ErrCarrierFunding = errors.New("invalid DRWA carrier funding")

// ErrCarrierUnderfunded refuses an operation whose gas does not cover the work
// it would accept. Nothing is written.
var ErrCarrierUnderfunded = errors.New("insufficient gas for DRWA carrier funding")

// CarrierPrice holds the exact gas entries of one effect class under one
// schedule (Part A 4.7.4). Source is the source's own work for the effect.
// Destination, Success, Refund and Completion are per leg: the destination's
// work, the two mutually exclusive outcome carriers, and the source's work to
// apply that leg's outcome. They are gas units of the paying transaction, not
// a balance.
type CarrierPrice struct {
	Source, Destination, Success, Refund, Completion uint64
}

// CarrierPriceSource supplies the price of new source admissions under the
// schedule active for the block in execution. There is no default price: an
// unknown class, a missing entry or an error refuses the admission.
type CarrierPriceSource interface {
	CarrierPrice(class string) (CarrierPrice, error)
	IsInterfaceNil() bool
}

// Carrier funding phases (Part A E.18.4). Before the source commits there is
// no record.
const (
	// CarrierOpen: the source committed; no leg has an outcome.
	CarrierOpen = uint8(1)
	// CarrierOutcome: at least one leg has its outcome; the source is not
	// terminal.
	CarrierOutcome = uint8(2)
	// CarrierTerminal: every leg has its outcome. The record stays as the
	// replay barrier.
	CarrierTerminal = uint8(3)
)

// CarrierReservation is the partition of one admission or one redrive.
type CarrierReservation struct {
	// Identity and Price are the retained pricing of the effect: the exact
	// entries and the pricing identity that names the class and those entries.
	Identity []byte
	Price    CarrierPrice
	Legs     uint32
	// LegGas is what each leg's carrier is given: destination work, one
	// outcome and its completion.
	LegGas uint64
	// Total was taken from the available gas; Remaining is what is left of it.
	Total, Remaining uint64
}

// CarrierFundingState is the retained record of one effect.
type CarrierFundingState struct {
	Identity []byte
	Price    CarrierPrice
	Legs     uint32
	Phase    uint8
	// Outcomes has bit n set when leg n's outcome was applied.
	Outcomes []byte
	Redrives uint64
}

// HasOutcome tells whether leg's outcome was applied. A retained record has
// no bit for a leg the effect does not have.
func (s *CarrierFundingState) HasOutcome(leg uint32) bool {
	return s != nil && int(leg/8) < len(s.Outcomes) && s.Outcomes[leg/8]&(1<<(leg%8)) != 0
}

// CarrierOutcomeResult is what the source did with one arriving outcome.
type CarrierOutcomeResult struct {
	// Applied is false for the outcome of a leg that already has one: nothing
	// was written and nothing was charged.
	Applied bool
	// Terminal is true when every leg has its outcome.
	Terminal bool
	// Completion is the retained completion work charged to the carrier's
	// gas; Remaining is what is left of that gas.
	Completion, Remaining uint64
}

// ArgsCarrierFunding holds the native dependencies of the funding owner.
// Limits is the chain-global retained budget of SP2-29. No value has a default.
type ArgsCarrierFunding struct {
	Accounts    state.AccountsAdapter
	Marshaller  marshal.Marshalizer
	Hasher      hashing.Hasher
	Block       ConvergenceBlockSource
	Prices      CarrierPriceSource
	Limits      RegistrationResourceLimits
	RecordBytes int
}

// CarrierFunding is the source-side owner of the pricing and phase of carried
// DRWA effects (AM-002/004/005; Part A 4.7.4, E.18).
//
//   - Accept prices a new effect under the active schedule, checks the whole
//     overflow-safe partition against the gas in hand and retains the exact
//     entries with the effect. An underfunded effect is refused before
//     anything is written.
//   - Outcome and Redrive use only the retained entries. A later schedule
//     prices new admissions and nothing else.
//   - The record is never deleted and never reopened: after the last outcome
//     it is the replay barrier.
//
// Every method runs inside its caller's native journal operation and neither
// commits nor reverts. The gas itself stays where the native processor keeps
// it: in the paying transaction and in the results it creates. The record
// holds prices and phase, not funds (E.18.4).
type CarrierFunding struct {
	args  ArgsCarrierFunding
	codec *registrationRecords
}

// NewCarrierFunding creates the owner. It reads no state.
func NewCarrierFunding(args ArgsCarrierFunding) (*CarrierFunding, error) {
	if check.IfNil(args.Block) || check.IfNil(args.Prices) || args.Limits.Records == 0 ||
		args.Limits.RetainedBytes == 0 || args.Limits.NewRecordsPerEpoch == 0 {
		return nil, ErrCarrierFunding
	}
	codec, err := newRegistrationRecords(args.Accounts, args.Marshaller, args.Hasher, args.RecordBytes)
	if err != nil {
		return nil, err
	}
	return &CarrierFunding{args: args, codec: codec}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (f *CarrierFunding) IsInterfaceNil() bool { return f == nil }

func (f *CarrierFunding) budget() *scopedAdmissionRecords {
	return &scopedAdmissionRecords{codec: f.codec, limits: scopedAdmissionLimits{recordBytes: f.codec.maxBytes,
		records: f.args.Limits.Records, retainedBytes: f.args.Limits.RetainedBytes,
		newRecordsPerEpoch: f.args.Limits.NewRecordsPerEpoch}}
}

// binding is the identity of one effect of one class.
func (f *CarrierFunding) binding(class string, effect []byte) ([]byte, error) {
	if len(class) == 0 || len(effect) == 0 {
		return nil, ErrCarrierFunding
	}
	preimage, err := f.codec.frame([]byte(carrierFundingTag), []byte(class), effect)
	if err != nil {
		return nil, ErrCarrierFunding
	}
	return f.codec.hasher.Compute(string(preimage)), nil
}

// priceIdentity is the pricing identity of an effect (Part A 4.7.4,
// gas_schedule_version): it names the class and exactly its five entries, so
// two schedules that price the class alike give the same identity, and a
// record whose identity and entries disagree is recognised.
func (f *CarrierFunding) priceIdentity(class string, price CarrierPrice) []byte {
	// The entries have a fixed size, so the class before them is unambiguous.
	preimage := append([]byte(carrierPriceTag), class...)
	for _, entry := range [...]uint64{price.Source, price.Destination, price.Success, price.Refund, price.Completion} {
		preimage = binary.BigEndian.AppendUint64(preimage, entry)
	}
	return f.codec.hasher.Compute(string(preimage))
}

// carrierLegGas is the overflow-safe gas of one leg: destination work, the
// larger of the two mutually exclusive outcomes, and completion.
func carrierLegGas(price CarrierPrice) (uint64, error) {
	leg, err := reserveOutcomeGas(^uint64(0), 0, price.Destination, price.Success, price.Refund, price.Completion)
	if err != nil {
		return 0, err
	}
	return leg.total, nil
}

// carrierReserve takes source work and legs legs out of available.
func carrierReserve(available, source uint64, legs uint32, price CarrierPrice) (legGas, total, remaining uint64, err error) {
	legGas, err = carrierLegGas(price)
	if err != nil {
		return 0, 0, 0, ErrCarrierFunding
	}
	total = source
	for leg := uint32(0); leg < legs; leg++ {
		if total, err = core.SafeAddUint64(total, legGas); err != nil {
			return 0, 0, 0, ErrCarrierFunding
		}
	}
	if total == 0 {
		return 0, 0, 0, ErrCarrierFunding
	}
	if remaining, err = core.SafeSubUint64(available, total); err != nil {
		return 0, 0, 0, ErrCarrierUnderfunded
	}
	return legGas, total, remaining, nil
}

func (f *CarrierFunding) encode(binding []byte, s *CarrierFundingState) ([]byte, error) {
	prices := make([]byte, 0, 40)
	for _, entry := range [...]uint64{s.Price.Source, s.Price.Destination, s.Price.Success, s.Price.Refund, s.Price.Completion} {
		prices = binary.BigEndian.AppendUint64(prices, entry)
	}
	return f.codec.frame([]byte(carrierFundingTag), binding, s.Identity, prices,
		binary.BigEndian.AppendUint32(nil, s.Legs), []byte{s.Phase}, s.Outcomes,
		binary.BigEndian.AppendUint64(nil, s.Redrives))
}

// decode accepts only the exact canonical record of this effect: a record that
// is shorter, longer, of another effect, whose phase disagrees with its
// outcomes, or whose pricing identity is not that of its class and entries is
// corruption and refuses every operation on the effect.
func (f *CarrierFunding) decode(class string, binding, raw []byte) (*CarrierFundingState, error) {
	fields, err := f.codec.unframe(raw, 8)
	if err != nil || len(fields[3]) != 40 || len(fields[4]) != 4 || len(fields[5]) != 1 ||
		len(fields[6]) != 32 || len(fields[7]) != 8 {
		return nil, ErrCarrierFunding
	}
	s := &CarrierFundingState{Identity: bytes.Clone(fields[2]), Legs: binary.BigEndian.Uint32(fields[4]),
		Phase: fields[5][0], Outcomes: bytes.Clone(fields[6]), Redrives: binary.BigEndian.Uint64(fields[7])}
	s.Price = CarrierPrice{Source: binary.BigEndian.Uint64(fields[3]), Destination: binary.BigEndian.Uint64(fields[3][8:]),
		Success: binary.BigEndian.Uint64(fields[3][16:]), Refund: binary.BigEndian.Uint64(fields[3][24:]),
		Completion: binary.BigEndian.Uint64(fields[3][32:])}
	if s.Legs == 0 || s.Legs > maxCarrierLegs || !bytes.Equal(s.Identity, f.priceIdentity(class, s.Price)) {
		return nil, ErrCarrierFunding
	}
	applied := uint32(0)
	for bit := uint32(0); bit < 256; bit++ {
		if s.Outcomes[bit/8]&(1<<(bit%8)) == 0 {
			continue
		}
		if bit >= s.Legs {
			return nil, ErrCarrierFunding
		}
		applied++
	}
	phase := CarrierOutcome
	switch applied {
	case 0:
		phase = CarrierOpen
	case s.Legs:
		phase = CarrierTerminal
	}
	if s.Phase != phase {
		return nil, ErrCarrierFunding
	}
	// The tag and the effect's own binding are checked here: the record must
	// be, byte for byte, what encode writes for this effect.
	canonical, err := f.encode(binding, s)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrCarrierFunding
	}
	return s, nil
}

func (f *CarrierFunding) load(class string, effect []byte) (account state.UserAccountHandler, key, binding, raw []byte, err error) {
	if binding, err = f.binding(class, effect); err != nil {
		return nil, nil, nil, nil, err
	}
	key = append([]byte(carrierFundingPrefix), binding...)
	if account, err = f.codec.state.systemAccount(); err != nil {
		return nil, nil, nil, nil, err
	}
	raw, _, err = account.RetrieveValue(key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return account, key, binding, bytes.Clone(raw), nil
}

func (f *CarrierFunding) save(account state.UserAccountHandler, key, binding []byte, s *CarrierFundingState) error {
	encoded, err := f.encode(binding, s)
	if err != nil {
		return ErrCarrierFunding
	}
	_, _, epoch, err := f.args.Block.ExecutingBlock()
	if err != nil {
		return err
	}
	return f.budget().retain(account, epoch, scopedAdmissionWrite{key, encoded})
}

// Accept admits one new effect of class with legs legs, paid from available
// gas units of the operation in execution. The caller takes Total from that
// gas and gives LegGas to each leg's carrier. An effect is admitted once: the
// same class and effect again is refused, whatever its phase.
func (f *CarrierFunding) Accept(class string, effect []byte, legs uint32, available uint64) (*CarrierReservation, error) {
	if legs == 0 || legs > maxCarrierLegs {
		return nil, ErrCarrierFunding
	}
	account, key, binding, raw, err := f.load(class, effect)
	if err != nil {
		return nil, err
	}
	if len(raw) != 0 {
		return nil, ErrCarrierFunding
	}
	price, err := f.args.Prices.CarrierPrice(class)
	if err != nil {
		return nil, err
	}
	identity := f.priceIdentity(class, price)
	legGas, total, remaining, err := carrierReserve(available, price.Source, legs, price)
	if err != nil {
		return nil, err
	}
	s := &CarrierFundingState{Identity: identity, Price: price, Legs: legs, Phase: CarrierOpen,
		Outcomes: make([]byte, 32)}
	if err = f.save(account, key, binding, s); err != nil {
		return nil, err
	}
	return &CarrierReservation{Identity: bytes.Clone(identity), Price: price, Legs: legs,
		LegGas: legGas, Total: total, Remaining: remaining}, nil
}

// Read returns the retained record of one effect, or nil when the effect was
// never admitted. Absence is not an outcome.
func (f *CarrierFunding) Read(class string, effect []byte) (*CarrierFundingState, error) {
	_, _, binding, raw, err := f.load(class, effect)
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	return f.decode(class, binding, raw)
}

// Outcome applies the outcome of one leg at the source, paid from the gas its
// carrier provided. The completion work is the retained entry, not the active
// schedule's. A leg has one outcome: the same leg again changes nothing and is
// not charged. A carrier with less gas than the retained completion work is
// refused and the leg stays open; it does not borrow from another leg or
// another effect. An effect that was never admitted has no outcome.
func (f *CarrierFunding) Outcome(class string, effect []byte, leg uint32, provided uint64) (CarrierOutcomeResult, error) {
	account, key, binding, raw, err := f.load(class, effect)
	if err != nil {
		return CarrierOutcomeResult{}, err
	}
	// An effect that was never admitted has no record, and no record decodes.
	s, err := f.decode(class, binding, raw)
	if err != nil {
		return CarrierOutcomeResult{}, err
	}
	if leg >= s.Legs {
		return CarrierOutcomeResult{}, ErrCarrierFunding
	}
	if s.HasOutcome(leg) {
		return CarrierOutcomeResult{Terminal: s.Phase == CarrierTerminal, Remaining: provided}, nil
	}
	remaining, err := core.SafeSubUint64(provided, s.Price.Completion)
	if err != nil {
		return CarrierOutcomeResult{}, ErrCarrierUnderfunded
	}
	s.Outcomes[leg/8] |= 1 << (leg % 8)
	s.Phase = CarrierOutcome
	terminal := true
	for other := uint32(0); other < s.Legs; other++ {
		terminal = terminal && s.HasOutcome(other)
	}
	if terminal {
		s.Phase = CarrierTerminal
	}
	if err = f.save(account, key, binding, s); err != nil {
		return CarrierOutcomeResult{}, err
	}
	return CarrierOutcomeResult{Applied: true, Terminal: terminal, Completion: s.Price.Completion, Remaining: remaining}, nil
}

// Redrive funds the same leg of an admitted effect again, at the retained
// entries, from available gas units of the operation that redrives it: the
// retained source work and one leg. Only a leg without an outcome can be
// redriven; the carrier it funds is the same leg of the same effect and can
// produce only that leg's one outcome. Which native operation may redrive, and
// who pays for it, is its caller's contract (Part A AR-13).
func (f *CarrierFunding) Redrive(class string, effect []byte, leg uint32, available uint64) (*CarrierReservation, error) {
	account, key, binding, raw, err := f.load(class, effect)
	if err != nil {
		return nil, err
	}
	s, err := f.decode(class, binding, raw)
	if err != nil {
		return nil, err
	}
	if leg >= s.Legs || s.HasOutcome(leg) {
		return nil, ErrCarrierFunding
	}
	legGas, total, remaining, err := carrierReserve(available, s.Price.Source, 1, s.Price)
	if err != nil {
		return nil, err
	}
	if s.Redrives, err = core.SafeAddUint64(s.Redrives, 1); err != nil {
		return nil, ErrCarrierFunding
	}
	if err = f.save(account, key, binding, s); err != nil {
		return nil, err
	}
	return &CarrierReservation{Identity: bytes.Clone(s.Identity), Price: s.Price, Legs: 1,
		LegGas: legGas, Total: total, Remaining: remaining}, nil
}

// CarrierDestinationGas is the destination's side of the partition (AM-004):
// of the gas a leg's carrier provided, the destination effect may use at most
// workLimit, the destination work the carrier was priced with. The rest is the
// outcome and completion reserve and is returned whole. A carrier that
// provides less than its work limit, or work above the limit, is refused.
func CarrierDestinationGas(provided, workLimit, used uint64) (remaining uint64, err error) {
	if _, err = core.SafeSubUint64(provided, workLimit); err != nil {
		return 0, ErrCarrierUnderfunded
	}
	if _, err = core.SafeSubUint64(workLimit, used); err != nil {
		return 0, ErrCarrierUnderfunded
	}
	return provided - used, nil
}
