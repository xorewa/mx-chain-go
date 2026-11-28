package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-79 (tracker line 72; Part A 4.7.4, E.18; F.2 AM-002/004/005): retained
// pricing, isolated outcome and completion resources, insufficiency before
// debit, phase-consistent persistence, return, replay and funded redrive.
// Every expectation below is written from the clause, not read from the code.

// sp279Schedule builds a native gas schedule map with the carrier section.
func sp279Schedule(classes map[string]CarrierPrice) map[string]map[string]uint64 {
	section := map[string]uint64{}
	for class, price := range classes {
		section[class+"Source"], section[class+"Destination"] = price.Source, price.Destination
		section[class+"Success"], section[class+"Refund"] = price.Success, price.Refund
		section[class+"Completion"] = price.Completion
	}
	return map[string]map[string]uint64{CarrierCostSection: section, "BaseOpsAPICost": {"AsyncCallStep": 1}}
}

// sp279Notifier is a gas schedule notifier that keeps its subscribers, as the
// native one does (common/forking/gasSchedule.go).
type sp279Notifier struct {
	schedule map[string]map[string]uint64
	handlers []core.GasScheduleSubscribeHandler
}

func (n *sp279Notifier) IsInterfaceNil() bool                            { return n == nil }
func (n *sp279Notifier) UnRegisterAll()                                  { n.handlers = nil }
func (n *sp279Notifier) LatestGasSchedule() map[string]map[string]uint64 { return n.schedule }
func (n *sp279Notifier) RegisterNotifyHandler(h core.GasScheduleSubscribeHandler) {
	n.handlers = append(n.handlers, h)
	h.GasScheduleChange(n.schedule)
}
func (n *sp279Notifier) change(schedule map[string]map[string]uint64) {
	n.schedule = schedule
	for _, h := range n.handlers {
		h.GasScheduleChange(schedule)
	}
}

type sp279World struct {
	t        *testing.T
	store    *qualNativeStore
	hasher   hashing.Hasher
	block    *sp223Block
	notifier *sp279Notifier
	limits   RegistrationResourceLimits
	prices   *GasScheduleCarrierPricing
	funding  *CarrierFunding
}

// The prices of the tests. They are test inputs, not proposed values.
var (
	sp279Old = CarrierPrice{Source: 1000, Destination: 300, Success: 70, Refund: 90, Completion: 200}
	sp279New = CarrierPrice{Source: 5000, Destination: 900, Success: 500, Refund: 100, Completion: 800}
)

// sp279Leg is the clause's leg: destination work, exactly one of the two
// outcomes (so the larger), and completion.
func sp279Leg(p CarrierPrice) uint64 {
	outcome := p.Success
	if p.Refund > outcome {
		outcome = p.Refund
	}
	return p.Destination + outcome + p.Completion
}

func sp279Total(p CarrierPrice, legs uint32) uint64 { return p.Source + uint64(legs)*sp279Leg(p) }

func sp279World_(t *testing.T, limits RegistrationResourceLimits, classes map[string]CarrierPrice) *sp279World {
	t.Helper()
	w := &sp279World{t: t, store: qualRegistrationStore(t, 0), hasher: blake2b.NewBlake2b(),
		block: &sp223Block{epoch: 10, hash: []byte("block"), header: []byte("header")}, limits: limits,
		notifier: &sp279Notifier{schedule: sp279Schedule(classes)}}
	t.Cleanup(func() { _ = w.store.Close() })
	budget := binary.BigEndian.AppendUint64(nil, 1)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(sp223BudgetKey)+32))
	budget = binary.BigEndian.AppendUint64(budget, 10)
	budget = binary.BigEndian.AppendUint64(budget, 0)
	qualRecordPut(t, w.store, []byte(sp223BudgetKey), budget)
	_, err := w.store.Commit()
	require.NoError(t, err)
	w.prices, err = NewGasScheduleCarrierPricing(w.notifier)
	require.NoError(t, err)
	w.build()
	return w
}

func sp279Default(t *testing.T) *sp279World {
	return sp279World_(t, sp223Ample(), map[string]CarrierPrice{"A": sp279Old, "B": sp279Old})
}

// build constructs the owner from the store and the configured inputs only.
func (w *sp279World) build() {
	var err error
	w.funding, err = NewCarrierFunding(ArgsCarrierFunding{Accounts: w.store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: w.hasher, Block: w.block, Prices: w.prices, Limits: w.limits, RecordBytes: 4096})
	require.NoError(w.t, err)
}

// restart commits, reopens the store at the committed root and rebuilds the
// owner: nothing survives but the state.
func (w *sp279World) restart() {
	root, err := w.store.Commit()
	require.NoError(w.t, err)
	require.NoError(w.t, w.store.RecreateTrie(holders.NewDefaultRootHashesHolder(root)))
	require.Zero(w.t, w.store.JournalLen())
	w.build()
}

func (w *sp279World) root() []byte {
	root, err := w.store.RootHash()
	require.NoError(w.t, err)
	return bytes.Clone(root)
}

// unchanged runs an operation that must be refused and must write nothing.
func (w *sp279World) unchanged(label string, expected error, run func() error) {
	w.t.Helper()
	root, journal := w.root(), w.store.JournalLen()
	err := run()
	require.Error(w.t, err, label)
	if expected != nil {
		require.ErrorIs(w.t, err, expected, label)
	}
	require.Equal(w.t, journal, w.store.JournalLen(), label+": journal")
	require.Equal(w.t, root, w.root(), label+": state")
}

func (w *sp279World) state(class, effect string) *CarrierFundingState {
	w.t.Helper()
	s, err := w.funding.Read(class, []byte(effect))
	require.NoError(w.t, err)
	return s
}

func TestQualSP279SufficientFundingGivesEachLegOneOutcome(t *testing.T) {
	w := sp279Default(t)
	const legs = uint32(3)
	total := sp279Total(sp279Old, legs)
	require.Equal(t, uint64(1000+3*(300+90+200)), total, "the test's own arithmetic")
	require.Nil(t, w.state("A", "effect"), "before the source commits there is no record")

	r, err := w.funding.Accept("A", []byte("effect"), legs, total+17)
	require.NoError(t, err)
	require.Equal(t, sp279Old, r.Price)
	require.Equal(t, legs, r.Legs)
	require.Equal(t, sp279Leg(sp279Old), r.LegGas)
	require.Equal(t, total, r.Total)
	require.Equal(t, uint64(17), r.Remaining, "nothing but the partition is taken")
	require.Equal(t, r.Total, r.Price.Source+uint64(r.Legs)*r.LegGas, "source and legs account for the whole total")

	s := w.state("A", "effect")
	require.Equal(t, CarrierOpen, s.Phase, "source committed, no outcome yet")
	require.Equal(t, r.Identity, s.Identity)
	require.Equal(t, sp279Old, s.Price)
	require.Zero(t, s.Redrives)

	// Each leg's carrier returns with the outcome and completion part of its gas.
	for leg := uint32(0); leg < legs; leg++ {
		provided := sp279Old.Completion + uint64(leg)
		result, outcomeErr := w.funding.Outcome("A", []byte("effect"), leg, provided)
		require.NoError(t, outcomeErr)
		require.True(t, result.Applied)
		require.Equal(t, sp279Old.Completion, result.Completion, "consumed as retained")
		require.Equal(t, uint64(leg), result.Remaining)
		require.Equal(t, leg == legs-1, result.Terminal)
		s = w.state("A", "effect")
		for other := uint32(0); other < legs; other++ {
			require.Equal(t, other <= leg, s.HasOutcome(other))
		}
		if leg < legs-1 {
			require.Equal(t, CarrierOutcome, s.Phase)
		}
	}
	require.Equal(t, CarrierTerminal, w.state("A", "effect").Phase)
	require.False(t, w.state("A", "effect").HasOutcome(legs), "a leg the effect does not have")

	// The largest effect: each of its 255 legs has its own outcome, and the
	// effect is terminal only after the last of them, in any order.
	_, err = w.funding.Accept("A", []byte("wide"), 255, sp279Total(sp279Old, 255))
	require.NoError(t, err)
	for i := uint32(0); i < 255; i++ {
		leg := (i*97 + 200) % 255
		require.False(t, w.state("A", "wide").HasOutcome(leg))
		result, outcomeErr := w.funding.Outcome("A", []byte("wide"), leg, sp279Old.Completion)
		require.NoError(t, outcomeErr)
		require.True(t, result.Applied)
		require.Equal(t, i == 254, result.Terminal)
		wide := w.state("A", "wide")
		require.True(t, wide.HasOutcome(leg))
		if i == 0 {
			for other := uint32(0); other < 255; other++ {
				require.Equal(t, other == leg, wide.HasOutcome(other), "only the leg that returned")
			}
		}
	}
	var none *CarrierFundingState
	require.False(t, none.HasOutcome(0))
	require.False(t, w.state("A", "wide").HasOutcome(255), "beyond the last leg an effect can have")
	require.False(t, w.state("A", "wide").HasOutcome(256))
	require.False(t, w.state("A", "wide").HasOutcome(^uint32(0)))
	require.False(t, (&CarrierFundingState{}).HasOutcome(0))
}

func TestQualSP279InsufficiencyIsRefusedBeforeAnyWrite(t *testing.T) {
	w := sp279Default(t)
	total := sp279Total(sp279Old, 3)
	accept := func(class, effect string, legs uint32, available uint64) func() error {
		return func() error {
			_, err := w.funding.Accept(class, []byte(effect), legs, available)
			return err
		}
	}
	// The boundary: one unit short is refused, the exact amount is admitted.
	w.unchanged("one unit short", ErrCarrierUnderfunded, accept("A", "e", 3, total-1))
	w.unchanged("no gas", ErrCarrierUnderfunded, accept("A", "e", 3, 0))
	w.unchanged("source work only", ErrCarrierUnderfunded, accept("A", "e", 3, sp279Old.Source))
	w.unchanged("two of three legs", ErrCarrierUnderfunded, accept("A", "e", 3, total-sp279Leg(sp279Old)))
	require.Nil(t, w.state("A", "e"), "a refused admission leaves no record")
	r, err := w.funding.Accept("A", []byte("e"), 3, total)
	require.NoError(t, err)
	require.Zero(t, r.Remaining)

	// Malformed requests and missing prices.
	w.unchanged("no legs", ErrCarrierFunding, accept("A", "f", 0, total))
	w.unchanged("too many legs", ErrCarrierFunding, accept("A", "f", 256, ^uint64(0)))
	w.unchanged("no class", ErrCarrierFunding, accept("", "f", 3, total))
	w.unchanged("no effect", ErrCarrierFunding, accept("A", "", 3, total))
	w.unchanged("unpriced class", ErrCarrierFunding, accept("C", "f", 3, ^uint64(0)))
	w.unchanged("effect larger than a record", ErrCarrierFunding, accept("A", string(make([]byte, 5000)), 3, total))
	_, err = w.funding.Accept("A", []byte("f"), 255, ^uint64(0))
	require.NoError(t, err, "255 legs is the most an effect can have")

	// Overflowing partitions are refused, not wrapped.
	huge := ^uint64(0)
	for label, price := range map[string]CarrierPrice{
		"leg overflow":     {Destination: huge, Completion: 1},
		"outcome overflow": {Destination: 1, Refund: huge},
		"legs overflow":    {Destination: huge / 2, Completion: 2},
		"source overflow":  {Source: huge, Completion: 1},
		"free":             {},
	} {
		w.notifier.change(sp279Schedule(map[string]CarrierPrice{"A": price}))
		w.unchanged(label, ErrCarrierFunding, accept("A", "g", 2, huge))
	}

	// A price whose entries are not all present is no price.
	schedule := sp279Schedule(map[string]CarrierPrice{"A": sp279Old})
	for _, field := range carrierPriceFields {
		partial := sp279Schedule(map[string]CarrierPrice{"A": sp279Old})
		delete(partial[CarrierCostSection], "A"+field)
		w.notifier.change(partial)
		w.unchanged("missing "+field, ErrCarrierFunding, accept("A", "g", 2, huge))
	}
	w.notifier.change(map[string]map[string]uint64{"BaseOpsAPICost": {"AsyncCallStep": 1}})
	w.unchanged("schedule without the section", ErrCarrierFunding, accept("A", "g", 2, huge))
	w.notifier.change(schedule)
	_, err = w.funding.Accept("A", []byte("g"), 2, huge)
	require.NoError(t, err)
}

func TestQualSP279RetainedBudgetBoundsFundingRecords(t *testing.T) {
	// The record is retained state: it is charged to the chain-global budget
	// of SP2-29 before it exists, and an update of it is charged nothing.
	limits := RegistrationResourceLimits{Records: 3, RetainedBytes: 1 << 20, NewRecordsPerEpoch: 2}
	w := sp279World_(t, limits, map[string]CarrierPrice{"A": sp279Old})
	total := sp279Total(sp279Old, 1)
	accept := func(effect string) error {
		_, err := w.funding.Accept("A", []byte(effect), 1, total)
		return err
	}
	usage := func() (count, size uint64) {
		raw := qualRegistryValue(t, w.store, sp223BudgetKey)
		return binary.BigEndian.Uint64(raw), binary.BigEndian.Uint64(raw[8:])
	}
	count, size := usage()
	require.NoError(t, accept("one"))
	count1, size1 := usage()
	require.Equal(t, count+1, count1)
	require.Greater(t, size1, size)
	_, err := w.funding.Outcome("A", []byte("one"), 0, sp279Old.Completion)
	require.NoError(t, err)
	count2, size2 := usage()
	require.Equal(t, count1, count2, "an outcome adds no record")
	require.Equal(t, size1, size2, "and no bytes")
	require.NoError(t, accept("two"))
	w.unchanged("third record of the epoch and of the budget", nil, func() error { return accept("three") })
	w.block.epoch++
	w.unchanged("record limit", nil, func() error { return accept("three") })

	for label, zero := range map[string]RegistrationResourceLimits{
		"records": {RetainedBytes: 1, NewRecordsPerEpoch: 1}, "bytes": {Records: 1, NewRecordsPerEpoch: 1}, "rate": {Records: 1, RetainedBytes: 1}} {
		_, err = NewCarrierFunding(ArgsCarrierFunding{Accounts: w.store, Marshaller: &marshal.GogoProtoMarshalizer{},
			Hasher: w.hasher, Block: w.block, Prices: w.prices, Limits: zero, RecordBytes: 4096})
		require.ErrorIs(t, err, ErrCarrierFunding, label)
	}
	args := ArgsCarrierFunding{Accounts: w.store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: w.hasher,
		Block: w.block, Prices: w.prices, Limits: sp223Ample(), RecordBytes: 4096}
	for label, change := range map[string]func(*ArgsCarrierFunding){
		"block": func(a *ArgsCarrierFunding) { a.Block = nil }, "prices": func(a *ArgsCarrierFunding) { a.Prices = nil },
		"accounts": func(a *ArgsCarrierFunding) { a.Accounts = nil }, "hasher": func(a *ArgsCarrierFunding) { a.Hasher = nil },
		"marshaller": func(a *ArgsCarrierFunding) { a.Marshaller = nil }, "record bytes": func(a *ArgsCarrierFunding) { a.RecordBytes = 0 }} {
		changed := args
		change(&changed)
		_, err = NewCarrierFunding(changed)
		require.Error(t, err, label)
	}
	var none *CarrierFunding
	require.True(t, none.IsInterfaceNil())
	require.False(t, w.funding.IsInterfaceNil())
}

func TestQualSP279ScheduleChangeDoesNotRepriceAnAcceptedEffect(t *testing.T) {
	w := sp279Default(t)
	accepted, err := w.funding.Accept("A", []byte("old"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)

	// A successor schedule with higher entries becomes active.
	w.notifier.change(sp279Schedule(map[string]CarrierPrice{"A": sp279New}))
	w.restart()
	fresh, err := w.funding.Accept("A", []byte("new"), 2, sp279Total(sp279New, 2))
	require.NoError(t, err)
	require.Equal(t, sp279New, fresh.Price, "new admissions pay the new schedule")
	require.NotEqual(t, accepted.Identity, fresh.Identity)
	w.unchanged("a new admission at the old amount", ErrCarrierUnderfunded, func() error {
		_, acceptErr := w.funding.Accept("A", []byte("newer"), 2, sp279Total(sp279Old, 2))
		return acceptErr
	})

	// The accepted effect completes at its retained entries: the old
	// completion work is enough for it and is what it is charged.
	result, err := w.funding.Outcome("A", []byte("old"), 0, sp279Old.Completion)
	require.NoError(t, err)
	require.True(t, result.Applied)
	require.Equal(t, sp279Old.Completion, result.Completion)
	require.Zero(t, result.Remaining)
	s := w.state("A", "old")
	require.Equal(t, accepted.Identity, s.Identity)
	require.Equal(t, sp279Old, s.Price)
	// The effect admitted under the new schedule is not served at old entries.
	w.unchanged("new effect at old completion", ErrCarrierUnderfunded, func() error {
		_, outcomeErr := w.funding.Outcome("A", []byte("new"), 0, sp279Old.Completion)
		return outcomeErr
	})

	// A redrive of the old effect is priced at its retained entries too.
	redrive, err := w.funding.Redrive("A", []byte("old"), 1, sp279Old.Source+sp279Leg(sp279Old))
	require.NoError(t, err)
	require.Equal(t, sp279Leg(sp279Old), redrive.LegGas)
	require.Equal(t, accepted.Identity, redrive.Identity)
	require.Zero(t, redrive.Remaining)

	// A later schedule that no longer prices the class: the open effect still
	// completes, a new admission is refused.
	w.notifier.change(map[string]map[string]uint64{})
	w.restart()
	result, err = w.funding.Outcome("A", []byte("old"), 1, sp279Old.Completion)
	require.NoError(t, err)
	require.True(t, result.Terminal)
	w.unchanged("no price", ErrCarrierFunding, func() error {
		_, acceptErr := w.funding.Accept("A", []byte("newest"), 2, ^uint64(0))
		return acceptErr
	})

	// Lower entries later do not release the retained ones either.
	cheap := CarrierPrice{Source: 1, Destination: 1, Success: 1, Refund: 1, Completion: 1}
	w.notifier.change(sp279Schedule(map[string]CarrierPrice{"A": cheap}))
	w.unchanged("new effect below its retained completion", ErrCarrierUnderfunded, func() error {
		_, outcomeErr := w.funding.Outcome("A", []byte("new"), 0, sp279New.Completion-1)
		return outcomeErr
	})
}

func TestQualSP279OneEffectCannotUseAnotherEffectsResources(t *testing.T) {
	w := sp279Default(t)
	// Two effects are admitted from one operation's gas: the second sees only
	// what the first left.
	available := sp279Total(sp279Old, 2) + sp279Total(sp279Old, 2) - 1
	first, err := w.funding.Accept("A", []byte("one"), 2, available)
	require.NoError(t, err)
	w.unchanged("the second effect is one unit short", ErrCarrierUnderfunded, func() error {
		_, acceptErr := w.funding.Accept("A", []byte("two"), 2, first.Remaining)
		return acceptErr
	})
	_, err = w.funding.Accept("A", []byte("two"), 2, first.Remaining+1)
	require.NoError(t, err)
	// The same effect identifier under another class is another effect.
	_, err = w.funding.Accept("B", []byte("one"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)

	raw := func(class, effect string) []byte {
		binding, bindErr := w.funding.binding(class, []byte(effect))
		require.NoError(t, bindErr)
		return qualRegistryValue(t, w.store, carrierFundingPrefix+string(binding))
	}
	two, other := raw("A", "two"), raw("B", "one")

	// A carrier of effect one that returns with too little gas is refused; the
	// ample gas of nothing else serves it, and its leg stays open.
	w.unchanged("underfunded outcome", ErrCarrierUnderfunded, func() error {
		_, outcomeErr := w.funding.Outcome("A", []byte("one"), 0, sp279Old.Completion-1)
		return outcomeErr
	})
	require.Equal(t, CarrierOpen, w.state("A", "one").Phase)
	// An outcome of effect one changes only effect one.
	_, err = w.funding.Outcome("A", []byte("one"), 0, sp279Old.Completion)
	require.NoError(t, err)
	_, err = w.funding.Outcome("A", []byte("one"), 1, sp279Old.Completion)
	require.NoError(t, err)
	require.Equal(t, two, raw("A", "two"))
	require.Equal(t, other, raw("B", "one"))
	require.Equal(t, CarrierOpen, w.state("A", "two").Phase)
	require.Equal(t, CarrierOpen, w.state("B", "one").Phase)

	// The destination side of the partition: the destination effect may use
	// its work limit and no more; the reserve comes back whole.
	leg := sp279Leg(sp279Old)
	remaining, err := CarrierDestinationGas(leg, sp279Old.Destination, sp279Old.Destination)
	require.NoError(t, err)
	require.Equal(t, leg-sp279Old.Destination, remaining, "the whole outcome and completion reserve")
	remaining, err = CarrierDestinationGas(leg, sp279Old.Destination, 0)
	require.NoError(t, err)
	require.Equal(t, leg, remaining)
	_, err = CarrierDestinationGas(leg, sp279Old.Destination, sp279Old.Destination+1)
	require.ErrorIs(t, err, ErrCarrierUnderfunded, "destination work cannot reach into the reserve")
	_, err = CarrierDestinationGas(sp279Old.Destination-1, sp279Old.Destination, 0)
	require.ErrorIs(t, err, ErrCarrierUnderfunded, "a carrier with less than its work limit")
	remaining, err = CarrierDestinationGas(sp279Old.Destination, sp279Old.Destination, sp279Old.Destination)
	require.NoError(t, err)
	require.Zero(t, remaining)
}

func TestQualSP279ReturnReplayAndDuplicateGiveOneOutcome(t *testing.T) {
	w := sp279Default(t)
	_, err := w.funding.Accept("A", []byte("e"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)
	outcome := func(effect string, leg uint32, provided uint64) func() error {
		return func() error {
			_, outcomeErr := w.funding.Outcome("A", []byte(effect), leg, provided)
			return outcomeErr
		}
	}
	// What was never admitted has no outcome.
	w.unchanged("unknown effect", ErrCarrierFunding, outcome("never", 0, ^uint64(0)))
	w.unchanged("leg the effect does not have", ErrCarrierFunding, outcome("e", 2, ^uint64(0)))
	w.unchanged("no class", ErrCarrierFunding, func() error {
		_, outcomeErr := w.funding.Outcome("", []byte("e"), 0, ^uint64(0))
		return outcomeErr
	})
	_, err = w.funding.Read("", []byte("e"))
	require.ErrorIs(t, err, ErrCarrierFunding, "an effect of no class cannot be read as absent")
	_, err = w.funding.Read("A", nil)
	require.ErrorIs(t, err, ErrCarrierFunding)

	duplicate := func(leg uint32, terminal bool) {
		t.Helper()
		root, journal := w.root(), w.store.JournalLen()
		result, outcomeErr := w.funding.Outcome("A", []byte("e"), leg, 12345)
		require.NoError(t, outcomeErr)
		require.Equal(t, CarrierOutcomeResult{Terminal: terminal, Remaining: 12345}, result, "not applied, not charged")
		require.Equal(t, journal, w.store.JournalLen())
		require.Equal(t, root, w.root())
	}
	first, err := w.funding.Outcome("A", []byte("e"), 1, sp279Old.Completion)
	require.NoError(t, err)
	require.True(t, first.Applied)
	duplicate(1, false)
	w.restart()
	duplicate(1, false)
	// The source cannot be admitted again while it is open.
	w.unchanged("second admission of an open effect", ErrCarrierFunding, func() error {
		_, acceptErr := w.funding.Accept("A", []byte("e"), 2, ^uint64(0))
		return acceptErr
	})

	last, err := w.funding.Outcome("A", []byte("e"), 0, sp279Old.Completion)
	require.NoError(t, err)
	require.True(t, last.Terminal)
	for range 2 {
		// The replay barrier outlives the terminal phase and a restart.
		duplicate(0, true)
		duplicate(1, true)
		w.unchanged("admission after the terminal phase", ErrCarrierFunding, func() error {
			_, acceptErr := w.funding.Accept("A", []byte("e"), 2, ^uint64(0))
			return acceptErr
		})
		w.unchanged("redrive after the terminal phase", ErrCarrierFunding, func() error {
			_, redriveErr := w.funding.Redrive("A", []byte("e"), 0, ^uint64(0))
			return redriveErr
		})
		require.Equal(t, CarrierTerminal, w.state("A", "e").Phase)
		w.block.epoch += 100
		w.restart()
	}
}

func TestQualSP279RedriveFundsTheSameLegOnce(t *testing.T) {
	w := sp279Default(t)
	accepted, err := w.funding.Accept("A", []byte("e"), 3, sp279Total(sp279Old, 3))
	require.NoError(t, err)
	_, err = w.funding.Outcome("A", []byte("e"), 0, sp279Old.Completion)
	require.NoError(t, err)
	cost := sp279Old.Source + sp279Leg(sp279Old)
	redrive := func(effect string, leg uint32, available uint64) func() error {
		return func() error {
			_, redriveErr := w.funding.Redrive("A", []byte(effect), leg, available)
			return redriveErr
		}
	}
	w.unchanged("a leg that has its outcome", ErrCarrierFunding, redrive("e", 0, ^uint64(0)))
	w.unchanged("a leg the effect does not have", ErrCarrierFunding, redrive("e", 3, ^uint64(0)))
	w.unchanged("an effect that was never admitted", ErrCarrierFunding, redrive("never", 1, ^uint64(0)))
	w.unchanged("one unit short", ErrCarrierUnderfunded, redrive("e", 1, cost-1))
	w.unchanged("no gas", ErrCarrierUnderfunded, redrive("e", 1, 0))

	// After a restart and a delay of many epochs the leg is still open and is
	// funded at what the effect retained; no timer released it.
	w.block.epoch += 1000
	w.restart()
	require.Equal(t, CarrierOutcome, w.state("A", "e").Phase)
	r, err := w.funding.Redrive("A", []byte("e"), 1, cost+5)
	require.NoError(t, err)
	require.Equal(t, CarrierReservation{Identity: accepted.Identity, Price: sp279Old, Legs: 1,
		LegGas: sp279Leg(sp279Old), Total: cost, Remaining: 5}, *r)
	s := w.state("A", "e")
	require.Equal(t, uint64(1), s.Redrives)
	require.False(t, s.HasOutcome(1), "a redrive is not an outcome")
	require.Equal(t, CarrierOutcome, s.Phase)
	// A second redrive of the same leg is paid again and is still one leg.
	_, err = w.funding.Redrive("A", []byte("e"), 1, cost)
	require.NoError(t, err)
	require.Equal(t, uint64(2), w.state("A", "e").Redrives)

	// Both deliveries of leg 1 return: one outcome.
	result, err := w.funding.Outcome("A", []byte("e"), 1, sp279Old.Completion)
	require.NoError(t, err)
	require.True(t, result.Applied)
	result, err = w.funding.Outcome("A", []byte("e"), 1, sp279Old.Completion)
	require.NoError(t, err)
	require.False(t, result.Applied, "the redriven delivery of an applied leg")
	w.unchanged("redrive of the applied leg", ErrCarrierFunding, redrive("e", 1, ^uint64(0)))
	result, err = w.funding.Outcome("A", []byte("e"), 2, sp279Old.Completion)
	require.NoError(t, err)
	require.True(t, result.Terminal)
	require.Equal(t, uint64(2), w.state("A", "e").Redrives)
}

func TestQualSP279MissingOrCorruptRecordFailsClosed(t *testing.T) {
	w := sp279Default(t)
	_, err := w.funding.Accept("A", []byte("e"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)
	_, err = w.funding.Outcome("A", []byte("e"), 0, sp279Old.Completion)
	require.NoError(t, err)
	_, err = w.funding.Accept("A", []byte("other"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)
	binding, err := w.funding.binding("A", []byte("e"))
	require.NoError(t, err)
	otherBinding, err := w.funding.binding("A", []byte("other"))
	require.NoError(t, err)
	key := []byte(carrierFundingPrefix + string(binding))
	good := qualRegistryValue(t, w.store, string(key))
	other := qualRegistryValue(t, w.store, carrierFundingPrefix+string(otherBinding))
	fields, err := w.funding.codec.unframe(good, 8)
	require.NoError(t, err)
	with := func(index int, value []byte) []byte {
		changed := make([][]byte, len(fields))
		copy(changed, fields)
		changed[index] = value
		return qualRecordFrame(changed...)
	}
	bit := func(n int) []byte {
		bitmap := bytes.Clone(fields[6])
		bitmap[n/8] |= 1 << (n % 8)
		return bitmap
	}
	corrupt := map[string][]byte{
		"truncated":                 good[:len(good)-1],
		"extended":                  append(bytes.Clone(good), 0),
		"another effect's record":   other,
		"another tag":               with(0, []byte("DRWA/CARRIER_FUNDING/candidate2")),
		"short identity":            with(2, fields[2][:31]),
		"identity of other entries": with(2, w.funding.priceIdentity("A", sp279New)),
		"identity of another class": with(2, w.funding.priceIdentity("B", sp279Old)),
		"entries its identity does not name": with(3, func() []byte {
			prices := bytes.Clone(fields[3])
			prices[39]--
			return prices
		}()),
		"short prices":               with(3, fields[3][:39]),
		"no legs":                    with(4, []byte{0, 0, 0, 0}),
		"too many legs":              with(4, []byte{0, 0, 1, 0}),
		"short legs":                 with(4, []byte{0, 2}),
		"phase open with an outcome": with(5, []byte{CarrierOpen}),
		"phase terminal too early":   with(5, []byte{CarrierTerminal}),
		"unknown phase":              with(5, []byte{9}),
		"no phase":                   with(5, nil),
		"outcome of a leg it lacks":  with(6, bit(2)),
		"highest bit":                with(6, bit(255)),
		"short bitmap":               with(6, fields[6][:31]),
		"short redrives":             with(7, fields[7][:7]),
		"seven fields":               qualRecordFrame(fields[:7]...),
	}
	for label, value := range corrupt {
		qualRecordPut(t, w.store, key, value)
		_, err = w.store.Commit()
		require.NoError(t, err)
		w.unchanged(label+": read", ErrCarrierFunding, func() error {
			_, readErr := w.funding.Read("A", []byte("e"))
			return readErr
		})
		w.unchanged(label+": outcome", ErrCarrierFunding, func() error {
			_, outcomeErr := w.funding.Outcome("A", []byte("e"), 1, ^uint64(0))
			return outcomeErr
		})
		w.unchanged(label+": redrive", ErrCarrierFunding, func() error {
			_, redriveErr := w.funding.Redrive("A", []byte("e"), 1, ^uint64(0))
			return redriveErr
		})
		w.unchanged(label+": admission", ErrCarrierFunding, func() error {
			_, acceptErr := w.funding.Accept("A", []byte("e"), 2, ^uint64(0))
			return acceptErr
		})
	}
	// Corruptions whose phase agrees with their outcomes, so that only the
	// leg checks can refuse them.
	otherKey := []byte(carrierFundingPrefix + string(otherBinding))
	open, err := w.funding.codec.unframe(other, 8)
	require.NoError(t, err)
	consistent := func(legs uint32, phase uint8, bits ...int) []byte {
		changed := make([][]byte, len(open))
		copy(changed, open)
		bitmap := make([]byte, 32)
		for _, n := range bits {
			bitmap[n/8] |= 1 << (n % 8)
		}
		changed[4], changed[5], changed[6] = binary.BigEndian.AppendUint32(nil, legs), []byte{phase}, bitmap
		return qualRecordFrame(changed...)
	}
	for label, value := range map[string][]byte{
		"no legs, open":                       consistent(0, CarrierOpen),
		"256 legs, open":                      consistent(256, CarrierOpen),
		"two outcomes, one of a leg it lacks": consistent(2, CarrierTerminal, 0, 2),
		"one outcome of a leg it lacks":       consistent(2, CarrierOutcome, 5),
		"three legs' outcomes for two legs":   consistent(2, CarrierTerminal, 0, 1, 2),
	} {
		qualRecordPut(t, w.store, otherKey, value)
		_, err = w.store.Commit()
		require.NoError(t, err)
		w.unchanged(label+": read", ErrCarrierFunding, func() error {
			_, readErr := w.funding.Read("A", []byte("other"))
			return readErr
		})
		w.unchanged(label+": outcome", ErrCarrierFunding, func() error {
			_, outcomeErr := w.funding.Outcome("A", []byte("other"), 1, ^uint64(0))
			return outcomeErr
		})
	}
	// A consistent record of the same size is accepted: the checks above are
	// what refused the others.
	qualRecordPut(t, w.store, otherKey, consistent(2, CarrierOutcome, 1))
	require.True(t, w.state("A", "other").HasOutcome(1))
	qualRecordPut(t, w.store, otherKey, other)

	// Restored exactly, the effect continues where it was.
	qualRecordPut(t, w.store, key, good)
	result, err := w.funding.Outcome("A", []byte("e"), 1, sp279Old.Completion)
	require.NoError(t, err)
	require.True(t, result.Terminal)

	// The redrive counter cannot wrap.
	fields, err = w.funding.codec.unframe(other, 8)
	require.NoError(t, err)
	qualRecordPut(t, w.store, []byte(carrierFundingPrefix+string(otherBinding)), with(7, bytes.Repeat([]byte{0xff}, 8)))
	w.unchanged("redrive counter at its maximum", ErrCarrierFunding, func() error {
		_, redriveErr := w.funding.Redrive("A", []byte("other"), 0, ^uint64(0))
		return redriveErr
	})
}

// sp279FailingAccounts fails the read of every existing account.
type sp279FailingAccounts struct {
	state.AccountsAdapter
	fail error
}

func (f *sp279FailingAccounts) GetExistingAccount([]byte) (vmcommon.AccountHandler, error) {
	return nil, f.fail
}

type sp279PriceStub struct {
	price CarrierPrice
	err   error
}

func (p *sp279PriceStub) IsInterfaceNil() bool { return p == nil }
func (p *sp279PriceStub) CarrierPrice(string) (CarrierPrice, error) {
	return p.price, p.err
}

func TestQualSP279NativeFailuresRefuseTheOperation(t *testing.T) {
	w := sp279Default(t)
	_, err := w.funding.Accept("A", []byte("e"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)
	all := func(label string, expected error) {
		t.Helper()
		w.unchanged(label+": admission", expected, func() error {
			_, e := w.funding.Accept("A", []byte("f"), 2, ^uint64(0))
			return e
		})
		w.unchanged(label+": outcome", expected, func() error {
			_, e := w.funding.Outcome("A", []byte("e"), 0, ^uint64(0))
			return e
		})
		w.unchanged(label+": redrive", expected, func() error {
			_, e := w.funding.Redrive("A", []byte("e"), 0, ^uint64(0))
			return e
		})
	}
	// No block in execution: no epoch to charge the record in.
	hash := w.block.hash
	w.block.hash = nil
	all("no executing block", ErrFinalityImport)
	w.block.hash = hash

	// The price source fails.
	failing := errors.New("price source failure")
	w.funding.args.Prices = &sp279PriceStub{err: failing}
	w.unchanged("price source error", failing, func() error {
		_, e := w.funding.Accept("A", []byte("f"), 2, ^uint64(0))
		return e
	})
	w.funding.args.Prices = w.prices

	// The budget record is missing: nothing is retained outside the budget.
	qualRecordPut(t, w.store, []byte(sp223BudgetKey), nil)
	_, err = w.store.Commit()
	require.NoError(t, err)
	all("no budget record", errScopedAdmission)
}

func TestQualSP279AccountReadFailureRefusesEveryOperation(t *testing.T) {
	w := sp279Default(t)
	_, err := w.funding.Accept("A", []byte("e"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)
	failing := errors.New("account read failure")
	w.store.AccountsAdapter = &sp279FailingAccounts{AccountsAdapter: w.store.AccountsAdapter, fail: failing}
	for label, run := range map[string]func() error{
		"admission": func() error { _, e := w.funding.Accept("A", []byte("f"), 2, ^uint64(0)); return e },
		"outcome":   func() error { _, e := w.funding.Outcome("A", []byte("e"), 0, ^uint64(0)); return e },
		"redrive":   func() error { _, e := w.funding.Redrive("A", []byte("e"), 0, ^uint64(0)); return e },
		"read":      func() error { _, e := w.funding.Read("A", []byte("e")); return e },
	} {
		require.ErrorIs(t, run(), failing, label)
	}
}

func TestQualSP279RecordReadFailureAndRecordLimit(t *testing.T) {
	w := sp279Default(t)
	_, err := w.funding.Accept("A", []byte("e"), 2, sp279Total(sp279Old, 2))
	require.NoError(t, err)
	binding, err := w.funding.binding("A", []byte("e"))
	require.NoError(t, err)
	// The read of the effect's own record fails: no operation proceeds on a
	// record it could not read, and none treats it as absent.
	failing := errors.New("record read failure")
	healthy := w.funding.codec.state.accounts
	w.funding.codec.state.accounts = &qualCurrentLocalReadStore{healthy, []byte(carrierFundingPrefix + string(binding)), failing}
	for label, run := range map[string]func() error{
		"admission": func() error { _, e := w.funding.Accept("A", []byte("e"), 2, ^uint64(0)); return e },
		"outcome":   func() error { _, e := w.funding.Outcome("A", []byte("e"), 0, ^uint64(0)); return e },
		"redrive":   func() error { _, e := w.funding.Redrive("A", []byte("e"), 0, ^uint64(0)); return e },
		"read":      func() error { _, e := w.funding.Read("A", []byte("e")); return e },
	} {
		w.unchanged(label, failing, run)
	}
	w.funding.codec.state.accounts = healthy

	// A record byte limit that holds the effect's identity but not its
	// record: the admission is refused before anything is written.
	small, err := NewCarrierFunding(ArgsCarrierFunding{Accounts: w.store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: w.hasher, Block: w.block, Prices: w.prices, Limits: w.limits, RecordBytes: 100})
	require.NoError(t, err)
	w.unchanged("record larger than the limit", ErrCarrierFunding, func() error {
		_, e := small.Accept("A", []byte("f"), 2, ^uint64(0))
		return e
	})
}

func TestQualSP279GasSchedulePricing(t *testing.T) {
	notifier := &sp279Notifier{schedule: sp279Schedule(map[string]CarrierPrice{"A": sp279Old, "AB": sp279New})}
	prices, err := NewGasScheduleCarrierPricing(notifier)
	require.NoError(t, err)
	require.Len(t, notifier.handlers, 1, "it follows schedule changes as a native subscriber")
	require.False(t, prices.IsInterfaceNil())
	var none *GasScheduleCarrierPricing
	require.True(t, none.IsInterfaceNil())
	_, err = NewGasScheduleCarrierPricing(nil)
	require.ErrorIs(t, err, ErrCarrierFunding)

	price, err := prices.CarrierPrice("A")
	require.NoError(t, err)
	require.Equal(t, sp279Old, price)
	price, err = prices.CarrierPrice("AB")
	require.NoError(t, err)
	require.Equal(t, sp279New, price)
	_, err = prices.CarrierPrice("")
	require.ErrorIs(t, err, ErrCarrierFunding)
	_, err = prices.CarrierPrice("C")
	require.ErrorIs(t, err, ErrCarrierFunding)
	// An entry that is present with value zero is a price; an absent one is not.
	notifier.change(sp279Schedule(map[string]CarrierPrice{"A": {Completion: 5}}))
	price, err = prices.CarrierPrice("A")
	require.NoError(t, err)
	require.Equal(t, CarrierPrice{Completion: 5}, price)
	_, err = prices.CarrierPrice("AB")
	require.ErrorIs(t, err, ErrCarrierFunding, "the entries of a replaced schedule are gone")

	// The pricing identity names exactly the class and its entries: it
	// changes with each of them, and is the same for the same entries
	// whichever schedule supplied them.
	w := sp279Default(t)
	identity := func(class string, p CarrierPrice) string {
		w.notifier.change(sp279Schedule(map[string]CarrierPrice{class: p}))
		r, acceptErr := w.funding.Accept(class, []byte{byte(len(w.notifier.handlers)), byte(w.block.epoch)}, 1, ^uint64(0))
		require.NoError(t, acceptErr)
		w.block.epoch++
		require.Len(t, r.Identity, w.hasher.Size())
		return string(r.Identity)
	}
	seen := map[string]string{identity("A", sp279Old): "A old"}
	for i := range carrierPriceFields {
		changed := sp279Old
		*[]*uint64{&changed.Source, &changed.Destination, &changed.Success, &changed.Refund, &changed.Completion}[i]++
		next := identity("A", changed)
		require.Empty(t, seen[next], carrierPriceFields[i])
		seen[next] = carrierPriceFields[i]
	}
	// Computed here from the definition: the tag, the class, the five entries
	// in their order, each as eight big-endian bytes.
	expected := []byte("DRWA/CARRIER_PRICE/candidate1" + "A")
	for _, entry := range []uint64{1000, 300, 70, 90, 200} {
		expected = binary.BigEndian.AppendUint64(expected, entry)
	}
	require.Equal(t, string(w.hasher.Compute(string(expected))), identity("A", sp279Old))
	require.Empty(t, seen[identity("B", sp279Old)], "the class is part of the identity")
	require.Equal(t, "A old", seen[identity("A", sp279Old)], "the same entries have the same identity")

	// Schedule changes and readers at once (run with -race).
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				prices.GasScheduleChange(sp279Schedule(map[string]CarrierPrice{"A": {Completion: uint64(j + 1)}}))
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				got, priceErr := prices.CarrierPrice("A")
				if priceErr != nil || got.Completion == 0 {
					t.Error("a reader saw a half-changed schedule")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// sp279Model is the clause as a model: an effect is absent, or holds its
// retained price and the set of legs with an outcome.
type sp279Model struct {
	price    CarrierPrice
	legs     uint32
	outcomes map[uint32]bool
	redrives uint64
}

func TestQualSP279SequencesAgainstIndependentModel(t *testing.T) {
	const sequences, steps = 40, 120
	applied, denied := 0, 0
	for seed := int64(1); seed <= sequences; seed++ {
		rng := rand.New(rand.NewSource(seed))
		active := sp279Old
		w := sp279World_(t, sp223Ample(), map[string]CarrierPrice{"A": active})
		model := map[string]*sp279Model{}
		for step := 0; step < steps; step++ {
			effect := string(rune('a' + rng.Intn(6)))
			m := model[effect]
			leg := uint32(rng.Intn(5))
			gas := uint64(rng.Intn(4000))
			switch rng.Intn(10) {
			case 0: // a successor schedule
				active = CarrierPrice{Source: uint64(rng.Intn(1500)), Destination: uint64(rng.Intn(400)),
					Success: uint64(rng.Intn(200)), Refund: uint64(rng.Intn(200)), Completion: uint64(1 + rng.Intn(400))}
				w.notifier.change(sp279Schedule(map[string]CarrierPrice{"A": active}))
			case 1:
				w.block.epoch += uint32(rng.Intn(3))
				w.restart()
			case 2, 3, 4: // admission
				legs := uint32(1 + rng.Intn(4))
				r, err := w.funding.Accept("A", []byte(effect), legs, gas)
				if m != nil || gas < sp279Total(active, legs) {
					require.Error(t, err, "seed %d step %d", seed, step)
					denied++
					continue
				}
				require.NoError(t, err, "seed %d step %d", seed, step)
				require.Equal(t, gas-sp279Total(active, legs), r.Remaining)
				model[effect] = &sp279Model{price: active, legs: legs, outcomes: map[uint32]bool{}}
				applied++
			case 5, 6, 7: // outcome
				result, err := w.funding.Outcome("A", []byte(effect), leg, gas)
				switch {
				case m == nil || leg >= m.legs:
					require.ErrorIs(t, err, ErrCarrierFunding, "seed %d step %d", seed, step)
					denied++
				case m.outcomes[leg]:
					require.NoError(t, err)
					require.False(t, result.Applied, "seed %d step %d", seed, step)
					require.Equal(t, gas, result.Remaining)
				case gas < m.price.Completion:
					require.ErrorIs(t, err, ErrCarrierUnderfunded, "seed %d step %d", seed, step)
					denied++
				default:
					require.NoError(t, err, "seed %d step %d", seed, step)
					m.outcomes[leg] = true
					require.True(t, result.Applied)
					require.Equal(t, gas-m.price.Completion, result.Remaining)
					require.Equal(t, len(m.outcomes) == int(m.legs), result.Terminal)
					applied++
				}
			default: // redrive
				r, err := w.funding.Redrive("A", []byte(effect), leg, gas)
				switch {
				case m == nil || leg >= m.legs || m.outcomes[leg]:
					require.ErrorIs(t, err, ErrCarrierFunding, "seed %d step %d", seed, step)
					denied++
				case gas < m.price.Source+sp279Leg(m.price):
					require.ErrorIs(t, err, ErrCarrierUnderfunded, "seed %d step %d", seed, step)
					denied++
				default:
					require.NoError(t, err, "seed %d step %d", seed, step)
					require.Equal(t, sp279Leg(m.price), r.LegGas)
					m.redrives++
					applied++
				}
			}
		}
		// The whole retained state equals the model.
		for effect := 'a'; effect < 'a'+6; effect++ {
			s, m := w.state("A", string(effect)), model[string(effect)]
			if m == nil {
				require.Nil(t, s)
				continue
			}
			require.Equal(t, m.price, s.Price)
			require.Equal(t, m.legs, s.Legs)
			require.Equal(t, m.redrives, s.Redrives)
			for leg := uint32(0); leg < 256; leg++ {
				require.Equal(t, m.outcomes[leg], s.HasOutcome(leg))
			}
			phase := CarrierOutcome
			if len(m.outcomes) == 0 {
				phase = CarrierOpen
			} else if len(m.outcomes) == int(m.legs) {
				phase = CarrierTerminal
			}
			require.Equal(t, phase, s.Phase)
		}
	}
	t.Logf("sequences %d, operations applied %d, denied %d", sequences, applied, denied)
	require.Greater(t, applied, 500)
	require.Greater(t, denied, 500)
}
