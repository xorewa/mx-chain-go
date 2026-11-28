package drwa

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Ample experimental values: no limit binds unless a test lowers it.
func sp229Ample() sp229Limits {
	return sp229Limits{recordBytes: 4096, records: 1 << 20, bytes: 1 << 40, perEpoch: 1 << 20, maxEver: 1 << 20}
}

// sp229Prefixes are the request chains whose last element is the measured or
// bounded request; the earlier elements are its prerequisites.
func sp229Chains() map[string][]sp229Request {
	i, s := sp229IntentFor(1), sp229ScopeFor(1)
	return map[string][]sp229Request{
		"intent":   {sp229OpenIntent(i)},
		"register": {sp229OpenIntent(i), sp229Register(i)},
		"retire":   {sp229OpenIntent(i), sp229Register(i), sp229Retire(i)},
		"enroll":   {sp229Enroll(s)},
		"decide":   {sp229Enroll(s), sp229Decide(s)},
		"withdraw": {sp229Enroll(s), sp229Decide(s), sp229Withdraw(s)},
	}
}

// Production against the independent model over whole request sequences, with
// scarce experimental limits so that every dimension is exhausted and released
// rate capacity is used again after an epoch change. Restarts are interleaved.
func TestQualSP229SequencesAgainstIndependentModel(t *testing.T) {
	requests, admitted, denied := 0, 0, 0
	kinds := map[string][2]int{}
	for seed := int64(1); seed <= 60; seed++ {
		rng := rand.New(rand.NewSource(seed))
		lim := sp229Limits{recordBytes: 4096, records: uint64(6 + rng.Intn(40)), bytes: uint64(1500 + rng.Intn(16000)),
			perEpoch: uint64(2 + rng.Intn(9)), maxEver: uint64(rng.Intn(4))}
		w := sp229New(t, lim)
		var open, registered []sp229Intent
		var enrolled, decided []sp229Scope
		next := 0
		for step := 0; step < 70; step++ {
			var r sp229Request
			var done func()
			switch choice := rng.Intn(16); {
			case choice == 0:
				w.nextEpoch()
				continue
			case choice == 1:
				w.restart()
				continue
			case choice < 6 || choice < 9 && len(open) == 0:
				i := sp229IntentFor(next)
				next++
				r, done = sp229OpenIntent(i), func() { open = append(open, i) }
			case choice < 9:
				i := open[0]
				r, done = sp229Register(i), func() { open, registered = open[1:], append(registered, i) }
			case choice == 9 && len(registered) != 0:
				i := registered[0]
				r, done = sp229Retire(i), func() { registered = registered[1:] }
			case choice < 13 || len(enrolled) == 0 && len(decided) == 0:
				s := sp229ScopeFor(next)
				next++
				r, done = sp229Enroll(s), func() { enrolled = append(enrolled, s) }
			case len(enrolled) != 0 && (choice == 13 || len(decided) == 0):
				s := enrolled[0]
				r, done = sp229Decide(s), func() { enrolled, decided = enrolled[1:], append(decided, s) }
			default:
				s := decided[0]
				r, done = sp229Withdraw(s), func() { decided = decided[1:] }
			}
			requests++
			count := kinds[r.name]
			if w.apply(r, fmt.Sprintf("seed %d step %d %s %+v", seed, step, r.name, lim)) {
				admitted++
				count[0]++
				done()
			} else {
				denied++
				count[1]++
			}
			kinds[r.name] = count
		}
	}
	for _, name := range []string{"intent", "register", "retire", "enroll", "decide", "withdraw"} {
		require.NotZero(t, kinds[name][0], name+" never admitted")
		require.NotZero(t, kinds[name][1], name+" never denied")
	}
	t.Logf("SP2-29 model comparison: %d requests, %d admitted, %d denied, 0 mismatches; per kind [admitted denied] %v", requests, admitted, denied, kinds)
}

// Each limit one below, at and one above the bound, for every request kind it
// applies to. The bound is taken from the independent model's own usage.
func TestQualSP229EachLimitBelowAtAbove(t *testing.T) {
	for kind, chain := range sp229Chains() {
		probe := &sp229Model{lim: sp229Ample(), count: 1, size: uint64(len(sp229BudgetKey) + 32), rateEpoch: 10, held: map[string]int{}}
		for _, r := range chain[:len(chain)-1] {
			require.True(t, probe.admit(10, r.token, r.writes))
		}
		beforeCount, beforeRate := probe.count, probe.rate
		last := chain[len(chain)-1]
		require.True(t, probe.admit(10, last.token, last.writes))
		type dimension struct {
			name  string
			need  uint64
			apply func(*sp229Limits, uint64)
		}
		dimensions := []dimension{{"bytes", probe.size, func(l *sp229Limits, v uint64) { l.bytes = v }}}
		if probe.count != beforeCount {
			dimensions = append(dimensions,
				dimension{"records", probe.count, func(l *sp229Limits, v uint64) { l.records = v }},
				dimension{"perEpoch", probe.rate, func(l *sp229Limits, v uint64) { l.perEpoch = v }})
			require.NotEqual(t, beforeRate, probe.rate)
		}
		if last.token {
			dimensions = append(dimensions, dimension{"maxEver", probe.tokens, func(l *sp229Limits, v uint64) { l.maxEver = v }})
		}
		for _, d := range dimensions {
			for offset, admitted := range map[int]bool{-1: false, 0: true, 1: true} {
				t.Run(fmt.Sprintf("%s/%s/%+d", kind, d.name, offset), func(t *testing.T) {
					lim := sp229Ample()
					d.apply(&lim, uint64(int64(d.need)+int64(offset)))
					if lim.records == 0 || lim.bytes == 0 || lim.perEpoch == 0 {
						// A zero budget limit is not a bound that denies every
						// request: every owner refuses to be built with it.
						ample := sp229New(t, sp229Ample())
						_, err := newScopedAdmissionRecords(ample.store, ample.boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(),
							[]byte("fixture-domain"), scopedAdmissionLimits{lim.recordBytes, lim.records, lim.bytes, lim.perEpoch},
							ample.verifier, qualClockSource(ample.clock, ample.store))
						require.Error(t, err)
						owner := ample.admission(sp229IntentFor(1)).owner
						p := []byte("synthetic")
						_, err = owner.WithRegistrationAdmission(qualClockSource(ample.clock, ample.store), []byte("n"), 10,
							RegistrationResourceLimits{lim.records, lim.bytes, lim.perEpoch}, ample.verifier, RegistrationProofs{p, p, p, p, p, p, p, p})
						require.Error(t, err)
						_, err = owner.WithBootstrapCancellation(qualClockSource(ample.clock, ample.store), []byte("n"), 10,
							RegistrationResourceLimits{lim.records, lim.bytes, lim.perEpoch}, ample.verifier)
						require.Error(t, err)
						return
					}
					w := sp229New(t, lim)
					for n, r := range chain[:len(chain)-1] {
						require.True(t, w.apply(r, fmt.Sprintf("prerequisite %d", n)))
					}
					require.Equal(t, admitted, w.apply(last, "bounded request"))
					// A request one unit over the bound has no partial effect:
					// the multi-record kinds are covered by apply's root check.
				})
			}
		}
	}
}

// The per-record byte bound is the work bound of one request: no record larger
// than it is framed, hashed, verified or retained.
func TestQualSP229RecordBytesBelowAtAbove(t *testing.T) {
	i := sp229IntentFor(1)
	// The largest record one intent request frames is its payload preimage.
	value := qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), i.encoded)
	require.Greater(t, len(value), len(sp229OpenIntent(i).writes[0].value))
	for offset, admitted := range map[int]bool{-1: false, 0: true, 1: true} {
		t.Run(fmt.Sprintf("%+d", offset), func(t *testing.T) {
			lim := sp229Ample()
			lim.recordBytes = len(value) + offset
			w := sp229New(t, lim)
			before, journal := w.root(), w.store.JournalLen()
			err := sp229OpenIntent(i).run(w)
			require.Equal(t, admitted, err == nil, "%v", err)
			if !admitted {
				require.Equal(t, before, w.root())
				require.Equal(t, journal, w.store.JournalLen())
			}
		})
	}
}

// Exhaustion of each dimension through the real owners, then every request
// kind that needs that dimension is denied without effect, and the kinds that
// do not need it are still served.
func TestQualSP229ExhaustionOfEachDimension(t *testing.T) {
	for _, dimension := range []string{"records", "bytes", "perEpoch", "maxEver"} {
		t.Run(dimension, func(t *testing.T) {
			lim := sp229Ample()
			switch dimension {
			case "records":
				lim.records = 12
			case "bytes":
				lim.bytes = 4000
			case "perEpoch":
				lim.perEpoch = 5
			case "maxEver":
				lim.maxEver = 2
			}
			w := sp229New(t, lim)
			var open []sp229Intent
			var scopes []sp229Scope
			n := 0
			// Fill with intents, registrations and enrollments in turn until a
			// whole round is denied.
			for progress := true; progress; {
				progress = false
				i, s := sp229IntentFor(n), sp229ScopeFor(n)
				n++
				if w.apply(sp229OpenIntent(i), "fill intent") {
					open, progress = append(open, i), true
				}
				if w.apply(sp229Enroll(s), "fill enroll") {
					scopes, progress = append(scopes, s), true
				}
				if len(open) != 0 && w.apply(sp229Register(open[0]), "fill register") {
					open, progress = open[1:], true
				}
				if dimension == "maxEver" && w.model.tokens == lim.maxEver {
					late := sp229IntentFor(900)
					require.True(t, w.apply(sp229OpenIntent(late), "intent at the token cap"))
					require.False(t, w.apply(sp229Register(late), "register at the token cap"))
					break
				}
				require.Less(t, n, 200)
			}
			root := w.root()
			budget := bytes.Clone(qualRegistryValue(t, w.store, sp229BudgetKey))
			for round := 0; round < 3; round++ {
				require.False(t, w.apply(sp229OpenIntent(sp229IntentFor(1000+round)), "exhausted intent") && dimension != "maxEver")
				require.False(t, w.apply(sp229Enroll(sp229ScopeFor(1000+round)), "exhausted enroll") && dimension != "maxEver")
				if dimension != "maxEver" {
					require.Equal(t, root, w.root())
					require.Equal(t, budget, qualRegistryValue(t, w.store, sp229BudgetKey))
				}
			}
			if dimension == "maxEver" {
				// Token cap exhausted: registration is denied, and intents and
				// enrollments go on being served and counted by the budget.
				require.Equal(t, lim.maxEver, w.model.tokens)
				extra := sp229IntentFor(5000)
				require.True(t, w.apply(sp229OpenIntent(extra), "intent after token cap"))
				require.False(t, w.apply(sp229Register(extra), "register after token cap"))
				require.True(t, w.apply(sp229Enroll(sp229ScopeFor(5000)), "enroll after token cap"))
			}
			if dimension == "perEpoch" {
				// The rate is per epoch: the next epoch serves again; the count
				// and bytes already retained stay charged.
				w.nextEpoch()
				require.True(t, w.apply(sp229OpenIntent(sp229IntentFor(6000)), "intent in next epoch"))
				require.Greater(t, binary.BigEndian.Uint64(qualRegistryValue(t, w.store, sp229BudgetKey)), binary.BigEndian.Uint64(budget))
			}
		})
	}
}

// Token cap exhausted, then pre-registration activity continues until the
// budget itself is exhausted: it stays bounded, and ends in denial.
func TestQualSP229PreRegistrationBoundedAfterTokenCap(t *testing.T) {
	lim := sp229Ample()
	lim.maxEver, lim.records = 1, 20
	w := sp229New(t, lim)
	first := sp229IntentFor(0)
	require.True(t, w.apply(sp229OpenIntent(first), "intent"))
	require.True(t, w.apply(sp229Register(first), "register"))
	admitted := 0
	for n := 1; n < 60; n++ {
		if w.apply(sp229OpenIntent(sp229IntentFor(n)), "intent after cap") {
			admitted++
		}
		if w.apply(sp229Enroll(sp229ScopeFor(n)), "enroll after cap") {
			admitted += 2
		}
		require.False(t, w.apply(sp229Register(sp229IntentFor(n)), "register after cap"))
	}
	// 20 records: the budget record, 3 for the one token, 16 left.
	require.Equal(t, 16, admitted)
	require.Equal(t, uint64(20), w.model.count)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, w.store, registryCountKey)))
}

// Abandoned and expired-retained work stays charged and is never recycled: an
// expired OPEN intent cannot register, cannot be retained again, keeps its
// record and its slot, and frees nothing for anyone else. The same holds for a
// consumed intent, a retired registration and a withdrawn decision.
func TestQualSP229AbandonedAndExpiredWorkIsNeverRecycled(t *testing.T) {
	lim := sp229Ample()
	lim.records = 9 // budget + abandoned intent + token (3) + scope (2) + decision + tombstone
	w := sp229New(t, lim)
	abandoned, used, s := sp229IntentFor(1), sp229IntentFor(2), sp229ScopeFor(1)
	for _, r := range []sp229Request{sp229OpenIntent(abandoned), sp229OpenIntent(used), sp229Register(used), sp229Retire(used),
		sp229Enroll(s), sp229Decide(s), sp229Withdraw(s)} {
		require.True(t, w.apply(r, r.name))
	}
	require.Equal(t, uint64(9), w.model.count)
	// The intents expire at time 1; move the evaluated header past it.
	w.time = 2
	w.header()
	root, budget := w.root(), bytes.Clone(qualRegistryValue(t, w.store, sp229BudgetKey))
	record := bytes.Clone(qualRegistryValue(t, w.store, "ELRONDDRWA@registration@intent@"+string(abandoned.id)))
	require.Equal(t, sp229OpenIntent(abandoned).writes[0].value, record, "ordinary expiry does not mutate the record")
	for name, r := range map[string]sp229Request{
		"expired intent registers":      sp229Register(abandoned),
		"expired intent retained again": sp229OpenIntent(abandoned),
		"consumed intent reopened":      sp229OpenIntent(used),
		"consumed intent registers":     sp229Register(used),
		"retired registration retired":  sp229Retire(used),
		"new intent takes a freed slot": sp229OpenIntent(sp229IntentFor(3)),
		"new scope takes a freed slot":  sp229Enroll(sp229ScopeFor(3)),
	} {
		require.Error(t, r.run(w), name)
		require.Equal(t, root, w.root(), name)
		require.Equal(t, budget, qualRegistryValue(t, w.store, sp229BudgetKey), name)
	}
	// Exact replays of retained scope work are no-ops and return no capacity.
	w.time = 1
	w.header()
	for name, r := range map[string]sp229Request{"enroll replay": sp229Enroll(s), "decision replay": sp229Decide(s), "withdrawal replay": sp229Withdraw(s)} {
		require.NoError(t, r.run(w), name)
		require.Equal(t, root, w.root(), name)
	}
	w.restart()
	w.nextEpoch()
	require.Error(t, sp229OpenIntent(sp229IntentFor(4)).run(w), "no slot returns after restart or epoch change")
	require.Equal(t, budget[:16], qualRegistryValue(t, w.store, sp229BudgetKey)[:16])
}

// The same requests in a different order. With capacity for all of them the
// committed state is identical whatever the order. Under scarcity the admitted
// set is exactly the first-come set of the executed order (ledger L31), and the
// same order always gives the same state.
func TestQualSP229ArrivalOrder(t *testing.T) {
	build := func() []sp229Request {
		var all []sp229Request
		for n := 1; n <= 3; n++ {
			all = append(all, sp229OpenIntent(sp229IntentFor(n)), sp229Enroll(sp229ScopeFor(n)))
		}
		return all
	}
	run := func(lim sp229Limits, order []int) ([]byte, []bool) {
		w := sp229New(t, lim)
		all, served := build(), make([]bool, 6)
		for _, index := range order {
			served[index] = w.apply(all[index], fmt.Sprintf("order %v request %d", order, index))
		}
		w.restart()
		return w.root(), served
	}
	rng := rand.New(rand.NewSource(229))
	identity := []int{0, 1, 2, 3, 4, 5}
	ampleRoot, _ := run(sp229Ample(), identity)
	scarce := sp229Ample()
	scarce.records = 6 // budget + five of the nine records requested
	sets := map[string]struct{}{}
	for trial := 0; trial < 40; trial++ {
		order := rng.Perm(6)
		root, served := run(sp229Ample(), order)
		require.Equal(t, ampleRoot, root, "order %v", order)
		require.Equal(t, []bool{true, true, true, true, true, true}, served)

		first, servedFirst := run(scarce, order)
		second, servedSecond := run(scarce, order)
		require.Equal(t, first, second, "order %v", order)
		require.Equal(t, servedFirst, servedSecond)
		// First come, first served: replay the order against the clause.
		left, want := 5, make([]bool, 6)
		for _, index := range order {
			need := 1 + index%2 // an intent retains one record, an enrollment two
			if need <= left {
				left, want[index] = left-need, true
			}
		}
		require.Equal(t, want, servedFirst, "order %v", order)
		sets[fmt.Sprint(servedFirst)] = struct{}{}
	}
	require.Greater(t, len(sets), 1, "scarcity must make the order matter in this test")
}

// Restart: counts are read back from the committed store and the limits come
// from the same configured input, so the boundary is where it was.
func TestQualSP229RestartKeepsCountsAndLimits(t *testing.T) {
	lim := sp229Ample()
	lim.records, lim.perEpoch, lim.maxEver = 8, 6, 1
	w := sp229New(t, lim)
	i := sp229IntentFor(1)
	require.True(t, w.apply(sp229OpenIntent(i), "intent"))
	require.True(t, w.apply(sp229Register(i), "register"))
	require.True(t, w.apply(sp229Enroll(sp229ScopeFor(1)), "enroll"))
	budget := bytes.Clone(qualRegistryValue(t, w.store, sp229BudgetKey))
	registry := bytes.Clone(qualRegistryValue(t, w.store, registryCountKey))
	w.restart()
	require.Equal(t, budget, qualRegistryValue(t, w.store, sp229BudgetKey))
	require.Equal(t, registry, qualRegistryValue(t, w.store, registryCountKey))
	// 6 of 8 records and 5 of 6 per epoch are used; the cap of one token is used.
	require.False(t, w.apply(sp229Enroll(sp229ScopeFor(2)), "two records over the rate"))
	second := sp229IntentFor(2)
	require.True(t, w.apply(sp229OpenIntent(second), "last record of the epoch"))
	require.False(t, w.apply(sp229OpenIntent(sp229IntentFor(3)), "rate exhausted"))
	require.False(t, w.apply(sp229Register(second), "token cap exhausted"))
	w.restart()
	w.nextEpoch()
	require.True(t, w.apply(sp229OpenIntent(sp229IntentFor(3)), "next epoch, last record"))
	require.False(t, w.apply(sp229OpenIntent(sp229IntentFor(4)), "records exhausted"))
	w.restart()
	require.False(t, w.apply(sp229OpenIntent(sp229IntentFor(4)), "records exhausted after restart"))
	// A node restarted with other limits does not serve past the committed
	// usage either: usage above a configured limit is refused, not truncated.
	w.lim.records = 7
	w.build()
	require.Error(t, sp229Retire(i).run(w))
}

// Where the chain-global budget exists, registration records cannot be
// retained outside it: the bare intent owner, which carries no limits, is
// refused before any write, and the admission-bound owner is charged.
func TestQualSP229RegistrationOutsideTheBudgetIsRefused(t *testing.T) {
	w := sp229New(t, sp229Ample())
	i := sp229IntentFor(1)
	require.True(t, w.apply(sp229OpenIntent(i), "intent"))
	owner := w.admission(i).owner
	root, journal := w.root(), w.store.JournalLen()
	called := false
	err := owner.RegisterTokenForCreation(i.body.issuer, bytes.Repeat([]byte{0x22}, 32), i.body.requestedTokenFamily,
		func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			called = true
			return qualRegistrationCreator(t, i.token)(accounts)
		})
	require.ErrorIs(t, err, errInvalidRegistrationRecord)
	require.True(t, called, "the refusal is at the retained write, inside the rolled-back operation")
	require.Equal(t, root, w.root())
	require.Equal(t, journal, w.store.JournalLen())
	require.True(t, w.apply(sp229Register(i), "admission-bound registration"))
}

// Ordinary accounts on a store whose DRWA budget is exhausted: an ordinary
// account creation, balance movement and nonce increment give identical
// account state to the same operations on a store without any DRWA record,
// and touch no DRWA record. Ordinary token issue and transfer through the
// native System SC and built-ins are compared in their own package.
func TestQualSP229OrdinaryAccountOperationsUnchanged(t *testing.T) {
	lim := sp229Ample()
	lim.records = 2
	w := sp229New(t, lim)
	require.True(t, w.apply(sp229OpenIntent(sp229IntentFor(1)), "intent"))
	require.False(t, w.apply(sp229OpenIntent(sp229IntentFor(2)), "exhausted"))
	plain := qualContainmentStore(t)
	t.Cleanup(func() { _ = plain.Close() })
	budget := bytes.Clone(qualRegistryValue(t, w.store, sp229BudgetKey))
	accounts := func(s state.AccountsAdapter) [][]byte {
		var encoded [][]byte
		alice, bob := bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb0}, 32)
		for step := 0; step < 2; step++ {
			a, err := s.LoadAccount(alice)
			require.NoError(t, err)
			b, err := s.LoadAccount(bob)
			require.NoError(t, err)
			sender, receiver := a.(state.UserAccountHandler), b.(state.UserAccountHandler)
			if step == 0 {
				require.NoError(t, sender.AddToBalance(big.NewInt(1000)))
			}
			require.NoError(t, sender.SubFromBalance(big.NewInt(7)))
			require.NoError(t, receiver.AddToBalance(big.NewInt(7)))
			sender.IncreaseNonce(1)
			require.NoError(t, s.SaveAccount(sender))
			require.NoError(t, s.SaveAccount(receiver))
		}
		_, err := s.Commit()
		require.NoError(t, err)
		for _, address := range [][]byte{alice, bob} {
			account, err := s.GetExistingAccount(address)
			require.NoError(t, err)
			user := account.(state.UserAccountHandler)
			encoded = append(encoded, user.GetBalance().Bytes(), binary.BigEndian.AppendUint64(nil, user.GetNonce()), user.GetRootHash(), user.GetCodeHash())
		}
		return encoded
	}
	require.Equal(t, accounts(plain), accounts(w.store))
	require.Equal(t, budget, qualRegistryValue(t, w.store, sp229BudgetKey))
}

// Measurements at the experimental values, for the row's measurement table.
// They are measurements of this fixture, not decisions and not gas: no DRWA
// gas schedule entry exists for these owners (ingress belongs to SP2-38).
func TestQualSP229MeasurementTable(t *testing.T) {
	t.Logf("SP2-29 MEASURE | request | new records | retained bytes charged | largest record bytes | verifier calls | account journal entries")
	for _, kind := range []string{"intent", "register", "retire", "enroll", "decide", "withdraw"} {
		chain := sp229Chains()[kind]
		w := sp229New(t, sp229Ample())
		for _, r := range chain[:len(chain)-1] {
			require.True(t, w.apply(r, "prerequisite"))
		}
		w.restart()
		before := bytes.Clone(qualRegistryValue(t, w.store, sp229BudgetKey))
		calls, journal := w.verifier.calls, w.store.JournalLen()
		last := chain[len(chain)-1]
		require.True(t, w.apply(last, kind))
		after := qualRegistryValue(t, w.store, sp229BudgetKey)
		largest := 0
		for _, write := range last.writes {
			largest = max(largest, len(write.value))
		}
		t.Logf("SP2-29 MEASURE | %s | %d | %d | %d | %d | %d", kind,
			binary.BigEndian.Uint64(after)-binary.BigEndian.Uint64(before),
			binary.BigEndian.Uint64(after[8:])-binary.BigEndian.Uint64(before[8:]), largest,
			w.verifier.calls-calls, w.store.JournalLen()-journal)
	}
	// The permanent registry itself: one marker, one ordinal entry, the count.
	token := "TKN-000001"
	t.Logf("SP2-29 MEASURE | registry entry per token (outside the budget, bounded by the token cap) | 2 | %d | %d | - | -",
		len(registryMemberKeyPrefix)+len(token)+1+len(registryEntryPrefix)+8+len(token), len(token))
}
