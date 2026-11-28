package drwa

import (
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// SP2-37: a failed native read or write, or a failed encoding, at any step is
// an error of that request and leaves the state it found.

// sp237Marshaller fails the at-th encoding.
type sp237Marshaller struct {
	marshal.Marshalizer
	at, calls int
	hit       bool
}

func (m *sp237Marshaller) Marshal(obj interface{}) ([]byte, error) {
	m.calls++
	if m.calls == m.at {
		m.hit = true
		return nil, errSP232
	}
	return m.Marshalizer.Marshal(obj)
}

// sp237Sweep runs one request once for every encoding and once for every
// native store operation it performs, with that one failing.
func sp237Sweep(t *testing.T, label string, faults *sp232Faults, codec *sp237Marshaller, revert func(), root func() []byte, run func() error) {
	t.Helper()
	before := root()
	swept := 0
	for at := 1; ; at++ {
		codec.at, codec.calls, codec.hit = at, 0, false
		err := run()
		if !codec.hit {
			require.NoError(t, err, label+": succeeds with no failed encoding")
			codec.at = 0
			swept += at - 1
			break
		}
		require.Error(t, err, "%s: encoding %d failed", label, at)
		revert()
		require.Equal(t, before, root(), "%s: encoding %d", label, at)
	}
	revert()
	swept += sp232Sweep(t, faults, revert, root, run)
	revert()
	require.Positive(t, swept, label)
}

func TestQualSP237NativeFailuresDenyTheSeal(t *testing.T) {
	for _, peer := range []bool{false, true} {
		s := sp232ShardNew(t, 1)
		sp237Put(t, s, sp232Token, 2, "SETUP")
		faults := &sp232Faults{AccountsAdapter: s.store, peer: peer}
		codec := &sp237Marshaller{Marshalizer: &marshal.GogoProtoMarshalizer{}}
		seal, err := NewLifecycleSeal(ArgsLifecycleSeal{Accounts: faults, Marshaller: codec,
			Hasher: s.f.reader.accounts.args.Hasher, Shard: 1, Shards: 3, RecordBytes: 4096})
		require.NoError(t, err)
		function := seal.Function()
		binding := sp237SetupBinding(s, 2)
		snapshot := s.store.JournalLen()
		revert := func() { require.NoError(t, s.store.RevertToSnapshot(snapshot)) }
		call := func(input *vmcommon.ContractCallInput) func() error {
			return func() error {
				_, callErr := function.ProcessBuiltinFunction(nil, nil, input)
				return callErr
			}
		}
		sp237Sweep(t, "the seal", faults, codec, revert, s.root, call(sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding)))
		sp237Sweep(t, "a setup leg's check", faults, codec, revert, s.root, func() error {
			return seal.VerifyAdminEffect(AdminEffect{TokenID: []byte(sp232Token), Binding: "CURRENT_CEB", Epoch: 2})
		})
		_, err = function.ProcessBuiltinFunction(nil, nil, sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding))
		require.NoError(t, err)
		s.commit()
		snapshot = s.store.JournalLen()
		sp237Sweep(t, "the seal again", faults, codec, revert, s.root, call(sp237Seal(1, sp232Token, 2, "SETUP_SEALED", binding)))
		sp237Sweep(t, "OPEN", faults, codec, revert, s.root, call(sp237Seal(1, sp232Token, 2, "OPEN", nil)))
	}

	// A shard that holds the record without the CEB pointer of its epoch
	// cannot check a seal: refused.
	s := sp232ShardNew(t, 0)
	sp237Install(t, s)
	qualRecordPut(t, s.store, sp237Key(sp232Token), sp237Record(sp232Token, 2, "SETUP"))
	s.commit()
	s.sp237Refused("no CEB pointer", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", sp237SetupBinding(s, 2)))
	qualRecordPut(t, s.store, sp237Pointer(sp232Token), qualRecordFrame([]byte{0, 0, 0, 0, 0, 0, 0, 1}, sp237CEB(2)))
	s.commit()
	s.sp237Refused("CEB pointer of another epoch", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", sp237SetupBinding(s, 2)))
	qualRecordPut(t, s.store, sp237Pointer(sp232Token), []byte("not a pointer"))
	s.commit()
	s.sp237Refused("a pointer that does not decode", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", sp237SetupBinding(s, 2)))
	qualRecordPut(t, s.store, sp237Pointer(sp232Token), qualRecordFrame([]byte{0, 0, 0, 0, 0, 0, 0, 2}, []byte("short")))
	s.commit()
	s.sp237Refused("a pointer with a short hash", sp237Seal(0, sp232Token, 2, "SETUP_SEALED", sp237SetupBinding(s, 2)))
	// Even under a binding derived from that short value.
	s.sp237Refused("a binding derived from the short hash", sp237Seal(0, sp232Token, 2, "SETUP_SEALED",
		sp237BindingOf(s, sp237SetupCoordinates(s, sp232Token, 2, []byte("short")), ConvergenceFamilySetup, "SETUP_SEALED", sp232Token, 2, "SETUP_SEALED", 0, 1, 2)))
}

func TestQualSP237NativeFailuresDenyTheReplication(t *testing.T) {
	for _, peer := range []bool{false, true} {
		w := sp237New(t)
		ready, sealed := w.ready(), w.sealed()
		require.NoError(t, w.life.phases.create(ready))
		for _, s := range w.shards {
			w.produce(ready, s)
			require.NoError(t, w.acknowledge(ready, s))
		}
		require.NoError(t, w.life.phases.complete(ready))
		store := w.f.x.f.store
		faults := &sp232Faults{AccountsAdapter: store, peer: peer}
		codec := &sp237Marshaller{Marshalizer: &marshal.GogoProtoMarshalizer{}}
		funding, err := NewCarrierFunding(ArgsCarrierFunding{Accounts: faults, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(),
			Block: w.block, Prices: &sp237Prices{CarrierPrice{Source: 100, Destination: 40, Success: 7, Refund: 9, Completion: 30}},
			Limits: sp223Ample(), RecordBytes: 4096})
		require.NoError(t, err)
		origin, err := NewLifecycleSealOrigin(ArgsLifecycleSealOrigin{Accounts: faults, Marshaller: codec, Hasher: blake2b.NewBlake2b(),
			Funding: funding, Shards: 3, RecordBytes: 4096})
		require.NoError(t, err)
		token := []byte(sp237Token)
		snapshot := store.JournalLen()
		revert := func() { require.NoError(t, store.RevertToSnapshot(snapshot)) }

		good, err := decodeConvergenceBinding(w.host.args.Records, w.binding(ready))
		require.NoError(t, err)
		sp237Sweep(t, "the family owner", faults, codec, revert, w.root, func() error { return origin.VerifyTransition(*good) })

		require.NoError(t, w.advance("SETUP_SEALED", ready))
		binding := w.binding(sealed)
		snapshot = store.JournalLen()
		var legs []vmcommon.OutputTransfer
		sp237Sweep(t, "the replication", faults, codec, revert, w.root, func() error {
			output := &vmcommon.VMOutput{}
			_, e := origin.Replicate(output, token, 1, "SETUP_SEALED", binding, 1<<20)
			legs = sp232Transfers(output)
			return e
		})
		_, err = origin.Replicate(&vmcommon.VMOutput{OutputAccounts: map[string]*vmcommon.OutputAccount{"x": nil}}, token, 1, "SETUP_SEALED", binding, 1<<20)
		require.ErrorIs(t, err, ErrLifecycleSeal, "an output that cannot take the calls")
		revert()
		_, err = origin.Replicate(&vmcommon.VMOutput{}, token, 1, "SETUP_SEALED", binding, 1<<20)
		require.NoError(t, err)
		require.Len(t, legs, 3)
		snapshot = store.JournalLen()
		sp237Sweep(t, "the redrive", faults, codec, revert, w.root, func() error {
			_, e := origin.Redrive(&vmcommon.VMOutput{}, token, 1, "SETUP_SEALED", binding, 2, 1<<20)
			return e
		})
		output, err := w.deliver(w.shards[0], legs[0])
		require.NoError(t, err)
		sp237Sweep(t, "the outcome", faults, codec, revert, w.root, func() error {
			_, _, e := origin.Outcome(sp237Callback(0, output))
			return e
		})

		// An output that cannot take the calls: refused, and nothing funded.
		for label, broken := range map[string]*vmcommon.VMOutput{
			"an output account that is nil": {OutputAccounts: map[string]*vmcommon.OutputAccount{"x": nil}},
			"no result index left": {OutputAccounts: map[string]*vmcommon.OutputAccount{"x": {Address: []byte("x"),
				BalanceDelta: big.NewInt(0), OutputTransfers: []vmcommon.OutputTransfer{{Index: ^uint32(0)}}}}},
		} {
			before := w.root()
			_, err = origin.Redrive(broken, token, 1, "SETUP_SEALED", binding, 1, 1<<20)
			require.ErrorIs(t, err, ErrLifecycleSeal, label)
			revert()
			require.Equal(t, before, w.root(), label)
		}
		_, err = origin.Redrive(&vmcommon.VMOutput{}, token, 1, "SETUP_SEALED", []byte("not a binding"), 1, 1<<20)
		require.Error(t, err)
	}

	// A price that gives a call no gas: nothing is emitted, since such a call
	// is applied and never answered. And one store for funding and lifecycle.
	w := sp237New(t)
	store := w.f.x.f.store
	free, err := NewCarrierFunding(ArgsCarrierFunding{Accounts: store, Marshaller: &marshal.GogoProtoMarshalizer{}, Hasher: blake2b.NewBlake2b(),
		Block: w.block, Prices: &sp237Prices{CarrierPrice{Source: 100}}, Limits: sp223Ample(), RecordBytes: 4096})
	require.NoError(t, err)
	origin, err := NewLifecycleSealOrigin(ArgsLifecycleSealOrigin{Accounts: store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: blake2b.NewBlake2b(), Funding: free, Shards: 3, RecordBytes: 4096})
	require.NoError(t, err)
	ready, sealed := w.ready(), w.sealed()
	require.NoError(t, w.life.phases.create(ready))
	for _, s := range w.shards {
		w.produce(ready, s)
		require.NoError(t, w.acknowledge(ready, s))
	}
	require.NoError(t, w.life.phases.complete(ready))
	require.NoError(t, w.advance("SETUP_SEALED", ready))
	output := &vmcommon.VMOutput{}
	_, err = origin.Replicate(output, []byte(sp237Token), 1, "SETUP_SEALED", w.binding(sealed), 1<<20)
	require.ErrorIs(t, err, ErrLifecycleSeal)
	require.Empty(t, output.OutputAccounts)
	other := sp232ShardNew(t, 0)
	_, err = NewLifecycleSealOrigin(ArgsLifecycleSealOrigin{Accounts: other.store, Marshaller: &marshal.GogoProtoMarshalizer{},
		Hasher: blake2b.NewBlake2b(), Funding: free, Shards: 3, RecordBytes: 4096})
	require.ErrorIs(t, err, ErrLifecycleSeal, "funding over another store")
	require.Equal(t, core.MetachainShardId, w.f.r.coordinator.SelfId())
}
