package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Canonicality and full CEB interpretation remain synthetic. This is a native
// storage/time/rollback reader control, not actual provider or profile admission.
type qualLifecycleHost struct {
	*qualCurrentLocalHost
	fields             lifecycleCEBFields
	expectedActivation []byte
}

func (h *qualLifecycleHost) LifecycleFields(body []byte) (lifecycleCEBFields, error) {
	if !bytes.Equal(body, h.body) {
		return lifecycleCEBFields{}, errCurrentLifecycle
	}
	return h.fields, h.check("fields")
}
func (h *qualLifecycleHost) VerifyLifecycle(token []byte, epoch uint64, hash, activation, lifecycle []byte, context *HeaderTimeContext) error {
	if !bytes.Equal(token, []byte("TOKEN-abcdef")) || epoch != 1 ||
		!bytes.Equal(hash, blake2b.NewBlake2b().Compute(string(h.body))) || context == nil ||
		h.expectedActivation != nil && !bytes.Equal(activation, h.expectedActivation) {
		return errCurrentLifecycle
	}
	// Supplied native bytes are detached and cannot rewrite the next baseline.
	token[0] ^= 1
	hash[0] ^= 1
	activation[0] ^= 1
	lifecycle[0] ^= 1
	return h.check("lifecycle")
}

type qualLifecycleFixture struct {
	x       *qualActivationFixture
	h       *qualLifecycleHost
	r       *currentLifecycleReader
	context *HeaderTimeContext
	hash    []byte
}

func qualLifecycleParent(token, intentID []byte, status string) []byte {
	fields := [][]byte{token, intentID, []byte(status)}
	if status != "BootstrapDeny" {
		fields = append(fields, blake2b.NewBlake2b().Compute("explicit synthetic durable readiness parent"))
	}
	return qualRecordFrame(fields...)
}

func qualLifecycleNew(t *testing.T) *qualLifecycleFixture {
	t.Helper()
	f := &qualLifecycleFixture{x: qualActivationNew(t)}
	require.NoError(t, f.x.activate())
	token := []byte("TOKEN-abcdef")
	// These fixtures inject the independently framed local replica. The
	// whole-set comparison helper supplies only the other prestate records.
	qualRecordPut(t, f.x.f.store, append([]byte(registrationActivationPrefix), token...), qualLifecycleParent(token, f.x.f.owner.id, "Active"))
	base := &qualCurrentLocalHost{body: bytes.Clone(f.x.genesis), faults: make(map[string]error), hooks: make(map[string]func()), calls: make(map[string]int), mutateBuffers: true}
	f.h = &qualLifecycleHost{qualCurrentLocalHost: base}
	coord, err := sharding.NewMultiShardCoordinator(3, core.MetachainShardId)
	require.NoError(t, err)
	origin := bytes.Clone(qualContainmentAddress)
	f.h.fields = lifecycleCEBFields{bytes.Clone(f.x.f.body.closurePlan), origin, coord.ComputeId(origin), uint32(core.Fungible)}
	for _, kind := range []string{"authority", "public-schema", "gas-schedule", "profile-parser", "token-admin"} {
		material := []byte("synthetic current lifecycle dependency " + kind)
		ref := currentLocalReference{[]byte(kind), []byte("fixture"), []byte{1}, blake2b.NewBlake2b().Compute(string(material))}
		base.refs = append(base.refs, ref)
		qualRecordPut(t, f.x.f.store, append([]byte(currentLocalDependencyPrefix), qualRecordFrame(ref.kind, ref.id, ref.version)...), material)
	}
	current, err := newCurrentLocalDependencies(f.x.f.store, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096, 10, f.h)
	require.NoError(t, err)
	f.r, err = newCurrentLifecycleReader(current, f.x.f.boundary, f.x.f.hook, coord)
	require.NoError(t, err)
	f.context, err = f.x.f.hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	f.hash = blake2b.NewBlake2b().Compute(string(f.x.genesis))
	return f
}

func (f *qualLifecycleFixture) read(consume func(lifecycleReadView) (*vmcommon.VMOutput, error)) error {
	return f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return f.r.withCurrent(f.context, []byte("TOKEN-abcdef"), 1, f.hash, consume)
	})
}

func TestQualDRWACurrentLifecycleExactDetachedRead(t *testing.T) {
	f := qualLifecycleNew(t)
	journal := f.x.f.store.JournalLen()
	calls := 0
	require.NoError(t, f.read(func(view lifecycleReadView) (*vmcommon.VMOutput, error) {
		calls++
		require.Equal(t, []byte("TOKEN-abcdef"), view.token)
		require.Equal(t, uint64(1), view.cebEpoch)
		require.Equal(t, f.hash, view.cebHash)
		require.Equal(t, "Active", view.activation)
		require.Equal(t, "SETUP", view.lifecycle)
		require.Equal(t, f.x.f.body.closurePlan, view.closurePlan)
		require.Equal(t, f.h.fields.supplyOrigin, view.supplyOrigin)
		require.Equal(t, f.h.fields.supplyOriginShard, view.supplyOriginShard)
		require.Equal(t, uint32(core.Fungible), view.tokenType)
		view.token[0] ^= 1
		view.cebHash[0] ^= 1
		view.closurePlan[0] ^= 1
		view.supplyOrigin[0] ^= 1
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}))
	require.Equal(t, 1, calls)
	require.Equal(t, 2, f.h.calls["current"])
	require.Equal(t, 10, f.h.calls["dependency"])
	require.Equal(t, 2, f.h.calls["fields"])
	require.Equal(t, 2, f.h.calls["lifecycle"])
	require.Equal(t, journal, f.x.f.store.JournalLen())
}

func TestQualDRWACurrentLifecycleRecordAndOriginDenials(t *testing.T) {
	for _, mode := range []string{"bootstrap", "retired", "missing lifecycle", "wrong lifecycle epoch", "impossible phase", "missing member", "wrong closure", "wrong type", "short origin", "wrong origin shard"} {
		t.Run(mode, func(t *testing.T) {
			f := qualLifecycleNew(t)
			token, epoch := []byte("TOKEN-abcdef"), binary.BigEndian.AppendUint64(nil, 1)
			lrcKey := append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...)
			switch mode {
			case "bootstrap", "retired":
				state := "BootstrapDeny"
				if mode == "retired" {
					state = "RetiredDeny"
				}
				qualRecordPut(t, f.x.f.store, append([]byte(registrationActivationPrefix), token...), qualLifecycleParent(token, f.x.f.owner.id, state))
				// Neither closed state needs an invented current positive CEB.
				qualRecordPut(t, f.x.f.store, append([]byte(currentLocalPointerPrefix), qualRecordFrame(token)...), nil)
				qualRecordPut(t, f.x.f.store, append([]byte(registrationAssociationPrefix), token...), nil)
				qualRecordPut(t, f.x.f.store, append([]byte(registrationIntentPrefix), f.x.f.owner.id...), nil)
			case "missing lifecycle":
				qualRecordPut(t, f.x.f.store, lrcKey, nil)
			case "wrong lifecycle epoch":
				qualRecordPut(t, f.x.f.store, lrcKey, qualRecordFrame(token, binary.BigEndian.AppendUint64(nil, 2), []byte("SETUP")))
			case "impossible phase":
				qualRecordPut(t, f.x.f.store, lrcKey, qualRecordFrame(token, epoch, []byte("WIND_DOWN")))
			case "missing member":
				qualRecordPut(t, f.x.f.store, append([]byte(registryMemberKeyPrefix), token...), nil)
			case "wrong closure":
				f.h.fields.closurePlan = []byte("wrong")
			case "wrong type":
				f.h.fields.tokenType = uint32(core.SemiFungible)
			case "short origin":
				f.h.fields.supplyOrigin = []byte{1}
			case "wrong origin shard":
				f.h.fields.supplyOriginShard = 3
			}
			called := 0
			err := f.read(func(lifecycleReadView) (*vmcommon.VMOutput, error) { called++; return nil, nil })
			require.Error(t, err)
			require.Zero(t, called)
			if mode == "bootstrap" || mode == "retired" {
				require.ErrorIs(t, err, errLifecycleClosed)
				require.Zero(t, f.h.calls["current"])
			}
			if mode == "wrong closure" || mode == "wrong type" || mode == "short origin" || mode == "wrong origin shard" {
				require.ErrorIs(t, err, errCurrentLifecycle)
				require.Equal(t, 1, f.h.calls["fields"])
			}
		})
	}
}

func TestQualDRWACurrentLifecycleCallbackAndDependencyInvalidation(t *testing.T) {
	for _, mode := range []string{"consumer refusal", "lifecycle", "current pointer", "intent", "projection"} {
		t.Run(mode, func(t *testing.T) {
			f := qualLifecycleNew(t)
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			sentinel := errors.New("dependent operation refused")
			calls := 0
			var output *vmcommon.VMOutput
			err = f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = f.r.withCurrent(f.context, []byte("TOKEN-abcdef"), 1, f.hash, func(lifecycleReadView) (*vmcommon.VMOutput, error) {
					calls++
					token := []byte("TOKEN-abcdef")
					switch mode {
					case "consumer refusal":
						return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, sentinel
					case "lifecycle":
						qualRecordPut(t, f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...), qualRecordFrame(token, binary.BigEndian.AppendUint64(nil, 1), []byte("OPEN")))
					case "current pointer":
						qualRecordPut(t, f.x.f.store, append([]byte(currentLocalPointerPrefix), qualRecordFrame(token)...), qualRecordFrame(binary.BigEndian.AppendUint64(nil, 2), f.hash))
					case "intent":
						qualRecordPut(t, f.x.f.store, append([]byte(registrationIntentPrefix), f.x.f.owner.id...), []byte("changed"))
					case "projection":
						f.h.fields.supplyOrigin = bytes.Repeat([]byte{9}, 32)
					}
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
				})
				return output, e
			})
			require.Error(t, err)
			require.Nil(t, output)
			require.Equal(t, 1, calls)
			if mode == "consumer refusal" {
				require.ErrorIs(t, err, sentinel)
			}
			if mode == "lifecycle" || mode == "intent" || mode == "projection" {
				require.ErrorIs(t, err, errCurrentLifecycle)
			}
			if mode == "current pointer" {
				require.ErrorIs(t, err, errCurrentLocalDependency)
			}
			after, e := f.x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
		})
	}
}

func TestQualDRWACurrentLifecycleVerifierMutationAndRefusal(t *testing.T) {
	for _, stage := range []string{"current", "fields", "lifecycle"} {
		for _, mutation := range []bool{false, true} {
			t.Run(stage+"/"+map[bool]string{false: "refusal", true: "mutation"}[mutation], func(t *testing.T) {
				f := qualLifecycleNew(t)
				sentinel := errors.New("native current lifecycle verifier unavailable")
				if mutation {
					f.h.hooks[stage] = func() { qualRecordPut(t, f.x.f.store, []byte("fixture/reader-mutation"), []byte{1}) }
				} else {
					f.h.faults[stage] = sentinel
				}
				root, err := f.x.f.store.RootHash()
				require.NoError(t, err)
				root = bytes.Clone(root)
				calls := 0
				err = f.read(func(lifecycleReadView) (*vmcommon.VMOutput, error) {
					calls++
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
				})
				require.Error(t, err)
				if mutation {
					require.ErrorIs(t, err, errInvalidRegistrationRecord)
				} else {
					require.ErrorIs(t, err, sentinel)
				}
				require.Zero(t, calls)
				require.Equal(t, 1, f.h.calls[stage])
				after, e := f.x.f.store.RootHash()
				require.NoError(t, e)
				require.Equal(t, root, after)
			})
		}
	}
}

func TestQualDRWACurrentLifecycleOwningOperationAndLocus(t *testing.T) {
	f := qualLifecycleNew(t)
	calls := 0
	consume := func(lifecycleReadView) (*vmcommon.VMOutput, error) {
		calls++
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}
	out, err := f.r.withCurrent(f.context, []byte("TOKEN-abcdef"), 1, f.hash, consume)
	require.ErrorIs(t, err, errCurrentLifecycle)
	require.Nil(t, out)
	other, err := sharding.NewMultiShardCoordinator(3, 1)
	require.NoError(t, err)
	f.r.coordinator = other
	require.ErrorIs(t, f.read(consume), errCurrentLifecycle)
	require.Zero(t, calls)
}

func TestQualDRWACurrentLifecycleExecutionShardUsesReplicatedBundle(t *testing.T) {
	f := qualLifecycleNew(t)
	// Synthetic local replica: the approved metachain intent is not another
	// required holder-shard record or a remote hot-path query dependency.
	qualRecordPut(t, f.x.f.store, append([]byte(registrationAssociationPrefix), []byte("TOKEN-abcdef")...), nil)
	qualRecordPut(t, f.x.f.store, append([]byte(registrationIntentPrefix), f.x.f.owner.id...), nil)
	hook, _ := qualT42Hook(t, f.x.f.store, 1, true)
	_, end := qualT42Install(t, hook, 1, 1)
	defer end()
	coord, err := sharding.NewMultiShardCoordinator(3, 1)
	require.NoError(t, err)
	f.r, err = newCurrentLifecycleReader(f.r.current, f.x.f.boundary, hook, coord)
	require.NoError(t, err)
	f.context, err = hook.EvaluatedHeaderTimeContext()
	require.NoError(t, err)
	calls := 0
	require.NoError(t, f.read(func(view lifecycleReadView) (*vmcommon.VMOutput, error) {
		calls++
		require.Equal(t, "Active", view.activation)
		require.Equal(t, "SETUP", view.lifecycle)
		require.Equal(t, f.h.fields.supplyOrigin, view.supplyOrigin)
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	}))
	require.Equal(t, 1, calls)
	require.Equal(t, 2, f.h.calls["lifecycle"])
}

func TestQualDRWACurrentLifecycleRequiresFullDecoderAndOwner(t *testing.T) {
	f := qualLifecycleNew(t)
	partial := *f.r.current
	partial.host = f.h.qualCurrentLocalHost // Existing CEB host alone lacks lifecycle proofs.
	r, err := newCurrentLifecycleReader(&partial, f.x.f.boundary, f.x.f.hook, f.r.coordinator)
	require.ErrorIs(t, err, errCurrentLifecycle)
	require.Nil(t, r)
	foreign, err := NewRollbackContainment(qualRegistrationStore(t, 0))
	require.NoError(t, err)
	r, err = newCurrentLifecycleReader(f.r.current, foreign, f.x.f.hook, f.r.coordinator)
	require.ErrorIs(t, err, errCurrentLifecycle)
	require.Nil(t, r)
	other := qualGovernedContext(t, qualHeaderTimeOwner(t), core.MetachainShardId, 1)
	calls := 0
	err = f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return f.r.withCurrent(other, []byte("TOKEN-abcdef"), 1, f.hash, func(lifecycleReadView) (*vmcommon.VMOutput, error) { calls++; return nil, nil })
	})
	require.ErrorIs(t, err, ErrInactiveHeaderTime)
	require.Zero(t, calls)
}

// Metadata-only availability. The canonical projection is synthetic; this does
// not perform or authorize any of these lifecycle transitions or value routes.
func TestQualDRWACurrentLifecycleAllMetadataPairs(t *testing.T) {
	valid := map[string]map[string]bool{
		"Active":       {"SETUP": true, "SETUP_SEALED": true, "OPEN": true, "REQUALIFYING": true},
		"WindDownDeny": {"WIND_DOWN": true, "WIND_DOWN_SEALED": true},
	}
	for _, activation := range []string{"Active", "WindDownDeny", "BootstrapDeny", "RetiredDeny", "unknown"} {
		for _, phase := range []string{"SETUP", "SETUP_SEALED", "OPEN", "REQUALIFYING", "WIND_DOWN", "WIND_DOWN_SEALED", "RETIRED", "unknown"} {
			require.Equal(t, valid[activation][phase], validCurrentLifecyclePair(activation, phase), activation+"/"+phase)
		}
	}
	for _, pair := range [][2]string{{"Active", "SETUP"}, {"Active", "SETUP_SEALED"}, {"Active", "OPEN"}, {"Active", "REQUALIFYING"}, {"WindDownDeny", "WIND_DOWN"}, {"WindDownDeny", "WIND_DOWN_SEALED"}} {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			f := qualLifecycleNew(t)
			token := []byte("TOKEN-abcdef")
			qualRecordPut(t, f.x.f.store, append([]byte(registrationActivationPrefix), token...), qualLifecycleParent(token, f.x.f.owner.id, pair[0]))
			qualRecordPut(t, f.x.f.store, append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...), qualRecordFrame(token, binary.BigEndian.AppendUint64(nil, 1), []byte(pair[1])))
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := f.x.f.store.JournalLen()
			calls := 0
			require.NoError(t, f.read(func(view lifecycleReadView) (*vmcommon.VMOutput, error) {
				calls++
				require.Equal(t, pair[0], view.activation)
				require.Equal(t, pair[1], view.lifecycle)
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}))
			require.Equal(t, 1, calls)
			after, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.x.f.store.JournalLen())
		})
	}
}

func TestQualDRWACurrentLifecycleUnavailableConstruction(t *testing.T) {
	f := qualLifecycleNew(t)
	root, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal := f.x.f.store.JournalLen()
	for _, mode := range []string{"nil current", "missing codec", "missing state", "missing accounts", "missing hasher", "missing marshaller", "missing boundary", "missing time", "missing coordinator"} {
		current := *f.r.current
		codec := *current.codec
		current.codec = &codec
		boundary, source, coordinator := f.r.boundary, f.r.source, f.r.coordinator
		candidate := &current
		switch mode {
		case "nil current":
			candidate = nil
		case "missing codec":
			current.codec = nil
		case "missing state":
			codec.state = nil
		case "missing accounts":
			stateCopy := *codec.state
			stateCopy.accounts = nil
			codec.state = &stateCopy
		case "missing hasher":
			codec.hasher = nil
		case "missing marshaller":
			codec.marshaller = nil
		case "missing boundary":
			boundary = nil
		case "missing time":
			source = nil
		case "missing coordinator":
			coordinator = nil
		}
		got, e := newCurrentLifecycleReader(candidate, boundary, source, coordinator)
		require.ErrorIs(t, e, errCurrentLifecycle, mode)
		require.Nil(t, got)
	}
	after, err := f.x.f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, f.x.f.store.JournalLen())
}

func TestQualDRWACurrentLifecycleLateProviderRefusalRollsBack(t *testing.T) {
	for _, stage := range []string{"current", "lifecycle", "fields"} {
		t.Run(stage, func(t *testing.T) {
			f := qualLifecycleNew(t)
			key := []byte("fixture/lifecycle-dependent-write")
			require.Empty(t, qualActivationValue(t, f.x.f.store, key))
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := f.x.f.store.JournalLen()
			sentinel := errors.New("late owning lifecycle provider refused")
			observedDirty := false
			f.h.hooks[stage] = func() {
				if f.h.calls[stage] == 2 {
					require.Equal(t, []byte{7}, qualActivationValue(t, f.x.f.store, key))
					require.Greater(t, f.x.f.store.JournalLen(), journal)
					observedDirty = true
					f.h.faults[stage] = sentinel
				}
			}
			calls := 0
			var output *vmcommon.VMOutput
			err = f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = f.r.withCurrent(f.context, []byte("TOKEN-abcdef"), 1, f.hash, func(lifecycleReadView) (*vmcommon.VMOutput, error) {
					calls++
					qualRecordPut(t, f.x.f.store, key, []byte{7})
					return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
				})
				return output, e
			})
			require.Same(t, sentinel, err)
			require.Nil(t, output)
			require.Equal(t, 1, calls)
			require.Equal(t, 2, f.h.calls[stage])
			require.True(t, observedDirty)
			require.Empty(t, qualActivationValue(t, f.x.f.store, key))
			after, e := f.x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.x.f.store.JournalLen())
		})
	}
}

func TestQualDRWACurrentLifecycleMalformedBindingRefusesBeforeConsumer(t *testing.T) {
	for _, mode := range []string{"bad token", "short hash", "zero epoch", "nil context", "nil reader", "nil consumer", "activation malformed", "activation foreign token", "activation short intent", "activation unknown", "activation foreign intent", "lifecycle foreign token", "lifecycle malformed", "lifecycle short epoch"} {
		t.Run(mode, func(t *testing.T) {
			f := qualLifecycleNew(t)
			token, epoch, hash := []byte("TOKEN-abcdef"), uint64(1), bytes.Clone(f.hash)
			context, reader := f.context, f.r
			activationKey := append([]byte(registrationActivationPrefix), token...)
			phaseKey := append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...)
			switch mode {
			case "bad token":
				token = []byte("invalid")
			case "short hash":
				hash = []byte{1}
			case "zero epoch":
				epoch = 0
			case "nil context":
				context = nil
			case "nil reader":
				reader = nil
			case "activation malformed":
				qualRecordPut(t, f.x.f.store, activationKey, []byte{255})
			case "activation foreign token":
				qualRecordPut(t, f.x.f.store, activationKey, qualLifecycleParent([]byte("OTHER-abcdef"), f.x.f.owner.id, "Active"))
			case "activation short intent":
				qualRecordPut(t, f.x.f.store, activationKey, qualLifecycleParent(token, []byte{1}, "Active"))
			case "activation unknown":
				qualRecordPut(t, f.x.f.store, activationKey, qualLifecycleParent(token, f.x.f.owner.id, "unknown"))
			case "activation foreign intent":
				qualRecordPut(t, f.x.f.store, activationKey, qualLifecycleParent(token, bytes.Repeat([]byte{9}, len(f.x.f.owner.id)), "Active"))
			case "lifecycle foreign token":
				qualRecordPut(t, f.x.f.store, phaseKey, qualRecordFrame([]byte("OTHER-abcdef"), binary.BigEndian.AppendUint64(nil, 1), []byte("SETUP")))
			case "lifecycle malformed":
				qualRecordPut(t, f.x.f.store, phaseKey, []byte{255})
			case "lifecycle short epoch":
				qualRecordPut(t, f.x.f.store, phaseKey, qualRecordFrame(token, []byte{1}, []byte("SETUP")))
			}
			calls := 0
			consume := func(lifecycleReadView) (*vmcommon.VMOutput, error) {
				calls++
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			}
			if mode == "nil consumer" {
				consume = nil
			}
			root, err := f.x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal := f.x.f.store.JournalLen()
			var output *vmcommon.VMOutput
			err = f.x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
				var e error
				output, e = reader.withCurrent(context, token, epoch, hash, consume)
				return output, e
			})
			require.ErrorIs(t, err, errCurrentLifecycle)
			require.Nil(t, output)
			require.Zero(t, calls)
			after, e := f.x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.x.f.store.JournalLen())
		})
	}
}
