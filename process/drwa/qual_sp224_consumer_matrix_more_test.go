package drwa

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/sharding"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// The remaining SP2-24 consumers. Fixtures that install their own evaluation
// are given a second real hook over the same accounts adapter, with no
// evaluation active, so that every case starts from "no context".

// qualSP224SignAdmission signs the eight registration purposes for one header
// time, as the fixture does for time 1, and rebinds the admission.
func qualSP224SignAdmission(t *testing.T, f *qualRegistrationAdmissionFixture, at uint64) {
	t.Helper()
	var evidence [][]byte
	for _, purpose := range qualRegistrationPurposes {
		role := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
		role.digest = blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte(purpose), f.verify.id, f.verify.intentHash, f.verify.body, f.v.bodyHash,
			binary.BigEndian.AppendUint64(nil, at), []byte{0, 0, 0, 10})))
		role.sign(t)
		f.verify.roles[purpose] = role
		evidence = append(evidence, qualRecordFrame(role.signatures...))
	}
	f.proofs = RegistrationProofs{evidence[0], evidence[1], evidence[2], evidence[3], evidence[4], evidence[5], evidence[6], evidence[7]}
	var err error
	f.admit, err = f.owner.WithRegistrationAdmission(f.hook, []byte("n"), 10, RegistrationResourceLimits{1000, 1048576, 100},
		&qualSP224RegistrationVerifier{base: f.verify, at: HeaderMilliseconds(at)}, f.proofs)
	require.NoError(t, err)
}

// qualSP224RegistrationVerifier is the fixture verifier of the admission tests
// for a chosen header time: it accepts only that time, epoch 10 and signatures
// made over that time. (The fixture's own verifier is fixed to time 1.)
type qualSP224RegistrationVerifier struct {
	base *qualRegistrationVerifier
	at   HeaderMilliseconds
}

func (v *qualSP224RegistrationVerifier) IsInterfaceNil() bool { return v == nil }
func (v *qualSP224RegistrationVerifier) VerifyRegistration(purpose string, id, digest, body, creation, proof []byte, at HeaderMilliseconds, epoch uint32) error {
	role, exists := v.base.roles[purpose]
	if !exists || at != v.at || epoch != 10 || !bytes.Equal(id, v.base.id) || !bytes.Equal(digest, v.base.intentHash) ||
		!bytes.Equal(body, v.base.body) || !bytes.Equal(creation, v.base.creation) {
		return errInvalidRegistrationRecord
	}
	decoded := &batch.Batch{}
	if (&marshal.GogoProtoMarshalizer{}).Unmarshal(decoded, proof) != nil {
		return errInvalidRegistrationRecord
	}
	bound := blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte(purpose), id, digest, body, creation,
		binary.BigEndian.AppendUint64(nil, uint64(at)), []byte{0, 0, 0, 10})))
	return verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", 3, role.members, []uint64{0, 1, 2}, decoded.Data, bound, 5, 32)
}

// qualSP224ProofProvider is the fixture provider of the proof-mechanics tests
// for a chosen header time. (The fixture's own provider is fixed to time 50.)
type qualSP224ProofProvider struct {
	base *qualBootstrapProofProvider
	at   HeaderMilliseconds
}

func (p *qualSP224ProofProvider) IsInterfaceNil() bool { return p == nil }
func (p *qualSP224ProofProvider) VerifyBootstrapBinding(b bootstrapProofBinding, id, digest []byte, at HeaderMilliseconds, epoch uint32) error {
	if !reflect.DeepEqual(p.base.expected, b) || !bytes.Equal(p.base.id, id) || !bytes.Equal(p.base.digest, digest) || at != p.at || epoch != 10 {
		return errInvalidRegistrationRecord
	}
	return nil
}

type qualSP224BootstrapVerifier struct {
	base *qualRegistrationVerifier
	at   HeaderMilliseconds
}

func (v *qualSP224BootstrapVerifier) IsInterfaceNil() bool { return v == nil }
func (v *qualSP224BootstrapVerifier) VerifyRegistration(p string, id, digest, body, creation, proof []byte, at HeaderMilliseconds, epoch uint32) error {
	if p != "BOOTSTRAP_INTENT" || !bytes.Equal(id, v.base.id) || !bytes.Equal(digest, v.base.intentHash) ||
		!bytes.Equal(body, v.base.body) || len(creation) != 0 || !bytes.Equal(proof, []byte("explicit-step1-mandate")) || at != v.at || epoch != 10 {
		return errInvalidRegistrationRecord
	}
	return nil
}

// signedAt is the header time the synthetic proofs are made for; the intent
// itself expires after time 1.
func qualSP224RegistrationConsumer(t *testing.T, operation string, signedAt uint64) *qualSP224Consumer {
	t.Helper()
	f := qualRegistrationAdmission(t, core.FungibleESDT)
	f.end()
	c := &qualSP224Consumer{hook: f.hook, shard: core.MetachainShardId, store: f.store, at: 1, ownLookup: true}
	if operation == "creation" {
		qualSP224SignAdmission(t, f, signedAt)
		c.run = func(*HeaderTimeContext) error { return f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")) }
		return c
	}
	// Retention of a new OPEN intent: no intent record yet, an empty budget.
	f.admit.verifier = &qualSP224BootstrapVerifier{base: f.verify, at: HeaderMilliseconds(signedAt)}
	budgetKey := []byte(scopedAdmissionPrefix + "budget")
	budget := bytes.Clone(qualRegistryValue(t, f.store, string(budgetKey)))
	qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), f.owner.id...), nil)
	binary.BigEndian.PutUint64(budget, 1)
	binary.BigEndian.PutUint64(budget[8:], uint64(len(budgetKey)+32))
	qualRecordPut(t, f.store, budgetKey, budget)
	c.run = func(*HeaderTimeContext) error {
		return f.admit.RetainBootstrapIntent(f.verify.body, []byte("explicit-step1-mandate"))
	}
	return c
}

func qualSP224CancellationConsumer(t *testing.T) (*qualSP224Consumer, *qualT46Fixture) {
	t.Helper()
	x := qualT46New(t, core.FungibleESDT)
	x.f.end()
	return &qualSP224Consumer{hook: x.f.hook, shard: core.MetachainShardId, store: x.f.store, at: 100, ownLookup: true,
		run: func(*HeaderTimeContext) error { return x.cancel(x.f.owner.id) }}, x
}

func qualSP224BootstrapProofConsumer(t *testing.T) *qualSP224Consumer {
	return qualSP224BootstrapProofAt(t, 50)
}

func qualSP224BootstrapProofAt(t *testing.T, at uint64) *qualSP224Consumer {
	t.Helper()
	codec, boundary, hook, _, fixed, binding, raw, end := qualBootstrapMechanicsFixture(t)
	end()
	provider := &qualSP224ProofProvider{base: fixed, at: HeaderMilliseconds(at)}
	return &qualSP224Consumer{hook: hook, shard: core.MetachainShardId, store: hook.GetAccountsAdapter(), at: 50,
		run: func(context *HeaderTimeContext) error {
			return boundary.executeOwned(func(operation *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				return nil, qualVerifyBootstrapMechanics(codec, operation, boundary, hook, context, provider, binding, raw)
			})
		}}
}

func qualSP224LifecycleConsumer(t *testing.T) *qualSP224Consumer {
	t.Helper()
	f := qualLifecycleNew(t)
	hook, _ := qualT42Hook(t, f.x.f.store, core.MetachainShardId, true)
	var err error
	f.r, err = newCurrentLifecycleReader(f.r.current, f.x.f.boundary, hook, f.r.coordinator)
	require.NoError(t, err)
	return &qualSP224Consumer{hook: hook, shard: core.MetachainShardId, store: f.x.f.store, at: 1,
		run: func(context *HeaderTimeContext) error {
			f.context = context
			return f.read(func(lifecycleReadView) (*vmcommon.VMOutput, error) {
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			})
		}}
}

func qualSP224SetupConsumer(t *testing.T) *qualSP224Consumer {
	t.Helper()
	f, _, host := qualSetupNew(t, uint32(core.Fungible), true, true)
	self := f.r.coordinator.SelfId()
	hook, _ := qualT42Hook(t, f.x.f.store, self, true)
	coordinator, err := sharding.NewMultiShardCoordinator(3, self)
	require.NoError(t, err)
	f.r, err = newCurrentLifecycleReader(f.r.current, f.x.f.boundary, hook, coordinator)
	require.NoError(t, err)
	setup, err := newSetupInitialization(f.r, host, 32)
	require.NoError(t, err)
	return &qualSP224Consumer{hook: hook, shard: self, store: f.x.f.store, at: 1,
		run: func(context *HeaderTimeContext) error { f.context = context; return qualSetupExecute(f, setup) }}
}

func qualSP224SupplyConsumer(t *testing.T) *qualSP224Consumer {
	t.Helper()
	w := qualOwnedSupplyNew(t, core.Fungible)
	_, err := w.db.Commit()
	require.NoError(t, err)
	w.owner, err = NewRollbackContainment(w.db)
	require.NoError(t, err)
	self := w.args.ShardCoordinator.SelfId()
	hook, _ := qualT42Hook(t, w.db, self, true)
	current, err := newCurrentLocalDependencies(w.db, w.args.Marshalizer, w.setup.r.current.codec.hasher, 4096, 10, w.setup.h)
	require.NoError(t, err)
	lifecycle, err := newCurrentLifecycleReader(current, w.owner, hook, w.args.ShardCoordinator)
	require.NoError(t, err)
	w.host = &qualLocalSetupHost{t: t, f: w.setup}
	w.reader, err = newSetupLocalStateReader(lifecycle, w.host, 32)
	require.NoError(t, err)
	w.refresh(t)
	mint := w.input(core.BuiltInFunctionESDTLocalMint, w.origin, w.origin, w.token, []byte{5})
	return &qualSP224Consumer{hook: hook, shard: self, store: w.db, at: 1,
		run: func(context *HeaderTimeContext) error {
			w.setup.context = context
			return w.supply(t, mint, 0, big.NewInt(5))
		}}
}

// The authority check owns its time source (owner decision D-3): the hook here.
// The reader's view must carry the hook's current context.
func qualSP224AuthorityConsumer(t *testing.T, all []qualSP227Binding, use scopedAuthorityUse, phase scopedAuthorityPhase, wants []scopedAuthorityRequirement) *qualSP224Consumer {
	t.Helper()
	f := qualSP227ConstitutionNew(t, all, qualSP227Programmes(all)[0])
	f.r.use, f.r.phase = use, phase
	f.bindRequest()
	store := qualRegistrationStore(t, 0)
	hook, _ := qualT42Hook(t, store, core.MetachainShardId, true)
	return &qualSP224Consumer{hook: hook, shard: core.MetachainShardId, store: store, at: 110,
		run: func(context *HeaderTimeContext) error {
			f.source = hook
			f.s.v.time = context
			return f.verify(f.sign(t, wants))
		}}
}

func TestQualSP224RegistrationRefusesEveryOtherContext(t *testing.T) {
	for _, operation := range []string{"creation", "retain_intent"} {
		t.Run(operation, func(t *testing.T) {
			qualSP224Refusals(t, func(t *testing.T) *qualSP224Consumer { return qualSP224RegistrationConsumer(t, operation, 1) })
		})
	}
	t.Run("cancellation", func(t *testing.T) {
		qualSP224Refusals(t, func(t *testing.T) *qualSP224Consumer { c, _ := qualSP224CancellationConsumer(t); return c })
	})
	t.Run("bootstrap_proof", func(t *testing.T) { qualSP224Refusals(t, qualSP224BootstrapProofConsumer) })
}

func TestQualSP224LocalReadersRefuseEveryOtherContext(t *testing.T) {
	t.Run("current_lifecycle", func(t *testing.T) { qualSP224Refusals(t, qualSP224LifecycleConsumer) })
	t.Run("setup_initialization", func(t *testing.T) { qualSP224Refusals(t, qualSP224SetupConsumer) })
	t.Run("supply_operation", func(t *testing.T) { qualSP224Refusals(t, qualSP224SupplyConsumer) })
}

func TestQualSP224AuthorityCheckRefusesEveryOtherContext(t *testing.T) {
	all := qualSP227Rosters(t)
	pa, pr := qualSP227Want(scopedPA, "approval", scopedCurrent), qualSP227Want(scopedPR, "approval", scopedCurrent)
	t.Run("authorize", func(t *testing.T) {
		qualSP224Refusals(t, func(t *testing.T) *qualSP224Consumer {
			return qualSP224AuthorityConsumer(t, all, scopedCEBChange, scopedAuthorize, []scopedAuthorityRequirement{pa, pr})
		})
	})
	t.Run("direct", func(t *testing.T) {
		qualSP224Refusals(t, func(t *testing.T) *qualSP224Consumer {
			return qualSP224AuthorityConsumer(t, all, scopedEmergencyAdd, scopedDirect, []scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)})
		})
	})
}

func TestQualSP224MoreConsumerBoundsWithTheNativeContext(t *testing.T) {
	all := qualSP227Rosters(t)
	pa, pr := qualSP227Want(scopedPA, "approval", scopedCurrent), qualSP227Want(scopedPR, "approval", scopedCurrent)
	type row struct {
		name     string
		build    func(t *testing.T, time uint64) *qualSP224Consumer
		admitted map[uint64]bool
	}
	rows := []row{
		// The OPEN intent expires after time 1 (inclusive). The synthetic proofs
		// are made for the tested time, so only the expiry decides. Time 0 is no
		// coordinate (owner decision D-1); every consumer's refusal of it is in
		// qualSP224Refusals.
		{"registration_creation_intent_expiry", func(t *testing.T, time uint64) *qualSP224Consumer {
			return qualSP224RegistrationConsumer(t, "creation", time)
		},
			map[uint64]bool{1: true, 2: false}},
		{"registration_retain_intent_expiry", func(t *testing.T, time uint64) *qualSP224Consumer {
			return qualSP224RegistrationConsumer(t, "retain_intent", time)
		}, map[uint64]bool{1: true, 2: false}},
		// Certificate window 10..90, inclusive at both ends.
		{"bootstrap_proof_window", func(t *testing.T, time uint64) *qualSP224Consumer { return qualSP224BootstrapProofAt(t, time) },
			map[uint64]bool{9: false, 10: true, 11: true, 89: true, 90: true, 91: false}},
		// Authority certificates 100..120 inclusive; the start window of an
		// authorisation is 105 inclusive to 120 exclusive.
		{"authority_certificate_window", func(t *testing.T, _ uint64) *qualSP224Consumer {
			return qualSP224AuthorityConsumer(t, all, scopedEmergencyAdd, scopedDirect, []scopedAuthorityRequirement{qualSP227Want(scopedEA, "add", scopedCurrent)})
		}, map[uint64]bool{99: false, 100: true, 101: true, 119: true, 120: true, 121: false}},
		{"authority_start_window", func(t *testing.T, _ uint64) *qualSP224Consumer {
			return qualSP224AuthorityConsumer(t, all, scopedCEBChange, scopedAuthorize, []scopedAuthorityRequirement{pa, pr})
		}, map[uint64]bool{104: false, 105: true, 106: true, 119: true, 120: false, 121: false}},
	}
	for _, r := range rows {
		for time, admitted := range r.admitted {
			t.Run(fmt.Sprintf("%s/%d", r.name, time), func(t *testing.T) {
				err := qualSP224At(t, r.build(t, time), time)
				if admitted {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			})
		}
	}
}

// Activation by header epoch at its bound, for the two consumers that compare
// the evaluated header's epoch with a configured enforcement epoch.
func TestQualSP224EnforcementEpochBoundWithTheNativeContext(t *testing.T) {
	for _, enable := range []uint32{9, 10, 11} {
		t.Run(fmt.Sprintf("creation/%d", enable), func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT) // evaluated header: epoch 10, time 1
			f.admit.enableEpoch = enable
			root, journal := qualSP224State(t, f.store)
			err := f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef"))
			if enable <= 10 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			after, afterJournal := qualSP224State(t, f.store)
			require.Equal(t, root, after)
			require.Equal(t, journal, afterJournal)
		})
		t.Run(fmt.Sprintf("cancellation/%d", enable), func(t *testing.T) {
			c, x := qualSP224CancellationConsumer(t)
			x.c.enableEpoch = enable
			err := qualSP224At(t, c, 100)
			if enable <= 10 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
