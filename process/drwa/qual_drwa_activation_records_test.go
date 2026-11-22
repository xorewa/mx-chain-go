package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/data/batch"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Native storage, T04/time, framing and existing registration are exercised.
// Genesis interpretation, activation authority and ACK canonicality are
// SYNTHETIC. No actual class/constitution/profile/codec is admitted by this test.
type qualActivationHost struct {
	f       *qualRegistrationAdmissionFixture
	genesis []byte
	view    activationGenesis
	err     error
	hook    func()
	calls   int
}

func (h *qualActivationHost) IsInterfaceNil() bool { return h == nil }
func (h *qualActivationHost) VerifyActivation(domain, token, id, body, genesis, certificates []byte,
	at HeaderMilliseconds, epoch uint32) (activationGenesis, error) {
	h.calls++
	if !bytes.Equal(domain, []byte("n")) || !bytes.Equal(token, []byte("TOKEN-abcdef")) ||
		!bytes.Equal(id, h.f.owner.id) || !bytes.Equal(body, h.f.verify.body) ||
		!bytes.Equal(genesis, h.genesis) || !bytes.Equal(certificates, []byte("synthetic-complete-activation-proof")) || at != 1 || epoch != 10 {
		return activationGenesis{}, errActivationRecord
	}
	if h.hook != nil {
		h.hook()
	}
	// Borrowed callback arguments do not alias the state about to be stored.
	genesis[0] ^= 1
	id[0] ^= 1
	certificates[0] ^= 1
	return h.view, h.err
}

type qualActivationFixture struct {
	f       *qualRegistrationAdmissionFixture
	h       *qualActivationHost
	a       *activationRecords
	g       *governedActionRecords
	gh      *qualGovernedActionHost
	acks    []RegistrationStateAck
	ackHost *qualRegistrationAckVerifier
	genesis []byte
}

func qualActivationNew(t *testing.T) *qualActivationFixture {
	t.Helper()
	return qualActivationForPlan(t, "burn-and-retire")
}

func qualActivationForPlan(t *testing.T, plan string) *qualActivationFixture {
	t.Helper()
	f := qualRegistrationAdmissionForPlan(t, core.FungibleESDT, plan)
	require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
	return qualActivationAfterRegistration(t, f)
}

func qualActivationAfterRegistration(t *testing.T, f *qualRegistrationAdmissionFixture) *qualActivationFixture {
	t.Helper()
	// Preserve registration as its own committed prestate before activation.
	_, _, err := f.boundary.Commit()
	require.NoError(t, err)
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = core.MetachainShardId
	r, boundary, err := NewRegistryRegistration(f.store, coordinator, 2)
	require.NoError(t, err)
	old := f.owner
	f.owner, err = r.BindIntent(old.id, old.digest, old.manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f.boundary = boundary
	f.admit, err = f.owner.WithRegistrationAdmission(f.hook, []byte("n"), 10, RegistrationResourceLimits{1000, 1048576, 100}, f.verify, f.proofs)
	require.NoError(t, err)
	x := &qualActivationFixture{f: f, genesis: []byte("synthetic-complete-genesis-body")}
	x.acks, x.ackHost = qualRegistrationAcks(t, f)
	x.gh = &qualGovernedActionHost{store: f.store, faults: make(map[string]error), hooks: make(map[string]func())}
	x.g, err = newGovernedActionRecords(f.store, boundary, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096,
		[]byte("n"), 4, 2, 2, x.gh, f.hook)
	require.NoError(t, err)
	x.h = &qualActivationHost{f: f, genesis: bytes.Clone(x.genesis), view: activationGenesis{
		token: []byte("TOKEN-abcdef"), closurePlan: bytes.Clone(f.body.closurePlan), epoch: 1,
		classes: []activationActionClass{{[]byte("TOKEN-abcdef"), []byte("synthetic-token-class")}, {bytes.Clone(f.body.programID), []byte("synthetic-program-class")}},
	}}
	x.a, err = newActivationRecords(f.admit, x.g, x.h)
	require.NoError(t, err)
	return x
}

func qualActivationValue(t *testing.T, s *qualNativeStore, key []byte) []byte {
	t.Helper()
	return qualRegistryValue(t, s, string(key))
}

func TestQualDRWAActivationWritesDurableReadinessParent(t *testing.T) {
	for _, mode := range []string{"full", "full-preserve", "burn-to-preserve", "preserve-to-burn", "partial", "foreign", "wrong-phase", "missing-funding", "native-parent-error", "tampered-parent", "tampered-setup", "late-original-error"} {
		t.Run(mode, func(t *testing.T) {
			// K.13 binds the genesis plan to the token's consumed intent.
			// Vary the two valid plans while holding the readiness proof fixed.
			registeredPlan := "burn-and-retire"
			if mode == "full-preserve" || mode == "preserve-to-burn" {
				registeredPlan = "preserve-and-close"
			}
			x := qualActivationForPlan(t, registeredPlan)
			t.Cleanup(x.f.end)
			s, owner := x.f.store, x.f.boundary
			ctx, err := x.f.hook.EvaluatedHeaderTimeContext()
			require.NoError(t, err)
			token, id := []byte("TOKEN-abcdef"), x.f.owner.id
			activationKey := append([]byte(registrationActivationPrefix), token...)
			lrcKey := append([]byte(lifecycleRecordPrefix), qualRecordFrame(token)...)
			h := blake2b.NewBlake2b()
			set := qualRecordFrame([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 1}, []byte{0, 0, 0, 2})
			beforeActivation := qualRecordFrame(token, id, []byte("BootstrapDeny"))
			target := h.Compute(string(qualRecordFrame(beforeActivation, x.f.body.requestedTokenFamily, x.f.body.creationProfile, x.f.owner.manager, []byte{1})))
			association := qualActivationValue(t, s, append([]byte(registrationAssociationPrefix), token...))
			lineage := qualRecordFrame(x.f.body.networkDomain, token, id, x.f.owner.digest, []byte("CONSUMED"))
			tr := convergenceTransition{action: id, digest: x.f.owner.digest, token: token, version: 1, target: target,
				dependencies: bytes.Repeat([]byte{0x5b}, 32), requiredSet: h.Compute(string(set)), shards: []uint32{0, 1, 2},
				context: &convergencePhaseContext{family: []byte("BOOTSTRAP_READINESS"), phase: []byte("TYPE_PROFILE_READINESS"), lineage: lineage,
					predecessor: h.Compute(string(association))}}
			binding := qualRecordFrame(tr.context.family, id, tr.digest, tr.context.phase, token, qualA38U64(1), tr.target, tr.dependencies,
				tr.requiredSet, set, tr.context.lineage, tr.context.predecessor)
			key := append([]byte(convergencePrefix), qualRecordFrame(tr.context.family, id, tr.context.phase, tr.context.lineage)...)
			phaseHost := &qualConvergenceHost{t: t, store: s, binding: binding, key: key, acks: make(map[string]uint32),
				faults: make(map[string]error), hooks: make(map[string]func())}
			readiness, err := newConvergenceRecords(s, owner, x.f.owner.records.marshaller, h, 4096, 3, phaseHost)
			require.NoError(t, err)
			require.NoError(t, readiness.create(tr))
			acks := make([][]byte, 3)
			for i, shard := range tr.shards {
				if mode == "partial" && shard == 2 {
					break
				}
				local := bytes.Repeat([]byte{byte(i + 7)}, 32)
				ack := qualRecordFrame(binding, binary.BigEndian.AppendUint32(nil, shard), local)
				phaseHost.acks[string(ack)] = shard
				acks[i] = h.Compute(string(ack))
				require.NoError(t, readiness.acknowledge(tr, shard, local, []byte("synthetic-S-R-H-M-B-proof")))
			}
			c := h.Compute(string(qualRecordFrame(binding, []byte{7}, qualRecordFrame(acks...))))
			want := qualRecordFrame(token, id, []byte("Active"), c)
			beforeRoot, err := s.RootHash()
			require.NoError(t, err)
			beforeK, beforeJournal, baseOutputs := qualActivationValue(t, s, key), s.JournalLen(), len(owner.outputs)
			refuse := errors.New("injected native activation proof or funding refusal")
			late := errors.New("late original activation failure")
			original := owner
			switch mode {
			case "burn-to-preserve":
				x.h.view.closurePlan = []byte("preserve-and-close")
			case "preserve-to-burn":
				x.h.view.closurePlan = []byte("burn-and-retire")
			case "foreign":
				original, err = NewRollbackContainment(qualRegistrationStore(t, 0))
				require.NoError(t, err)
			case "wrong-phase":
				tr.context.phase = []byte("unrelated")
			case "missing-funding":
				phaseHost.faults["complete"] = refuse
			case "native-parent-error":
				phaseHost.faults["parent"] = refuse
			case "tampered-parent":
				phaseHost.hooks["after_parent"] = func() { qualRecordPut(t, s, activationKey, qualRecordFrame(token, id, []byte("Active"), tr.target)) }
			case "tampered-setup":
				phaseHost.hooks["after_parent"] = func() { qualRecordPut(t, s, lrcKey, qualRecordFrame(token, qualA38U64(1), []byte("OPEN"))) }
			}
			certificate := []byte("synthetic-complete-activation-proof")
			run := func() error {
				return original.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
					a, exists := any(x.a).(interface {
						activateFromReadinessOwned(*rollbackOperation, *HeaderTimeContext, *convergenceRecords, convergenceTransition,
							[]byte, []byte) (*vmcommon.VMOutput, error)
					})
					if !exists {
						return nil, x.a.activate(token, id, x.genesis, certificate, x.acks, x.ackHost)
					}
					out, e := a.activateFromReadinessOwned(op, ctx, readiness, tr, x.genesis, certificate)
					if e != nil || out == nil {
						return nil, e
					}
					require.Len(t, owner.outputs, baseOutputs)
					if mode == "late-original-error" {
						return []*vmcommon.VMOutput{out}, late
					}
					return []*vmcommon.VMOutput{out}, nil
				})
			}
			err = run()
			if mode == "full" || mode == "full-preserve" {
				require.NoError(t, err)
				require.Equal(t, want, qualActivationValue(t, s, activationKey))
				require.Equal(t, qualRecordFrame(binding, []byte("COMPLETE"), []byte{7}, qualRecordFrame(acks...), c), qualActivationValue(t, s, key))
				require.Equal(t, qualRecordFrame(token, qualA38U64(1), []byte("SETUP")), qualActivationValue(t, s, lrcKey))
				require.NoError(t, run(), "COMPLETE replay reads retained parent without a second activation")
				require.Equal(t, 1, x.h.calls)
				require.Equal(t, 1, phaseHost.completeCalls)
				require.Len(t, owner.outputs, baseOutputs+1)
				_, outputs, e := owner.Commit()
				require.NoError(t, e)
				require.Equal(t, [][]byte{[]byte("parent-phase-applied")}, outputs[len(outputs)-1].ReturnData)
				return
			}
			switch mode {
			case "burn-to-preserve", "preserve-to-burn":
				require.ErrorIs(t, err, errActivationRecord)
				require.Equal(t, 1, x.h.calls, "activation verifier reached with all readiness ACKs")
				require.Zero(t, phaseHost.completeCalls, "plan mismatch stops before the funded native effect")
				intentKey := append([]byte(registrationIntentPrefix), id...)
				require.Equal(t, qualRecordFrame(x.f.verify.body, []byte("CONSUMED"), token), qualActivationValue(t, s, intentKey))
				require.Equal(t, association, qualActivationValue(t, s, append([]byte(registrationAssociationPrefix), token...)))
				require.Equal(t, []byte{1}, qualActivationValue(t, s, append([]byte(registryMemberKeyPrefix), token...)))
				require.Equal(t, qualA38U64(1), qualActivationValue(t, s, []byte(registryCountKey)))
				require.Empty(t, qualActivationValue(t, s, append([]byte(currentLocalBodyPrefix), qualRecordFrame(token, qualA38U64(1))...)))
				require.Empty(t, qualActivationValue(t, s, append([]byte(currentLocalPointerPrefix), qualRecordFrame(token)...)))
				for _, c := range x.h.view.classes {
					key, e := x.g.key("nonce", []byte("n"), c.subject, c.class)
					require.NoError(t, e)
					require.Empty(t, qualActivationValue(t, s, key))
				}
			case "missing-funding", "native-parent-error":
				require.ErrorIs(t, err, refuse)
			case "late-original-error":
				require.ErrorIs(t, err, late)
			default:
				require.Error(t, err)
			}
			after, e := s.RootHash()
			require.NoError(t, e)
			require.Equal(t, beforeRoot, after)
			require.Equal(t, beforeJournal, s.JournalLen())
			require.Equal(t, beforeK, qualActivationValue(t, s, key))
			require.Equal(t, beforeActivation, qualActivationValue(t, s, activationKey))
			require.Empty(t, qualActivationValue(t, s, lrcKey))
			require.Len(t, owner.outputs, baseOutputs)
		})
	}
}

func (x *qualActivationFixture) activate() error {
	return x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		err := x.a.activate([]byte("TOKEN-abcdef"), x.f.owner.id, x.genesis, []byte("synthetic-complete-activation-proof"), x.acks, x.ackHost)
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, err
	})
}

func TestQualDRWAActivationRefusesDetachedOperation(t *testing.T) {
	x := qualActivationNew(t)
	require.ErrorIs(t, x.a.activate([]byte("TOKEN-abcdef"), x.f.owner.id, x.genesis, []byte("synthetic-complete-activation-proof"), x.acks, x.ackHost), errInvalidRegistrationRecord)
	require.Zero(t, x.h.calls)
	require.Zero(t, x.ackHost.calls)
	require.Zero(t, x.f.store.JournalLen())
	require.Empty(t, x.f.boundary.outputs)
	owner := *x.f.owner
	owner.boundary = nil
	for _, admission := range []*RegistrationAdmission{nil, {}, {owner: &owner}} {
		require.ErrorIs(t, admission.withBootstrapReadinessInOperation(nil, nil, nil, nil), errInvalidRegistrationRecord)
	}
}

func TestQualDRWAActivationUsesExistingOperation(t *testing.T) {
	x := qualActivationNew(t)
	commits := x.f.store.commits
	err := x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		require.True(t, x.f.boundary.running)
		if err := x.a.activate([]byte("TOKEN-abcdef"), x.f.owner.id, x.genesis, []byte("synthetic-complete-activation-proof"), x.acks, x.ackHost); err != nil {
			return nil, err
		}
		require.True(t, x.f.boundary.running)
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, x.h.calls)
	require.Equal(t, 3, x.ackHost.calls)
	require.Equal(t, commits, x.f.store.commits)
	require.Len(t, x.f.boundary.outputs, 1, "only the original operation retains its output")
	token := []byte("TOKEN-abcdef")
	require.Equal(t, qualRecordFrame(token, x.f.owner.id, []byte("Active")), qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), token...)))
	require.NoError(t, x.f.boundary.Abort())
	require.Equal(t, qualRecordFrame(token, x.f.owner.id, []byte("BootstrapDeny")), qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), token...)))
}

func TestQualDRWAActivationLaterNativeFailureRollsBack(t *testing.T) {
	x := qualActivationNew(t)
	root, err := x.f.store.RootHash()
	require.NoError(t, err)
	root = bytes.Clone(root)
	journal, commits := x.f.store.JournalLen(), x.f.store.commits
	sentinel := errors.New("later original native operation refused")
	err = x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		if err := x.a.activate([]byte("TOKEN-abcdef"), x.f.owner.id, x.genesis, []byte("synthetic-complete-activation-proof"), x.acks, x.ackHost); err != nil {
			return nil, err
		}
		require.Greater(t, x.f.store.JournalLen(), journal)
		require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), x.f.owner.id, []byte("Active")), qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), []byte("TOKEN-abcdef")...)))
		return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, sentinel
	})
	require.Same(t, sentinel, err)
	require.Equal(t, 1, x.h.calls)
	after, err := x.f.store.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Equal(t, journal, x.f.store.JournalLen())
	require.Equal(t, commits, x.f.store.commits)
	require.Empty(t, x.f.boundary.outputs)
}

func TestQualDRWAActivationAtomicGenesisAndReplay(t *testing.T) {
	x := qualActivationNew(t)
	beforeIntent := bytes.Clone(qualActivationValue(t, x.f.store, append([]byte(registrationIntentPrefix), x.f.owner.id...)))
	budgetKey := []byte(scopedAdmissionPrefix + "budget")
	beforeBudget := bytes.Clone(qualActivationValue(t, x.f.store, budgetKey))
	require.NoError(t, x.activate())
	require.Equal(t, 1, x.h.calls)
	require.Equal(t, 3, x.ackHost.calls)
	epoch := binary.BigEndian.AppendUint64(nil, 1)
	token := []byte("TOKEN-abcdef")
	key := qualRecordFrame(token)
	require.Equal(t, qualRecordFrame(token, x.f.owner.id, []byte("Active")), qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), token...)))
	require.Equal(t, x.genesis, qualActivationValue(t, x.f.store, append([]byte(currentLocalBodyPrefix), qualRecordFrame(token, epoch)...)))
	require.Equal(t, qualRecordFrame(epoch, blake2b.NewBlake2b().Compute(string(x.genesis))), qualActivationValue(t, x.f.store, append([]byte(currentLocalPointerPrefix), key...)))
	require.Equal(t, qualRecordFrame(token, epoch, []byte("SETUP")), qualActivationValue(t, x.f.store, append([]byte(lifecycleRecordPrefix), key...)))
	afterBudget := qualActivationValue(t, x.f.store, budgetKey)
	addedBytes := len(currentLocalBodyPrefix) + len(qualRecordFrame(token, epoch)) + len(x.genesis) +
		len(currentLocalPointerPrefix) + len(key) + len(qualRecordFrame(epoch, blake2b.NewBlake2b().Compute(string(x.genesis)))) +
		len(lifecycleRecordPrefix) + len(key) + len(qualRecordFrame(token, epoch, []byte("SETUP")))
	require.Equal(t, binary.BigEndian.Uint64(beforeBudget)+3, binary.BigEndian.Uint64(afterBudget))
	require.Equal(t, binary.BigEndian.Uint64(beforeBudget[8:])+uint64(addedBytes), binary.BigEndian.Uint64(afterBudget[8:]))
	require.Equal(t, binary.BigEndian.Uint64(beforeBudget[24:])+3, binary.BigEndian.Uint64(afterBudget[24:]))
	for _, c := range x.h.view.classes {
		counter, err := x.g.key("nonce", []byte("n"), c.subject, c.class)
		require.NoError(t, err)
		require.Equal(t, make([]byte, 8), qualActivationValue(t, x.f.store, counter))
	}
	active, err := x.g.key("active", []byte("n"), token)
	require.NoError(t, err)
	require.Equal(t, qualRecordFrame(make([]byte, 8), make([]byte, 8), blake2b.NewBlake2b().Compute(""), nil), qualActivationValue(t, x.f.store, active))
	require.Equal(t, beforeIntent, qualActivationValue(t, x.f.store, append([]byte(registrationIntentPrefix), x.f.owner.id...)))
	require.Equal(t, []byte{1}, qualActivationValue(t, x.f.store, append([]byte(registryMemberKeyPrefix), token...)))
	require.Error(t, x.activate())
	require.Equal(t, 1, x.h.calls)
	require.NoError(t, x.f.boundary.Abort())
	require.Equal(t, qualRecordFrame(token, x.f.owner.id, []byte("BootstrapDeny")), qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), token...)))
	require.Equal(t, beforeIntent, qualActivationValue(t, x.f.store, append([]byte(registrationIntentPrefix), x.f.owner.id...)))
}

func TestQualDRWAActivationRejectsInvalidGenesisAndPrestate(t *testing.T) {
	for _, mode := range []string{"closure plan", "token", "epoch", "missing classes", "duplicate classes", "oversize class", "partial readiness", "verifier refusal", "verifier mutation", "existing current", "existing active aggregate", "live class counter"} {
		t.Run(mode, func(t *testing.T) {
			x := qualActivationNew(t)
			sentinel := errors.New("synthetic activation mandate refused")
			initializers := 0
			x.gh.hooks["initialize"] = func() { initializers++ }
			switch mode {
			case "closure plan":
				x.h.view.closurePlan = []byte("a-different-plan")
			case "token":
				x.h.view.token = []byte("OTHER-abcdef")
			case "epoch":
				x.h.view.epoch = 2
			case "missing classes":
				x.h.view.classes = nil
			case "duplicate classes":
				x.h.view.classes[1] = x.h.view.classes[0]
			case "oversize class":
				x.h.view.classes[0].class = bytes.Repeat([]byte{1}, 4097)
			case "partial readiness":
				x.acks = x.acks[:2]
			case "verifier refusal":
				x.h.err = sentinel
			case "verifier mutation":
				x.h.hook = func() { qualRecordPut(t, x.f.store, []byte("unrelated-activation-alias"), []byte{1}) }
			case "existing current":
				qualRecordPut(t, x.f.store, append([]byte(currentLocalPointerPrefix), qualRecordFrame([]byte("TOKEN-abcdef"))...), []byte("must-preserve"))
			case "existing active aggregate":
				key, err := x.g.key("active", []byte("n"), []byte("TOKEN-abcdef"))
				require.NoError(t, err)
				qualRecordPut(t, x.f.store, key, []byte("must-preserve"))
			case "live class counter":
				c := x.h.view.classes[0]
				key, err := x.g.key("nonce", []byte("n"), c.subject, c.class)
				require.NoError(t, err)
				qualRecordPut(t, x.f.store, key, binary.BigEndian.AppendUint64(nil, 7))
			}
			root, err := x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal, outputs := x.f.store.JournalLen(), len(x.f.boundary.outputs)
			err = x.activate()
			require.Error(t, err)
			if mode == "verifier refusal" {
				require.ErrorIs(t, err, sentinel)
			} else if mode == "partial readiness" || mode == "verifier mutation" {
				require.ErrorIs(t, err, errInvalidRegistrationRecord)
			} else {
				require.ErrorIs(t, err, errActivationRecord)
			}
			if mode == "partial readiness" {
				require.Zero(t, x.h.calls)
			} else {
				require.Equal(t, 1, x.h.calls)
			}
			if mode == "live class counter" {
				require.Equal(t, 1, initializers)
			} else {
				require.Zero(t, initializers)
			}
			after, e := x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, x.f.store.JournalLen())
			require.Len(t, x.f.boundary.outputs, outputs)
			require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), x.f.owner.id, []byte("BootstrapDeny")), qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), []byte("TOKEN-abcdef")...)))
		})
	}
}

func TestQualDRWAActivationLateClassFailureAndVerifierMutation(t *testing.T) {
	for _, mode := range []string{"second class refusal", "initializer unrelated write"} {
		t.Run(mode, func(t *testing.T) {
			x := qualActivationNew(t)
			sentinel := errors.New("late native class initialization refused")
			calls := 0
			x.gh.hooks["initialize"] = func() {
				calls++
				require.Equal(t, qualRecordFrame([]byte("TOKEN-abcdef"), x.f.owner.id, []byte("Active")), qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), []byte("TOKEN-abcdef")...)))
				if mode == "second class refusal" && calls == 2 {
					x.gh.faults["initialize"] = sentinel
				}
				if mode == "initializer unrelated write" {
					qualRecordPut(t, x.f.store, []byte("unrelated-initializer-alias"), []byte{1})
				}
			}
			root, err := x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			err = x.activate()
			require.Error(t, err)
			if mode == "second class refusal" {
				require.ErrorIs(t, err, sentinel)
				require.Equal(t, 2, calls)
			} else {
				require.ErrorIs(t, err, errInvalidRegistrationRecord)
				require.Equal(t, 1, calls)
			}
			after, e := x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Zero(t, x.f.store.JournalLen())
			require.Empty(t, x.f.boundary.outputs)
		})
	}
}

func TestQualDRWAGASInternalInitializationRequiresExistingOperation(t *testing.T) {
	f := qualGovernedActionNew(t)
	require.ErrorIs(t, f.g.initializeInOperation(f.x, f.p.subject, f.p.class, f.p.token), errGovernedActionRecord)
	require.ErrorIs(t, f.g.initializeInOperation(f.x, nil, f.p.class, f.p.token), errGovernedActionRecord)
	require.ErrorIs(t, f.g.initialize(f.x, nil, f.p.class, f.p.token), errGovernedActionRecord)
	require.Zero(t, f.s.JournalLen())
	f.initialize(t) // Original owning entrypoint still owns its own operation.
	key, err := f.g.key("nonce", f.g.domain, f.p.subject, f.p.class)
	require.NoError(t, err)
	require.Equal(t, make([]byte, 8), qualActivationValue(t, f.s, key))
	qualRecordPut(t, f.s, key, []byte{1})
	f.denied(t, func() error { return f.g.initialize(f.x, f.p.subject, f.p.class, f.p.token) })
}

func TestQualDRWAActivationConstructorBoundaries(t *testing.T) {
	x := qualActivationNew(t)
	foreign := *x.g
	var err error
	foreign.boundary, err = NewRollbackContainment(x.f.store)
	require.NoError(t, err)
	for _, args := range []struct {
		registration *RegistrationAdmission
		actions      *governedActionRecords
		host         activationHost
	}{
		{nil, x.g, x.h}, {&RegistrationAdmission{}, x.g, x.h},
		{x.f.admit, nil, x.h}, {x.f.admit, &governedActionRecords{}, x.h},
		{x.f.admit, x.g, nil}, {x.f.admit, &foreign, x.h},
	} {
		a, e := newActivationRecords(args.registration, args.actions, args.host)
		require.ErrorIs(t, e, errActivationRecord)
		require.Nil(t, a)
	}
	require.Zero(t, x.f.store.JournalLen())
}

func TestQualDRWAActivationInputAndClassBounds(t *testing.T) {
	var absent *activationRecords
	require.ErrorIs(t, absent.activate(nil, nil, nil, nil, nil, nil), errActivationRecord)
	require.ErrorIs(t, (&activationRecords{}).activate(nil, nil, nil, nil, nil, nil), errActivationRecord)
	for _, mode := range []string{"bad token", "wrong intent", "no genesis", "no certificates", "oversize envelope", "empty subject", "empty class", "too many classes", "oversize subject", "frame overhead"} {
		t.Run(mode, func(t *testing.T) {
			x := qualActivationNew(t)
			token, id, genesis, certs := []byte("TOKEN-abcdef"), bytes.Clone(x.f.owner.id), bytes.Clone(x.genesis), []byte("synthetic-complete-activation-proof")
			beforeHost := true
			expected := error(errActivationRecord)
			switch mode {
			case "bad token":
				token = []byte("bad")
			case "wrong intent":
				id = []byte("wrong")
			case "no genesis":
				genesis = nil
			case "no certificates":
				certs = nil
			case "oversize envelope":
				genesis = bytes.Repeat([]byte{1}, 4097)
				expected = errInvalidRegistrationRecord
			case "empty subject":
				x.h.view.classes[0].subject = nil
				beforeHost = false
			case "empty class":
				x.h.view.classes[0].class = nil
				beforeHost = false
			case "too many classes":
				x.h.view.classes = make([]activationActionClass, 2049)
				beforeHost = false
			case "oversize subject":
				x.h.view.classes[0].subject = bytes.Repeat([]byte{1}, 4097)
				beforeHost = false
			case "frame overhead":
				x.h.view.classes = []activationActionClass{{bytes.Repeat([]byte{1}, 4094), []byte{1}}}
				beforeHost = false
				expected = errInvalidRegistrationRecord
			}
			initializers := 0
			x.gh.hooks["initialize"] = func() { initializers++ }
			root, e := x.f.store.RootHash()
			require.NoError(t, e)
			root = bytes.Clone(root)
			journal, outputs := x.f.store.JournalLen(), len(x.f.boundary.outputs)
			err := x.f.boundary.Execute(func() (*vmcommon.VMOutput, error) {
				err := x.a.activate(token, id, genesis, certs, x.acks, x.ackHost)
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, err
			})
			require.ErrorIs(t, err, expected)
			if beforeHost {
				require.Zero(t, x.h.calls)
				require.Zero(t, x.ackHost.calls)
			} else {
				require.Equal(t, 1, x.h.calls)
				require.Equal(t, 3, x.ackHost.calls)
			}
			require.Zero(t, initializers)
			after, e := x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, x.f.store.JournalLen())
			require.Len(t, x.f.boundary.outputs, outputs)
		})
	}
}

// Decorate only the named storage failure. Native account serialization, data
// trie updates and rollback continue through the original AccountsDB: wrappers
// must be removed before SaveAccount, preserving its concrete native account.
type qualActivationStorageFaults struct {
	state.AccountsAdapter
	fault func(operation string, key, value []byte) error
}

type qualActivationStorageUser struct {
	state.UserAccountHandler
	owner *qualActivationStorageFaults
}

func (a *qualActivationStorageFaults) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	if err := a.fault("load", address, nil); err != nil {
		return nil, err
	}
	account, err := a.AccountsAdapter.GetExistingAccount(address)
	if err != nil {
		return nil, err
	}
	user, found := account.(state.UserAccountHandler)
	if !found {
		return account, nil
	}
	return &qualActivationStorageUser{user, a}, nil
}

func (a *qualActivationStorageFaults) SaveAccount(account vmcommon.AccountHandler) error {
	if err := a.fault("save", account.AddressBytes(), nil); err != nil {
		return err
	}
	if user, found := account.(*qualActivationStorageUser); found {
		account = user.UserAccountHandler
	}
	return a.AccountsAdapter.SaveAccount(account)
}

func (u *qualActivationStorageUser) RetrieveValue(key []byte) ([]byte, uint32, error) {
	value, depth, err := u.UserAccountHandler.RetrieveValue(key)
	if err != nil {
		return nil, depth, err
	}
	if err = u.owner.fault("read", key, value); err != nil {
		return nil, depth, err
	}
	return value, depth, nil
}

func (u *qualActivationStorageUser) SaveKeyValue(key, value []byte) error {
	if err := u.owner.fault("write", key, value); err != nil {
		return err
	}
	return u.UserAccountHandler.SaveKeyValue(key, value)
}

func TestQualDRWAActivationStorageFailuresPreserveBootstrap(t *testing.T) {
	for _, mode := range []string{"prestate load", "body read", "resource save", "retained load", "activation read", "activation write", "activation save", "class nonce read"} {
		t.Run(mode, func(t *testing.T) {
			x := qualActivationNew(t)
			token := []byte("TOKEN-abcdef")
			activationKey := append([]byte(registrationActivationPrefix), token...)
			bodyKey := append([]byte(currentLocalBodyPrefix), qualRecordFrame(token, binary.BigEndian.AppendUint64(nil, 1))...)
			firstClass := x.h.view.classes[0]
			nonceKey, err := x.g.key("nonce", x.g.domain, firstClass.subject, firstClass.class)
			require.NoError(t, err)
			root, err := x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal, outputs := x.f.store.JournalLen(), len(x.f.boundary.outputs)
			intentKey := append([]byte(registrationIntentPrefix), x.f.owner.id...)
			commits := x.f.store.commits
			intent := bytes.Clone(qualActivationValue(t, x.f.store, intentKey))
			initializers, hits := 0, 0
			activationWrite, dirtyObserved := false, false
			x.gh.hooks["initialize"] = func() { initializers++ }
			sentinel := errors.New("named native activation storage failure")
			faults := &qualActivationStorageFaults{AccountsAdapter: x.f.store.AccountsAdapter}
			faults.fault = func(operation string, key, value []byte) error {
				if operation == "write" && bytes.Equal(key, activationKey) {
					activationWrite = true
				}
				if x.h.calls == 0 {
					return nil
				}
				retained := x.f.store.JournalLen() > journal
				fail := mode == "prestate load" && operation == "load" && !retained ||
					mode == "body read" && operation == "read" && bytes.Equal(key, bodyKey) ||
					mode == "resource save" && operation == "save" ||
					mode == "retained load" && operation == "load" && retained ||
					mode == "activation read" && operation == "read" && bytes.Equal(key, activationKey) && retained ||
					mode == "activation write" && operation == "write" && bytes.Equal(key, activationKey) ||
					mode == "activation save" && operation == "save" && activationWrite ||
					mode == "class nonce read" && operation == "read" && bytes.Equal(key, nonceKey) && len(value) == 8
				if !fail {
					return nil
				}
				hits++
				if mode == "retained load" || mode == "activation read" || mode == "activation write" || mode == "activation save" || mode == "class nonce read" {
					require.True(t, retained)
					actual, e := x.f.store.RootHash()
					require.NoError(t, e)
					require.NotEqual(t, root, actual)
					dirtyObserved = true
				}
				return sentinel
			}
			x.f.store.AccountsAdapter = faults
			err = x.activate()
			faults.fault = func(string, []byte, []byte) error { return nil }
			require.Same(t, sentinel, err)
			require.Equal(t, 1, hits)
			require.Equal(t, 1, x.h.calls)
			if mode == "class nonce read" {
				require.Equal(t, 1, initializers)
			} else {
				require.Zero(t, initializers)
			}
			if mode == "retained load" || mode == "activation read" || mode == "activation write" || mode == "activation save" || mode == "class nonce read" {
				require.True(t, dirtyObserved)
			}
			after, e := x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, x.f.store.JournalLen())
			require.Len(t, x.f.boundary.outputs, outputs)
			require.Equal(t, commits, x.f.store.commits)
			require.Equal(t, qualRecordFrame(token, x.f.owner.id, []byte("BootstrapDeny")), qualActivationValue(t, x.f.store, activationKey))
			require.Equal(t, intent, qualActivationValue(t, x.f.store, intentKey))
		})
	}
}

type qualActivationEncodingFault struct {
	marshal.Marshalizer
	refuse func(*batch.Batch) error
}

func (m *qualActivationEncodingFault) Marshal(value interface{}) ([]byte, error) {
	if frame, found := value.(*batch.Batch); found {
		if err := m.refuse(frame); err != nil {
			return nil, err
		}
	}
	return m.Marshalizer.Marshal(value)
}

func TestQualDRWAActivationEncodingFailureBeforeWrites(t *testing.T) {
	for _, mode := range []string{"token key", "body identity", "lifecycle"} {
		t.Run(mode, func(t *testing.T) {
			x := qualActivationNew(t)
			token := []byte("TOKEN-abcdef")
			fields := [][]byte{token}
			if mode != "token key" {
				fields = append(fields, binary.BigEndian.AppendUint64(nil, 1))
			}
			if mode == "lifecycle" {
				fields = append(fields, []byte("SETUP"))
			}
			root, err := x.f.store.RootHash()
			require.NoError(t, err)
			root = bytes.Clone(root)
			journal, commits := x.f.store.JournalLen(), x.f.store.commits
			outputs := len(x.f.boundary.outputs)
			intentKey := append([]byte(registrationIntentPrefix), x.f.owner.id...)
			intent := bytes.Clone(qualActivationValue(t, x.f.store, intentKey))
			initializers, hits := 0, 0
			x.gh.hooks["initialize"] = func() { initializers++ }
			sentinel := errors.New("native activation encoder refused")
			codec := x.a.registration.owner.records
			original := codec.marshaller
			codec.marshaller = &qualActivationEncodingFault{Marshalizer: original, refuse: func(frame *batch.Batch) error {
				if x.h.calls != 1 || len(frame.Data) != len(fields) {
					return nil
				}
				for i := range fields {
					if !bytes.Equal(frame.Data[i], fields[i]) {
						return nil
					}
				}
				hits++
				require.Equal(t, journal, x.f.store.JournalLen())
				return sentinel
			}}
			err = x.activate()
			codec.marshaller = original
			require.Same(t, sentinel, err)
			require.Equal(t, 1, hits)
			require.Equal(t, 1, x.h.calls)
			require.Equal(t, 3, x.ackHost.calls)
			require.Zero(t, initializers)
			after, e := x.f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, x.f.store.JournalLen())
			require.Equal(t, commits, x.f.store.commits)
			require.Len(t, x.f.boundary.outputs, outputs)
			require.Equal(t, intent, qualActivationValue(t, x.f.store, intentKey))
			require.Equal(t, qualRecordFrame(token, x.f.owner.id, []byte("BootstrapDeny")),
				qualActivationValue(t, x.f.store, append([]byte(registrationActivationPrefix), token...)))
		})
	}
}

// activate is the earlier whole-set comparison fixture. It installs no production path.
func (a *activationRecords) activate(token, intentID, genesis, certificates []byte,
	acks []RegistrationStateAck, verifier RegistrationAckVerifier) error {
	if a == nil || a.registration == nil || a.registration.owner == nil {
		return errActivationRecord
	}
	r := a.registration.owner.records
	if !vmcommon.ValidateToken(token) || !bytes.Equal(intentID, a.registration.owner.id) ||
		len(genesis) == 0 || len(certificates) == 0 {
		return errActivationRecord
	}
	if _, err := r.frame(token, intentID, genesis, certificates); err != nil {
		return err
	}
	token, intentID = bytes.Clone(token), bytes.Clone(intentID)
	genesis, certificates = bytes.Clone(genesis), bytes.Clone(certificates)
	return a.registration.withBootstrapReadinessInOperation(token, acks, verifier, func() (*vmcommon.VMOutput, error) {
		context, err := a.registration.source.EvaluatedHeaderTimeContext()
		if err != nil {
			return nil, err
		}
		return a.writeActivationInHeader(context, token, intentID, genesis, certificates, nil, nil)
	})
}
