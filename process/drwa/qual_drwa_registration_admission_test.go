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
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7 EXPERIMENTAL: eight separate synthetic trust purposes, five native
// Ed25519 members / threshold three each, epoch 10 / millisecond 1, 3 shards,
// native Blake2b, 4096-byte records and capacity 2. These are NOT appointments,
// canonical import, production resource admission or a real transaction proof.
// Native hook/time, signatures, records, trie and journal are exercised here;
// this package's token creator is synthetic. The System-SC qualifier uses the
// actual native creator separately.
var qualRegistrationPurposes = []string{"CANONICAL_OPEN_INTENT", "ISSUER_TRANSACTION", "CURRENT_ADMISSION",
	"REGISTER_TOKEN_ADMISSION", "PROGRAM_ADMINISTRATION", "REGISTER_TOKEN", "CURRENT_SUPPORT", "RESOURCE_ADMISSION"}

type qualRegistrationVerifier struct {
	t                              *testing.T
	id, intentHash, body, creation []byte
	roles                          map[string]w03SignatureFixture
	calls                          []string
	hook                           func(string)
}

func (v *qualRegistrationVerifier) IsInterfaceNil() bool { return v == nil }
func (v *qualRegistrationVerifier) VerifyRegistration(purpose string, id, digest, body, creation, proof []byte,
	at HeaderMilliseconds, epoch uint32) error {
	v.calls = append(v.calls, purpose)
	role, exists := v.roles[purpose]
	if !exists || at != 1 || epoch != 10 || !bytes.Equal(id, v.id) || !bytes.Equal(digest, v.intentHash) ||
		!bytes.Equal(body, v.body) || !bytes.Equal(creation, v.creation) {
		return errInvalidRegistrationRecord
	}
	decoded := &batch.Batch{}
	if (&marshal.GogoProtoMarshalizer{}).Unmarshal(decoded, proof) != nil || !bytes.Equal(proof, qualRecordFrame(decoded.Data...)) {
		return errInvalidRegistrationRecord
	}
	bound := blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte(purpose), id, digest, body, creation,
		[]byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte{0, 0, 0, 10})))
	if err := verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", 3, role.members, []uint64{0, 1, 2}, decoded.Data, bound, 5, 32); err != nil {
		return err
	}
	if v.hook != nil {
		v.hook(purpose)
	}
	// A verifier's retained/mutated argument aliases cannot change owner state.
	id[0] ^= 1
	digest[0] ^= 1
	body[0] ^= 1
	creation[0] ^= 1
	proof[0] ^= 1
	return nil
}

type qualRegistrationAdmissionFixture struct {
	store    *qualNativeStore
	owner    *RegistrationIntentOwner
	boundary *RollbackContainment
	hook     *hooks.BlockChainHookImpl
	end      func()
	v        qualCreationVector
	body     bootstrapIntentBody
	verify   *qualRegistrationVerifier
	proofs   RegistrationProofs
	admit    *RegistrationAdmission
}

func qualRegistrationAdmission(t *testing.T, family string) *qualRegistrationAdmissionFixture {
	t.Helper()
	return qualRegistrationAdmissionForPlan(t, family, "burn-and-retire")
}

func qualRegistrationAdmissionForPlan(t *testing.T, family, plan string) *qualRegistrationAdmissionFixture {
	t.Helper()
	f := &qualRegistrationAdmissionFixture{}
	f.body, _, _, _, f.v = qualCreationIntent(family)
	f.body.closurePlan = []byte(plan)
	encoded, digest, id := qualCreationIntentBytes(f.body)
	f.store = qualRegistrationStore(t, 0)
	qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(encoded, []byte("OPEN"), nil))
	budgetKey := []byte(scopedAdmissionPrefix + "budget")
	budget := binary.BigEndian.AppendUint64(nil, 2)
	budget = binary.BigEndian.AppendUint64(budget, uint64(len(budgetKey)+32+len(registrationIntentPrefix)+len(id)+len(qualRecordFrame(encoded, []byte("OPEN"), nil))))
	budget = binary.BigEndian.AppendUint64(budget, 10)
	budget = binary.BigEndian.AppendUint64(budget, 0)
	qualRecordPut(t, f.store, budgetKey, budget)
	_, err := f.store.Commit()
	require.NoError(t, err)
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = core.MetachainShardId
	r, boundary, err := NewRegistryRegistration(f.store, coordinator, 2)
	require.NoError(t, err)
	f.boundary = boundary
	f.owner, err = r.BindIntent(id, digest, bytes.Repeat([]byte{0x22}, 32), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f.hook, _ = qualT42Hook(t, f.store, core.MetachainShardId, true)
	_, f.end = qualT42Install(t, f.hook, core.MetachainShardId, 1)
	f.verify = &qualRegistrationVerifier{t: t, id: bytes.Clone(id), intentHash: bytes.Clone(digest), body: encoded,
		creation: f.v.bodyHash, roles: make(map[string]w03SignatureFixture)}
	var evidence [][]byte
	for _, purpose := range qualRegistrationPurposes {
		role := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
		role.digest = blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte(purpose), id, digest, encoded, f.v.bodyHash,
			[]byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte{0, 0, 0, 10})))
		role.sign(t)
		f.verify.roles[purpose] = role
		evidence = append(evidence, qualRecordFrame(role.signatures...))
	}
	f.proofs = RegistrationProofs{evidence[0], evidence[1], evidence[2], evidence[3], evidence[4], evidence[5], evidence[6], evidence[7]}
	f.admit, err = f.owner.WithRegistrationAdmission(f.hook, []byte("n"), 10, RegistrationResourceLimits{1000, 1048576, 100}, f.verify, f.proofs)
	require.NoError(t, err)
	return f
}

func (f *qualRegistrationAdmissionFixture) register(t *testing.T, create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	t.Helper()
	return f.admit.RegisterTokenForAuthenticatedCreation(f.owner.id, f.v.body, f.body.issuer, f.owner.manager,
		f.body.requestedTokenFamily, f.v.profile, f.v.name, f.v.ticker, 6,
		func(accounts state.AccountsAdapter, _, _, _, _, _ []byte, _ uint32, _ [][]byte) ([]byte, *vmcommon.VMOutput, error) {
			return create(accounts)
		})
}

func TestQualDRWAT44T45AdmissionFamilies(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			f := qualRegistrationAdmission(t, family)
			require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
			require.Equal(t, qualRegistrationPurposes, f.verify.calls)
			record, _, err := f.owner.records.registeredToken([]byte("TOKEN-abcdef"))
			require.NoError(t, err)
			require.Equal(t, "CONSUMED", record.status)
			require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, f.store, registryCountKey)))
			require.Error(t, f.register(t, func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				t.Fatal("replay reached creator")
				return nil, nil, nil
			}))
		})
	}
}

func TestQualDRWAT44T45AuthenticatedCreationBorrowsOriginalOperation(t *testing.T) {
	for _, tc := range []struct{ name, family string }{
		{"fungible", core.FungibleESDT}, {"nft", core.NonFungibleESDTv2}, {"sft", core.SemiFungibleESDT}, {"meta", core.MetaESDT},
		{"dynamic-nft", core.DynamicNFTESDT}, {"dynamic-sft", core.DynamicSFTESDT}, {"dynamic-meta", core.DynamicMetaESDT},
		{"missing-canonical", core.FungibleESDT}, {"missing-support", core.FungibleESDT}, {"inactive-header", core.FungibleESDT},
		{"foreign-operation", core.FungibleESDT}, {"candidate-view-owner", core.FungibleESDT},
		{"missing-verifier", core.FungibleESDT}, {"late-failure", core.FungibleESDT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := qualRegistrationAdmission(t, tc.family)
			t.Cleanup(f.end)
			root, err := f.store.RootHash()
			require.NoError(t, err)
			journal := f.store.JournalLen()
			header, err := f.hook.EvaluatedHeaderTimeContext()
			require.NoError(t, err)
			original := f.boundary
			late := errors.New("synthetic failure after authenticated creation")
			switch tc.name {
			case "missing-canonical":
				delete(f.verify.roles, "CANONICAL_OPEN_INTENT")
			case "missing-support":
				delete(f.verify.roles, "CURRENT_SUPPORT")
			case "missing-verifier":
				f.admit.verifier = nil
			case "inactive-header":
				other := qualRegistrationAdmission(t, tc.family)
				t.Cleanup(other.end)
				header, err = other.hook.EvaluatedHeaderTimeContext()
				require.NoError(t, err)
			case "foreign-operation":
				original, err = NewRollbackContainment(qualRegistrationStore(t, 0))
				require.NoError(t, err)
			case "candidate-view-owner":
				writer := f.owner.registration.(*RegistryRegistration)
				parent := &committedRegistry{anchor: metaRegistryAnchor{root: bytes.Clone(root)}, members: make(map[string]struct{})}
				candidate := attachRegistrationCandidate(writer, original, parent, &parent.anchor)
				f.owner.registration = candidate
				t.Cleanup(func() { require.Empty(t, candidate.view.added) })
			}
			creates := 0
			creator := func(a state.AccountsAdapter, issuer, manager, family, name, ticker []byte, decimals uint32, properties [][]byte) ([]byte, *vmcommon.VMOutput, error) {
				creates++
				require.Same(t, f.store, a)
				require.Equal(t, f.body.issuer, issuer)
				require.Equal(t, f.owner.manager, manager)
				require.Equal(t, []byte(tc.family), family)
				require.Equal(t, f.v.name, name)
				require.Equal(t, f.v.ticker, ticker)
				require.Equal(t, uint32(6), decimals)
				require.Contains(t, properties, []byte("canAddSpecialRoles"))
				return qualRegistrationCreator(t, "TOKEN-abcdef")(a)
			}
			err = original.executeOwned(func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				v, exists := any(f.admit).(interface {
					registerTokenForAuthenticatedCreationOwned(*rollbackOperation, *HeaderTimeContext, []byte, []byte, []byte, []byte, []byte, []byte, []byte, []byte, uint32,
						func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error)
				})
				if !exists {
					return nil, f.admit.RegisterTokenForAuthenticatedCreation(f.owner.id, f.v.body, f.body.issuer, f.owner.manager,
						f.body.requestedTokenFamily, f.v.profile, f.v.name, f.v.ticker, 6, creator)
				}
				out, e := v.registerTokenForAuthenticatedCreationOwned(op, header, f.owner.id, f.v.body, f.body.issuer, f.owner.manager,
					f.body.requestedTokenFamily, f.v.profile, f.v.name, f.v.ticker, 6, creator)
				if e != nil {
					require.Nil(t, out)
					if tc.name == "missing-canonical" || tc.name == "missing-support" || tc.name == "missing-verifier" || tc.name == "inactive-header" {
						return nil, nil // the original operation must retain the denied write
					}
					return nil, e
				}
				require.Empty(t, original.outputs)
				if tc.name == "late-failure" {
					return []*vmcommon.VMOutput{out}, late
				}
				return []*vmcommon.VMOutput{out}, nil
			})
			switch tc.name {
			case "missing-canonical", "missing-support", "missing-verifier":
				require.ErrorIs(t, err, errInvalidRegistrationRecord)
			case "inactive-header":
				require.ErrorIs(t, err, ErrInactiveHeaderTime)
			case "foreign-operation", "candidate-view-owner":
				require.ErrorIs(t, err, errInvalidMetaContext)
			case "late-failure":
				require.ErrorIs(t, err, late)
				require.Equal(t, 1, creates)
			default:
				require.NoError(t, err)
				require.Equal(t, 1, creates)
				require.Equal(t, qualRegistrationPurposes, f.verify.calls)
				token := []byte("TOKEN-abcdef")
				require.Equal(t, qualRecordFrame(token, f.owner.id, []byte("BootstrapDeny")), qualRegistryValue(t, f.store, registrationActivationPrefix+string(token)))
				require.Equal(t, []byte{1}, qualRegistryValue(t, f.store, registryMemberKeyPrefix+string(token)))
				_, outputs, e := original.Commit()
				require.NoError(t, e)
				require.Len(t, outputs, 1)
				require.Equal(t, [][]byte{token}, outputs[0].ReturnData)
				return
			}
			if tc.name != "late-failure" {
				require.Zero(t, creates)
			}
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, root, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Empty(t, original.outputs)
		})
	}
}

func TestQualDRWAT44T45AdmissionEachIndependentProof(t *testing.T) {
	for _, purpose := range qualRegistrationPurposes {
		for _, fault := range []string{"missing-role", "bad-signature", "borrowed-purpose", "state-mutation"} {
			t.Run(purpose+"/"+fault, func(t *testing.T) {
				f := qualRegistrationAdmission(t, core.FungibleESDT)
				role := f.verify.roles[purpose]
				switch fault {
				case "missing-role":
					delete(f.verify.roles, purpose)
				case "bad-signature":
					role.members[0][0] ^= 1
				case "borrowed-purpose":
					other := "REGISTER_TOKEN"
					if purpose == other {
						other = "PROGRAM_ADMINISTRATION"
					}
					f.verify.roles[purpose] = f.verify.roles[other]
				case "state-mutation":
					f.verify.hook = func(p string) {
						if p == purpose {
							qualRecordPut(t, f.store, []byte("unrelated-native-key"), []byte{1})
						}
					}
				}
				before, err := f.store.RootHash()
				require.NoError(t, err)
				journal, outputs := f.store.JournalLen(), len(f.boundary.outputs)
				called := false
				require.Error(t, f.register(t, func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }))
				require.False(t, called)
				after, err := f.store.RootHash()
				require.NoError(t, err)
				require.Equal(t, before, after)
				require.Equal(t, journal, f.store.JournalLen())
				require.Len(t, f.boundary.outputs, outputs)
			})
		}
	}
}

func TestQualDRWAT44T45AdmissionNativeTimeAndRollback(t *testing.T) {
	for _, fault := range []string{"ended", "expired", "before-epoch", "domain", "context-invalidation", "creator", "late-count-save", "rollback-poison"} {
		t.Run(fault, func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			original, rollback := errors.New("creator failure"), errors.New("rollback failure")
			switch fault {
			case "ended":
				f.end()
			case "expired":
				f.end()
				qualT42Install(t, f.hook, core.MetachainShardId, 2)
			case "before-epoch":
				f.admit.enableEpoch = 11
			case "domain":
				f.admit.domain = []byte("other-network")
			case "context-invalidation":
				f.verify.hook = func(p string) {
					if p == "REGISTER_TOKEN" {
						require.NoError(t, f.hook.SetCurrentHeader(qualT42Header(core.MetachainShardId, 2)))
					}
				}
			}
			before, err := f.store.RootHash()
			require.NoError(t, err)
			creatorCalls := 0
			err = f.register(t, func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				creatorCalls++
				id, out, e := qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
				if e != nil {
					return nil, nil, e
				}
				switch fault {
				case "creator", "rollback-poison":
					if fault == "rollback-poison" {
						f.store.revertErr = rollback
					}
					return nil, nil, original
				case "late-count-save":
					f.store.saveErr = original
				}
				return id, out, nil
			})
			require.Error(t, err)
			require.Empty(t, f.boundary.outputs)
			if fault == "rollback-poison" {
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, rollback)
				_, _, e := f.boundary.Commit()
				require.ErrorIs(t, e, rollback)
				return
			}
			f.store.saveErr = nil
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			if fault == "ended" || fault == "expired" || fault == "before-epoch" || fault == "domain" {
				require.Zero(t, creatorCalls)
			}
		})
	}
}

func TestQualDRWAT44T45AdmissionSerializesNativeOwner(t *testing.T) {
	f := qualRegistrationAdmission(t, core.FungibleESDT)
	entered, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	f.verify.hook = func(p string) {
		if p == "CANONICAL_OPEN_INTENT" {
			close(entered)
			<-release
		}
	}
	go func() { result <- f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")) }()
	<-entered
	err := f.register(t, func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		t.Error("competing registration reached creator")
		return nil, nil, nil
	})
	close(release)
	require.ErrorIs(t, err, ErrExecutionBusy)
	require.NoError(t, <-result)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, f.store, registryCountKey)))
	require.Len(t, f.boundary.outputs, 1)
}

// Component composition only: actual AccountsDB/token/intent/registry journal,
// existing synthetic creator and convergence host. No native admission verifier,
// transaction-origin lease, authority appointment or T01 representation is supplied.
func qualT01OriginalRegistrationConvergence(t *testing.T) (*RegistrationIntentOwner, *qualConvergenceFixture) {
	t.Helper()
	store, _, digest, id := qualRecordStore(t)
	writer, boundary := qualRegistrationOwner(t, store, 2)
	owner, err := writer.BindIntent(id, digest, bytes.Repeat([]byte{0x22}, 32),
		&marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f := qualConvergenceNew(t, 3)
	f.store, f.owner, f.host.store = store, boundary, store
	f.records, err = newConvergenceRecords(store, boundary, &marshal.GogoProtoMarshalizer{},
		blake2b.NewBlake2b(), 4096, 16, f.host)
	require.NoError(t, err)
	// The generic convergence tests retain their currentization tuples.
	// This interface owns T01, so use a three-shard bootstrap phase here.
	owner.shards = 3
	body, encoded, _, _ := qualRecordBody()
	qualBootstrapReadinessPhase(f, owner, body.networkDomain, encoded, nil)
	return owner, f
}

func qualT01RegisterOriginal(t *testing.T, owner *RegistrationIntentOwner) error {
	t.Helper()
	body, _, _, _ := qualRecordBody()
	return owner.RegisterTokenForCreation(body.issuer, owner.manager, body.requestedTokenFamily,
		qualRegistrationCreator(t, "TOKEN-abcdef"))
}

func TestQualT01OriginalRegistrationCreatesConvergenceAtomically(t *testing.T) {
	for _, lateFailure := range []bool{false, true} {
		name := "one_original_output"
		if lateFailure {
			name = "late_failure_after_K"
		}
		t.Run(name, func(t *testing.T) {
			owner, f := qualT01OriginalRegistrationConvergence(t)
			before, err := f.store.RootHash()
			require.NoError(t, err)
			builderCalls := 0
			bound, err := owner.withConvergence(f.records, func(tokenID []byte) (convergenceTransition, error) {
				builderCalls++
				require.Equal(t, []byte("TOKEN-abcdef"), tokenID)
				intent, _, readErr := owner.records.registeredToken(tokenID)
				require.NoError(t, readErr, "original association must exist before K binding")
				require.Equal(t, "CONSUMED", intent.status)
				require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, f.store, registryCountKey)))
				require.Equal(t, []byte{1}, qualRegistryValue(t, f.store, registryMemberKeyPrefix+string(tokenID)))
				return f.tr, nil
			})
			require.NoError(t, err)
			fault := errors.New("original guard invalidated after K")
			if lateFailure {
				bound.guard = func(_ []state.AccountsAdapter, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
					output, e := execute()
					if e != nil {
						return nil, e
					}
					f.assert(t, "PENDING")
					return output, fault
				}
			}
			err = qualT01RegisterOriginal(t, bound)
			if lateFailure {
				require.ErrorIs(t, err, fault)
				after, rootErr := f.store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, before, after)
				require.Zero(t, f.store.JournalLen())
				intent, readErr := owner.records.intent(owner.id)
				require.NoError(t, readErr)
				require.Equal(t, "OPEN", intent.status)
				require.Empty(t, qualRegistryValue(t, f.store, string(f.key)))
				require.Empty(t, qualRegistryValue(t, f.store, registrationAssociationPrefix+"TOKEN-abcdef"))
				require.Empty(t, qualRegistryValue(t, f.store, registrationActivationPrefix+"TOKEN-abcdef"))
				require.Empty(t, qualRegistryValue(t, f.store, registryMemberKeyPrefix+"TOKEN-abcdef"))
				require.Equal(t, uint64(0), binary.BigEndian.Uint64(qualRegistryValue(t, f.store, registryCountKey)))
				_, tokenAccountErr := f.store.GetExistingAccount(core.ESDTSCAddress)
				require.Error(t, tokenAccountErr, "the newly created token account must also roll back")
			} else {
				require.NoError(t, err)
				f.assert(t, "PENDING")
			}
			require.Equal(t, 1, builderCalls)
			_, outputs, commitErr := f.owner.Commit()
			require.NoError(t, commitErr)
			if lateFailure {
				require.Empty(t, outputs)
			} else {
				require.Len(t, outputs, 1)
				require.Equal(t, [][]byte{[]byte("TOKEN-abcdef")}, outputs[0].ReturnData)
			}
		})
	}
}

func TestQualT01OriginalRegistrationConvergenceBindingRefusals(t *testing.T) {
	for _, fault := range []string{"foreign_owner", "nil_builder", "rebound", "substituted_token", "builder_write", "reentry", "closed", "invalid_creator_id", "creator_error"} {
		t.Run(fault, func(t *testing.T) {
			owner, f := qualT01OriginalRegistrationConvergence(t)
			builderCalls := 0
			var bound *RegistrationIntentOwner
			build := func([]byte) (convergenceTransition, error) {
				builderCalls++
				transition := f.tr
				switch fault {
				case "substituted_token":
					transition.token = []byte("OTHER-abcdef")
				case "builder_write":
					qualRecordPut(t, f.store, []byte("fixture/illegal-builder-write"), []byte("not-authority"))
				case "reentry":
					return transition, qualT01RegisterOriginal(t, bound)
				}
				return transition, nil
			}
			if fault == "foreign_owner" {
				_, foreign := qualT01OriginalRegistrationConvergence(t)
				_, err := owner.withConvergence(foreign.records, build)
				require.Error(t, err)
				return
			}
			if fault == "nil_builder" {
				_, err := owner.withConvergence(f.records, nil)
				require.Error(t, err)
				return
			}
			var err error
			bound, err = owner.withConvergence(f.records, build)
			require.NoError(t, err)
			if fault == "rebound" {
				_, err = bound.withConvergence(f.records, build)
				require.Error(t, err)
				return
			}
			if fault == "closed" {
				_, _, err = f.owner.Commit()
				require.NoError(t, err)
			}
			before, err := f.store.RootHash()
			require.NoError(t, err)
			if fault == "invalid_creator_id" || fault == "creator_error" {
				body, _, _, _ := qualRecordBody()
				err = bound.RegisterTokenForCreation(body.issuer, bound.manager, body.requestedTokenFamily,
					func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
						id, output, e := qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
						if e != nil {
							return nil, nil, e
						}
						if fault == "creator_error" {
							return id, output, errors.New("creator failed after native write")
						}
						return bytes.Repeat([]byte{'x'}, bound.records.maxBytes+1), output, nil
					})
			} else {
				err = qualT01RegisterOriginal(t, bound)
			}
			require.Error(t, err)
			if fault == "invalid_creator_id" || fault == "creator_error" {
				require.Zero(t, builderCalls)
			}
			if fault == "reentry" {
				require.ErrorIs(t, err, ErrExecutionBusy)
			}
			if fault == "closed" {
				require.ErrorIs(t, err, ErrExecutionClosed)
				require.Zero(t, builderCalls)
			}
			after, rootErr := f.store.RootHash()
			require.NoError(t, rootErr)
			require.Equal(t, before, after)
			require.Zero(t, f.store.JournalLen())
			require.Empty(t, f.owner.outputs)
			require.Zero(t, f.host.verifyCalls)
			require.Zero(t, f.host.admissionCalls)
		})
	}
}

func TestQualT01CandidatePublishesOnlyAfterOriginalConvergence(t *testing.T) {
	for _, lateFailure := range []bool{false, true} {
		name := "publish_after_K"
		if lateFailure {
			name = "no_publication_after_late_failure"
		}
		t.Run(name, func(t *testing.T) {
			f := qualCandidateRecords(t, false, false, core.FungibleESDT)
			convergence := qualConvergenceNew(t, 3)
			convergence.store, convergence.host.store = f.store.qualNativeStore, f.store.qualNativeStore
			boundary := f.candidate.writer.boundary
			records, err := newConvergenceRecords(f.store, boundary, &marshal.GogoProtoMarshalizer{},
				blake2b.NewBlake2b(), 4096, 16, convergence.host)
			require.NoError(t, err)
			convergence.records = records
			f.owner.shards = 3
			qualBootstrapReadinessPhase(convergence, f.owner, f.body.networkDomain, f.encoded, nil)
			bound, err := f.owner.withConvergence(records, func(tokenID []byte) (convergenceTransition, error) {
				require.Equal(t, []byte("TOKEN-abcdef"), tokenID)
				require.Empty(t, f.candidate.view.added, "no view delta before all original writes and K")
				return convergence.tr, nil
			})
			require.NoError(t, err)
			f.owner = bound
			fault := errors.New("late original candidate guard failure")
			if lateFailure {
				bound.guard = func(_ []state.AccountsAdapter, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
					out, e := execute()
					if e != nil {
						return nil, e
					}
					convergence.assert(t, "PENDING")
					return out, fault
				}
			}
			before, err := f.store.RootHash()
			require.NoError(t, err)
			err = f.create(qualRegistrationCreator(t, "TOKEN-abcdef"))
			if lateFailure {
				require.ErrorIs(t, err, fault)
				after, rootErr := f.store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, before, after)
				require.Empty(t, f.candidate.view.added)
				qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", false)
			} else {
				require.NoError(t, err)
				convergence.assert(t, "PENDING")
				qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", true)
			}
			_, outputs, commitErr := f.candidate.commit()
			require.NoError(t, commitErr)
			if lateFailure {
				require.Empty(t, outputs)
			} else {
				require.Len(t, outputs, 1)
			}
		})
	}
}

func TestQualT01OwnedCandidatePublishesOnlyAfterOriginalSuccess(t *testing.T) {
	for _, scenario := range []string{"success", "late-failure", "writer-failure", "wrong-owner"} {
		t.Run(scenario, func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			defer f.end()
			root, err := f.store.RootHash()
			require.NoError(t, err)
			writer := f.owner.registration.(*RegistryRegistration)
			anchor := metaRegistryAnchor{root: root, candidateHash: []byte("synthetic-metachain-candidate")}
			parent := &committedRegistry{anchor: anchor, members: make(map[string]struct{})}
			candidate := attachRegistrationCandidate(writer, f.boundary, parent, &anchor)
			f.owner.registration = candidate
			header, err := f.hook.EvaluatedHeaderTimeContext()
			require.NoError(t, err)
			token := []byte("TOKEN-abcdef")
			failure := errors.New("synthetic failure in the original operation")
			execute := func(op *rollbackOperation) ([]*vmcommon.VMOutput, error) {
				out, err := f.admit.registerTokenForAuthenticatedCreationOwned(op, header, f.owner.id, f.v.body,
					f.body.issuer, f.owner.manager, f.body.requestedTokenFamily, f.v.profile, f.v.name, f.v.ticker, 6,
					func(accounts state.AccountsAdapter, _, _, _, _, _ []byte, _ uint32, _ [][]byte) ([]byte, *vmcommon.VMOutput, error) {
						id, output, err := qualRegistrationCreator(t, string(token))(accounts)
						if scenario == "writer-failure" {
							return id, output, failure
						}
						return id, output, err
					})
				require.Empty(t, candidate.view.added)
				require.Empty(t, f.boundary.outputs)
				if err != nil {
					require.Nil(t, out)
					if scenario == "writer-failure" && errors.Is(err, failure) {
						return nil, nil // a swallowed write failure still rolls back
					}
					return nil, err
				}
				require.Equal(t, []byte{1}, qualRegistryValue(t, f.store, registryMemberKeyPrefix+string(token)))
				if scenario == "late-failure" {
					return []*vmcommon.VMOutput{out}, failure
				}
				return []*vmcommon.VMOutput{out}, nil
			}
			run := f.boundary.executeOwned
			if owner, ok := any(candidate).(interface {
				executeRegistrationOwned(func(*rollbackOperation) ([]*vmcommon.VMOutput, error)) error
			}); ok && scenario != "wrong-owner" {
				run = owner.executeRegistrationOwned
			}
			err = run(execute)
			switch scenario {
			case "success":
				require.NoError(t, err)
				qualAssertRegistrationClassification(t, candidate, anchor.candidateHash, string(token), true)
				require.Len(t, f.boundary.outputs, 1)
				return
			case "wrong-owner":
				require.ErrorIs(t, err, errInvalidMetaContext)
			default:
				require.ErrorIs(t, err, failure)
			}
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, f.store.JournalLen())
			require.Empty(t, f.boundary.outputs)
			qualAssertRegistrationClassification(t, candidate, anchor.candidateHash, string(token), false)
		})
	}
}

func TestQualT01AdmissionTimeGuardIncludesOriginalConvergence(t *testing.T) {
	for _, endDuringK := range []bool{false, true} {
		name := "active_native_time_owner"
		if endDuringK {
			name = "ended_during_K_admission"
		}
		t.Run(name, func(t *testing.T) {
			// Retain the existing synthetic signed-purpose component fixture;
			// it is not an appointment or a genuine registration transaction.
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			defer f.end()
			convergence := qualConvergenceNew(t, 3)
			convergence.store, convergence.host.store = f.store, f.store
			records, err := newConvergenceRecords(f.store, f.boundary, &marshal.GogoProtoMarshalizer{},
				blake2b.NewBlake2b(), 4096, 16, convergence.host)
			require.NoError(t, err)
			convergence.records = records
			qualBootstrapReadinessPhase(convergence, f.owner, f.body.networkDomain, f.verify.body, nil)
			bound, err := f.owner.withConvergence(records, func(tokenID []byte) (convergenceTransition, error) {
				require.Equal(t, []byte("TOKEN-abcdef"), tokenID)
				return convergence.tr, nil
			})
			require.NoError(t, err)
			admit := f.admit
			f.admit, err = bound.WithRegistrationAdmission(admit.source, admit.domain, admit.enableEpoch,
				admit.limits, admit.verifier, f.proofs)
			require.NoError(t, err)
			f.owner = bound
			if endDuringK {
				convergence.host.hooks["admission"] = f.end
			}
			before, err := f.store.RootHash()
			require.NoError(t, err)
			err = f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef"))
			if endDuringK {
				require.ErrorIs(t, err, ErrInactiveHeaderTime)
				after, rootErr := f.store.RootHash()
				require.NoError(t, rootErr)
				require.Equal(t, before, after)
				require.Zero(t, f.store.JournalLen())
				intent, readErr := f.owner.records.intent(f.owner.id)
				require.NoError(t, readErr)
				require.Equal(t, "OPEN", intent.status)
				require.Empty(t, qualRegistryValue(t, f.store, string(convergence.key)))
				require.Empty(t, f.boundary.outputs)
			} else {
				require.NoError(t, err)
				convergence.assert(t, "PENDING")
				require.Len(t, f.boundary.outputs, 1)
			}
			require.Equal(t, qualRegistrationPurposes, f.verify.calls)
			require.Equal(t, 1, convergence.host.admissionCalls)
		})
	}
}
