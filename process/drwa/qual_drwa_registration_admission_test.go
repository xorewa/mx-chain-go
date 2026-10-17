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
	f := &qualRegistrationAdmissionFixture{}
	f.body, _, _, _, f.v = qualCreationIntent(family)
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
