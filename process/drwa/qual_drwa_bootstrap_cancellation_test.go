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
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7 experimental: separate native Ed25519 3/5 fixture rosters for exact PA
// and independent cancellation purposes. Appointment/lineage and canonical
// no-setup/OpenEffect evidence remain synthetic, never protocol acceptance.
// This package uses a synthetic native token proof; the companion System-SC
// qualifier couples this owner to the actual native creator/reader.
type qualT46Verifier struct {
	t              *testing.T
	subject, state []byte
	roles          map[string]w03SignatureFixture
	calls          []string
	deny           string
	hook           func(string)
}

func (v *qualT46Verifier) IsInterfaceNil() bool { return v == nil }
func (v *qualT46Verifier) VerifyBootstrapCancellation(p string, subject, proof []byte, at HeaderMilliseconds, epoch uint32) error {
	v.calls = append(v.calls, p)
	if p == v.deny || at != 100 || epoch != 10 || !bytes.Equal(subject, v.subject) {
		return errInvalidRegistrationRecord
	}
	if p == "NATIVE_BOOTSTRAP_STATE" {
		if !bytes.Equal(proof, v.state) {
			return errInvalidRegistrationRecord
		}
	} else {
		role, exists := v.roles[p]
		if !exists {
			return errInvalidRegistrationRecord
		}
		b := &batch.Batch{}
		if (&marshal.GogoProtoMarshalizer{}).Unmarshal(b, proof) != nil || !bytes.Equal(proof, qualRecordFrame(b.Data...)) {
			return errInvalidRegistrationRecord
		}
		digest := blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte(p), subject)))
		if err := verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", 3, role.members, []uint64{0, 1, 2}, b.Data, digest, 5, 32); err != nil {
			return err
		}
	}
	if v.hook != nil {
		v.hook(p)
	}
	subject[0] ^= 1
	proof[0] ^= 1 // aliases cannot rewrite the retained evidence
	return nil
}

type qualT46Fixture struct {
	f                            *qualRegistrationAdmissionFixture
	c                            *RegistrationCancellation
	v                            *qualT46Verifier
	token, native, pa, co, state []byte
	nativeHook                   func()
	nativeErr                    error
}

func qualT46New(t *testing.T, family string) *qualT46Fixture {
	t.Helper()
	f := qualRegistrationAdmission(t, family)
	require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
	_, _, err := f.boundary.Commit()
	require.NoError(t, err)
	coordinator := testscommon.NewMultiShardsCoordinatorMock(3)
	coordinator.CurrentShard = core.MetachainShardId
	r, b, err := NewRegistryRegistration(f.store, coordinator, 2)
	require.NoError(t, err)
	id, digest, manager := bytes.Clone(f.owner.id), bytes.Clone(f.owner.digest), bytes.Clone(f.owner.manager)
	f.owner, err = r.BindIntent(id, digest, manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	f.boundary = b
	f.end()
	_, f.end = qualT42Install(t, f.hook, core.MetachainShardId, 100)
	x := &qualT46Fixture{f: f, token: []byte("TOKEN-abcdef"), native: []byte("synthetic-native-never-issued-no-role"), state: []byte("synthetic-canonical-no-supply-setup-open-effect")}
	subject := qualRecordFrame([]byte("DRWA/BOOTSTRAP_CANCEL/candidate1"), []byte("n"), x.token, id, digest, f.verify.body, manager, x.native, x.state, binary.BigEndian.AppendUint64(nil, 100), binary.BigEndian.AppendUint32(nil, 10))
	x.v = &qualT46Verifier{t: t, subject: subject, state: bytes.Clone(x.state), roles: make(map[string]w03SignatureFixture)}
	for _, p := range []string{"PROGRAM_ADMINISTRATION", "BOOTSTRAP_CANCEL"} {
		role := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
		role.digest = blake2b.NewBlake2b().Compute(string(qualRecordFrame([]byte(p), subject)))
		role.sign(t)
		x.v.roles[p] = role
		if p == "PROGRAM_ADMINISTRATION" {
			x.pa = qualRecordFrame(role.signatures...)
		} else {
			x.co = qualRecordFrame(role.signatures...)
		}
	}
	x.c, err = f.owner.WithBootstrapCancellation(f.hook, []byte("n"), 10, RegistrationResourceLimits{Records: 1000, RetainedBytes: 1048576, NewRecordsPerEpoch: 100}, x.v)
	require.NoError(t, err)
	return x
}
func (x *qualT46Fixture) cancel(id []byte) error {
	return x.c.CancelBootstrapRegistration(x.token, id, x.pa, x.co, x.state, func(a state.AccountsAdapter, token, manager, family []byte) ([]byte, error) {
		if a != x.f.store || !bytes.Equal(token, x.token) || !bytes.Equal(manager, x.f.owner.manager) || !bytes.Equal(family, x.f.body.requestedTokenFamily) {
			return nil, errInvalidRegistrationRecord
		}
		if x.nativeHook != nil {
			x.nativeHook()
		}
		return x.native, x.nativeErr
	})
}
func TestQualDRWAT46CancellationFamiliesAndRetention(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT, core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			x := qualT46New(t, family)
			f := x.f
			intent := bytes.Clone(qualRegistryValue(t, f.store, registrationIntentPrefix+string(f.owner.id)))
			association := bytes.Clone(qualRegistryValue(t, f.store, registrationAssociationPrefix+string(x.token)))
			count := bytes.Clone(qualRegistryValue(t, f.store, registryCountKey))
			member := bytes.Clone(qualRegistryValue(t, f.store, registryMemberKeyPrefix+string(x.token)))
			budget := bytes.Clone(qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget"))
			old := qualRegistryValue(t, f.store, registrationActivationPrefix+string(x.token))
			require.NoError(t, x.cancel(f.owner.id))
			want := qualRecordFrame(x.token, f.owner.id, []byte("RetiredDeny"), x.native, x.state, x.pa, x.co)
			require.Equal(t, want, qualRegistryValue(t, f.store, registrationActivationPrefix+string(x.token)))
			require.Equal(t, intent, qualRegistryValue(t, f.store, registrationIntentPrefix+string(f.owner.id)))
			require.Equal(t, association, qualRegistryValue(t, f.store, registrationAssociationPrefix+string(x.token)))
			require.Equal(t, count, qualRegistryValue(t, f.store, registryCountKey))
			require.Equal(t, member, qualRegistryValue(t, f.store, registryMemberKeyPrefix+string(x.token)))
			after := qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")
			require.Equal(t, budget[:8], after[:8])
			require.Equal(t, budget[16:], after[16:])
			require.Equal(t, binary.BigEndian.Uint64(budget[8:16])+uint64(len(want)-len(old)), binary.BigEndian.Uint64(after[8:16]))
			require.Equal(t, []string{"PROGRAM_ADMINISTRATION", "BOOTSTRAP_CANCEL", "NATIVE_BOOTSTRAP_STATE"}, x.v.calls)
			// The existing activation consumer must reject the retained retired
			// record even with otherwise valid bootstrap ACKs from before cancel.
			admit, e := f.owner.WithRegistrationAdmission(f.hook, []byte("n"), 10, x.c.limits, f.verify, f.proofs)
			require.NoError(t, e)
			acks, verifier := qualRegistrationAcks(t, f)
			require.Error(t, admit.WithBootstrapReadiness(x.token, acks, verifier, func() (*vmcommon.VMOutput, error) {
				t.Fatal("retired token reached activation")
				return nil, nil
			}))
			require.Zero(t, verifier.calls)
			before, e := f.store.RootHash()
			require.NoError(t, e)
			journal := f.store.JournalLen()
			require.Error(t, x.cancel(f.owner.id))
			root, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, root)
			require.Equal(t, journal, f.store.JournalLen())
			roots, outputs, e := f.boundary.Commit()
			require.NoError(t, e)
			require.Len(t, outputs, 1)
			require.Nil(t, outputs[0], "state-only action retains no VM output")
			require.NoError(t, f.store.RecreateTrie(holders.NewRootHashHolder(roots[0], core.OptionalUint32{})))
			record, manager, e := f.owner.records.registeredToken(x.token)
			require.NoError(t, e)
			require.Equal(t, "CONSUMED", record.status)
			require.Equal(t, f.owner.manager, manager)
			require.Error(t, x.cancel(f.owner.id)) // closed owner cannot be revived
			// Fresh native-store reconstruction retains the exact irreversible record.
			require.Equal(t, want, qualRegistryValue(t, f.store, registrationActivationPrefix+string(x.token)))
		})
	}
}
func TestQualDRWAT46CancellationDenials(t *testing.T) {
	for _, fault := range []string{"association-missing", "intent-open", "intent-cancelled", "wrong-digest", "wrong-manager", "nonmember", "count-zero", "count-malformed", "activation-missing", "activation-active", "activation-setup", "activation-retired", "activation-malformed", "supplied-id", "domain", "before-epoch", "ended", "native-error", "native-mutation", "pa-missing", "co-missing", "pa-unavailable", "co-unavailable", "state-missing", "pa-bad", "co-bad", "borrow-purpose", "state-denied", "verifier-mutation", "time-invalidation", "save", "rollback", "bytes-exhausted", "budget-missing", "oversize"} {
		t.Run(fault, func(t *testing.T) {
			x := qualT46New(t, core.FungibleESDT)
			f := x.f
			id := bytes.Clone(f.owner.id)
			original, rollback := errors.New("T46 original failure"), errors.New("T46 rollback failure")
			switch fault {
			case "association-missing":
				qualRecordPut(t, f.store, []byte(registrationAssociationPrefix+string(x.token)), nil)
			case "intent-open":
				qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(f.verify.body, []byte("OPEN"), nil))
			case "intent-cancelled":
				qualRecordPut(t, f.store, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(f.verify.body, []byte("CANCELLED"), nil))
			case "wrong-digest":
				f.owner.digest[0] ^= 1
			case "wrong-manager":
				f.owner.manager[0] ^= 1
			case "nonmember":
				qualRecordPut(t, f.store, []byte(registryMemberKeyPrefix+string(x.token)), nil)
			case "count-zero":
				qualRecordPut(t, f.store, []byte(registryCountKey), make([]byte, 8))
			case "count-malformed":
				qualRecordPut(t, f.store, []byte(registryCountKey), []byte{1})
			case "activation-missing":
				qualRecordPut(t, f.store, []byte(registrationActivationPrefix+string(x.token)), nil)
			case "activation-active", "activation-setup", "activation-retired", "activation-malformed":
				qualRecordPut(t, f.store, []byte(registrationActivationPrefix+string(x.token)), qualRecordFrame(x.token, id, []byte(map[string]string{"activation-active": "Active", "activation-setup": "SETUP", "activation-retired": "RetiredDeny", "activation-malformed": "other"}[fault])))
			case "supplied-id":
				id[0] ^= 1
			case "domain":
				x.c.domain = []byte("other-network")
			case "before-epoch":
				x.c.enableEpoch = 11
			case "ended":
				f.end()
			case "native-error":
				x.nativeErr = original
			case "native-mutation":
				x.nativeHook = func() { qualRecordPut(t, f.store, []byte("T46-unrelated"), []byte{1}) }
			case "pa-missing":
				x.pa = nil
			case "co-missing":
				x.co = nil
			case "pa-unavailable":
				delete(x.v.roles, "PROGRAM_ADMINISTRATION")
			case "co-unavailable":
				delete(x.v.roles, "BOOTSTRAP_CANCEL")
			case "state-missing":
				x.state = nil
			case "pa-bad":
				x.pa[len(x.pa)-1] ^= 1
			case "co-bad":
				x.co[len(x.co)-1] ^= 1
			case "borrow-purpose":
				x.co = bytes.Clone(x.pa)
			case "state-denied":
				x.v.deny = "NATIVE_BOOTSTRAP_STATE"
			case "verifier-mutation":
				x.v.hook = func(p string) {
					if p == "PROGRAM_ADMINISTRATION" {
						qualRecordPut(t, f.store, []byte("T46-unrelated"), []byte{1})
					}
				}
			case "time-invalidation":
				x.v.hook = func(p string) {
					if p == "NATIVE_BOOTSTRAP_STATE" {
						require.NoError(t, f.hook.SetCurrentHeader(qualT42Header(core.MetachainShardId, 101)))
					}
				}
			case "save":
				f.store.saveErr = original
			case "rollback":
				x.nativeErr = original
				x.nativeHook = func() { qualRecordPut(t, f.store, []byte("T46-unrelated"), []byte{1}) }
				f.store.revertErr = rollback
			case "bytes-exhausted":
				x.c.limits.RetainedBytes = binary.BigEndian.Uint64(qualRegistryValue(t, f.store, scopedAdmissionPrefix+"budget")[8:16])
			case "budget-missing":
				qualRecordPut(t, f.store, []byte(scopedAdmissionPrefix+"budget"), nil)
			case "oversize":
				x.state = bytes.Repeat([]byte{1}, 4097)
			}
			before, e := f.store.RootHash()
			require.NoError(t, e)
			journal := f.store.JournalLen()
			err := x.cancel(id)
			require.Error(t, err)
			if fault == "rollback" {
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, rollback)
				_, out, e := f.boundary.Commit()
				require.ErrorIs(t, e, rollback)
				require.Empty(t, out)
				return
			}
			f.store.saveErr = nil
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Empty(t, f.boundary.outputs)
		})
	}
}
func TestQualDRWAT46CancellationSerializesAndNoDefaults(t *testing.T) {
	x := qualT46New(t, core.FungibleESDT)
	f := x.f
	_, err := f.owner.WithBootstrapCancellation(nil, []byte("n"), 10, x.c.limits, x.v)
	require.Error(t, err)
	_, err = f.owner.WithBootstrapCancellation(f.hook, []byte("n"), 10, x.c.limits, nil)
	require.Error(t, err)
	foreign, _ := qualT42Hook(t, qualRegistrationStore(t, 0), core.MetachainShardId, true)
	_, err = f.owner.WithBootstrapCancellation(foreign, []byte("n"), 10, x.c.limits, x.v)
	require.Error(t, err)
	entered, release, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	x.v.hook = func(p string) {
		if p == "PROGRAM_ADMINISTRATION" {
			close(entered)
			<-release
		}
	}
	go func() { result <- x.cancel(f.owner.id) }()
	<-entered
	err = x.cancel(f.owner.id)
	require.ErrorIs(t, err, ErrExecutionBusy)
	close(release)
	require.NoError(t, <-result)
}
