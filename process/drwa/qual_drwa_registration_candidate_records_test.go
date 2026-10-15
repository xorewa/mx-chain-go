package drwa

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

type qualCandidateRecordsStore struct {
	*qualNativeStore
	saves, failAt int
	fault         error
}

func (s *qualCandidateRecordsStore) SaveAccount(a vmcommon.AccountHandler) error {
	s.saves++
	if err := s.qualNativeStore.SaveAccount(a); err != nil {
		return err
	}
	if s.saves == s.failAt {
		return s.fault
	}
	return nil
}

type qualCandidateRecordsFixture struct {
	candidate           *registrationCandidate
	store               *qualCandidateRecordsStore
	owner               *RegistrationIntentOwner
	body                bootstrapIntentBody
	vector              qualCreationVector
	id, encoded, digest []byte
	anchor              metaRegistryAnchor
}

func qualCandidateRecords(t *testing.T, auto, full bool, family string) qualCandidateRecordsFixture {
	t.Helper()
	body, encoded, digest, id, vector := qualCreationIntent(family)
	count := make([]byte, 8)
	if full {
		count[7] = 2
	}
	f := qualRegistryTransportWithSetup(t, auto, count, []byte{1}, false, func(accounts state.AccountsAdapter) {
		qualRecordPut(t, &qualNativeStore{AccountsAdapter: accounts}, append([]byte(registrationIntentPrefix), id...),
			qualRecordFrame(encoded, []byte("OPEN"), nil))
	})
	transport, err := newRegistryTransport(f.reader, 2, f.limit)
	require.NoError(t, err)
	projection, err := transport.reconstruct(f.anchor, f.count, f.members)
	require.NoError(t, err)
	s := &qualCandidateRecordsStore{qualNativeStore: &qualNativeStore{AccountsAdapter: f.source}}
	r, err := reconstructRegistrationCandidate(s, qualRegistrationCoordinator(), 2, projection)
	require.NoError(t, err)
	owner, err := r.BindIntent(id, digest, bytes.Repeat([]byte{0x22}, 32), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	return qualCandidateRecordsFixture{candidate: r, store: s, owner: owner, body: body, vector: vector,
		id: id, encoded: encoded, digest: digest, anchor: copyRegistryAnchor(f.anchor)}
}

func (f qualCandidateRecordsFixture) create(create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	return f.owner.RegisterTokenForCommittedCreation(f.body.issuer, f.owner.manager, f.body.requestedTokenFamily,
		f.vector.profile, f.vector.name, f.vector.ticker, 6, f.vector.bodyHash,
		func(accounts state.AccountsAdapter, _, _, _, _, _ []byte, _ uint32, _ [][]byte) ([]byte, *vmcommon.VMOutput, error) {
			return create(accounts)
		})
}

func TestQualDRWARegistrationCandidateRecordsFamilies(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
			core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
			t.Run(fmt.Sprintf("auto_%t/%s", auto, family), func(t *testing.T) {
				f := qualCandidateRecords(t, auto, false, family)
				require.NoError(t, f.create(qualRegistrationCreator(t, "TOKEN-abcdef")))
				qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", true)
				qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdee", false)
				require.Equal(t, 3, f.store.saves, "one native token, one full-record and one registry/count save")
				for key, want := range map[string][]byte{
					registrationIntentPrefix + string(f.id):        qualRecordFrame(f.encoded, []byte("CONSUMED"), []byte("TOKEN-abcdef")),
					registrationAssociationPrefix + "TOKEN-abcdef": qualRecordFrame([]byte("TOKEN-abcdef"), f.id, f.digest, f.encoded, bytes.Repeat([]byte{0x22}, 32)),
					registrationActivationPrefix + "TOKEN-abcdef":  qualRecordFrame([]byte("TOKEN-abcdef"), f.id, []byte("BootstrapDeny")),
					registryMemberKeyPrefix + "TOKEN-abcdef":       {1},
					registryCountKey:                               {0, 0, 0, 0, 0, 0, 0, 1},
				} {
					require.Equal(t, want, qualRegistryValue(t, f.store.qualNativeStore, key), key)
				}
				// Replay cannot consume the intent a second time or add a delta.
				require.Error(t, f.create(qualRegistrationCreator(t, "TOKEN-abcdee")))
				qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", true)
				qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdee", false)
				_, outputs, err := f.candidate.commit()
				require.NoError(t, err)
				require.Len(t, outputs, 1)
				require.Equal(t, []byte("TOKEN-abcdef"), outputs[0].ReturnData[0])
				_, err = f.candidate.classify(f.anchor.candidateHash, []byte("TOKEN-abcdef"))
				require.ErrorIs(t, err, ErrExecutionClosed)
			})
		}
	}
}

func TestQualDRWARegistrationCandidateRecordsRollback(t *testing.T) {
	for _, fault := range []string{"token", "records", "registry", "creator", "cancelled", "nil-output", "failed-output", "invalid-id"} {
		t.Run(fault, func(t *testing.T) {
			f := qualCandidateRecords(t, false, false, core.FungibleESDT)
			original := errors.New("full registration fault")
			f.store.fault = original
			switch fault {
			case "token":
				f.store.failAt = 1
			case "records":
				f.store.failAt = 2
			case "registry":
				f.store.failAt = 3
			}
			root, err := f.store.RootHash()
			require.NoError(t, err)
			err = f.create(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
				id, out, err := qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
				if err != nil {
					return nil, nil, err
				}
				switch fault {
				case "creator":
					return nil, nil, original
				case "cancelled":
					qualRecordPut(t, f.store.qualNativeStore, append([]byte(registrationIntentPrefix), f.id...), qualRecordFrame(f.encoded, []byte("CANCELLED"), nil))
				case "nil-output":
					out = nil
				case "failed-output":
					out.ReturnCode = vmcommon.UserError
				case "invalid-id":
					id = []byte("invalid")
				}
				return id, out, nil
			})
			require.Error(t, err)
			if fault == "token" || fault == "records" || fault == "registry" || fault == "creator" {
				require.ErrorIs(t, err, original)
			}
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, f.store.JournalLen())
			require.Equal(t, qualRecordFrame(f.encoded, []byte("OPEN"), nil), qualRegistryValue(t, f.store.qualNativeStore, registrationIntentPrefix+string(f.id)))
			for _, prefix := range []string{registrationAssociationPrefix, registrationActivationPrefix, registryMemberKeyPrefix} {
				require.Empty(t, qualRegistryValue(t, f.store.qualNativeStore, prefix+"TOKEN-abcdef"))
			}
			qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", false)
			f.store.failAt = 0
			require.NoError(t, f.create(qualRegistrationCreator(t, "TOKEN-abcdef")))
			qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", true)
			_, outputs, err := f.candidate.commit()
			require.NoError(t, err)
			require.Len(t, outputs, 1)
		})
	}
}

func TestQualDRWARegistrationCandidateRecordsPoison(t *testing.T) {
	for _, fault := range []string{"rollback", "commit", "abort"} {
		t.Run(fault, func(t *testing.T) {
			f := qualCandidateRecords(t, false, false, core.FungibleESDT)
			original, undo := errors.New("full record write fault"), errors.New("full record rollback fault")
			if fault == "rollback" {
				f.store.fault, f.store.failAt, f.store.revertErr = original, 3, undo
				err := f.create(qualRegistrationCreator(t, "TOKEN-abcdef"))
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, undo)
			} else {
				require.NoError(t, f.create(qualRegistrationCreator(t, "TOKEN-abcdef")))
				if fault == "commit" {
					f.store.commitErr = original
					_, out, err := f.candidate.commit()
					require.ErrorIs(t, err, original)
					require.Nil(t, out)
				} else {
					require.NoError(t, f.candidate.abort())
				}
			}
			_, err := f.candidate.classify(f.anchor.candidateHash, []byte("TOKEN-abcdef"))
			require.Error(t, err)
			_, out, err := f.candidate.commit()
			require.Error(t, err)
			require.Nil(t, out)
			require.Error(t, f.create(qualRegistrationCreator(t, "TOKEN-abcdee")))
			if fault != "abort" {
				require.NoError(t, f.candidate.recover())
			}
			after, err := f.store.RootHash()
			require.NoError(t, err)
			require.Equal(t, f.anchor.root, after)
			require.Zero(t, f.store.JournalLen())
			require.Equal(t, qualRecordFrame(f.encoded, []byte("OPEN"), nil), qualRegistryValue(t, f.store.qualNativeStore, registrationIntentPrefix+string(f.id)))
			for _, prefix := range []string{registrationAssociationPrefix, registrationActivationPrefix, registryMemberKeyPrefix} {
				require.Empty(t, qualRegistryValue(t, f.store.qualNativeStore, prefix+"TOKEN-abcdef"))
			}
		})
	}
}

func TestQualDRWARegistrationCandidateRecordsGuards(t *testing.T) {
	for _, fault := range []string{"capacity", "issuer", "manager", "family", "profile", "body", "nil-writer", "nil-candidate"} {
		t.Run(fault, func(t *testing.T) {
			f := qualCandidateRecords(t, false, fault == "capacity", core.FungibleESDT)
			switch fault {
			case "issuer":
				f.body.issuer[0] ^= 1
			case "manager":
				f.owner.manager[0] ^= 1
			case "family":
				f.body.requestedTokenFamily = []byte(core.NonFungibleESDTv2)
			case "profile":
				f.vector.profile[0] ^= 1
			case "body":
				f.vector.bodyHash[0] ^= 1
			case "nil-writer":
				f.owner.registration = (*RegistryRegistration)(nil)
			case "nil-candidate":
				f.owner.registration = (*registrationCandidate)(nil)
			}
			called := false
			require.Error(t, f.create(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }))
			require.False(t, called)
			require.Zero(t, f.store.saves)
			require.Zero(t, f.store.JournalLen())
			qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", false)
			require.Equal(t, qualRecordFrame(f.encoded, []byte("OPEN"), nil), qualRegistryValue(t, f.store.qualNativeStore, registrationIntentPrefix+string(f.id)))
		})
	}
}

func TestQualDRWARegistrationCandidateRecordsReentry(t *testing.T) {
	f := qualCandidateRecords(t, false, false, core.FungibleESDT)
	require.NoError(t, f.create(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		_, err := f.candidate.classify(f.anchor.candidateHash, []byte("TOKEN-abcdef"))
		require.ErrorIs(t, err, ErrExecutionBusy)
		require.ErrorIs(t, f.create(qualRegistrationCreator(t, "TOKEN-abcdee")), ErrExecutionBusy)
		_, _, err = f.candidate.commit()
		require.ErrorIs(t, err, ErrExecutionBusy)
		require.ErrorIs(t, f.candidate.recover(), ErrExecutionBusy)
		return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
	}))
	qualAssertRegistrationClassification(t, f.candidate, f.anchor.candidateHash, "TOKEN-abcdef", true)
}
