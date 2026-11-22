package drwa

import (
	"bytes"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-chain-go/testscommon"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

func TestQualDRWARegistryRegistrationIntentOwnerControl(t *testing.T) {
	s, _, digest, id := qualRecordStore(t)
	registration, boundary := qualRegistrationOwner(t, s, 2)
	manager := bytes.Repeat([]byte{0x22}, 32)
	originalID, originalManager := bytes.Clone(id), bytes.Clone(manager)
	owner, err := registration.BindIntent(id, digest, manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	require.False(t, owner.IsInterfaceNil())
	id[0] ^= 1
	digest[0] ^= 1
	manager[0] ^= 1
	body, _, _, _ := qualRecordBody()
	require.NoError(t, owner.RegisterTokenForCreation(body.issuer, originalManager, body.requestedTokenFamily, qualRegistrationCreator(t, "TOKEN-abcdef")))
	_, out, err := boundary.Commit()
	require.NoError(t, err)
	require.Len(t, out, 1)
	intent, actualManager, err := owner.records.registeredToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.Equal(t, originalManager, actualManager)
	_, _, actualID, err := owner.records.identity(intent.body)
	require.NoError(t, err)
	require.Equal(t, originalID, actualID)
	require.Error(t, owner.RegisterTokenForCreation(body.issuer, originalManager, body.requestedTokenFamily, qualRegistrationCreator(t, "TOKEN-abcdee")))
}

type qualIntentOwnerReadFault struct {
	state.AccountsAdapter
	reads int
	fault error
}

func (s *qualIntentOwnerReadFault) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	s.reads++
	if s.reads == 3 {
		return nil, s.fault
	}
	return s.AccountsAdapter.GetExistingAccount(address)
}

func TestQualDRWARegistryRegistrationIntentOwnerReadError(t *testing.T) {
	s, _, digest, id := qualRecordStore(t)
	fault := errors.New("identity read failed")
	reader := &qualIntentOwnerReadFault{AccountsAdapter: s, fault: fault}
	registration, _, err := NewRegistryRegistration(reader, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 2)
	require.NoError(t, err)
	body, _, _, _ := qualRecordBody()
	manager := bytes.Repeat([]byte{0x22}, 32)
	owner, err := registration.BindIntent(id, digest, manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	reader.reads = 0
	called := false
	err = owner.RegisterTokenForCreation(body.issuer, manager, body.requestedTokenFamily, func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil })
	require.ErrorIs(t, err, fault)
	require.False(t, called)
	require.Equal(t, 3, reader.reads)
	require.Zero(t, s.JournalLen())
}

func TestQualDRWARegistryRegistrationIntentOwnerInvalid(t *testing.T) {
	s, _, digest, id := qualRecordStore(t)
	registration, _ := qualRegistrationOwner(t, s, 2)
	manager := bytes.Repeat([]byte{0x22}, 32)
	for _, defect := range []string{"nil-registration", "empty-registration", "missing-state", "missing-boundary", "id", "digest", "manager", "marshaller", "hasher", "bound"} {
		t.Run(defect, func(t *testing.T) {
			r := registration
			gotID, gotDigest, gotManager := id, digest, manager
			mar := marshal.Marshalizer(&marshal.GogoProtoMarshalizer{})
			hash := blake2b.NewBlake2b()
			limit := 4096
			switch defect {
			case "nil-registration":
				r = nil
			case "empty-registration":
				r = &RegistryRegistration{}
			case "missing-state":
				copy := *registration
				copy.state = nil
				r = &copy
			case "missing-boundary":
				copy := *registration
				copy.boundary = nil
				r = &copy
			case "id":
				gotID = nil
			case "digest":
				gotDigest = nil
			case "manager":
				gotManager = nil
			case "marshaller":
				mar = nil
			case "hasher":
				hash = nil
			case "bound":
				limit = 0
			}
			_, err := r.BindIntent(gotID, gotDigest, gotManager, mar, hash, limit)
			require.Error(t, err)
		})
	}
	var missing *RegistrationIntentOwner
	require.True(t, missing.IsInterfaceNil())
	body, _, _, _ := qualRecordBody()
	for _, owner := range []*RegistrationIntentOwner{nil, {}, {registration: registration}, {records: &registrationRecords{}}} {
		require.Error(t, owner.RegisterTokenForCreation(body.issuer, manager, body.requestedTokenFamily, qualRegistrationCreator(t, "TOKEN-abcdef")))
	}
	owner, err := registration.BindIntent(id, digest, manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	require.Error(t, owner.RegisterTokenForCreation(body.issuer, manager, body.requestedTokenFamily, nil))
}

func TestQualDRWARegistryRegistrationIntentOwnerCreation(t *testing.T) {
	s, _, digest, id := qualRecordStore(t)
	registration, boundary := qualRegistrationOwner(t, s, 2)
	manager := bytes.Repeat([]byte{0x22}, 32)
	owner, err := registration.BindIntent(id, digest, manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	body, _, _, _ := qualRecordBody()
	for _, defect := range []string{"issuer", "family", "manager"} {
		t.Run(defect, func(t *testing.T) {
			issuer, family, m := bytes.Clone(body.issuer), bytes.Clone(body.requestedTokenFamily), bytes.Clone(manager)
			switch defect {
			case "issuer":
				issuer[0] ^= 1
			case "family":
				family = []byte(core.NonFungibleESDTv2)
			case "manager":
				m[0] ^= 1
			}
			called := false
			err := owner.RegisterTokenForCreation(issuer, m, family, func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil })
			require.Error(t, err)
			require.False(t, called)
			require.Zero(t, s.JournalLen())
		})
	}
	require.NoError(t, owner.RegisterTokenForCreation(body.issuer, manager, body.requestedTokenFamily, qualRegistrationCreator(t, "TOKEN-abcdef")))
	_, out, err := boundary.Commit()
	require.NoError(t, err)
	require.Len(t, out, 1)
}
