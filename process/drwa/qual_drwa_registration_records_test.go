package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/common/holders"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// Independent field-1 protobuf vectors: no production codec or Batch marshaler
// creates these expected bytes. Numeric bounds below are experimental fixtures,
// not admitted capacity, deployment or authority inputs.
func qualRecordFrame(fields ...[]byte) []byte {
	var out []byte
	for _, field := range fields {
		out = append(out, 0x0a)
		var length [10]byte
		n := binary.PutUvarint(length[:], uint64(len(field)))
		out = append(out, length[:n]...)
		out = append(out, field...)
	}
	return out
}

func qualRecordBody() (bootstrapIntentBody, []byte, []byte, []byte) {
	body := bootstrapIntentBody{networkDomain: []byte("n"), issuer: bytes.Repeat([]byte{0x11}, 32),
		programID: []byte("p"), intentNonce: []byte("1"), requestedTokenFamily: []byte(core.FungibleESDT),
		creationProfile: []byte("profile"), nameCommitment: []byte("name"), tickerCommitment: []byte("ticker"),
		propertyCommitment: []byte("props"), publicSchemaProfile: []byte("schema"),
		issuerProgramAdmissionDecision: []byte("admission"), proposedProgramAuthoritySetBodies: [][]byte{[]byte("pa-body")},
		proposedProgramAuthoritySetHashes: [][]byte{bytes.Repeat([]byte{2}, 32)}, closurePlan: []byte("burn-and-retire"),
		networkProfile: []byte("network-profile"), expiry: HeaderMilliseconds(1)}
	encoded := qualRecordFrame([]byte("n"), bytes.Repeat([]byte{0x11}, 32), []byte("p"), []byte("1"),
		[]byte(core.FungibleESDT), []byte("profile"), []byte("name"), []byte("ticker"), []byte("props"),
		[]byte("schema"), []byte("admission"), qualRecordFrame([]byte("pa-body")),
		qualRecordFrame(bytes.Repeat([]byte{2}, 32)), []byte("burn-and-retire"), []byte("network-profile"),
		[]byte{0, 0, 0, 0, 0, 0, 0, 1})
	hash := blake2b.NewBlake2b()
	digest := hash.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), encoded)))
	id := hash.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), []byte("n"),
		bytes.Repeat([]byte{0x11}, 32), []byte("p"), []byte("1"), digest)))
	return body, encoded, digest, id
}

func qualRecordPut(t *testing.T, s *qualNativeStore, key, value []byte) {
	t.Helper()
	a, err := s.GetExistingAccount(core.SystemAccountAddress)
	require.NoError(t, err)
	require.NoError(t, a.(state.UserAccountHandler).SaveKeyValue(key, value))
	require.NoError(t, s.SaveAccount(a))
}

func qualRecordStore(t *testing.T) (*qualNativeStore, *registrationRecords, []byte, []byte) {
	t.Helper()
	s := qualRegistrationStore(t, 0)
	_, body, digest, id := qualRecordBody()
	qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(body, []byte("OPEN"), nil))
	_, err := s.Commit()
	require.NoError(t, err)
	records, err := newRegistrationRecords(s, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	return s, records, digest, id
}

func TestQualDRWARegistryRegistrationRecordsVectors(t *testing.T) {
	_, records, _, _ := qualRecordStore(t)
	encoded, err := records.frame([]byte("a"), nil)
	require.NoError(t, err)
	require.Equal(t, []byte{0x0a, 1, 'a', 0x0a, 0}, encoded)
	body, expected, digest, id := qualRecordBody()
	actual, actualDigest, actualID, err := records.identity(body)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, digest, actualDigest)
	require.Equal(t, id, actualID)
	decoded, err := records.decodeBody(expected)
	require.NoError(t, err)
	require.Equal(t, body, decoded)
	shortExpiry := append(bytes.Clone(expected[:len(expected)-10]), 0x0a, 1, 1)
	_, err = records.decodeBody(shortExpiry)
	require.Error(t, err)
	_, err = records.decodeBody(qualRecordFrame([]byte("only")))
	require.Error(t, err)
	for _, value := range [][]byte{nil, {0x0a}, {0x0a, 0x81, 0, 'a', 0x0a, 0},
		{0x0a, 1, 'a', 0x0a, 0, 0x28, 0}, {0x0a, 1, 'a', 0x0a, 0, 0x18, 1},
		{0x0a, 1, 'a'}, bytes.Repeat([]byte{0}, 4097)} {
		_, err = records.unframe(value, 2)
		require.Error(t, err)
	}
	for _, plan := range []string{"", "unknown", "Burn-And-Retire", "burn-and-retire ", "preserve-and-close"} {
		changed := body
		changed.closurePlan = []byte(plan)
		_, err = records.encodeBody(changed)
		if plan == "preserve-and-close" {
			require.NoError(t, err)
			_, nextDigest, nextID, err := records.identity(changed)
			require.NoError(t, err)
			require.NotEqual(t, digest, nextDigest)
			require.NotEqual(t, id, nextID)
		} else {
			require.Error(t, err)
		}
	}
}

func TestQualDRWARegistryRegistrationRecordsAtomic(t *testing.T) {
	s, records, digest, id := qualRecordStore(t)
	r, boundary := qualRegistrationOwner(t, s, 2)
	manager := bytes.Repeat([]byte{0x22}, 32) // fixture only, not allocated manager
	tokenID := []byte("TOKEN-abcdef")
	require.NoError(t, r.registerTokenForIntent(records, id, digest, manager, qualRegistrationCreator(t, string(tokenID))))
	intent, actualManager, err := records.registeredToken(tokenID)
	require.NoError(t, err)
	require.Equal(t, "CONSUMED", intent.status)
	require.Equal(t, tokenID, intent.tokenID)
	require.Equal(t, manager, actualManager)
	_, body, _, _ := qualRecordBody()
	require.Equal(t, qualRecordFrame(tokenID, id, digest, body, manager),
		qualRegistryValue(t, s, registrationAssociationPrefix+string(tokenID)))
	require.Equal(t, qualRecordFrame(tokenID, id, []byte("BootstrapDeny")),
		qualRegistryValue(t, s, registrationActivationPrefix+string(tokenID)))
	require.Equal(t, qualRecordFrame(body, []byte("CONSUMED"), tokenID),
		qualRegistryValue(t, s, registrationIntentPrefix+string(id)))
	called := false
	require.Error(t, r.registerTokenForIntent(records, id, digest, manager,
		func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }))
	require.False(t, called)
	roots, output, err := boundary.Commit()
	require.NoError(t, err)
	require.Len(t, output, 1)
	require.NoError(t, s.RecreateTrie(holders.NewRootHashHolder(roots[0], core.OptionalUint32{})))
	intent, actualManager, err = records.registeredToken(tokenID)
	require.NoError(t, err)
	require.Equal(t, manager, actualManager)
	require.Equal(t, body, intent.encoded)
	require.Equal(t, uint64(1), binary.BigEndian.Uint64(qualRegistryValue(t, s, registryCountKey)))
	actualManager[0] ^= 1
	_, actualManager, err = records.registeredToken(tokenID)
	require.NoError(t, err)
	require.Equal(t, manager, actualManager)
}

func TestQualDRWARegistryRegistrationRecordsRollback(t *testing.T) {
	for _, fault := range []string{"digest", "cancelled", "changed-body", "association", "activation", "save", "late-registry", "failed-rollback"} {
		t.Run(fault, func(t *testing.T) {
			s, records, digest, id := qualRecordStore(t)
			_, body, _, _ := qualRecordBody()
			if fault == "cancelled" {
				qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(body, []byte("CANCELLED"), nil))
			}
			if fault == "association" || fault == "activation" {
				prefix := registrationAssociationPrefix
				if fault == "activation" {
					prefix = registrationActivationPrefix
				}
				qualRecordPut(t, s, []byte(prefix+"TOKEN-abcdef"), []byte("corrupt existing fact"))
			}
			_, err := s.Commit()
			require.NoError(t, err)
			root, err := s.RootHash()
			require.NoError(t, err)
			r, boundary := qualRegistrationOwner(t, s, 2)
			if fault == "digest" {
				digest = bytes.Repeat([]byte{3}, 32)
			}
			original, rollback := errors.New("record save failed"), errors.New("rollback failed")
			err = r.registerTokenForIntent(records, id, digest, bytes.Repeat([]byte{0x22}, 32),
				func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
					tokenID, out, err := qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
					if err != nil {
						return nil, nil, err
					}
					if fault == "changed-body" {
						qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame([]byte("wrong-body"), []byte("OPEN"), nil))
					}
					if fault == "save" || fault == "failed-rollback" {
						s.saveErr = original
					}
					if fault == "failed-rollback" {
						s.revertErr = rollback
					}
					if fault == "late-registry" {
						qualRecordPut(t, s, []byte(registryMemberKeyPrefix+"TOKEN-abcdef"), []byte{1})
					}
					return tokenID, out, nil
				})
			require.Error(t, err)
			if fault == "failed-rollback" {
				require.ErrorIs(t, err, original)
				require.ErrorIs(t, err, rollback)
				_, out, err := boundary.Commit()
				require.Error(t, err)
				require.Empty(t, out)
				require.NoError(t, boundary.Recover())
			} else if fault == "save" {
				require.ErrorIs(t, err, original)
			}
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, s.JournalLen())
			require.Equal(t, uint64(0), binary.BigEndian.Uint64(qualRegistryValue(t, s, registryCountKey)))
		})
	}
}

func TestQualDRWARegistryRegistrationRecordsMalformed(t *testing.T) {
	s, records, _, id := qualRecordStore(t)
	body, encoded, _, _ := qualRecordBody()
	for _, mutate := range []func(*bootstrapIntentBody){
		func(b *bootstrapIntentBody) { b.issuer = nil },
		func(b *bootstrapIntentBody) { b.issuer = []byte{1} },
		func(b *bootstrapIntentBody) { b.programID = nil },
		func(b *bootstrapIntentBody) { b.requestedTokenFamily = []byte("unknown") },
		func(b *bootstrapIntentBody) { b.proposedProgramAuthoritySetBodies = nil },
		func(b *bootstrapIntentBody) { b.proposedProgramAuthoritySetBodies = [][]byte{nil} },
		func(b *bootstrapIntentBody) { b.proposedProgramAuthoritySetHashes = nil },
		func(b *bootstrapIntentBody) {
			b.proposedProgramAuthoritySetHashes = [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
		},
		func(b *bootstrapIntentBody) { b.proposedProgramAuthoritySetHashes = [][]byte{{1}} },
	} {
		changed := body
		mutate(&changed)
		_, err := records.encodeBody(changed)
		require.Error(t, err)
	}
	_, err := records.frame(bytes.Repeat([]byte{1}, 4097))
	require.Error(t, err)
	_, err = records.frame(bytes.Repeat([]byte{1}, 4094))
	require.Error(t, err, "native varint overhead exceeds the exact byte bound")
	_, err = records.authorityList(make([][]byte, 2049))
	require.Error(t, err)
	_, err = records.authorityList(nil)
	require.Error(t, err)
	_, err = newRegistrationRecords(nil, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.Error(t, err)
	_, err = newRegistrationRecords(s, nil, blake2b.NewBlake2b(), 4096)
	require.Error(t, err)
	_, err = newRegistrationRecords(s, &marshal.GogoProtoMarshalizer{}, nil, 4096)
	require.Error(t, err)
	_, err = newRegistrationRecords(s, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 0)
	require.Error(t, err)
	_, err = records.intent(nil)
	require.Error(t, err)
	for _, status := range []string{"", "UNKNOWN", "OPEN", "CANCELLED", "CONSUMED"} {
		token := []byte("TOKEN-abcdef")
		if status == "CONSUMED" {
			token = nil
		}
		qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(encoded, []byte(status), token))
		_, err := records.intent(id)
		require.Error(t, err)
	}
	_, _, err = records.registeredToken([]byte("invalid"))
	require.Error(t, err)
	_, _, err = records.registeredToken([]byte("TOKEN-abcdef"))
	require.Error(t, err)
}

type qualRecordMarshaller struct {
	marshal.GogoProtoMarshalizer
	reads int
}

func (m *qualRecordMarshaller) Unmarshal(value interface{}, encoded []byte) error {
	m.reads++
	return m.GogoProtoMarshalizer.Unmarshal(value, encoded)
}

func TestQualDRWARegistryRegistrationRecordsDecodeBudget(t *testing.T) {
	s, _, _, _ := qualRecordStore(t)
	m := &qualRecordMarshaller{}
	records, err := newRegistrationRecords(s, m, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	_, err = records.unframe(bytes.Repeat([]byte{0}, 4097), 1)
	require.Error(t, err)
	require.Zero(t, m.reads, "reject before native protobuf allocations")
	_, err = records.unframe(nil, 1)
	require.Error(t, err)
	require.Zero(t, m.reads)
}

func TestQualDRWARegistryRegistrationRecordsPredecessor(t *testing.T) {
	s, records, digest, id := qualRecordStore(t)
	expected, err := records.intent(id)
	require.NoError(t, err)
	manager, token := bytes.Repeat([]byte{0x22}, 32), []byte("TOKEN-abcdef")
	wrongBody := *expected
	wrongBody.encoded = []byte("other body")
	require.Error(t, records.consume(id, &wrongBody, token, manager))
	wrongDigest := *expected
	wrongDigest.digest = bytes.Repeat([]byte{0x33}, 32)
	require.Error(t, records.consume(id, &wrongDigest, token, manager))
	require.Error(t, records.consume(id, nil, token, manager))
	require.Error(t, records.consume(id, expected, token, nil))
	require.Error(t, records.consume(id, expected, []byte("invalid"), manager))
	_, encoded, _, _ := qualRecordBody()
	qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(encoded, []byte("CANCELLED"), nil))
	_, err = s.Commit()
	require.NoError(t, err)
	r, _ := qualRegistrationOwner(t, s, 2)
	called := false
	require.Error(t, r.registerTokenForIntent(records, id, digest, manager,
		func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }))
	require.False(t, called, "terminal intent is refused before creation")
	qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(encoded, []byte("OPEN"), nil))
	_, err = s.Commit()
	require.NoError(t, err)
	r, _ = qualRegistrationOwner(t, s, 2)
	require.Error(t, r.registerTokenForIntent(records, id, bytes.Repeat([]byte{0x33}, 32), manager,
		func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) { called = true; return nil, nil, nil }))
	require.False(t, called, "wrong immutable digest is refused before creation")
	other, otherRecords, _, _ := qualRecordStore(t)
	_ = other
	require.Error(t, r.registerTokenForIntent(otherRecords, id, digest, manager, qualRegistrationCreator(t, string(token))))
	require.Error(t, r.registerTokenForIntent(nil, id, digest, manager, nil))
	require.Error(t, r.registerTokenForIntent(records, id, digest, manager, nil))
	changed, _, _, _ := qualRecordBody()
	changed.closurePlan = []byte("preserve-and-close")
	changedBytes, err := records.encodeBody(changed)
	require.NoError(t, err)
	qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(changedBytes, []byte("OPEN"), nil))
	_, err = records.intent(id)
	require.Error(t, err, "valid different body cannot occupy the old intent identity")
}

func TestQualDRWARegistryRegistrationRecordsSaveError(t *testing.T) {
	s, records, _, id := qualRecordStore(t)
	expected, err := records.intent(id)
	require.NoError(t, err)
	root, err := s.RootHash()
	require.NoError(t, err)
	boundary, err := NewRollbackContainment(s)
	require.NoError(t, err)
	fault := errors.New("record account save failed")
	s.saveErr = fault
	err = boundary.Execute(func() (*vmcommon.VMOutput, error) {
		return nil, records.consume(id, expected, []byte("TOKEN-abcdef"), bytes.Repeat([]byte{0x22}, 32))
	})
	require.ErrorIs(t, err, fault)
	after, err := s.RootHash()
	require.NoError(t, err)
	require.Equal(t, root, after)
	require.Zero(t, s.JournalLen())
}

func TestQualDRWARegistryRegistrationRecordsConstructorControl(t *testing.T) {
	s := qualRegistrationStore(t, 0)
	records, err := newRegistrationRecords(s, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	require.NotNil(t, records)
}

type qualRecordReads struct {
	state.AccountsAdapter
	reads int
}

func (s *qualRecordReads) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	s.reads++
	return s.AccountsAdapter.GetExistingAccount(address)
}

type qualRecordZeroHasher struct{ hashing.Hasher }

func (h *qualRecordZeroHasher) Size() int { return 0 }

func TestQualDRWARegistryRegistrationRecordsEarlyInput(t *testing.T) {
	s, _, _, _ := qualRecordStore(t)
	reader := &qualRecordReads{AccountsAdapter: s}
	records, err := newRegistrationRecords(reader, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	_, err = records.intent(nil)
	require.Error(t, err)
	require.Zero(t, reader.reads)
	_, _, err = records.registeredToken([]byte("invalid"))
	require.Error(t, err)
	require.Zero(t, reader.reads)
	_, err = newRegistrationRecords(s, &marshal.GogoProtoMarshalizer{}, &qualRecordZeroHasher{Hasher: blake2b.NewBlake2b()}, 4096)
	require.Error(t, err)
}

func TestQualDRWARegistryRegistrationRecordsInputOwnership(t *testing.T) {
	s, records, digest, id := qualRecordStore(t)
	r, boundary := qualRegistrationOwner(t, s, 2)
	manager := bytes.Repeat([]byte{0x22}, 32)
	originalManager, originalID := bytes.Clone(manager), bytes.Clone(id)
	require.NoError(t, r.registerTokenForIntent(records, id, digest, manager,
		func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			id[0] ^= 1
			manager[0] ^= 1
			return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
		}))
	_, _, err := boundary.Commit()
	require.NoError(t, err)
	intent, actualManager, err := records.registeredToken([]byte("TOKEN-abcdef"))
	require.NoError(t, err)
	require.Equal(t, originalManager, actualManager)
	_, _, actualID, err := records.identity(intent.body)
	require.NoError(t, err)
	require.Equal(t, originalID, actualID)
}

func TestQualDRWARegistryRegistrationRecordsAssociationIntegrity(t *testing.T) {
	for _, fault := range []string{"token", "intent", "digest", "body", "manager", "consumed-token", "consumed-status"} {
		t.Run(fault, func(t *testing.T) {
			s, records, digest, id := qualRecordStore(t)
			r, boundary := qualRegistrationOwner(t, s, 2)
			manager := bytes.Repeat([]byte{0x22}, 32)
			token := []byte("TOKEN-abcdef")
			require.NoError(t, r.registerTokenForIntent(records, id, digest, manager, qualRegistrationCreator(t, string(token))))
			_, _, err := boundary.Commit()
			require.NoError(t, err)
			_, body, _, _ := qualRecordBody()
			fields := [][]byte{token, id, digest, body, manager}
			switch fault {
			case "token":
				fields[0] = []byte("TOKEN-abcdee")
			case "intent":
				fields[1] = bytes.Repeat([]byte{3}, 32)
			case "digest":
				fields[2] = bytes.Repeat([]byte{3}, 32)
			case "body":
				fields[3] = []byte("wrong-body")
			case "manager":
				fields[4] = nil
			case "consumed-token":
				qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(body, []byte("CONSUMED"), []byte("TOKEN-abcdee")))
			case "consumed-status":
				qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(body, []byte("OPEN"), nil))
			}
			qualRecordPut(t, s, []byte(registrationAssociationPrefix+string(token)), qualRecordFrame(fields...))
			_, _, err = records.registeredToken(token)
			require.Error(t, err)
		})
	}
}
