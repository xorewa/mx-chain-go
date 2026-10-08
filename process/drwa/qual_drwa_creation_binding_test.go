package drwa

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

// These vectors precede creationBinding.go. The literal field order and values
// come from the owner-approved experimental L41 proposal e30be12c, not an
// encoder under test. qualRecordFrame hand-assembles native field-1 protobuf.
// Manager/address/byte bounds are fixtures, never network allocations.
func qualCreationProfileFields(family string) [][]byte {
	transfer := byte(1)
	if family == "FungibleESDT" {
		transfer = 0
	}
	return [][]byte{[]byte("DRWA/CREATION_PROFILE/v2"), []byte("n"), bytes.Repeat([]byte{0x22}, 32),
		[]byte(family), {0}, {1}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {transfer}}
}

type qualCreationVector struct {
	profile, name, ticker, decimals, profileHash, nameHash, tickerHash, propertyHash, body, bodyHash []byte
}

func qualCreationExpected(family string) qualCreationVector {
	h := blake2b.NewBlake2b()
	profile := qualRecordFrame(qualCreationProfileFields(family)...)
	profileHash := h.Compute(string(profile))
	name, ticker, decimals := []byte("RegulatedToken"), []byte("TOKEN"), []byte{0, 0, 0, 6}
	nameHash := h.Compute(string(qualRecordFrame([]byte("DRWA/CREATION_NAME/v1"), name)))
	tickerHash := h.Compute(string(qualRecordFrame([]byte("DRWA/CREATION_TICKER/v1"), ticker)))
	propertyHash := h.Compute(string(qualRecordFrame([]byte("DRWA/CREATION_PROPERTIES/v1"), profileHash, decimals)))
	body := qualRecordFrame([]byte("DRWA/TOKEN_CREATION_BODY/v1"), []byte(family), profileHash, name, ticker, decimals)
	return qualCreationVector{profile, name, ticker, decimals, profileHash, nameHash, tickerHash, propertyHash, body, h.Compute(string(body))}
}

func qualCreationIntent(family string) (bootstrapIntentBody, []byte, []byte, []byte, qualCreationVector) {
	b, _, _, _ := qualRecordBody()
	v := qualCreationExpected(family)
	b.requestedTokenFamily, b.creationProfile = []byte(family), v.profileHash
	b.nameCommitment, b.tickerCommitment, b.propertyCommitment = v.nameHash, v.tickerHash, v.propertyHash
	encoded, digest, id := qualCreationIntentBytes(b)
	return b, encoded, digest, id, v
}

func qualCreationIntentBytes(b bootstrapIntentBody) ([]byte, []byte, []byte) {
	encoded := qualRecordFrame(b.networkDomain, b.issuer, b.programID, b.intentNonce,
		b.requestedTokenFamily, b.creationProfile, b.nameCommitment, b.tickerCommitment, b.propertyCommitment,
		b.publicSchemaProfile, b.issuerProgramAdmissionDecision, qualRecordFrame(b.proposedProgramAuthoritySetBodies...),
		qualRecordFrame(b.proposedProgramAuthoritySetHashes...), b.closurePlan, b.networkProfile,
		[]byte{0, 0, 0, 0, 0, 0, 0, 1})
	h := blake2b.NewBlake2b()
	digest := h.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT_PAYLOAD/v1"), encoded)))
	id := h.Compute(string(qualRecordFrame([]byte("DRWA/BOOTSTRAP_INTENT/v1"), b.networkDomain,
		b.issuer, b.programID, b.intentNonce, digest)))
	return encoded, digest, id
}

func qualCreationOwner(t *testing.T, body bootstrapIntentBody) (*qualNativeStore, *RegistrationIntentOwner, *RollbackContainment) {
	t.Helper()
	s := qualRegistrationStore(t, 0)
	encoded, digest, id := qualCreationIntentBytes(body)
	qualRecordPut(t, s, append([]byte(registrationIntentPrefix), id...), qualRecordFrame(encoded, []byte("OPEN"), nil))
	_, err := s.Commit()
	require.NoError(t, err)
	r, boundary := qualRegistrationOwner(t, s, 2)
	o, err := r.BindIntent(id, digest, bytes.Repeat([]byte{0x22}, 32), &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
	require.NoError(t, err)
	return s, o, boundary
}

func TestQualDRWARegistryRegistrationCreationBindingFamilies(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			body, _, _, _, v := qualCreationIntent(family)
			s, o, boundary := qualCreationOwner(t, body)
			called := 0
			err := o.RegisterTokenForCommittedCreation(body.issuer, bytes.Repeat([]byte{0x22}, 32), []byte(family),
				v.profile, v.name, v.ticker, 6, v.bodyHash,
				func(accounts state.AccountsAdapter, issuer, manager, kind, name, ticker []byte, decimals uint32, properties [][]byte) ([]byte, *vmcommon.VMOutput, error) {
					called++
					require.Equal(t, body.issuer, issuer)
					require.Equal(t, bytes.Repeat([]byte{0x22}, 32), manager)
					require.Equal(t, []byte(family), kind)
					require.Equal(t, []byte("RegulatedToken"), name)
					require.Equal(t, []byte("TOKEN"), ticker)
					require.Equal(t, uint32(6), decimals)
					want := [][]byte{[]byte("canUpgrade"), []byte("false"), []byte("canAddSpecialRoles"), []byte("true")}
					if family != core.FungibleESDT {
						want = append(want, []byte("canTransferNFTCreateRole"), []byte("true"))
					}
					require.Equal(t, want, properties)
					return qualRegistrationCreator(t, "TOKEN-abcdef")(accounts)
				})
			require.NoError(t, err)
			require.Equal(t, 1, called)
			roots, outputs, err := boundary.Commit()
			require.NoError(t, err)
			require.Len(t, roots, 1)
			require.Len(t, outputs, 1)
			require.Equal(t, []byte{1}, qualRegistryValue(t, s, registryMemberKeyPrefix+"TOKEN-abcdef"))
			intent, manager, err := o.records.registeredToken([]byte("TOKEN-abcdef"))
			require.NoError(t, err)
			require.Equal(t, body, intent.body)
			require.Equal(t, bytes.Repeat([]byte{0x22}, 32), manager)
		})
	}
}

func TestQualDRWARegistryRegistrationCreationBindingDenial(t *testing.T) {
	faults := []string{"domain", "network", "profile-manager", "profile-family", "version", "profile-hash", "name", "ticker", "decimals", "body-hash",
		"body-width", "bool-width", "bool-invalid", "reordered", "extra", "unknown-metadata", "noncanonical", "truncated", "oversize", "frame-budget"}
	for i := 0; i < 10; i++ {
		faults = append(faults, "fixed-"+string(rune('0'+i)))
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			body, _, _, _, v := qualCreationIntent(core.FungibleESDT)
			f := qualCreationProfileFields(core.FungibleESDT)
			decimals := uint32(6)
			switch fault {
			case "domain":
				f[0] = []byte("WRONG/CREATION_PROFILE/v2")
			case "version":
				f[0] = []byte("DRWA/CREATION_PROFILE/v1")
			case "network":
				f[1] = []byte("wrong-network")
			case "profile-manager":
				f[2][0] ^= 1
			case "profile-family":
				f[3] = []byte(core.NonFungibleESDTv2)
			case "profile-hash":
				body.creationProfile = bytes.Repeat([]byte{3}, 32)
			case "name":
				v.name = []byte("OtherName")
			case "ticker":
				v.ticker = []byte("OTHER")
			case "decimals":
				decimals = 7
			case "body-hash":
				v.bodyHash = bytes.Repeat([]byte{3}, 32)
			case "body-width":
				v.bodyHash = []byte{3}
			case "bool-width":
				f[4] = []byte{0, 0}
			case "bool-invalid":
				f[4] = []byte{2}
			case "reordered":
				f[4], f[5] = f[5], f[4]
			case "extra":
				f = append(f, []byte{0})
			case "frame-budget":
				v.name = bytes.Repeat([]byte{'a'}, 4096)
			}
			if len(fault) == 7 && fault[:6] == "fixed-" {
				i := int(fault[6] - '0')
				f[4+i][0] ^= 1
			}
			v.profile = qualRecordFrame(f...)
			switch fault {
			case "unknown-metadata":
				v.profile = append(v.profile, 0x18, 1)
			case "noncanonical":
				v.profile = append([]byte{0x0a, 0x98, 0}, v.profile[2:]...)
			case "truncated":
				v.profile = v.profile[:len(v.profile)-1]
			case "oversize":
				v.profile = bytes.Repeat([]byte{0}, 4097)
			}
			// Shape/profile tests retain their hash to ensure the parser, rather
			// than a later hash mismatch, is the rejecting guard.
			h := blake2b.NewBlake2b()
			actualProfileHash := h.Compute(string(v.profile))
			if fault != "profile-hash" {
				body.creationProfile = actualProfileHash
				if fault != "decimals" {
					body.propertyCommitment = h.Compute(string(qualRecordFrame([]byte("DRWA/CREATION_PROPERTIES/v1"), actualProfileHash, []byte{0, 0, 0, 6})))
				}
			}
			if fault != "body-hash" && fault != "body-width" {
				width := make([]byte, 4)
				binary.BigEndian.PutUint32(width, decimals)
				v.bodyHash = h.Compute(string(qualRecordFrame([]byte("DRWA/TOKEN_CREATION_BODY/v1"), body.requestedTokenFamily, actualProfileHash, v.name, v.ticker, width)))
			}
			if fault == "frame-budget" {
				// A malformed authenticated commitment must not turn a failed
				// bounded frame into the hash of an empty buffer and permit work.
				body.nameCommitment, v.bodyHash = h.Compute(""), h.Compute("")
			}
			s, o, _ := qualCreationOwner(t, body)
			root, err := s.RootHash()
			require.NoError(t, err)
			called := false
			err = o.RegisterTokenForCommittedCreation(body.issuer, bytes.Repeat([]byte{0x22}, 32), body.requestedTokenFamily,
				v.profile, v.name, v.ticker, decimals, v.bodyHash,
				func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error) {
					called = true
					return nil, nil, nil
				})
			require.Error(t, err)
			require.False(t, called)
			after, err := s.RootHash()
			require.NoError(t, err)
			require.Equal(t, root, after)
			require.Zero(t, s.JournalLen())
			require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, qualRegistryValue(t, s, registryCountKey))
		})
	}
}

func TestQualDRWARegistryRegistrationCreationBindingNil(t *testing.T) {
	body, _, _, _, v := qualCreationIntent(core.FungibleESDT)
	_, healthy, _ := qualCreationOwner(t, body)
	create := func(state.AccountsAdapter, []byte, []byte, []byte, []byte, []byte, uint32, [][]byte) ([]byte, *vmcommon.VMOutput, error) {
		t.Fatal("must not create")
		return nil, nil, nil
	}
	for _, o := range []*RegistrationIntentOwner{nil, {registration: healthy.registration}} {
		require.Error(t, o.RegisterTokenForCommittedCreation(body.issuer, bytes.Repeat([]byte{0x22}, 32), body.requestedTokenFamily, v.profile, v.name, v.ticker, 6, v.bodyHash, create))
	}
	require.Error(t, healthy.RegisterTokenForCommittedCreation(body.issuer, bytes.Repeat([]byte{0x22}, 32), body.requestedTokenFamily, v.profile, v.name, v.ticker, 6, v.bodyHash, nil))
}

func TestQualDRWARegistryRegistrationCreationIndependentVectors(t *testing.T) {
	// Literal Python hashlib Blake2b-256 results retained before the product
	// encoder: independent_vectors.json c26a52035919c7a3f682e49db4f7adf79a668de421aadcaa16e17e448420e895.
	profiles := map[string]string{
		core.FungibleESDT:      "80ade8522896d00bc58c2357604cd635dc45aeda82afc7c447c63524ec89afe9",
		core.NonFungibleESDTv2: "33028fd07a994034b4f8a7a0fca6209b81d16bfcecdb75b223293aa330760f3a",
		core.SemiFungibleESDT:  "e5bc188f30ea437e6b1f4343d3e23b53288df876b1c9c883feb19c5f6ea499d7",
		core.MetaESDT:          "b8fdcb80ef9e51df8e1ab00dde53798f4fdb99c65d6a744903489e6ff067c2cf",
		core.DynamicNFTESDT:    "6fe42be35faf4d419330ea7bc74a352bef9742000c43d8dbb9c6112ab77eacd7",
		core.DynamicSFTESDT:    "eb7cf483f058372ecd9b3978127536089fc6cab8826b70443b9e90519712c6e3",
		core.DynamicMetaESDT:   "ed8beae0f9b3cf8818810919e60e04273cffbc7d424ab41de4f26820353d2662",
	}
	// Explicit decimal bytes, not production numeric encoding.
	require.Equal(t, uint32(6), binary.BigEndian.Uint32([]byte{0, 0, 0, 6}))
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			v := qualCreationExpected(family)
			require.Equal(t, []byte{0x0a, 0x18}, v.profile[:2])
			require.Len(t, v.profileHash, 32)
			require.Len(t, v.bodyHash, 32)
			require.Equal(t, profiles[family], hex.EncodeToString(v.profileHash))
			require.Equal(t, "f648b8081b183f490755d7707308ea992f64c8f98e4f01c629a441bb1b128ca9", hex.EncodeToString(v.nameHash))
			require.Equal(t, "6a2400720afa718586175cba4ce03a9ed982abdffa4df70eede739a3fc1b29c8", hex.EncodeToString(v.tickerHash))
			require.NotEqual(t, v.nameHash, v.tickerHash)
			require.NotEqual(t, v.propertyHash, v.bodyHash)
		})
	}
}

type qualCreationReadStore struct {
	state.AccountsAdapter
	reads  int
	onRead func(int) error
}

func (s *qualCreationReadStore) GetExistingAccount(address []byte) (vmcommon.AccountHandler, error) {
	s.reads++
	if s.onRead != nil {
		if err := s.onRead(s.reads); err != nil {
			return nil, err
		}
	}
	return s.AccountsAdapter.GetExistingAccount(address)
}

func TestQualDRWARegistryRegistrationCreationBindingBuffersAndReadError(t *testing.T) {
	for _, fault := range []string{"caller-buffers", "read-error", "pre-copy-budget"} {
		t.Run(fault, func(t *testing.T) {
			body, _, _, _, v := qualCreationIntent(core.FungibleESDT)
			s, original, _ := qualCreationOwner(t, body)
			reader := &qualCreationReadStore{AccountsAdapter: s}
			r, boundary, err := NewRegistryRegistration(reader, &testscommon.ShardsCoordinatorMock{SelfIDCalled: func() uint32 { return core.MetachainShardId }}, 2)
			require.NoError(t, err)
			o, err := r.BindIntent(original.id, original.digest, original.manager, &marshal.GogoProtoMarshalizer{}, blake2b.NewBlake2b(), 4096)
			require.NoError(t, err)
			reader.reads = 0
			readFault := errors.New("creation commitment native read failed")
			reader.onRead = func(n int) error {
				if fault == "read-error" && n == 4 {
					return readFault
				}
				if fault == "caller-buffers" && n == 1 {
					for _, value := range [][]byte{v.profile, v.name, v.ticker, v.bodyHash} {
						value[0] ^= 1
					}
				}
				return nil
			}
			if fault == "pre-copy-budget" {
				v.name = bytes.Repeat([]byte{'a'}, 4097)
			}
			called := false
			err = o.RegisterTokenForCommittedCreation(body.issuer, original.manager, body.requestedTokenFamily, v.profile, v.name, v.ticker, 6, v.bodyHash,
				func(a state.AccountsAdapter, _, _, _, name, ticker []byte, decimals uint32, _ [][]byte) ([]byte, *vmcommon.VMOutput, error) {
					called = true
					require.Equal(t, []byte("RegulatedToken"), name)
					require.Equal(t, []byte("TOKEN"), ticker)
					require.Equal(t, uint32(6), decimals)
					return qualRegistrationCreator(t, "TOKEN-abcdef")(a)
				})
			if fault == "caller-buffers" {
				require.NoError(t, err)
				require.True(t, called)
				_, outputs, commitErr := boundary.Commit()
				require.NoError(t, commitErr)
				require.Len(t, outputs, 1)
			} else {
				require.Error(t, err)
				require.False(t, called)
				require.Zero(t, s.JournalLen())
				if fault == "read-error" {
					require.ErrorIs(t, err, readFault)
					require.Equal(t, 4, reader.reads)
				}
				if fault == "pre-copy-budget" {
					require.Zero(t, reader.reads)
				}
			}
		})
	}
}
