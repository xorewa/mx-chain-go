package drwa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/stretchr/testify/require"
)

// R7 EXPERIMENTAL: three shards; canonical import/finality and lawful
// dependencies are synthetic. Native Ed25519 proof checks and actual native
// metadata byte representations are used. No network ACK/activation claim.
type qualRegistrationAckVerifier struct {
	t        *testing.T
	expected map[uint32][]byte
	roles    map[uint32]w03SignatureFixture
	hook     func(uint32)
	calls    int
}

func (v *qualRegistrationAckVerifier) IsInterfaceNil() bool { return v == nil }
func (v *qualRegistrationAckVerifier) VerifyRegistrationAck(shard uint32, expected, proof []byte) error {
	v.calls++
	if !bytes.Equal(v.expected[shard], expected) {
		return errInvalidRegistrationRecord
	}
	role, exists := v.roles[shard]
	if !exists || !bytes.Equal(proof, qualRecordFrame(role.signatures...)) {
		return errInvalidRegistrationRecord
	}
	if err := verifyProgrammeAuthoritySignatures("ED25519_M_OF_N", 3, role.members, role.indices, role.signatures,
		blake2b.NewBlake2b().Compute(string(expected)), 5, 32); err != nil {
		return err
	}
	if v.hook != nil {
		v.hook(shard)
	}
	expected[0] ^= 1
	proof[0] ^= 1
	return nil
}

func qualRegistrationAcks(t *testing.T, f *qualRegistrationAdmissionFixture) ([]RegistrationStateAck, *qualRegistrationAckVerifier) {
	t.Helper()
	acks := make([]RegistrationStateAck, 3)
	v := &qualRegistrationAckVerifier{t: t, expected: make(map[uint32][]byte), roles: make(map[uint32]w03SignatureFixture)}
	for shard := uint32(0); shard < 3; shard++ {
		types := map[string]byte{core.FungibleESDT: 1, core.NonFungibleESDTv2: 3, core.SemiFungibleESDT: 5, core.MetaESDT: 4,
			core.DynamicNFTESDT: 6, core.DynamicSFTESDT: 7, core.DynamicMetaESDT: 8}
		ack := RegistrationStateAck{Shard: shard, GlobalState: []byte{0, types[string(f.body.requestedTokenFamily)]}, AdminState: []byte("native-admin-false/profile"), Dependencies: []byte("exact-current-authority/profile")}
		// Independently frame all fields from the approved ACK obligations;
		// no production readiness encoder creates its own expected signature.
		activation := qualRecordFrame([]byte("TOKEN-abcdef"), f.owner.id, []byte("BootstrapDeny"))
		expected := qualRecordFrame([]byte("DRWA/STATE_ACK/candidate1"), []byte("n"), []byte("TOKEN-abcdef"), f.owner.id,
			blake2b.NewBlake2b().Compute(string(activation)), f.body.requestedTokenFamily, f.v.profileHash, f.owner.manager,
			ack.GlobalState, ack.AdminState, []byte{1}, ack.Dependencies, binary.BigEndian.AppendUint32(nil, shard))
		role := w03SignatureProof(t, 5, 3, []uint64{0, 1, 2})
		role.digest = blake2b.NewBlake2b().Compute(string(expected))
		role.sign(t)
		ack.Proof = qualRecordFrame(role.signatures...)
		v.expected[shard], v.roles[shard] = expected, role
		acks[shard] = ack
	}
	return acks, v
}

func TestQualDRWAT44T45ReadinessFamilies(t *testing.T) {
	for _, family := range []string{core.FungibleESDT, core.NonFungibleESDTv2, core.SemiFungibleESDT, core.MetaESDT,
		core.DynamicNFTESDT, core.DynamicSFTESDT, core.DynamicMetaESDT} {
		t.Run(family, func(t *testing.T) {
			f := qualRegistrationAdmission(t, family)
			require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
			acks, host := qualRegistrationAcks(t, f)
			require.NoError(t, f.admit.WithBootstrapReadiness([]byte("TOKEN-abcdef"), acks, host,
				func() (*vmcommon.VMOutput, error) { return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil }))
			require.Equal(t, 3, host.calls)
		})
	}
}

func TestQualDRWAT44T45ReadinessExactAllShardBarrier(t *testing.T) {
	for _, fault := range []string{"healthy", "out-of-order", "partial", "duplicate", "outside", "missing-state", "burn-enabled",
		"type-unset", "wrong-type", "noncanonical-state", "admin", "dependencies", "proof", "missing-member", "wrong-activation",
		"wrong-association", "host-mutation", "ended-context", "operation-error", "operation-failed-output"} {
		t.Run(fault, func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			require.NoError(t, f.register(t, qualRegistrationCreator(t, "TOKEN-abcdef")))
			acks, host := qualRegistrationAcks(t, f)
			switch fault {
			case "out-of-order":
				acks[0], acks[2] = acks[2], acks[0]
			case "partial":
				acks = acks[:2]
			case "duplicate":
				acks[2] = acks[0]
			case "outside":
				acks[2].Shard = 3
			case "missing-state":
				acks[1].GlobalState = nil
			case "burn-enabled":
				acks[1].GlobalState = []byte{4, 1}
			case "type-unset":
				acks[1].GlobalState = []byte{0, 0}
			case "wrong-type":
				acks[1].GlobalState = []byte{0, 7}
			case "noncanonical-state":
				acks[1].GlobalState = []byte{128, 1}
			case "admin":
				acks[1].AdminState = []byte("other-profile")
			case "dependencies":
				acks[1].Dependencies = []byte("stale-authority")
			case "proof":
				acks[1].Proof[0] ^= 1
			case "missing-member":
				qualRecordPut(t, f.store, []byte(registryMemberKeyPrefix+"TOKEN-abcdef"), nil)
			case "wrong-activation":
				qualRecordPut(t, f.store, []byte(registrationActivationPrefix+"TOKEN-abcdef"), []byte("other"))
			case "wrong-association":
				qualRecordPut(t, f.store, []byte(registrationAssociationPrefix+"TOKEN-abcdef"), []byte("other"))
			case "host-mutation":
				host.hook = func(uint32) { qualRecordPut(t, f.store, []byte("foreign-host-write"), []byte{1}) }
			case "ended-context":
				f.end()
			}
			before, err := f.store.RootHash()
			require.NoError(t, err)
			journal, outputs, called := f.store.JournalLen(), len(f.boundary.outputs), 0
			original := errors.New("owning readiness operation failed")
			err = f.admit.WithBootstrapReadiness([]byte("TOKEN-abcdef"), acks, host, func() (*vmcommon.VMOutput, error) {
				called++
				qualRecordPut(t, f.store, []byte("readiness-owning-operation"), []byte{1})
				if fault == "operation-error" {
					return nil, original
				}
				if fault == "operation-failed-output" {
					return &vmcommon.VMOutput{ReturnCode: vmcommon.UserError}, nil
				}
				return &vmcommon.VMOutput{ReturnCode: vmcommon.Ok}, nil
			})
			if fault == "healthy" || fault == "out-of-order" {
				require.NoError(t, err)
				require.Equal(t, 1, called)
				require.Equal(t, 3, host.calls)
				require.Len(t, f.boundary.outputs, outputs+1)
				return
			}
			require.Error(t, err)
			if fault == "operation-error" {
				require.ErrorIs(t, err, original)
			}
			if fault != "operation-error" && fault != "operation-failed-output" {
				require.Zero(t, called)
			}
			after, e := f.store.RootHash()
			require.NoError(t, e)
			require.Equal(t, before, after)
			require.Equal(t, journal, f.store.JournalLen())
			require.Len(t, f.boundary.outputs, outputs)
		})
	}
}

func TestQualDRWAT44T45AdmissionNoDefaultOrDetachedOwner(t *testing.T) {
	for _, fault := range []string{"nil-source", "nil-verifier", "typed-nil-verifier", "empty-domain", "empty-proof", "oversize-proof", "other-accounts"} {
		t.Run(fault, func(t *testing.T) {
			f := qualRegistrationAdmission(t, core.FungibleESDT)
			var source HeaderTimeSource = f.hook
			var verifier RegistrationVerifier = f.verify
			domain, proofs := []byte("n"), f.proofs
			switch fault {
			case "nil-source":
				source = nil
			case "nil-verifier":
				verifier = nil
			case "typed-nil-verifier":
				verifier = (*qualRegistrationVerifier)(nil)
			case "empty-domain":
				domain = nil
			case "empty-proof":
				proofs.Independent = nil
			case "oversize-proof":
				proofs.Support = make([]byte, 4097)
			case "other-accounts":
				source, _ = qualT42Hook(t, qualRegistrationStore(t, 0), core.MetachainShardId, true)
			}
			_, err := f.owner.WithRegistrationAdmission(source, domain, 10, RegistrationResourceLimits{1000, 1048576, 100}, verifier, proofs)
			require.Error(t, err)
		})
	}
}
