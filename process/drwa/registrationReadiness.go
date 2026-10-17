package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core/check"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	"github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// RegistrationStateAck is untrusted E10 transport (Part A L2349-2373), not
// readiness. GlobalState must be a positively present canonical native record;
// native IsBurnForAll's false result on a missing record is insufficient.
type RegistrationStateAck struct {
	Shard                                 uint32
	GlobalState, AdminState, Dependencies []byte
	Proof                                 []byte
}

// RegistrationAckVerifier authenticates the exact candidate preimage against
// canonical shard result/state evidence. It must prove the native global state
// has the expected token type, admin/profile/dependencies and permanent member,
// not merely a local receipt, matching hash, source message or supplied boolean.
// Expected is DRWA-defined experimental Batch framing, not an allocated wire
// format. G3/P13 bootstrap/ACK admission remains required. No default verifier.
type RegistrationAckVerifier interface {
	VerifyRegistrationAck(shard uint32, expected, proof []byte) error
	IsInterfaceNil() bool
}

// WithBootstrapReadiness is an owning-operation guard, not a cached readiness
// flag or another ACK registry. The configured shard count comes from the same
// native coordinator that created this registration owner. Every invocation
// authenticates all shards before execute, in this owner's existing T04/time
// boundary. execute owns the actual activation predicates/state transition;
// this E10 prerequisite alone cannot authorize activation or publish outputs.
func (a *RegistrationAdmission) WithBootstrapReadiness(tokenID []byte, acks []RegistrationStateAck,
	verifier RegistrationAckVerifier, execute func() (*vmcommon.VMOutput, error)) error {
	if a == nil || a.owner == nil || check.IfNil(verifier) || execute == nil || !vmcommon.ValidateToken(tokenID) ||
		a.owner.shards == 0 || uint64(len(acks)) != uint64(a.owner.shards) {
		return errInvalidRegistrationRecord
	}
	remaining := a.owner.records.maxBytes
	// Every ACK has four nonempty bounded fields. Refuse an impossible
	// cardinality before allocating a second copy of the caller's slice.
	if len(acks) > remaining/4 {
		return errInvalidRegistrationRecord
	}
	owned := make([]RegistrationStateAck, len(acks))
	for i, ack := range acks {
		owned[i].Shard = ack.Shard
		for j, value := range [][]byte{ack.GlobalState, ack.AdminState, ack.Dependencies, ack.Proof} {
			if len(value) == 0 || len(value) > remaining {
				return errInvalidRegistrationRecord
			}
			remaining -= len(value)
			switch j {
			case 0:
				owned[i].GlobalState = bytes.Clone(value)
			case 1:
				owned[i].AdminState = bytes.Clone(value)
			case 2:
				owned[i].Dependencies = bytes.Clone(value)
			case 3:
				owned[i].Proof = bytes.Clone(value)
			}
		}
	}
	tokenID = bytes.Clone(tokenID)
	return a.owner.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		context, err := a.source.EvaluatedHeaderTimeContext()
		if err != nil {
			return nil, err
		}
		return withHeaderTime(a.source, context, func() (*vmcommon.VMOutput, error) {
			_, epoch, err := scopedAdmissionTime(context)
			if err != nil || epoch < a.enableEpoch {
				return nil, errInvalidRegistrationRecord
			}
			records := a.owner.records
			intent, manager, err := records.registeredToken(tokenID)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(intent.digest, a.owner.digest) || !bytes.Equal(manager, a.owner.manager) ||
				!bytes.Equal(intent.body.networkDomain, a.domain) {
				return nil, errInvalidRegistrationRecord
			}
			// Resolve the authoritative consumed-intent association, never a
			// caller-selected intent. A different consumed intent must not match.
			_, _, id, err := records.identity(intent.body)
			if err != nil || !bytes.Equal(id, a.owner.id) {
				return nil, errInvalidRegistrationRecord
			}
			account, err := records.state.systemAccount()
			if err != nil {
				return nil, err
			}
			activation, _, err := account.RetrieveValue(append([]byte(registrationActivationPrefix), tokenID...))
			if err != nil {
				return nil, err
			}
			want, err := records.frame(tokenID, id, []byte("BootstrapDeny"))
			if err != nil || !bytes.Equal(want, activation) {
				return nil, errInvalidRegistrationRecord
			}
			member, _, err := account.RetrieveValue(append([]byte(registryMemberKeyPrefix), tokenID...))
			if err != nil || !bytes.Equal(member, []byte{1}) {
				return nil, errInvalidRegistrationRecord
			}
			seen := make(map[uint32]struct{}, len(owned))
			for _, ack := range owned {
				if ack.Shard >= a.owner.shards {
					return nil, errInvalidRegistrationRecord
				}
				if _, duplicate := seen[ack.Shard]; duplicate {
					return nil, errInvalidRegistrationRecord
				}
				seen[ack.Shard] = struct{}{}
				metadata := builtInFunctions.ESDTGlobalMetadataFromBytes(ack.GlobalState)
				if len(ack.GlobalState) != 2 || !bytes.Equal(metadata.ToBytes(), ack.GlobalState) ||
					metadata.BurnRoleForAll || metadata.TokenType == 0 {
					return nil, errInvalidRegistrationRecord
				}
				expected, err := records.frame([]byte("DRWA/STATE_ACK/candidate1"), a.domain, tokenID, id,
					records.hasher.Compute(string(activation)), intent.body.requestedTokenFamily, intent.body.creationProfile,
					manager, ack.GlobalState, ack.AdminState, member, ack.Dependencies, binary.BigEndian.AppendUint32(nil, ack.Shard))
				if err != nil {
					return nil, err
				}
				if err = verifyRegistrationState(a.owner.boundary.stores, func() error {
					return verifier.VerifyRegistrationAck(ack.Shard, bytes.Clone(expected), bytes.Clone(ack.Proof))
				}); err != nil {
					return nil, err
				}
			}
			output, err := execute()
			if err == nil && (output == nil || output.ReturnCode != vmcommon.Ok) {
				return nil, errInvalidRegistrationRecord
			}
			return output, err
		})
	})
}
