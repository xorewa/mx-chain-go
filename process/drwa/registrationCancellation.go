package drwa

import (
	"bytes"
	"encoding/binary"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// BootstrapCancellationVerifier is a mandatory, read-only native-owner
// dependency for Part A L2511-2529. PROGRAM_ADMINISTRATION resolves the exact
// proposed PA body/hash from the consumed intent, never a current root pointer.
// BOOTSTRAP_CANCEL independently proves the adopted scoped cancellation
// combination and lawful lineage/version, including unavailable-role rules.
// Neither purpose may substitute for the other or infer PA-only authority.
//
// NATIVE_BOOTSTRAP_STATE must authenticate the full canonical no SupplyState,
// setup/role mutation or OpenEffect proof. In particular, an uninitialized
// ActiveGovernedActionSet is not an empty aggregate. The native token record
// alone does not prove distributed NFT supply or absence of setup effects.
//
// Purpose strings are DRWA-defined construction discriminators, not wire enums.
// No default verifier, caller boolean, CEB creation or GAS recovery is supplied.
type BootstrapCancellationVerifier interface {
	VerifyBootstrapCancellation(purpose string, subject, proof []byte, at HeaderMilliseconds, epoch uint32) error
	IsInterfaceNil() bool
}

// RegistrationCancellation reuses the exact existing native account/T04 owner.
// The owner supplies admitted domain/epoch/resource dependencies; they are not
// request values. Actual D01/D02 and canonical-state admission remain required.
type RegistrationCancellation struct {
	owner       *RegistrationIntentOwner
	source      HeaderTimeSource
	domain      []byte
	enableEpoch uint32
	limits      RegistrationResourceLimits
	verifier    BootstrapCancellationVerifier
}

func (o *RegistrationIntentOwner) WithBootstrapCancellation(source HeaderTimeSource, domain []byte,
	enableEpoch uint32, limits RegistrationResourceLimits, verifier BootstrapCancellationVerifier) (*RegistrationCancellation, error) {
	if o == nil || o.records == nil || o.boundary == nil || check.IfNil(source) ||
		source.GetAccountsAdapter() != o.records.state.accounts || check.IfNil(verifier) ||
		len(domain) == 0 || len(domain) > o.records.maxBytes ||
		limits.Records == 0 || limits.RetainedBytes == 0 || limits.NewRecordsPerEpoch == 0 {
		return nil, errInvalidRegistrationRecord
	}
	return &RegistrationCancellation{owner: o, source: source, domain: bytes.Clone(domain),
		enableEpoch: enableEpoch, limits: limits, verifier: verifier}, nil
}

func (c *RegistrationCancellation) IsInterfaceNil() bool { return c == nil }

// CancelBootstrapRegistration is the structural contract for the separately
// locked native System-SC owner. nativeProof must read the actual token from
// this exact account adapter; it is not transaction-supplied code/evidence.
// The private native coupling supplies that implementation. Every callback is
// read-only and checked against every participating T04 store.
//
// Cancellation needs its own fresh purpose proofs, not an unexpired creation
// permit or live registration-admission proof. An expired CONSUMED intent stays
// the immutable PA identity. All three proofs remain mandatory.
func (c *RegistrationCancellation) CancelBootstrapRegistration(tokenID, suppliedIntentID,
	paProof, independentProof, stateProof []byte,
	nativeProof func(state.AccountsAdapter, []byte, []byte, []byte) ([]byte, error)) error {
	if c == nil || c.owner == nil || nativeProof == nil || !vmcommon.ValidateToken(tokenID) ||
		!bytes.Equal(suppliedIntentID, c.owner.id) {
		return errInvalidRegistrationRecord
	}
	remaining := c.owner.records.maxBytes
	for _, proof := range [][]byte{paProof, independentProof, stateProof} {
		if len(proof) == 0 || len(proof) > remaining {
			return errInvalidRegistrationRecord
		}
		remaining -= len(proof)
	}
	tokenID, suppliedIntentID = bytes.Clone(tokenID), bytes.Clone(suppliedIntentID)
	paProof, independentProof, stateProof = bytes.Clone(paProof), bytes.Clone(independentProof), bytes.Clone(stateProof)
	return c.owner.boundary.Execute(func() (*vmcommon.VMOutput, error) {
		context, err := c.source.EvaluatedHeaderTimeContext()
		if err != nil {
			return nil, err
		}
		return withHeaderTime(c.source, context, func() (*vmcommon.VMOutput, error) {
			at, epoch, err := scopedAdmissionTime(context)
			if err != nil || epoch < c.enableEpoch {
				return nil, errInvalidRegistrationRecord
			}
			r := c.owner.records
			intent, manager, err := r.registeredToken(tokenID)
			if err != nil {
				return nil, err
			}
			_, digest, id, err := r.identity(intent.body)
			if err != nil || !bytes.Equal(id, suppliedIntentID) || !bytes.Equal(digest, c.owner.digest) ||
				!bytes.Equal(manager, c.owner.manager) || !bytes.Equal(intent.body.networkDomain, c.domain) {
				return nil, errInvalidRegistrationRecord
			}
			account, err := r.state.systemAccount()
			if err != nil {
				return nil, err
			}
			key := append([]byte(registrationActivationPrefix), tokenID...)
			activation, _, err := account.RetrieveValue(key)
			if err != nil {
				return nil, err
			}
			want, err := r.frame(tokenID, id, []byte("BootstrapDeny"))
			if err != nil || !bytes.Equal(activation, want) {
				return nil, errInvalidRegistrationRecord
			}
			member, _, err := account.RetrieveValue(append([]byte(registryMemberKeyPrefix), tokenID...))
			if err != nil || !bytes.Equal(member, []byte{1}) {
				return nil, errInvalidRegistrationRecord
			}
			count, err := registrationCount(account)
			if err != nil || count == 0 {
				return nil, errInvalidRegistrationRecord
			}
			var native []byte
			err = verifyRegistrationState(c.owner.boundary.stores, func() error {
				var proofErr error
				native, proofErr = nativeProof(r.state.accounts, bytes.Clone(tokenID), bytes.Clone(manager), bytes.Clone(intent.body.requestedTokenFamily))
				native = bytes.Clone(native)
				return proofErr
			})
			if err != nil {
				return nil, err
			}
			if len(native) == 0 || len(native) > r.maxBytes {
				return nil, errInvalidRegistrationRecord
			}
			// Exact bound subject, including the immutable consumed intent and
			// the actual native record. Experimental existing Batch framing.
			subject, err := r.frame([]byte("DRWA/BOOTSTRAP_CANCEL/candidate1"), c.domain, tokenID, id,
				digest, intent.encoded, manager, native, stateProof, binary.BigEndian.AppendUint64(nil, uint64(at)),
				binary.BigEndian.AppendUint32(nil, epoch))
			if err != nil {
				return nil, err
			}
			for i, purpose := range []string{"PROGRAM_ADMINISTRATION", "BOOTSTRAP_CANCEL", "NATIVE_BOOTSTRAP_STATE"} {
				proof := [][]byte{paProof, independentProof, stateProof}[i]
				if err = verifyRegistrationState(c.owner.boundary.stores, func() error {
					return c.verifier.VerifyBootstrapCancellation(purpose, bytes.Clone(subject), bytes.Clone(proof), at, epoch)
				}); err != nil {
					return nil, err
				}
			}
			retired, err := r.frame(tokenID, id, []byte("RetiredDeny"), native, stateProof, paProof, independentProof)
			if err != nil {
				return nil, err
			}
			// Retain proof growth in the existing chain-global budget. No intent,
			// association, membership, ordinal or permanent-count write/removal.
			budget := &scopedAdmissionRecords{codec: r, limits: scopedAdmissionLimits{recordBytes: r.maxBytes,
				records: c.limits.Records, retainedBytes: c.limits.RetainedBytes, newRecordsPerEpoch: c.limits.NewRecordsPerEpoch}}
			if err = budget.retainRecords(account, epoch, true, scopedAdmissionWrite{key, retired}); err != nil {
				return nil, err
			}
			// Recheck native evidence after external verifiers and the save. The
			// native owner also checks its VM overlay/output here; account roots
			// alone cannot detect a retained alias staging VM-only effects.
			err = verifyRegistrationState(c.owner.boundary.stores, func() error {
				current, proofErr := nativeProof(r.state.accounts, bytes.Clone(tokenID), bytes.Clone(manager), bytes.Clone(intent.body.requestedTokenFamily))
				if proofErr != nil {
					return proofErr
				}
				if !bytes.Equal(current, native) {
					return errInvalidRegistrationRecord
				}
				return nil
			})
			return nil, err
		})
	})
}
