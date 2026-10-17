package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// RegistrationIntentOwner binds the native creator's structural RegisterToken
// contract to the complete retained record write set (Part A L2236-2247).
// It is DRWA-defined construction, NOT authority or a public ingress endpoint.
// The eventual T14 producer must verify canonical-final OPEN intent, current
// independent admission/approvals, issuer, creation commitments, expiry, support
// and epoch, and supply the actual admitted manager/profile. No bool, caller
// address or this object substitutes for those checks. No ordinary importer.
type RegistrationIntentOwner struct {
	registration interface {
		registerTokenForIntent(*registrationRecords, []byte, []byte, []byte,
			func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error), ...registrationGuard) error
		IsInterfaceNil() bool
	}
	records    *registrationRecords
	id, digest []byte
	manager    []byte
	guard      registrationGuard
	boundary   *RollbackContainment
	shards     uint32
}

// BindIntent is an unwired production binding, not a record/authority writer.
// It neither creates an OPEN intent nor selects any hash, address or numeric
// default. Native configured dependencies and qualified maxBytes are supplied
// by the eventual owner. Caller buffers must remain stable during construction;
// the returned binding retains private copies for subsequent native execution.
func (r *RegistryRegistration) BindIntent(id, digest, manager []byte,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, maxBytes int) (*RegistrationIntentOwner, error) {
	if r == nil || r.state == nil || r.boundary == nil {
		return nil, errInvalidRegistrationRecord
	}
	records, err := newRegistrationRecords(r.state.accounts, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	if len(id) != hasher.Size() || len(digest) != hasher.Size() || len(manager) != len(core.SystemAccountAddress) {
		return nil, errInvalidRegistrationRecord
	}
	return &RegistrationIntentOwner{registration: r, records: records,
		id: bytes.Clone(id), digest: bytes.Clone(digest), manager: bytes.Clone(manager), boundary: r.boundary, shards: r.shards}, nil
}

func (o *RegistrationIntentOwner) IsInterfaceNil() bool { return o == nil }

// RegisterTokenForCreation is the owning native creator coupling. Its actual
// issuer/family and permanent manager are compared inside the SAME operation
// before native creation, not merely checked against a caller boolean. Name,
// ticker/properties/profile and certified type-specific-body encoding remain
// the owning T14 pre-entry construction; this identity check does not claim it.
// No output is released here; the native containment owner is the only
// commit/publication boundary, including after failed rollback.
func (o *RegistrationIntentOwner) RegisterTokenForCreation(issuer, manager, family []byte,
	create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	if o == nil || check.IfNil(o.registration) || o.records == nil || create == nil {
		return errInvalidRegistrationRecord
	}
	issuer, manager, family = bytes.Clone(issuer), bytes.Clone(manager), bytes.Clone(family)
	return o.registration.registerTokenForIntent(o.records, o.id, o.digest, o.manager,
		func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
			intent, err := o.records.intent(o.id)
			if err != nil {
				return nil, nil, err
			}
			if !bytes.Equal(issuer, intent.body.issuer) || !bytes.Equal(family, intent.body.requestedTokenFamily) ||
				!bytes.Equal(manager, o.manager) {
				return nil, nil, errInvalidRegistrationRecord
			}
			return create(accounts)
		}, o.guard)
}
