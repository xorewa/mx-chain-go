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
	records     *registrationRecords
	id, digest  []byte
	manager     []byte
	guard       registrationGuard
	boundary    *RollbackContainment
	shards      uint32
	convergence *registrationConvergence
}

// registrationConvergence is private original-owner composition, not a native
// admission provider or a requester-selected transition. The real native owner
// still owes the authenticated builder/host and every T01 input before wiring.
type registrationConvergence struct {
	records *convergenceRecords
	build   func(tokenID []byte) (convergenceTransition, error)
}

func (o *RegistrationIntentOwner) withConvergence(records *convergenceRecords,
	build func([]byte) (convergenceTransition, error)) (*RegistrationIntentOwner, error) {
	if o == nil || o.records == nil || o.records.state == nil || o.boundary == nil || o.convergence != nil ||
		records == nil || records.codec == nil || records.codec.state == nil || check.IfNil(records.host) || records.boundary != o.boundary ||
		records.codec.state.accounts != o.records.state.accounts || build == nil {
		return nil, errInvalidRegistrationRecord
	}
	bound := *o
	bound.convergence = &registrationConvergence{records: records, build: build}
	return &bound, nil
}

// These discriminators describe the retained experimental T01 phase. Actual
// lineage, predecessor, support and canonical source evidence belong to the
// admitted native convergence host before first use.
func (o *RegistrationIntentOwner) matchesBootstrapReadiness(t convergenceTransition) bool {
	if !bytes.Equal(t.action, o.id) || !bytes.Equal(t.digest, o.digest) || t.version != 1 ||
		t.context == nil || string(t.context.family) != "BOOTSTRAP_READINESS" ||
		string(t.context.phase) != "TYPE_PROFILE_READINESS" ||
		o.shards == 0 || uint64(len(t.shards)) != uint64(o.shards) {
		return false
	}
	for i, shard := range t.shards {
		if shard != uint32(i) {
			return false
		}
	}
	return true
}

func (c *registrationConvergence) create(owner *RegistrationIntentOwner, tokenID []byte) error {
	var transition convergenceTransition
	err := verifyRegistrationState(c.records.boundary.stores, func() error {
		var err error
		transition, err = c.build(bytes.Clone(tokenID))
		return err
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(transition.token, tokenID) || !owner.matchesBootstrapReadiness(transition) {
		return errInvalidRegistrationRecord
	}
	operation, err := c.records.prepareCreate(transition)
	if err != nil {
		return err
	}
	// Already inside the original registration Execute and its complete guard.
	// K creation adds neither a second journal entry boundary nor an output.
	_, err = operation()
	return err
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
	_, err := o.registerTokenForCreation(nil, issuer, manager, family, create)
	return err
}

func (o *RegistrationIntentOwner) registerTokenForCreation(operation *rollbackOperation, issuer, manager, family []byte,
	create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
	if o == nil || check.IfNil(o.registration) || o.records == nil || create == nil {
		return nil, errInvalidRegistrationRecord
	}
	issuer, manager, family = bytes.Clone(issuer), bytes.Clone(manager), bytes.Clone(family)
	guard := o.guard
	var created []byte
	if o.convergence != nil {
		guard = func(stores []state.AccountsAdapter, execute func() (*vmcommon.VMOutput, error)) (*vmcommon.VMOutput, error) {
			complete := func() (*vmcommon.VMOutput, error) {
				output, err := execute()
				if err != nil {
					return nil, err
				}
				if err = o.convergence.create(o, created); err != nil {
					return nil, err
				}
				return output, nil
			}
			if o.guard != nil {
				return o.guard(stores, complete)
			}
			return complete()
		}
	}
	creator := func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		intent, err := o.records.intent(o.id)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(issuer, intent.body.issuer) || !bytes.Equal(family, intent.body.requestedTokenFamily) ||
			!bytes.Equal(manager, o.manager) {
			return nil, nil, errInvalidRegistrationRecord
		}
		if o.convergence == nil {
			return create(accounts)
		}
		id, output, err := create(accounts)
		if err != nil {
			return nil, nil, err
		}
		// Reuse consume's native validity bound before retaining a copy.
		if !vmcommon.ValidateToken(id) {
			return nil, nil, errInvalidRegistrationRecord
		}
		created = bytes.Clone(id)
		return bytes.Clone(created), output, nil
	}
	if operation == nil {
		return nil, o.registration.registerTokenForIntent(o.records, o.id, o.digest, o.manager, creator, guard)
	}
	switch owner := o.registration.(type) {
	case *RegistryRegistration:
		if owner.boundary == o.boundary {
			return owner.registerTokenForIntentOwned(operation, o.records, o.id, o.digest, o.manager, creator, guard)
		}
	case *registrationCandidate:
		if owner.writer.boundary == o.boundary {
			return owner.registerTokenForIntentOwned(operation, o.records, o.id, o.digest, o.manager, creator, guard)
		}
	}
	return nil, errInvalidMetaContext
}
