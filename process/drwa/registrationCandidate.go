package drwa

import (
	"bytes"

	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/sharding"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
)

// registrationCandidate couples the existing metachain registration writer and
// block-local view (Part A L4863-4888) to the SAME native containment owner. It
// adds no persistence domain or journal. Native executor/factory admission,
// scheduler dependencies and before-first-effect dispatch remain separate work.
// The accounts store must be exclusively owned throughout this handle's life.
type registrationCandidate struct {
	writer *RegistryRegistration
	view   *registryCandidate
}

// reconstructRegistrationCandidate is only for startup/state-sync/integrity
// reconstruction, never per-block full-set rebuilding. projection is the private
// authenticated transport result, with its sole-producer completeness invariant;
// the executing native store must be at that exact committed root. Stable input
// ownership is required until this call returns, as for registry transport.
func reconstructRegistrationCandidate(accounts state.AccountsAdapter, coordinator sharding.Coordinator,
	maxEver uint64, projection *registryProjection) (*registrationCandidate, error) {
	if projection == nil || projection.members == nil || uint64(len(projection.members)) > maxEver {
		return nil, errInvalidRegistryTransport
	}
	a := &projection.anchor
	if len(a.candidateHash) == 0 || len(a.metaHash) == 0 || len(a.executedHash) == 0 || len(a.root) == 0 {
		return nil, errInvalidMetaContext
	}
	writer, owner, err := NewRegistryRegistration(accounts, coordinator, maxEver)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(owner.roots[0], a.root) {
		return nil, errInvalidMetaContext
	}
	parent := &committedRegistry{anchor: copyRegistryAnchor(a), members: make(map[string]struct{}, len(projection.members))}
	for id := range projection.members {
		parent.members[id] = struct{}{}
	}
	view := &registryCandidate{parent: parent, before: copyRegistryAnchor(a), after: copyRegistryAnchor(a),
		added: make(map[string]struct{}), ready: true,
		material: &registryMaterialization{state: writer.state, owner: owner, required: copyRegistryAnchor(a)}}
	parent.active = view
	return &registrationCandidate{writer: writer, view: view}, nil
}

func (r *registrationCandidate) RegisterToken(create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	return r.register(r.writer.RegisterToken, create)
}

// BindIntent reuses the complete T19 identity/profile/record owner. Its native
// creator contract is unchanged, but its operation now passes through the same
// candidate publication boundary as RegisterToken. This is not authenticated
// ingress; BindIntent's existing current-authority obligations still apply.
func (r *registrationCandidate) BindIntent(id, digest, manager []byte,
	marshaller marshal.Marshalizer, hasher hashing.Hasher, maxBytes int) (*RegistrationIntentOwner, error) {
	if r == nil || r.writer == nil || r.view == nil {
		return nil, errInvalidRegistrationRecord
	}
	owner, err := r.writer.BindIntent(id, digest, manager, marshaller, hasher, maxBytes)
	if err != nil {
		return nil, err
	}
	owner.registration = r
	return owner, nil
}

func (r *registrationCandidate) IsInterfaceNil() bool { return r == nil }

func (r *registrationCandidate) registerTokenForIntent(records *registrationRecords,
	id, digest, manager []byte, create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	return r.register(func(creator func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
		return r.writer.registerTokenForIntent(records, id, digest, manager, creator)
	}, create)
}

// register holds the existing view lock over the COMPLETE selected native
// operation. In the intent path, record consumption can fail after creation;
// no memory delta is published until records, token, membership and count all
// succeed inside the unchanged T19 journal. There is no nested Execute here.
func (r *registrationCandidate) register(
	operation func(func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error,
	create func(state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error)) error {
	if create == nil {
		return ErrInvalidOperation
	}
	if !r.view.parent.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	var added []byte
	err := operation(func(accounts state.AccountsAdapter) ([]byte, *vmcommon.VMOutput, error) {
		id, out, err := create(accounts)
		// The writer and view each own their identifier bytes. A creator's
		// retained slice must not change either identity after return.
		added = bytes.Clone(id)
		return bytes.Clone(added), out, err
	})
	if err != nil {
		return err
	}
	// No fallible action follows publication. The existing view mutex hides
	// the interval between the native journal write and this memory delta.
	r.view.added[string(added)] = struct{}{}
	return nil
}

func (r *registrationCandidate) classify(candidateHash, tokenID []byte) (bool, error) {
	// A native creator can reenter classification; never deadlock on its own
	// registration lock or expose a partially written registration as absence.
	if !r.view.parent.mut.TryRLock() {
		return false, ErrExecutionBusy
	}
	r.view.parent.mut.RUnlock()
	return r.view.classify(candidateHash, tokenID)
}

// commit releases only the existing containment owner's native receipt. The
// old handle closes; this does not manufacture the next authoritative anchor or
// publish the execution-shard projection with an obsolete metachain root.
// Incremental transfer to the next admitted native candidate is still owed by
// its finalizer; this reconstruction function is not a substitute for that path.
func (r *registrationCandidate) commit() ([][]byte, []*vmcommon.VMOutput, error) {
	if !r.view.parent.mut.TryLock() {
		return nil, nil, ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	return r.writer.boundary.Commit()
}

func (r *registrationCandidate) abort() error {
	if !r.view.parent.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	return r.view.material.abort()
}

func (r *registrationCandidate) recover() error {
	if !r.view.parent.mut.TryLock() {
		return ErrExecutionBusy
	}
	defer r.view.parent.mut.Unlock()
	return r.writer.boundary.Recover()
}
